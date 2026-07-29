//! Seeded randomized tests.
//!
//! Two properties, both mechanical:
//!
//! 1. **Split invariance.** A sans-io decoder's whole promise is that where the
//!    byte stream was cut cannot change what comes out of it. Every case here
//!    decodes the same bytes under many different chunkings and demands
//!    identical results — events *and* the terminating error, if any.
//! 2. **Garbage is never fatal.** Arbitrary bytes must produce an error, not a
//!    panic, an overflow, or an allocation the size of a claimed length.
//!
//! Failures reproduce from the seed printed in the assertion message. Budget
//! overrides for a longer soak: `RAMJET_WS_FUZZ_CASES=10000`.

mod common;

use common::*;
use ramjet_ws::{Decoder, Error, Event};

/// splitmix64 — deterministic, seedable, and not a dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(1))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }

    /// A string of random scalar values, so multi-byte sequences show up often.
    fn text(&mut self, chars: usize) -> String {
        (0..chars)
            .map(|_| {
                loop {
                    // from_u32 rejects surrogates and anything above U+10FFFF, so
                    // whatever survives is a legal scalar value.
                    if let Some(c) = char::from_u32(self.next_u64() as u32 % 0x11_000) {
                        break c;
                    }
                }
            })
            .collect()
    }
}

/// Everything one run of the decoder produced: the events, then the error that
/// stopped it, if one did.
type Outcome = (Vec<Event>, Option<Error>);

/// Feed `bytes` in the given chunk sizes, draining after each.
fn run(bytes: &[u8], chunks: &[usize]) -> Outcome {
    let mut d = Decoder::new();
    let mut events = Vec::new();
    let mut rest = bytes;
    let mut sizes = chunks.iter().copied().cycle();

    while !rest.is_empty() {
        let take = sizes.next().unwrap_or(1).clamp(1, rest.len());
        let (chunk, tail) = rest.split_at(take);
        rest = tail;
        d.feed(chunk);
        loop {
            match d.next_event() {
                Ok(Some(e)) => events.push(e),
                Ok(None) => break,
                Err(e) => return (events, Some(e)),
            }
        }
    }
    (events, None)
}

/// Decode the same bytes many ways and insist the answer never moves.
fn assert_split_invariant(seed: u64, bytes: &[u8], what: &str) -> Outcome {
    let whole = run(bytes, &[usize::MAX]);
    let mut rng = Rng::new(seed ^ 0x5151_5151);

    // Every small fixed chunk size, which is where header and payload
    // boundaries land in the nastiest places.
    for n in 1..=9usize {
        assert_eq!(
            run(bytes, &[n]),
            whole,
            "seed {seed}: {what} decoded differently in {n}-byte chunks"
        );
    }
    // Plus ragged chunkings, which fixed sizes never produce.
    for _ in 0..8 {
        let pattern: Vec<usize> = (0..4).map(|_| 1 + rng.below(17)).collect();
        assert_eq!(
            run(bytes, &pattern),
            whole,
            "seed {seed}: {what} decoded differently in chunks {pattern:?}"
        );
    }
    whole
}

/// Build a stream of well-formed frames and the events it must produce.
fn valid_stream(rng: &mut Rng) -> (Vec<u8>, Vec<Event>) {
    let mut wire = Vec::new();
    let mut expect = Vec::new();

    for _ in 0..1 + rng.below(4) {
        // A control frame between messages.
        if rng.below(4) == 0 {
            push_control(rng, &mut wire, &mut expect);
        }

        let is_text = rng.below(2) == 0;
        let payload = if is_text {
            let chars = rng.below(24);
            rng.text(chars).into_bytes()
        } else {
            let len = rng.below(200);
            rng.bytes(len)
        };

        // Split into fragments at arbitrary byte offsets — for text that means
        // code points straddle frame boundaries, which is legal and worth
        // hitting often.
        let mut cuts: Vec<usize> = (0..rng.below(4))
            .map(|_| rng.below(payload.len() + 1))
            .collect();
        cuts.sort_unstable();
        let mut bounds = vec![0];
        bounds.extend(cuts);
        bounds.push(payload.len());

        for i in 0..bounds.len() - 1 {
            let piece = &payload[bounds[i]..bounds[i + 1]];
            let last = i == bounds.len() - 2;
            let opcode = if i == 0 {
                if is_text { TEXT } else { BINARY }
            } else {
                CONTINUATION
            };
            wire.extend(frame(last, opcode, piece));
            // A control frame may interleave between fragments, and its event
            // arrives before the message it interrupted.
            if !last && rng.below(3) == 0 {
                push_control(rng, &mut wire, &mut expect);
            }
        }

        expect.push(if is_text {
            Event::Text(
                String::from_utf8(payload).expect("generated text is valid by construction"),
            )
        } else {
            Event::Binary(payload)
        });
    }

    if rng.below(3) == 0 {
        let code = [1000u16, 1001, 1002, 1003, 1007, 1011, 3000, 4999][rng.below(8)];
        let chars = rng.below(10);
        let reason = rng.text(chars);
        wire.extend(frame(true, CLOSE, &close_payload(code, &reason)));
        expect.push(Event::Close(Some(ramjet_ws::CloseFrame { code, reason })));
    }

    (wire, expect)
}

fn push_control(rng: &mut Rng, wire: &mut Vec<u8>, expect: &mut Vec<Event>) {
    let len = rng.below(126);
    let body = rng.bytes(len);
    if rng.below(2) == 0 {
        wire.extend(frame(true, PING, &body));
        expect.push(Event::Ping(body));
    } else {
        wire.extend(frame(true, PONG, &body));
        expect.push(Event::Pong(body));
    }
}

fn cases() -> u64 {
    std::env::var("RAMJET_WS_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400)
}

#[test]
fn valid_streams_decode_the_same_however_they_are_split() {
    let mut messages = 0usize;
    for seed in 0..cases() {
        let mut rng = Rng::new(seed);
        let (wire, expect) = valid_stream(&mut rng);
        let (events, err) = assert_split_invariant(seed, &wire, "a valid stream");
        assert_eq!(
            err, None,
            "seed {seed}: a well-formed stream failed to decode"
        );
        assert_eq!(events, expect, "seed {seed}: wrong events");
        messages += expect.len();
    }
    assert!(messages > 0, "the generator produced nothing to check");
    println!("split-invariance: {} cases, {messages} events", cases());
}

#[test]
fn arbitrary_garbage_never_panics_and_stays_deterministic() {
    let mut errors = 0usize;
    let mut accepted = 0usize;
    for seed in 0..cases() {
        let mut rng = Rng::new(seed ^ 0xDEAD_BEEF);
        let len = rng.below(300);
        let bytes = rng.bytes(len);
        let (events, err) = assert_split_invariant(seed, &bytes, "garbage");
        if err.is_some() {
            errors += 1;
        }
        accepted += events.len();
    }
    // Random bytes are overwhelmingly invalid; if none of them errored, the
    // decoder would be accepting anything and this test would prove nothing.
    assert!(errors > 0, "no garbage was rejected");
    println!(
        "garbage: {} cases, {errors} rejected, {accepted} events accepted",
        cases()
    );
}

#[test]
fn corrupted_valid_streams_never_panic() {
    let mut errors = 0usize;
    for seed in 0..cases() {
        let mut rng = Rng::new(seed ^ 0x1234_5678);
        let (mut wire, _) = valid_stream(&mut rng);
        if wire.is_empty() {
            continue;
        }
        // Flip a handful of bytes: mangled headers, lengths and payloads alike.
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(wire.len());
            wire[at] ^= 1 << rng.below(8);
        }
        let (_, err) = assert_split_invariant(seed, &wire, "a corrupted stream");
        if err.is_some() {
            errors += 1;
        }
    }
    assert!(errors > 0, "corruption never produced an error");
    println!("corruption: {} cases, {errors} rejected", cases());
}

#[test]
fn absurd_length_headers_cost_nothing() {
    // A claimed payload of 2^62 bytes must be refused from the header rather
    // than reserving anything, and must behave the same however it is split.
    for &(opcode, masked) in &[(0x82u8, true), (0x81, true)] {
        let mut wire = vec![opcode, if masked { 0xFF } else { 0x7F }];
        wire.extend_from_slice(&(1u64 << 62).to_be_bytes());
        wire.extend_from_slice(&MASK);
        let (events, err) = assert_split_invariant(0, &wire, "an absurd length");
        assert!(events.is_empty());
        assert_eq!(
            err,
            Some(Error::TooLarge {
                limit: Decoder::new().max_message()
            })
        );
    }
}

/// The zero-copy path must never disagree with the streaming path, and must
/// never touch a buffer it declines — a caller's fallback is to feed those same
/// bytes onward, and a second unmask would restore the masked payload.
#[test]
fn the_in_place_path_agrees_with_the_streaming_path() {
    let mut taken = 0usize;
    let mut declined = 0usize;

    for seed in 0..cases() {
        let mut rng = Rng::new(seed ^ 0x00FF_1CE5);

        // A whole single-frame data message: what the fast path exists for.
        let is_text = rng.below(2) == 0;
        let payload = if is_text {
            let chars = rng.below(40);
            rng.text(chars).into_bytes()
        } else {
            let len = rng.below(400);
            rng.bytes(len)
        };
        let opcode = if is_text { TEXT } else { BINARY };
        let wire = frame(true, opcode, &payload);

        let mut fast = wire.clone();
        let mut d = Decoder::new();
        match d.take_whole_frame(&mut fast) {
            Ok(Some(view)) => {
                taken += 1;
                assert_eq!(
                    &fast[view.payload],
                    &payload[..],
                    "seed {seed}: in-place payload differs from what was sent"
                );
            }
            Ok(None) => {
                declined += 1;
                assert_eq!(fast, wire, "seed {seed}: a declined buffer was modified");
            }
            Err(e) => panic!("seed {seed}: a well-formed frame was refused: {e}"),
        }

        // Whatever the fast path did, the streaming path reads the original
        // bytes the same way.
        let (events, err) = run(&wire, &[usize::MAX]);
        assert_eq!(err, None, "seed {seed}");
        let expect = if is_text {
            Event::Text(String::from_utf8(payload).expect("valid by construction"))
        } else {
            Event::Binary(payload)
        };
        assert_eq!(events, vec![expect], "seed {seed}");
    }

    assert!(taken > 0, "the fast path never triggered");
    println!(
        "in-place: {} cases, {taken} taken, {declined} declined",
        cases()
    );
}

/// Garbage handed to the fast path must error or decline, never panic — and a
/// decline must still leave the bytes alone.
#[test]
fn the_in_place_path_never_panics_on_garbage() {
    let mut errors = 0usize;
    for seed in 0..cases() {
        let mut rng = Rng::new(seed ^ 0xBAD0_C0DE);
        let len = rng.below(80);
        let bytes = rng.bytes(len);
        let mut buf = bytes.clone();
        let mut d = Decoder::new();
        match d.take_whole_frame(&mut buf) {
            Ok(Some(_)) => {}
            Ok(None) => assert_eq!(buf, bytes, "seed {seed}: declined but modified"),
            Err(_) => errors += 1,
        }
    }
    assert!(
        errors > 0,
        "no garbage reached the fast path's error branch"
    );
    println!("in-place garbage: {} cases, {errors} rejected", cases());
}
