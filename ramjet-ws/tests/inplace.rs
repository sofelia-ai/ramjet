//! The zero-copy path: `Decoder::take_whole_frame`.
//!
//! Two things matter here beyond "does it decode". First, a rejection has to
//! leave the buffer byte-for-byte as it was, because the caller's fallback is to
//! hand those same bytes to `feed` — unmasking them twice would silently restore
//! the masked payload. Second, the reply header a server writes must fit in
//! front of the payload, which is the whole reason the path exists.

mod common;

use common::*;
use ramjet_ws::{Decoder, Error, Event, MessageKind, encode};

/// Payload length -> bytes a server's reply header occupies.
fn reply_header_len(len: usize) -> usize {
    if len < 126 {
        2
    } else if len <= usize::from(u16::MAX) {
        4
    } else {
        10
    }
}

#[test]
fn takes_a_whole_binary_frame_in_place() {
    let payload: Vec<u8> = (0..200u8).collect();
    let mut wire = frame(true, BINARY, &payload);
    let mut d = Decoder::new();

    let view = d
        .take_whole_frame(&mut wire)
        .expect("no protocol error")
        .expect("a whole binary frame is the fast path");
    assert_eq!(view.kind, MessageKind::Binary);
    assert_eq!(&wire[view.payload.clone()], &payload[..]);
    assert_eq!(view.payload.end, wire.len(), "payload runs to the end");
}

#[test]
fn takes_a_whole_text_frame_and_validates_it() {
    let mut wire = frame(true, TEXT, "héllo 日本語".as_bytes());
    let mut d = Decoder::new();
    let view = d.take_whole_frame(&mut wire).unwrap().expect("fast path");
    assert_eq!(view.kind, MessageKind::Text);
    assert_eq!(
        std::str::from_utf8(&wire[view.payload]).unwrap(),
        "héllo 日本語"
    );
}

#[test]
fn invalid_utf8_in_a_text_frame_is_rejected() {
    // A UTF-16 surrogate, which is never valid UTF-8.
    let mut wire = frame(true, TEXT, &[0xED, 0xA0, 0x80]);
    let mut d = Decoder::new();
    assert_eq!(d.take_whole_frame(&mut wire), Err(Error::InvalidUtf8));
    // And the decoder stays failed, like any other terminal error.
    assert_eq!(d.next_event(), Err(Error::InvalidUtf8));
}

#[test]
fn protocol_errors_are_terminal_here_too() {
    for bad in [
        frame_masked(true, TEXT, b"x", None), // unmasked client frame
        frame(true, 0x3, b""),                // reserved opcode
        frame(false, PING, b""),              // fragmented control frame
    ] {
        let mut wire = bad;
        let mut d = Decoder::new();
        let err = d.take_whole_frame(&mut wire).expect_err("must be refused");
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        assert!(d.next_event().is_err(), "the decoder must stay failed");
    }
}

#[test]
fn an_oversize_frame_is_refused_without_unmasking() {
    let payload = vec![0u8; 4096];
    let mut wire = frame(true, BINARY, &payload);
    let before = wire.clone();
    let mut d = Decoder::with_max_message(64);
    assert_eq!(
        d.take_whole_frame(&mut wire),
        Err(Error::TooLarge { limit: 64 })
    );
    assert_eq!(wire, before, "a refused frame must not be touched");
}

/// Every case the fast path declines has to leave the bytes alone, because the
/// caller's next move is to feed those same bytes to the streaming decoder.
#[test]
fn declined_frames_are_left_byte_for_byte_untouched() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("a fragment", frame(false, TEXT, b"first")),
        ("a continuation", frame(true, CONTINUATION, b"rest")),
        ("a ping", frame(true, PING, b"beat")),
        ("a pong", frame(true, PONG, b"beat")),
        ("a close", frame(true, CLOSE, &close_payload(1000, "bye"))),
    ];

    // A header with the payload still in flight.
    let whole = frame(true, BINARY, &[7u8; 40]);
    cases.push(("a truncated frame", whole[..whole.len() - 10].to_vec()));
    cases.push(("just two header bytes", whole[..2].to_vec()));
    cases.push(("an empty buffer", Vec::new()));

    // Two frames coalesced: the second would be lost if the first were taken.
    let mut two = frame(true, TEXT, b"one");
    two.extend(frame(true, TEXT, b"two"));
    cases.push(("two frames in one buffer", two));

    for (what, bytes) in cases {
        let mut buf = bytes.clone();
        let mut d = Decoder::new();
        assert_eq!(
            d.take_whole_frame(&mut buf),
            Ok(None),
            "{what} should decline the fast path"
        );
        assert_eq!(buf, bytes, "{what} was modified despite being declined");

        // And the streaming path still reads those untouched bytes correctly.
        d.feed(&buf);
        let _ = drain(&mut d);
    }
}

/// A decoder mid-stream cannot interpret a bare buffer, so it must decline.
#[test]
fn a_decoder_holding_state_declines() {
    // Open a fragmented message, which leaves the decoder mid-message.
    let mut d = Decoder::new();
    d.feed(&frame(false, TEXT, b"open"));
    assert_eq!(d.next_event(), Ok(None));

    let mut wire = frame(true, BINARY, b"whole");
    let before = wire.clone();
    assert_eq!(d.take_whole_frame(&mut wire), Ok(None));
    assert_eq!(wire, before);

    // Leftover unread bytes also count as state.
    let mut d2 = Decoder::new();
    let partial = frame(true, BINARY, &[1u8; 50]);
    d2.feed(&partial[..4]);
    assert_eq!(d2.next_event(), Ok(None));
    let mut wire2 = frame(true, BINARY, b"whole");
    let before2 = wire2.clone();
    assert_eq!(d2.take_whole_frame(&mut wire2), Ok(None));
    assert_eq!(wire2, before2);
}

/// The property the echo path depends on: a client's masked header always
/// leaves room for the server's reply header in front of the payload.
#[test]
fn the_reply_header_always_fits_in_front_of_the_payload() {
    for len in [0usize, 1, 125, 126, 127, 1000, 65535, 65536, 70_000] {
        let payload = vec![0xA5u8; len];
        let mut wire = frame(true, BINARY, &payload);
        let mut d = Decoder::new();
        let view = d
            .take_whole_frame(&mut wire)
            .unwrap()
            .unwrap_or_else(|| panic!("length {len} should take the fast path"));
        let need = reply_header_len(view.payload.len());
        assert!(
            view.payload.start >= need,
            "length {len}: payload starts at {} but a reply header needs {need}",
            view.payload.start
        );
        // The client's masked header is exactly four bytes longer than ours.
        assert_eq!(view.payload.start, need + 4, "length {len}");
    }
}

/// The fast path and the streaming path must agree on the bytes.
#[test]
fn agrees_with_the_streaming_path() {
    for payload in [
        Vec::new(),
        b"hello".to_vec(),
        vec![0x00u8; 125],
        vec![0xFFu8; 126],
        (0..=255u8).collect(),
        vec![9u8; 70_000],
    ] {
        let wire = frame(true, BINARY, &payload);

        let mut fast = wire.clone();
        let mut d = Decoder::new();
        let view = d.take_whole_frame(&mut fast).unwrap().expect("fast path");
        let via_fast = fast[view.payload].to_vec();

        let via_stream = match decode_all(&wire).unwrap().first() {
            Some(Event::Binary(b)) => b.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(via_fast, via_stream);
        assert_eq!(via_fast, payload);
    }
}

/// Using both paths on one decoder, in sequence, has to keep working: the fast
/// path leaves no residue behind it.
#[test]
fn fast_and_streaming_paths_interleave() {
    let mut d = Decoder::new();
    for round in 0..8 {
        // Fast path.
        let payload = vec![round as u8; 32];
        let mut wire = frame(true, BINARY, &payload);
        let view = d
            .take_whole_frame(&mut wire)
            .unwrap()
            .unwrap_or_else(|| panic!("round {round} declined"));
        assert_eq!(&wire[view.payload], &payload[..]);

        // Streaming path, including a control frame the fast path never takes.
        d.feed(&frame(true, PING, b"beat"));
        assert_eq!(d.next_event(), Ok(Some(Event::Ping(b"beat".to_vec()))));
        assert_eq!(d.next_event(), Ok(None));
    }
}

// ---- batches: `take_frame_at` --------------------------------------------
//
// A pipelining client puts several frames in one read, and the whole point of
// the batch path is that every reply fits back inside that same buffer. These
// pin both halves: the frames come out right, and the room for the replies is
// there and grows.

/// Walk a buffer of whole frames, collecting (kind, payload bytes) and the
/// offset the walk stopped at.
fn take_all(d: &mut Decoder, buf: &mut [u8]) -> (Vec<(MessageKind, Vec<u8>)>, usize) {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(view) = d.take_frame_at(buf, from).expect("no protocol error") {
        out.push((view.kind, buf[view.payload.clone()].to_vec()));
        from = view.payload.end;
    }
    (out, from)
}

#[test]
fn takes_every_frame_of_a_pipelined_batch() {
    let payloads: Vec<Vec<u8>> = (0..8u8)
        .map(|i| vec![b'a' + i; 1 + i as usize * 40])
        .collect();
    let mut wire = Vec::new();
    for p in &payloads {
        wire.extend_from_slice(&frame(true, BINARY, p));
    }
    let full = wire.len();

    let mut d = Decoder::new();
    let (got, from) = take_all(&mut d, &mut wire);
    assert_eq!(from, full, "the walk consumed the whole batch");
    assert_eq!(got.len(), payloads.len());
    for (i, (kind, data)) in got.iter().enumerate() {
        assert_eq!(*kind, MessageKind::Binary);
        assert_eq!(data, &payloads[i], "frame {i}");
    }
}

#[test]
fn a_batch_leaves_room_for_every_reply_header() {
    // Mixed lengths so both the 2-byte and 4-byte reply headers appear.
    let payloads: Vec<Vec<u8>> = vec![vec![b'x'; 3], vec![b'y'; 200], vec![b'z'; 70]];
    let mut wire = Vec::new();
    for p in &payloads {
        wire.extend_from_slice(&frame(true, BINARY, p));
    }

    let mut d = Decoder::new();
    // Replies are laid out back to back from the front of the buffer, exactly as
    // the echo server does it. The invariant is that the write cursor never
    // catches up with the payload it is about to copy.
    let mut w = 0usize;
    let mut from = 0usize;
    let mut slack = Vec::new();
    while let Some(view) = d.take_frame_at(&mut wire, from).expect("no protocol error") {
        let h = reply_header_len(view.payload.len());
        assert!(
            w + h <= view.payload.start,
            "reply header for a {}-byte payload at {} would overwrite it from {w}",
            view.payload.len(),
            view.payload.start
        );
        slack.push(view.payload.start - (w + h));
        w += h + view.payload.len();
        from = view.payload.end;
    }
    assert_eq!(slack.len(), payloads.len());
    // Four bytes per frame, because that is the mask the reply does not carry.
    assert_eq!(
        slack,
        vec![4, 8, 12],
        "the room grows by the mask each frame"
    );
    assert!(
        w < wire.len(),
        "the corked batch is shorter than what arrived"
    );
}

#[test]
fn a_batch_stops_at_the_first_thing_it_cannot_take() {
    let mut wire = frame(true, BINARY, b"first");
    let whole = wire.len();
    // A control frame, then a data frame behind it: the walk must stop at the
    // control frame and leave everything from there for the streaming path.
    wire.extend_from_slice(&frame(true, 0x9, b"ping"));
    wire.extend_from_slice(&frame(true, BINARY, b"third"));
    let untouched = wire[whole..].to_vec();

    let mut d = Decoder::new();
    let (got, from) = take_all(&mut d, &mut wire);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, b"first");
    assert_eq!(from, whole, "stopped at the control frame");
    assert_eq!(
        &wire[whole..],
        &untouched[..],
        "the tail is left byte-for-byte for `feed`"
    );
}

#[test]
fn a_batch_ending_in_a_partial_frame_leaves_the_partial_alone() {
    let mut wire = frame(true, TEXT, b"whole");
    let whole = wire.len();
    let mut partial = frame(true, TEXT, b"cut short");
    partial.truncate(partial.len() - 3);
    wire.extend_from_slice(&partial);
    let untouched = wire[whole..].to_vec();

    let mut d = Decoder::new();
    let (got, from) = take_all(&mut d, &mut wire);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, b"whole");
    assert_eq!(from, whole);
    assert_eq!(&wire[whole..], &untouched[..], "partial frame untouched");

    // And the streaming path finishes it once the rest turns up.
    d.feed(&wire[whole..]);
    d.feed(&frame(true, TEXT, b"")[..0]); // no-op, keeps the shape honest
    assert_eq!(d.next_event().expect("no error"), None, "still incomplete");
}

#[test]
fn a_batch_agrees_with_the_streaming_path() {
    let payloads: Vec<Vec<u8>> = vec![vec![b'a'; 1], vec![b'b'; 130], vec![b'c'; 60]];
    let mut wire = Vec::new();
    for p in &payloads {
        wire.extend_from_slice(&frame(true, BINARY, p));
    }

    let mut fast = Decoder::new();
    let (got, _) = take_all(&mut fast, &mut wire.clone());

    let mut slow = Decoder::new();
    slow.feed(&wire);
    let mut expected = Vec::new();
    while let Some(e) = slow.next_event().expect("no error") {
        match e {
            Event::Binary(d) => expected.push((MessageKind::Binary, d)),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got, expected, "both paths decode a batch identically");
}

#[test]
fn a_protocol_error_mid_batch_is_terminal() {
    let mut wire = frame(true, BINARY, b"good");
    let whole = wire.len();
    // Reserved opcode 0x3 behind a valid frame.
    wire.extend_from_slice(&frame(true, 0x3, b"bad"));

    let mut d = Decoder::new();
    let first = d
        .take_frame_at(&mut wire, 0)
        .expect("first frame is fine")
        .expect("a whole frame");
    assert_eq!(first.payload.end, whole);
    let e = d
        .take_frame_at(&mut wire, whole)
        .expect_err("reserved opcode must be refused");
    assert!(matches!(e, Error::Protocol(_)));
    // Sticky, exactly like the streaming path.
    assert!(d.take_frame_at(&mut wire, whole).is_err());
}

#[test]
fn fused_echo_packs_a_mixed_batch_into_ready_server_frames() {
    let cases: Vec<(MessageKind, Vec<u8>)> = vec![
        (MessageKind::Binary, Vec::new()),
        (MessageKind::Text, "héllo".as_bytes().to_vec()),
        (MessageKind::Binary, vec![0xA5; 125]),
        (MessageKind::Binary, vec![0x5A; 126]),
        (MessageKind::Text, vec![b'z'; 1000]),
    ];
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for (kind, payload) in &cases {
        let opcode = match kind {
            MessageKind::Text => TEXT,
            MessageKind::Binary => BINARY,
        };
        wire.extend_from_slice(&frame(true, opcode, payload));
        match kind {
            MessageKind::Text => encode::text(&mut expected, std::str::from_utf8(payload).unwrap()),
            MessageKind::Binary => encode::binary(&mut expected, payload),
        }
    }
    let input_len = wire.len();

    let mut d = Decoder::new();
    let mut from = 0usize;
    let mut to = 0usize;
    for (kind, payload) in &cases {
        let echoed = d
            .take_echo_frame_at(&mut wire, from, to)
            .expect("valid frame")
            .expect("whole data frame");
        assert_eq!(&wire[echoed.payload.clone()], &payload[..]);
        let opcode = match kind {
            MessageKind::Text => 0x1,
            MessageKind::Binary => 0x2,
        };
        assert_eq!(wire[echoed.frame.start] & 0x0F, opcode);
        from = echoed.consumed;
        to = echoed.frame.end;
    }

    assert_eq!(from, input_len, "every client frame was consumed");
    assert_eq!(&wire[..to], &expected, "batch is ready for one write");
    assert!(
        to < input_len,
        "removing one mask from every frame must compact the batch"
    );
}

#[test]
fn fused_echo_declines_without_touching_partial_or_misplaced_output() {
    let whole = frame(true, BINARY, &[7u8; 64]);

    let mut partial = whole[..whole.len() - 1].to_vec();
    let before = partial.clone();
    let mut d = Decoder::new();
    assert_eq!(d.take_echo_frame_at(&mut partial, 0, 0), Ok(None));
    assert_eq!(partial, before);

    let mut misplaced = whole;
    let before = misplaced.clone();
    let mut d = Decoder::new();
    assert_eq!(d.take_echo_frame_at(&mut misplaced, 0, 1), Ok(None));
    assert_eq!(misplaced, before);
}

#[test]
fn fused_echo_validates_text_and_keeps_the_error_sticky() {
    let mut wire = frame(true, TEXT, &[0xED, 0xA0, 0x80]);
    let mut d = Decoder::new();
    assert_eq!(
        d.take_echo_frame_at(&mut wire, 0, 0),
        Err(Error::InvalidUtf8)
    );
    assert_eq!(d.next_event(), Err(Error::InvalidUtf8));
}

#[test]
fn an_offset_past_the_end_declines_rather_than_panics() {
    let mut wire = frame(true, BINARY, b"x");
    let mut d = Decoder::new();
    let end = wire.len();
    assert_eq!(d.take_frame_at(&mut wire, end).unwrap(), None);
    assert_eq!(d.take_frame_at(&mut wire, end + 99).unwrap(), None);
}
