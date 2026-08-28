//! Deterministic no-panic and determinism regression for arbitrary input.
//!
//! CI runs a bounded sample. Before a release, reproduce the full security
//! audit budget with:
//! `RAMJET_HTTP_FUZZ_CASES=10000000 cargo test -p ramjet-http --test fuzz --release -- --nocapture`

use std::env;

use ramjet_http::{ParseRef, parse, parse_ref, parse_ref_from};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

fn cases() -> usize {
    env::var("RAMJET_HTTP_FUZZ_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000)
}

#[test]
fn arbitrary_input_never_panics_and_is_deterministic() {
    let cases = cases();
    let mut rng = Rng(0x5241_4D4A_4554_4854);
    let mut bytes = Vec::with_capacity(256);

    for case in 0..cases {
        bytes.clear();
        let len = (rng.next() as usize) & 0xff;
        bytes.extend((0..len).map(|_| rng.next() as u8));

        let first = parse(&bytes);
        let second = parse(&bytes);
        assert_eq!(
            first, second,
            "non-deterministic owned parse at case {case}"
        );
        let _ = parse_ref(&bytes);

        // Feed the same bytes through the resumable scanner at irregular
        // boundaries. Any terminal result ends the connection in real use.
        let mut scanned = 0;
        let mut cut = 0;
        while cut < bytes.len() {
            cut = (cut + 1 + (rng.next() as usize & 0x0f)).min(bytes.len());
            match parse_ref_from(&bytes[..cut], &mut scanned) {
                Ok(ParseRef::NeedMore) => {}
                Ok(ParseRef::Request { .. }) | Err(_) => break,
            }
        }
    }

    println!("ramjet-http fuzzed {cases} arbitrary inputs without a panic");
}
