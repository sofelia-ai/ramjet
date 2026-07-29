//! Unmasking, eight bytes at a time.
//!
//! Every frame a client sends is XORed with a rotating four-byte key, so
//! unmasking is the one cost a server pays per *byte* rather than per frame.
//! Done a byte at a time with an index computation each, it is the only part of
//! this codec whose cost grows with payload size and nothing else — which is
//! exactly the shape of the throughput gap we are chasing.
//!
//! The trick is that the key repeats every four bytes and eight is a multiple of
//! four, so one `u64` built from the key twice over applies unchanged to every
//! eight-byte chunk. No alignment handling: `chunks_exact_mut` plus native-endian
//! conversions compile to unaligned loads on every target we serve, and staying
//! in safe code is worth more than the last percent.

/// XOR `data` in place with `mask`, rotating, starting at key byte `phase`.
///
/// `phase` is the offset into the key that `data[0]` corresponds to, so a
/// payload arriving in several chunks passes the running total of bytes already
/// unmasked and the key lines up across the split. Only the low two bits
/// matter, so callers are free to let their counter grow.
pub(crate) fn unmask(data: &mut [u8], mask: [u8; 4], phase: usize) {
    // Rotate the key so its first byte is the one `data[0]` wants. After this
    // the offset into `data` *is* the offset into the key.
    let k = [
        mask[phase & 3],
        mask[(phase + 1) & 3],
        mask[(phase + 2) & 3],
        mask[(phase + 3) & 3],
    ];
    let word = u64::from_ne_bytes([k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]]);

    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes(c.try_into().expect("chunks_exact_mut(8) yields 8")) ^ word;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    // Every chunk was eight bytes, a multiple of the key length, so the
    // remainder starts back at the rotated key's first byte.
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= k[i & 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition, kept deliberately stupid: this is what the fast path has
    /// to agree with.
    fn reference(data: &mut [u8], mask: [u8; 4], phase: usize) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= mask[(phase + i) & 3];
        }
    }

    /// Cheap deterministic bytes, so a failure reproduces from the length alone.
    fn payload(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    }

    /// The whole point. Every length from empty to past any chunk boundary, and
    /// every key phase, against the byte-at-a-time definition.
    #[test]
    fn agrees_with_the_byte_loop_at_every_length_and_phase() {
        let mask = [0xA3, 0x5C, 0x01, 0xFE];
        for len in 0..=1024usize {
            for phase in 0..4usize {
                let mut fast = payload(len, phase as u8);
                let mut slow = fast.clone();
                unmask(&mut fast, mask, phase);
                reference(&mut slow, mask, phase);
                assert_eq!(
                    fast, slow,
                    "mismatch at len {len} phase {phase}: the word path and the \
                     byte path disagree"
                );
            }
        }
    }

    /// A phase larger than the key length is legal — callers keep a running
    /// byte count rather than a modulo — so only the low two bits may matter.
    #[test]
    fn only_the_low_bits_of_the_phase_matter() {
        let mask = [1, 2, 3, 4];
        for len in [0usize, 1, 7, 8, 9, 100] {
            for phase in 0..4usize {
                let mut a = payload(len, 0);
                let mut b = a.clone();
                unmask(&mut a, mask, phase);
                unmask(&mut b, mask, phase + 4000);
                assert_eq!(a, b, "len {len} phase {phase} vs phase+4000");
            }
        }
    }

    /// Unmasking a payload in arbitrary pieces, carrying the phase, must give
    /// the same answer as doing it in one go. This is the streaming path's
    /// actual contract, and the reason `phase` exists at all.
    #[test]
    fn splitting_the_payload_anywhere_gives_the_same_bytes() {
        let mask = [0x11, 0x22, 0x33, 0x44];
        let whole = payload(300, 7);
        let mut one_go = whole.clone();
        unmask(&mut one_go, mask, 0);

        for cut in 0..=whole.len() {
            let mut split = whole.clone();
            let (head, tail) = split.split_at_mut(cut);
            unmask(head, mask, 0);
            unmask(tail, mask, cut);
            assert_eq!(split, one_go, "split at {cut} changed the result");
        }
    }

    /// XOR is its own inverse, and a masked-then-unmasked round trip is what a
    /// real frame goes through. Cheap, and it catches a key built backwards in a
    /// way comparing against a reference with the same bug would not.
    #[test]
    fn unmasking_twice_restores_the_original() {
        let mask = [0xDE, 0xAD, 0xBE, 0xEF];
        for len in [0usize, 1, 3, 4, 5, 8, 15, 16, 17, 1000] {
            for phase in 0..4usize {
                let original = payload(len, 3);
                let mut buf = original.clone();
                unmask(&mut buf, mask, phase);
                if len > 0 && mask.iter().any(|&b| b != 0) {
                    assert_ne!(buf, original, "len {len} phase {phase} was a no-op");
                }
                unmask(&mut buf, mask, phase);
                assert_eq!(buf, original, "len {len} phase {phase} did not round trip");
            }
        }
    }
}
