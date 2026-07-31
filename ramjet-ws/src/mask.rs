//! Unmasking with measured eight- and sixteen-byte paths.
//!
//! Every frame a client sends is XORed with a rotating four-byte key, so
//! unmasking is the one cost a server pays per *byte* rather than per frame.
//! Done a byte at a time with an index computation each, it is the only part of
//! this codec whose cost grows with payload size and nothing else — which is
//! exactly the shape of the throughput gap we are chasing.
//!
//! The trick is that the key repeats every four bytes and both sixteen and
//! eight are multiples of four, so repeated-key `u128`/`u64` words apply
//! unchanged to every chunk. Target-hardware measurements show the wider loop
//! winning from 32 through 512 bytes while the simpler `u64` loop wins again on
//! larger payloads, so the choice is deliberately size-adaptive. No alignment
//! handling: native-endian conversions compile to unaligned loads on every
//! target we serve, and staying in safe code is worth more than the last
//! percent.

use std::ops::Range;

fn rotated(mask: [u8; 4], phase: usize) -> [u8; 4] {
    [
        mask[phase & 3],
        mask[(phase + 1) & 3],
        mask[(phase + 2) & 3],
        mask[(phase + 3) & 3],
    ]
}

fn word64(k: [u8; 4]) -> u64 {
    u64::from_ne_bytes([k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3]])
}

fn word128(k: [u8; 4]) -> u128 {
    u128::from_ne_bytes([
        k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3], k[0], k[1], k[2], k[3], k[0], k[1], k[2],
        k[3],
    ])
}

/// XOR `data` in place with `mask`, rotating, starting at key byte `phase`.
///
/// `phase` is the offset into the key that `data[0]` corresponds to, so a
/// payload arriving in several chunks passes the running total of bytes already
/// unmasked and the key lines up across the split. Only the low two bits
/// matter, so callers are free to let their counter grow.
pub(crate) fn unmask(data: &mut [u8], mask: [u8; 4], phase: usize) {
    // Rotate the key so its first byte is the one `data[0]` wants. After this
    // the offset into `data` *is* the offset into the key.
    let k = rotated(mask, phase);
    let word64 = word64(k);

    let tail = if (32..=512).contains(&data.len()) {
        let word128 = word128(k);
        let mut chunks = data.chunks_exact_mut(16);
        for c in &mut chunks {
            let v = u128::from_ne_bytes(c.try_into().expect("16-byte chunk")) ^ word128;
            c.copy_from_slice(&v.to_ne_bytes());
        }
        let remainder = chunks.into_remainder();
        let (word, tail) = if remainder.len() >= 8 {
            remainder.split_at_mut(8)
        } else {
            remainder.split_at_mut(0)
        };
        if !word.is_empty() {
            let v = u64::from_ne_bytes(word.try_into().expect("8-byte tail")) ^ word64;
            word.copy_from_slice(&v.to_ne_bytes());
        }
        tail
    } else {
        let mut chunks = data.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let v = u64::from_ne_bytes(chunk.try_into().expect("8-byte chunk")) ^ word64;
            chunk.copy_from_slice(&v.to_ne_bytes());
        }
        chunks.into_remainder()
    };
    // Every word width is a multiple of the key length, so the tail starts back
    // at the rotated key's first byte.
    for (i, b) in tail.iter_mut().enumerate() {
        *b ^= k[i & 3];
    }
}

/// Unmask `source` while moving it earlier in the same buffer.
///
/// A batched echo has to remove each client's four-byte masking key before it
/// writes the unmasked server frames. Doing an in-place XOR followed by
/// `copy_within` touches every payload twice. This forward pass loads each word
/// once, XORs it, and stores it directly at `target`.
///
/// `target <= source.start` is what makes overlapping moves safe: a store can
/// overwrite bytes already loaded, but never bytes a later iteration still
/// needs.
pub(crate) fn unmask_into(
    data: &mut [u8],
    source: Range<usize>,
    target: usize,
    mask: [u8; 4],
    phase: usize,
) {
    debug_assert!(target <= source.start);
    debug_assert!(target + source.len() <= data.len());

    let k = rotated(mask, phase);
    let word64 = word64(k);
    let len = source.len();
    let mut at = 0usize;

    if (32..=512).contains(&len) {
        let word128 = word128(k);
        while at + 16 <= len {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[source.start + at..source.start + at + 16]);
            let value = u128::from_ne_bytes(bytes) ^ word128;
            data[target + at..target + at + 16].copy_from_slice(&value.to_ne_bytes());
            at += 16;
        }
    }
    while at + 8 <= len {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[source.start + at..source.start + at + 8]);
        let value = u64::from_ne_bytes(bytes) ^ word64;
        data[target + at..target + at + 8].copy_from_slice(&value.to_ne_bytes());
        at += 8;
    }
    while at < len {
        let value = data[source.start + at] ^ k[at & 3];
        data[target + at] = value;
        at += 1;
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

    #[test]
    fn fused_move_agrees_with_unmask_then_memmove() {
        let mask = [0xA3, 0x5C, 0x01, 0xFE];
        for len in 0..=1024usize {
            for shift in 0..=32usize {
                for phase in 0..4usize {
                    let source_start = 40usize;
                    let target = source_start - shift;
                    let mut fused = vec![0xCC; source_start + len + 8];
                    fused[source_start..source_start + len]
                        .copy_from_slice(&payload(len, phase as u8));
                    let mut separate = fused.clone();

                    unmask_into(
                        &mut fused,
                        source_start..source_start + len,
                        target,
                        mask,
                        phase,
                    );
                    unmask(&mut separate[source_start..source_start + len], mask, phase);
                    separate.copy_within(source_start..source_start + len, target);

                    assert_eq!(
                        &fused[target..target + len],
                        &separate[target..target + len],
                        "len {len} shift {shift} phase {phase}"
                    );
                }
            }
        }
    }
}
