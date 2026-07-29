//! SHA-1, because RFC 6455 says so.
//!
//! **This is not a security decision.** The upgrade handshake hashes the
//! client's `Sec-WebSocket-Key` with a fixed public GUID and echoes the result
//! back; its only job is to prove both ends speak WebSocket and to stop a
//! cache or proxy from replaying an ordinary HTTP response as an upgrade. The
//! input is not a secret, the output is not a credential, and SHA-1's collision
//! weaknesses are irrelevant to it. RFC 6455 §1.3 mandates exactly this
//! construction, so a modern hash here would simply fail to interoperate.
//!
//! Roughly 60 lines, straight from FIPS 180-4, so the crate keeps its promise
//! of no dependencies.

/// SHA-1 of `msg`, as 20 bytes.
pub(crate) fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    // Padding: a 1 bit, then zeros, then the length in bits as a 64-bit
    // big-endian integer, all to a multiple of 64 bytes.
    let mut padded = msg.to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        // Expand the block into 80 words.
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Vectors from FIPS 180-2 Appendix A and RFC 3174 §7.3.
    #[test]
    fn known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn pangram_vector() {
        assert_eq!(
            hex(&sha1(b"The quick brown fox jumps over the lazy dog")),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
        // One bit of difference, an entirely different digest.
        assert_eq!(
            hex(&sha1(b"The quick brown fox jumps over the lazy cog")),
            "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        );
    }

    /// 55 bytes is the largest message whose padding still fits its own block,
    /// 56 forces a second block, and 64 is exactly one block — the lengths a
    /// padding bug hides behind.
    #[test]
    fn block_boundaries() {
        for len in [0usize, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let a = sha1(&vec![b'x'; len]);
            assert_eq!(a, sha1(&vec![b'x'; len]), "not deterministic at {len}");
            if len > 0 {
                assert_ne!(a, sha1(&vec![b'x'; len - 1]), "length {len} collided");
            }
        }
    }
}
