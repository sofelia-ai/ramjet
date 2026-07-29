//! Base64 encoding, standard alphabet with padding (RFC 4648 §4).
//!
//! Only the encoder exists, because the handshake only ever needs to produce
//! `Sec-WebSocket-Accept`. The key coming the other way is echoed through SHA-1
//! as the opaque ASCII it arrives as, never decoded.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` as base64 with `=` padding.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        // Pack up to three bytes into 24 bits, then read four 6-bit groups out.
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let bits = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            // A group is padding when the bytes feeding it were never there.
            if i <= chunk.len() {
                let idx = (bits >> (18 - 6 * i)) & 0x3F;
                out.push(ALPHABET[idx as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vectors from RFC 4648 §10, which cover every padding case.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn covers_the_whole_alphabet_including_62_and_63() {
        // 0xFB 0xFF encodes to indices 62 and 63, the '+' and '/' that a
        // url-safe alphabet would get wrong.
        assert_eq!(encode(&[0xFB, 0xFF, 0xFF]), "+///");
        assert_eq!(encode(&[0x00, 0x00, 0x00]), "AAAA");
    }

    #[test]
    fn output_length_is_always_a_multiple_of_four() {
        for len in 0..64 {
            let s = encode(&vec![0xA5; len]);
            assert_eq!(s.len() % 4, 0, "length {len} produced {}", s.len());
            assert_eq!(s.len(), len.div_ceil(3) * 4);
        }
    }
}
