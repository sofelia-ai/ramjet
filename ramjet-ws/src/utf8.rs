//! Incremental UTF-8 validation.
//!
//! `std::str::from_utf8` needs the whole string at once, which is exactly what a
//! streaming decoder does not have: a text message arrives as several frames,
//! and each frame arrives as several reads. This validates a byte at a time and
//! carries its state across all of those boundaries, so a bad sequence is
//! rejected the moment it is complete rather than at the end of the message.
//!
//! It rejects everything RFC 3629 excludes, not merely what decodes: overlong
//! encodings, UTF-16 surrogates, and anything above U+10FFFF.

/// A partially consumed UTF-8 sequence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Utf8 {
    /// Continuation bytes still owed to the sequence in progress.
    need: u8,
    /// Code point accumulated so far.
    cp: u32,
    /// Smallest value the sequence in progress is allowed to encode. Anything
    /// below it is an overlong form and must be rejected.
    min: u32,
}

impl Utf8 {
    /// Feed one byte. `false` means the stream is invalid from here on.
    pub(crate) fn push(&mut self, byte: u8) -> bool {
        if self.need == 0 {
            // Start of a sequence.
            match byte {
                0x00..=0x7F => true,
                // 0xC0 and 0xC1 can only ever encode an overlong ASCII byte.
                0xC2..=0xDF => {
                    self.need = 1;
                    self.cp = u32::from(byte & 0x1F);
                    self.min = 0x80;
                    true
                }
                0xE0..=0xEF => {
                    self.need = 2;
                    self.cp = u32::from(byte & 0x0F);
                    self.min = 0x800;
                    true
                }
                // 0xF5..=0xFF would all start a code point above U+10FFFF.
                0xF0..=0xF4 => {
                    self.need = 3;
                    self.cp = u32::from(byte & 0x07);
                    self.min = 0x1_0000;
                    true
                }
                // A stray continuation byte, or one of the impossible leads.
                _ => false,
            }
        } else {
            // Continuation bytes are 10xxxxxx and nothing else.
            if byte & 0xC0 != 0x80 {
                return false;
            }
            self.cp = (self.cp << 6) | u32::from(byte & 0x3F);
            self.need -= 1;
            if self.need > 0 {
                return true;
            }
            // Sequence complete: it must be minimal, must not be a surrogate,
            // and must be inside the Unicode range.
            self.cp >= self.min && !(0xD800..=0xDFFF).contains(&self.cp) && self.cp <= 0x10_FFFF
        }
    }

    /// Feed a run of bytes, stopping at the first invalid one.
    pub(crate) fn push_all(&mut self, bytes: &[u8]) -> bool {
        bytes.iter().all(|&b| self.push(b))
    }

    /// True when no sequence is half-finished. A text message that ends here is
    /// truncated and must be rejected.
    pub(crate) fn is_complete(&self) -> bool {
        self.need == 0
    }
}

/// Validate a complete buffer in one go — for close reasons, which are never
/// split across frames.
pub(crate) fn is_valid(bytes: &[u8]) -> bool {
    let mut v = Utf8::default();
    v.push_all(bytes) && v.is_complete()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case here is one `std::str::from_utf8` agrees with; the point is
    /// that this validator reaches the same verdict one byte at a time.
    #[test]
    fn agrees_with_std_on_whole_buffers() {
        let cases: &[&[u8]] = &[
            b"",
            b"ascii",
            "héllo wörld".as_bytes(),
            "日本語".as_bytes(),
            "\u{10348}".as_bytes(),
            &[0x80],                   // stray continuation
            &[0xC0, 0x80],             // overlong NUL
            &[0xC1, 0xBF],             // overlong
            &[0xE0, 0x80, 0x80],       // overlong
            &[0xF0, 0x80, 0x80, 0x80], // overlong
            &[0xED, 0xA0, 0x80],       // surrogate U+D800
            &[0xED, 0xBF, 0xBF],       // surrogate U+DFFF
            &[0xF4, 0x90, 0x80, 0x80], // above U+10FFFF
            &[0xF5, 0x80, 0x80, 0x80], // impossible lead
            &[0xFE],
            &[0xFF],
            &[0xC2],             // truncated 2-byte
            &[0xE2, 0x82],       // truncated 3-byte
            &[0xF0, 0x9F, 0x92], // truncated 4-byte
            &[0xE2, 0x28, 0xA1], // bad continuation
        ];
        for case in cases {
            assert_eq!(
                is_valid(case),
                std::str::from_utf8(case).is_ok(),
                "disagreed with std on {case:02x?}"
            );
        }
    }

    /// The property that matters for a streaming decoder: the verdict cannot
    /// depend on where the byte stream happened to be cut.
    #[test]
    fn verdict_is_independent_of_chunking() {
        let cases: &[&[u8]] = &[
            "hello ✓ 日本語 \u{10348}".as_bytes(),
            &[0xED, 0xA0, 0x80],
            &[0xF0, 0x9F, 0x92, 0xA9],
            &[0xC2],
        ];
        for case in cases {
            let whole = is_valid(case);
            for split in 0..=case.len() {
                let mut v = Utf8::default();
                let ok = v.push_all(&case[..split]) && v.push_all(&case[split..]);
                assert_eq!(
                    ok && v.is_complete(),
                    whole,
                    "{case:02x?} split at {split} disagreed with the whole"
                );
            }
        }
    }

    #[test]
    fn rejects_as_soon_as_the_sequence_is_complete() {
        // U+D800 as ED A0 80: the third byte completes it, and that is where
        // the error must appear — not at the end of the message.
        let mut v = Utf8::default();
        assert!(v.push(0xED));
        assert!(v.push(0xA0));
        assert!(!v.push(0x80), "surrogate must be rejected on its last byte");
    }

    #[test]
    fn truncated_sequence_is_incomplete_not_invalid() {
        let mut v = Utf8::default();
        assert!(v.push(0xE2), "a lead byte on its own is not yet wrong");
        assert!(!v.is_complete(), "but the sequence is unfinished");
    }
}
