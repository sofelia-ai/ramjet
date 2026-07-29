//! Decoder conformance: header edge cases, masking, fragmentation, close codes,
//! UTF-8, and the message ceiling.

mod common;

use common::*;
use ramjet_ws::{CloseFrame, Decoder, Error, Event};

// ---------------------------------------------------------------- headers

#[test]
fn decodes_a_simple_text_frame() {
    let wire = frame(true, TEXT, b"hello");
    assert_eq!(decode_all(&wire).unwrap(), [Event::Text("hello".into())]);
}

#[test]
fn unmasks_a_payload_longer_than_the_mask() {
    // 100 bytes forces the four-byte mask to repeat 25 times; an off-by-one in
    // the mask offset would corrupt everything past the fourth byte.
    let payload: Vec<u8> = (0..100u8).collect();
    let wire = frame(true, BINARY, &payload);
    assert_eq!(decode_all(&wire).unwrap(), [Event::Binary(payload)]);
}

#[test]
fn empty_payloads_are_fine() {
    assert_eq!(
        decode_all(&frame(true, TEXT, b"")).unwrap(),
        [Event::Text(String::new())]
    );
    assert_eq!(
        decode_all(&frame(true, BINARY, b"")).unwrap(),
        [Event::Binary(Vec::new())]
    );
}

#[test]
fn all_three_length_encodings_agree() {
    // 125 is the largest 7-bit length, 126 the smallest 16-bit one, and 65536
    // the smallest 64-bit one.
    for len in [0usize, 1, 125, 126, 127, 65_535, 65_536] {
        let payload = vec![0xA5u8; len];
        let wire = frame(true, BINARY, &payload);
        assert_eq!(
            decode_all(&wire).unwrap(),
            [Event::Binary(payload)],
            "length {len} round-tripped wrong"
        );
    }
}

#[test]
fn non_minimal_length_encodings_are_accepted() {
    // RFC 6455 says the length "MUST" use the minimal form, but a receiver is
    // not asked to police it, and Autobahn expects these to be accepted.
    for encoding in [126u8, 127] {
        let wire = frame_len_encoding(TEXT, b"hi", encoding);
        assert_eq!(
            decode_all(&wire).unwrap(),
            [Event::Text("hi".into())],
            "length encoding {encoding} was rejected"
        );
    }
}

#[test]
fn reserved_bits_are_rejected() {
    for rsv in [0x40u8, 0x20, 0x10, 0x70] {
        let mut wire = frame(true, TEXT, b"x");
        wire[0] |= rsv;
        assert!(
            matches!(decode_all(&wire), Err(Error::Protocol(_))),
            "RSV bits {rsv:#04x} were accepted"
        );
    }
}

#[test]
fn reserved_opcodes_are_rejected() {
    // 0x3-0x7 reserved for future data frames, 0xB-0xF for future control.
    for opcode in [0x3u8, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
        let wire = frame(true, opcode, b"");
        assert!(
            matches!(decode_all(&wire), Err(Error::Protocol(_))),
            "opcode {opcode:#x} was accepted"
        );
    }
}

#[test]
fn unmasked_client_frames_are_rejected() {
    let wire = frame_masked(true, TEXT, b"hello", None);
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));
}

#[test]
fn sixty_four_bit_length_with_the_high_bit_set_is_rejected() {
    let wire = [
        0x82, 0xFF, // binary, masked, 64-bit length
        0x80, 0, 0, 0, 0, 0, 0, 1, // high bit set
        0, 0, 0, 0, // mask
    ];
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));
}

// ------------------------------------------------------------ control frames

#[test]
fn ping_pong_and_close_round_trip() {
    assert_eq!(
        decode_all(&frame(true, PING, b"beat")).unwrap(),
        [Event::Ping(b"beat".to_vec())]
    );
    assert_eq!(
        decode_all(&frame(true, PONG, b"beat")).unwrap(),
        [Event::Pong(b"beat".to_vec())]
    );
    assert_eq!(
        decode_all(&frame(true, CLOSE, b"")).unwrap(),
        [Event::Close(None)]
    );
}

#[test]
fn control_frames_may_not_be_fragmented() {
    for opcode in [CLOSE, PING, PONG] {
        let wire = frame(false, opcode, b"");
        assert!(
            matches!(decode_all(&wire), Err(Error::Protocol(_))),
            "a fragmented control frame {opcode:#x} was accepted"
        );
    }
}

#[test]
fn control_payloads_stop_at_125_bytes() {
    for opcode in [CLOSE, PING, PONG] {
        // A close payload has to start with a valid code, so build its 125
        // bytes as code + 123 bytes of reason rather than filler.
        let at_limit = if opcode == CLOSE {
            close_payload(1000, &"x".repeat(123))
        } else {
            vec![b'x'; 125]
        };
        assert_eq!(at_limit.len(), 125);
        assert!(
            decode_all(&frame(true, opcode, &at_limit)).is_ok(),
            "a 125-byte control frame {opcode:#x} was rejected"
        );

        // One byte over is refused from the header, before the payload means
        // anything, so filler is fine here for every opcode.
        assert!(
            matches!(
                decode_all(&frame(true, opcode, &[b'x'; 126])),
                Err(Error::Protocol(_))
            ),
            "a 126-byte control frame {opcode:#x} was accepted"
        );
    }
}

// ------------------------------------------------------------- fragmentation

#[test]
fn a_fragmented_message_is_reassembled() {
    let mut wire = frame(false, TEXT, b"frag");
    wire.extend(frame(false, CONTINUATION, b"ment"));
    wire.extend(frame(true, CONTINUATION, b"ed"));
    assert_eq!(
        decode_all(&wire).unwrap(),
        [Event::Text("fragmented".into())]
    );
}

#[test]
fn control_frames_interleave_between_fragments() {
    // The sequence Autobahn 5.x checks: a ping in the middle of a message must
    // be reported on its own without disturbing the reassembly.
    let mut wire = frame(false, TEXT, b"data");
    wire.extend(frame(true, PING, b"ping"));
    wire.extend(frame(true, CONTINUATION, b"more"));
    assert_eq!(
        decode_all(&wire).unwrap(),
        [
            Event::Ping(b"ping".to_vec()),
            Event::Text("datamore".into()),
        ]
    );
}

#[test]
fn a_data_frame_inside_an_open_message_is_rejected() {
    let mut wire = frame(false, TEXT, b"open");
    wire.extend(frame(true, TEXT, b"second"));
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));
}

#[test]
fn a_continuation_with_no_message_open_is_rejected() {
    let wire = frame(true, CONTINUATION, b"orphan");
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));

    // Also after a message has been completed and closed out.
    let mut wire = frame(true, TEXT, b"done");
    wire.extend(frame(true, CONTINUATION, b"orphan"));
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));
}

#[test]
fn empty_fragments_are_legal() {
    let mut wire = frame(false, TEXT, b"");
    wire.extend(frame(false, CONTINUATION, b"body"));
    wire.extend(frame(true, CONTINUATION, b""));
    assert_eq!(decode_all(&wire).unwrap(), [Event::Text("body".into())]);
}

// -------------------------------------------------------------- close codes

#[test]
fn every_close_code_boundary() {
    // RFC 6455 §7.4.1 plus the ranges Autobahn 7.9.x probes. 1004 was never
    // assigned; 1005 and 1006 are for local reporting and must never appear on
    // the wire; 1012-2999 are reserved for the RFC and its registry.
    let valid = [
        1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999,
    ];
    let invalid = [
        0u16, 1, 999, 1004, 1005, 1006, 1012, 1013, 1014, 1015, 1016, 1100, 2000, 2999, 5000, 65535,
    ];

    for code in valid {
        let wire = frame(true, CLOSE, &close_payload(code, "bye"));
        assert_eq!(
            decode_all(&wire).unwrap(),
            [Event::Close(Some(CloseFrame {
                code,
                reason: "bye".into()
            }))],
            "close code {code} should be valid"
        );
    }
    for code in invalid {
        let wire = frame(true, CLOSE, &close_payload(code, ""));
        assert!(
            matches!(decode_all(&wire), Err(Error::Protocol(_))),
            "close code {code} should be rejected"
        );
    }
}

#[test]
fn a_one_byte_close_payload_is_rejected() {
    let wire = frame(true, CLOSE, &[0x03]);
    assert!(matches!(decode_all(&wire), Err(Error::Protocol(_))));
}

#[test]
fn a_close_reason_must_be_valid_utf8() {
    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0xF8, 0x88, 0x80, 0x80]);
    let wire = frame(true, CLOSE, &payload);
    assert_eq!(decode_all(&wire), Err(Error::InvalidUtf8));
}

#[test]
fn a_close_with_a_code_and_no_reason_is_fine() {
    let wire = frame(true, CLOSE, &close_payload(1000, ""));
    assert_eq!(
        decode_all(&wire).unwrap(),
        [Event::Close(Some(CloseFrame {
            code: 1000,
            reason: String::new()
        }))]
    );
}

// -------------------------------------------------------------------- UTF-8

#[test]
fn invalid_utf8_in_a_text_message_is_rejected() {
    for bad in [
        vec![0x80],                   // stray continuation
        vec![0xFE],                   // impossible byte
        vec![0xC0, 0x80],             // overlong NUL
        vec![0xE0, 0x80, 0x80],       // overlong
        vec![0xED, 0xA0, 0x80],       // surrogate
        vec![0xF4, 0x90, 0x80, 0x80], // above U+10FFFF
        vec![0xC2],                   // truncated at the end of the message
    ] {
        let wire = frame(true, TEXT, &bad);
        assert_eq!(
            decode_all(&wire),
            Err(Error::InvalidUtf8),
            "{bad:02x?} was accepted as text"
        );
    }
}

#[test]
fn binary_messages_carry_arbitrary_bytes() {
    let payload = vec![0x80, 0xFE, 0xFF, 0x00, 0xC0];
    let wire = frame(true, BINARY, &payload);
    assert_eq!(decode_all(&wire).unwrap(), [Event::Binary(payload)]);
}

#[test]
fn a_code_point_split_across_fragments_is_accepted() {
    // U+00E9 is C3 A9; splitting it between two frames is legal, because only
    // the reassembled message has to be valid.
    let mut wire = frame(false, TEXT, &[b'a', 0xC3]);
    wire.extend(frame(true, CONTINUATION, &[0xA9, b'b']));
    assert_eq!(decode_all(&wire).unwrap(), [Event::Text("aéb".into())]);
}

#[test]
fn invalid_utf8_is_caught_in_the_fragment_that_completes_it() {
    // The surrogate ED A0 80 straddles two fragments. The error must land on
    // the second fragment, not wait for the end of the message — so the message
    // never completes and no event comes out.
    let mut d = Decoder::new();
    d.feed(&frame(false, TEXT, &[0xED, 0xA0]));
    assert_eq!(d.next_event(), Ok(None), "nothing is wrong yet");

    d.feed(&frame(false, CONTINUATION, &[0x80]));
    assert_eq!(
        d.next_event(),
        Err(Error::InvalidUtf8),
        "the byte completing the surrogate must fail immediately"
    );
}

#[test]
fn invalid_utf8_is_caught_mid_frame_before_the_frame_ends() {
    // The whole frame claims 64 bytes but the bad sequence completes in the
    // first three. Fail-fast means erroring here, with 61 bytes still to come.
    let mut payload = vec![0xED, 0xA0, 0x80];
    payload.extend_from_slice(&[b'x'; 61]);
    let wire = frame(true, TEXT, &payload);

    let mut d = Decoder::new();
    d.feed(&wire[..wire.len() - 40]); // header plus the first few payload bytes
    assert_eq!(
        d.next_event(),
        Err(Error::InvalidUtf8),
        "must not wait for the rest of the frame"
    );
}

#[test]
fn the_error_is_sticky() {
    let mut d = Decoder::new();
    d.feed(&frame(true, TEXT, &[0xFF]));
    assert_eq!(d.next_event(), Err(Error::InvalidUtf8));
    // Feeding perfectly good bytes afterwards changes nothing: the stream
    // cannot be resynchronised.
    d.feed(&frame(true, TEXT, b"fine"));
    assert_eq!(d.next_event(), Err(Error::InvalidUtf8));
}

// --------------------------------------------------------------- size limits

#[test]
fn an_oversized_message_is_refused_from_the_header() {
    let mut d = Decoder::with_max_message(1024);
    // Claim 8 MiB but send only the header: the limit must be caught without
    // waiting for, or allocating, the payload.
    let mut wire = vec![0x82, 0xFF];
    wire.extend_from_slice(&(8u64 * 1024 * 1024).to_be_bytes());
    wire.extend_from_slice(&MASK);
    d.feed(&wire);
    assert_eq!(d.next_event(), Err(Error::TooLarge { limit: 1024 }));
}

#[test]
fn fragments_are_counted_against_the_limit_together() {
    let mut d = Decoder::with_max_message(10);
    d.feed(&frame(false, BINARY, &[0u8; 6]));
    assert_eq!(d.next_event(), Ok(None));
    d.feed(&frame(true, CONTINUATION, &[0u8; 6]));
    assert_eq!(d.next_event(), Err(Error::TooLarge { limit: 10 }));
}

#[test]
fn a_message_exactly_at_the_limit_is_allowed() {
    let mut d = Decoder::with_max_message(8);
    d.feed(&frame(true, BINARY, &[7u8; 8]));
    assert_eq!(d.next_event(), Ok(Some(Event::Binary(vec![7u8; 8]))));
}

// ------------------------------------------------------------------ chunking

#[test]
fn split_points_never_change_the_result() {
    let mut wire = frame(false, TEXT, b"hello ");
    wire.extend(frame(true, PING, b"p"));
    wire.extend(frame(true, CONTINUATION, b"world"));
    wire.extend(frame(true, BINARY, &(0..200u8).collect::<Vec<_>>()));
    wire.extend(frame(true, CLOSE, &close_payload(1000, "done")));

    let whole = decode_all(&wire).unwrap();
    assert_eq!(whole.len(), 4);
    for n in 1..=wire.len() {
        assert_eq!(
            decode_chunked(&wire, n).unwrap(),
            whole,
            "chunk size {n} decoded differently"
        );
    }
}

#[test]
fn several_frames_in_one_feed_all_come_out() {
    let mut wire = frame(true, TEXT, b"one");
    wire.extend(frame(true, TEXT, b"two"));
    wire.extend(frame(true, PING, b""));
    assert_eq!(
        decode_all(&wire).unwrap(),
        [
            Event::Text("one".into()),
            Event::Text("two".into()),
            Event::Ping(Vec::new()),
        ]
    );
}
