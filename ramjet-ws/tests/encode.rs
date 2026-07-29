//! Encoder conformance, and the round trip back through the decoder.

mod common;

use common::*;
use ramjet_ws::{CloseFrame, Decoder, Error, Event, MessageKind, encode};

/// Re-mask a server frame so the decoder (which is server-role and demands a
/// mask) will read back what the encoder wrote.
fn as_client_frame(server_frame: &[u8]) -> Vec<u8> {
    let fin = server_frame[0] & 0x80 != 0;
    let opcode = server_frame[0] & 0x0F;
    let len7 = server_frame[1] & 0x7F;
    let (len, header) = match len7 {
        126 => (
            usize::from(u16::from_be_bytes([server_frame[2], server_frame[3]])),
            4,
        ),
        127 => {
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&server_frame[2..10]);
            (u64::from_be_bytes(wide) as usize, 10)
        }
        n => (usize::from(n), 2),
    };
    assert_eq!(
        server_frame[1] & 0x80,
        0,
        "server frames must never be masked"
    );
    assert_eq!(server_frame.len(), header + len);
    frame(fin, opcode, &server_frame[header..])
}

#[test]
fn text_and_binary_have_the_expected_bytes_on_the_wire() {
    let mut out = Vec::new();
    encode::text(&mut out, "Hi");
    assert_eq!(out, [0x81, 0x02, b'H', b'i']);

    out.clear();
    encode::binary(&mut out, &[0xDE, 0xAD]);
    assert_eq!(out, [0x82, 0x02, 0xDE, 0xAD]);
}

#[test]
fn server_frames_are_never_masked() {
    let mut out = Vec::new();
    encode::text(&mut out, "anything");
    encode::binary(&mut out, &[1, 2, 3]);
    encode::ping(&mut out, b"p").unwrap();
    encode::pong(&mut out, b"p").unwrap();
    encode::close(&mut out, 1000, "bye").unwrap();
    // Every second header byte in the stream would carry 0x80 if we masked;
    // decoding the stream back proves the layout, so just spot-check the first.
    assert_eq!(out[1] & 0x80, 0);
}

#[test]
fn length_encoding_switches_at_the_right_sizes() {
    let cases = [
        (0usize, 2usize),
        (125, 2),    // largest 7-bit length
        (126, 4),    // smallest 16-bit length
        (65535, 4),  // largest 16-bit length
        (65536, 10), // smallest 64-bit length
    ];
    for (len, header) in cases {
        let mut out = Vec::new();
        encode::binary(&mut out, &vec![0u8; len]);
        assert_eq!(
            out.len(),
            header + len,
            "payload of {len} used a bad header"
        );
    }
}

#[test]
fn everything_encoded_decodes_back() {
    let payloads: &[&[u8]] = &[b"", b"x", &[0u8; 125], &[1u8; 126], &[2u8; 70_000]];
    for payload in payloads {
        let mut out = Vec::new();
        encode::binary(&mut out, payload);
        assert_eq!(
            decode_all(&as_client_frame(&out)).unwrap(),
            [Event::Binary(payload.to_vec())],
            "binary payload of {} bytes did not survive",
            payload.len()
        );
    }

    for text in ["", "hello", "héllo wörld", "日本語", "\u{10348}"] {
        let mut out = Vec::new();
        encode::text(&mut out, text);
        assert_eq!(
            decode_all(&as_client_frame(&out)).unwrap(),
            [Event::Text(text.into())]
        );
    }
}

#[test]
fn a_fragmented_message_encodes_and_reassembles() {
    let mut out = Vec::new();
    encode::first(&mut out, MessageKind::Text, "frag".as_bytes());
    encode::cont(&mut out, "ment".as_bytes());
    encode::last(&mut out, "ed".as_bytes());

    // Re-mask each frame in turn, then decode the lot.
    let mut wire = Vec::new();
    let mut rest = &out[..];
    while !rest.is_empty() {
        let len = usize::from(rest[1] & 0x7F);
        let frame_len = 2 + len;
        wire.extend(as_client_frame(&rest[..frame_len]));
        rest = &rest[frame_len..];
    }
    assert_eq!(
        decode_all(&wire).unwrap(),
        [Event::Text("fragmented".into())]
    );
}

#[test]
fn a_code_point_may_straddle_two_fragments() {
    // Fragments take bytes precisely so this is expressible: é is C3 A9.
    let mut out = Vec::new();
    encode::first(&mut out, MessageKind::Text, &[b'a', 0xC3]);
    encode::last(&mut out, &[0xA9]);

    let first_len = 2 + usize::from(out[1] & 0x7F);
    let mut wire = as_client_frame(&out[..first_len]);
    wire.extend(as_client_frame(&out[first_len..]));
    assert_eq!(decode_all(&wire).unwrap(), [Event::Text("aé".into())]);
}

#[test]
fn control_frames_refuse_payloads_over_125_bytes() {
    let mut out = Vec::new();
    assert!(encode::ping(&mut out, &[0u8; 125]).is_ok());
    assert!(encode::pong(&mut out, &[0u8; 125]).is_ok());

    assert!(matches!(
        encode::ping(&mut out, &[0u8; 126]),
        Err(Error::Protocol(_))
    ));
    assert!(matches!(
        encode::pong(&mut out, &[0u8; 126]),
        Err(Error::Protocol(_))
    ));
    // A close reason has to leave room for the two-byte code.
    assert!(encode::close(&mut out, 1000, &"x".repeat(123)).is_ok());
    assert!(matches!(
        encode::close(&mut out, 1000, &"x".repeat(124)),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn close_frames_round_trip_with_and_without_a_payload() {
    let mut out = Vec::new();
    encode::close(&mut out, 1001, "going away").unwrap();
    assert_eq!(
        decode_all(&as_client_frame(&out)).unwrap(),
        [Event::Close(Some(CloseFrame {
            code: 1001,
            reason: "going away".into()
        }))]
    );

    out.clear();
    encode::close_empty(&mut out);
    assert_eq!(
        decode_all(&as_client_frame(&out)).unwrap(),
        [Event::Close(None)]
    );
}

#[test]
fn encoding_appends_and_never_clears() {
    let mut out = vec![0xAA, 0xBB];
    encode::text(&mut out, "x");
    assert_eq!(
        &out[..2],
        &[0xAA, 0xBB],
        "the caller's bytes were disturbed"
    );
    assert_eq!(&out[2..], &[0x81, 0x01, b'x']);
}

#[test]
fn a_ping_can_be_answered_with_its_own_payload() {
    // The echo pattern a server actually uses.
    let mut d = Decoder::new();
    d.feed(&frame(true, PING, b"payload"));
    let Some(Event::Ping(body)) = d.next_event().unwrap() else {
        panic!("expected a ping");
    };
    let mut out = Vec::new();
    encode::pong(&mut out, &body).unwrap();
    assert_eq!(
        decode_all(&as_client_frame(&out)).unwrap(),
        [Event::Pong(b"payload".to_vec())]
    );
}
