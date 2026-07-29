//! Upgrade handshake conformance.

use ramjet_ws::{Error, handshake};

const REQUEST: &str = "GET /chat HTTP/1.1\r\n\
     Host: server.example.com\r\n\
     Upgrade: websocket\r\n\
     Connection: Upgrade\r\n\
     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
     Sec-WebSocket-Version: 13\r\n\
     \r\n";

fn accept(bytes: &[u8]) -> (String, usize) {
    match handshake::upgrade(bytes) {
        Ok(handshake::Upgrade::Accept { response, consumed }) => {
            (String::from_utf8(response).unwrap(), consumed)
        }
        other => panic!("expected an accepted upgrade, got {other:?}"),
    }
}

/// The worked example from RFC 6455 §1.3 — request and response both.
#[test]
fn rfc6455_worked_example() {
    assert_eq!(
        handshake::accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );

    let (response, consumed) = accept(REQUEST.as_bytes());
    assert_eq!(consumed, REQUEST.len());
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains("Upgrade: websocket\r\n"));
    assert!(response.contains("Connection: Upgrade\r\n"));
    assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(response.ends_with("\r\n\r\n"), "headers must be terminated");
}

#[test]
fn header_names_and_token_values_are_case_insensitive() {
    let request = "GET / HTTP/1.1\r\n\
         host: x\r\n\
         UPGRADE: WebSocket\r\n\
         CoNnEcTiOn: UPGRADE\r\n\
         sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         SEC-WEBSOCKET-VERSION: 13\r\n\
         \r\n";
    let (response, _) = accept(request.as_bytes());
    assert!(response.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}

#[test]
fn connection_header_may_be_a_token_list() {
    // Browsers behind proxies routinely send "keep-alive, Upgrade".
    let request = REQUEST.replace("Connection: Upgrade", "Connection: keep-alive, Upgrade");
    accept(request.as_bytes());
}

#[test]
fn incomplete_requests_ask_for_more_and_consume_nothing() {
    let bytes = REQUEST.as_bytes();
    for split in 0..bytes.len() {
        assert_eq!(
            handshake::upgrade(&bytes[..split]),
            Ok(handshake::Upgrade::NeedMore),
            "a request cut at {split} should not have been accepted"
        );
    }
    // Only the complete block is enough.
    accept(bytes);
}

#[test]
fn bytes_after_the_header_block_are_left_for_the_decoder() {
    let mut input = REQUEST.as_bytes().to_vec();
    input.extend_from_slice(&[0x81, 0x82, 0x00, 0x00, 0x00, 0x00, b'h', b'i']);
    let (_, consumed) = accept(&input);
    assert_eq!(consumed, REQUEST.len());
    assert_eq!(&input[consumed..], &[0x81, 0x82, 0, 0, 0, 0, b'h', b'i']);
}

#[test]
fn a_missing_or_wrong_field_is_refused() {
    let cases = [
        ("POST /", REQUEST.replace("GET /chat", "POST /chat")),
        ("HTTP/1.0", REQUEST.replace("HTTP/1.1", "HTTP/1.0")),
        (
            "no upgrade header",
            REQUEST.replace("Upgrade: websocket\r\n", ""),
        ),
        (
            "wrong upgrade protocol",
            REQUEST.replace("Upgrade: websocket", "Upgrade: h2c"),
        ),
        (
            "no connection header",
            REQUEST.replace("Connection: Upgrade\r\n", ""),
        ),
        (
            "connection not requesting upgrade",
            REQUEST.replace("Connection: Upgrade", "Connection: keep-alive"),
        ),
        (
            "version 8",
            REQUEST.replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8"),
        ),
        (
            "no key",
            REQUEST.replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""),
        ),
        ("empty key", REQUEST.replace("dGhlIHNhbXBsZSBub25jZQ==", "")),
    ];
    for (what, request) in cases {
        assert!(
            matches!(
                handshake::upgrade(request.as_bytes()),
                Err(Error::Handshake(_))
            ),
            "{what} should have been refused"
        );
    }
}

#[test]
fn a_header_line_without_a_colon_is_refused() {
    let request = REQUEST.replace("Host: server.example.com", "this is not a header");
    assert!(matches!(
        handshake::upgrade(request.as_bytes()),
        Err(Error::Handshake(_))
    ));
}

#[test]
fn handshake_errors_are_not_close_codes_but_stay_total() {
    let err = handshake::upgrade(b"GET / HTTP/1.0\r\n\r\n").unwrap_err();
    assert_eq!(err.close_code(), 1002);
    assert!(err.to_string().contains("upgrade request"));
}

#[test]
fn different_keys_give_different_accepts() {
    // Guards against a hash that ignores its input, which would still pass the
    // single RFC vector if it were hardcoded.
    let a = handshake::accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    let b = handshake::accept_key("x3JJHMbDL1EzLkh9GBhXDw==");
    assert_ne!(a, b);
    assert_eq!(b, "HSmrc0sMlYUkAGmm5OPpG2HaGWk=");
}
