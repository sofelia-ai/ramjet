use ramjet_http::{
    Error, MAX_BODY, MAX_HEAD, MAX_HEADERS, Parse, ParseRef, Version, encode, parse, parse_ref,
    parse_ref_from,
};

fn whole(bytes: &[u8]) -> (ramjet_http::Request, usize) {
    match parse(bytes).expect("request should parse") {
        Parse::Request { request, consumed } => (request, consumed),
        Parse::NeedMore => panic!("expected a complete request"),
    }
}

#[test]
fn simple_get() {
    let wire = b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\n\r\n";
    let (request, consumed) = whole(wire);
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/a?b=1");
    assert_eq!(request.version, Version::Http11);
    assert_eq!(request.header("host"), Some("x"));
    assert!(request.body.is_empty());
    assert_eq!(consumed, wire.len());
}

#[test]
fn post_with_body() {
    let wire = b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let (request, consumed) = whole(wire);
    assert_eq!(request.body, b"hello");
    assert_eq!(consumed, wire.len());
}

#[test]
fn trickle_input_needs_more_until_complete() {
    let wire = b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    for cut in 0..wire.len() {
        assert_eq!(parse(&wire[..cut]).unwrap(), Parse::NeedMore, "cut={cut}");
    }
    whole(wire);
}

#[test]
fn resumable_scan_stays_at_the_header_while_a_body_trickles() {
    let head = b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
    let mut wire = head.to_vec();
    wire.extend_from_slice(b"hello");
    let mut scanned = 0;
    let mut body_state = None;

    for cut in 0..wire.len() {
        assert!(
            matches!(
                parse_ref_from(&wire[..cut], &mut scanned).unwrap(),
                ParseRef::NeedMore
            ),
            "cut={cut}"
        );
        if cut >= head.len() {
            match body_state {
                Some(state) => assert_eq!(
                    scanned, state,
                    "body growth must not change the cached framing state"
                ),
                None => body_state = Some(scanned),
            }
        }
    }

    let ParseRef::Request { request, consumed } =
        parse_ref_from(&wire, &mut scanned).expect("complete request")
    else {
        panic!("expected request");
    };
    assert_eq!(request.body, b"hello");
    assert_eq!(consumed, wire.len());
    assert_eq!(scanned, 0, "a complete request resets the scan state");
}

#[test]
fn maximum_body_byte_trickle_reuses_one_cached_framing_state() {
    let head = format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {MAX_BODY}\r\n\r\n");
    let mut wire = Vec::with_capacity(head.len() + MAX_BODY);
    wire.extend_from_slice(head.as_bytes());
    wire.resize(head.len() + MAX_BODY, 0xA5);

    let mut scanned = 0;
    assert!(matches!(
        parse_ref_from(head.as_bytes(), &mut scanned).unwrap(),
        ParseRef::NeedMore
    ));
    let body_state = scanned;
    for cut in head.len() + 1..wire.len() {
        assert!(matches!(
            parse_ref_from(&wire[..cut], &mut scanned).unwrap(),
            ParseRef::NeedMore
        ));
        assert_eq!(scanned, body_state);
    }

    let ParseRef::Request { consumed, .. } = parse_ref_from(&wire, &mut scanned).unwrap() else {
        panic!("expected complete maximum-size request");
    };
    assert_eq!(consumed, wire.len());
    assert_eq!(scanned, 0);
}

#[test]
fn pipelined_requests_slice_and_repeat() {
    let wire = b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let (first, consumed) = whole(&wire);
    assert_eq!(first.target, "/1");
    let (second, rest) = whole(&wire[consumed..]);
    assert_eq!(second.target, "/2");
    assert_eq!(consumed + rest, wire.len());
}

#[test]
fn keep_alive_defaults_by_version() {
    let (r, _) = whole(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(r.keep_alive());
    let (r, _) = whole(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(!r.keep_alive());
    let (r, _) = whole(b"GET / HTTP/1.0\r\n\r\n");
    assert!(!r.keep_alive());
    let (r, _) = whole(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    assert!(r.keep_alive());
}

#[test]
fn duplicate_connection_fields_are_folded_before_keep_alive() {
    let wire = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n";
    let (owned, _) = whole(wire);
    assert!(!owned.keep_alive());

    let ParseRef::Request { request, .. } = parse_ref(wire).unwrap() else {
        panic!("expected request");
    };
    assert!(!request.keep_alive());
}

#[test]
fn http11_requires_exactly_one_host() {
    for wire in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        &b"GET / HTTP/1.1\r\nHost: first\r\nHost: second\r\n\r\n"[..],
    ] {
        assert_eq!(parse(wire).unwrap_err().status_code(), 400);
    }

    // Host was not mandatory in HTTP/1.0.
    whole(b"GET / HTTP/1.0\r\n\r\n");
}

#[test]
fn extension_methods_use_the_full_token_grammar() {
    let (request, _) = whole(b"M-SEARCH * HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(request.method, "M-SEARCH");
    let (request, _) = whole(b"VERSION2 / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(request.method, "VERSION2");
}

#[test]
fn rejects_bad_framing() {
    let cases: &[(&[u8], u16)] = &[
        (b"GET / HTTP/2.0\r\n\r\n", 501),
        (b"GET /\r\n\r\n", 400),
        (b"G@T / HTTP/1.1\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nno-colon\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nContent-Length: +5\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nContent-Length: nope\r\n\r\n", 400),
        (
            b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            400,
        ),
        (b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 501),
    ];
    for (wire, status) in cases {
        let err = parse(wire).expect_err(&format!("{}", String::from_utf8_lossy(wire)));
        assert_eq!(
            err.status_code(),
            *status,
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn rejects_control_bytes_and_non_token_header_names() {
    let cases: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: before\nafter\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: before\rafter\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: before\0after\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nX,Y: value\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding\0: chunked\r\n\r\n",
    ];
    for wire in cases {
        assert_eq!(
            parse(wire).unwrap_err().status_code(),
            400,
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn rejects_non_http_whitespace_around_content_length() {
    for whitespace in ["\u{00a0}", "\u{000b}", "\u{000c}", "\u{0085}", "\u{2003}"] {
        let wire = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length:{whitespace}5{whitespace}\r\n\r\nhello"
        );
        assert_eq!(
            parse(wire.as_bytes()).unwrap_err().status_code(),
            400,
            "U+{:04X} must not be treated as HTTP OWS",
            whitespace.chars().next().unwrap() as u32
        );
    }

    let (request, _) = whole(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\t5 \r\n\r\nhello");
    assert_eq!(request.body, b"hello", "SP and HTAB remain valid OWS");
}

#[test]
fn rejects_whitespace_or_controls_in_the_request_target() {
    for wire in [
        &b"GET /bad\tpath HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &b"GET /bad\x7fpath HTTP/1.1\r\nHost: x\r\n\r\n"[..],
    ] {
        assert_eq!(parse(wire).unwrap_err().status_code(), 400);
    }
}

#[test]
fn duplicate_content_length_with_same_value_is_fine() {
    let wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok";
    let (request, _) = whole(wire);
    assert_eq!(request.body, b"ok");
}

#[test]
fn oversized_head_errors_before_completion() {
    let wire = vec![b'A'; MAX_HEAD + 1];
    assert_eq!(parse(&wire), Err(Error::TooLarge { limit: MAX_HEAD }));
}

#[test]
fn oversized_body_errors_from_the_declared_length() {
    let wire = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY + 1
    );
    // No body bytes buffered — the declared length alone is enough to refuse.
    assert_eq!(
        parse(wire.as_bytes()),
        Err(Error::TooLarge { limit: MAX_BODY })
    );
}

#[test]
fn parse_ref_borrows_and_agrees_with_owned_parse() {
    let wire = b"POST /p?q=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
    let ParseRef::Request { request, consumed } = parse_ref(wire).unwrap() else {
        panic!("expected a complete request");
    };
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/p?q=1");
    assert_eq!(request.header("HOST"), Some("x"));
    assert_eq!(request.body, b"hello");
    assert_eq!(request.headers().len(), 2);
    assert!(request.keep_alive());
    assert_eq!(consumed, wire.len());
    // The borrowed body is a window into the input, not a copy.
    assert_eq!(request.body.as_ptr(), wire[wire.len() - 5..].as_ptr());

    let (owned, owned_consumed) = whole(wire);
    assert_eq!(owned, request.to_owned());
    assert_eq!(owned_consumed, consumed);
}

#[test]
fn header_count_is_capped() {
    let mut wire = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    for i in 0..MAX_HEADERS - 1 {
        wire.push_str(&format!("X-{i}: v\r\n"));
    }
    wire.push_str("\r\n");
    // Exactly at the cap parses; one more is refused.
    whole(wire.as_bytes());
    let over = wire.replace("\r\n\r\n", "\r\nX-Over: v\r\n\r\n");
    let err = parse(over.as_bytes()).unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[test]
fn encode_roundtrips_through_reason_and_length() {
    let mut out = Vec::new();
    encode::response(&mut out, 404, &[("X-Test", "1")], b"gone").unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "HTTP/1.1 404 Not Found\r\nX-Test: 1\r\nContent-Length: 4\r\n\r\ngone"
    );
}

#[test]
fn encode_pipelines_into_one_buffer() {
    let mut out = Vec::new();
    encode::response(&mut out, 200, &[], b"a").unwrap();
    encode::response(&mut out, 204, &[], b"").unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("HTTP/1.1 204 No Content\r\n"));
}

#[test]
fn encode_rejects_injection_and_double_framing_atomically() {
    use encode::EncodeError;

    let cases = [
        (
            200,
            vec![("X-Bad\r\nInjected", "value")],
            EncodeError::InvalidHeaderName,
        ),
        (
            200,
            vec![("X-Test", "safe\r\nSet-Cookie: owned=1")],
            EncodeError::InvalidHeaderValue,
        ),
        (
            200,
            vec![("Content-Length", "1")],
            EncodeError::FramingHeader,
        ),
        (
            200,
            vec![("transfer-encoding", "chunked")],
            EncodeError::FramingHeader,
        ),
        (99, vec![], EncodeError::InvalidStatus(99)),
        (600, vec![], EncodeError::InvalidStatus(600)),
    ];

    for (status, headers, expected) in cases {
        let mut out = b"existing".to_vec();
        assert_eq!(
            encode::response(&mut out, status, &headers, b"body"),
            Err(expected)
        );
        assert_eq!(out, b"existing", "an encoder error must append nothing");
    }
}

#[test]
fn statuses_without_content_emit_no_length_or_body() {
    for status in [100, 199, 204, 304] {
        let mut out = Vec::new();
        encode::response(&mut out, status, &[("X-Test", "ok")], b"must-not-appear").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.ends_with("X-Test: ok\r\n\r\n"),
            "status {status}: {text:?}"
        );
        assert!(
            !text.contains("Content-Length"),
            "status {status}: {text:?}"
        );
        assert!(
            !text.contains("must-not-appear"),
            "status {status}: {text:?}"
        );
    }
}

#[test]
fn head_response_reports_get_length_without_content_bytes() {
    let mut out = Vec::new();
    encode::response_head_only(&mut out, 200, &[("Content-Type", "text/plain")], 12).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\n"
    );
}
