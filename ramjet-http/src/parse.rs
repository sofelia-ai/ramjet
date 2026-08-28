//! Request parsing, sans-io like everything else.
//!
//! # Framing contract
//!
//! An HTTP header block ends at the first `\r\n\r\n`; the body is exactly
//! `Content-Length` bytes after it. Until all of that has arrived, [`parse`]
//! returns [`Parse::NeedMore`] and consumes nothing, so the caller can simply
//! keep appending to one buffer and calling again. Bytes past the request
//! belong to the next one: [`Parse::Request`] reports how many were consumed
//! so pipelined requests fall out of a slice-and-repeat loop.
//!
//! [`parse_ref`] is the same parser without the copies: everything it returns
//! borrows straight from the input buffer, so a hot server pays zero
//! allocations per request. [`parse`] is that plus a [`RequestRef::to_owned`],
//! for callers who need the request to outlive the buffer.

use crate::{Error, Request, Version, keep_alive_from};

/// Longest header block the parser will accept before giving up on the peer.
pub const MAX_HEAD: usize = 16 * 1024;

/// Largest `Content-Length` the parser will accept.
pub const MAX_BODY: usize = 1024 * 1024;

/// Most header fields a request may carry. Browsers send around fifteen;
/// a chain of proxies maybe doubles that. Sixty-four is headroom, not a wall
/// anyone honest hits.
pub const MAX_HEADERS: usize = 64;

/// Marker stored in the caller's scan state once the head has been parsed and
/// only body bytes remain. The remaining bits hold the total request length;
/// all accepted requests are far smaller than this bit on 32- and 64-bit
/// targets.
const BODY_PENDING: usize = 1usize << (usize::BITS - 1);

/// What a parse attempt found, owned flavor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    /// No complete request yet. Read more and call again with the longer
    /// buffer; nothing has been consumed.
    NeedMore,
    /// A complete request.
    Request {
        /// The parsed request.
        request: Request,
        /// Bytes of the input the request occupied, body included. Everything
        /// after this belongs to the next request.
        consumed: usize,
    },
}

/// What a parse attempt found, borrowed flavor.
///
/// The `Request` variant is ~2 KiB — the fixed header array lives inline, and
/// boxing it would put an allocation back into the path whose whole point is
/// having none. Returned by value once and not passed around after.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ParseRef<'a> {
    /// No complete request yet; nothing has been consumed.
    NeedMore,
    /// A complete request, borrowing from the input buffer.
    Request {
        /// The parsed request.
        request: RequestRef<'a>,
        /// Bytes of the input the request occupied, body included.
        consumed: usize,
    },
}

/// A complete request whose every part points into the buffer it was parsed
/// from. Costs no allocation at all; call [`RequestRef::to_owned`] if it has
/// to outlive the buffer.
#[derive(Debug, Clone)]
pub struct RequestRef<'a> {
    /// The method, verbatim from the request line ("GET", "POST", ...).
    pub method: &'a str,
    /// The request target, verbatim ("/path?query").
    pub target: &'a str,
    /// The declared HTTP version.
    pub version: Version,
    /// The body, exactly `Content-Length` bytes. Empty when the request had
    /// no body.
    pub body: &'a [u8],
    headers: [(&'a str, &'a str); MAX_HEADERS],
    header_count: usize,
}

impl<'a> RequestRef<'a> {
    /// Header fields in wire order, names left in their original case.
    pub fn headers(&self) -> &[(&'a str, &'a str)] {
        &self.headers[..self.header_count]
    }

    /// The value of the first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    /// Whether the connection should stay open after the response.
    ///
    /// HTTP/1.1 persists unless the request says `Connection: close`;
    /// HTTP/1.0 closes unless it says `Connection: keep-alive`.
    pub fn keep_alive(&self) -> bool {
        let connections = self
            .headers()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| *value);
        keep_alive_from(self.version, connections)
    }

    /// Copy every borrowed part into an owned [`Request`].
    pub fn to_owned(&self) -> Request {
        Request {
            method: self.method.to_string(),
            target: self.target.to_string(),
            version: self.version,
            headers: self
                .headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: self.body.to_vec(),
        }
    }
}

/// Parse one request out of the front of `bytes`, borrowing from it.
///
/// Returns [`ParseRef::NeedMore`] until the head and the whole declared body
/// are present. Errors are terminal for the connection: answer with
/// [`Error::status_code`] and close.
///
pub fn parse_ref(bytes: &[u8]) -> Result<ParseRef<'_>, Error> {
    parse_ref_from(bytes, &mut 0)
}

/// Parse one request while resuming the header-boundary scan from the previous
/// call.
///
/// Keep one `scanned` counter per connection and pass the same value whenever
/// more bytes are appended to that connection's current request. This keeps
/// byte-at-a-time input linear. The counter resets itself after a complete
/// request and is relative to the `bytes` slice passed for that request.
pub fn parse_ref_from<'a>(bytes: &'a [u8], scanned: &mut usize) -> Result<ParseRef<'a>, Error> {
    let pending_total = (*scanned & BODY_PENDING != 0).then_some(*scanned & !BODY_PENDING);
    if let Some(total) = pending_total {
        if bytes.len() < total {
            return Ok(ParseRef::NeedMore);
        }
    }

    let search_from = if pending_total.is_some() {
        0
    } else {
        scanned.saturating_sub(3)
    };
    let Some(end) = find_header_end_from(bytes, search_from) else {
        *scanned = bytes.len();
        if bytes.len() > MAX_HEAD {
            return Err(Error::TooLarge { limit: MAX_HEAD });
        }
        return Ok(ParseRef::NeedMore);
    };
    if end > MAX_HEAD {
        return Err(Error::TooLarge { limit: MAX_HEAD });
    }
    // The header block is ASCII by definition; anything else is not a request
    // this crate is willing to guess at.
    let head = std::str::from_utf8(&bytes[..end - 4])
        .map_err(|_| Error::Parse("request headers were not valid UTF-8"))?;

    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(Error::Parse("request line missing"))?;
    let (method, target, version) = split_request_line(request_line)?;

    let mut headers = [("", ""); MAX_HEADERS];
    let mut header_count = 0usize;
    let mut content_length: Option<usize> = None;
    let mut host_count = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Parse("header line has no colon"));
        };
        // Whitespace before the colon is how request smuggling starts
        // (RFC 7230 §3.2.4 says reject), so no trimming on the name side.
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(Error::Parse("malformed header name"));
        }
        let value = trim_ows(value);
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(Error::Parse("header value contains a control byte"));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // A body framed any way but Content-Length would desync the
            // stream if we guessed; refuse loudly instead.
            return Err(Error::Unsupported("transfer-encoding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n = parse_content_length(value)?;
            match content_length {
                Some(prev) if prev != n => {
                    return Err(Error::Parse("conflicting Content-Length headers"));
                }
                _ => content_length = Some(n),
            }
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
        }
        if header_count == MAX_HEADERS {
            return Err(Error::Parse("more than 64 header fields"));
        }
        headers[header_count] = (name, value);
        header_count += 1;
    }

    if version == Version::Http11 && host_count != 1 {
        return Err(Error::Parse("HTTP/1.1 requires exactly one Host header"));
    }

    let body_len = content_length.unwrap_or(0);
    if body_len > MAX_BODY {
        return Err(Error::TooLarge { limit: MAX_BODY });
    }
    let total = end + body_len;
    if bytes.len() < total {
        // Cache the framing result. Future body-only calls compare one length
        // and do not rescan or reparse the head.
        *scanned = BODY_PENDING | total;
        return Ok(ParseRef::NeedMore);
    }

    *scanned = 0;

    Ok(ParseRef::Request {
        request: RequestRef {
            method,
            target,
            version,
            body: &bytes[end..total],
            headers,
            header_count,
        },
        consumed: total,
    })
}

/// Parse one request out of the front of `bytes`, copying into an owned
/// [`Request`]. Same behavior as [`parse_ref`] plus the copies.
pub fn parse(bytes: &[u8]) -> Result<Parse, Error> {
    match parse_ref(bytes)? {
        ParseRef::NeedMore => Ok(Parse::NeedMore),
        ParseRef::Request { request, consumed } => Ok(Parse::Request {
            request: request.to_owned(),
            consumed,
        }),
    }
}

/// Byte offset just past the first `\r\n\r\n` at or after `start`.
fn find_header_end_from(bytes: &[u8], start: usize) -> Option<usize> {
    let start = start.min(bytes.len());
    bytes[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| start + i + 4)
}

fn split_request_line(line: &str) -> Result<(&str, &str, Version), Error> {
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(Error::Parse("request line has too many parts"));
    }
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(Error::Parse("malformed method"));
    }
    if target.is_empty() {
        return Err(Error::Parse("request target missing"));
    }
    if target.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(Error::Parse("malformed request target"));
    }
    let version = match version {
        "HTTP/1.1" => Version::Http11,
        "HTTP/1.0" => Version::Http10,
        // No version at all is a malformed line, not a version we lack.
        "" => return Err(Error::Parse("request line has too few parts")),
        _ => return Err(Error::Unsupported("http version")),
    };
    Ok((method, target, version))
}

pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|c| c == ' ' || c == '\t')
}

/// Strict digits only: `usize::from_str` would take a leading `+`, and a
/// Content-Length two parsers read differently is a smuggling primitive.
fn parse_content_length(value: &str) -> Result<usize, Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Parse("Content-Length is not a number"));
    }
    value
        .parse()
        .map_err(|_| Error::Parse("Content-Length is not a number"))
}
