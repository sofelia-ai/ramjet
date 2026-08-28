//! Response encoding: append validated wire bytes to a buffer you own.
//!
//! [`response`] writes one complete HTTP/1.1 response. It owns message framing:
//! callers cannot inject `Content-Length` or `Transfer-Encoding`, and invalid
//! input returns an error before a single byte is appended.

use std::fmt;

use crate::parse::is_tchar;

/// Why a response could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// HTTP status codes are three digits in the inclusive range 100..=599.
    InvalidStatus(u16),
    /// A header name was empty or contained a byte outside the HTTP token set.
    InvalidHeaderName,
    /// A header value contained a control byte forbidden on the wire.
    InvalidHeaderValue,
    /// Response framing belongs to this encoder and cannot be supplied twice.
    FramingHeader,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::InvalidStatus(status) => {
                write!(f, "HTTP status {status} is outside 100..=599")
            }
            EncodeError::InvalidHeaderName => f.write_str("invalid HTTP header name"),
            EncodeError::InvalidHeaderValue => f.write_str("invalid HTTP header value"),
            EncodeError::FramingHeader => {
                f.write_str("Content-Length and Transfer-Encoding are encoder-owned")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Append a complete response to `out`.
///
/// `Content-Length` is added automatically for responses that can carry a
/// body. Informational, 204, and 304 responses emit neither a length nor body,
/// even if `body` is non-empty. Use [`response_head_only`] for a response to a
/// HEAD request.
///
/// Validation is atomic: on `Err`, `out` is unchanged.
pub fn response(
    out: &mut Vec<u8>,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), EncodeError> {
    validate(status, headers)?;
    write_head(out, status, headers);
    if response_has_no_content(status) {
        out.extend_from_slice(b"\r\n");
        return Ok(());
    }
    write_content_length(out, body.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(())
}

/// Append a response to HEAD without writing content bytes.
///
/// For a status that normally carries content, `body_len` is the length that
/// the corresponding GET response would have carried. Statuses that never
/// carry content omit `Content-Length` entirely.
///
/// Validation is atomic: on `Err`, `out` is unchanged.
pub fn response_head_only(
    out: &mut Vec<u8>,
    status: u16,
    headers: &[(&str, &str)],
    body_len: usize,
) -> Result<(), EncodeError> {
    validate(status, headers)?;
    write_head(out, status, headers);
    if !response_has_no_content(status) {
        write_content_length(out, body_len);
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

fn validate(status: u16, headers: &[(&str, &str)]) -> Result<(), EncodeError> {
    if !(100..=599).contains(&status) {
        return Err(EncodeError::InvalidStatus(status));
    }
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(EncodeError::InvalidHeaderName);
        }
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(EncodeError::FramingHeader);
        }
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(EncodeError::InvalidHeaderValue);
        }
    }
    Ok(())
}

fn write_head(out: &mut Vec<u8>, status: u16, headers: &[(&str, &str)]) {
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason(status).as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

fn write_content_length(out: &mut Vec<u8>, body_len: usize) {
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(body_len.to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn response_has_no_content(status: u16) -> bool {
    status < 200 || status == 204 || status == 304
}

/// The standard reason phrase for a status code, empty for ones off the
/// beaten path — the phrase is decorative in HTTP/1.1 and clients ignore it.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "",
    }
}
