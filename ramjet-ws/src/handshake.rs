//! The HTTP/1.1 upgrade handshake, sans-io like everything else.
//!
//! [`upgrade`] takes the bytes you have read so far and either asks for more or
//! hands back the exact 101 response to write. It does not read, write, or
//! parse HTTP beyond what RFC 6455 §4.2.1 requires of the opening request.
//!
//! # Framing contract
//!
//! An HTTP header block ends at the first `\r\n\r\n`. Until those four bytes
//! arrive, [`upgrade`] returns [`Upgrade::NeedMore`] and consumes nothing, so
//! the caller can simply keep appending to one buffer and calling again. Bytes
//! past the header block belong to the WebSocket stream, not to the request:
//! [`Upgrade::Accept`] reports how many were consumed so you can hand the rest
//! straight to a [`Decoder`](crate::Decoder).

use crate::Error;
use crate::base64;
use crate::sha1::sha1;

/// The magic string from RFC 6455 §1.3. Public, fixed, and the same for
/// everyone — it exists to prove the peer speaks WebSocket, not to keep a
/// secret.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// What a parse attempt found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upgrade {
    /// No complete header block yet. Read more and call again with the longer
    /// buffer; nothing has been consumed.
    NeedMore,
    /// A valid upgrade request.
    Accept {
        /// The 101 response to write back, verbatim.
        response: Vec<u8>,
        /// Bytes of the input the request occupied. Everything after this is
        /// already WebSocket data.
        consumed: usize,
    },
}

/// Compute the `Sec-WebSocket-Accept` value for a client's key.
///
/// `base64(SHA-1(key ++ GUID))`, exactly as RFC 6455 §4.2.2 step 5 spells it.
pub fn accept_key(key: &str) -> String {
    let mut buf = String::with_capacity(key.len() + GUID.len());
    buf.push_str(key);
    buf.push_str(GUID);
    base64::encode(&sha1(buf.as_bytes()))
}

/// Parse an upgrade request and build its response.
///
/// Returns [`Upgrade::NeedMore`] until the header block is complete. Errors
/// with [`Error::Handshake`] when the request is malformed or asks for
/// something other than WebSocket version 13.
pub fn upgrade(bytes: &[u8]) -> Result<Upgrade, Error> {
    let Some(end) = find_header_end(bytes) else {
        return Ok(Upgrade::NeedMore);
    };
    // The header block is ASCII by definition; anything else is not a request
    // this crate is willing to guess at.
    let head = std::str::from_utf8(&bytes[..end - 4])
        .map_err(|_| Error::Handshake("request headers were not valid UTF-8"))?;

    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(Error::Handshake("request line missing"))?;
    check_request_line(request_line)?;

    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut version_ok = false;
    let mut key: Option<&str> = None;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Handshake("header line has no colon"));
        };
        let value = value.trim();
        // Field names are case-insensitive (RFC 7230 §3.2).
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgrade_ok = has_token(value, "websocket"),
            "connection" => connection_ok = has_token(value, "upgrade"),
            "sec-websocket-version" => version_ok = value == "13",
            "sec-websocket-key" if key.is_none() => key = Some(value),
            _ => {}
        }
    }

    if !upgrade_ok {
        return Err(Error::Handshake("Upgrade header is not websocket"));
    }
    if !connection_ok {
        return Err(Error::Handshake(
            "Connection header does not request an upgrade",
        ));
    }
    if !version_ok {
        return Err(Error::Handshake("Sec-WebSocket-Version must be 13"));
    }
    let key = key.ok_or(Error::Handshake("Sec-WebSocket-Key is missing"))?;
    if key.is_empty() {
        return Err(Error::Handshake("Sec-WebSocket-Key is empty"));
    }

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept_key(key)
    );
    Ok(Upgrade::Accept {
        response: response.into_bytes(),
        consumed: end,
    })
}

/// Byte offset just past the first `\r\n\r\n`, if it is there yet.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn check_request_line(line: &str) -> Result<(), Error> {
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("");
    let _target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method != "GET" {
        return Err(Error::Handshake("upgrade request must use GET"));
    }
    // 1.0 has no persistent connection to upgrade.
    if version != "HTTP/1.1" {
        return Err(Error::Handshake("upgrade request must be HTTP/1.1"));
    }
    Ok(())
}

/// Whether a comma-separated header value contains `token`, case-insensitively.
/// `Connection: keep-alive, Upgrade` has to match "upgrade".
fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 6455 §1.3.
    #[test]
    fn rfc6455_accept_vector() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
