//! Frame encoding, server role.
//!
//! Every function appends to a `Vec<u8>` you own and hands back nothing — there
//! is no internal buffer, no flushing, and no I/O. Write the vector out however
//! your runtime does that.
//!
//! Server frames are never masked (RFC 6455 §5.1), so nothing here takes a
//! masking key.

use crate::{Error, MessageKind};

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Largest payload a control frame may carry.
const MAX_CONTROL: usize = 125;

/// Append a frame header. The mask bit stays clear: this is the server side.
fn header(out: &mut Vec<u8>, fin: bool, opcode: u8, len: usize) {
    out.push(if fin { 0x80 | opcode } else { opcode });
    if len < 126 {
        out.push(len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
}

fn frame(out: &mut Vec<u8>, fin: bool, opcode: u8, payload: &[u8]) {
    header(out, fin, opcode, payload.len());
    out.extend_from_slice(payload);
}

fn control(out: &mut Vec<u8>, opcode: u8, payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_CONTROL {
        return Err(Error::Protocol("control frame payload exceeds 125 bytes"));
    }
    frame(out, true, opcode, payload);
    Ok(())
}

/// Append a complete text message as one frame.
pub fn text(out: &mut Vec<u8>, payload: &str) {
    frame(out, true, OP_TEXT, payload.as_bytes());
}

/// Append a complete binary message as one frame.
pub fn binary(out: &mut Vec<u8>, payload: &[u8]) {
    frame(out, true, OP_BINARY, payload);
}

/// Append the first frame of a fragmented message.
///
/// Fragments take bytes rather than `&str` even for a text message, because a
/// code point may straddle the boundary between two of them — only the
/// reassembled whole has to be valid UTF-8.
///
/// Follow with any number of [`cont`] and exactly one [`last`].
pub fn first(out: &mut Vec<u8>, kind: MessageKind, payload: &[u8]) {
    let opcode = match kind {
        MessageKind::Text => OP_TEXT,
        MessageKind::Binary => OP_BINARY,
    };
    frame(out, false, opcode, payload);
}

/// Append a middle frame of a fragmented message.
pub fn cont(out: &mut Vec<u8>, payload: &[u8]) {
    frame(out, false, OP_CONTINUATION, payload);
}

/// Append the final frame of a fragmented message.
pub fn last(out: &mut Vec<u8>, payload: &[u8]) {
    frame(out, true, OP_CONTINUATION, payload);
}

/// Append a Ping.
///
/// Fails if `payload` is longer than 125 bytes, which no control frame may be.
pub fn ping(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), Error> {
    control(out, OP_PING, payload)
}

/// Append a Pong. Answer a [`crate::Event::Ping`] by echoing its payload here.
///
/// Fails if `payload` is longer than 125 bytes.
pub fn pong(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), Error> {
    control(out, OP_PONG, payload)
}

/// Append a Close carrying `code` and `reason`.
///
/// Fails if the reason does not leave room for the code inside 125 bytes, so
/// `reason` may be at most 123 bytes.
pub fn close(out: &mut Vec<u8>, code: u16, reason: &str) -> Result<(), Error> {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    control(out, OP_CLOSE, &payload)
}

/// Append a Close with no payload at all, which is what to send when there is
/// nothing useful to say about why.
pub fn close_empty(out: &mut Vec<u8>) {
    frame(out, true, OP_CLOSE, &[]);
}
