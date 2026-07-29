//! Shared helpers: building the masked client frames a decoder expects.
//!
//! Cargo compiles this module separately into every integration test binary, so
//! each one sees whatever it does not use as dead. The allow is about that, not
//! about anything here being unused everywhere.
#![allow(dead_code)]

use ramjet_ws::{Decoder, Error, Event};

pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const BINARY: u8 = 0x2;
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xA;

/// An arbitrary but non-trivial mask — every byte differs, so a decoder that
/// mixed up the mask offset would produce visible garbage.
pub const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// Build one frame as a client would send it: masked, with the shortest length
/// encoding that fits.
pub fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    frame_masked(fin, opcode, payload, Some(MASK))
}

/// Build a frame, optionally unmasked (which a server must reject).
pub fn frame_masked(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Build a frame forcing a particular length encoding, to exercise the
/// non-minimal forms the RFC permits.
pub fn frame_len_encoding(opcode: u8, payload: &[u8], encoding: u8) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    match encoding {
        126 => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        127 => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        _ => out.push(0x80 | payload.len() as u8),
    }
    out.extend_from_slice(&MASK);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
    out
}

/// A close frame payload: big-endian code followed by the reason.
pub fn close_payload(code: u16, reason: &str) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason.as_bytes());
    p
}

/// Feed everything at once and drain every event.
pub fn decode_all(bytes: &[u8]) -> Result<Vec<Event>, Error> {
    let mut d = Decoder::new();
    d.feed(bytes);
    drain(&mut d)
}

/// Pull events until the decoder wants more input.
pub fn drain(d: &mut Decoder) -> Result<Vec<Event>, Error> {
    let mut out = Vec::new();
    while let Some(e) = d.next_event()? {
        out.push(e);
    }
    Ok(out)
}

/// Feed `bytes` in chunks of `n` and drain after each, which is what a real
/// socket does to you.
pub fn decode_chunked(bytes: &[u8], n: usize) -> Result<Vec<Event>, Error> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    for chunk in bytes.chunks(n.max(1)) {
        d.feed(chunk);
        out.extend(drain(&mut d)?);
    }
    Ok(out)
}
