//! Sans-io WebSocket codec: bytes in, events out. It never touches a socket.
//!
//! [`Decoder`] takes whatever bytes you happened to read — split mid-header,
//! several frames coalesced, it does not care — and hands back complete
//! [`Event`]s. [`encode`] appends frames to a `Vec<u8>` you then write however
//! you like. [`handshake`] turns an HTTP upgrade request into the 101 response
//! bytes. Nothing here spawns, blocks, or knows what a file descriptor is.
//!
//! That makes the crate useful well outside this repository: a tokio user, an
//! embedded event loop, or a test harness feeding canned byte strings can all
//! drive it the same way. It has no dependencies at all.
//!
//! ```
//! use ramjet_ws::{Decoder, Event, encode};
//!
//! // A masked client frame carrying "Hi", as it would arrive off the wire.
//! let wire = [0x81, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93];
//!
//! let mut decoder = Decoder::new();
//! decoder.feed(&wire);
//! match decoder.next_event().unwrap() {
//!     Some(Event::Text(s)) => assert_eq!(s, "Hi"),
//!     other => panic!("unexpected: {other:?}"),
//! }
//!
//! // Replies are server-role, so they go out unmasked.
//! let mut out = Vec::new();
//! encode::text(&mut out, "Hi");
//! assert_eq!(out, [0x81, 0x02, b'H', b'i']);
//! ```
//!
//! # Role
//!
//! This is the **server** half. The decoder requires client frames to be masked
//! and rejects unmasked ones; the encoder never masks what it writes. A client
//! needs the mirror of both, which this crate does not provide.

#![forbid(unsafe_code)]

mod base64;
mod decode;
mod mask;
mod sha1;
mod utf8;

pub mod encode;
pub mod handshake;

pub use decode::{DEFAULT_MAX_MESSAGE, Decoder, WholeFrame};

use std::fmt;

/// Which kind of data message this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A text message. Its payload is always valid UTF-8.
    Text,
    /// A binary message. Its payload is arbitrary bytes.
    Binary,
}

/// The payload of a Close frame that carried one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    /// The close code, already checked against the values RFC 6455 allows on
    /// the wire — a decoded one is never 1005, 1006 or another reserved code.
    pub code: u16,
    /// The human-readable reason, possibly empty. Always valid UTF-8.
    pub reason: String,
}

/// Something complete the decoder pulled out of the byte stream.
///
/// Fragmented data messages are reassembled, so `Text` and `Binary` are always
/// whole messages however many frames carried them. Control frames are reported
/// as they arrive, including ones interleaved between a message's fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete text message, validated as UTF-8.
    Text(String),
    /// A complete binary message.
    Binary(Vec<u8>),
    /// A Ping. Echo its payload back in a Pong.
    Ping(Vec<u8>),
    /// A Pong.
    Pong(Vec<u8>),
    /// A Close. `None` means the frame carried no payload at all.
    Close(Option<CloseFrame>),
}

/// Everything that can go wrong reading a stream or a handshake.
///
/// Each variant maps to the close code a server should send before hanging up;
/// see [`Error::close_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The peer broke RFC 6455 — a reserved bit, a bad opcode, an unmasked
    /// client frame, a fragmentation rule. Close code 1002.
    Protocol(&'static str),
    /// A text payload or a close reason was not valid UTF-8. Close code 1007.
    InvalidUtf8,
    /// A message went past the decoder's configured limit. Close code 1009.
    /// Raised from the length header, before any of those bytes are buffered,
    /// so an absurd length costs the error and nothing else.
    TooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// The HTTP upgrade request was malformed, or asked for something this
    /// crate does not do.
    Handshake(&'static str),
}

impl Error {
    /// The RFC 6455 close code to report for this error.
    ///
    /// [`Error::Handshake`] has no real answer — the connection never became a
    /// WebSocket, so there is nothing to close and the reply belongs in HTTP.
    /// It maps to 1002 only so this function can stay total.
    pub fn close_code(&self) -> u16 {
        match self {
            Error::Protocol(_) | Error::Handshake(_) => 1002,
            Error::InvalidUtf8 => 1007,
            Error::TooLarge { .. } => 1009,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol(why) => write!(f, "websocket protocol error: {why}"),
            Error::InvalidUtf8 => write!(f, "payload was not valid UTF-8"),
            Error::TooLarge { limit } => write!(f, "message exceeded the {limit} byte limit"),
            Error::Handshake(why) => write!(f, "bad upgrade request: {why}"),
        }
    }
}

impl std::error::Error for Error {}
