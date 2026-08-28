//! Sans-io HTTP/1.1 server codec: bytes in, requests out. It never touches a
//! socket.
//!
//! [`parse`] takes whatever bytes you happened to read — split mid-header,
//! several requests pipelined together, it does not care — and hands back a
//! complete [`Request`] plus how many bytes it occupied, so the caller can
//! slice the buffer and go again. [`encode::response`] appends a response to a
//! `Vec<u8>` you then write however you like. Nothing here spawns, blocks, or
//! knows what a file descriptor is.
//!
//! That makes the crate useful well outside this repository: a tokio user, an
//! embedded event loop, or a test harness feeding canned byte strings can all
//! drive it the same way. It has no dependencies at all.
//!
//! ```
//! use ramjet_http::{Parse, parse, encode};
//!
//! let wire = b"GET /hello HTTP/1.1\r\nHost: example\r\n\r\n";
//!
//! let Parse::Request { request, consumed } = parse(wire).unwrap() else {
//!     panic!("request was complete");
//! };
//! assert_eq!(request.method, "GET");
//! assert_eq!(request.target, "/hello");
//! assert_eq!(consumed, wire.len());
//!
//! let mut out = Vec::new();
//! encode::response(&mut out, 200, &[("Content-Type", "text/plain")], b"hi").unwrap();
//! assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! ```
//!
//! # Scope
//!
//! This is the **server** half of plain HTTP/1.1: request in, response out.
//! Bodies are framed by `Content-Length` only; a request carrying
//! `Transfer-Encoding` is rejected with [`Error::Unsupported`] so the caller
//! can answer 501 instead of misreading the stream. Clients, HTTP/2, and TLS
//! are out of scope, exactly as they are for `ramjet-ws`.

#![forbid(unsafe_code)]

mod parse;

pub mod encode;

pub use parse::{
    MAX_BODY, MAX_HEAD, MAX_HEADERS, Parse, ParseRef, RequestRef, parse, parse_ref, parse_ref_from,
};

use std::fmt;

/// Which HTTP version the request line declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0: connections close by default.
    Http10,
    /// HTTP/1.1: connections persist by default.
    Http11,
}

/// A complete request: head and body, ready to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, verbatim from the request line ("GET", "POST", ...).
    pub method: String,
    /// The request target, verbatim ("/path?query").
    pub target: String,
    /// The declared HTTP version.
    pub version: Version,
    /// Header fields in wire order, names left in their original case.
    /// Look one up with [`Request::header`].
    pub headers: Vec<(String, String)>,
    /// The body, exactly `Content-Length` bytes. Empty when the request had
    /// no body.
    pub body: Vec<u8>,
}

impl Request {
    /// The value of the first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the connection should stay open after the response.
    ///
    /// HTTP/1.1 persists unless the request says `Connection: close`;
    /// HTTP/1.0 closes unless it says `Connection: keep-alive`.
    pub fn keep_alive(&self) -> bool {
        let connections = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value.as_str());
        keep_alive_from(self.version, connections)
    }
}

pub(crate) fn keep_alive_from<'a>(
    version: Version,
    mut values: impl Iterator<Item = &'a str> + Clone,
) -> bool {
    if values.clone().any(|value| has_token(value, "close")) {
        return false;
    }
    match version {
        Version::Http11 => true,
        Version::Http10 => values.any(|value| has_token(value, "keep-alive")),
    }
}

/// Whether a comma-separated header value contains `token`, case-insensitively.
/// `Connection: keep-alive, Upgrade` has to match "upgrade".
pub(crate) fn has_token(value: &str, token: &str) -> bool {
    value.split(',').any(|part| {
        part.trim_matches(|c| c == ' ' || c == '\t')
            .eq_ignore_ascii_case(token)
    })
}

/// Everything that can go wrong reading a request.
///
/// Each variant maps to the status a server should answer with before hanging
/// up; see [`Error::status_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The request broke HTTP framing — a bad request line, a header without
    /// a colon, a Content-Length that is not a number. Status 400.
    Parse(&'static str),
    /// The head or the declared body went past a limit. Raised from the
    /// declared length, before any of those bytes are buffered, so an absurd
    /// length costs the error and nothing else. Status 413.
    TooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// The request was well-formed but asks for something this crate does not
    /// do — chunked transfer encoding, an HTTP version past 1.1. Status 501.
    Unsupported(&'static str),
}

impl Error {
    /// The status code to answer with for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Error::Parse(_) => 400,
            Error::TooLarge { .. } => 413,
            Error::Unsupported(_) => 501,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(why) => write!(f, "http parse error: {why}"),
            Error::TooLarge { limit } => write!(f, "request exceeded the {limit} byte limit"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for Error {}
