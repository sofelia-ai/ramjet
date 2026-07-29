// WebSocket echo server: the ramjet reactor driving the ramjet-ws codec.
// Usage: `ws_echo [PORT]`, default 9001 — the port the Autobahn fuzzingclient
// expects.
//
// The runtime does the I/O and knows nothing about WebSocket; the codec parses
// bytes and knows nothing about sockets. This file is the whole of the glue,
// and it is an example rather than library API on purpose: the shape wants to
// prove itself against Autobahn before any of it hardens into a public type.

use std::collections::HashMap;
use std::env;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};
use ramjet_ws::{Decoder, Event, MessageKind, encode, handshake};

/// Autobahn's 9.x limit cases send messages up to 16 MiB, so the ceiling has to
/// sit above that to echo them rather than refuse them. It still exists: a peer
/// claiming more than this gets a 1009 instead of an allocation.
const MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// What to send when the opening request is not a WebSocket upgrade at all.
const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn main() -> io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9001);

    // 0.0.0.0, not loopback: the Autobahn client runs in a container and
    // reaches the host through host.docker.internal, which resolves to a real
    // interface address. A loopback-only bind is invisible to it.
    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    println!(
        "ramjet ws_echo listening on 0.0.0.0:{}",
        listener.local_addr().port()
    );
    serve(listener.into_raw_fd())
}

/// Reply headers for every payload length that fits a 7-bit length field, one
/// table per opcode. FIN set and the mask bit clear, because a server never
/// masks — so the whole header is decided by the length alone.
const TEXT_HEADERS: [[u8; 2]; 126] = short_headers(0x80 | 0x1);
const BINARY_HEADERS: [[u8; 2]; 126] = short_headers(0x80 | 0x2);

const fn short_headers(first: u8) -> [[u8; 2]; 126] {
    let mut table = [[0u8; 2]; 126];
    let mut len = 0usize;
    while len < 126 {
        table[len] = [first, len as u8];
        len += 1;
    }
    table
}

/// The server's reply header for a `len`-byte payload of this kind: the bytes,
/// and how many of them count.
fn reply_header(kind: MessageKind, len: usize) -> ([u8; 10], usize) {
    let table = match kind {
        MessageKind::Text => &TEXT_HEADERS,
        MessageKind::Binary => &BINARY_HEADERS,
    };
    // Byte 0 is the same for every length in a table: FIN plus the opcode.
    let first = table[0][0];
    let mut out = [0u8; 10];
    if len < 126 {
        out[..2].copy_from_slice(&table[len]);
        (out, 2)
    } else if len <= usize::from(u16::MAX) {
        out[0] = first;
        out[1] = 126;
        out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        (out, 4)
    } else {
        out[0] = first;
        out[1] = 127;
        out[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        (out, 10)
    }
}

/// Write the reply header into the bytes immediately before `payload` and return
/// where it starts, ready to hand to [`Op::WriteFrom`].
///
/// The room is guaranteed rather than hoped for: a client frame is masked, so
/// its header carries a four-byte key the reply does not, and is therefore
/// always exactly four bytes longer than the reply header for the same payload.
/// The assert states that invariant rather than trusting it silently.
fn reply_header_into(buf: &mut [u8], kind: MessageKind, payload: &Range<usize>) -> usize {
    let (header, n) = reply_header(kind, payload.len());
    assert!(
        payload.start >= n,
        "a masked client header is always longer than the reply header, but a \
         {}-byte payload started at {} with a {n}-byte header to write",
        payload.len(),
        payload.start,
    );
    let start = payload.start - n;
    buf[start..payload.start].copy_from_slice(&header[..n]);
    start
}

/// Echo a whole pipelined batch out of the buffer it arrived in, leaving the
/// replies packed into `buf[..returned length]` ready for one single write.
/// Returns false if it took nothing, in which case `buf` is untouched and
/// belongs to the streaming path.
///
/// This is what keeps a pipelining client from costing a write per message. The
/// replies are laid down from the front of the buffer as each frame is unmasked
/// in place, so N messages become one write of one buffer with no allocation and
/// no reassembly anywhere.
///
/// The room is guaranteed, not hoped for. A reply header is exactly four bytes
/// shorter than the masked client header it replaces, so the write cursor starts
/// four bytes behind the first payload and falls four bytes further behind with
/// every frame. The assert states it per frame rather than trusting the
/// induction silently.
fn cork_batch(conn: &mut Conn, buf: &mut Vec<u8>) -> bool {
    let mut written = 0usize;
    let mut from = 0usize;
    loop {
        match conn.decoder.take_frame_at(buf, from) {
            Ok(Some(view)) => {
                let (header, n) = reply_header(view.kind, view.payload.len());
                assert!(
                    written + n <= view.payload.start,
                    "reply {written}+{n} would overwrite a payload starting at {}",
                    view.payload.start,
                );
                buf[written..written + n].copy_from_slice(&header[..n]);
                buf.copy_within(view.payload.clone(), written + n);
                written += n + view.payload.len();
                from = view.payload.end;
            }
            Ok(None) => break,
            Err(e) => {
                // The frames already taken were whole and valid, so their
                // replies stand; the close goes out behind them.
                conn.send_close(e.close_code());
                from = buf.len();
                break;
            }
        }
    }
    if written == 0 {
        return false;
    }
    if from < buf.len() {
        // A partial frame, a fragment or a control frame. Compaction only ever
        // wrote below `from`, so these bytes are exactly as they arrived.
        //
        // Their replies land in `out` and go out on the next write rather than
        // joining this one. ponytail: a control frame arriving mid-batch is rare
        // enough to leave at two writes; merge them if a profile ever says so.
        conn.on_frames(&buf[from..]);
    }
    buf.truncate(written);
    true
}

// A completion carries a `user` tag, so routing one costs no hashing at all:
// the kind of op goes in the high bits and its descriptor in the low 32.
const KIND_ACCEPT: u64 = 0;
const KIND_READ: u64 = 1;
const KIND_WRITE: u64 = 2;
const KIND_CLOSE: u64 = 3;

fn tag(kind: u64, fd: RawFd) -> u64 {
    (kind << 32) | u64::from(fd as u32)
}

fn tag_kind(user: u64) -> u64 {
    user >> 32
}

fn tag_fd(user: u64) -> RawFd {
    (user & 0xFFFF_FFFF) as u32 as RawFd
}

/// One client. Starts out reading an HTTP request and becomes a WebSocket.
struct Conn {
    /// The upgrade request so far. `None` once the handshake has succeeded.
    request: Option<Vec<u8>>,
    decoder: Decoder,
    /// Bytes waiting to go out. Drained into a single Write whenever none is in
    /// flight, which coalesces a burst of frames into one syscall.
    out: Vec<u8>,
    /// The driver allows one Write per fd at a time; this tracks it.
    writing: bool,
    /// Close the socket once `out` has drained — after a Close frame, or after
    /// the 400 for a request that was never an upgrade.
    close_when_flushed: bool,
    /// The conversation is over; anything else the peer says is not our problem.
    ignoring: bool,
}

impl Conn {
    fn new() -> Self {
        Conn {
            request: Some(Vec::new()),
            decoder: Decoder::with_max_message(MAX_MESSAGE),
            out: Vec::new(),
            writing: false,
            close_when_flushed: false,
            ignoring: false,
        }
    }

    /// Take bytes off the socket, in whichever phase this connection is in.
    fn on_bytes(&mut self, bytes: &[u8]) {
        if self.ignoring {
            return;
        }
        if let Some(mut request) = self.request.take() {
            request.extend_from_slice(bytes);
            match handshake::upgrade(&request) {
                // The header block is not complete; keep collecting.
                Ok(handshake::Upgrade::NeedMore) => {
                    self.request = Some(request);
                }
                Ok(handshake::Upgrade::Accept { response, consumed }) => {
                    self.out.extend_from_slice(&response);
                    // A client may pipeline frames right behind the request.
                    // `request` stays taken, so this recurses no further.
                    let leftover = request[consumed..].to_vec();
                    self.on_frames(&leftover);
                }
                Err(_) => {
                    self.out.extend_from_slice(BAD_REQUEST);
                    self.close_when_flushed = true;
                    self.ignoring = true;
                }
            }
            return;
        }
        self.on_frames(bytes);
    }

    fn on_frames(&mut self, bytes: &[u8]) {
        self.decoder.feed(bytes);
        loop {
            match self.decoder.next_event() {
                Ok(Some(event)) => {
                    if self.on_event(event) {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    // The taxonomy already knows which code each failure earns:
                    // 1002 protocol, 1007 bad UTF-8, 1009 too large.
                    self.send_close(e.close_code());
                    return;
                }
            }
        }
    }

    /// Handle one event. Returns true when the conversation is finished.
    fn on_event(&mut self, event: Event) -> bool {
        match event {
            Event::Text(text) => encode::text(&mut self.out, &text),
            Event::Binary(data) => encode::binary(&mut self.out, &data),
            // A Pong carries whatever the Ping did, and the decoder has already
            // enforced the 125-byte limit that is the only way this could fail.
            Event::Ping(payload) => {
                let _ = encode::pong(&mut self.out, &payload);
            }
            // Unsolicited Pongs are legal and mean nothing to an echo server.
            Event::Pong(_) => {}
            Event::Close(frame) => {
                // Echo the peer's code back, or 1000 when it sent none.
                self.send_close(frame.map_or(1000, |f| f.code));
                return true;
            }
        }
        false
    }

    /// Whether an echo can go straight back out of the receive buffer.
    ///
    /// Only when there is nothing else to send first — the reply has to be the
    /// whole of the next write, since `WriteFrom` sends one buffer and the
    /// driver allows one write per fd at a time. The decoder decides separately
    /// whether it holds state that would make a bare buffer meaningless.
    fn can_echo_in_place(&self) -> bool {
        self.request.is_none() && !self.ignoring && !self.writing && self.out.is_empty()
    }

    fn send_close(&mut self, code: u16) {
        // An empty reason always fits inside a control frame.
        let _ = encode::close(&mut self.out, code, "");
        self.close_when_flushed = true;
        self.ignoring = true;
    }
}

/// Submit whatever this connection has pending. Returns true once it has been
/// closed and should be forgotten.
fn pump(fd: RawFd, conn: &mut Conn, d: &mut PlatformDriver) -> io::Result<bool> {
    if conn.writing {
        return Ok(false);
    }
    if !conn.out.is_empty() {
        let buf = std::mem::take(&mut conn.out);
        d.submit_with(Op::Write { fd, buf }, tag(KIND_WRITE, fd))?;
        conn.writing = true;
        return Ok(false);
    }
    if conn.close_when_flushed {
        d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
        return Ok(true);
    }
    Ok(false)
}

fn serve(listener: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut conns: HashMap<RawFd, Conn> = HashMap::new();
    let mut done = Vec::new();

    d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            match tag_kind(c.user) {
                KIND_ACCEPT => match c.result {
                    Ok(fd) => {
                        let fd = fd as RawFd;
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                        conns.insert(fd, Conn::new());
                        d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                    }
                    // The pending connection died before we could take it, which
                    // says nothing about the listener. macOS reports this as
                    // EINVAL rather than ECONNABORTED.
                    Err(ref e)
                        if matches!(
                            e.raw_os_error(),
                            Some(
                                libc::ECONNABORTED | libc::ECONNRESET | libc::EINVAL | libc::EINTR
                            )
                        ) =>
                    {
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                    }
                    // Anything else means the listener itself is unusable and
                    // will fail the same way forever: fail loudly, not in a spin.
                    Err(e) => return Err(e),
                },

                KIND_READ => {
                    let fd = tag_fd(c.user);
                    // A Close already retired this fd and cancelled the read.
                    if matches!(&c.result, Err(e) if e.raw_os_error() == Some(libc::ECANCELED)) {
                        continue;
                    }
                    let Some(conn) = conns.get_mut(&fd) else {
                        if let Some(buf) = c.buf {
                            d.recycle(buf);
                        }
                        continue;
                    };
                    match (c.result, c.buf) {
                        (Ok(n), Some(mut buf)) if n > 0 => {
                            // Zero-copy echo, in two shapes. If the read is
                            // exactly one whole unfragmented data frame, the
                            // payload is already unmasked where it lies, so the
                            // reply is a header written in front of it and a
                            // write from that offset: nothing moves at all.
                            // Failing that, a read holding a pipelined batch of
                            // whole frames is corked — every reply packed into
                            // the front of the same buffer and sent as one
                            // write. Only what neither shape covers — a
                            // fragment, a control frame, a partial read, or a
                            // decoder already mid-message — goes to the
                            // ordinary path.
                            let unclaimed = if conn.can_echo_in_place() {
                                match conn.decoder.take_whole_frame(&mut buf) {
                                    Ok(Some(view)) => {
                                        let start =
                                            reply_header_into(&mut buf, view.kind, &view.payload);
                                        let op = Op::WriteFrom { fd, buf, start };
                                        d.submit_with(op, tag(KIND_WRITE, fd))?;
                                        conn.writing = true;
                                        None
                                    }
                                    Ok(None) if cork_batch(conn, &mut buf) => {
                                        d.submit_with(Op::Write { fd, buf }, tag(KIND_WRITE, fd))?;
                                        conn.writing = true;
                                        None
                                    }
                                    Ok(None) => Some(buf),
                                    Err(e) => {
                                        conn.send_close(e.close_code());
                                        Some(buf)
                                    }
                                }
                            } else {
                                Some(buf)
                            };
                            if let Some(buf) = unclaimed {
                                conn.on_bytes(&buf);
                                d.recycle(buf);
                            }
                            let wants_more = !conn.close_when_flushed;
                            let closed = pump(fd, conn, &mut d)?;
                            if closed {
                                conns.remove(&fd);
                            } else if wants_more {
                                d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                            }
                        }
                        // EOF or a dead connection: hand back buffer and fd both.
                        (_, buf) => {
                            if let Some(buf) = buf {
                                d.recycle(buf);
                            }
                            conns.remove(&fd);
                            d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                        }
                    }
                }

                KIND_WRITE => {
                    let fd = tag_fd(c.user);
                    if let Some(buf) = c.buf {
                        d.recycle(buf);
                    }
                    let Some(conn) = conns.get_mut(&fd) else {
                        continue;
                    };
                    conn.writing = false;
                    if c.result.is_err() {
                        // The peer is gone; nothing left to say to it.
                        conn.out.clear();
                        conn.close_when_flushed = true;
                        conn.ignoring = true;
                    }
                    if pump(fd, conn, &mut d)? {
                        conns.remove(&fd);
                    }
                }

                // A Close completion: the descriptor is already gone.
                _ => {}
            }
        }
    }
}
