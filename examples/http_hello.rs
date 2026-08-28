// HTTP hello server: the ramjet reactor driving the ramjet-http codec.
// Usage: `http_hello [PORT]`, default 8080.
//
// The runtime does the I/O and knows nothing about HTTP; the codec parses
// bytes and knows nothing about sockets. This file is the whole of the glue.
//
// The hot path is allocation-free: requests are parsed with `parse_ref`
// straight out of the buffer the read completed into, replies are memcpys of
// two responses encoded once at startup, and a whole pipelined batch goes out
// as one write. Only a request split across reads touches the per-connection
// spill buffer.

use std::collections::VecDeque;
use std::env;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};
use ramjet_http::{ParseRef, encode, parse_ref_from};

const BODY: &[u8] = b"hello world\n";
/// Bound queued response memory per connection. One completed read may exceed
/// this watermark once, but no further read is armed until writes catch up.
const MAX_PENDING_OUT: usize = 256 * 1024;
const MAX_SPARES: usize = 32;
const MAX_SPARE_CAPACITY: usize = 64 * 1024;
/// Resource exhaustion completes immediately, so rearming accept without a
/// pause would turn a descriptor attack into a full-core busy loop.
const ACCEPT_RESOURCE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

fn main() -> io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    println!(
        "ramjet http_hello listening on 0.0.0.0:{}",
        listener.local_addr().port()
    );
    serve(listener.into_raw_fd())
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

/// The two answers this server ever gives, encoded once. The keep-alive reply
/// is the entire per-request write cost: one memcpy of these bytes.
struct Replies {
    keep: Vec<u8>,
    close: Vec<u8>,
    head_keep: Vec<u8>,
    head_close: Vec<u8>,
}

impl Replies {
    fn new() -> Self {
        let mut keep = Vec::new();
        encode::response(
            &mut keep,
            200,
            &[("Content-Type", "text/plain"), ("Connection", "keep-alive")],
            BODY,
        )
        .expect("literal keep-alive response");
        let mut close = Vec::new();
        encode::response(
            &mut close,
            200,
            &[("Content-Type", "text/plain"), ("Connection", "close")],
            BODY,
        )
        .expect("literal close response");
        let mut head_keep = Vec::new();
        encode::response_head_only(
            &mut head_keep,
            200,
            &[("Content-Type", "text/plain"), ("Connection", "keep-alive")],
            BODY.len(),
        )
        .expect("literal HEAD keep-alive response");
        let mut head_close = Vec::new();
        encode::response_head_only(
            &mut head_close,
            200,
            &[("Content-Type", "text/plain"), ("Connection", "close")],
            BODY.len(),
        )
        .expect("literal HEAD close response");
        Replies {
            keep,
            close,
            head_keep,
            head_close,
        }
    }
}

/// One client connection.
struct Conn {
    /// Bytes of a request split across reads. Empty in the fast path, where
    /// requests are parsed directly from the read buffer.
    spill: Vec<u8>,
    /// Resumable search position for the current request's header terminator.
    head_scanned: usize,
    /// Bytes waiting to go out. Drained into a single Write whenever none is
    /// in flight, which coalesces pipelined replies into one syscall.
    out: Vec<u8>,
    /// The driver allows one Write per fd at a time; this tracks it.
    writing: bool,
    /// Backpressure: no read is armed while queued replies are above the
    /// watermark. The write completion resumes it after the queue drains.
    read_paused: bool,
    /// Close the socket once `out` has drained — after `Connection: close`,
    /// or after answering a request the codec refused.
    close_when_flushed: bool,
}

impl Conn {
    fn new() -> Self {
        Conn {
            spill: Vec::new(),
            head_scanned: 0,
            out: Vec::new(),
            writing: false,
            read_paused: false,
            close_when_flushed: false,
        }
    }
}

/// Answer every complete request in `data`, appending replies to `out`.
/// Returns how many bytes were consumed and whether the connection is done.
fn respond(
    data: &[u8],
    scanned: &mut usize,
    out: &mut Vec<u8>,
    replies: &Replies,
) -> (usize, bool) {
    let mut cursor = 0;
    loop {
        match parse_ref_from(&data[cursor..], scanned) {
            Ok(ParseRef::NeedMore) => return (cursor, false),
            Ok(ParseRef::Request { request, consumed }) => {
                let keep = request.keep_alive();
                cursor += consumed;
                let head_only = request.method.eq_ignore_ascii_case("HEAD");
                if keep {
                    out.extend_from_slice(if head_only {
                        &replies.head_keep
                    } else {
                        &replies.keep
                    });
                } else {
                    out.extend_from_slice(if head_only {
                        &replies.head_close
                    } else {
                        &replies.close
                    });
                    return (cursor, true);
                }
            }
            Err(e) => {
                // The taxonomy already knows the status each failure earns:
                // 400 malformed, 413 too large, 501 unsupported.
                encode::response(out, e.status_code(), &[("Connection", "close")], &[])
                    .expect("codec status and literal header are valid");
                return (cursor, true);
            }
        }
    }
}

/// Take one read's bytes: fast path parses straight from the read buffer and
/// spills only an incomplete tail; the slow path stitches onto the spill from
/// the previous read and compacts it once, not once per request.
fn on_bytes(conn: &mut Conn, bytes: &[u8], replies: &Replies) {
    if conn.close_when_flushed {
        return;
    }
    if conn.spill.is_empty() {
        let (used, done) = respond(bytes, &mut conn.head_scanned, &mut conn.out, replies);
        conn.close_when_flushed = done;
        if !done && used < bytes.len() {
            conn.spill.extend_from_slice(&bytes[used..]);
        }
    } else {
        conn.spill.extend_from_slice(bytes);
        let (used, done) = respond(&conn.spill, &mut conn.head_scanned, &mut conn.out, replies);
        conn.close_when_flushed = done;
        if used > 0 {
            conn.spill.drain(..used);
        }
    }
}

/// Connections indexed by fd: the kernel hands out low densely-packed
/// descriptors, so a flat Vec beats hashing on every completion.
struct Slab(Vec<Option<Conn>>);

impl Slab {
    fn insert(&mut self, fd: RawFd) {
        let i = fd as usize;
        if i >= self.0.len() {
            self.0.resize_with(i + 1, || None);
        }
        self.0[i] = Some(Conn::new());
    }

    fn get(&mut self, fd: RawFd) -> Option<&mut Conn> {
        self.0.get_mut(fd as usize)?.as_mut()
    }

    fn remove(&mut self, fd: RawFd) {
        if let Some(slot) = self.0.get_mut(fd as usize) {
            *slot = None;
        }
    }
}

/// Submit whatever this connection has pending. Returns true once it has been
/// closed and should be forgotten.
fn pump(
    fd: RawFd,
    conn: &mut Conn,
    spares: &mut VecDeque<Vec<u8>>,
    d: &mut PlatformDriver,
) -> io::Result<bool> {
    if conn.writing {
        return Ok(false);
    }
    if !conn.out.is_empty() {
        // Swap in a spare write buffer rather than leaving a fresh Vec behind,
        // so the next batch of replies appends into warm capacity.
        let mut buf = spares.pop_front().unwrap_or_default();
        std::mem::swap(&mut conn.out, &mut buf);
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

fn recycle_spare(mut buf: Vec<u8>, spares: &mut VecDeque<Vec<u8>>, d: &mut PlatformDriver) {
    buf.clear();
    if buf.capacity() <= MAX_SPARE_CAPACITY && spares.len() < MAX_SPARES {
        spares.push_back(buf);
    } else {
        d.recycle(buf);
    }
}

fn read_after_response(conn: &mut Conn) -> bool {
    if conn.out.len() > MAX_PENDING_OUT {
        conn.read_paused = true;
    }
    !conn.close_when_flushed && !conn.read_paused
}

fn resume_read_after_write(conn: &mut Conn) -> bool {
    let resume = conn.read_paused && conn.out.len() <= MAX_PENDING_OUT && !conn.close_when_flushed;
    if resume {
        conn.read_paused = false;
    }
    resume
}

fn serve(listener: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let replies = Replies::new();
    let mut conns = Slab(Vec::new());
    // Retired write buffers, waiting to carry another batch of replies.
    let mut spares: VecDeque<Vec<u8>> = VecDeque::new();
    let mut done = Vec::new();

    d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        let mut retry_accept_with_backoff = false;
        for c in done.drain(..) {
            match tag_kind(c.user) {
                KIND_ACCEPT => match c.result {
                    Ok(fd) => {
                        let fd = fd as RawFd;
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                        conns.insert(fd);
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
                    Err(ref e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
                        ) =>
                    {
                        retry_accept_with_backoff = true;
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
                    let Some(conn) = conns.get(fd) else {
                        if let Some(buf) = c.buf {
                            d.recycle(buf);
                        }
                        continue;
                    };
                    match (c.result, c.buf) {
                        (Ok(n), Some(buf)) if n > 0 => {
                            on_bytes(conn, &buf, &replies);
                            d.recycle(buf);
                            let wants_more = read_after_response(conn);
                            let closed = pump(fd, conn, &mut spares, &mut d)?;
                            if closed {
                                conns.remove(fd);
                            } else if wants_more {
                                d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                            }
                        }
                        // EOF or a dead connection: hand back buffer and fd both.
                        (_, buf) => {
                            if let Some(buf) = buf {
                                d.recycle(buf);
                            }
                            conns.remove(fd);
                            d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                        }
                    }
                }

                KIND_WRITE => {
                    let fd = tag_fd(c.user);
                    if let Some(buf) = c.buf {
                        recycle_spare(buf, &mut spares, &mut d);
                    }
                    let Some(conn) = conns.get(fd) else {
                        continue;
                    };
                    conn.writing = false;
                    if c.result.is_err() {
                        // The peer is gone; nothing left to say to it.
                        conn.out.clear();
                        conn.close_when_flushed = true;
                    }
                    let resume_read = resume_read_after_write(conn);
                    if pump(fd, conn, &mut spares, &mut d)? {
                        conns.remove(fd);
                    } else if resume_read {
                        d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                    }
                }

                // A Close completion: the descriptor is already gone.
                _ => {}
            }
        }
        if retry_accept_with_backoff {
            std::thread::sleep(ACCEPT_RESOURCE_BACKOFF);
            d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_watermark_pauses_and_resumes_reads() {
        let mut conn = Conn::new();
        conn.out.resize(MAX_PENDING_OUT + 1, 0);
        assert!(!read_after_response(&mut conn));
        assert!(conn.read_paused);

        conn.out.clear();
        assert!(resume_read_after_write(&mut conn));
        assert!(!conn.read_paused);
    }

    #[test]
    fn spare_reservoir_is_count_and_capacity_bounded() {
        let mut d = PlatformDriver::new().expect("driver");
        let mut spares = VecDeque::new();
        for _ in 0..MAX_SPARES * 2 {
            recycle_spare(Vec::new(), &mut spares, &mut d);
        }
        for _ in 0..MAX_SPARES {
            recycle_spare(
                Vec::with_capacity(MAX_SPARE_CAPACITY + 1),
                &mut spares,
                &mut d,
            );
        }
        assert_eq!(spares.len(), MAX_SPARES);
        assert!(
            spares
                .iter()
                .all(|buf| buf.capacity() <= MAX_SPARE_CAPACITY)
        );
    }
}
