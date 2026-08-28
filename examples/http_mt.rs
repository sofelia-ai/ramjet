// Thread-per-core HTTP hello server. Usage: `http_mt [PORT] [--workers N]`.
//
// The echo_mt shape carrying the http_hello logic: one acceptor thread deals
// descriptors out round-robin over Unix pipes, and each worker runs its own
// reactor over its own share of the connections, sharing nothing else. The
// per-connection code is http_hello's, unchanged: parse_ref straight from the
// read buffer, replies memcpyd from two responses encoded once per worker.

use std::collections::VecDeque;
use std::env;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};
use ramjet_http::{ParseRef, encode, parse_ref_from};

const BODY: &[u8] = b"hello world\n";
const MAX_PENDING_OUT: usize = 256 * 1024;
const MAX_SPARES: usize = 32;
const MAX_SPARE_CAPACITY: usize = 64 * 1024;
const ACCEPT_RESOURCE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// A descriptor number on the wire between acceptor and worker.
const FRAME: usize = 4;

/// More workers than this stops helping on the machines this targets.
const MAX_WORKERS: usize = 8;

fn main() -> io::Result<()> {
    let (port, workers) = parse_args();

    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    let bound = listener.local_addr().port();

    let mut channels = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (mine, theirs) = UnixStream::pair()?;
        // The driver requires non-blocking fds and does not set them itself.
        theirs.set_nonblocking(true)?;
        let worker_fd = theirs.into_raw_fd();
        thread::spawn(move || {
            if let Err(e) = worker(worker_fd) {
                eprintln!("worker exited: {e}");
            }
        });
        channels.push(mine);
    }

    println!("ramjet http_mt listening on 0.0.0.0:{bound} with {workers} workers");
    accept_loop(listener.into_raw_fd(), &mut channels)
}

fn parse_args() -> (u16, usize) {
    let mut port = 8080u16;
    let mut workers = 0usize;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--workers" => workers = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            other => {
                if let Ok(p) = other.parse() {
                    port = p;
                }
            }
        }
    }
    if workers == 0 {
        workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(MAX_WORKERS);
    }
    (port, workers.max(1))
}

/// Accept connections and deal them out round-robin. Runs on the main thread
/// with a reactor of its own, whose only ever op is the next Accept.
fn accept_loop(listener: RawFd, channels: &mut [UnixStream]) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut done = Vec::new();
    let mut next = 0usize;

    let mut accept = d.submit(Op::Accept { fd: listener })?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        let mut retry_accept_with_backoff = false;
        for c in done.drain(..) {
            if c.id != accept {
                continue; // Close completions and the like carry no work
            }
            match c.result {
                Ok(fd) => {
                    let fd = fd as RawFd;
                    let worker = next % channels.len();
                    next = next.wrapping_add(1);
                    hand_off(&mut channels[worker], fd);
                    accept = d.submit(Op::Accept { fd: listener })?;
                }
                // The pending connection died before we could take it, which
                // says nothing about the listener. macOS reports this as EINVAL
                // rather than ECONNABORTED. Drop it and keep serving.
                Err(ref e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::ECONNABORTED | libc::ECONNRESET | libc::EINVAL | libc::EINTR)
                    ) =>
                {
                    accept = d.submit(Op::Accept { fd: listener })?;
                }
                Err(ref e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
                    ) =>
                {
                    retry_accept_with_backoff = true;
                }
                // Anything else means the listener itself is unusable, and it
                // will fail identically forever: fail loudly rather than spin.
                Err(e) => return Err(e),
            }
        }
        if retry_accept_with_backoff {
            thread::sleep(ACCEPT_RESOURCE_BACKOFF);
            accept = d.submit(Op::Accept { fd: listener })?;
        }
    }
}

/// Send one accepted descriptor to a worker. The write blocks, which is fine
/// here and only here: four bytes cannot fill a socket buffer that starts in
/// the kilobytes, so it never actually waits.
fn hand_off(channel: &mut UnixStream, fd: RawFd) {
    if channel.write_all(&fd.to_le_bytes()).is_err() {
        // That worker is gone and nobody else holds this connection.
        // SAFETY: `fd` is ours — we accepted it and never handed it on.
        unsafe { libc::close(fd) };
    }
}

// Completion routing tags, as in http_hello, plus one for the acceptor pipe.
const KIND_READ: u64 = 1;
const KIND_WRITE: u64 = 2;
const KIND_CLOSE: u64 = 3;
const KIND_CHANNEL: u64 = 4;

fn tag(kind: u64, fd: RawFd) -> u64 {
    (kind << 32) | u64::from(fd as u32)
}

fn tag_kind(user: u64) -> u64 {
    user >> 32
}

fn tag_fd(user: u64) -> RawFd {
    (user & 0xFFFF_FFFF) as u32 as RawFd
}

/// The two answers this server ever gives, encoded once per worker.
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

/// One client connection. Identical to http_hello's.
struct Conn {
    spill: Vec<u8>,
    head_scanned: usize,
    out: Vec<u8>,
    writing: bool,
    read_paused: bool,
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
                encode::response(out, e.status_code(), &[("Connection", "close")], &[])
                    .expect("codec status and literal header are valid");
                return (cursor, true);
            }
        }
    }
}

/// Take one read's bytes; spill only an incomplete tail.
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

/// Connections indexed by fd, as in http_hello.
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

/// Submit whatever this connection has pending. Returns true once closed.
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

/// One worker: its own reactor, its own connections, nothing shared.
fn worker(channel: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let replies = Replies::new();
    let mut conns = Slab(Vec::new());
    let mut spares: VecDeque<Vec<u8>> = VecDeque::new();
    let mut done = Vec::new();
    // Descriptor numbers arrive as a byte stream; this holds a split frame.
    let mut partial: Vec<u8> = Vec::new();

    d.submit_with(Op::ReadPooled { fd: channel }, tag(KIND_CHANNEL, channel))?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            match tag_kind(c.user) {
                KIND_CHANNEL => match (c.result, c.buf) {
                    (Ok(n), Some(buf)) if n > 0 => {
                        partial.extend_from_slice(&buf);
                        d.recycle(buf);
                        while partial.len() >= FRAME {
                            let fd = i32::from_le_bytes([
                                partial[0], partial[1], partial[2], partial[3],
                            ]);
                            partial.drain(..FRAME);
                            conns.insert(fd);
                            d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                        }
                        d.submit_with(Op::ReadPooled { fd: channel }, tag(KIND_CHANNEL, channel))?;
                    }
                    // EOF or error on the channel: the acceptor is gone, and
                    // with it any reason for this worker to exist.
                    (_, buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        return Ok(());
                    }
                },

                KIND_READ => {
                    let fd = tag_fd(c.user);
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
    }
}
