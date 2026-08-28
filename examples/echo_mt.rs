// Thread-per-core echo server. Usage: `echo_mt [PORT] [--workers N]`.
//
// Pillar 2, the shape macOS actually allows. Linux fans connections out across
// several sockets bound to one address (`SO_REUSEPORT`), and FreeBSD does the
// same with `SO_REUSEPORT_LB`; macOS has neither — it permits the extra binds
// but hands every connection to the last binder (measured: 30 of 30). So the
// fan-out happens in userspace instead: one acceptor thread hands each accepted
// descriptor to a worker, and each worker runs its own reactor over its own
// share of the connections, sharing nothing else.
//
// This is an example, not library API. It exists to prove the shape works
// before anything gets promoted into `ramjet`.

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op, OpId};

/// A descriptor number on the wire between acceptor and worker.
const FRAME: usize = 4;

/// More workers than this stops helping on the machines this targets.
const MAX_WORKERS: usize = 8;
const ACCEPT_RESOURCE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

fn main() -> io::Result<()> {
    let (port, workers) = parse_args();

    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let bound = listener.local_addr().port();

    // One channel per worker. The acceptor keeps the near end and writes
    // descriptor numbers into it; the far end is the worker's only wakeup
    // source, parked in its reactor like any other read.
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

    println!("ramjet echo_mt listening on 127.0.0.1:{bound} with {workers} workers");
    accept_loop(listener.into_raw_fd(), &mut channels)
}

fn parse_args() -> (u16, usize) {
    let mut port = 9000u16;
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

/// Send one accepted descriptor to a worker.
///
/// The number crosses the thread boundary as a plain integer, which is all a
/// descriptor is: the table it indexes belongs to the process, not to a thread,
/// so the worker's reactor can use it directly with nothing to hand over.
///
/// The write blocks, which is fine here and only here: four bytes cannot fill a
/// socket buffer that starts in the kilobytes, so it never actually waits.
fn hand_off(channel: &mut UnixStream, fd: RawFd) {
    if channel.write_all(&fd.to_le_bytes()).is_err() {
        // That worker is gone and nobody else holds this connection.
        // SAFETY: `fd` is ours — we accepted it and never handed it on.
        unsafe { libc::close(fd) };
    }
}

/// What an op was, so its completion can be routed — a `Completion` carries only an id.
enum Job {
    /// The channel from the acceptor, carrying descriptor numbers.
    Channel,
    Read(RawFd),
    Write(RawFd),
}

/// One worker: its own reactor, its own connections, nothing shared.
///
/// `PlatformDriver` is `!Send` by design, so it is built here rather than handed
/// in. Only the channel descriptor crosses the thread boundary.
fn worker(channel: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut jobs: HashMap<OpId, Job> = HashMap::new();
    let mut done = Vec::new();
    // Descriptor numbers arrive as a byte stream, so a frame can be split
    // across reads and several can arrive in one. This holds the remainder.
    let mut partial: Vec<u8> = Vec::new();

    jobs.insert(d.submit(Op::ReadPooled { fd: channel })?, Job::Channel);

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            match jobs.remove(&c.id) {
                Some(Job::Channel) => match (c.result, c.buf) {
                    (Ok(n), Some(buf)) if n > 0 => {
                        partial.extend_from_slice(&buf);
                        d.recycle(buf);
                        while partial.len() >= FRAME {
                            let fd = i32::from_le_bytes([
                                partial[0], partial[1], partial[2], partial[3],
                            ]);
                            partial.drain(..FRAME);
                            jobs.insert(d.submit(Op::ReadPooled { fd })?, Job::Read(fd));
                        }
                        jobs.insert(d.submit(Op::ReadPooled { fd: channel })?, Job::Channel);
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
                Some(Job::Read(fd)) => match (c.result, c.buf) {
                    // A pooled buffer arrives trimmed to the bytes read, so it
                    // goes into the Write whole and comes back on its completion.
                    (Ok(n), Some(buf)) if n > 0 => {
                        jobs.insert(d.submit(Op::Write { fd, buf })?, Job::Write(fd));
                    }
                    // A Close already retired this fd and cancelled the read.
                    // Closing again would hit whatever has reused the number.
                    (Err(ref e), _) if e.raw_os_error() == Some(libc::ECANCELED) => {}
                    // EOF or a dead connection: hand back buffer and fd both.
                    (_, buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        d.submit(Op::Close { fd })?;
                    }
                },
                Some(Job::Write(fd)) => match (c.result, c.buf) {
                    (Ok(_), buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        jobs.insert(d.submit(Op::ReadPooled { fd })?, Job::Read(fd));
                    }
                    (Err(_), buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        d.submit(Op::Close { fd })?;
                    }
                },
                // Close completions carry no job.
                None => {}
            }
        }
    }
}
