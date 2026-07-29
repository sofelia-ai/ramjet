// Single-threaded echo server on the ramjet reactor. Usage: `echo [PORT]`.
// Plain `//` and not `//!`: tests/echo.rs include!s this file into a module,
// where an inner doc comment is not a legal item.

use std::collections::HashMap;
use std::env;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op, OpId};

fn main() -> io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);
    // ramjet's own socket, not std's: already non-blocking, as the driver needs.
    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    println!(
        "ramjet echo listening on 127.0.0.1:{}",
        listener.local_addr().port()
    );
    serve(listener.into_raw_fd())
}

/// What an op was, so its completion can be routed — a `Completion` carries only an id.
enum Job {
    Accept,
    Read(RawFd),
    Write(RawFd),
}

/// Echo loop over `listener`. Only returns if the driver itself fails.
pub fn serve(listener: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut jobs: HashMap<OpId, Job> = HashMap::new();
    let mut done = Vec::new();

    jobs.insert(d.submit(Op::Accept { fd: listener })?, Job::Accept);

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            match jobs.remove(&c.id) {
                Some(Job::Accept) => match c.result {
                    Ok(fd) => {
                        let fd = fd as RawFd;
                        jobs.insert(d.submit(Op::Accept { fd: listener })?, Job::Accept);
                        // Pooled: this connection holds no read buffer until it
                        // actually has something to read.
                        jobs.insert(d.submit(Op::ReadPooled { fd })?, Job::Read(fd));
                    }
                    // The pending connection died before we could take it, which
                    // says nothing about the listener. macOS reports this as
                    // EINVAL rather than ECONNABORTED (measured: 141 of 400
                    // reset-before-accept clients). Drop it and keep serving.
                    Err(ref e)
                        if matches!(
                            e.raw_os_error(),
                            Some(
                                libc::ECONNABORTED | libc::ECONNRESET | libc::EINVAL | libc::EINTR
                            )
                        ) =>
                    {
                        jobs.insert(d.submit(Op::Accept { fd: listener })?, Job::Accept);
                    }
                    // Anything else means the listener itself is unusable. EBADF
                    // and friends fail identically forever, so resubmitting
                    // would spin this loop at 100% CPU; fail loudly instead.
                    Err(e) => return Err(e),
                },
                Some(Job::Read(fd)) => match (c.result, c.buf) {
                    // A pooled buffer arrives trimmed to the bytes read, so it
                    // goes into the Write whole, and comes back on its
                    // completion.
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
