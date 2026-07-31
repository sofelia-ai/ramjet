// Single-threaded echo server on the ramjet reactor.
// Usage: `echo [PORT] [BIND_IP]`.
// Plain `//` and not `//!`: tests/echo.rs include!s this file into a module,
// where an inner doc comment is not a legal item.

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let port = args
        .next()
        .map(|value| {
            value.parse::<u16>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid port: {value}"),
                )
            })
        })
        .transpose()?
        .unwrap_or(9000);
    let bind_ip = args
        .next()
        .map(|value| {
            value.parse::<IpAddr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid bind IP: {value}"),
                )
            })
        })
        .transpose()?
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    if let Some(extra) = args.next() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unexpected argument: {extra}"),
        ));
    }
    // ramjet's own socket, not std's: already non-blocking, as the driver needs.
    let listener = Listener::bind(SocketAddr::new(bind_ip, port))?;
    println!("ramjet echo listening on {}", listener.local_addr());
    serve(listener.into_raw_fd())
}

// The kernel already carries 64 bits of application data beside every
// completion. Keep the operation kind in the high half and the descriptor in
// the low half, so routing is two shifts instead of a hash-table lookup.
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

/// Echo loop over `listener`. Only returns if the driver itself fails.
pub fn serve(listener: RawFd) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut done = Vec::new();

    d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            let kind = tag_kind(c.user);
            let fd = tag_fd(c.user);

            match kind {
                KIND_ACCEPT => match c.result {
                    Ok(fd) => {
                        let fd = fd as RawFd;
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                        // Pooled: this connection holds no read buffer until it
                        // actually has something to read.
                        d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
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
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                    }
                    // Anything else means the listener itself is unusable. EBADF
                    // and friends fail identically forever, so resubmitting
                    // would spin this loop at 100% CPU; fail loudly instead.
                    Err(e) => return Err(e),
                },
                KIND_READ => match (c.result, c.buf) {
                    // A pooled buffer arrives trimmed to the bytes read, so it
                    // goes into the Write whole, and comes back on its
                    // completion.
                    (Ok(n), Some(buf)) if n > 0 => {
                        d.submit_with(Op::Write { fd, buf }, tag(KIND_WRITE, fd))?;
                    }
                    // A Close already retired this fd and cancelled the read.
                    // Closing again would hit whatever has reused the number.
                    (Err(ref e), _) if e.raw_os_error() == Some(libc::ECANCELED) => {}
                    // EOF or a dead connection: hand back buffer and fd both.
                    (_, buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                    }
                },
                KIND_WRITE => match (c.result, c.buf) {
                    (Ok(_), buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                    }
                    (Err(_), buf) => {
                        if let Some(buf) = buf {
                            d.recycle(buf);
                        }
                        d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                    }
                },
                KIND_CLOSE => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("completion carried unknown operation tag {kind}"),
                    ));
                }
            }
        }
    }
}
