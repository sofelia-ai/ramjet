//! A completion-based networking runtime: submit an operation, harvest a
//! completion. That is the io_uring mental model, and it is the model here on
//! every platform — io_uring on Linux, kqueue on macOS and BSD, behind one
//! [`reactor::Driver`] trait and the [`reactor::PlatformDriver`] alias.
//!
//! The library depends on `libc` and nothing else.
//!
//! # What this is, and is not
//!
//! This is the **low-level engine**. You drive the reactor yourself, as the
//! example below does. There is no `listen().await`, no executor, no task
//! spawning — if you want those, this is not that library yet.
//!
//! What you get instead is a small, explicit API with no hidden allocation and
//! no work stealing, which is where the performance comes from: roughly one
//! syscall per thousand requests under load, and about 516 bytes of memory per
//! idle connection.
//!
//! # An echo server
//!
//! ```no_run
//! use std::io;
//! use std::net::{Ipv4Addr, SocketAddr};
//! use std::os::fd::{IntoRawFd, RawFd};
//!
//! use ramjet::net::Listener;
//! use ramjet::reactor::{Driver, Op, PlatformDriver};
//!
//! // A completion carries back whatever `user` tag its submission had, so an
//! // op can route itself. Pack the kind and the fd into those 64 bits and no
//! // lookup table is needed at all.
//! const ACCEPT: u64 = 0;
//! const READ: u64 = 1;
//! const WRITE: u64 = 2;
//!
//! fn tag(kind: u64, fd: RawFd) -> u64 {
//!     (kind << 32) | (fd as u32 as u64)
//! }
//!
//! fn main() -> io::Result<()> {
//!     // ramjet's own listener: socket options are applied before bind(2), and
//!     // the socket arrives non-blocking, which the driver requires.
//!     let listener = Listener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 9000)))?;
//!     let lfd = listener.into_raw_fd();
//!
//!     let mut d = PlatformDriver::new()?;
//!     d.submit_with(Op::Accept { fd: lfd }, tag(ACCEPT, lfd))?;
//!
//!     let mut done = Vec::new();
//!     loop {
//!         // Blocks until at least one op finishes, then drains everything
//!         // that is ready. Empty means nothing is in flight any more.
//!         d.wait(&mut done)?;
//!         if done.is_empty() {
//!             return Ok(());
//!         }
//!
//!         for c in done.drain(..) {
//!             let kind = c.user >> 32;
//!             let fd = c.user as u32 as RawFd;
//!
//!             match (kind, c.result) {
//!                 // A new connection: re-arm the accept, then read from it.
//!                 (ACCEPT, Ok(conn)) => {
//!                     let conn = conn as RawFd;
//!                     d.submit_with(Op::Accept { fd: lfd }, tag(ACCEPT, lfd))?;
//!                     // Pooled: this connection owns no buffer while it waits.
//!                     // The kernel picks one only when bytes actually arrive.
//!                     d.submit_with(Op::ReadPooled { fd: conn }, tag(READ, conn))?;
//!                 }
//!
//!                 // Bytes arrived. A pooled read hands back its buffer trimmed
//!                 // to exactly what was read, so `buf` *is* the data.
//!                 (READ, Ok(n)) if n > 0 => {
//!                     let buf = c.buf.expect("a pooled read returns its buffer");
//!                     d.submit_with(Op::Write { fd, buf }, tag(WRITE, fd))?;
//!                 }
//!
//!                 // Reply flushed: hand the buffer back and read again.
//!                 (WRITE, Ok(_)) => {
//!                     if let Some(buf) = c.buf {
//!                         d.recycle(buf);
//!                     }
//!                     d.submit_with(Op::ReadPooled { fd }, tag(READ, fd))?;
//!                 }
//!
//!                 // A read of 0 is EOF; anything else here is a dead peer.
//!                 _ => {
//!                     d.submit(Op::Close { fd })?;
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! Run that and `nc 127.0.0.1 9000` echoes. The same shape drives the
//! WebSocket and TLS examples in the repository.
//!
//! # The pieces
//!
//! - [`reactor`] — the [`Driver`](reactor::Driver) trait, its two backends, and
//!   the [`Op`](reactor::Op) set: `Accept`, `Read`, `ReadPooled`, `Write`,
//!   `WriteFrom`, `Close`.
//! - [`net`] — listeners that apply socket options *before* `bind(2)`, which
//!   `std::net` gives no opportunity to do. `SO_REUSEPORT` needs exactly that.
//!
//! For WebSocket framing see the companion crate `ramjet-ws`: sans-io, zero
//! dependencies, and it knows nothing about this runtime.
//!
//! # Two rules worth knowing
//!
//! Every fd handed to the driver inside an [`Op`](reactor::Op) must already be
//! non-blocking. Sockets from [`net::Listener`] and from `Accept` already are.
//!
//! A completion is delivered exactly once per submitted op, and buffers travel
//! by ownership: submit a `Vec`, get it back. `Op::ReadPooled` is the exception
//! worth reading about — its buffer belongs to the driver's pool and returns
//! trimmed to the bytes actually read, which is what keeps one connection from
//! ever seeing another's leftovers.

pub mod net;
pub mod reactor;
