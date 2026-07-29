//! Completion-based reactor: submit ops, harvest completions.
//!
//! This is the io_uring mental model even on platforms without io_uring.
//! Backends:
//! - kqueue (macOS/BSD): completion emulated over readiness — the backend
//!   performs the syscall when the fd is ready and hands back a finished op.
//! - io_uring (Linux): true completions. Planned, same trait.
//!
//! Buffers are passed by ownership (submit a `Vec<u8>`, get it back in the
//! completion). That is the shape registered buffer rings need later; no API
//! break when zero-copy lands.
//!
//! Precondition: every fd handed to the driver inside an [`Op`] must already be
//! non-blocking. The driver does not check and does not set it — a blocking fd
//! will stall the whole reactor on the first syscall. fds the driver produces
//! itself (an accepted socket) are prepared by the driver.

use std::io;
use std::os::fd::RawFd;

/// Token correlating a submission with its completion.
pub type OpId = u64;

/// One I/O operation to submit to the driver.
#[derive(Debug)]
pub enum Op {
    /// Accept a connection on a listening socket. Completes with the new fd.
    ///
    /// That fd is owned by whoever holds the completion: drop the completion
    /// without closing it and the fd leaks.
    Accept { fd: RawFd },
    /// Read into the owned buffer. Completes with bytes read; 0 = peer EOF.
    ///
    /// The buffer must be non-empty — a zero-length read completes with 0,
    /// which the caller cannot tell apart from EOF.
    Read { fd: RawFd, buf: Vec<u8> },
    /// Read into a buffer the driver supplies from its own pool, attached only
    /// when the read actually completes.
    ///
    /// `result` is the byte count and 0 is peer EOF, as with [`Op::Read`]. The
    /// buffer differs: it arrives trimmed to exactly the bytes read, so
    /// `buf.len() == n` and the data is the whole buffer. There is no `buf[..n]`
    /// step, and EOF or an error yields an empty buffer rather than a full-sized
    /// one.
    ///
    /// **That asymmetry with [`Op::Read`] is a safety property, not a
    /// convenience.** A pooled buffer is handed out again to whichever
    /// connection reads next, so bytes the previous reader left in its spare
    /// capacity are still there. Trimming to `n` puts them out of reach of safe
    /// code: there is no length at which one connection can observe another's
    /// data. A caller-supplied [`Op::Read`] buffer never crosses connections, so
    /// it keeps its own length and the `buf[..n]` contract.
    ///
    /// A parked `ReadPooled` holds no buffer at all. That is the point of the
    /// variant — a connection idling between requests occupies no read memory —
    /// and it is why a cancelled one completes with `buf: None`, where a
    /// cancelled [`Op::Read`] always returns the caller's buffer.
    ///
    /// Hand the buffer back with [`Driver::recycle`] once you are done with it.
    ReadPooled { fd: RawFd },
    /// Write the owned buffer fully (driver handles partial writes).
    ///
    /// A failed Write says nothing about how much was sent: an indeterminate
    /// prefix of the buffer may already have reached the peer. The stream is
    /// not resumable after one, only closable.
    Write { fd: RawFd, buf: Vec<u8> },
    /// Write `buf[start..]` fully, then hand the **whole** buffer back.
    ///
    /// Partial writes are handled exactly as for [`Op::Write`]. What differs is
    /// the completion: it returns the entire `Vec`, not the slice that was
    /// sent, so a caller can keep reusing one buffer whose payload begins
    /// partway in. `result` is the number of bytes written — `buf.len() -
    /// start` — not the buffer's length.
    ///
    /// This is what makes an echo free of assembly: read into a pooled buffer,
    /// write a reply header into the bytes just before the payload, and send
    /// from that offset without copying or allocating anything.
    ///
    /// `start > buf.len()` is rejected with `ErrorKind::InvalidInput`. Shares
    /// the write slot with [`Op::Write`], so only one of the two may be in
    /// flight on an fd at a time.
    WriteFrom {
        fd: RawFd,
        buf: Vec<u8>,
        start: usize,
    },
    /// Close the fd.
    ///
    /// Ops still in flight on that fd are cancelled first — each completes with
    /// `ECANCELED` and hands its buffer back, if it had one; a parked
    /// [`Op::ReadPooled`] owns none. The Close completion means the fd is gone
    /// whatever its `result` says; a failure is diagnostic only.
    ///
    /// Submitting anything on the fd *after* its Close is a caller bug with a
    /// deliberately unspecified result. The kernel may recycle the number at
    /// any moment — an in-flight Accept completing is enough — and on a
    /// completion-based backend the stale op can execute against the
    /// successor fd and "succeed" (the classic async-I/O fd-reuse hazard).
    /// The driver stays memory-safe and still delivers exactly one completion
    /// for the op; which fd it touched is on the caller.
    Close { fd: RawFd },
}

/// A finished operation.
#[derive(Debug)]
pub struct Completion {
    pub id: OpId,
    /// Whatever the caller passed to [`Driver::submit_with`], handed straight
    /// back. Zero for an op submitted through [`Driver::submit`].
    ///
    /// This is the io_uring `user_data` idea: rather than keep a map from id to
    /// "what was this op for", pack that into the submission and read it off the
    /// completion. A server can encode an fd and a job kind in these 64 bits and
    /// route completions without hashing anything.
    pub user: u64,
    /// Accept: new fd. Read/Write: byte count. Close: 0.
    pub result: io::Result<i64>,
    /// The buffer given at submit time (Read/Write), returned to the caller
    /// whether the op succeeded or failed, at the length the caller chose.
    ///
    /// For [`Op::ReadPooled`] this is the driver's own buffer instead, and its
    /// length is the byte count — trimmed to exactly the bytes read, empty on
    /// EOF or error. See [`Op::ReadPooled`] for why the two differ.
    pub buf: Option<Vec<u8>>,
}

/// A completion-based I/O driver. One per core; `!Send` by design.
pub trait Driver {
    /// Queue an op. Never blocks. Returns the token for its completion.
    ///
    /// An `Err` means nothing was queued and no completion will ever arrive for
    /// it; the op is consumed either way, so its buffer is dropped. A driver may
    /// refuse an op that collides with one already in flight
    /// (`ErrorKind::ResourceBusy`) or a zero-length Read
    /// (`ErrorKind::InvalidInput`).
    fn submit(&mut self, op: Op) -> io::Result<OpId>;

    /// Queue an op, tagging it with `user` to be returned on its completion.
    ///
    /// The default ignores `user`, so a driver that has no use for it needs to
    /// do nothing and its completions simply report 0.
    fn submit_with(&mut self, op: Op, user: u64) -> io::Result<OpId> {
        let _ = user;
        self.submit(op)
    }

    /// Block until at least one op finishes; drain all ready completions.
    ///
    /// Returns immediately, appending nothing, when no op is in flight. A loop
    /// driving this should treat an empty drain as "nothing left to do" and
    /// stop, not spin.
    fn wait(&mut self, out: &mut Vec<Completion>) -> io::Result<()>;

    /// Hand a buffer back to the driver's pool.
    ///
    /// Optional but recommended: recycling is what keeps [`Op::ReadPooled`]
    /// cheap once a server is warm.
    ///
    /// Reliably kept are the buffers that arrive on `ReadPooled` completions,
    /// and any `Vec` whose *capacity* is between one and two times the driver's
    /// pool buffer size — for the kqueue driver, `POOL_BUF_SIZE` and its
    /// `pool_buf_size()`. Anything else is dropped: too small to serve a read
    /// without reallocating, or so large that pooling it would pin far more
    /// memory than the allocation it saves. Buffers arriving when the pool is
    /// already full are dropped too.
    ///
    /// So failing to recycle, or handing back something the pool declines,
    /// costs nothing worse than an ordinary `Vec` going out of scope.
    ///
    /// The default implementation drops the buffer.
    fn recycle(&mut self, _buf: Vec<u8>) {}
}

// Backend-shared internals.
mod pool;
mod slab;

pub use pool::POOL_BUF_SIZE;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod kqueue;

#[cfg(target_os = "linux")]
pub mod uring;

/// The native backend for the current platform, under one name so tests,
/// examples, and callers that just want "the driver here" need no cfg of
/// their own: kqueue on macOS/BSD, io_uring on Linux.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub type PlatformDriver = kqueue::KqueueDriver;

#[cfg(target_os = "linux")]
pub type PlatformDriver = uring::UringDriver;
