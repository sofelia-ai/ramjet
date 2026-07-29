//! kqueue backend: completion semantics emulated over readiness.
//!
//! kqueue reports *readiness*; this driver performs the syscall itself once the
//! fd is ready and hands back a finished op, so callers see io_uring-shaped
//! completions. Every submit tries the syscall eagerly first — a ready fd never
//! costs a kevent round trip.
//!
//! M0 limit: at most one in-flight op per (fd, filter), i.e. one Read (or
//! Accept) and one Write per fd. kqueue keys registrations by (ident, filter),
//! so a second one would replace the first's kevent and strand it; `submit`
//! rejects the collision with `ErrorKind::ResourceBusy` instead.

use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;

use super::pool::{self, POOL_BUF_SIZE};
use super::slab::Slab;
use super::{Completion, Driver, Op, OpId};

/// Re-exported so callers that had it from this module keep working.
pub use super::pool::POOL_BUF_SIZE as BUF_SIZE;

/// OpIds ride through the kernel in a kevent's `udata` pointer, so a pointer
/// must be wide enough to hold one without truncating.
const _: () = assert!(size_of::<usize>() >= size_of::<OpId>());

/// Marks an unoccupied per-fd slot. No real id can collide with it: slot
/// indices stay far below `u32::MAX` and would need the top generation too.
const NO_OP: OpId = u64::MAX;

/// How many `wait` calls may be served straight from already-finished ops
/// before one of them spends a kevent on the parked ones.
///
/// The zero-timeout poll exists so a connection that keeps completing eagerly
/// cannot starve a parked one, but paying a syscall for it on *every* call made
/// kevent 13% of a profile. This bounds the unfairness instead of eliminating
/// it: a parked op waits at most this many cycles, and the poll costs one
/// syscall per that many cycles rather than one per cycle.
const FAIRNESS_POLL_EVERY: u32 = 8;

/// Highest descriptor the per-fd table will index. Beyond this the table stops
/// being a reasonable trade — a server with a million sockets has other
/// problems — and the op is failed rather than allowed to allocate 16 MiB of
/// mostly-empty rows. Unreachable in practice: a descriptor that large only
/// arrives from a caller that already ignored its own rlimit.
const MAX_TRACKED_FD: usize = 1 << 20;

/// Which op, if any, holds each of an fd's two kevent slots.
#[derive(Clone, Copy)]
struct FdSlots {
    read: OpId,
    write: OpId,
}

impl Default for FdSlots {
    fn default() -> Self {
        FdSlots {
            read: NO_OP,
            write: NO_OP,
        }
    }
}

/// A submitted op that could not finish yet, waiting on a kevent.
enum Pending {
    Accept {
        fd: RawFd,
    },
    Read {
        fd: RawFd,
        buf: Vec<u8>,
    },
    /// A pooled read with no buffer attached — the whole reason the variant
    /// exists. It borrows one from the pool only when the fd is actually
    /// readable, and gives it straight back if the read would block.
    ReadPooled {
        fd: RawFd,
    },
    /// `off` is how far into `buf` the write has got; it completes at
    /// `off == buf.len()`. `start` is where the payload began, so the byte
    /// count a `WriteFrom` reports excludes the header bytes before it.
    Write {
        fd: RawFd,
        buf: Vec<u8>,
        off: usize,
        start: usize,
    },
}

impl Pending {
    fn fd(&self) -> RawFd {
        match *self {
            Pending::Accept { fd }
            | Pending::Read { fd, .. }
            | Pending::ReadPooled { fd }
            | Pending::Write { fd, .. } => fd,
        }
    }

    fn filter(&self) -> i16 {
        match *self {
            Pending::Accept { .. } | Pending::Read { .. } | Pending::ReadPooled { .. } => {
                libc::EVFILT_READ
            }
            Pending::Write { .. } => libc::EVFILT_WRITE,
        }
    }

    /// The buffer to hand back on a cancel or an error. `ReadPooled` yields
    /// `None` because a parked one genuinely owns nothing.
    fn take_buf(&mut self) -> Option<Vec<u8>> {
        match self {
            Pending::Accept { .. } | Pending::ReadPooled { .. } => None,
            Pending::Read { buf, .. } | Pending::Write { buf, .. } => Some(mem::take(buf)),
        }
    }
}

/// kqueue-backed driver for macOS/BSD.
///
/// Owns raw fds and a kqueue bound to one thread, so it is deliberately `!Send`:
///
/// ```compile_fail
/// fn needs_send<T: Send>(_: T) {}
/// let d = ramjet::reactor::kqueue::KqueueDriver::new().unwrap();
/// needs_send(d);
/// ```
pub struct KqueueDriver {
    kq: RawFd,
    /// In-flight ops, indexed by the id rather than hashed.
    slab: Slab<Pending>,
    /// Which op owns each fd's read and write kevent, so a colliding submit can
    /// be refused and a Close knows exactly what to cancel. Indexed by fd:
    /// descriptors are small dense integers, so an array beats a hash map, and
    /// the table grows only to the highest fd this driver has parked an op on.
    /// Kept in exact sync with `slab`.
    fds: Vec<FdSlots>,
    /// Ops finished eagerly at submit time or by the last `wait`.
    ready: Vec<Completion>,
    /// `wait` calls served without touching kqueue, for the fairness budget.
    since_poll: u32,
    /// Free list backing `Op::ReadPooled`. Buffers live here between reads, not
    /// in the parked ops, so idle connections cost nothing.
    pool: Vec<Vec<u8>>,
    /// `*const ()` is neither Send nor Sync, which is the point.
    _not_send: PhantomData<*const ()>,
}

impl KqueueDriver {
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue() takes no arguments and either returns a fresh fd or -1.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            kq,
            slab: Slab::new(),
            fds: Vec::new(),
            ready: Vec::new(),
            since_poll: 0,
            pool: Vec::new(),
            _not_send: PhantomData,
        })
    }

    /// Size of the buffers this driver's pool hands out, and the size a `Vec`
    /// must be for [`Driver::recycle`] to keep it. Same value as
    /// [`POOL_BUF_SIZE`], reachable from a driver you already hold.
    pub fn pool_buf_size() -> usize {
        POOL_BUF_SIZE
    }

    /// Everything this driver believes about its own state, as one line per
    /// descriptor plus a header. Meant for a stalled test to print: a hang that
    /// says which slot is occupied by what names its own bug.
    ///
    /// Diagnostic only. The shape of the string is not a contract and no code
    /// should parse it.
    pub fn debug_state(&self) -> String {
        let occupant = |id: OpId| match self.slab.peek(id) {
            _ if id == NO_OP => "-".to_string(),
            None => "<cell empty or stale>".to_string(),
            Some(Pending::Accept { .. }) => "Accept".to_string(),
            Some(Pending::Read { buf, .. }) => format!("Read[{}]", buf.len()),
            Some(Pending::ReadPooled { .. }) => "ReadPooled".to_string(),
            Some(Pending::Write { buf, off, .. }) => format!("Write[{}/{}]", off, buf.len()),
        };
        let mut s = format!(
            "kqueue: live={} ready={} pool={} since_poll={}",
            self.slab.live(),
            self.ready.len(),
            self.pool.len(),
            self.since_poll,
        );
        for (fd, slots) in self.fds.iter().enumerate() {
            if slots.read == NO_OP && slots.write == NO_OP {
                continue;
            }
            s.push_str(&format!(
                "\n  fd {fd}: read={} write={}",
                occupant(slots.read),
                occupant(slots.write),
            ));
        }
        s
    }

    /// Register one-shot interest so the next `wait` picks this op back up.
    fn arm(&self, fd: RawFd, filter: i16, id: OpId) -> io::Result<()> {
        let mut ev = zeroed_kevent();
        ev.ident = fd as usize;
        ev.filter = filter;
        ev.flags = libc::EV_ADD | libc::EV_ONESHOT;
        ev.udata = id as usize as *mut libc::c_void;
        self.change(&ev)
    }

    fn disarm(&self, fd: RawFd, filter: i16) -> io::Result<()> {
        let mut ev = zeroed_kevent();
        ev.ident = fd as usize;
        ev.filter = filter;
        ev.flags = libc::EV_DELETE;
        self.change(&ev)
    }

    fn change(&self, ev: &libc::kevent) -> io::Result<()> {
        // SAFETY: `ev` is one initialised kevent we hand in as a 1-element
        // changelist; the eventlist is empty so nothing is written back.
        let r = unsafe { libc::kevent(self.kq, ev, 1, ptr::null_mut(), 0, ptr::null()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Which ops hold this fd's two kevent slots. Never grows the table.
    fn fd_slots(&self, fd: RawFd) -> FdSlots {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get(i))
            .copied()
            .unwrap_or_default()
    }

    /// Same, but grown so it can be written. `None` for a descriptor the table
    /// will not index — see [`MAX_TRACKED_FD`].
    fn fd_slots_mut(&mut self, fd: RawFd) -> Option<&mut FdSlots> {
        let i = usize::try_from(fd).ok()?;
        if i > MAX_TRACKED_FD {
            return None;
        }
        if i >= self.fds.len() {
            self.fds.resize(i + 1, FdSlots::default());
        }
        Some(&mut self.fds[i])
    }

    /// Park `p` in the cell `id` already names, arming its kevent.
    ///
    /// An arming failure, or an fd the table cannot index, becomes a completion
    /// rather than a silently dropped op.
    fn park(&mut self, id: OpId, mut p: Pending) {
        let (fd, filter) = (p.fd(), p.filter());
        let failure = match self.arm(fd, filter, id) {
            Err(e) => Some(e),
            Ok(()) => match self.fd_slots_mut(fd) {
                Some(slots) => {
                    if filter == libc::EVFILT_READ {
                        slots.read = id;
                    } else {
                        slots.write = id;
                    }
                    None
                }
                None => Some(io::Error::from_raw_os_error(libc::EBADF)),
            },
        };
        match failure {
            None => self.slab.put_op(id, p),
            Some(e) => {
                let user = self.slab.user(id);
                self.slab.release(id);
                self.ready.push(Completion {
                    id,
                    user,
                    result: Err(e),
                    buf: p.take_buf(),
                });
            }
        }
    }

    /// Take a parked op out to work on it, freeing its fd slot. The cell stays
    /// reserved so the op keeps its id if it has to park again. The kevent is
    /// one-shot, so a fired one needs no explicit removal.
    fn unpark(&mut self, id: OpId) -> Option<Pending> {
        let p = self.slab.take_op(id)?;
        if let Some(slots) = self.fd_slots_mut(p.fd()) {
            if p.filter() == libc::EVFILT_READ {
                slots.read = NO_OP;
            } else {
                slots.write = NO_OP;
            }
        }
        Some(p)
    }

    /// Cancel everything parked on `fd`, drop its kevents, then close(2) it.
    fn close(&mut self, fd: RawFd, user: u64) -> OpId {
        // An id nobody else will be given. The cell is freed immediately: a
        // Close never parks, it only needs a name for its completion.
        let id = self.slab.reserve(user);
        self.slab.release(id);

        // The fd's own row says exactly what is parked on it, so there is
        // nothing to scan. Also clears the row, which is what keeps a recycled
        // descriptor from inheriting this one's bookkeeping.
        let doomed = self.fd_slots(fd);
        for cancelled in [doomed.read, doomed.write] {
            if cancelled == NO_OP {
                continue;
            }
            let Some(mut p) = self.unpark(cancelled) else {
                continue;
            };
            let cancelled_user = self.slab.user(cancelled);
            self.slab.release(cancelled);
            let _ = self.disarm(fd, p.filter());
            self.ready.push(Completion {
                id: cancelled,
                user: cancelled_user,
                result: Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                buf: p.take_buf(),
            });
        }
        if let Some(slots) = self.fd_slots_mut(fd) {
            *slots = FdSlots::default();
        }

        // SAFETY: the caller handed us ownership of `fd` with this op.
        let result = if unsafe { libc::close(fd) } < 0 {
            let e = io::Error::last_os_error();
            // EINTR still closes the fd on macOS/BSD. Retrying could close a
            // descriptor number something else has already reused.
            if e.kind() == io::ErrorKind::Interrupted {
                Ok(0)
            } else {
                Err(e)
            }
        } else {
            Ok(0)
        };
        self.ready.push(Completion {
            id,
            user,
            result,
            buf: None,
        });
        id
    }
}

impl Drop for KqueueDriver {
    fn drop(&mut self) {
        // Undrained completions die with the driver. An Accept completion holds
        // an fd nobody has closed, so dropping one leaks it — drain before drop.
        // SAFETY: self.kq is owned by this struct and never used after drop.
        unsafe { libc::close(self.kq) };
    }
}

impl Driver for KqueueDriver {
    fn submit(&mut self, op: Op) -> io::Result<OpId> {
        self.submit_with(op, 0)
    }

    fn submit_with(&mut self, op: Op, user: u64) -> io::Result<OpId> {
        let slot = match &op {
            Op::Accept { fd } | Op::Read { fd, .. } | Op::ReadPooled { fd } => {
                (*fd, libc::EVFILT_READ)
            }
            Op::Write { fd, .. } | Op::WriteFrom { fd, .. } => (*fd, libc::EVFILT_WRITE),
            Op::Close { fd } => return Ok(self.close(*fd, user)),
        };
        if let Op::Read { buf, .. } = &op
            && buf.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Read needs a non-empty buffer: a 0-byte read is indistinguishable from EOF",
            ));
        }
        if let Op::WriteFrom { buf, start, .. } = &op
            && *start > buf.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WriteFrom start is past the end of the buffer",
            ));
        }
        let occupied = {
            let slots = self.fd_slots(slot.0);
            if slot.1 == libc::EVFILT_READ {
                slots.read
            } else {
                slots.write
            }
        };
        if occupied != NO_OP {
            // The op is refused, but its buffer is untouched and may well be
            // pool-sized: keep it rather than dropping a usable allocation.
            if let Op::Read { buf, .. } | Op::Write { buf, .. } | Op::WriteFrom { buf, .. } = op {
                pool::put(&mut self.pool, buf);
            }
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "an op of this kind is already in flight on this fd",
            ));
        }

        // Reserve the cell before the syscall so the op has an id either way.
        // If it finishes eagerly the cell is handed straight back, which bumps
        // its generation and guarantees the next op gets a different id.
        let id = self.slab.reserve(user);
        let mut p = match op {
            Op::Accept { fd } => Pending::Accept { fd },
            Op::Read { fd, buf } => Pending::Read { fd, buf },
            Op::ReadPooled { fd } => Pending::ReadPooled { fd },
            Op::Write { fd, buf } => Pending::Write {
                fd,
                buf,
                off: 0,
                start: 0,
            },
            Op::WriteFrom { fd, buf, start } => Pending::Write {
                fd,
                buf,
                off: start,
                start,
            },
            // Returned above, before any state changed.
            Op::Close { fd } => return Ok(self.close(fd, user)),
        };

        match step(id, user, &mut p, &mut self.pool) {
            Some(c) => {
                self.slab.release(id);
                self.ready.push(c);
            }
            None => self.park(id, p),
        }
        Ok(id)
    }

    fn wait(&mut self, out: &mut Vec<Completion>) -> io::Result<()> {
        // Completions already in hand: hand them over without a syscall, unless
        // the fairness budget says it is this call's turn to look at the parked
        // ops. Nothing parked means there is nothing to be fair to.
        if !self.ready.is_empty() {
            self.since_poll += 1;
            if self.slab.is_empty() || self.since_poll < FAIRNESS_POLL_EVERY {
                out.append(&mut self.ready);
                return Ok(());
            }
        }

        // Nothing in flight means nothing can ever wake us: return empty rather
        // than block forever.
        while !self.slab.is_empty() {
            // Fairness: even with eager completions already ready, harvest
            // kqueue with a zero timeout. Never doing so lets connections that
            // keep hitting the eager fast path starve parked ones — measured as
            // a 6x p99 blowup at 200 connections — so the budget above thins
            // this out rather than skipping it.
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let timeout: *const libc::timespec = if self.ready.is_empty() {
                ptr::null() // nothing ready: block until something happens
            } else {
                &zero
            };
            // SAFETY: kevent is plain-old-data, so an all-zero array is a valid
            // (if meaningless) value for the kernel to overwrite.
            let mut evs: [libc::kevent; 64] = unsafe { mem::zeroed() };
            // SAFETY: `evs` is a valid, writable array of exactly 64 kevents,
            // the changelist is empty, and `timeout` is null or a live timespec
            // that outlives the call.
            let n = unsafe {
                libc::kevent(
                    self.kq,
                    ptr::null(),
                    0,
                    evs.as_mut_ptr(),
                    evs.len() as i32,
                    timeout,
                )
            };
            // Blocking or not, kqueue has been looked at: the budget restarts.
            self.since_poll = 0;
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }

            for ev in &evs[..n as usize] {
                let id = ev.udata as usize as OpId;
                let user = self.slab.user(id);
                let Some(mut p) = self.unpark(id) else {
                    continue;
                };
                if ev.flags & libc::EV_ERROR != 0 && ev.data != 0 {
                    self.slab.release(id);
                    self.ready.push(Completion {
                        id,
                        user,
                        result: Err(io::Error::from_raw_os_error(ev.data as i32)),
                        buf: p.take_buf(),
                    });
                    continue;
                }
                match step(id, user, &mut p, &mut self.pool) {
                    // Finished for good: the cell goes back on the free list.
                    Some(c) => {
                        self.slab.release(id);
                        self.ready.push(c);
                    }
                    // Still short of its target — a partial write, or a
                    // spurious wake. Park it again under the same id.
                    None => self.park(id, p),
                }
            }

            // Something to hand out (eager or just harvested): stop polling.
            // Only stale events (all ids already gone) loop back to block again.
            if !self.ready.is_empty() {
                break;
            }
        }
        out.append(&mut self.ready);
        Ok(())
    }

    fn recycle(&mut self, buf: Vec<u8>) {
        pool::put(&mut self.pool, buf);
    }
}

fn zeroed_kevent() -> libc::kevent {
    // SAFETY: kevent is a plain-old-data struct; all-zero is a valid value and
    // every field we care about is overwritten by the caller.
    unsafe { mem::zeroed() }
}

/// Prepare a freshly accepted socket: non-blocking, EPIPE instead of a
/// SIGPIPE that would kill a host process ramjet does not control, and
/// TCP_NODELAY — a completion runtime schedules its own writes; Nagle only
/// adds latency it can never win back.
fn prepare(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFL reads flags only; it touches no memory of ours.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same, with the flag word we just read plus O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let on: libc::c_int = 1;
    // SAFETY: `on` is a live c_int and we pass exactly its size as optlen.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same shape as above — live c_int, exact optlen.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Try to finish `p`. `Some` = done (the op is consumed), `None` = would block.
///
/// `pool` is only touched by `ReadPooled`, which borrows a buffer for the length
/// of the read and returns it untouched if the read would have blocked.
fn step(id: OpId, user: u64, p: &mut Pending, pool: &mut Vec<Vec<u8>>) -> Option<Completion> {
    let done = |result, buf| {
        Some(Completion {
            id,
            user,
            result,
            buf,
        })
    };

    match p {
        Pending::Accept { fd } => {
            // SAFETY: null addr/addrlen is the documented way to accept without
            // asking for the peer address.
            let new = unsafe { libc::accept(*fd, ptr::null_mut(), ptr::null_mut()) };
            if new < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return None;
                }
                return done(Err(e), None);
            }
            match prepare(new) {
                Ok(()) => done(Ok(i64::from(new)), None),
                Err(e) => {
                    // SAFETY: `new` is ours and unreachable to the caller, so
                    // closing it here is the only way to avoid leaking it.
                    unsafe { libc::close(new) };
                    done(Err(e), None)
                }
            }
        }

        Pending::Read { fd, buf } => {
            // SAFETY: buf is a live allocation of exactly buf.len() writable bytes.
            let n = unsafe { libc::read(*fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return None;
                }
                return done(Err(e), Some(mem::take(buf)));
            }
            done(Ok(n as i64), Some(mem::take(buf)))
        }

        Pending::ReadPooled { fd } => {
            let mut buf = pool::take(pool);
            let spare = buf.spare_capacity_mut();
            let room = spare.len().min(POOL_BUF_SIZE);
            // SAFETY: `spare` is `room` bytes of this Vec's own allocation, not
            // aliased by anything, and read() only ever writes to them. They are
            // uninitialised, which is fine because nothing reads them: the
            // set_len below claims exactly the bytes the kernel reports writing,
            // and on any other path the buffer stays empty.
            let n = unsafe { libc::read(*fd, spare.as_mut_ptr().cast(), room) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    // Nothing to read after all. Give the buffer straight back
                    // so the op parks owning no memory, which is the point of
                    // the variant.
                    pool::put(pool, buf);
                    return None;
                }
                // Still empty, so nothing is the caller's to see.
                return done(Err(e), Some(buf));
            }
            // SAFETY: read() reported writing exactly `n` bytes into the spare
            // capacity and `n <= room`, so those bytes are initialised and
            // inside the allocation. Claiming only them is also what keeps the
            // previous tenant's bytes out of reach: the length *is* the data,
            // never more.
            unsafe { buf.set_len(n as usize) };
            done(Ok(n as i64), Some(buf))
        }

        Pending::Write {
            fd,
            buf,
            off,
            start,
        } => loop {
            // SAFETY: buf[off..] is in bounds, so the pointer/len pair covers
            // exactly the unflushed tail of a live allocation.
            let n = unsafe { libc::write(*fd, buf[*off..].as_ptr().cast(), buf.len() - *off) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    return None;
                }
                return done(Err(e), Some(mem::take(buf)));
            }
            *off += n as usize;
            if *off >= buf.len() {
                // Bytes written, which for a plain Write (start 0) is the whole
                // buffer and for a WriteFrom excludes the header before `start`.
                let sent = (*off - *start) as i64;
                return done(Ok(sent), Some(mem::take(buf)));
            }
            if n == 0 {
                return None; // no progress and no error: wait for writability
            }
        },
    }
}

#[cfg(test)]
impl KqueueDriver {
    /// Test-only window on the free list. The pool is deliberately invisible in
    /// the public API — its size is an implementation detail, not a contract.
    fn pool_len(&self) -> usize {
        self.pool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::pool::POOL_CAP;
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::IntoRawFd;

    /// A connected pair. The returned fd is non-blocking, as the driver requires.
    fn connected_pair() -> (TcpStream, RawFd) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = l.accept().expect("accept");
        server.set_nonblocking(true).expect("set_nonblocking");
        (client, server.into_raw_fd())
    }

    #[test]
    fn recycle_stops_at_the_pool_ceiling() {
        let mut d = KqueueDriver::new().expect("driver");
        for _ in 0..300 {
            d.recycle(vec![0u8; POOL_BUF_SIZE]);
        }
        assert_eq!(
            d.pool_len(),
            POOL_CAP,
            "pool must stop growing once it is full"
        );
    }

    #[test]
    fn a_buffer_too_small_to_serve_a_read_is_dropped() {
        let mut d = KqueueDriver::new().expect("driver");
        d.recycle(vec![0u8; POOL_BUF_SIZE / 2]);
        assert_eq!(d.pool_len(), 0, "an undersized buffer is not worth keeping");
    }

    /// The other end of the admission window: pooling a huge buffer would let
    /// POOL_CAP of them pin far more memory than the allocations they save.
    #[test]
    fn an_oversized_buffer_is_dropped() {
        let mut d = KqueueDriver::new().expect("driver");
        d.recycle(vec![0u8; POOL_BUF_SIZE * 2 + 1]);
        assert_eq!(
            d.pool_len(),
            0,
            "an oversized buffer would pin memory out of proportion to what it saves"
        );

        // Exactly at the ceiling is still fine.
        d.recycle(vec![0u8; POOL_BUF_SIZE * 2]);
        assert_eq!(d.pool_len(), 1, "the upper bound is inclusive");
    }

    /// The memory story: parking a pooled read must leave the pool untouched.
    #[test]
    fn a_parked_pooled_read_holds_no_buffer() {
        let (_client, fd) = connected_pair();
        let mut d = KqueueDriver::new().expect("driver");
        d.recycle(vec![0u8; POOL_BUF_SIZE]);
        assert_eq!(d.pool_len(), 1);

        // No data waiting, so this parks.
        d.submit(Op::ReadPooled { fd }).expect("submit pooled read");
        assert_eq!(
            d.pool_len(),
            1,
            "a parked pooled read must give its buffer back to the pool"
        );

        d.submit(Op::Close { fd }).expect("close");
    }

    /// A recycled buffer comes back trimmed to its last read. The next read
    /// must still be able to fill the whole allocation, or every later message
    /// through that buffer would be silently capped at the previous one's size.
    #[test]
    fn a_recycled_trimmed_buffer_does_not_cap_the_next_read() {
        let (mut client, fd) = connected_pair();
        let mut d = KqueueDriver::new().expect("driver");

        // Stand in for a completion that read 4 bytes and was recycled.
        let mut used = vec![0u8; POOL_BUF_SIZE];
        used.truncate(4);
        d.recycle(used);
        assert_eq!(d.pool_len(), 1);

        // Offer far more than the trimmed length.
        let payload = vec![b'x'; 64];
        client.write_all(&payload).expect("client write");

        let id = d.submit(Op::ReadPooled { fd }).expect("submit");
        let mut out = Vec::new();
        d.wait(&mut out).expect("wait");
        let c = out.into_iter().find(|c| c.id == id).expect("completion");
        let n = c.result.expect("read ok") as usize;
        let buf = c.buf.expect("buffer");
        assert_eq!(
            n,
            payload.len(),
            "a trimmed recycled buffer must not cap the next read"
        );
        assert!(
            buf.capacity() >= POOL_BUF_SIZE,
            "the pooled allocation is still full size"
        );
        assert_eq!(buf.len(), n, "completion length is the byte count");

        d.submit(Op::Close { fd }).expect("close");
    }

    #[test]
    fn an_eager_pooled_read_borrows_from_the_pool_and_returns_it() {
        let (mut client, fd) = connected_pair();
        let mut d = KqueueDriver::new().expect("driver");
        for _ in 0..300 {
            d.recycle(vec![0u8; POOL_BUF_SIZE]);
        }
        assert_eq!(d.pool_len(), POOL_CAP);

        client.write_all(b"pooled").expect("client write");
        let id = d.submit(Op::ReadPooled { fd }).expect("submit");
        let mut out = Vec::new();
        d.wait(&mut out).expect("wait");
        let i = out.iter().position(|c| c.id == id).expect("completion");
        let c = out.swap_remove(i);
        let n = c.result.expect("read ok") as usize;
        let buf = c.buf.expect("pooled buffer came out with the completion");
        assert_eq!(buf, b"pooled", "the buffer is exactly the data read");
        assert_eq!(buf.len(), n);
        assert_eq!(
            d.pool_len(),
            POOL_CAP - 1,
            "the in-flight buffer is out of the pool"
        );
        d.recycle(buf);
        assert_eq!(d.pool_len(), POOL_CAP, "recycling puts it back");

        d.submit(Op::Close { fd }).expect("close");
    }
}
