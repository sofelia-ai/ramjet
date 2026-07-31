//! io_uring backend: true completions, batched submission, no wrapper crate.
//!
//! The rings are driven raw — syscalls 425/426, hand-laid ABI structs, two
//! mmaps — because the whole point of this backend is owning the submission
//! path: `submit` writes a squeue entry and makes **no syscall at all**;
//! `wait` flushes everything queued and harvests completions in **one**
//! `io_uring_enter`. When completions are already in hand, the cqueue is
//! *peeked* — a pair of atomic loads on shared memory — so the fairness that
//! cost kqueue a polling budget costs nothing here.
//!
//! Reads on a socket go through a **multishot receive** armed once per
//! descriptor, drawing buffers from a kernel-registered ring. A parked
//! `ReadPooled` therefore owns nothing at all: the buffer is bound at delivery,
//! not at submit, which is what makes an idle connection cost bytes rather than
//! kilobytes. The arm is the driver's own op under its own slab id — never the
//! fd's read slot — so it does not spend the one-read-per-fd budget, and
//! deliveries that arrive with no read outstanding are stashed in stream order
//! until one does. Anything the ring will not serve (a non-socket, or a kernel
//! that refused the buffer registration) falls back to the single-shot path,
//! where the buffer is taken at submit time and held through the flight.
//!
//! Contract parity with the kqueue backend, with one honest difference:
//! `Op::Close` dooms the fd's in-flight ops immediately, but their `ECANCELED`
//! completions are delivered only when the kernel confirms via each op's CQE —
//! the kernel may write into a read buffer until then, so the buffer hand-back
//! must wait. The contract leaves timing unspecified. Reads parked on an arm
//! own no kernel-side request and are cancelled inline instead.
//!
//! `RAMJET_MULTISHOT_ACCEPT=1` opts listeners into one persistent multishot
//! accept arm. Caller-visible `Op::Accept` semantics stay one submission to one
//! completion: the driver pairs arm deliveries with waiting caller ops and
//! keeps a bounded queue of early arrivals. The fast path activates only when
//! the kernel also supports synchronous cancellation, which lets shutdown
//! harvest and close every descriptor the arm installed before its last CQE.
//! It remains opt-in because both primitives are kernel-specific.
//!
//! fd slots are freed the moment `Close` is submitted (not when its CQE
//! lands): the kernel cannot recycle the fd number before the async close
//! executes, and the doomed ops are tracked by generation-tagged slab id, so
//! a recycled number starts clean while stale CQEs still resolve correctly.

use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use super::pool::{self, POOL_BUF_SIZE};
use super::slab::Slab;
use super::{Completion, Driver, Op, OpId};

const SYS_IO_URING_SETUP: libc::c_long = 425;
const SYS_IO_URING_ENTER: libc::c_long = 426;
const SYS_IO_URING_REGISTER: libc::c_long = 427;

const IORING_OFF_SQ_RING: libc::off_t = 0;
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;

const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_ENTER_GETEVENTS: libc::c_uint = 1;

const IORING_OP_ACCEPT: u8 = 13;
const IORING_OP_ASYNC_CANCEL: u8 = 14;
const IORING_OP_CLOSE: u8 = 19;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_OP_SEND: u8 = 26;
const IORING_OP_RECV: u8 = 27;

// Provided-buffer rings (5.19+). Verified against the running kernel rather
// than the image's headers, which are older than it: io_uring_buf_reg is 40
// bytes with ring_addr@0/ring_entries@8/bgid@12, io_uring_buf is 16 bytes with
// addr@0/len@8/bid@12/resv@14.
const IORING_REGISTER_PBUF_RING: libc::c_uint = 22;
const IORING_UNREGISTER_PBUF_RING: libc::c_uint = 23;
const IORING_REGISTER_SYNC_CANCEL: libc::c_uint = 24;
/// sqe.flags: pick the buffer from the group in sqe.buf_index.
const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
/// cqe.flags: the buffer id is in the top 16 bits.
const IORING_CQE_F_BUFFER: u32 = 1 << 0;
const IORING_CQE_BUFFER_SHIFT: u32 = 16;
/// cqe.flags: this multishot arm is still live; more CQEs will follow.
const IORING_CQE_F_MORE: u32 = 1 << 1;
/// sqe.ioprio bit that makes ACCEPT multishot.
const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;
/// sqe.ioprio bit that makes RECV multishot.
const IORING_RECV_MULTISHOT: u16 = 2;

/// The one buffer group this driver uses.
const BGID: u16 = 0;
/// Buffers in the ring. Must be a power of two: the kernel masks the tail.
///
/// Small on purpose, and 32 is a measured optimum rather than a guess. Raising
/// it costs memory and *loses* throughput: at 64 KiB buffers, 200 connections,
/// pipeline depth 8, a 4 KiB payload gave 418k req/s at 32 entries against 308k
/// at 256, with p99 6.1 ms against 10.0 ms. Lowering it to 16 is no better at
/// 4 KiB and clearly worse at 64 B (694k against 787k, ranges apart), so the
/// curve has a peak here rather than sliding toward zero.
///
/// The count is not load-bearing because **running dry is free**. The `enobufs`
/// counter below says the ring at 32 entries is refused 1.7 million times in a
/// six-second run while being the fastest configuration measured; taking the
/// count to 1024 drove `enobufs` to exactly zero and moved throughput by less
/// than the noise. A refused receive costs a re-arm, and the bytes are still in
/// the socket waiting — so starvation shows up in a counter and not in a number
/// anyone cares about.
///
/// Why fewer is *faster* is **observed, reproduced, and unexplained** — recorded
/// that way on purpose, because a plausible guess here would be worse than an
/// honest gap. It holds on two machines and two kernels: in a 6.10.14 container
/// (418k against 308k req/s at 4 KiB, 32 against 256 entries) and on an EC2
/// 7.0 box (307k against 223k, ranges separate), monotonically in the count both
/// times. So it is a property of the system rather than of one box.
///
/// The plausible story is that a momentarily dry ring lets the socket accumulate,
/// so the next receive drains a larger batch into a 64 KiB buffer and more
/// replies cork into one write — but buffers consumed per round trip come out the
/// same either way, which does not support it. Standing invitation to whoever
/// profiles it.
const RING_BUFS: u16 = 32;

/// Submission queue depth. Must be a power of two.
const ENTRIES: u32 = 256;
/// Bound speculative accepts while an opt-in multishot listener has no caller
/// waiting. A continuously accepting server drains this immediately; a paused
/// one cannot make the driver retain descriptors without limit.
const ACCEPT_STASH_LIMIT: usize = ENTRIES as usize;

/// `user_data` for internal ops (ASYNC_CANCEL) whose CQEs are swallowed.
const SENTINEL: u64 = u64::MAX;

// ---- ABI ------------------------------------------------------------------
// Layouts mirror <linux/io_uring.h>. They are kernel ABI: fixed forever.

#[repr(C)]
#[derive(Clone, Copy)]
struct SqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
struct UringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
}

#[repr(C)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    _pad: [u64; 2],
}

#[repr(C)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

#[repr(C)]
struct KernelTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Argument to `IORING_REGISTER_SYNC_CANCEL`.
///
/// Multishot accept installs process descriptors before publishing their CQEs.
/// Drop must therefore cancel the arm synchronously and harvest its last CQEs;
/// merely closing the ring could discard a CQE while leaving its fd installed.
#[repr(C)]
struct SyncCancelReg {
    addr: u64,
    fd: i32,
    flags: u32,
    timeout: KernelTimespec,
    opcode: u8,
    pad: [u8; 7],
    pad2: [u64; 3],
}

const _: () = assert!(mem::size_of::<Sqe>() == 64);
const _: () = assert!(mem::size_of::<Cqe>() == 16);
const _: () = assert!(mem::size_of::<UringParams>() == 120);

/// `io_uring_buf_reg`: what registration takes.
#[repr(C)]
struct BufReg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

/// One provided-buffer descriptor.
///
/// The ring's header aliases descriptor 0: the kernel reads its `tail` at byte
/// offset 14, which is exactly where descriptor 0's `resv` sits. Nothing here
/// ever writes `resv`, so slot 0 is a usable buffer and the tail survives.
#[repr(C)]
struct Buf {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}

const _: () = assert!(mem::size_of::<BufReg>() == 40);
const _: () = assert!(mem::size_of::<Buf>() == 16);
/// The aliasing above only holds if `tail` lands on `resv`.
const _: () = assert!(mem::offset_of!(Buf, resv) == 14);

// ---- provided-buffer ring --------------------------------------------------

/// A registered provided-buffer ring: the kernel picks a buffer per receive
/// instead of us naming one at submit time.
///
/// Each buffer id owns an individual `Vec<u8>` here. The kernel writes into that
/// Vec's spare capacity; on the completion we take the Vec and claim exactly the
/// bytes it reports, which is the same argument that keeps the pool's
/// spare-capacity reads sound — and the same reason a stale tail from a previous
/// tenant can never be reached.
struct BufRing {
    /// Anonymous mapping of `RING_BUFS` descriptors. Its first descriptor
    /// aliases the ring header; see [`Buf`].
    ring: *mut u8,
    ring_len: usize,
    /// Backing storage per buffer id. `None` while the kernel owns the slot.
    owned: Vec<Option<Vec<u8>>>,
    /// Our shadow of the tail the kernel reads.
    tail: u16,
}

impl BufRing {
    /// Map and register the ring, filling it with buffers.
    ///
    /// An `Err` is not fatal to the driver: the caller keeps the single-shot
    /// path. Portability beats cleverness.
    fn new(ring_fd: RawFd, pool: &mut Vec<Vec<u8>>) -> io::Result<Self> {
        let ring_len = RING_BUFS as usize * mem::size_of::<Buf>();
        // SAFETY: a plain anonymous mapping; the kernel is told its address at
        // registration and only ever reads descriptors from it.
        let ring = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ring_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ring = ring as *mut u8;
        // The header must start zeroed: tail lives inside descriptor 0.
        // SAFETY: the mapping is ours and exactly ring_len bytes.
        unsafe { ptr::write_bytes(ring, 0, ring_len) };

        let reg = BufReg {
            ring_addr: ring as u64,
            ring_entries: u32::from(RING_BUFS),
            bgid: BGID,
            flags: 0,
            resv: [0; 3],
        };
        // SAFETY: io_uring_register reads one BufReg of the exact ABI size.
        let r = unsafe {
            libc::syscall(
                SYS_IO_URING_REGISTER,
                ring_fd,
                IORING_REGISTER_PBUF_RING,
                &reg as *const BufReg,
                1 as libc::c_uint,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: the mapping is ours and unshared.
            unsafe { libc::munmap(ring as *mut libc::c_void, ring_len) };
            return Err(e);
        }

        let mut me = BufRing {
            ring,
            ring_len,
            owned: (0..RING_BUFS as usize).map(|_| None).collect(),
            tail: 0,
        };
        for bid in 0..RING_BUFS {
            me.owned[bid as usize] = Some(pool::take(pool));
            me.publish(bid);
        }
        me.commit();
        Ok(me)
    }

    /// Descriptor slot `i` of the ring.
    fn slot(&self, i: u16) -> *mut Buf {
        let idx = usize::from(i & (RING_BUFS - 1));
        // SAFETY: idx < RING_BUFS and the mapping holds that many descriptors.
        unsafe { self.ring.add(idx * mem::size_of::<Buf>()) as *mut Buf }
    }

    /// Hand buffer `bid` to the kernel at the current tail.
    ///
    /// Writes only addr/len/bid — never `resv`, because that field is the ring's
    /// tail for descriptor 0.
    fn publish(&mut self, bid: u16) {
        let Some(buf) = self.owned[usize::from(bid)].as_mut() else {
            return;
        };
        let (addr, len) = (buf.as_mut_ptr() as u64, buf.capacity() as u32);
        let slot = self.slot(self.tail);
        // SAFETY: `slot` is a live descriptor in our mapping; the kernel will
        // not look at it until `commit` moves the tail past it.
        unsafe {
            (*slot).addr = addr;
            (*slot).len = len;
            (*slot).bid = bid;
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Publish the tail so the kernel can see everything added since the last
    /// commit.
    fn commit(&self) {
        // SAFETY: the tail is a u16 at offset 14 of descriptor 0, which is what
        // the const assert on `Buf::resv` pins.
        let tail = unsafe { self.ring.add(14) as *const AtomicU16 };
        unsafe { &*tail }.store(self.tail, Ordering::Release);
    }

    /// Take the buffer the kernel filled with `n` bytes, and give its slot a
    /// fresh one.
    fn take(&mut self, bid: u16, n: usize, pool: &mut Vec<Vec<u8>>) -> Option<Vec<u8>> {
        let mut buf = self.owned[usize::from(bid)].take()?;
        // SAFETY: the kernel reported writing `n` bytes into the region we
        // published, which is this Vec's capacity from its start; `n` never
        // exceeds the `len` we advertised. Claiming exactly those bytes is also
        // what keeps a previous tenant's tail unreachable.
        debug_assert!(n <= buf.capacity());
        unsafe { buf.set_len(n.min(buf.capacity())) };
        // Refill the slot straight away so the ring never runs dry quietly.
        self.owned[usize::from(bid)] = Some(pool::take(pool));
        self.publish(bid);
        self.commit();
        Some(buf)
    }

    /// Give every buffer back to the pool and tear the ring down.
    fn shutdown(&mut self, ring_fd: RawFd, pool: &mut Vec<Vec<u8>>) {
        let reg = BufReg {
            ring_addr: 0,
            ring_entries: 0,
            bgid: BGID,
            flags: 0,
            resv: [0; 3],
        };
        // SAFETY: unregistering the group we registered; failure is ignorable
        // because closing the ring fd tears it down anyway.
        unsafe {
            libc::syscall(
                SYS_IO_URING_REGISTER,
                ring_fd,
                IORING_UNREGISTER_PBUF_RING,
                &reg as *const BufReg,
                1 as libc::c_uint,
            );
        }
        for slot in &mut self.owned {
            if let Some(buf) = slot.take() {
                pool::put(pool, buf);
            }
        }
        // SAFETY: the mapping is ours; the kernel no longer references it.
        unsafe { libc::munmap(self.ring as *mut libc::c_void, self.ring_len) };
        self.ring = ptr::null_mut();
    }
}

// ---- driver state ----------------------------------------------------------

/// What an in-flight op is, and what it owns.
enum Kind {
    Accept,
    /// A caller's `Accept` waiting for the listener's multishot arm.
    AcceptWaiting,
    /// The driver's persistent accept request. One SQE, many accepted fds.
    MultishotAccept,
    Read {
        buf: Vec<u8>,
    },
    ReadPooled {
        buf: Vec<u8>,
    },
    /// A caller's `ReadPooled` waiting for the multishot arm's next delivery.
    /// Owns **no** buffer — that is the whole point of the multishot path.
    PooledWaiting,
    /// A caller's `Op::Read` waiting to be filled by copy from a delivery.
    ReadWaiting {
        buf: Vec<u8>,
    },
    /// The driver's own multishot receive arm. Its CQEs carry data, not the
    /// completion of a caller's op, and it is **not** the fd's read slot.
    MultishotRecv,
    /// One state for Write and WriteFrom: `start` is the caller's offset,
    /// `sent` grows as partial completions are resubmitted internally.
    Write {
        buf: Vec<u8>,
        start: usize,
        sent: usize,
    },
    Close,
}

/// One multishot delivery, held until a caller's read asks for it.
enum Stashed {
    Data(Vec<u8>),
    Eof,
    Err(i32),
}

/// One multishot-accept delivery held until a caller submits `Op::Accept`.
enum Accepted {
    Fd(RawFd),
    Err(i32),
}

struct Flight {
    fd: RawFd,
    kind: Kind,
    /// Set by `Op::Close`: when this op's CQE arrives it completes ECANCELED
    /// regardless of what the kernel says.
    doomed: bool,
}

/// Deliberately not `Clone`: the stash owns buffers, so a stray clone would
/// copy kilobytes per fd.
#[derive(Default)]
struct FdState {
    read_slot: Option<OpId>,
    write_slot: Option<OpId>,
    /// Whether the fd is a socket (send with MSG_NOSIGNAL) or not (plain
    /// write — the echo_mt fd-passing pipes go through here). Probed once.
    sock: Option<bool>,
    /// Slab id of the driver-owned multishot receive arm, while armed.
    ms_arm: Option<OpId>,
    /// Slab id of the driver-owned multishot accept arm, while armed.
    accept_arm: Option<OpId>,
    /// Connections accepted before the caller submitted its next `Accept`.
    accepted: VecDeque<Accepted>,
    /// Deliveries that arrived before a caller had a read outstanding.
    stash: VecDeque<Stashed>,
}

/// io_uring-backed driver for Linux. One per core; `!Send` by design.
///
/// ```compile_fail
/// fn needs_send<T: Send>(_: T) {}
/// let d = ramjet::reactor::uring::UringDriver::new().unwrap();
/// needs_send(d);
/// ```
pub struct UringDriver {
    ring: RawFd,

    // SQ ring (mmap #1, shared with the CQ ring via SINGLE_MMAP).
    sq_mmap: *mut u8,
    sq_mmap_len: usize,
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_entries: u32,

    // SQE array (mmap #2).
    sqes: *mut Sqe,
    sqes_len: usize,

    // CQ ring (inside mmap #1).
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const Cqe,

    /// SQEs written but not yet handed to the kernel.
    to_submit: u32,

    ops: Slab<Flight>,
    /// Dense per-fd state; fds are small integers. Grows to the largest fd
    /// seen, which is bounded by the process fd limit.
    fds: Vec<FdState>,
    pool: Vec<Vec<u8>>,
    ready: Vec<Completion>,
    /// Accepted descriptors in `ready` have not crossed the Driver boundary
    /// yet. Track them until `wait` hands the completions to the caller so a
    /// driver dropped between completion and handoff cannot leak them.
    ready_accepted: Vec<RawFd>,

    /// Provided-buffer ring, when the kernel took the registration. `None`
    /// keeps the P1 single-shot path wholesale: portability over cleverness.
    bufs: Option<BufRing>,
    /// Opt-in: serve caller Accept ops from a persistent listener arm.
    multishot_accept: bool,
    /// Every accept arm still capable of producing an installed descriptor.
    /// Unlike the per-fd pointer, this survives `Op::Close` resetting an fd
    /// slot and lets Drop synchronously retire races before unmapping the CQ.
    active_accept_arms: Vec<OpId>,
    /// Multishot accept arms created. Test and profiling proof that the path
    /// actually engaged rather than silently using single-shot accept.
    multishot_accept_arms: u64,
    /// Multishot arms established. Non-zero proves the fast path is engaged;
    /// a silent fallback to single-shot would pass every behavioural test.
    multishot_arms: u64,
    /// Buffers taken out of the provided-buffer ring and handed to a caller as
    /// received bytes.
    ring_buffers_consumed: u64,
    /// Every buffer the kernel selected and gave back, filled or not. It must
    /// track what the kernel took or the ring bleeds; see `complete`.
    ring_buffers_reclaimed: u64,
    /// `io_uring_enter` calls that asked for completions, i.e. the ones a
    /// larger `min_complete` could coalesce. Against `cqes` this gives
    /// completions-per-enter, which is the harvest fatness the whole
    /// min_complete hypothesis rests on.
    enters_waiting: u64,
    /// `io_uring_enter` calls that only pushed submissions. `min_complete` is
    /// already 0 for these, so no batching change can remove them — they are
    /// the floor under any saving.
    enters_submitting: u64,
    /// Completion queue entries consumed. Kernel work per crossing, not
    /// completions delivered: a multishot delivery and a stale CQE both cost a
    /// ring slot and neither reaches the caller.
    cqes_harvested: u64,
    /// Thread CPU nanoseconds spent inside `io_uring_enter`, and inside the
    /// whole `wait`, when `RAMJET_URING_STATS` is set. Thread CPU time does not
    /// advance while blocked, so this is cycles burned in the syscall and not
    /// time asleep waiting for a peer — which is the only version of the number
    /// that bounds what fewer syscalls could ever save.
    enter_cpu_ns: u64,
    wait_cpu_ns: u64,
    /// Print the counters to stderr every this many **milliseconds**. Zero is
    /// off, which is the default: `RAMJET_URING_STATS=<ms>` turns it on. A
    /// server that is killed rather than shut down cannot report on the way
    /// out, so this reports as it goes.
    ///
    /// Wall clock rather than a count of enters, and that distinction is not
    /// cosmetic: keyed off enters, the cadence varies with the very thing under
    /// measurement, so the last line lands at a different point in each run and
    /// counters from two configurations are not comparable. That artifact
    /// produced a 2000x difference in `ring_consumed` between two runs that
    /// were doing the same work.
    stats_every_ms: u64,
    /// Monotonic nanoseconds at which to report next.
    stats_next_ns: u64,
    /// `wait` calls that returned without a blocking enter — completions were
    /// already in hand, or nothing of the caller's was in flight. Against
    /// `enters_waiting` this says how often the driver needs the kernel to wait
    /// for it at all.
    waits_early: u64,
    /// Times the kernel answered a receive with `-ENOBUFS`: it wanted a buffer
    /// from the provided ring and the ring was empty.
    ///
    /// Worth its own counter because a starving buffer group is invisible from
    /// the outside — the arm dies, we re-arm, and the only symptom is throughput
    /// that looks like a failed optimisation rather than a group that is too
    /// small. Zero here is what licenses reading a disappointing benchmark as a
    /// disappointing idea.
    enobufs: u64,
    /// Multishot arms currently live. They occupy slab cells but are the
    /// driver's own work, not the caller's, so `wait` must not treat them as
    /// something the caller is waiting for.
    live_arms: usize,
    /// `*const ()` is neither Send nor Sync, which is the point.
    _not_send: PhantomData<*const ()>,
}

/// `io_uring_setup` flags for task-work discipline. Profiled motivation: with
/// multishot armed on hundreds of sockets, eager task-work dominated the CPU
/// (42% of samples in `sock_def_readable`, 5% in IPI dispatch). SINGLE_ISSUER
/// (true for us — the driver is `!Send`) lets the kernel drop locking, and
/// COOP_TASKRUN stops the IPI storm.
///
/// `IORING_SETUP_DEFER_TASKRUN` is **off by default**, opt-in through
/// `RAMJET_DEFER_TASKRUN=1`. It is the flag that batches the rest of that work
/// into our one `enter` per cycle, and where it works it is worth having:
/// on an EC2 kernel 7.0 box it measured +2.5% throughput and a 24% better p99
/// at 500 connections with pipeline depth 8.
///
/// It is not the default because on 6.10 it loses multishot-recv wakeups: an
/// arm parks on poll, the peer writes or closes, and the request is never
/// re-issued. `/proc/self/fdinfo` shows it still on the `PollList` with
/// `task_works=0` while the socket polls readable, and the driver blocks
/// forever on a completion the kernel will never post. The state-machine
/// fuzzer reproduces that within twenty cases with the flag on, and runs four
/// hundred clean with it off; on 7.0 four hundred thousand operations pass
/// with it on.
///
/// A startup probe cannot decide this safely — the failure is intermittent
/// enough to take tens of cases to appear, so a probe would pass on a kernel
/// that later hangs. Enable it only after running the fuzzer soak on the
/// kernel you deploy to:
///
/// ```text
/// RAMJET_DEFER_TASKRUN=1 RAMJET_FUZZ_CASES=400 RAMJET_FUZZ_STEPS=2000 \
///     cargo test --test fuzz_driver --release
/// ```
const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;

impl UringDriver {
    pub fn new() -> io::Result<Self> {
        let multishot_accept =
            std::env::var_os("RAMJET_MULTISHOT_ACCEPT").is_some_and(|value| value == "1");
        // Newest discipline first; an older kernel rejects unknown setup
        // flags with EINVAL and we step down. The driver behaves identically
        // under all of them — only where the kernel runs its bookkeeping moves.
        let deferred = std::env::var_os("RAMJET_DEFER_TASKRUN").is_some_and(|v| v == "1");
        let ladder = if deferred {
            &[
                IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
                IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN,
                IORING_SETUP_COOP_TASKRUN,
                0,
            ][..]
        } else {
            &[
                IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN,
                IORING_SETUP_COOP_TASKRUN,
                0,
            ][..]
        };
        let mut ring = -1;
        let mut p: UringParams = unsafe { mem::zeroed() };
        for &flags in ladder {
            p = unsafe { mem::zeroed() };
            p.flags = flags;
            // SAFETY: io_uring_setup reads `p`, fills it, and returns a ring
            // fd. `p` is a live params struct of the exact ABI size.
            ring = unsafe { libc::syscall(SYS_IO_URING_SETUP, ENTRIES, &mut p) } as libc::c_int;
            if ring >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                break;
            }
        }
        if ring < 0 {
            return Err(io::Error::last_os_error());
        }
        // Single-mmap rings exist since 5.4; this backend does not chase
        // museum kernels. Refusing loudly beats mapping the CQ ring twice.
        if p.features & IORING_FEAT_SINGLE_MMAP == 0 {
            // SAFETY: ring is ours and unshared.
            unsafe { libc::close(ring) };
            return Err(io::Error::other(
                "kernel too old: no IORING_FEAT_SINGLE_MMAP",
            ));
        }

        let sq_mmap_len = std::cmp::max(
            p.sq_off.array as usize + p.sq_entries as usize * mem::size_of::<u32>(),
            p.cq_off.cqes as usize + p.cq_entries as usize * mem::size_of::<Cqe>(),
        );
        // SAFETY: standard io_uring ring mapping: the kernel provides these
        // regions at these fixed offsets on the ring fd.
        let sq_mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sq_mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring,
                IORING_OFF_SQ_RING,
            )
        };
        if sq_mmap == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            // SAFETY: ring is ours and unshared.
            unsafe { libc::close(ring) };
            return Err(e);
        }
        let sqes_len = p.sq_entries as usize * mem::size_of::<Sqe>();
        // SAFETY: as above, at the SQE-array offset.
        let sqes = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sqes_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring,
                IORING_OFF_SQES,
            )
        };
        if sqes == libc::MAP_FAILED {
            let e = io::Error::last_os_error();
            // SAFETY: both resources are ours and unshared.
            unsafe {
                libc::munmap(sq_mmap, sq_mmap_len);
                libc::close(ring);
            }
            return Err(e);
        }

        let base = sq_mmap as *mut u8;
        // SAFETY (all below): offsets come from the kernel for this mapping;
        // each points at a u32 the kernel and we update with atomic ops.
        let sq_head = unsafe { base.add(p.sq_off.head as usize) } as *const AtomicU32;
        let sq_tail = unsafe { base.add(p.sq_off.tail as usize) } as *const AtomicU32;
        let sq_mask = unsafe { *(base.add(p.sq_off.ring_mask as usize) as *const u32) };
        let sq_array = unsafe { base.add(p.sq_off.array as usize) } as *mut u32;
        let cq_head = unsafe { base.add(p.cq_off.head as usize) } as *const AtomicU32;
        let cq_tail = unsafe { base.add(p.cq_off.tail as usize) } as *const AtomicU32;
        let cq_mask = unsafe { *(base.add(p.cq_off.ring_mask as usize) as *const u32) };
        let cqes = unsafe { base.add(p.cq_off.cqes as usize) } as *const Cqe;

        // The indirection array never changes: slot i of the SQE array is
        // always entry i. Fill it once, identity, and forget it exists.
        for i in 0..p.sq_entries {
            // SAFETY: array has sq_entries u32 cells per the mapping above.
            unsafe { *sq_array.add(i as usize) = i };
        }

        let stats_every_ms: u64 = std::env::var_os("RAMJET_URING_STATS")
            .and_then(|v| v.to_str().and_then(|v| v.parse().ok()))
            .unwrap_or(0);
        let mut me = Self {
            ring,
            sq_mmap: base,
            sq_mmap_len,
            sq_head,
            sq_tail,
            sq_mask,
            sq_entries: p.sq_entries,
            sqes: sqes as *mut Sqe,
            sqes_len,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            to_submit: 0,
            ops: Slab::new(),
            fds: Vec::new(),
            pool: Vec::new(),
            ready: Vec::new(),
            ready_accepted: Vec::new(),
            bufs: None,
            multishot_accept: false,
            active_accept_arms: Vec::new(),
            multishot_accept_arms: 0,
            multishot_arms: 0,
            ring_buffers_consumed: 0,
            ring_buffers_reclaimed: 0,
            live_arms: 0,
            enobufs: 0,
            waits_early: 0,
            enters_waiting: 0,
            enters_submitting: 0,
            cqes_harvested: 0,
            enter_cpu_ns: 0,
            wait_cpu_ns: 0,
            stats_every_ms,
            // First report after a full interval, not on the first wait: one
            // enter into a run there is nothing to average.
            stats_next_ns: monotonic_ns() + stats_every_ms * 1_000_000,
            _not_send: PhantomData,
        };

        // Provided buffers are an optimisation, not a requirement: if the
        // kernel will not register the ring, the single-shot path stands as-is.
        let mut pool = mem::take(&mut me.pool);
        me.bufs = BufRing::new(me.ring, &mut pool).ok();
        me.pool = pool;
        // Multishot accept arrived in Linux 5.19, but synchronous cancellation
        // arrived in 6.0. The latter is a correctness requirement here: an
        // accepted fd can exist before userspace has consumed its CQE, so Drop
        // must be able to cancel and harvest the arm deterministically.
        me.multishot_accept = multishot_accept && me.sync_cancel_supported();
        Ok(me)
    }

    /// Pooled-read buffer size, same contract as the kqueue driver.
    pub fn pool_buf_size() -> usize {
        POOL_BUF_SIZE
    }

    /// Everything this driver believes about its own state, as one line per
    /// descriptor plus a header. Meant for a stalled test to print: the whole
    /// multishot failure class looks identical from the outside — a read that
    /// never completes — and is told apart only by whether the fd still has an
    /// arm, whether anything is stashed behind it, and whether the kernel
    /// agrees the descriptor is readable. So all three are here.
    ///
    /// Diagnostic only. The shape of the string is not a contract and no code
    /// should parse it.
    pub fn debug_state(&self) -> String {
        let occupant = |slot: Option<OpId>| match slot.map(|id| (id, self.ops.peek(id))) {
            None => "-".to_string(),
            Some((id, None)) => format!("{id}=<cell empty or stale>"),
            Some((id, Some(f))) => format!(
                "{id}={}{}",
                match f.kind {
                    Kind::Accept => "Accept",
                    Kind::AcceptWaiting => "AcceptWaiting",
                    Kind::MultishotAccept => "MultishotAccept",
                    Kind::Read { .. } => "Read",
                    Kind::ReadPooled { .. } => "ReadPooled",
                    Kind::PooledWaiting => "PooledWaiting",
                    Kind::ReadWaiting { .. } => "ReadWaiting",
                    Kind::MultishotRecv => "MultishotRecv",
                    Kind::Write { .. } => "Write",
                    Kind::Close => "Close",
                },
                if f.doomed { " (doomed)" } else { "" },
            ),
        };
        let mut s = format!(
            "uring: ops.live={} live_arms={} to_submit={} ready={} pool={} \
             recv_arms={} accept_arms={} ring_consumed={} ring_reclaimed={} enobufs={} \
             enters(waiting={} submitting={}) cqes={} cqes_per_waiting_enter={:.2} \
             waits_early={} cpu_ns(enter={} wait={} thread_total={}) \
             enter_share_of_thread_cpu={:.4}",
            self.ops.live(),
            self.live_arms,
            self.to_submit,
            self.ready.len(),
            self.pool.len(),
            self.multishot_arms,
            self.multishot_accept_arms,
            self.ring_buffers_consumed,
            self.ring_buffers_reclaimed,
            self.enobufs,
            self.enters_waiting,
            self.enters_submitting,
            self.cqes_harvested,
            self.cqes_harvested as f64 / self.enters_waiting.max(1) as f64,
            self.waits_early,
            self.enter_cpu_ns,
            self.wait_cpu_ns,
            thread_cpu_ns(),
            self.enter_cpu_ns as f64 / thread_cpu_ns().max(1) as f64,
        );
        for (fd, st) in self.fds.iter().enumerate() {
            if st.read_slot.is_none()
                && st.write_slot.is_none()
                && st.ms_arm.is_none()
                && st.accept_arm.is_none()
                && st.accepted.is_empty()
                && st.stash.is_empty()
            {
                continue;
            }
            let stash: Vec<String> = st
                .stash
                .iter()
                .map(|i| match i {
                    Stashed::Data(b) => format!("Data({})", b.len()),
                    Stashed::Eof => "Eof".to_string(),
                    Stashed::Err(e) => format!("Err({e})"),
                })
                .collect();
            // What the kernel thinks, next to what we think: a parked read on a
            // descriptor the kernel calls readable is the whole bug, visible in
            // one line.
            let mut pf = libc::pollfd {
                fd: fd as RawFd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live pollfd, zero timeout.
            unsafe { libc::poll(&mut pf, 1, 0) };
            let mut queued: libc::c_int = -1;
            // SAFETY: FIONREAD writes one c_int.
            unsafe { libc::ioctl(fd as RawFd, libc::FIONREAD, &mut queued) };
            s.push_str(&format!(
                "\n  fd {fd}: read={} write={} recv_arm={} accept_arm={} \
                 accepted={} stash={stash:?} \
                 kernel(revents={:#x} readable={queued})",
                occupant(st.read_slot),
                occupant(st.write_slot),
                occupant(st.ms_arm),
                occupant(st.accept_arm),
                st.accepted.len(),
                pf.revents,
            ));
        }
        s
    }

    /// Whether the kernel accepted a provided-buffer ring.
    ///
    /// Test-only: a silent fallback to the single-shot path would still pass
    /// every behavioural test, so the suite asserts the fast path is present
    /// rather than trusting that it is.
    #[cfg(test)]
    pub(crate) fn has_buffer_ring(&self) -> bool {
        self.bufs.is_some()
    }

    fn fd_state(&mut self, fd: RawFd) -> &mut FdState {
        let i = fd as usize;
        if i >= self.fds.len() {
            self.fds.resize_with(i + 1, FdState::default);
        }
        &mut self.fds[i]
    }

    fn is_socket(&mut self, fd: RawFd) -> bool {
        if let Some(s) = self.fd_state(fd).sock {
            return s;
        }
        let mut ty: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `ty`/`len` are live locals of the advertised size.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut ty).cast(),
                &mut len,
            )
        };
        let sock = r == 0;
        self.fd_state(fd).sock = Some(sock);
        sock
    }

    /// Write one SQE into the ring. No syscall unless the ring is full.
    fn push_sqe(
        &mut self,
        opcode: u8,
        fd: RawFd,
        addr: u64,
        len: u32,
        op_flags: u32,
        user_data: u64,
    ) -> io::Result<()> {
        self.push_sqe_ex(opcode, fd, addr, len, op_flags, user_data, 0, 0, 0)
    }

    /// The full squeue entry, including the fields only multishot and
    /// buffer-select ops set.
    #[allow(clippy::too_many_arguments)]
    fn push_sqe_ex(
        &mut self,
        opcode: u8,
        fd: RawFd,
        addr: u64,
        len: u32,
        op_flags: u32,
        user_data: u64,
        ioprio: u16,
        sqe_flags: u8,
        buf_index: u16,
    ) -> io::Result<()> {
        // SAFETY: ring pointers are valid for the driver's lifetime.
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let tail = unsafe { &*self.sq_tail }.load(Ordering::Relaxed);
        if tail.wrapping_sub(head) == self.sq_entries {
            self.flush()?;
        }
        let tail = unsafe { &*self.sq_tail }.load(Ordering::Relaxed);
        let idx = (tail & self.sq_mask) as usize;
        // SAFETY: idx < sq_entries; the SQE array is ours between tail bumps.
        unsafe {
            self.sqes.add(idx).write(Sqe {
                opcode,
                flags: sqe_flags,
                ioprio,
                fd,
                off: 0,
                addr,
                len,
                op_flags,
                user_data,
                buf_index,
                personality: 0,
                splice_fd_in: 0,
                _pad: [0; 2],
            });
        }
        // Publish: the kernel may read the SQE the moment the tail moves.
        unsafe { &*self.sq_tail }.store(tail.wrapping_add(1), Ordering::Release);
        self.to_submit += 1;
        Ok(())
    }

    /// Hand queued SQEs to the kernel without waiting for completions.
    fn flush(&mut self) -> io::Result<()> {
        while self.to_submit > 0 {
            self.enters_submitting += 1;
            // SAFETY: plain io_uring_enter with no sigset.
            let r = unsafe {
                libc::syscall(
                    SYS_IO_URING_ENTER,
                    self.ring,
                    self.to_submit,
                    0 as libc::c_uint,
                    0 as libc::c_uint,
                    ptr::null::<libc::c_void>(),
                )
            };
            if r < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // CQ is full of unharvested completions: reap, retry.
                    Some(libc::EBUSY) => {
                        self.drain_cq();
                        continue;
                    }
                    _ => return Err(e),
                }
            }
            self.to_submit -= r as u32;
        }
        Ok(())
    }

    /// Queue the kernel-facing SQE for `flight` under `id`.
    fn arm(&mut self, id: OpId, flight: &mut Flight) -> io::Result<()> {
        match &mut flight.kind {
            Kind::Accept => self.push_sqe(
                IORING_OP_ACCEPT,
                flight.fd,
                0,
                0,
                libc::SOCK_CLOEXEC as u32,
                id,
            ),
            Kind::MultishotAccept => self.push_sqe_ex(
                IORING_OP_ACCEPT,
                flight.fd,
                0,
                0,
                libc::SOCK_CLOEXEC as u32,
                id,
                IORING_ACCEPT_MULTISHOT,
                0,
                0,
            ),
            Kind::Read { buf } => {
                // Caller buffer keeps its own length; read fills [0..len].
                self.push_sqe(
                    IORING_OP_READ,
                    flight.fd,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u32,
                    0,
                    id,
                )
            }
            Kind::ReadPooled { buf } => {
                // Pool buffers come back empty; the kernel writes into spare
                // capacity and the CQE's byte count becomes the length.
                self.push_sqe(
                    IORING_OP_READ,
                    flight.fd,
                    buf.as_mut_ptr() as u64,
                    buf.capacity() as u32,
                    0,
                    id,
                )
            }
            Kind::Write { buf, start, sent } => {
                let from = *start + *sent;
                let (opcode, op_flags) = if self.is_socket(flight.fd) {
                    // MSG_NOSIGNAL: ramjet is a library; a dead peer must be
                    // EPIPE, never a process-killing SIGPIPE.
                    (IORING_OP_SEND, libc::MSG_NOSIGNAL as u32)
                } else {
                    (IORING_OP_WRITE, 0)
                };
                // SAFETY of the raw pointer: `from <= buf.len()` is upheld by
                // submit-time validation and by `sent` only growing by the
                // kernel's own byte counts.
                self.push_sqe(
                    opcode,
                    flight.fd,
                    unsafe { buf.as_ptr().add(from) } as u64,
                    (buf.len() - from) as u32,
                    op_flags,
                    id,
                )
            }
            Kind::Close => self.push_sqe(IORING_OP_CLOSE, flight.fd, 0, 0, 0, id),
            // The arm names no buffer: the kernel picks one from group BGID
            // and reports which in the completion's flags.
            Kind::MultishotRecv => self.push_sqe_ex(
                IORING_OP_RECV,
                flight.fd,
                0,
                0,
                0,
                id,
                IORING_RECV_MULTISHOT,
                IOSQE_BUFFER_SELECT,
                BGID,
            ),
            // Waiting ops have no squeue entry at all — they are woken by the
            // arm's deliveries, which is what makes them free to park.
            Kind::AcceptWaiting | Kind::PooledWaiting | Kind::ReadWaiting { .. } => Ok(()),
        }
    }

    /// Ensure `fd` has a live multishot receive arm.
    ///
    /// The arm is driver infrastructure under its own slab id; it is never the
    /// caller's read slot, so it does not consume the one-read-per-fd budget.
    fn ensure_recv_arm(&mut self, fd: RawFd) -> io::Result<()> {
        if self.fd_state(fd).ms_arm.is_some() {
            return Ok(());
        }
        let id = self.ops.reserve(0);
        let mut flight = Flight {
            fd,
            kind: Kind::MultishotRecv,
            doomed: false,
        };
        if let Err(e) = self.arm(id, &mut flight) {
            self.ops.release(id);
            return Err(e);
        }
        self.ops.put_op(id, flight);
        self.fd_state(fd).ms_arm = Some(id);
        self.multishot_arms += 1;
        self.live_arms += 1;
        Ok(())
    }

    fn sync_cancel(&self, id: OpId, timeout: KernelTimespec) -> io::Result<usize> {
        let reg = SyncCancelReg {
            addr: id,
            fd: -1,
            flags: 0,
            timeout,
            opcode: 0,
            pad: [0; 7],
            pad2: [0; 3],
        };
        // SAFETY: `reg` exactly mirrors the stable kernel ABI, remains live
        // for the synchronous call, and this ring belongs to the driver.
        let result = unsafe {
            libc::syscall(
                SYS_IO_URING_REGISTER,
                self.ring,
                IORING_REGISTER_SYNC_CANCEL,
                &raw const reg,
                1u32,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn sync_cancel_supported(&self) -> bool {
        match self.sync_cancel(
            SENTINEL,
            KernelTimespec {
                tv_sec: -1,
                tv_nsec: -1,
            },
        ) {
            Ok(_) => true,
            // No request uses SENTINEL while a driver is being built. ENOENT
            // therefore proves the opcode was understood and found no match.
            Err(error) => error.raw_os_error() == Some(libc::ENOENT),
        }
    }

    fn shutdown_accept_arms(&mut self) {
        if self.active_accept_arms.is_empty() {
            return;
        }
        // Submit any arm that still only exists in the SQ, then make every
        // live arm close raced accepts instead of exposing them.
        let _ = self.flush();
        self.drain_cq();
        let arms = self.active_accept_arms.clone();
        for &arm in &arms {
            let Some(mut flight) = self.ops.take_op(arm) else {
                continue;
            };
            if !matches!(flight.kind, Kind::MultishotAccept) {
                self.ops.put_op(arm, flight);
                continue;
            }
            flight.doomed = true;
            self.ops.put_op(arm, flight);
        }
        for arm in arms {
            // A finite timeout keeps Drop bounded on a broken kernel. The
            // feature probe in `new` prevents this path on kernels without
            // synchronous cancellation support.
            let _ = self.sync_cancel(
                arm,
                KernelTimespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                },
            );
            // DEFER_TASKRUN kernels publish task-local completions when the
            // issuer re-enters with GETEVENTS. `min_complete = 0` runs that
            // work without introducing a second unbounded wait in Drop.
            // SAFETY: plain io_uring_enter with no sigset or submissions.
            unsafe {
                libc::syscall(
                    SYS_IO_URING_ENTER,
                    self.ring,
                    0 as libc::c_uint,
                    0 as libc::c_uint,
                    IORING_ENTER_GETEVENTS,
                    ptr::null::<libc::c_void>(),
                )
            };
            // Synchronous cancellation has retired the request; consume every
            // accepted fd it published before unmapping the CQ.
            self.drain_cq();
        }
    }

    fn retire_accept_arm(&mut self, id: OpId) {
        if let Some(index) = self
            .active_accept_arms
            .iter()
            .position(|candidate| *candidate == id)
        {
            self.active_accept_arms.swap_remove(index);
        }
        self.live_arms = self.live_arms.saturating_sub(1);
        self.ops.release(id);
    }

    fn handoff_ready(&mut self, out: &mut Vec<Completion>) {
        out.append(&mut self.ready);
        // Ownership of every successful Accept result now belongs to `out`.
        self.ready_accepted.clear();
    }

    /// Ensure `fd` has one live multishot accept arm.
    fn ensure_accept_arm(&mut self, fd: RawFd) -> io::Result<()> {
        if self.fd_state(fd).accept_arm.is_some() {
            return Ok(());
        }
        let id = self.ops.reserve(0);
        let mut flight = Flight {
            fd,
            kind: Kind::MultishotAccept,
            doomed: false,
        };
        if let Err(error) = self.arm(id, &mut flight) {
            self.ops.release(id);
            return Err(error);
        }
        self.ops.put_op(id, flight);
        self.fd_state(fd).accept_arm = Some(id);
        self.active_accept_arms.push(id);
        self.multishot_accept_arms += 1;
        self.live_arms += 1;
        Ok(())
    }

    /// Apply the socket setup promised by `Op::Accept`.
    fn prepare_accepted(&mut self, fd: RawFd) {
        self.fd_state(fd).sock = Some(true);
        let on: libc::c_int = 1;
        // SAFETY: `on` is a live c_int with the advertised size.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&raw const on).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }

    fn stash_accept(&mut self, listener: RawFd, accepted: Accepted) {
        if self.fd_state(listener).accepted.len() < ACCEPT_STASH_LIMIT {
            self.fd_state(listener).accepted.push_back(accepted);
        } else if let Accepted::Fd(fd) = accepted {
            // The application stopped submitting Accept. Keep speculative
            // ownership bounded rather than exhausting its descriptor table.
            // SAFETY: the arm has not exposed this descriptor to any caller.
            unsafe { libc::close(fd) };
        }
    }

    /// Pair one accept-arm delivery with the caller waiting on this listener,
    /// or retain it until the caller submits its next `Op::Accept`.
    fn deliver_accept(&mut self, listener: RawFd, accepted: Accepted) {
        let slot = self.fd_state(listener).read_slot;
        let waiting = slot.filter(|&id| {
            matches!(
                self.ops.peek(id).map(|flight| &flight.kind),
                Some(Kind::AcceptWaiting)
            )
        });
        let Some(waiting) = waiting else {
            self.stash_accept(listener, accepted);
            return;
        };
        let Some(flight) = self.ops.take_op(waiting) else {
            self.stash_accept(listener, accepted);
            return;
        };
        debug_assert!(matches!(flight.kind, Kind::AcceptWaiting));
        let user = self.ops.user(waiting);
        let result = match accepted {
            Accepted::Fd(fd) => {
                self.ready_accepted.push(fd);
                Ok(i64::from(fd))
            }
            Accepted::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
        };
        self.free_slot(listener, true);
        self.ready.push(Completion {
            id: waiting,
            user,
            result,
            buf: None,
        });
        self.ops.release(waiting);
    }

    /// The kernel rejected multishot accept. Turn the already-pending caller
    /// op into an ordinary accept without exposing a synthetic error or
    /// requiring the application to resubmit.
    fn fallback_accept_waiter(&mut self, listener: RawFd) {
        let Some(waiting) = self.fd_state(listener).read_slot else {
            return;
        };
        let Some(mut flight) = self.ops.take_op(waiting) else {
            return;
        };
        if !matches!(flight.kind, Kind::AcceptWaiting) {
            self.ops.put_op(waiting, flight);
            return;
        }
        let user = self.ops.user(waiting);
        flight.kind = Kind::Accept;
        if let Err(error) = self.arm(waiting, &mut flight) {
            self.free_slot(listener, true);
            self.ready.push(Completion {
                id: waiting,
                user,
                result: Err(error),
                buf: None,
            });
            self.ops.release(waiting);
        } else {
            self.ops.put_op(waiting, flight);
        }
    }

    /// Whether this fd should use the multishot path at all.
    fn multishot_ok(&mut self, fd: RawFd) -> bool {
        self.bufs.is_some() && self.is_socket(fd)
    }

    /// Give a delivery to the fd's waiting read, or hold it until one arrives.
    fn deliver(&mut self, fd: RawFd, item: Stashed) {
        let slot = self.fd_state(fd).read_slot;
        // Only a parked waiting op can be served this way; a single-shot read
        // has its own squeue entry and its own completion already coming.
        let servable = slot.filter(|&id| {
            matches!(
                self.ops.peek(id).map(|f| &f.kind),
                Some(Kind::PooledWaiting) | Some(Kind::ReadWaiting { .. })
            )
        });
        let Some(waiting) = servable else {
            self.fd_state(fd).stash.push_back(item);
            return;
        };
        let Some(flight) = self.ops.take_op(waiting) else {
            self.fd_state(fd).stash.push_back(item);
            return;
        };
        let user = self.ops.user(waiting);
        let doomed = flight.doomed;
        match flight.kind {
            Kind::PooledWaiting => {
                let (result, buf) = match item {
                    Stashed::Data(b) => (Ok(b.len() as i64), b),
                    Stashed::Eof => (Ok(0), Vec::new()),
                    Stashed::Err(e) => (Err(io::Error::from_raw_os_error(e)), Vec::new()),
                };
                self.free_slot(fd, true);
                self.ready.push(Completion {
                    id: waiting,
                    user,
                    result,
                    buf: Some(buf),
                });
                self.ops.release(waiting);
            }
            Kind::ReadWaiting { mut buf } => {
                let result = match item {
                    Stashed::Data(mut data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        if n < data.len() {
                            // A byte stream does not lose the remainder just
                            // because the caller's buffer was smaller.
                            data.drain(..n);
                            self.fd_state(fd).stash.push_front(Stashed::Data(data));
                        } else {
                            pool::put(&mut self.pool, data);
                        }
                        Ok(n as i64)
                    }
                    Stashed::Eof => Ok(0),
                    Stashed::Err(e) => Err(io::Error::from_raw_os_error(e)),
                };
                self.free_slot(fd, true);
                self.ready.push(Completion {
                    id: waiting,
                    user,
                    result,
                    buf: Some(buf),
                });
                self.ops.release(waiting);
            }
            kind => {
                // The peek above admitted only the two waiting kinds.
                self.ops.put_op(waiting, Flight { fd, kind, doomed });
                self.fd_state(fd).stash.push_back(item);
            }
        }
    }

    /// Serve a caller's read from the stash, if anything is queued.
    fn serve_from_stash(
        &mut self,
        fd: RawFd,
        pooled: bool,
        caller: &mut Option<Vec<u8>>,
    ) -> Option<(io::Result<i64>, Vec<u8>)> {
        let item = self.fd_state(fd).stash.pop_front()?;
        match item {
            Stashed::Data(mut data) => {
                if pooled {
                    Some((Ok(data.len() as i64), data))
                } else {
                    let mut buf = caller.take().unwrap_or_default();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        data.drain(..n);
                        self.fd_state(fd).stash.push_front(Stashed::Data(data));
                    } else {
                        pool::put(&mut self.pool, data);
                    }
                    Some((Ok(n as i64), buf))
                }
            }
            Stashed::Eof => Some((Ok(0), caller.take().unwrap_or_default())),
            Stashed::Err(e) => Some((
                Err(io::Error::from_raw_os_error(e)),
                caller.take().unwrap_or_default(),
            )),
        }
    }

    /// Drain every CQE currently visible. No syscall.
    fn drain_cq(&mut self) {
        // SAFETY: ring pointers are valid for the driver's lifetime.
        let tail = unsafe { &*self.cq_tail }.load(Ordering::Acquire);
        let mut head = unsafe { &*self.cq_head }.load(Ordering::Relaxed);
        while head != tail {
            let idx = (head & self.cq_mask) as usize;
            // SAFETY: idx < cq_entries; entries below tail are published.
            let cqe = unsafe { &*self.cqes.add(idx) };
            let (user_data, res, flags) = (cqe.user_data, cqe.res, cqe.flags);
            head = head.wrapping_add(1);
            // Free the CQ slot before processing: completing an op can
            // resubmit (partial write) and in the worst case flush into EBUSY
            // handling, which drains this ring reentrantly-by-loop.
            unsafe { &*self.cq_head }.store(head, Ordering::Release);
            self.cqes_harvested += 1;
            self.complete(user_data, res, flags);
        }
    }

    /// Turn one CQE into a completion (or a resubmission, or nothing).
    fn complete(&mut self, id: u64, res: i32, flags: u32) {
        // Reclaim a kernel-selected buffer first, whatever becomes of the op.
        // The kernel has already taken it out of the ring, so skipping this on
        // an ignorable CQE would shrink the ring by one buffer every time —
        // and a ring that has quietly run dry answers every receive with
        // -ENOBUFS forever.
        //
        // The flag alone decides, never the byte count: the kernel gives back
        // the buffer it picked even when the receive ended in EOF or an error,
        // so keying this off `res > 0` leaks one buffer per closed connection.
        let selected = if flags & IORING_CQE_F_BUFFER != 0 {
            let bid = (flags >> IORING_CQE_BUFFER_SHIFT) as u16;
            let n = res.max(0) as usize;
            match self.bufs.as_mut() {
                Some(ring) => {
                    let got = ring.take(bid, n, &mut self.pool);
                    self.ring_buffers_reclaimed += u64::from(got.is_some());
                    got
                }
                None => None,
            }
        } else {
            None
        };
        if id == SENTINEL {
            if let Some(buf) = selected {
                pool::put(&mut self.pool, buf);
            }
            return; // an ASYNC_CANCEL's own result: not interesting
        }
        let Some(mut flight) = self.ops.take_op(id) else {
            // Stale or duplicated CQE: generation says ignore. The buffer is
            // still ours to give back.
            if let Some(buf) = selected {
                pool::put(&mut self.pool, buf);
            }
            return;
        };
        let user = self.ops.user(id);

        if matches!(flight.kind, Kind::MultishotAccept) {
            if let Some(buf) = selected {
                pool::put(&mut self.pool, buf);
            }
            let listener = flight.fd;
            let more = flags & IORING_CQE_F_MORE != 0;
            let errno = res.checked_neg().filter(|_| res < 0);

            if flight.doomed {
                // A connection can race with cancellation. It was never handed
                // to the caller, so close it here rather than leak an installed
                // process descriptor.
                if res >= 0 {
                    // SAFETY: this accepted descriptor belongs exclusively to
                    // the doomed arm and is not visible anywhere else.
                    unsafe { libc::close(res) };
                }
                if more {
                    self.ops.put_op(id, flight);
                } else {
                    if self.fd_state(listener).accept_arm == Some(id) {
                        self.fd_state(listener).accept_arm = None;
                    }
                    self.retire_accept_arm(id);
                }
                return;
            }

            let unsupported = !more
                && errno.is_some_and(|errno| {
                    [libc::EINVAL, libc::EOPNOTSUPP, libc::ENOSYS].contains(&errno)
                });
            if unsupported {
                self.multishot_accept = false;
                self.fd_state(listener).accept_arm = None;
                self.retire_accept_arm(id);
                self.fallback_accept_waiter(listener);
                return;
            }

            if !more {
                self.fd_state(listener).accept_arm = None;
            }
            if res >= 0 {
                self.prepare_accepted(res);
                self.deliver_accept(listener, Accepted::Fd(res));
            } else {
                self.deliver_accept(listener, Accepted::Err(errno.unwrap_or(libc::EIO)));
            }
            if more {
                self.ops.put_op(id, flight);
            } else {
                self.retire_accept_arm(id);
            }
            return;
        }

        // Only the multishot arm asks for kernel-selected buffers. If one turns
        // up on any other op it belongs to nobody; give it back rather than
        // drop it on the floor.
        let selected = match (selected, matches!(flight.kind, Kind::MultishotRecv)) {
            (Some(buf), false) => {
                pool::put(&mut self.pool, buf);
                None
            }
            (other, _) => other,
        };

        if flight.doomed {
            // Close already freed the fd slots; just deliver the contract.
            if matches!(flight.kind, Kind::Accept) && res >= 0 {
                // The accept won its race with cancellation, but Close already
                // promised ECANCELED to the caller. The installed descriptor
                // therefore never crosses the driver boundary.
                // SAFETY: this successful doomed accept is driver-owned.
                unsafe { libc::close(res) };
            }
            let buf = match flight.kind {
                Kind::Read { buf } => Some(buf),
                Kind::Write { buf, .. } => Some(buf),
                Kind::ReadPooled { buf } => {
                    // The pooled buffer was never the caller's; keep it.
                    pool::put(&mut self.pool, buf);
                    None
                }
                Kind::ReadWaiting { buf } => Some(buf),
                // Parked pooled reads and the arm itself own nothing.
                Kind::Accept
                | Kind::AcceptWaiting
                | Kind::MultishotAccept
                | Kind::Close
                | Kind::PooledWaiting
                | Kind::MultishotRecv => None,
            };
            self.ready.push(Completion {
                id,
                user,
                result: Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                buf,
            });
            self.ops.release(id);
            return;
        }

        if matches!(flight.kind, Kind::MultishotRecv) {
            let fd = flight.fd;
            // The kernel drops the arm when F_MORE is clear; mirror that here
            // so the next pooled read re-arms rather than waiting forever.
            let more = flags & IORING_CQE_F_MORE != 0;
            if !more {
                self.fd_state(fd).ms_arm = None;
                self.live_arms = self.live_arms.saturating_sub(1);
            }
            match selected {
                // Bytes: the buffer is the delivery.
                Some(buf) if res > 0 => {
                    self.ring_buffers_consumed += 1;
                    self.deliver(fd, Stashed::Data(buf));
                }
                // EOF or error with a buffer the kernel picked and never
                // filled: it is the ring's, not the caller's.
                other => {
                    if let Some(buf) = other {
                        pool::put(&mut self.pool, buf);
                    }
                    if res == 0 {
                        self.deliver(fd, Stashed::Eof);
                    } else if -res == libc::ENOBUFS {
                        self.enobufs += 1;
                    } else if res < 0 {
                        self.deliver(fd, Stashed::Err(-res));
                    }
                }
            }
            // Out of buffers is not an error to report: the ring refills as
            // completions are consumed, and the next read re-arms.
            if more {
                self.ops.put_op(id, flight);
                return;
            }
            self.ops.release(id);
            // The arm is gone. A read parked on it is waiting for a wake-up
            // that will never come — and it holds the fd's read slot, so the
            // caller cannot issue the next ReadPooled that would re-arm. Do it
            // here instead.
            let still_waiting = self.fd_state(fd).read_slot.is_some_and(|w| {
                matches!(
                    self.ops.peek(w).map(|f| &f.kind),
                    Some(Kind::PooledWaiting) | Some(Kind::ReadWaiting { .. })
                )
            });
            if still_waiting && let Err(e) = self.ensure_recv_arm(fd) {
                // Re-arming failed: fail the parked read rather than strand it.
                self.deliver(fd, Stashed::Err(e.raw_os_error().unwrap_or(libc::EIO)));
            }
            return;
        }

        match &mut flight.kind {
            Kind::Accept => {
                let result = if res < 0 {
                    Err(io::Error::from_raw_os_error(-res))
                } else {
                    // accept(2) can only return a socket. Cache that fact and
                    // apply the same socket setup as a multishot delivery.
                    self.prepare_accepted(res);
                    self.ready_accepted.push(res);
                    Ok(res as i64)
                };
                self.free_slot(flight.fd, true);
                self.ready.push(Completion {
                    id,
                    user,
                    result,
                    buf: None,
                });
                self.ops.release(id);
            }
            Kind::Read { buf } => {
                let buf = mem::take(buf);
                let result = if res < 0 {
                    Err(io::Error::from_raw_os_error(-res))
                } else {
                    Ok(res as i64)
                };
                self.free_slot(flight.fd, true);
                self.ready.push(Completion {
                    id,
                    user,
                    result,
                    buf: Some(buf),
                });
                self.ops.release(id);
            }
            Kind::ReadPooled { buf } => {
                let mut buf = mem::take(buf);
                let result = if res < 0 {
                    Err(io::Error::from_raw_os_error(-res))
                } else {
                    // SAFETY: the kernel wrote exactly `res` bytes at the
                    // start of the buffer; claiming them (and only them) is
                    // the ReadPooled trim contract.
                    unsafe { buf.set_len(res as usize) };
                    Ok(res as i64)
                };
                self.free_slot(flight.fd, true);
                self.ready.push(Completion {
                    id,
                    user,
                    result,
                    buf: Some(buf),
                });
                self.ops.release(id);
            }
            Kind::Write { buf, start, sent } => {
                if res < 0 {
                    let buf = mem::take(buf);
                    self.free_slot(flight.fd, false);
                    self.ready.push(Completion {
                        id,
                        user,
                        result: Err(io::Error::from_raw_os_error(-res)),
                        buf: Some(buf),
                    });
                    self.ops.release(id);
                    return;
                }
                *sent += res as usize;
                if *start + *sent < buf.len() {
                    // Short write: the driver owes the rest. Same slab cell,
                    // same id, new SQE for the remainder.
                    if let Err(e) = self.arm(id, &mut flight) {
                        let Kind::Write { buf, .. } = flight.kind else {
                            unreachable!()
                        };
                        self.free_slot(flight.fd, false);
                        self.ready.push(Completion {
                            id,
                            user,
                            result: Err(e),
                            buf: Some(buf),
                        });
                        self.ops.release(id);
                        return;
                    }
                    self.ops.put_op(id, flight);
                    return;
                }
                let written = (buf.len() - *start) as i64;
                let buf = mem::take(buf);
                self.free_slot(flight.fd, false);
                self.ready.push(Completion {
                    id,
                    user,
                    result: Ok(written),
                    buf: Some(buf),
                });
                self.ops.release(id);
            }
            // Woken by a driver arm, never directly by a completion queue entry.
            Kind::AcceptWaiting
            | Kind::MultishotAccept
            | Kind::PooledWaiting
            | Kind::ReadWaiting { .. }
            | Kind::MultishotRecv => {
                self.ops.put_op(id, flight);
            }
            Kind::Close => {
                let result = if res < 0 {
                    Err(io::Error::from_raw_os_error(-res))
                } else {
                    Ok(0)
                };
                self.ready.push(Completion {
                    id,
                    user,
                    result,
                    buf: None,
                });
                self.ops.release(id);
            }
        }
    }

    fn free_slot(&mut self, fd: RawFd, read_side: bool) {
        let st = self.fd_state(fd);
        if read_side {
            st.read_slot = None;
        } else {
            st.write_slot = None;
        }
    }

    fn queue(&mut self, mut flight: Flight, user: u64) -> io::Result<OpId> {
        let id = self.ops.reserve(user);
        if let Err(e) = self.arm(id, &mut flight) {
            self.ops.release(id);
            return Err(e);
        }
        self.ops.put_op(id, flight);
        Ok(id)
    }

    fn submit_inner(&mut self, op: Op, user: u64) -> io::Result<OpId> {
        match op {
            Op::Accept { fd } => {
                if self.fd_state(fd).read_slot.is_some() {
                    return Err(busy());
                }
                if let Some(accepted) = self.fd_state(fd).accepted.pop_front() {
                    let id = self.ops.reserve(user);
                    self.ops.release(id);
                    let result = match accepted {
                        Accepted::Fd(accepted) => {
                            self.ready_accepted.push(accepted);
                            Ok(i64::from(accepted))
                        }
                        Accepted::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                    };
                    self.ready.push(Completion {
                        id,
                        user,
                        result,
                        buf: None,
                    });
                    return Ok(id);
                }
                let kind = if self.multishot_accept {
                    self.ensure_accept_arm(fd)?;
                    Kind::AcceptWaiting
                } else {
                    Kind::Accept
                };
                let id = self.queue(
                    Flight {
                        fd,
                        kind,
                        doomed: false,
                    },
                    user,
                )?;
                self.fd_state(fd).read_slot = Some(id);
                Ok(id)
            }
            Op::Read { fd, buf } => {
                if buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "zero-length read is indistinguishable from EOF",
                    ));
                }
                if self.fd_state(fd).read_slot.is_some() {
                    return Err(busy());
                }
                // Anything an arm already delivered sits at the front of this
                // stream, so it is served first — whether or not the arm that
                // fetched it is still up. A fresh RECV would jump over it.
                let mut caller = Some(buf);
                if let Some((result, buf)) = self.serve_from_stash(fd, false, &mut caller) {
                    let id = self.ops.reserve(user);
                    self.ops.release(id);
                    self.ready.push(Completion {
                        id,
                        user,
                        result,
                        buf: Some(buf),
                    });
                    return Ok(id);
                }
                let buf = caller.take().unwrap_or_default();
                // Once an arm owns this fd's stream, a plain Read waits on it
                // too — issuing a competing RECV would race the arm for the
                // same bytes and reorder the stream.
                if self.fd_state(fd).ms_arm.is_some() {
                    let id = self.queue(
                        Flight {
                            fd,
                            kind: Kind::ReadWaiting { buf },
                            doomed: false,
                        },
                        user,
                    )?;
                    self.fd_state(fd).read_slot = Some(id);
                    return Ok(id);
                }
                let id = self.queue(
                    Flight {
                        fd,
                        kind: Kind::Read { buf },
                        doomed: false,
                    },
                    user,
                )?;
                self.fd_state(fd).read_slot = Some(id);
                Ok(id)
            }
            Op::ReadPooled { fd } => {
                if self.fd_state(fd).read_slot.is_some() {
                    return Err(busy());
                }
                // Anything the arm already delivered completes now, with no
                // syscall and nothing re-armed.
                let mut none = None;
                if let Some((result, buf)) = self.serve_from_stash(fd, true, &mut none) {
                    let id = self.ops.reserve(user);
                    self.ops.release(id);
                    self.ready.push(Completion {
                        id,
                        user,
                        result,
                        buf: Some(buf),
                    });
                    return Ok(id);
                }
                if self.multishot_ok(fd) {
                    // Nothing queued: park owning no buffer and let the arm
                    // wake us. Re-arms lazily if the kernel dropped the arm.
                    self.ensure_recv_arm(fd)?;
                    let id = self.queue(
                        Flight {
                            fd,
                            kind: Kind::PooledWaiting,
                            doomed: false,
                        },
                        user,
                    )?;
                    self.fd_state(fd).read_slot = Some(id);
                    return Ok(id);
                }
                let buf = pool::take(&mut self.pool);
                let id = self.queue(
                    Flight {
                        fd,
                        kind: Kind::ReadPooled { buf },
                        doomed: false,
                    },
                    user,
                )?;
                self.fd_state(fd).read_slot = Some(id);
                Ok(id)
            }
            Op::Write { fd, buf } => self.submit_write(fd, buf, 0, user),
            Op::WriteFrom { fd, buf, start } => {
                if start > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "WriteFrom start beyond the end of the buffer",
                    ));
                }
                self.submit_write(fd, buf, start, user)
            }
            Op::Close { fd } => {
                // Doom whatever is in flight; free the slots immediately so a
                // recycled fd number starts clean (see module docs).
                let st = mem::take(self.fd_state(fd));
                for doomed in [st.read_slot, st.write_slot].into_iter().flatten() {
                    if let Some(mut f) = self.ops.take_op(doomed) {
                        // A waiting op never had a squeue entry: the multishot
                        // arm was going to wake it. There is no CQE coming for
                        // it, ever, so cancel it here rather than wait forever.
                        if let Kind::AcceptWaiting
                        | Kind::PooledWaiting
                        | Kind::ReadWaiting { .. } = f.kind
                        {
                            let user = self.ops.user(doomed);
                            let buf = match f.kind {
                                Kind::ReadWaiting { buf } => Some(buf),
                                _ => None,
                            };
                            self.ready.push(Completion {
                                id: doomed,
                                user,
                                result: Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                                buf,
                            });
                            self.ops.release(doomed);
                            continue;
                        }
                        f.doomed = true;
                        self.ops.put_op(doomed, f);
                        // Ask the kernel to hurry the op's CQE along. Its own
                        // result is noise; the doomed op's CQE is the signal.
                        self.push_sqe(IORING_OP_ASYNC_CANCEL, -1, doomed, 0, 0, SENTINEL)?;
                    }
                }
                // The multishot arm is the driver's, not the caller's: cancel
                // it and forget the cell. Its trailing CQE finds nothing and is
                // ignored, exactly like any other stale completion.
                if let Some(arm) = st.ms_arm {
                    self.live_arms = self.live_arms.saturating_sub(1);
                    self.ops.release(arm);
                    self.push_sqe(IORING_OP_ASYNC_CANCEL, -1, arm, 0, 0, SENTINEL)?;
                }
                // Unlike receive buffers, accepted descriptors are installed
                // into this process. Keep the arm cell until its final CQE so
                // racing accepts can be identified and closed safely.
                if let Some(arm) = st.accept_arm {
                    if let Some(mut flight) = self.ops.take_op(arm) {
                        flight.doomed = true;
                        self.ops.put_op(arm, flight);
                        self.push_sqe(IORING_OP_ASYNC_CANCEL, -1, arm, 0, 0, SENTINEL)?;
                    } else {
                        self.retire_accept_arm(arm);
                    }
                }
                // Early accepts belong to the driver until handed to a caller.
                for accepted in st.accepted {
                    if let Accepted::Fd(accepted) = accepted {
                        // SAFETY: the fd is owned only by this stash.
                        unsafe { libc::close(accepted) };
                    }
                }
                // Stashed buffers were never the caller's; they go back.
                for item in st.stash {
                    if let Stashed::Data(b) = item {
                        pool::put(&mut self.pool, b);
                    }
                }
                let id = self.queue(
                    Flight {
                        fd,
                        kind: Kind::Close,
                        doomed: false,
                    },
                    user,
                )?;
                // Close is control-plane, and its side effect is visible
                // outside the completion stream (the peer sees the socket
                // die). Flush it now so a caller that closes and never waits
                // — a pattern the kqueue backend honored by closing inline —
                // still actually closes. One syscall on a rare path.
                self.flush()?;
                Ok(id)
            }
        }
    }

    fn submit_write(
        &mut self,
        fd: RawFd,
        buf: Vec<u8>,
        start: usize,
        user: u64,
    ) -> io::Result<OpId> {
        if self.fd_state(fd).write_slot.is_some() {
            return Err(busy());
        }
        let id = self.queue(
            Flight {
                fd,
                kind: Kind::Write {
                    buf,
                    start,
                    sent: 0,
                },
                doomed: false,
            },
            user,
        )?;
        self.fd_state(fd).write_slot = Some(id);
        Ok(id)
    }
}

/// Thread CPU nanoseconds. Deliberately *thread CPU* and not wall clock: it
/// does not advance while the thread is blocked, so timing a blocking syscall
/// with it measures the cycles the syscall burns rather than how long a peer
/// took to answer. Only the former can be saved by making fewer calls.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one live timespec, and the clock id is a constant.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one live timespec, and the clock id is a constant.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        "an op of this kind is already in flight on this fd",
    )
}

impl Driver for UringDriver {
    fn submit(&mut self, op: Op) -> io::Result<OpId> {
        self.submit_inner(op, 0)
    }

    fn submit_with(&mut self, op: Op, user: u64) -> io::Result<OpId> {
        self.submit_inner(op, user)
    }

    fn wait(&mut self, out: &mut Vec<Completion>) -> io::Result<()> {
        // Completions already in hand: peek the CQ ring — two atomic loads,
        // no syscall — so kernel-finished ops interleave for free.
        if !self.ready.is_empty() {
            // Queued entries still have to reach the kernel. A completion can
            // reach `ready` without the ring being entered — a multishot
            // delivery served straight from an fd's stash does exactly that —
            // so this path can be taken over and over while a queued re-arm
            // sits unsubmitted. That is one connection stalling for as long as
            // the others stay busy, with nothing else looking wrong. Costs a
            // submit-only syscall, and only when something is actually queued.
            if self.to_submit > 0 {
                self.flush()?;
            }
            self.drain_cq();
            self.waits_early += 1;
            self.handoff_ready(out);
            return Ok(());
        }
        // Nothing of the caller's in flight means nothing can wake us on their
        // behalf. A live multishot arm sits in the slab but is the driver's own
        // work: blocking on it would hang a caller who is simply done.
        if self.ops.live().saturating_sub(self.live_arms) == 0 {
            // Still push any queued entries — the arms have to reach the kernel
            // — but do not wait for them.
            self.flush()?;
            self.drain_cq();
            self.waits_early += 1;
            self.handoff_ready(out);
            return Ok(());
        }
        let wait_started = (self.stats_every_ms > 0).then(thread_cpu_ns);
        while self.ready.is_empty() {
            // One syscall: flush every queued SQE and wait for a completion.
            // `min_complete` is 1: return as soon as anything is done. Raising
            // it would coalesce these calls at the cost of holding finished
            // work back, which is the lever under measurement — the counters
            // here are what decide whether it is worth building.
            self.enters_waiting += 1;
            let entered = wait_started.map(|_| thread_cpu_ns());
            // SAFETY: plain io_uring_enter with no sigset.
            let r = unsafe {
                libc::syscall(
                    SYS_IO_URING_ENTER,
                    self.ring,
                    self.to_submit,
                    1 as libc::c_uint,
                    IORING_ENTER_GETEVENTS,
                    ptr::null::<libc::c_void>(),
                )
            };
            if let Some(entered) = entered {
                self.enter_cpu_ns += thread_cpu_ns().saturating_sub(entered);
            }
            if r < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EBUSY) => {}
                    _ => return Err(e),
                }
            } else {
                self.to_submit -= r as u32;
            }
            self.drain_cq();
        }
        if let Some(started) = wait_started {
            self.wait_cpu_ns += thread_cpu_ns().saturating_sub(started);
            let now = monotonic_ns();
            if now >= self.stats_next_ns {
                self.stats_next_ns = now + self.stats_every_ms * 1_000_000;
                use std::io::Write as _;
                let line = self.debug_state();
                let head = line.lines().next().unwrap_or("").to_string();
                let _ = writeln!(std::io::stderr(), "{head}");
            }
        }
        self.handoff_ready(out);
        Ok(())
    }

    fn recycle(&mut self, buf: Vec<u8>) {
        pool::put(&mut self.pool, buf);
    }
}

impl Drop for UringDriver {
    fn drop(&mut self) {
        self.shutdown_accept_arms();
        for accepted in self.ready_accepted.drain(..) {
            // SAFETY: these Accept completions have not been handed to the
            // caller's output vector, so the driver still owns their fds.
            unsafe { libc::close(accepted) };
        }
        for state in &mut self.fds {
            for accepted in state.accepted.drain(..) {
                if let Accepted::Fd(accepted) = accepted {
                    // SAFETY: accepted fds stay driver-owned until a caller's
                    // Accept completion is built.
                    unsafe { libc::close(accepted) };
                }
            }
        }
        // Unregister the buffer ring before the fd goes: its backing Vecs are
        // ours again once the kernel has let go of them.
        if let Some(mut bufs) = self.bufs.take() {
            let mut pool = mem::take(&mut self.pool);
            bufs.shutdown(self.ring, &mut pool);
        }
        // SAFETY: mappings and the ring fd are exclusively ours; the kernel
        // tears down in-flight ops when the ring closes.
        unsafe {
            libc::munmap(self.sqes as *mut libc::c_void, self.sqes_len);
            libc::munmap(self.sq_mmap as *mut libc::c_void, self.sq_mmap_len);
            libc::close(self.ring);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::net::UnixStream;

    /// Resident set size in bytes, from `/proc/self/statm` field 2 (pages).
    fn rss_bytes() -> usize {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
        let pages: usize = statm
            .split_whitespace()
            .nth(1)
            .and_then(|f| f.parse().ok())
            .expect("resident pages");
        // SAFETY: sysconf takes a constant and returns a long.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        pages * page
    }

    fn raise_fd_limit(target: u64) {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: both calls take a live rlimit of the right type.
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
                lim.rlim_cur = target.min(lim.rlim_max);
                libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
        }
    }

    /// A connected pair; the returned fd is the server side.
    fn connected_pair(listener: &TcpListener) -> (TcpStream, RawFd) {
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server.into_raw_fd())
    }

    fn drain_until(d: &mut UringDriver, id: OpId) -> Completion {
        let mut out = Vec::new();
        for _ in 0..64 {
            out.clear();
            d.wait(&mut out).expect("wait");
            if let Some(i) = out.iter().position(|c| c.id == id) {
                return out.swap_remove(i);
            }
        }
        panic!("op {id} never completed");
    }

    /// A successful accept is itself proof that the returned descriptor is a
    /// socket. Keep that fact in the fd state: probing it again on the first
    /// pooled read cut connection-churn throughput in half under contention.
    #[test]
    fn accepted_descriptor_is_already_known_to_be_a_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut d = UringDriver::new().expect("ring");

        let accept = d
            .submit(Op::Accept {
                fd: listener.as_raw_fd(),
            })
            .expect("accept");
        let _client = TcpStream::connect(addr).expect("connect");
        let fd = drain_until(&mut d, accept).result.expect("accepted") as RawFd;

        assert_eq!(
            d.fd_state(fd).sock,
            Some(true),
            "the first read must not issue getsockopt(SO_TYPE)"
        );
        d.submit(Op::Close { fd }).expect("close");
    }

    #[test]
    fn one_multishot_accept_arm_serves_many_caller_ops() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let listener = listener.into_raw_fd();
        let mut d = UringDriver::new().expect("ring");
        d.multishot_accept = true;

        let mut clients = Vec::new();
        let mut accepted = Vec::new();
        for round in 0..8u64 {
            let tag = 0xACCE_0000 + round;
            let id = d
                .submit_with(Op::Accept { fd: listener }, tag)
                .expect("accept");
            clients.push(TcpStream::connect(addr).expect("connect"));
            let completion = drain_until(&mut d, id);
            assert_eq!(completion.user, tag);
            accepted.push(completion.result.expect("accepted") as RawFd);
        }

        assert_eq!(
            d.multishot_accept_arms, 1,
            "eight caller Accept ops must reuse one kernel arm"
        );
        assert!(
            d.fd_state(listener).accept_arm.is_some(),
            "the accept arm must remain live"
        );
        for fd in accepted {
            let close = d.submit(Op::Close { fd }).expect("close accepted");
            let _ = drain_until(&mut d, close);
        }
        let close = d
            .submit(Op::Close { fd: listener })
            .expect("close listener");
        let _ = drain_until(&mut d, close);
        drop(clients);
    }

    #[test]
    fn live_accept_arm_is_synchronously_retired_before_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let listener = listener.into_raw_fd();
        let mut d = UringDriver::new().expect("ring");
        if !d.sync_cancel_supported() {
            // `new` leaves the opt-in fast path disabled on this kernel.
            return;
        }
        d.multishot_accept = true;

        let accept = d.submit(Op::Accept { fd: listener }).expect("accept");
        let client = TcpStream::connect(addr).expect("connect");
        let accepted = drain_until(&mut d, accept).result.expect("accepted") as RawFd;
        assert_eq!(d.active_accept_arms.len(), 1, "one arm must be live");

        d.shutdown_accept_arms();
        assert!(
            d.active_accept_arms.is_empty(),
            "synchronous cancellation must consume the arm's final CQE"
        );
        assert!(
            d.fd_state(listener).accept_arm.is_none(),
            "the listener must not retain a stale arm id"
        );

        let close = d
            .submit(Op::Close { fd: accepted })
            .expect("close accepted");
        let _ = drain_until(&mut d, close);
        let close = d
            .submit(Op::Close { fd: listener })
            .expect("close listener");
        let _ = drain_until(&mut d, close);
        drop(client);
    }

    #[test]
    fn multishot_accept_stash_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let listener = listener.as_raw_fd();
        let mut d = UringDriver::new().expect("ring");

        for _ in 0..ACCEPT_STASH_LIMIT * 2 {
            d.stash_accept(listener, Accepted::Err(libc::ECONNABORTED));
        }
        assert_eq!(
            d.fd_state(listener).accepted.len(),
            ACCEPT_STASH_LIMIT,
            "a paused caller must not grow accepted state without bound"
        );
    }

    #[test]
    fn unclaimed_ready_accept_is_closed_with_driver() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (mut witness, accepted) = UnixStream::pair().expect("socket pair");
        witness.set_nonblocking(true).expect("nonblocking witness");
        let accepted = accepted.into_raw_fd();
        let mut d = UringDriver::new().expect("ring");
        d.fd_state(listener.as_raw_fd())
            .accepted
            .push_back(Accepted::Fd(accepted));

        d.submit(Op::Accept {
            fd: listener.as_raw_fd(),
        })
        .expect("accept from stash");
        assert_eq!(d.ready_accepted, [accepted]);
        drop(d);

        // EOF proves that the underlying socket description lost its final
        // peer. Checking `fcntl(accepted, F_GETFD)` instead is racy: another
        // parallel test can reuse that numeric descriptor immediately after
        // Drop closes it and make a correct close look like a leak.
        let mut byte = [0u8; 1];
        assert_eq!(
            witness
                .read(&mut byte)
                .expect("a leaked peer would return WouldBlock"),
            0,
            "Drop must close an Accept result that wait never handed off"
        );
    }

    #[test]
    fn successful_doomed_accept_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (mut witness, accepted) = UnixStream::pair().expect("socket pair");
        witness.set_nonblocking(true).expect("nonblocking witness");
        let accepted = accepted.into_raw_fd();
        let mut d = UringDriver::new().expect("ring");
        let id = d.ops.reserve(0);
        d.ops.put_op(
            id,
            Flight {
                fd: listener.as_raw_fd(),
                kind: Kind::Accept,
                doomed: true,
            },
        );

        d.complete(id, accepted, 0);

        let mut byte = [0u8; 1];
        assert_eq!(
            witness
                .read(&mut byte)
                .expect("a leaked peer would return WouldBlock"),
            0,
            "an accept that beats cancellation must not leak its fd"
        );
        assert_eq!(
            d.ready
                .pop()
                .expect("ECANCELED completion")
                .result
                .expect_err("doomed accept must fail")
                .raw_os_error(),
            Some(libc::ECANCELED)
        );
    }

    /// A read that arms multishot, then meets EOF, then reads again: the second
    /// arm goes onto a socket whose FIN has already been consumed, and it must
    /// still complete. EOF is sticky, so a driver that only re-arms and waits
    /// hangs here.
    #[test]
    fn reads_after_eof_keep_completing() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (client, fd) = connected_pair(&listener);
        let mut d = UringDriver::new().expect("ring");

        let id = d.submit(Op::ReadPooled { fd }).expect("pooled read");
        drop(client); // FIN
        assert_eq!(drain_until(&mut d, id).result.expect("read ok"), 0);

        // Both shapes, twice each: whichever path re-arms must survive an
        // already-dead peer rather than park on a wake-up that cannot come.
        for _ in 0..2 {
            let id = d.submit(Op::ReadPooled { fd }).expect("pooled read");
            assert_eq!(drain_until(&mut d, id).result.expect("read ok"), 0);
            let id = d
                .submit(Op::Read {
                    fd,
                    buf: vec![0; 64],
                })
                .expect("read");
            assert_eq!(drain_until(&mut d, id).result.expect("read ok"), 0);
        }
        d.submit(Op::Close { fd }).expect("close");
    }

    /// The flat floor, measured absolutely rather than as a slope.
    ///
    /// `parked_pooled_reads_own_no_buffer` measures cost *per connection* and
    /// would wave through any buffer size at all, because the regression a large
    /// buffer causes is entirely in a fixed floor that a per-connection delta
    /// never looks at. A 64 KiB buffer across a 256-entry ring would be 16 MiB
    /// of it and that test would still pass. So this one asserts the floor.
    ///
    /// The ring is allocated and registered when the driver is built, so a
    /// driver that has served nothing is exactly the floor.
    ///
    /// What it measures is the **resident** floor, and that turns out to be far
    /// smaller than the ring: 131 KB against 2 MiB of buffers here. Registering
    /// a provided-buffer ring hands the kernel a descriptor array, not pinned
    /// pages, so the buffers themselves stay untouched virtual memory until
    /// traffic faults them in. The size arithmetic bounds the virtual cost; only
    /// this bounds what a server that never reads a byte actually pays.
    #[test]
    fn an_idle_driver_costs_a_bounded_flat_floor() {
        // A generous ceiling: the ring itself is RING_BUFS * POOL_BUF_SIZE, and
        // the assertion exists to catch a size or count change that multiplies
        // that, not to pin an allocator's exact behaviour.
        const CEILING: usize = 6 * 1024 * 1024;

        let before = rss_bytes();
        let d = UringDriver::new().expect("ring");
        assert!(
            d.has_buffer_ring(),
            "no provided-buffer ring on this kernel"
        );
        let after = rss_bytes();
        let floor = after.saturating_sub(before);

        let ring = usize::from(RING_BUFS) * POOL_BUF_SIZE;
        println!(
            "idle driver flat floor: {floor} bytes resident, ring is {ring} bytes \
             ({RING_BUFS} x {POOL_BUF_SIZE})"
        );
        assert!(
            floor < CEILING,
            "an idle driver went resident by {floor} bytes: the buffer ring is \
             {ring} bytes ({RING_BUFS} x {POOL_BUF_SIZE}), and a flat floor this \
             size is charged to every server whether it reads a byte or not"
        );
        drop(d);
    }

    /// The engagement proof. A driver that silently fell back to the P1
    /// single-shot path would still echo correctly and pass every behavioural
    /// test — so this asserts the counters, and fails if the fast path is off.
    #[test]
    fn multishot_recv_is_actually_engaged() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (mut client, fd) = connected_pair(&listener);
        let mut d = UringDriver::new().expect("ring");
        assert!(
            d.has_buffer_ring(),
            "no provided-buffer ring on this kernel"
        );

        client.write_all(b"multishot").expect("client write");
        let id = d.submit(Op::ReadPooled { fd }).expect("pooled read");
        let c = drain_until(&mut d, id);
        let n = c.result.expect("read ok") as usize;
        let buf = c.buf.expect("buffer");
        assert_eq!(&buf[..n], b"multishot");

        println!(
            "engagement: multishot_arms={} ring_buffers_consumed={}",
            d.multishot_arms, d.ring_buffers_consumed
        );
        assert!(
            d.multishot_arms > 0,
            "no multishot arm was established: the read went down the \
             single-shot path"
        );
        assert!(
            d.ring_buffers_consumed > 0,
            "no buffer came out of the provided-buffer ring: the payload was \
             not kernel-selected"
        );
        d.submit(Op::Close { fd }).expect("close");
    }

    /// A second pooled read on the same fd reuses the arm rather than making
    /// another: the arm is infrastructure, not per-op.
    #[test]
    fn one_arm_serves_many_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let (mut client, fd) = connected_pair(&listener);
        let mut d = UringDriver::new().expect("ring");

        for round in 0..8 {
            let msg = format!("round-{round}");
            client.write_all(msg.as_bytes()).expect("write");
            let id = d.submit(Op::ReadPooled { fd }).expect("pooled read");
            let c = drain_until(&mut d, id);
            let n = c.result.expect("ok") as usize;
            assert_eq!(&c.buf.expect("buf")[..n], msg.as_bytes(), "round {round}");
        }
        println!(
            "one arm, eight reads: multishot_arms={} ring_buffers_consumed={} reclaimed={}",
            d.multishot_arms, d.ring_buffers_consumed, d.ring_buffers_reclaimed
        );
        assert_eq!(d.multishot_arms, 1, "the arm must be established once");
        assert!(d.ring_buffers_consumed >= 8);
        d.submit(Op::Close { fd }).expect("close");
    }

    /// The memory claim: a parked pooled read owns no buffer, so idle
    /// connections cost essentially nothing. The single-shot path costs one
    /// pool buffer per parked read — 4 KiB each, which this threshold excludes.
    #[test]
    fn parked_pooled_reads_own_no_buffer() {
        const CONNS: usize = 1000;
        raise_fd_limit(8192);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut d = UringDriver::new().expect("ring");
        assert!(d.has_buffer_ring());

        let mut clients = Vec::with_capacity(CONNS);
        let mut fds = Vec::with_capacity(CONNS);
        for _ in 0..CONNS {
            let (c, fd) = connected_pair(&listener);
            clients.push(c);
            fds.push(fd);
        }

        // Measure only what parking the reads costs, not the sockets.
        let before = rss_bytes();
        for &fd in &fds {
            d.submit(Op::ReadPooled { fd }).expect("pooled read");
        }
        d.flush().expect("flush the arms to the kernel");
        let after = rss_bytes();

        let per_conn = after.saturating_sub(before) / CONNS;
        println!("parked pooled reads: {per_conn} bytes/conn over {CONNS} idle connections");
        assert!(
            per_conn < 1024,
            "{per_conn} bytes/conn — a parked pooled read is holding a buffer \
             (the single-shot path costs {POOL_BUF_SIZE})"
        );

        for &fd in &fds {
            let _ = d.submit(Op::Close { fd });
        }
    }

    /// The registration must actually succeed on the kernels we target — and if
    /// it ever does not, the driver must still come up on the single-shot path
    /// rather than fail to construct.
    #[test]
    fn buffer_ring_registers_on_this_kernel() {
        let d = UringDriver::new().expect("ring");
        assert!(
            d.has_buffer_ring(),
            "IORING_REGISTER_PBUF_RING was refused; the driver still works but \
             the multishot fast path is silently off"
        );
    }

    /// Building and dropping many drivers must not leak mappings or buffers —
    /// each one registers a ring and hands 256 buffers back on the way out.
    #[test]
    fn rings_can_be_built_and_dropped_repeatedly() {
        for _ in 0..32 {
            let d = UringDriver::new().expect("ring");
            assert!(d.has_buffer_ring());
        }
    }
}
