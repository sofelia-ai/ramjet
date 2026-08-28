//! Deterministic randomized stress test of the driver state machine.
//!
//! One case is a seed. The seed drives a hand-rolled splitmix64 PRNG, so a
//! failure reproduces exactly from the seed printed in the panic message — no
//! nightly, no cargo-fuzz, no dependency, just `cargo test`.
//!
//! Budget overrides for a longer soak:
//! `RAMJET_FUZZ_STEPS=5000 RAMJET_FUZZ_CASES=100 cargo test --test fuzz_driver`
//!
//! Everything runs in ONE `#[test]`, sequentially. Descriptor numbers are
//! process-wide state, and invariant 5 (fd hygiene) plus the closed-fd action
//! both reason about them; a sibling test allocating sockets on another thread
//! would make that reasoning false.

use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Completion, Driver, Op, OpId};

/// Most connections alive at once. Deliberately small so that collisions on the
/// same fd, and closes racing parked ops, happen often rather than never.
const MAX_CONNS: usize = 8;

/// How many recent actions the watchdog reports. Enough to see the close, the
/// re-open and the reads that followed it; short enough to read.
const LOG_DEPTH: usize = 20;

/// splitmix64: seedable, deterministic, and short enough to not be a dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

/// What we submitted, so its completion can be judged.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Read,
    ReadPooled,
    Write,
    Close,
    /// Submitted against a descriptor we had just closed. Must fail, never
    /// succeed and never panic.
    Stale,
}

struct InFlight {
    kind: Kind,
    /// The `user` tag this op was submitted with, to be checked on completion.
    user: u64,
    /// Index into `conns`, absent for ops not tied to a tracked connection.
    conn: Option<usize>,
    fd: RawFd,
    /// Length of the buffer we handed over, for owned Read/Write.
    len: usize,
}

struct Conn {
    client: Option<TcpStream>,
    fd: RawFd,
    alive: bool,
    /// Everything the client has actually written to this connection, which is
    /// exactly what reads on it are allowed to return.
    written: Vec<u8>,
    /// How much of `written` completed reads have consumed.
    consumed: usize,
}

/// Coverage counters. A fuzzer that quietly does nothing also passes, so the
/// run prints what it actually exercised.
#[derive(Default)]
struct Stats {
    conns: u64,
    submitted: [u64; 5],
    busy: u64,
    invalid: u64,
    completions: u64,
    cancelled: u64,
    bytes_verified: u64,
    pooled_bytes: u64,
    stale_errors: u64,
    open_failed: u64,
    midflight_drops: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.conns += o.conns;
        for i in 0..self.submitted.len() {
            self.submitted[i] += o.submitted[i];
        }
        self.busy += o.busy;
        self.invalid += o.invalid;
        self.completions += o.completions;
        self.cancelled += o.cancelled;
        self.bytes_verified += o.bytes_verified;
        self.pooled_bytes += o.pooled_bytes;
        self.stale_errors += o.stale_errors;
        self.open_failed += o.open_failed;
        self.midflight_drops += o.midflight_drops;
    }

    /// Every one of these must be non-zero, or the run proved nothing about
    /// the path it was supposed to cover.
    fn assert_exercised(&self) {
        let checks: [(&str, u64); 10] = [
            ("connections opened", self.conns),
            ("Read submitted", self.submitted[Kind::Read as usize]),
            (
                "ReadPooled submitted",
                self.submitted[Kind::ReadPooled as usize],
            ),
            ("Write submitted", self.submitted[Kind::Write as usize]),
            ("Close submitted", self.submitted[Kind::Close as usize]),
            ("ops on a closed fd", self.submitted[Kind::Stale as usize]),
            ("completions checked", self.completions),
            ("ops cancelled by Close", self.cancelled),
            ("payload bytes verified", self.bytes_verified),
            ("drivers dropped with live ops", self.midflight_drops),
        ];
        for (what, n) in checks {
            assert!(
                n > 0,
                "fuzzer never exercised: {what} — the run proves nothing"
            );
        }
    }
}

struct World {
    seed: u64,
    rng: Rng,
    d: PlatformDriver,
    conns: Vec<Conn>,
    inflight: HashMap<OpId, InFlight>,
    /// Buffers handed to us by completions, available to recycle.
    held: Vec<Vec<u8>>,
    /// fds we have submitted a Close for — the only ops allowed to be cancelled.
    closed: HashSet<RawFd>,
    stats: Stats,
    /// Source of distinct `user` tags.
    next_tag: u64,
    /// Steps taken, and the tail of what they were.
    steps: u64,
    log: VecDeque<String>,
}

/// Close this socket with an RST instead of a FIN, so it leaves no TIME_WAIT
/// behind. A long soak opens tens of thousands of loopback connections, and at
/// two ephemeral ports each, TIME_WAIT exhausts the range and `connect` starts
/// failing with EADDRNOTAVAIL — an artefact of the harness that looks nothing
/// like a driver bug but stops the run just the same.
fn reset_on_close(fd: RawFd) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `l` is a live linger struct and we pass exactly its size.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

/// A connected pair, both ends non-blocking. The listener is dropped, so only
/// the two descriptors survive.
///
/// `None` means the machine would not give us a connection right now (the
/// ephemeral range is momentarily full); the caller skips the step rather than
/// failing, and the run reports how often that happened.
fn connected_pair() -> Option<(TcpStream, RawFd)> {
    let l = TcpListener::bind("127.0.0.1:0").ok()?;
    let addr = l.local_addr().ok()?;

    let mut client = None;
    for attempt in 0..8 {
        match TcpStream::connect(addr) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                thread::sleep(Duration::from_millis(2 << attempt));
            }
            Err(_) => return None,
        }
    }
    let client = client?;
    let (server, _) = l.accept().ok()?;
    server.set_nonblocking(true).expect("server nonblocking");
    client.set_nonblocking(true).expect("client nonblocking");
    let fd = server.into_raw_fd();
    // Only the server side: the client keeps normal FIN semantics so that
    // dropping it still exercises the read-returns-0 EOF path.
    reset_on_close(fd);
    Some((client, fd))
}

/// The number a fresh descriptor gets, which tracks how many are open.
fn probe_fd_number() -> RawFd {
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    f.as_raw_fd()
}

fn hex(b: &[u8]) -> String {
    let head: Vec<String> = b.iter().take(48).map(|x| format!("{x:02x}")).collect();
    let tail = if b.len() > 48 { " …" } else { "" };
    format!("[{} bytes] {}{}", b.len(), head.join(" "), tail)
}

impl World {
    fn new(seed: u64) -> Self {
        World {
            seed,
            rng: Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(1)),
            d: PlatformDriver::new().expect("driver"),
            conns: Vec::new(),
            inflight: HashMap::new(),
            held: Vec::new(),
            closed: HashSet::new(),
            stats: Stats::default(),
            next_tag: 1,
            steps: 0,
            log: VecDeque::with_capacity(LOG_DEPTH),
        }
    }

    /// Submit either tagged or untagged, so both entry points get exercised.
    /// Returns the tag the completion must report back.
    fn choose_tag(&mut self) -> Option<u64> {
        if self.rng.below(2) == 0 {
            let tag = self.next_tag;
            self.next_tag += 1;
            Some(tag)
        } else {
            None
        }
    }

    /// Record what the fuzzer just did. A hang is a history, not a state: the
    /// op left parked is rarely the one that broke the driver, so the watchdog
    /// prints the run-up as well as the wreck.
    fn note(&mut self, what: String) {
        if self.log.len() == LOG_DEPTH {
            self.log.pop_front();
        }
        self.log.push_back(format!("step {}: {what}", self.steps));
    }

    fn send(&mut self, op: Op, tag: Option<u64>) -> std::io::Result<OpId> {
        self.note(match &op {
            Op::Accept { fd } => format!("submit Accept fd {fd} tag {tag:?}"),
            Op::Read { fd, buf } => format!("submit Read fd {fd} len {} tag {tag:?}", buf.len()),
            Op::ReadPooled { fd } => format!("submit ReadPooled fd {fd} tag {tag:?}"),
            Op::Write { fd, buf } => format!("submit Write fd {fd} len {} tag {tag:?}", buf.len()),
            Op::WriteFrom { fd, buf, start } => {
                format!(
                    "submit WriteFrom fd {fd} {start}..{} tag {tag:?}",
                    buf.len()
                )
            }
            Op::Close { fd } => format!("submit Close fd {fd} tag {tag:?}"),
        });
        let r = match tag {
            Some(t) => self.d.submit_with(op, t),
            None => self.d.submit(op),
        };
        match &r {
            Ok(id) => self.note(format!("  -> op {id}")),
            Err(e) => self.note(format!("  -> refused: {} ({e})", e.kind())),
        }
        r
    }

    fn live(&self) -> Vec<usize> {
        (0..self.conns.len())
            .filter(|&i| self.conns[i].alive)
            .collect()
    }

    fn pick_live(&mut self) -> Option<usize> {
        let live = self.live();
        if live.is_empty() {
            return None;
        }
        Some(live[self.rng.below(live.len())])
    }

    /// Invariant 4: submit may only refuse an op for a documented reason.
    fn check_submit_err(&self, e: &std::io::Error) {
        let kind = e.kind();
        assert!(
            kind == std::io::ErrorKind::ResourceBusy || kind == std::io::ErrorKind::InvalidInput,
            "seed {}: submit failed with undocumented error kind {kind:?} ({e})",
            self.seed
        );
    }

    fn note_submit_err(&mut self, e: &std::io::Error) {
        self.check_submit_err(e);
        if e.kind() == std::io::ErrorKind::ResourceBusy {
            self.stats.busy += 1;
        } else {
            self.stats.invalid += 1;
        }
    }

    fn step(&mut self) {
        self.steps += 1;
        match self.rng.below(100) {
            0..=16 => self.act_submit_read(),
            17..=33 => self.act_submit_pooled(),
            34..=46 => self.act_submit_write(),
            47..=53 => self.act_close(),
            54..=61 => self.act_recycle(),
            62..=70 => self.act_open(),
            71..=84 => self.act_client_write(),
            85..=89 => self.act_client_drain(),
            90..=92 => self.act_client_drop(),
            _ => self.act_wait(),
        }
    }

    fn act_open(&mut self) {
        if self.live().len() >= MAX_CONNS {
            return;
        }
        let Some((client, fd)) = connected_pair() else {
            self.stats.open_failed += 1;
            return;
        };
        self.stats.conns += 1;
        self.note(format!("open conn {} fd {fd}", self.conns.len()));
        self.conns.push(Conn {
            client: Some(client),
            fd,
            alive: true,
            written: Vec::new(),
            consumed: 0,
        });
    }

    fn act_submit_read(&mut self) {
        let Some(i) = self.pick_live() else { return };
        let fd = self.conns[i].fd;
        // Mostly a real buffer, occasionally an empty one so the documented
        // InvalidInput refusal gets exercised too.
        let len = if self.rng.below(32) == 0 {
            0
        } else {
            1 + self.rng.below(8192)
        };
        let tag = self.choose_tag();
        match self.send(
            Op::Read {
                fd,
                buf: vec![0; len],
            },
            tag,
        ) {
            Ok(id) => {
                self.record(
                    id,
                    InFlight {
                        user: tag.unwrap_or(0),
                        kind: Kind::Read,
                        conn: Some(i),
                        fd,
                        len,
                    },
                );
            }
            Err(e) => self.note_submit_err(&e),
        }
    }

    fn act_submit_pooled(&mut self) {
        let Some(i) = self.pick_live() else { return };
        let fd = self.conns[i].fd;
        let tag = self.choose_tag();
        match self.send(Op::ReadPooled { fd }, tag) {
            Ok(id) => {
                self.record(
                    id,
                    InFlight {
                        user: tag.unwrap_or(0),
                        kind: Kind::ReadPooled,
                        conn: Some(i),
                        fd,
                        len: 0,
                    },
                );
            }
            Err(e) => self.note_submit_err(&e),
        }
    }

    fn act_submit_write(&mut self) {
        let Some(i) = self.pick_live() else { return };
        let fd = self.conns[i].fd;
        // Zero-length writes are legal and complete immediately.
        let len = self.rng.below(8193);
        let buf = self.rng.bytes(len);
        let tag = self.choose_tag();
        match self.send(Op::Write { fd, buf }, tag) {
            Ok(id) => {
                self.record(
                    id,
                    InFlight {
                        user: tag.unwrap_or(0),
                        kind: Kind::Write,
                        conn: Some(i),
                        fd,
                        len,
                    },
                );
            }
            Err(e) => self.note_submit_err(&e),
        }
    }

    fn act_close(&mut self) {
        let Some(i) = self.pick_live() else { return };
        let fd = self.conns[i].fd;
        self.closed.insert(fd);
        let tag = self.choose_tag();
        match self.send(Op::Close { fd }, tag) {
            Ok(id) => {
                self.record(
                    id,
                    InFlight {
                        user: tag.unwrap_or(0),
                        kind: Kind::Close,
                        conn: Some(i),
                        fd,
                        len: 0,
                    },
                );
            }
            Err(e) => self.note_submit_err(&e),
        }
        self.conns[i].alive = false;
        self.conns[i].client = None;

        // Submit against a descriptor that has never been open. NOT the one
        // just closed: on a completion-based backend the op executes later
        // than it is submitted, an in-flight Accept can recycle the closed
        // number in that gap, and the "stale" read then steals real bytes
        // from the successor connection (documented on Op::Close). An fd far
        // above anything this small fuzz universe ever allocates is EBADF on
        // every backend, deterministically.
        const NEVER_OPEN_FD: i32 = 4096;
        if self.rng.below(10) < 4 {
            let len = 1 + self.rng.below(64);
            // Its own tag: reusing the Close's would assert the wrong thing.
            let stale_tag = self.choose_tag();
            match self.send(
                Op::Read {
                    fd: NEVER_OPEN_FD,
                    buf: vec![0; len],
                },
                stale_tag,
            ) {
                Ok(id) => {
                    self.record(
                        id,
                        InFlight {
                            user: stale_tag.unwrap_or(0),
                            kind: Kind::Stale,
                            conn: None,
                            fd: NEVER_OPEN_FD,
                            len,
                        },
                    );
                }
                Err(e) => self.note_submit_err(&e),
            }
        }
    }

    fn act_recycle(&mut self) {
        if self.held.is_empty() {
            return;
        }
        let i = self.rng.below(self.held.len());
        let mut buf = self.held.swap_remove(i);
        self.note(format!("recycle buf len {}", buf.len()));
        // Sometimes hand back something the pool is supposed to refuse.
        match self.rng.below(12) {
            0 => buf = vec![0; 16],      // undersized
            1 => buf = vec![0; 1 << 20], // oversized: must be dropped, not kept
            2 => buf = Vec::new(),       // empty
            _ => {}
        }
        self.d.recycle(buf);
    }

    fn act_client_write(&mut self) {
        let Some(i) = self.pick_live() else { return };
        if self.conns[i].client.is_none() {
            return;
        }
        let len = 1 + self.rng.below(512);
        let bytes = self.rng.bytes(len);
        // Non-blocking, single call: record only what the kernel accepted, so a
        // full socket buffer can never deadlock the fuzzer.
        let wrote = match self.conns[i].client.as_mut().map(|c| c.write(&bytes)) {
            Some(Ok(w)) => w,
            _ => 0,
        };
        self.conns[i].written.extend_from_slice(&bytes[..wrote]);
        self.note(format!(
            "client write conn {i} fd {} {wrote}/{len} bytes",
            self.conns[i].fd
        ));
    }

    fn act_client_drain(&mut self) {
        let Some(i) = self.pick_live() else { return };
        let mut sink = [0u8; 4096];
        if let Some(c) = self.conns[i].client.as_mut() {
            let _ = c.read(&mut sink);
        }
    }

    fn act_client_drop(&mut self) {
        let Some(i) = self.pick_live() else { return };
        self.note(format!(
            "client drop conn {i} fd {} (sends FIN)",
            self.conns[i].fd
        ));
        self.conns[i].client = None;
    }

    /// `wait()` blocks until an op finishes, so calling it with every in-flight
    /// op stalled hangs the fuzzer — a defect in the test, not the driver. Wake
    /// one op first; one is enough for `wait` to return, and it then drains
    /// whatever else happens to be ready.
    fn ensure_progress(&mut self) {
        let ids: Vec<OpId> = self.inflight.keys().copied().collect();
        if ids.is_empty() {
            return; // an idle driver returns empty immediately
        }
        let id = ids[self.rng.below(ids.len())];
        let (kind, conn) = {
            let f = &self.inflight[&id];
            (f.kind, f.conn)
        };
        // Close and Stale complete eagerly at submit, so they are already ready.
        let Some(i) = conn else { return };

        match kind {
            Kind::Read | Kind::ReadPooled => {
                // Data makes it readable. A client already dropped has sent its
                // FIN, which wakes the read just as well.
                if self.conns[i].client.is_some() {
                    let bytes = self.rng.bytes(64);
                    let wrote = match self.conns[i].client.as_mut().map(|c| c.write(&bytes)) {
                        Some(Ok(w)) => w,
                        _ => 0,
                    };
                    self.conns[i].written.extend_from_slice(&bytes[..wrote]);
                }
            }
            Kind::Write => {
                // A parked write is waiting for room: empty the peer's buffer.
                if let Some(c) = self.conns[i].client.as_mut() {
                    let mut sink = [0u8; 8192];
                    while let Ok(n) = c.read(&mut sink) {
                        if n == 0 {
                            break;
                        }
                    }
                }
            }
            Kind::Close | Kind::Stale => {}
        }
    }

    /// Snapshot what is outstanding, for the watchdog. A hang is always inside
    /// the `wait()` that follows, so this is exactly the state the driver could
    /// not make progress on — without it the watchdog names a seed and nothing
    /// else, and the seed alone does not reproduce a timing-dependent strand.
    fn note_wait(&self) {
        let mut s = format!(
            "seed {} at step {}: {} op(s) in flight",
            self.seed,
            self.steps,
            self.inflight.len()
        );
        for (id, f) in &self.inflight {
            s.push_str(&format!(
                "\n  op {id} {:?} fd {} user {} conn {:?} len {}",
                f.kind, f.fd, f.user, f.conn, f.len
            ));
        }
        s.push_str("\n  connections:");
        for (i, c) in self.conns.iter().enumerate() {
            s.push_str(&format!(
                "\n    conn {i} fd {} alive={} client={} written={} consumed={}",
                c.fd,
                c.alive,
                if c.client.is_some() {
                    "open"
                } else {
                    "dropped"
                },
                c.written.len(),
                c.consumed
            ));
        }
        s.push_str("\n  driver: ");
        s.push_str(&self.d.debug_state().replace('\n', "\n  "));
        s.push_str("\n  last actions:");
        for line in &self.log {
            s.push_str(&format!("\n    {line}"));
        }
        let fds = self.inflight.values().map(|f| f.fd).collect();
        if let Ok(mut slot) = LAST_WAIT.try_lock() {
            *slot = (s, fds);
        }
    }

    fn act_wait(&mut self) {
        self.ensure_progress();
        self.note_wait();
        let mut out = Vec::new();
        if let Err(e) = self.d.wait(&mut out) {
            panic!("seed {}: wait() failed: {e}", self.seed);
        }
        for c in out {
            self.check_completion(c);
        }
    }

    /// Invariant 3, first half: an id may not already be in flight.
    fn record(&mut self, id: OpId, f: InFlight) {
        self.stats.submitted[f.kind as usize] += 1;
        assert!(
            self.inflight.insert(id, f).is_none(),
            "seed {}: submit handed out op id {id} while it was still in flight",
            self.seed
        );
    }

    fn check_completion(&mut self, c: Completion) {
        let seed = self.seed;
        let Completion {
            id,
            user,
            result,
            buf,
        } = c;

        // Invariant 3: exactly one completion per submitted id.
        let f = self.inflight.remove(&id).unwrap_or_else(|| {
            panic!("seed {seed}: completion for op id {id}, which is unknown or already completed")
        });
        self.stats.completions += 1;
        // io_uring's user_data contract: whatever went in comes back out.
        assert_eq!(
            user, f.user,
            "seed {seed}: op {id} ({:?}) came back with tag {user}, submitted with {}",
            f.kind, f.user
        );

        // Invariant 4: cancellation only ever follows a Close on that fd.
        if let Err(ref e) = result
            && e.raw_os_error() == Some(libc::ECANCELED)
        {
            self.stats.cancelled += 1;
            assert!(
                self.closed.contains(&f.fd),
                "seed {seed}: op {id} ({:?}) on fd {} was cancelled with no Close submitted for it",
                f.kind,
                f.fd
            );
        }

        match f.kind {
            // Invariant 2: an owned buffer always comes back, at its own length.
            Kind::Read | Kind::Write => {
                let buf = buf.unwrap_or_else(|| {
                    panic!(
                        "seed {seed}: {:?} op {id} completed without its buffer",
                        f.kind
                    )
                });
                assert_eq!(
                    buf.len(),
                    f.len,
                    "seed {seed}: {:?} op {id} came back at the wrong length",
                    f.kind
                );
                if f.kind == Kind::Read
                    && let Ok(n) = result
                {
                    self.check_read_data(f.conn, id, &buf[..n as usize]);
                }
                self.held.push(buf);
            }

            Kind::ReadPooled => match (&result, buf) {
                // A parked pooled read owns nothing, so a cancel returns nothing.
                (Err(e), None) if e.raw_os_error() == Some(libc::ECANCELED) => {}
                (r, Some(buf)) => {
                    let n = match r {
                        Ok(n) => *n as usize,
                        Err(_) => 0,
                    };
                    // The contract that closes the disclosure hole: length is
                    // the byte count, so no stale tail is reachable.
                    assert_eq!(
                        buf.len(),
                        n,
                        "seed {seed}: pooled op {id} handed back {} bytes for a {n}-byte read — \
                         everything past {n} is another connection's data\n  buffer: {}",
                        buf.len(),
                        hex(&buf)
                    );
                    self.stats.pooled_bytes += n as u64;
                    self.check_read_data(f.conn, id, &buf);
                    self.held.push(buf);
                }
                (r, None) => {
                    panic!("seed {seed}: pooled op {id} completed with no buffer and result {r:?}")
                }
            },

            Kind::Close => {
                assert!(
                    buf.is_none(),
                    "seed {seed}: Close op {id} returned a buffer it never had"
                );
            }

            Kind::Stale => {
                // The target fd has never been open in this process, so this
                // must error on every backend. (An op on a *recycled* number
                // would be unspecified — see Op::Close — which is exactly why
                // the fuzzer no longer submits those.)
                assert!(
                    result.is_err(),
                    "seed {seed}: op {id} on never-open fd {} reported success ({result:?})",
                    f.fd
                );
                self.stats.stale_errors += 1;
                if let Some(buf) = buf {
                    self.held.push(buf);
                }
            }
        }
    }

    /// Invariant 7. Bytes a read returns must be the next bytes the client
    /// actually wrote to *that* connection. This is what catches a pooled
    /// buffer carrying another connection's payload.
    fn check_read_data(&mut self, conn: Option<usize>, id: OpId, data: &[u8]) {
        let Some(i) = conn else { return };
        let seed = self.seed;
        let c = &mut self.conns[i];
        let start = c.consumed;
        let end = start + data.len();

        assert!(
            end <= c.written.len(),
            "seed {seed}: op {id} on conn {i} returned {} bytes but only {} remain unread of what \
             was written — {} bytes came from somewhere else\n  got: {}",
            data.len(),
            c.written.len() - start,
            end - c.written.len(),
            hex(data)
        );
        assert_eq!(
            data,
            &c.written[start..end],
            "seed {seed}: op {id} on conn {i} returned bytes never written to this connection\n  \
             expected: {}\n  got:      {}",
            hex(&c.written[start..end]),
            hex(data)
        );
        c.consumed = end;
        self.stats.bytes_verified += data.len() as u64;
    }

    /// Close everything, drain to quiescence, then check what is left over.
    fn finish(&mut self) {
        for i in 0..self.conns.len() {
            if !self.conns[i].alive {
                continue;
            }
            let fd = self.conns[i].fd;
            self.closed.insert(fd);
            let tag = self.choose_tag();
            match self.send(Op::Close { fd }, tag) {
                Ok(id) => self.record(
                    id,
                    InFlight {
                        user: tag.unwrap_or(0),
                        kind: Kind::Close,
                        conn: Some(i),
                        fd,
                        len: 0,
                    },
                ),
                Err(e) => self.note_submit_err(&e),
            }
            self.conns[i].alive = false;
            self.conns[i].client = None;
        }

        for _ in 0..10_000 {
            self.note_wait();
            let mut out = Vec::new();
            if let Err(e) = self.d.wait(&mut out) {
                panic!("seed {}: wait() failed while draining: {e}", self.seed);
            }
            if out.is_empty() {
                break;
            }
            for c in out {
                self.check_completion(c);
            }
        }

        // Invariant 3, second half: nothing submitted went unanswered.
        assert!(
            self.inflight.is_empty(),
            "seed {}: {} op(s) never completed: {:?}",
            self.seed,
            self.inflight.len(),
            self.inflight.keys().take(8).collect::<Vec<_>>()
        );

        // Invariant 6: idle driver hands back nothing, immediately.
        let mut out = Vec::new();
        self.d.wait(&mut out).expect("wait on idle driver");
        assert!(
            out.is_empty(),
            "seed {}: idle driver produced {} completion(s)",
            self.seed,
            out.len()
        );
    }

    /// Exercise the teardown path the normal `finish` deliberately avoids:
    /// destroy the driver while kernel operations are still live, then close
    /// the caller-owned descriptors only after the driver is gone.
    fn drop_midflight(self) {
        assert!(
            !self.inflight.is_empty(),
            "mid-flight teardown needs at least one live operation"
        );
        let World {
            d, conns, inflight, ..
        } = self;
        let mut possibly_open: HashSet<RawFd> = conns
            .iter()
            .filter(|conn| conn.alive)
            .map(|conn| conn.fd)
            .collect();
        possibly_open.extend(
            inflight
                .values()
                .filter(|flight| flight.kind == Kind::Close)
                .map(|flight| flight.fd),
        );

        // A Close the driver has already carried out frees its descriptor
        // number, and the harness hands that number straight back out on the
        // next connection — so a queued Close names a number a peer socket may
        // now own. Those are not ours to close twice: the raw close would shut
        // a live connection, and its owner would abort on the second one.
        let peers: HashSet<RawFd> = conns
            .iter()
            .filter_map(|conn| conn.client.as_ref().map(TcpStream::as_raw_fd))
            .collect();

        drop(d);
        for fd in possibly_open.difference(&peers).copied() {
            // SAFETY: this number is not owned by any peer socket, so it is
            // either still the caller's connection or already closed. Nothing
            // allocates a descriptor between the driver's Drop and this loop,
            // so an already-won queued Close can only make this return EBADF.
            unsafe { libc::close(fd) };
        }
    }
}

/// Seed of the case in flight, and a counter bumped as each case starts.
static SEED: AtomicU64 = AtomicU64::new(0);
static CASE_TICK: AtomicU64 = AtomicU64::new(0);
static ALL_DONE: AtomicBool = AtomicBool::new(false);
/// What was outstanding at the last `wait()`, printed by the watchdog: the
/// human-readable table, and the descriptors it mentions so the watchdog can
/// ask the kernel what it thinks of them.
static LAST_WAIT: Mutex<(String, Vec<RawFd>)> = Mutex::new((String::new(), Vec::new()));

/// What the kernel says about `fd` right now: readability and queued bytes.
/// A stranded read on a descriptor the kernel calls readable is a driver bug —
/// the bytes are there and nothing is collecting them.
fn probe_fd(fd: RawFd) -> String {
    // POLLIN alone: hangup is reported in `revents` whether asked for or not,
    // and POLLRDHUP is Linux-only.
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd, zero timeout.
    let r = unsafe { libc::poll(&mut p, 1, 0) };
    let mut queued: libc::c_int = -1;
    // SAFETY: FIONREAD writes one c_int.
    unsafe { libc::ioctl(fd, libc::FIONREAD, &mut queued) };
    format!("poll={r} revents={:#x} fionread={queued}", p.revents)
}

/// `Driver::wait` blocks by contract, so a driver bug that strands an op shows
/// up here as a hang rather than a failure — and a hang in CI is a timeout with
/// no diagnostic. This turns it back into a loud failure that names the seed.
fn spawn_watchdog(limit: Duration) {
    thread::spawn(move || {
        let mut last = CASE_TICK.load(Ordering::Relaxed);
        let mut stalled = Duration::ZERO;
        let poll = Duration::from_millis(250);
        loop {
            thread::sleep(poll);
            if ALL_DONE.load(Ordering::Relaxed) {
                return;
            }
            let now = CASE_TICK.load(Ordering::Relaxed);
            if now != last {
                last = now;
                stalled = Duration::ZERO;
                continue;
            }
            stalled += poll;
            if stalled >= limit {
                let seed = SEED.load(Ordering::Relaxed);
                let state = match LAST_WAIT.try_lock() {
                    Ok(s) => {
                        let mut out = s.0.clone();
                        for fd in &s.1 {
                            out.push_str(&format!("\n  kernel fd {fd}: {}", probe_fd(*fd)));
                        }
                        out
                    }
                    Err(_) => "<snapshot unavailable>".to_string(),
                };
                let msg = format!(
                    "\nfuzz watchdog: seed {seed} made no progress for {limit:?}.\n\
                     The driver is blocked in wait() on an op that can never complete — \
                     stranded by a Close, a clobbered registration, or a lost wakeup.\n\
                     Outstanding at that wait():\n{state}\n\
                     Reproduce: RAMJET_FUZZ_CASES={} cargo test --test fuzz_driver\n\n",
                    seed + 1
                );
                // Straight to the real stderr: the test harness captures the
                // print macros, and a diagnostic nobody sees is no diagnostic.
                let _ = std::io::stderr().write_all(msg.as_bytes());
                let _ = std::io::stderr().flush();
                std::process::abort();
            }
        }
    });
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn fuzz_driver_state_machine() {
    let steps = env_usize("RAMJET_FUZZ_STEPS", 400);
    let cases = env_usize("RAMJET_FUZZ_CASES", 24);
    let case_limit = Duration::from_secs(env_usize("RAMJET_FUZZ_CASE_SECS", 60) as u64);
    spawn_watchdog(case_limit);

    let mut total = Stats::default();
    // Baseline for the whole run, not per case: a leak of one or two
    // descriptors per case hides forever behind a per-case delta, since each
    // case then starts from the inflated number the last one left behind.
    let baseline = probe_fd_number();

    for seed in 0..cases as u64 {
        SEED.store(seed, Ordering::Relaxed);
        CASE_TICK.fetch_add(1, Ordering::Relaxed);
        {
            let mut w = World::new(seed);
            for _ in 0..steps {
                w.step();
            }
            if seed % 4 == 0 && !w.inflight.is_empty() {
                w.stats.midflight_drops += 1;
                total.add(&w.stats);
                w.drop_midflight();
            } else {
                w.finish();
                total.add(&w.stats);
            }
        }
        // Invariant 5: the driver, its fds and every connection are gone.
        let after = probe_fd_number();
        assert!(
            after <= baseline + 2,
            "seed {seed}: descriptors leaked (probe fd was {baseline} at the start of the run, \
             {after} now — a leak of even one per case accumulates to this)"
        );
    }

    println!(
        "fuzz: {cases} cases x {steps} steps | {} conns | submitted read={} pooled={} write={} \
close={} stale={} | {} completions, {} cancelled | refused busy={} invalid={} | \
verified {} payload bytes ({} via pooled) | {} closed-fd ops errored | {} mid-flight drops",
        total.conns,
        total.submitted[Kind::Read as usize],
        total.submitted[Kind::ReadPooled as usize],
        total.submitted[Kind::Write as usize],
        total.submitted[Kind::Close as usize],
        total.submitted[Kind::Stale as usize],
        total.completions,
        total.cancelled,
        total.busy,
        total.invalid,
        total.bytes_verified,
        total.pooled_bytes,
        total.stale_errors,
        total.midflight_drops,
    );
    if total.open_failed > 0 {
        println!(
            "fuzz: {} connection attempt(s) skipped — the machine ran out of ephemeral ports",
            total.open_failed
        );
    }
    total.assert_exercised();
    ALL_DONE.store(true, Ordering::Relaxed);
}
