//! Driver-level regression tests: cancellation, idle wait, and slot collisions.
//! These drive the reactor API directly rather than going through the echo loop.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::time::{Duration, Instant};

use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};

/// A connected pair. The returned fd is non-blocking (the driver's precondition)
/// and idle, so a Read on it parks instead of completing eagerly.
fn connected_pair() -> (TcpStream, i32) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = l.accept().expect("accept");
    server.set_nonblocking(true).expect("set_nonblocking");
    (client, server.into_raw_fd())
}

/// C1: Close must cancel ops parked on that fd with ECANCELED and give the
/// buffer back, rather than dropping them so the caller waits forever.
#[test]
fn close_cancels_parked_ops_with_ecanceled() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    let read = d
        .submit(Op::Read {
            fd,
            buf: vec![0; 64],
        })
        .expect("submit read");
    let close = d.submit(Op::Close { fd }).expect("submit close");

    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");

    let cancelled = out.iter().find(|c| c.id == read).expect("read completion");
    let err = cancelled.result.as_ref().expect_err("read was cancelled");
    assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
    assert_eq!(
        cancelled.buf.as_ref().map(Vec::len),
        Some(64),
        "cancelled op must hand its buffer back"
    );
    assert!(out.iter().any(|c| c.id == close && c.result.is_ok()));
}

/// C2: with nothing in flight `wait` must return empty, not block forever.
#[test]
fn wait_returns_immediately_when_nothing_is_in_flight() {
    let mut d = PlatformDriver::new().expect("driver");
    let mut out = Vec::new();

    let t = Instant::now();
    d.wait(&mut out).expect("wait on idle driver");
    assert!(out.is_empty());

    // Same again once a completion has been submitted and drained: the driver
    // is idle, so the second wait must not block either.
    let (_client, fd) = connected_pair();
    d.submit(Op::Close { fd }).expect("submit close");
    d.wait(&mut out).expect("wait");
    assert_eq!(out.len(), 1);
    out.clear();
    d.wait(&mut out).expect("wait after drain");
    assert!(out.is_empty());

    assert!(
        t.elapsed() < Duration::from_secs(5),
        "wait blocked with nothing in flight"
    );
}

/// C3: a second op on the same (fd, filter) would clobber the first's kevent, so
/// it is refused synchronously instead of stranding the first op.
#[test]
fn colliding_op_on_same_fd_and_filter_is_refused() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    let first = d
        .submit(Op::Read {
            fd,
            buf: vec![0; 64],
        })
        .expect("first read parks");
    let err = d
        .submit(Op::Read {
            fd,
            buf: vec![0; 64],
        })
        .expect_err("second read on the same fd must be refused");
    assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);

    // A Write uses the other filter, so it does not collide.
    d.submit(Op::Write {
        fd,
        buf: b"hello".to_vec(),
    })
    .expect("write uses EVFILT_WRITE");

    // The first read is still live: closing the fd cancels it.
    d.submit(Op::Close { fd }).expect("submit close");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");
    assert!(out.iter().any(|c| c.id == first));
}

/// Fairness: a connection that keeps completing eagerly must not starve a
/// parked one. Regression for the 200-conn p99 blowup — `wait` must harvest
/// kqueue with a zero timeout even when eager completions are already ready.
#[test]
fn eager_fast_path_does_not_starve_parked_ops() {
    use std::io::Write;
    use std::thread;

    let (mut client_a, srv_a) = connected_pair();
    let (mut client_b, srv_b) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    // Keep `srv_a` permanently hot: every Read on it completes eagerly.
    // Unblocked by the RST from Close at the end of the test.
    let writer = thread::spawn(move || {
        let chunk = [0u8; 65536];
        while client_a.write_all(&chunk).is_ok() {}
    });

    // `srv_b`'s data lands only once the hot loop is already spinning.
    let waker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let _ = client_b.write_all(b"finally");
    });

    let b_read = d
        .submit(Op::Read {
            fd: srv_b,
            buf: vec![0; 64],
        })
        .expect("submit b read");
    let mut a_read = d
        .submit(Op::Read {
            fd: srv_a,
            buf: vec![0; 4096],
        })
        .expect("submit a read");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut b_done = false;
    'outer: while Instant::now() < deadline {
        d.wait(&mut out).expect("wait");
        for c in out.drain(..) {
            if c.id == b_read {
                assert!(c.result.is_ok(), "b read failed: {:?}", c.result);
                b_done = true;
                break 'outer;
            }
            if c.id == a_read {
                let buf = c.buf.expect("a buffer returned");
                a_read = d
                    .submit(Op::Read { fd: srv_a, buf })
                    .expect("resubmit a read");
            }
        }
    }
    assert!(b_done, "parked read starved behind the eager fast path");

    d.submit(Op::Close { fd: srv_a }).expect("close a");
    d.submit(Op::Close { fd: srv_b }).expect("close b");
    let _ = writer.join();
    let _ = waker.join();
}

/// A zero-length Read would complete with 0 and be misread as EOF.
#[test]
fn empty_read_buffer_is_rejected() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    let err = d
        .submit(Op::Read {
            fd,
            buf: Vec::new(),
        })
        .expect_err("empty read buffer must be refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    d.submit(Op::Close { fd }).expect("submit close");
}

/// Registrations outlive the ops that created them: only the first Read on an fd
/// registers interest, and every later one relies on that same knote. Churning
/// 100 sequential Reads over one fd exercises both the reuse and the tolerance of
/// spurious events left behind by ops that already finished.
#[test]
fn persistent_registration_survives_op_churn() {
    use std::io::Write;

    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");
    let mut out = Vec::new();

    for i in 0..100u32 {
        let msg = format!("msg-{i:03}");
        client.write_all(msg.as_bytes()).expect("client write");

        let id = d
            .submit(Op::Read {
                fd,
                buf: vec![0; 64],
            })
            .expect("submit read");

        let mut got = None;
        for _ in 0..10 {
            out.clear();
            d.wait(&mut out).expect("wait");
            if let Some(i) = out.iter().position(|c| c.id == id) {
                let c = out.swap_remove(i);
                let n = c.result.expect("read succeeded") as usize;
                got = Some(c.buf.expect("buffer returned")[..n].to_vec());
                break;
            }
        }
        assert_eq!(got.expect("read completed"), msg.as_bytes(), "round {i}");
    }

    d.submit(Op::Close { fd }).expect("close");
}

/// EV_DISPATCH disables a knote as it delivers, so every later op on that
/// (fd, filter) has to re-enable it. This pins the re-enable against a lost
/// wakeup, in the one ordering that can expose it: the op parks on an empty
/// socket (queueing an EV_ENABLE that has not reached the kernel yet) and the
/// data lands *before* the changelist is flushed. Only the kernel re-evaluating
/// the filter when it applies EV_ENABLE can deliver that event. If that
/// assumption is wrong this test hangs rather than fails.
#[test]
fn re_enabled_knote_sees_data_that_arrived_before_the_flush() {
    use std::io::Write;

    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");
    let mut out = Vec::new();

    let round = |d: &mut PlatformDriver, out: &mut Vec<_>, client: &mut TcpStream, msg: &[u8]| {
        // Socket is empty here, so this parks: first time queueing EV_ADD,
        // afterwards EV_ENABLE against the knote EV_DISPATCH just disabled.
        let id = d
            .submit(Op::Read {
                fd,
                buf: vec![0; 64],
            })
            .expect("submit read");
        // Racing arrival: lands after the park, before the flush.
        client.write_all(msg).expect("client write");

        for _ in 0..10 {
            out.clear();
            d.wait(out).expect("wait");
            if let Some(i) = out
                .iter()
                .position(|c: &ramjet::reactor::Completion| c.id == id)
            {
                let c = out.swap_remove(i);
                let n = c.result.expect("read succeeded") as usize;
                return c.buf.expect("buffer returned")[..n].to_vec();
            }
        }
        panic!("read never completed");
    };

    // Round 1 exercises EV_ADD, round 2 onward the EV_ENABLE re-arm.
    assert_eq!(round(&mut d, &mut out, &mut client, b"one"), b"one");
    assert_eq!(round(&mut d, &mut out, &mut client, b"two"), b"two");
    assert_eq!(round(&mut d, &mut out, &mut client, b"three"), b"three");

    d.submit(Op::Close { fd }).expect("close");
}

/// `WriteFrom` sends only the tail of the buffer but hands the whole thing
/// back, and reports the bytes it actually sent.
#[test]
fn write_from_sends_the_tail_and_returns_the_whole_buffer() {
    use std::io::Read as _;

    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    // Four header bytes the peer must never see, then the payload.
    let mut buf = b"HDR!".to_vec();
    buf.extend_from_slice(b"payload");
    let id = d
        .submit(Op::Write {
            fd,
            buf: Vec::new(),
        })
        .expect("prime the slot with an empty write");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");
    assert!(out.iter().any(|c| c.id == id));
    out.clear();

    let id = d
        .submit(Op::WriteFrom { fd, buf, start: 4 })
        .expect("submit write_from");
    d.wait(&mut out).expect("wait");
    let c = out.into_iter().find(|c| c.id == id).expect("completion");
    assert_eq!(
        c.result.expect("write ok"),
        7,
        "result is the bytes sent, not the buffer length"
    );
    let back = c.buf.expect("buffer returned");
    assert_eq!(back, b"HDR!payload", "the whole buffer comes back");

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut got = [0u8; 7];
    client.read_exact(&mut got).expect("client read");
    assert_eq!(&got, b"payload", "the header bytes must not go on the wire");

    d.submit(Op::Close { fd }).expect("close");
}

#[test]
fn write_from_at_the_end_of_the_buffer_sends_nothing() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");
    let buf = b"header only".to_vec();
    let len = buf.len();
    let id = d
        .submit(Op::WriteFrom {
            fd,
            buf,
            start: len,
        })
        .expect("start == len is legal and writes nothing");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");
    let c = out.into_iter().find(|c| c.id == id).expect("completion");
    assert_eq!(c.result.expect("ok"), 0);
    assert_eq!(c.buf.expect("buffer").len(), len);
    d.submit(Op::Close { fd }).expect("close");
}

#[test]
fn write_from_past_the_end_is_refused() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");
    let err = match d.submit(Op::WriteFrom {
        fd,
        buf: vec![0; 4],
        start: 5,
    }) {
        Ok(_) => panic!("a start past the end must be refused"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    d.submit(Op::Close { fd }).expect("close");
}

/// WriteFrom shares the write slot with Write, so the collision rule applies
/// across both.
#[test]
fn write_from_collides_with_a_plain_write() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    // 8 MiB dwarfs the loopback socket buffers, and a Write only completes
    // once fully flushed with nobody reading the peer — so this always parks.
    // No wait() probe: wait would block until the write finishes, i.e. forever.
    let write = d
        .submit(Op::Write {
            fd,
            buf: vec![0u8; 8 * 1024 * 1024],
        })
        .expect("big write parks");

    let err = match d.submit(Op::WriteFrom {
        fd,
        buf: vec![0; 16],
        start: 8,
    }) {
        Ok(_) => panic!("WriteFrom must collide with a parked Write"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);

    // Close cancels the parked write; drain and check it comes back ECANCELED.
    d.submit(Op::Close { fd }).expect("close");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");
    let cancelled = out
        .iter()
        .find(|c| c.id == write)
        .expect("write completion");
    assert_eq!(
        cancelled
            .result
            .as_ref()
            .expect_err("cancelled")
            .raw_os_error(),
        Some(libc::ECANCELED)
    );
}

/// `submit_with` hands its tag back on the completion, and plain `submit`
/// reports zero.
#[test]
fn user_data_round_trips_on_every_op_kind() {
    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    // Eager read: data is already waiting.
    use std::io::Write as _;
    client.write_all(b"tagged").expect("client write");
    let read = d
        .submit_with(
            Op::Read {
                fd,
                buf: vec![0; 32],
            },
            0xDEAD_BEEF_CAFE_1234,
        )
        .expect("submit read");

    let write = d
        .submit_with(
            Op::Write {
                fd,
                buf: b"out".to_vec(),
            },
            0x1111_2222_3333_4444,
        )
        .expect("submit write");

    // A second connection, because the read above may still hold this fd's read
    // slot — whether it completed eagerly depends on when the data landed.
    let (_client2, fd2) = connected_pair();
    let plain = d
        .submit(Op::ReadPooled { fd: fd2 })
        .expect("plain submit carries no tag");

    let close = d
        .submit_with(Op::Close { fd }, 0xFFFF_0000_FFFF_0000)
        .expect("submit close");

    // Closing fd2 cancels its parked read, so every op above reaches a
    // completion and the drain below terminates.
    d.submit(Op::Close { fd: fd2 }).expect("close fd2");

    let mut seen = Vec::new();
    for _ in 0..10 {
        let mut out = Vec::new();
        d.wait(&mut out).expect("wait");
        if out.is_empty() {
            break;
        }
        seen.extend(out.into_iter().map(|c| (c.id, c.user)));
    }

    let tag = |id| seen.iter().find(|(i, _)| *i == id).map(|(_, u)| *u);
    assert_eq!(tag(read), Some(0xDEAD_BEEF_CAFE_1234));
    assert_eq!(tag(write), Some(0x1111_2222_3333_4444));
    assert_eq!(tag(close), Some(0xFFFF_0000_FFFF_0000));
    assert_eq!(tag(plain), Some(0), "plain submit must report zero");
}

/// A tag survives an op that parks and is woken later, and one that a Close
/// cancels — the two paths where the completion is built far from the submit.
#[test]
fn user_data_survives_parking_and_cancellation() {
    use std::io::Write as _;

    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    // Parks: nothing to read yet.
    let parked = d
        .submit_with(Op::ReadPooled { fd }, 0xABCD)
        .expect("submit");
    client.write_all(b"late").expect("client write");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");
    let c = out.iter().find(|c| c.id == parked).expect("completion");
    assert_eq!(c.user, 0xABCD, "a woken op keeps its tag");

    // Cancelled by a Close.
    let doomed = d
        .submit_with(Op::ReadPooled { fd }, 0x9999)
        .expect("submit");
    d.submit_with(Op::Close { fd }, 0x7777).expect("close");
    out.clear();
    d.wait(&mut out).expect("wait");
    let c = out.iter().find(|c| c.id == doomed).expect("cancelled");
    assert_eq!(c.user, 0x9999, "a cancelled op keeps its tag");
    assert_eq!(
        c.result.as_ref().expect_err("cancelled").raw_os_error(),
        Some(libc::ECANCELED)
    );
}
