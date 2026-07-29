//! Late buffer binding: `Op::ReadPooled` behaviour through the public API.
//! Pool internals are covered by unit tests inside `src/reactor/kqueue.rs`;
//! these only assert what a caller can actually observe.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::thread;
use std::time::Duration;

use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Completion, Driver, Op, OpId};

/// A connected pair. The returned fd is non-blocking (the driver's precondition)
/// and idle, so a read on it parks instead of completing eagerly.
fn connected_pair() -> (TcpStream, RawFd) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = l.accept().expect("accept");
    server.set_nonblocking(true).expect("set_nonblocking");
    (client, server.into_raw_fd())
}

/// Pump the driver until `id` completes, then hand back its completion.
fn drain_until(d: &mut PlatformDriver, id: OpId) -> Completion {
    let mut out = Vec::new();
    for _ in 0..20 {
        out.clear();
        d.wait(&mut out).expect("wait");
        if let Some(i) = out.iter().position(|c| c.id == id) {
            return out.swap_remove(i);
        }
    }
    panic!("op {id} never completed");
}

/// Eager path: the data is already waiting, so the completion comes back from
/// `submit` with a buffer attached.
#[test]
fn pooled_read_roundtrips_on_the_eager_path() {
    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    client.write_all(b"eager payload").expect("client write");

    let id = d.submit(Op::ReadPooled { fd }).expect("submit pooled read");
    let c = drain_until(&mut d, id);
    let n = c.result.expect("read succeeded") as usize;
    let buf = c.buf.expect("a pooled read completes with a buffer");
    assert_eq!(buf, b"eager payload", "the buffer is exactly the data read");
    assert_eq!(
        buf.len(),
        n,
        "a pooled completion's length is its byte count, with no slicing step"
    );

    d.recycle(buf);
    d.submit(Op::Close { fd }).expect("close");
}

/// Parked path: nothing to read at submit time, so the op parks owning no
/// buffer and picks one up only when the data lands. Then round two on the same
/// fd, which can only work if the pool and the bufferless re-park both hold up.
#[test]
fn parked_pooled_read_completes_when_data_arrives_and_the_fd_can_be_reused() {
    let (mut client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    for (round, msg) in [b"first round".as_slice(), b"second round".as_slice()]
        .into_iter()
        .enumerate()
    {
        // Submit against an idle socket: this parks, holding nothing.
        let id = d.submit(Op::ReadPooled { fd }).expect("submit pooled read");
        // Data lands afterwards, so only the wake path can deliver it.
        client.write_all(msg).expect("client write");

        let c = drain_until(&mut d, id);
        let n = c.result.expect("read succeeded") as usize;
        let buf = c.buf.expect("a pooled read completes with a buffer");
        assert_eq!(buf, msg, "round {round}");
        assert_eq!(buf.len(), n, "round {round}: length is the byte count");

        // Round two draws this very buffer back out of the pool.
        d.recycle(buf);
    }

    d.submit(Op::Close { fd }).expect("close");
}

/// A cancelled pooled read reports `ECANCELED` with no buffer, because a parked
/// one never had one. This is the documented asymmetry against `Op::Read`.
#[test]
fn close_cancels_a_parked_pooled_read_with_no_buffer() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    let read = d.submit(Op::ReadPooled { fd }).expect("submit pooled read");
    let close = d.submit(Op::Close { fd }).expect("submit close");

    let mut out = Vec::new();
    d.wait(&mut out).expect("wait");

    let cancelled = out.iter().find(|c| c.id == read).expect("read completion");
    let err = cancelled.result.as_ref().expect_err("read was cancelled");
    assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
    assert!(
        cancelled.buf.is_none(),
        "a parked pooled read owns no buffer, so there is none to hand back"
    );
    assert!(out.iter().any(|c| c.id == close && c.result.is_ok()));
}

/// Pooled and plain reads share the one (fd, EVFILT_READ) slot, with no special
/// case for the pooled variant.
#[test]
fn a_pooled_read_collides_with_a_plain_read_on_the_same_fd() {
    let (_client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    d.submit(Op::ReadPooled { fd }).expect("first read parks");
    let err = match d.submit(Op::Read {
        fd,
        buf: vec![0; 64],
    }) {
        Ok(_) => panic!("a second read on the same fd must be refused"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy);

    d.submit(Op::Close { fd }).expect("close");
}

/// Peer EOF still reports 0 with the buffer attached, same as `Op::Read`.
#[test]
fn pooled_read_reports_eof_as_zero() {
    let (client, fd) = connected_pair();
    let mut d = PlatformDriver::new().expect("driver");

    let id = d.submit(Op::ReadPooled { fd }).expect("submit pooled read");
    drop(client);

    let c = drain_until(&mut d, id);
    assert_eq!(c.result.expect("read succeeded"), 0, "peer EOF reads as 0");
    let buf = c.buf.expect("even an EOF completion carries the buffer");
    assert!(buf.is_empty(), "EOF read nothing, so the buffer is empty");

    d.submit(Op::Close { fd }).expect("close");
}

/// Cross-connection disclosure regression.
///
/// A pooled buffer goes back out to whichever connection reads next, carrying
/// whatever the previous reader left in its spare capacity. The completion is
/// trimmed to the bytes read precisely so that safe code cannot reach those
/// bytes. This recycles connection A's completion buffer *as-is*, which is the
/// documented thing to do, and checks that B cannot see A's payload.
#[test]
fn one_connection_cannot_observe_another_through_a_recycled_buffer() {
    let mut d = PlatformDriver::new().expect("driver");

    let (mut a, fd_a) = connected_pair();
    let secret = [0xAAu8; 100];
    a.write_all(&secret).expect("A writes");
    let id_a = d.submit(Op::ReadPooled { fd: fd_a }).expect("A read");
    let c_a = drain_until(&mut d, id_a);
    let n_a = c_a.result.expect("A read ok") as usize;
    let buf_a = c_a.buf.expect("A buffer");
    assert_eq!(n_a, secret.len());
    assert_eq!(
        buf_a.len(),
        n_a,
        "A's completion is trimmed to its own read"
    );

    // Recycled untouched — the caller does nothing to scrub it.
    d.recycle(buf_a);

    let (mut b, fd_b) = connected_pair();
    b.write_all(b"0123456789").expect("B writes");
    let id_b = d.submit(Op::ReadPooled { fd: fd_b }).expect("B read");
    let c_b = drain_until(&mut d, id_b);
    let n_b = c_b.result.expect("B read ok") as usize;
    let buf_b = c_b.buf.expect("B buffer");

    assert_eq!(n_b, 10);
    assert_eq!(
        buf_b.len(),
        10,
        "B's buffer must end at B's data, not run on into A's"
    );
    assert_eq!(buf_b, b"0123456789");
    assert!(
        !buf_b.contains(&0xAA),
        "B must not be able to observe any byte of A's payload"
    );

    d.submit(Op::Close { fd: fd_a }).expect("close A");
    d.submit(Op::Close { fd: fd_b }).expect("close B");
}

/// Make `close()` on this socket send an RST, so our next read fails.
fn reset_on_close(s: &TcpStream) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `l` is a live linger struct and we pass exactly its size.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "setsockopt(SO_LINGER) failed");
}

/// The error path is the same disclosure vector as the success path: a failed
/// read borrows a pool buffer that may still hold the previous connection's
/// bytes, so it must hand back nothing rather than a full-sized buffer.
#[test]
fn a_failed_pooled_read_hands_back_no_stale_bytes() {
    let mut d = PlatformDriver::new().expect("driver");

    // Seed the pool with a recognisable "previous connection" payload.
    d.recycle(vec![0xAAu8; PlatformDriver::pool_buf_size()]);

    let (mut client, fd) = connected_pair();
    reset_on_close(&client);
    // Unread data plus an RST is what makes the next read fail rather than EOF.
    client.write_all(b"unread").expect("client write");
    drop(client);

    let mut failed = None;
    for _ in 0..50 {
        let id = d.submit(Op::ReadPooled { fd }).expect("submit");
        let c = drain_until(&mut d, id);
        match c.result {
            Err(_) => {
                failed = Some(c.buf.expect("even a failed read carries the buffer field"));
                break;
            }
            Ok(_) => {
                if let Some(b) = c.buf {
                    d.recycle(b);
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    let buf = failed.expect("the RST should have made a read fail");
    assert!(
        buf.is_empty(),
        "a failed pooled read read nothing, so it must carry nothing (got {} bytes)",
        buf.len()
    );

    d.submit(Op::Close { fd }).expect("close");
}
