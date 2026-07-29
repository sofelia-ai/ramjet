//! Recycled-descriptor safety, in its own test binary: it depends on which fd
//! number the kernel hands out next, and tests sharing a process run in parallel
//! threads that would race for that number.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};

/// Accept one connection on `l`. The returned fd is non-blocking (the driver's
/// precondition) and idle, so a Read on it parks instead of completing eagerly.
fn pair_on(l: &TcpListener) -> (TcpStream, RawFd) {
    let addr = l.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = l.accept().expect("accept");
    server.set_nonblocking(true).expect("set_nonblocking");
    (client, server.into_raw_fd())
}

/// An fd's registration must not outlive it. A Read parks on A — queueing a
/// registration that no `wait` has flushed yet — and A is closed before that
/// flush. When the next connection lands on A's descriptor number, its own Read
/// has to register from scratch and complete on its own data, with no stale
/// interest and no EBADF leaking across from the dead fd.
#[test]
fn a_closed_fds_registration_does_not_follow_its_descriptor_number() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut d = PlatformDriver::new().expect("driver");

    let (client_a, fd_a) = pair_on(&l);
    let read_a = d
        .submit(Op::Read {
            fd: fd_a,
            buf: vec![0; 64],
        })
        .expect("read A parks, registration only queued");
    d.submit(Op::Close { fd: fd_a }).expect("close A");
    drop(client_a);

    // Both descriptors A used are free now, and the kernel hands out the lowest
    // free number, so the new connection lands exactly on A's.
    let (mut client_b, fd_b) = pair_on(&l);
    assert_eq!(
        fd_b, fd_a,
        "test is only meaningful if the descriptor number is reused"
    );

    let read_b = d
        .submit(Op::Read {
            fd: fd_b,
            buf: vec![0; 64],
        })
        .expect("read B");
    client_b.write_all(b"fresh").expect("write B");

    let mut all = Vec::new();
    let mut out = Vec::new();
    for _ in 0..10 {
        out.clear();
        d.wait(&mut out).expect("wait");
        all.append(&mut out);
        if all.iter().any(|c| c.id == read_b) {
            break;
        }
    }

    let b = all
        .iter()
        .find(|c| c.id == read_b)
        .expect("B's read must complete, not hang on A's dead registration");
    let n = *b
        .result
        .as_ref()
        .expect("B's read must not inherit an error from the closed fd") as usize;
    assert_eq!(&b.buf.as_ref().expect("buffer")[..n], b"fresh");

    // A's own read was cancelled by the close, not silently dropped.
    let a = all.iter().find(|c| c.id == read_a).expect("A's completion");
    assert_eq!(
        a.result
            .as_ref()
            .expect_err("A was cancelled")
            .raw_os_error(),
        Some(libc::ECANCELED)
    );

    d.submit(Op::Close { fd: fd_b }).expect("close B");
}
