#![cfg(any(target_os = "macos", target_os = "freebsd"))]
//! SO_NOSIGPIPE regression. Its own test binary on purpose: it changes
//! process-wide signal disposition, which must not leak into the other suites.
//!
//! Rust's std quietly sets SO_NOSIGPIPE on every socket it creates on Apple
//! targets, and `accept(2)` inherits the option — so a listener that came from
//! `TcpListener` hides this bug entirely. The test clears the option first to
//! stand in for the listener a C host would hand us.

use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::thread;
use std::time::Duration;

use ramjet::reactor::kqueue::KqueueDriver;
use ramjet::reactor::{Driver, Op};

fn nosigpipe(fd: RawFd) -> libc::c_int {
    let mut v: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v`/`len` are live and sized as the option expects.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&raw mut v).cast(),
            &raw mut len,
        )
    };
    assert_eq!(r, 0, "getsockopt(SO_NOSIGPIPE) failed");
    v
}

fn set_nosigpipe(fd: RawFd, on: libc::c_int) {
    // SAFETY: `on` is a live c_int and we pass exactly its size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&raw const on).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "setsockopt(SO_NOSIGPIPE) failed");
}

#[test]
fn accepted_fd_is_protected_from_sigpipe() {
    // std ignores SIGPIPE process-wide; restore the default so an unprotected
    // write aborts this process the way it would abort a C host embedding
    // ramjet. Surviving to the end of this test is half the assertion.
    // SAFETY: setting a signal to SIG_DFL is always defined.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local_addr");
    l.set_nonblocking(true).expect("set_nonblocking");
    set_nosigpipe(l.as_raw_fd(), 0);
    let listener = l.into_raw_fd();

    let mut d = KqueueDriver::new().expect("driver");
    let accept = d
        .submit(Op::Accept { fd: listener })
        .expect("submit accept");

    let client = TcpStream::connect(addr).expect("connect");
    let mut out = Vec::new();
    d.wait(&mut out).expect("wait for accept");
    let conn = out
        .iter()
        .find(|c| c.id == accept)
        .and_then(|c| c.result.as_ref().ok().copied())
        .expect("accepted fd") as RawFd;
    out.clear();

    // The driver must set this itself: it was cleared on the listener, so it
    // cannot have been inherited.
    assert_eq!(
        nosigpipe(conn),
        1,
        "driver must set SO_NOSIGPIPE on accepted fds"
    );

    // End-to-end: the peer goes away, and writing to it must produce an error
    // completion rather than a signal. The first write still lands in the socket
    // buffer; it is a later one that would raise SIGPIPE.
    drop(client);
    thread::sleep(Duration::from_millis(50));
    let mut saw_error = false;
    for _ in 0..4 {
        d.submit(Op::Write {
            fd: conn,
            buf: vec![b'x'; 8192],
        })
        .expect("submit write");
        d.wait(&mut out).expect("wait for write");
        saw_error |= out.iter().any(|c| c.result.is_err());
        out.clear();
        thread::sleep(Duration::from_millis(30));
    }
    assert!(
        saw_error,
        "write to a dead peer should complete with an error"
    );

    d.submit(Op::Close { fd: conn }).expect("close conn");
    d.submit(Op::Close { fd: listener })
        .expect("close listener");
}
