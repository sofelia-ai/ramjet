//! Descriptor-accounting tests: both assert things about fd *numbers*.
//!
//! They live in their own binary, serialised against each other, because that
//! is the only way to make them deterministic. Descriptor numbers are process
//! -wide state allocated lowest-free-first, so any sibling test opening or
//! closing a socket on another thread moves them underneath these assertions.
//! Sharing `tests/net.rs` cost 7 failures in 20 runs; alone here it is 0.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Mutex, MutexGuard};

use ramjet::net::Listener;

/// Only one of these tests may touch descriptor numbers at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    // A panic in one test poisons the lock; the other still wants to run.
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// The number a fresh descriptor gets, which tracks how many are open:
/// allocation is lowest-free-first, so a 200-descriptor leak moves this by about
/// 200. The probe file closes when this returns, freeing the number again.
fn probe_fd_number() -> RawFd {
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    f.as_raw_fd()
}

/// Dropping a Listener closes its socket. Asked of the descriptor directly
/// rather than by reconnecting to the port, which would race whoever binds next.
#[test]
fn dropping_a_listener_closes_the_socket() {
    let _guard = serial();

    let l = Listener::bind(loopback(0)).expect("bind");
    let fd = l.as_raw_fd();
    // SAFETY: F_GETFD only reads the flags of a descriptor number.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) },
        -1,
        "fd should be open while the Listener is alive"
    );

    drop(l);

    // SAFETY: as above. The number may now be closed, which is the question.
    let after = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_eq!(
        after, -1,
        "fd should be closed once the Listener is dropped"
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}

/// `build` opens the socket before it can know whether bind will succeed, so
/// every failure path has to close it again.
#[test]
fn a_failed_bind_leaks_no_descriptor() {
    let _guard = serial();

    let first = Listener::bind(loopback(0)).expect("first bind");
    let addr = first.local_addr();

    let before = probe_fd_number();
    for _ in 0..200 {
        match Listener::bind(addr) {
            Ok(_) => panic!("bind should have failed"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::AddrInUse),
        }
    }
    let after = probe_fd_number();
    assert_eq!(
        after, before,
        "failed binds leaked descriptors: probe fd {before} -> {after}"
    );
}
