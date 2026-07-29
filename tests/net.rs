//! Tests for ramjet-owned sockets. Clients are always `std::net::TcpStream`:
//! a ramjet listener has to interoperate with the ordinary world, and using
//! std on the other end is what proves it.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, RawFd};
#[cfg(target_os = "macos")]
use std::ptr;

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Completion, Driver, Op, OpId};

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
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

/// Read a socket option back as its raw integer.
///
/// macOS reports the underlying `so_options` bit rather than a normalised 1
/// (`SO_REUSEADDR` reads back as 4, `SO_REUSEPORT` as 512), so callers must test
/// against zero and never against one.
fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut v: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are live and sized exactly as the option expects.
    let r = unsafe { libc::getsockopt(fd, level, name, (&raw mut v).cast(), &raw mut len) };
    assert_eq!(r, 0, "getsockopt failed: {}", io::Error::last_os_error());
    v
}

/// Accept everything queued on a listening fd, closing each, and report how
/// many there were. The listener is non-blocking, so an empty queue ends it.
/// Only the macOS last-binder-wins test needs this; gate it with that test.
#[cfg(target_os = "macos")]
fn drain_accepts(fd: RawFd) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: null addr/addrlen accepts without asking for the peer address.
        let c = unsafe { libc::accept(fd, ptr::null_mut(), ptr::null_mut()) };
        if c < 0 {
            return n;
        }
        // SAFETY: `c` is ours and we are done with it.
        unsafe { libc::close(c) };
        n += 1;
    }
}

/// Bind v6 loopback, or report `None` if this machine has no IPv6 at all.
fn bind_v6_or_skip(only_v6: bool) -> Option<Listener> {
    match Listener::builder(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
        .only_v6(only_v6)
        .build()
    {
        Ok(l) => Some(l),
        Err(e)
            if e.kind() == io::ErrorKind::AddrNotAvailable
                || e.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
        {
            eprintln!("skipping: no IPv6 loopback here ({e})");
            None
        }
        Err(e) => panic!("IPv6 bind failed: {e}"),
    }
}

/// The whole loop: ramjet binds, std connects, the driver accepts and echoes.
#[test]
fn listener_interops_with_std_clients_and_the_driver() {
    let l = Listener::bind(loopback(0)).expect("bind");
    let addr = l.local_addr();
    assert_ne!(
        addr.port(),
        0,
        "local_addr must report the port the kernel actually chose"
    );
    let listener = l.into_raw_fd();

    let mut d = PlatformDriver::new().expect("driver");
    let accept = d
        .submit(Op::Accept { fd: listener })
        .expect("submit accept");

    let mut client = TcpStream::connect(addr).expect("std client connects");
    let conn = drain_until(&mut d, accept)
        .result
        .expect("accept succeeded") as RawFd;

    client.write_all(b"hello ramjet").expect("client write");
    let read = d
        .submit(Op::Read {
            fd: conn,
            buf: vec![0; 64],
        })
        .expect("submit read");
    let c = drain_until(&mut d, read);
    let n = c.result.expect("read succeeded") as usize;
    let buf = c.buf.expect("buffer returned");
    assert_eq!(&buf[..n], b"hello ramjet");

    let write = d
        .submit(Op::Write {
            fd: conn,
            buf: buf[..n].to_vec(),
        })
        .expect("submit write");
    drain_until(&mut d, write).result.expect("write succeeded");

    let mut got = vec![0; n];
    client.read_exact(&mut got).expect("client read");
    assert_eq!(got, b"hello ramjet");

    d.submit(Op::Close { fd: conn }).expect("close conn");
    d.submit(Op::Close { fd: listener })
        .expect("close listener");
}

/// SO_REUSEPORT only works if it reaches the socket before bind(2), so two
/// listeners sharing one address is the proof that the build order is right.
#[test]
fn reuseport_lets_two_listeners_share_one_address() {
    let first = Listener::builder(loopback(0))
        .reuseport(true)
        .build()
        .expect("first bind");
    let addr = first.local_addr();

    let second = Listener::builder(addr)
        .reuseport(true)
        .build()
        .expect("second bind must be allowed to share the address");
    assert_eq!(second.local_addr(), addr);
}

/// Sharing the address is *all* macOS gives you: the last binder takes every
/// connection and the earlier ones starve. Pinned so that if Apple ever ships
/// real fan-out we find out from a failing test rather than by guessing.
#[cfg(target_os = "macos")]
#[test]
fn macos_reuseport_hands_every_connection_to_the_last_binder() {
    const CONNS: usize = 30;

    let first = Listener::builder(loopback(0))
        .reuseport(true)
        .build()
        .expect("first bind");
    let addr = first.local_addr();
    let middle = Listener::builder(addr)
        .reuseport(true)
        .build()
        .expect("second bind");
    let last = Listener::builder(addr)
        .reuseport(true)
        .build()
        .expect("third bind");

    let clients: Vec<TcpStream> = (0..CONNS)
        .map(|_| TcpStream::connect(addr).expect("connect"))
        .collect();

    let counts = [
        drain_accepts(first.as_raw_fd()),
        drain_accepts(middle.as_raw_fd()),
        drain_accepts(last.as_raw_fd()),
    ];
    assert_eq!(
        counts,
        [0, 0, CONNS],
        "macOS SO_REUSEPORT does not load balance: the last binder takes all"
    );

    drop(clients);
}

/// The same two binds without SO_REUSEPORT: the second must be refused. Pins
/// that the option is doing the work, not SO_REUSEADDR or luck.
#[test]
fn without_reuseport_a_second_bind_is_refused() {
    let first = Listener::bind(loopback(0)).expect("first bind");
    // Matched rather than `expect_err`: Listener deliberately has no Debug impl.
    let err = match Listener::bind(first.local_addr()) {
        Ok(_) => panic!("second bind must fail without SO_REUSEPORT"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
}

/// Options set before bind really are on the socket afterwards — read back with
/// getsockopt rather than inferred from behaviour.
#[test]
fn options_are_readable_back_off_the_socket() {
    let default = Listener::bind(loopback(0)).expect("bind with defaults");
    assert_ne!(
        getsockopt_int(default.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR),
        0,
        "SO_REUSEADDR defaults on (macOS reports the raw so_options bit, not 1)"
    );

    let plain = Listener::builder(loopback(0))
        .reuseaddr(false)
        .build()
        .expect("bind without reuseaddr");
    assert_eq!(
        getsockopt_int(plain.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR),
        0,
        "reuseaddr(false) must leave SO_REUSEADDR clear"
    );

    if let Some(v6) = bind_v6_or_skip(true) {
        assert_ne!(
            getsockopt_int(v6.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
            0,
            "only_v6(true) must set IPV6_V6ONLY"
        );
    }
}

/// into_raw_fd hands the descriptor over instead of closing it, so the socket
/// outlives the Listener that made it.
#[test]
fn into_raw_fd_keeps_the_socket_open() {
    let l = Listener::bind(loopback(0)).expect("bind");
    let addr = l.local_addr();
    let fd = l.into_raw_fd();

    TcpStream::connect(addr).expect("still listening after into_raw_fd");

    // SAFETY: `fd` is ours now — into_raw_fd gave up ownership.
    unsafe { libc::close(fd) };
}

/// The fd traits are real trait impls, not inherent methods that merely look
/// like them: these bounds would not resolve otherwise.
#[test]
fn listener_implements_the_fd_traits() {
    fn needs_as_fd<T: AsFd>(t: &T) -> RawFd {
        t.as_fd().as_raw_fd()
    }
    fn needs_as_raw_fd<T: AsRawFd>(t: &T) -> RawFd {
        t.as_raw_fd()
    }
    fn needs_into_raw_fd<T: IntoRawFd>(t: T) -> RawFd {
        t.into_raw_fd()
    }

    let l = Listener::bind(loopback(0)).expect("bind");
    assert_eq!(needs_as_fd(&l), needs_as_raw_fd(&l));

    let fd = needs_into_raw_fd(l);
    // SAFETY: ownership was transferred to us by into_raw_fd.
    unsafe { libc::close(fd) };
}

/// IPv6 loopback, end to end through the driver.
#[test]
fn ipv6_loopback_binds_and_accepts() {
    let Some(l) = bind_v6_or_skip(false) else {
        return;
    };

    let addr = l.local_addr();
    assert!(addr.is_ipv6());
    assert_ne!(addr.port(), 0);
    let listener = l.into_raw_fd();

    let mut d = PlatformDriver::new().expect("driver");
    let accept = d
        .submit(Op::Accept { fd: listener })
        .expect("submit accept");
    let _client = TcpStream::connect(addr).expect("std client connects over v6");
    let conn = drain_until(&mut d, accept)
        .result
        .expect("accept succeeded over v6") as RawFd;

    d.submit(Op::Close { fd: conn }).expect("close conn");
    d.submit(Op::Close { fd: listener })
        .expect("close listener");
}
