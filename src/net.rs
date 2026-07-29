//! Socket birth, owned by ramjet.
//!
//! `std::net::TcpListener::bind` creates, binds and listens in a single call,
//! which leaves no moment in which to set a socket option. That is fatal for
//! `SO_REUSEPORT`, which only has an effect if it is set *before* `bind(2)`, so
//! ramjet opens its own sockets.
//!
//! # What SO_REUSEPORT actually buys you, per platform
//!
//! The name means two different things, and only one of them is load balancing:
//!
//! - **Linux** (`SO_REUSEPORT`) and **FreeBSD** (`SO_REUSEPORT_LB`) fan incoming
//!   connections out across every socket bound to the address. That is the
//!   kernel-side half of thread-per-core accept.
//! - **macOS** has the original BSD semantics only: several sockets may bind the
//!   same address, but the **last** binder receives **all** connections. There
//!   is no fan-out. Measured, not assumed — three listeners, thirty connections,
//!   distribution `[0, 0, 30]` — and `tests/net.rs` pins it so we hear about it
//!   if Apple ever changes their mind.
//!
//! So on macOS this option does not give you thread-per-core accept. Getting
//! that here needs one acceptor distributing accepted fds to the reactors in
//! userspace. What the option does provide everywhere is rebinding an address
//! without first dropping the socket holding it.
//!
//! Only the socket *calls* are ours. Addresses stay `std::net` types, and the
//! descriptors handed out here are ordinary fds that interoperate with anything
//! else on the system.
//!
//! The build order is the entire point of the module:
//! `socket(2)` → every option → `bind(2)` → `listen(2)` → `O_NONBLOCK`.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// FreeBSD splits the two behaviours across two options: plain `SO_REUSEPORT`
/// shares the address, `SO_REUSEPORT_LB` also load-balances across the binders.
/// On Linux the one name does both, and on macOS it does only the first.
#[cfg(target_os = "freebsd")]
const REUSEPORT: libc::c_int = libc::SO_REUSEPORT_LB;
#[cfg(not(target_os = "freebsd"))]
const REUSEPORT: libc::c_int = libc::SO_REUSEPORT;

/// A bound, listening, non-blocking TCP socket.
///
/// Ready to hand to a [`Driver`](crate::reactor::Driver) as
/// [`Op::Accept`](crate::reactor::Op::Accept).
pub struct Listener {
    fd: OwnedFd,
    local: SocketAddr,
}

impl Listener {
    /// Bind with sane defaults: `SO_REUSEADDR`, backlog 1024 (kernel-clamped),
    /// no `SO_REUSEPORT`.
    pub fn bind(addr: SocketAddr) -> io::Result<Listener> {
        Listener::builder(addr).build()
    }

    /// Configure every option that has to be set before `bind(2)`.
    pub fn builder(addr: SocketAddr) -> ListenerBuilder {
        ListenerBuilder {
            addr,
            reuseaddr: true,
            reuseport: false,
            backlog: 1024,
            only_v6: false,
        }
    }

    /// The address actually bound, which is how you learn the port the kernel
    /// picked for a request with port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Listener {
    /// Give up ownership of the descriptor: closing it becomes the caller's job.
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

/// Builder for a [`Listener`]. Every option here is one that must reach the
/// socket before `bind(2)` to have any effect.
pub struct ListenerBuilder {
    addr: SocketAddr,
    reuseaddr: bool,
    reuseport: bool,
    backlog: i32,
    only_v6: bool,
}

impl ListenerBuilder {
    /// Allow several sockets to bind this exact address.
    ///
    /// **What that gets you depends on the platform.** On Linux, and on FreeBSD
    /// through `SO_REUSEPORT_LB`, the kernel distributes incoming connections
    /// across the binders — the basis of thread-per-core accept. On macOS it
    /// does not: binding succeeds, but the **last** socket to bind receives
    /// **every** connection and the earlier ones are starved. See the module
    /// docs.
    ///
    /// **Security.** BSD and macOS apply no credential check here, so *any*
    /// local process may bind an address you are already listening on and, given
    /// the last-binder-wins rule above, quietly take all of your traffic. On a
    /// multi-tenant or otherwise untrusted host, bind a concrete interface
    /// rather than a wildcard address and treat this option as something you opt
    /// into deliberately. `SO_REUSEPORT_LB` closes none of that gap either: it
    /// changes who receives the connections, not who is allowed to ask.
    pub fn reuseport(mut self, on: bool) -> Self {
        self.reuseport = on;
        self
    }

    /// Skip the `TIME_WAIT` wait on rebind. On by default.
    pub fn reuseaddr(mut self, on: bool) -> Self {
        self.reuseaddr = on;
        self
    }

    /// Pending-connection queue depth handed to `listen(2)`. Default 1024.
    ///
    /// The kernel clamps this to `kern.ipc.somaxconn`, 128 by default on macOS,
    /// so a larger number is a request rather than a guarantee. Negative values
    /// are treated as 0.
    pub fn backlog(mut self, n: i32) -> Self {
        self.backlog = n;
        self
    }

    /// For a v6 address, refuse v4-mapped clients.
    ///
    /// Off by default, in which case a **wildcard** v6 listener (`[::]`) also
    /// accepts v4 clients, through v4-mapped addresses. A listener bound to a
    /// specific v6 address such as `[::1]` serves only v6 either way, since no
    /// v4 traffic can reach that address to begin with. Ignored for v4
    /// addresses.
    pub fn only_v6(mut self, on: bool) -> Self {
        self.only_v6 = on;
        self
    }

    pub fn build(self) -> io::Result<Listener> {
        let domain = match self.addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        // SAFETY: socket() takes three scalars and returns a fresh fd or -1.
        let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket() just minted `raw` and nothing else owns it. Handing it
        // to OwnedFd now is what closes it on every `?` below.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        set_cloexec(raw)?;
        set_flag(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, self.reuseaddr)?;
        set_flag(raw, libc::SOL_SOCKET, REUSEPORT, self.reuseport)?;
        if matches!(self.addr, SocketAddr::V6(_)) {
            set_flag(raw, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, self.only_v6)?;
        }

        bind_to(raw, self.addr)?;
        // SAFETY: `raw` is a bound socket of ours; listen touches no memory.
        if unsafe { libc::listen(raw, self.backlog.max(0)) } < 0 {
            return Err(io::Error::last_os_error());
        }
        set_nonblocking(raw)?;

        // Ask the kernel rather than echoing back `self.addr`: with port 0 the
        // requested address is not the one we got.
        let local = getsockname(raw)?;
        Ok(Listener { fd, local })
    }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // macOS `socket(2)` has no SOCK_CLOEXEC, unlike Linux, so the descriptor is
    // briefly inheritable and this second call is what closes that window.
    // Writing the whole flag word is fine: FD_CLOEXEC is the only
    // file-descriptor flag there is, so nothing can be clobbered.
    // SAFETY: F_SETFD takes an int by value and touches no memory of ours.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL reads the flag word and touches no memory of ours.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same, with the flag word we just read plus O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_flag(fd: RawFd, level: libc::c_int, name: libc::c_int, on: bool) -> io::Result<()> {
    let v: libc::c_int = on.into();
    // SAFETY: `v` is a live c_int and we pass exactly its size as optlen.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const v).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_to(fd: RawFd, addr: SocketAddr) -> io::Result<()> {
    let r = match addr {
        SocketAddr::V4(v4) => {
            let sa = sockaddr_v4(&v4);
            // SAFETY: `sa` is a fully initialised sockaddr_in; we pass its exact
            // size, so bind reads only bytes we own.
            unsafe {
                libc::bind(
                    fd,
                    (&raw const sa).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sa = sockaddr_v6(&v6);
            // SAFETY: same, for a fully initialised sockaddr_in6.
            unsafe {
                libc::bind(
                    fd,
                    (&raw const sa).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sockaddr_v4(a: &SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain-old-data; all-zero is a valid starting value
    // and every field that matters is set below.
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    // The BSDs carry a length byte in every sockaddr; Linux has no such field.
    // Setting it is optional even where it exists — bind(2) is told the length
    // separately — but it costs nothing and keeps the struct well-formed.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = a.port().to_be();
    // `octets()` is already in network order, so reading it back as a native
    // u32 reproduces exactly the byte pattern `s_addr` wants.
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(a.ip().octets()),
    };
    sa
}

fn sockaddr_v6(a: &SocketAddrV6) -> libc::sockaddr_in6 {
    // SAFETY: as above — plain-old-data, zeroed then filled in.
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
    }
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_port = a.port().to_be();
    sa.sin6_flowinfo = a.flowinfo();
    sa.sin6_addr = libc::in6_addr {
        s6_addr: a.ip().octets(),
    };
    sa.sin6_scope_id = a.scope_id();
    sa
}

fn getsockname(fd: RawFd) -> io::Result<SocketAddr> {
    // SAFETY: sockaddr_storage is plain-old-data and exists precisely to be a
    // buffer of this shape.
    let mut ss: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `ss` and `len` are live; getsockname writes at most `len` bytes
    // into `ss` and updates `len` to what it actually used. Ignoring that
    // returned length afterwards is sound only because `ss` started fully
    // zeroed: any field of the variant we read that the kernel chose not to
    // write is a zero, never uninitialised memory.
    let r = unsafe { libc::getsockname(fd, (&raw mut ss).cast(), &raw mut len) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    from_sockaddr(&ss)
}

fn from_sockaddr(ss: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match libc::c_int::from(ss.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family field says this storage holds a sockaddr_in,
            // and sockaddr_storage is sized and aligned to hold one.
            let sa = unsafe { &*(&raw const *ss).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sa.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: as above, for a sockaddr_in6.
            let sa = unsafe { &*(&raw const *ss).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sa.sin6_addr.s6_addr),
                u16::from_be(sa.sin6_port),
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socket bound to address family {other}, which ramjet does not handle"),
        )),
    }
}
