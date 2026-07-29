// TLS-terminated WebSocket echo: rustls over the ramjet reactor.
// Usage: `wss_echo [PORT]`, default 9002. Needs `scripts/gen-certs.sh` first.
//
// The point of this example is what it does *not* contain: no driver change.
// rustls is sans-io in the same sense ramjet-ws is — it never touches a socket,
// it moves bytes between two buffers — so terminating TLS is a byte-plumbing
// job that fits behind the existing `Op::Read`/`Op::Write` contract untouched.
// Three layers, none of which knows about the others:
//
//   reactor  ciphertext in/out of the socket, and nothing else
//   rustls   ciphertext <-> plaintext
//   codec    plaintext <-> WebSocket events
//
// WHAT TLS COSTS: the zero-copy echo path is gone, and cannot be kept. In
// `ws_echo` a whole frame is unmasked in place and replied to out of the very
// buffer it arrived in, header written in front of the payload. That works
// because the bytes on the wire *are* the bytes of the message. Under TLS they
// are not: rustls must read plaintext out of its own buffer and write ciphertext
// into another, so there is a mandatory copy in each direction and nothing to be
// clever about. This file is the honest version — decode, encode, encrypt — and
// no attempt is made to contort it. kTLS is what gets the fast path back, by
// moving the crypto into the kernel so the plaintext path can stay in place;
// that is a separate piece of work and deliberately not attempted here.

use std::collections::HashMap;
use std::env;
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};
use std::sync::Arc;

use ramjet::net::Listener;
use ramjet::reactor::PlatformDriver;
use ramjet::reactor::{Driver, Op};
use ramjet_ws::{Decoder, Event, encode, handshake};
use rustls::{ServerConfig, ServerConnection};

/// Same ceiling as the plaintext example: above Autobahn's 16 MiB limit cases,
/// but still a ceiling.
const MAX_MESSAGE: usize = 32 * 1024 * 1024;

const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

// Routing by completion tag, as in ws_echo: op kind in the high bits, fd in the
// low 32, so dispatch costs no hashing.
const KIND_ACCEPT: u64 = 0;
const KIND_READ: u64 = 1;
const KIND_WRITE: u64 = 2;
const KIND_CLOSE: u64 = 3;

fn tag(kind: u64, fd: RawFd) -> u64 {
    (kind << 32) | u64::from(fd as u32)
}
fn tag_kind(user: u64) -> u64 {
    user >> 32
}
fn tag_fd(user: u64) -> RawFd {
    (user & 0xFFFF_FFFF) as u32 as RawFd
}

fn load_config() -> io::Result<Arc<ServerConfig>> {
    let cert_path = env::var("RAMJET_TLS_CERT").unwrap_or_else(|_| "certs/cert.pem".into());
    let key_path = env::var("RAMJET_TLS_KEY").unwrap_or_else(|_| "certs/key.pem".into());

    let certs = rustls_pemfile::certs(&mut io::BufReader::new(std::fs::File::open(&cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::other(format!("no certificates in {cert_path}")));
    }
    let key =
        rustls_pemfile::private_key(&mut io::BufReader::new(std::fs::File::open(&key_path)?))?
            .ok_or_else(|| io::Error::other(format!("no private key in {key_path}")))?;

    // The provider is named rather than left to a process default: which one is
    // installed then becomes a property of this file instead of of link order.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    Ok(Arc::new(config))
}

/// One client: a TLS session wrapped around the same WebSocket state machine the
/// plaintext example uses.
struct Conn {
    tls: ServerConnection,
    /// The upgrade request so far, in plaintext. `None` once it has succeeded.
    request: Option<Vec<u8>>,
    decoder: Decoder,
    /// Plaintext replies waiting to be handed to rustls.
    plain_out: Vec<u8>,
    /// Ciphertext waiting to go out on the socket. One `Write` per fd at a time,
    /// so this is where a burst coalesces.
    wire_out: Vec<u8>,
    writing: bool,
    close_when_flushed: bool,
    /// The conversation is over; anything else the peer says is not our problem.
    ignoring: bool,
}

impl Conn {
    fn new(config: &Arc<ServerConfig>) -> Result<Self, rustls::Error> {
        Ok(Conn {
            tls: ServerConnection::new(Arc::clone(config))?,
            request: Some(Vec::new()),
            decoder: Decoder::with_max_message(MAX_MESSAGE),
            plain_out: Vec::new(),
            wire_out: Vec::new(),
            writing: false,
            close_when_flushed: false,
            ignoring: false,
        })
    }

    /// Ciphertext off the socket, through TLS, into the WebSocket state machine,
    /// and back out as ciphertext. The whole adapter is this function.
    fn on_wire(&mut self, mut cipher: &[u8]) -> Result<(), rustls::Error> {
        // `read_tls` takes whatever fits in its internal buffer and no more, so
        // one call is not enough — a 64 KiB read is several TLS records and it
        // will hand them over in pieces. `&mut &[u8]` is an `io::Read` that
        // advances, which is the entire trick to using a sans-io TLS library
        // from a completion-based reactor: no socket, just a cursor.
        while !cipher.is_empty() {
            match self.tls.read_tls(&mut cipher) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // Reading from a slice cannot fail for any other reason.
                Err(e) => unreachable!("slice read failed: {e}"),
            }
            self.tls.process_new_packets()?;
            self.drain_plaintext();
        }
        // A handshake step can want to write without any plaintext moving, so
        // this runs whether or not the loop above produced anything.
        self.pump_tls();
        Ok(())
    }

    /// Everything rustls has decrypted, fed to the WebSocket layer.
    fn drain_plaintext(&mut self) {
        let mut scratch = [0u8; 16 * 1024];
        loop {
            match self.tls.reader().read(&mut scratch) {
                // Zero is a clean end of the plaintext stream; WouldBlock is
                // simply "nothing more decrypted yet". Neither is an error and
                // both mean stop.
                Ok(0) => return,
                // `scratch` is a local, so the borrow of `self.tls` ended when
                // `read` returned and the slice goes straight through.
                Ok(n) => self.on_plaintext(&scratch[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => return,
            }
        }
    }

    /// Hand the pending plaintext replies to rustls and collect the ciphertext.
    ///
    /// The interleaving is not decoration. rustls caps how much plaintext it will
    /// hold before you drain it, so `writer()` is free to accept less than it was
    /// offered — and a reply larger than that cap (a 64 KiB echo is, comfortably)
    /// gets a short write. `write_all` turns that into `WriteZero`, which is how
    /// the first version of this function silently dropped every large message
    /// while passing every small one. So: drain to make room, write what fits,
    /// repeat.
    fn pump_tls(&mut self) {
        let mut sent = 0;
        loop {
            // Drain first — emptying the plaintext buffer into ciphertext is
            // what creates room for the rest of the reply.
            while self.tls.wants_write() {
                // Writing into a Vec cannot fail.
                if self.tls.write_tls(&mut self.wire_out).is_err() {
                    break;
                }
            }
            if sent == self.plain_out.len() {
                break;
            }
            match self.tls.writer().write(&self.plain_out[sent..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => sent += n,
            }
        }
        self.plain_out.drain(..sent);
    }

    /// Plaintext bytes, in whichever phase this connection is in. Identical in
    /// shape to the plaintext example: the codec cannot tell it is behind TLS.
    fn on_plaintext(&mut self, bytes: &[u8]) {
        if self.ignoring {
            return;
        }
        if let Some(mut request) = self.request.take() {
            request.extend_from_slice(bytes);
            match handshake::upgrade(&request) {
                Ok(handshake::Upgrade::NeedMore) => self.request = Some(request),
                Ok(handshake::Upgrade::Accept { response, consumed }) => {
                    self.plain_out.extend_from_slice(&response);
                    // A client may pipeline frames behind the request. `request`
                    // stays taken, so this recurses no further.
                    let leftover = request[consumed..].to_vec();
                    self.on_frames(&leftover);
                }
                Err(_) => {
                    self.plain_out.extend_from_slice(BAD_REQUEST);
                    self.close_when_flushed = true;
                    self.ignoring = true;
                }
            }
            return;
        }
        self.on_frames(bytes);
    }

    fn on_frames(&mut self, bytes: &[u8]) {
        self.decoder.feed(bytes);
        loop {
            match self.decoder.next_event() {
                Ok(Some(event)) => {
                    if self.on_event(event) {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    // The codec's taxonomy already knows the code each failure
                    // earns: 1002 protocol, 1007 bad UTF-8, 1009 too large.
                    self.send_close(e.close_code());
                    return;
                }
            }
        }
    }

    /// Handle one event. Returns true when the conversation is finished.
    fn on_event(&mut self, event: Event) -> bool {
        match event {
            Event::Text(text) => encode::text(&mut self.plain_out, &text),
            Event::Binary(data) => encode::binary(&mut self.plain_out, &data),
            // The decoder has already enforced the 125-byte limit that is the
            // only way a pong could fail to encode.
            Event::Ping(payload) => {
                let _ = encode::pong(&mut self.plain_out, &payload);
            }
            // Unsolicited pongs are legal and mean nothing to an echo server.
            Event::Pong(_) => {}
            Event::Close(frame) => {
                self.send_close(frame.map_or(1000, |f| f.code));
                return true;
            }
        }
        false
    }

    fn send_close(&mut self, code: u16) {
        // An empty reason always fits inside a control frame.
        let _ = encode::close(&mut self.plain_out, code, "");
        self.close_when_flushed = true;
        self.ignoring = true;
    }
}

/// Submit whatever this connection has pending. Returns true once it has been
/// closed and should be forgotten.
fn pump(fd: RawFd, conn: &mut Conn, d: &mut PlatformDriver) -> io::Result<bool> {
    conn.pump_tls();
    if conn.writing {
        return Ok(false);
    }
    if !conn.wire_out.is_empty() {
        let buf = std::mem::take(&mut conn.wire_out);
        d.submit_with(Op::Write { fd, buf }, tag(KIND_WRITE, fd))?;
        conn.writing = true;
        return Ok(false);
    }
    if conn.close_when_flushed {
        d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
        return Ok(true);
    }
    Ok(false)
}

fn main() -> io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9002);
    let config = load_config()?;

    // 0.0.0.0, not loopback: the Autobahn client runs in a container and reaches
    // the host through a real interface address.
    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    println!(
        "ramjet wss_echo listening on 0.0.0.0:{}",
        listener.local_addr().port()
    );
    serve(listener.into_raw_fd(), config)
}

fn serve(listener: RawFd, config: Arc<ServerConfig>) -> io::Result<()> {
    let mut d = PlatformDriver::new()?;
    let mut conns: HashMap<RawFd, Conn> = HashMap::new();
    let mut done = Vec::new();

    d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;

    loop {
        d.wait(&mut done)?;
        if done.is_empty() {
            return Ok(()); // nothing in flight; waiting again would just spin
        }
        for c in done.drain(..) {
            match tag_kind(c.user) {
                KIND_ACCEPT => match c.result {
                    Ok(fd) => {
                        let fd = fd as RawFd;
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                        match Conn::new(&config) {
                            Ok(conn) => {
                                conns.insert(fd, conn);
                                d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                            }
                            // A session that will not start is this connection's
                            // problem, not the listener's.
                            Err(e) => {
                                eprintln!("tls session setup failed: {e}");
                                d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                            }
                        }
                    }
                    // The pending connection died before we took it, which says
                    // nothing about the listener. macOS reports this as EINVAL.
                    Err(ref e)
                        if matches!(
                            e.raw_os_error(),
                            Some(
                                libc::ECONNABORTED | libc::ECONNRESET | libc::EINVAL | libc::EINTR
                            )
                        ) =>
                    {
                        d.submit_with(Op::Accept { fd: listener }, tag(KIND_ACCEPT, listener))?;
                    }
                    // Anything else means the listener is unusable and will fail
                    // the same way forever: fail loudly, not in a spin.
                    Err(e) => return Err(e),
                },

                KIND_READ => {
                    let fd = tag_fd(c.user);
                    // A Close already retired this fd and cancelled the read.
                    if matches!(&c.result, Err(e) if e.raw_os_error() == Some(libc::ECANCELED)) {
                        continue;
                    }
                    let Some(conn) = conns.get_mut(&fd) else {
                        if let Some(buf) = c.buf {
                            d.recycle(buf);
                        }
                        continue;
                    };
                    match (c.result, c.buf) {
                        (Ok(n), Some(buf)) if n > 0 => {
                            let fatal = conn.on_wire(&buf).err();
                            d.recycle(buf);
                            if let Some(e) = fatal {
                                // A TLS error is terminal. rustls has already
                                // queued the alert describing it, so flush and
                                // go rather than dropping the socket silently.
                                eprintln!("tls error on fd {fd}: {e}");
                                conn.close_when_flushed = true;
                                conn.ignoring = true;
                            }
                            let wants_more = !conn.close_when_flushed;
                            if pump(fd, conn, &mut d)? {
                                conns.remove(&fd);
                            } else if wants_more {
                                d.submit_with(Op::ReadPooled { fd }, tag(KIND_READ, fd))?;
                            }
                        }
                        // EOF or a dead connection: hand back buffer and fd both.
                        (_, buf) => {
                            if let Some(buf) = buf {
                                d.recycle(buf);
                            }
                            conns.remove(&fd);
                            d.submit_with(Op::Close { fd }, tag(KIND_CLOSE, fd))?;
                        }
                    }
                }

                KIND_WRITE => {
                    let fd = tag_fd(c.user);
                    if let Some(buf) = c.buf {
                        d.recycle(buf);
                    }
                    let Some(conn) = conns.get_mut(&fd) else {
                        continue;
                    };
                    conn.writing = false;
                    if c.result.is_err() {
                        // The peer is gone; nothing left to say to it.
                        conn.wire_out.clear();
                        conn.plain_out.clear();
                        conn.close_when_flushed = true;
                        conn.ignoring = true;
                    }
                    if pump(fd, conn, &mut d)? {
                        conns.remove(&fd);
                    }
                }

                // A Close completion: the descriptor is already gone.
                _ => {}
            }
        }
    }
}
