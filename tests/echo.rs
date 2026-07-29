//! Round-trip tests against the echo example, driven by blocking std sockets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::IntoRawFd;
use std::thread;
use std::time::Duration;

// Test the shipped example itself rather than a copy of its loop; `main` is
// unused here, hence the allow.
#[allow(dead_code)]
mod echo {
    include!("../examples/echo.rs");
}

/// Bind an ephemeral port, serve it on a background thread, return the port.
/// Binding happens before the thread starts, so connect() can't lose a race.
fn start() -> u16 {
    // Server side is a ramjet socket; the clients below stay std::net on
    // purpose, so every test here doubles as an interop check.
    let l = ramjet::net::Listener::bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )))
    .expect("bind");
    let port = l.local_addr().port();
    let fd = l.into_raw_fd();
    thread::spawn(move || echo::serve(fd));
    port
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s
}

fn roundtrip(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).expect("write");
    let mut got = vec![0; msg.len()];
    s.read_exact(&mut got).expect("read");
    assert_eq!(got, msg);
}

#[test]
fn sequential_messages_on_one_connection() {
    let mut s = connect(start());
    for i in 0..16 {
        roundtrip(&mut s, format!("message {i}").as_bytes());
    }
    // A payload spanning many read buffers still comes back whole. Write from a
    // second thread: a single-threaded client would deadlock against its own
    // full receive buffer long before 256 KiB was sent.
    let big = vec![b'x'; 256 * 1024];
    let mut w = s.try_clone().expect("clone");
    let sent = big.clone();
    let writer = thread::spawn(move || w.write_all(&sent).expect("write big"));
    let mut got = vec![0; big.len()];
    s.read_exact(&mut got).expect("read big");
    writer.join().expect("writer thread");
    assert_eq!(got, big);
}

#[test]
fn concurrent_connections() {
    let port = start();
    let clients: Vec<_> = (0..8u8)
        .map(|i| {
            thread::spawn(move || {
                let mut s = connect(port);
                for round in 0..4 {
                    roundtrip(&mut s, &vec![i; 100 + round]);
                }
            })
        })
        .collect();
    for c in clients {
        c.join().expect("client thread");
    }
}

#[test]
fn immediate_disconnect_does_not_break_server() {
    let port = start();
    for _ in 0..4 {
        drop(connect(port));
    }
    let mut s = connect(port);
    roundtrip(&mut s, b"still alive");
}
