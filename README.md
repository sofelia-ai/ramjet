# ramjet

A completion-based networking runtime in Rust. Standard wire protocols, novel
engine underneath.

Named for the jet engine with no moving parts, which only works once it is
already going fast: no locks, no work-stealing, no atomics on the hot path.

```
Autobahn        517/517 cases, 0 failed — ws:// and wss://
vs uWebSockets  +52.5% throughput, 45% better p99   (64 B, real NIC)
vs uSockets     +18.4% throughput, 26% better p99   (500 conns, pipelined)
vs tokio        +22.2% throughput
100k conns      53 MB   (tokio needs 877 MB for plain TCP)
syscalls        ~1 per 1,000 requests
dependencies    libc
```

Full numbers, methodology, and the things that are *not* claimed:
[BENCHMARKS.md](BENCHMARKS.md). Interop proofs: [CONFORMANCE.md](CONFORMANCE.md).

## Status

The engine is real and measured. The **ergonomic layer is not written yet** —
today you drive the reactor directly, as the examples do. If you want a
`listen().await` API, this is not that library yet.

| Layer | State |
|---|---|
| Reactor — io_uring (Linux), kqueue (macOS/BSD) | working, fuzzed |
| Sockets — `ramjet::net`, options before bind | working |
| WebSocket — [`ramjet-ws`](ramjet-ws/), sans-io, zero deps | working, Autobahn 517/0 |
| TLS 1.3 — rustls, `wss://` | working (example) |
| Ergonomic server API | **not started** |
| Thread-per-core | example only, scaling unproven |
| HTTP/1.1 — [`ramjet-http`](ramjet-http/), sans-io, zero deps | codec working, fuzzed; servers are examples |
| QUIC | not started |

## Install

As a library:

```toml
[dependencies]
ramjet    = "0.1"      # the runtime (low-level: you drive the reactor)
ramjet-ws = "0.1"      # just the WebSocket codec — no deps, no I/O, standalone
```

Prebuilt binaries for Linux and macOS on x86_64 and arm64 are attached to each
[release](https://github.com/sofelia-ai/ramjet/releases), with `.sha256` files
beside them. There is no Windows build: the reactor has io_uring and kqueue
backends and no IOCP one, so Windows does not compile rather than merely
running slowly.

## Use it

An echo server, complete. This is the whole API surface you need:

```rust
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{IntoRawFd, RawFd};

use ramjet::net::Listener;
use ramjet::reactor::{Driver, Op, PlatformDriver};

// A completion carries back whatever `user` tag its submission had, so an op
// routes itself. Pack the kind and the fd into those 64 bits — no lookup table.
const ACCEPT: u64 = 0;
const READ: u64 = 1;
const WRITE: u64 = 2;

fn tag(kind: u64, fd: RawFd) -> u64 {
    (kind << 32) | (fd as u32 as u64)
}

fn main() -> io::Result<()> {
    let listener = Listener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 9000)))?;
    let lfd = listener.into_raw_fd();

    let mut d = PlatformDriver::new()?;
    d.submit_with(Op::Accept { fd: lfd }, tag(ACCEPT, lfd))?;

    let mut done = Vec::new();
    loop {
        d.wait(&mut done)?;              // blocks until something finishes
        if done.is_empty() {
            return Ok(());               // nothing in flight
        }

        for c in done.drain(..) {
            let kind = c.user >> 32;
            let fd = c.user as u32 as RawFd;

            match (kind, c.result) {
                (ACCEPT, Ok(conn)) => {
                    let conn = conn as RawFd;
                    d.submit_with(Op::Accept { fd: lfd }, tag(ACCEPT, lfd))?;
                    // Pooled: this connection owns no buffer while it waits.
                    d.submit_with(Op::ReadPooled { fd: conn }, tag(READ, conn))?;
                }
                (READ, Ok(n)) if n > 0 => {
                    // A pooled read returns its buffer trimmed to the bytes
                    // read, so `buf` *is* the data.
                    let buf = c.buf.expect("pooled read returns its buffer");
                    d.submit_with(Op::Write { fd, buf }, tag(WRITE, fd))?;
                }
                (WRITE, Ok(_)) => {
                    if let Some(buf) = c.buf {
                        d.recycle(buf);  // back to the pool
                    }
                    d.submit_with(Op::ReadPooled { fd }, tag(READ, fd))?;
                }
                _ => {
                    d.submit(Op::Close { fd })?;   // EOF or a dead peer
                }
            }
        }
    }
}
```

`nc 127.0.0.1 9000` will echo. That same loop shape drives the WebSocket and
TLS examples — only the handling of a completed read changes.

For WebSocket framing, [`ramjet-ws`](ramjet-ws/) is a separate crate with no
dependencies and no knowledge of this runtime; use it with tokio if you like.

## Run the examples

```sh
cargo run --release --example echo -- 9000     # TCP echo, loopback by default
cargo run --release --example echo -- 9003 192.0.2.10  # explicit bind IP
cargo run --release --example ws_echo 9001     # WebSocket echo
./scripts/gen-certs.sh                          # self-signed cert
cargo run --release --example wss_echo 9002    # WebSocket over TLS 1.3

cargo run --release --bin connect_bench -- 127.0.0.1:9000 --workers 16
cargo run --release --bin connect_bench -- 127.0.0.1:9000 --workers 16 --reset-close
cargo run --release --bin ws_bench      -- 127.0.0.1:9001 --conns 200 --pipeline 8
cargo run --release --bin ws_bench      -- 127.0.0.1:9001 --conns 1 --pipeline 256 --burst
```

The first connection-churn command keeps normal FIN-close semantics. The
`--reset-close` variant still verifies the complete echoed payload, then uses
RST so a same-host comparison measures the server rather than destination-port
`TIME_WAIT` history.

The WebSocket client also verifies every echoed payload byte. Its default
sliding mode keeps up to `--pipeline` frames in flight while writing them one
at a time. `--burst` writes a whole pipeline as one TCP batch and then drains
it, which is useful for measuring coalesced-frame/codec throughput without
making one client write syscall per frame.

For the measured Linux connection-churn configuration:

```sh
cargo build --profile release-lto --example echo
RAMJET_MULTISHOT_ACCEPT=1 RAMJET_DEFER_TASKRUN=1 \
    target/release-lto/examples/echo 9003 127.0.0.1
```

`RAMJET_MULTISHOT_ACCEPT=1` keeps one kernel accept request armed across
connections. It is feature-probed, falls back to ordinary accept if the kernel
cannot cancel the arm synchronously, bounds early accepted descriptors, and
closes driver-owned descriptors on cancellation and teardown.
`RAMJET_DEFER_TASKRUN=1` is more kernel-sensitive: run the fuzzer soak below on
the exact deployment kernel before enabling it. Both switches are Linux-only
opt-ins; neither changes the portable default.

Tests, including a state-machine fuzzer that has caught five real bugs:

```sh
cargo test --workspace
RAMJET_FUZZ_STEPS=2000 RAMJET_FUZZ_CASES=50 cargo test --test fuzz_driver --release
./scripts/linux.sh cargo test --workspace      # Linux/io_uring, in Docker
```

## How it works

Everything is submit-an-operation, harvest-a-completion — the io_uring mental
model, on every platform. One `Driver` trait, two backends:

```rust
let mut d = PlatformDriver::new()?;
d.submit(Op::Accept { fd: listener })?;

let mut done = Vec::new();
d.wait(&mut done)?;              // blocks until something finishes
for c in done.drain(..) {
    // c.id, c.result, c.buf, c.user
}
```

Four properties that produce the numbers above:

- **Completions, not readiness.** On Linux the kernel has already done the
  work when you hear about it. On macOS, kqueue reports readiness and the
  backend performs the syscall itself, so callers see the same shape.
- **Batching.** `submit` makes no syscall; `wait` flushes everything queued
  and harvests in one `io_uring_enter`. Under load that is ~1 syscall per
  1,000 requests.
- **Buffers by ownership.** Submit a `Vec`, get it back on completion. A
  parked pooled read owns *nothing* — the kernel picks a buffer only when
  bytes arrive, which is why 100k idle connections cost 516 B each.
- **Thread-per-core, share-nothing.** The driver is `!Send` by construction.

`Op::WriteFrom` lets a reply be written from inside the buffer the request
arrived in. The WebSocket echo fast path validates each complete frame and
unmasks it directly into its compacted reply position, so a batch needs no
second payload copy or output allocation.

## Security

- Memory-safe Rust. `unsafe` is confined to the reactor and documented at
  every call site with the argument for why it holds.
- **A seeded state-machine fuzzer** (`tests/fuzz_driver.rs`) runs in every
  `cargo test` and scales to soaks. It checks buffer conservation, completion
  conservation, fd hygiene, and per-connection stream integrity. It has caught
  five real bugs, including a cross-connection data disclosure and a kernel
  bug in `DEFER_TASKRUN`.
- TLS is rustls only. The WebSocket parsers are fuzzed, and conformance is
  proven by Autobahn rather than asserted.
- Failures are load-bearing: every rejected optimisation is written down in
  BENCHMARKS.md with its numbers, so nobody re-walks a dead end.

## Layout

```
src/reactor/    driver trait, io_uring + kqueue backends, slab, buffer pool
src/net.rs      listeners with options applied before bind
ramjet-ws/      sans-io WebSocket codec — no dependencies, no I/O, reusable
ramjet-http/    sans-io HTTP/1.1 server codec — no dependencies, no I/O, reusable
examples/       echo, ws_echo, wss_echo, http_hello, echo_mt, http_mt (thread-per-core)
bench/          competitor sources and build recipes, so results reproduce
```

`ramjet-ws` depends on nothing and knows nothing about this runtime. If you
only want an RFC 6455 codec, take it.

## License

MIT or Apache-2.0, at your option. Free and open source.
