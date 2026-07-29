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
| HTTP/1.1, QUIC | not started |

## Try it

```sh
cargo run --release --example echo 9000        # TCP echo
cargo run --release --example ws_echo 9001     # WebSocket echo
./scripts/gen-certs.sh                          # self-signed cert
cargo run --release --example wss_echo 9002    # WebSocket over TLS 1.3

cargo run --release --bin bench    -- 127.0.0.1:9000 --conns 200 --pipeline 8
cargo run --release --bin ws_bench -- 127.0.0.1:9001 --conns 200 --pipeline 8
```

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
arrived in, so echoing a WebSocket frame copies and allocates nothing.

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
examples/       echo, ws_echo, wss_echo, echo_mt (thread-per-core)
bench/          competitor sources and build recipes, so results reproduce
```

`ramjet-ws` depends on nothing and knows nothing about this runtime. If you
only want an RFC 6455 codec, take it.

## License

MIT or Apache-2.0, at your option. Free and open source.
