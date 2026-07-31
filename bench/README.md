# Reproducing the benchmarks

`BENCHMARKS.md` claims every number here is reproducible. These are the exact
competitor builds and rigs it was measured against, so that claim survives the
machines being gone.

The three sources beside this file are the competitor benchmark harnesses.
Protocol normalization is documented below; diff them against the pinned
upstream revision before trusting a comparison.

## Competitors

**uSockets** (raw TCP, epoll on Linux / kqueue on macOS)

```sh
git clone https://github.com/uNetworking/uSockets
git -C uSockets checkout 2353808c2e605c4f38bd9f09261fff13ae2a58be
cp uSockets_echo_server.c uSockets/examples/echo_server.c
cd uSockets && make                      # default target: no SSL
gcc -O3 -flto -DLIBUS_NO_SSL -std=c11 -Isrc \
    -o uws-echo examples/echo_server.c uSockets.a
./uws-echo 9004 172.31.45.118             # port, then bind IP
```

That revision is the tested upstream head from 2026-06-04. Its default Linux
build is epoll with `-O3`, LTO, `LIBUS_NO_SSL`, and `TCP_NODELAY` on accepted
sockets. The stock example nevertheless hardcodes `SSL = 1` with local
certificate paths, prints every connection and payload, and updates an idle
timer on every packet. The harness disables TLS, removes those hot-path logs
and timer updates, binds loopback, and takes the port from `argv[1]`; it keeps
uSockets' normal write and backpressure path.

The separate [`uNetworking/tcp`](https://github.com/uNetworking/tcp) repository
is an experimental userspace TCP implementation, not uSockets' default Linux
backend. Its own setup disables kernel-generated RST packets with an iptables
rule. It was neither enabled in the uSockets comparison nor treated as a
production baseline here.

**uWebSockets** (WebSocket)

```sh
git clone https://github.com/uNetworking/uWebSockets
git -C uWebSockets checkout fe7da4cb05622b8d004718ec3ca05101782eb1c2
git -C uWebSockets submodule update --init --recursive
cp RamjetEchoServer.cpp uWebSockets/examples/
cd uWebSockets && make -C uSockets
g++ -O3 -flto -std=c++20 -DLIBUS_NO_SSL -DUWS_NO_ZLIB -Isrc -IuSockets/src \
    examples/RamjetEchoServer.cpp uSockets/*.o -o uws-ws-echo
```

That is uWebSockets head `fe7da4cb05622b8d004718ec3ca05101782eb1c2`
from 2026-07-31 and uSockets submodule
`86097c490263ab662d62e8e7b541390bdec7d149`. Pinning both matters: a recursive
clone at a later date does not reproduce this comparison.
`-DUWS_NO_ZLIB` compiles permessage-deflate out entirely rather than merely
declining it at negotiation — the stronger form of "compression off", and it
matters because upstream's example enables compression by default, which would
have skewed every WebSocket comparison silently.

**tokio** — `tokio_echo_main.rs`, `current_thread` flavour, `cargo build --release`.

**node** — `net.createServer(s => s.pipe(s))` with `perMessageDeflate: false`
for the `ws` variant. **go** — goroutine-per-connection `io.Copy`, run with
`GOMAXPROCS=1`, `EnableCompression=false` for gorilla.

All servers single-threaded, `TCP_NODELAY` on accepted sockets, compression off.

## Rigs, and what each can actually measure

**Loopback, one box.** Server pinned to core 0, client to the rest. Resolves
large payloads, but client and server share a machine and there is no real
network stack — which systematically flatters epoll, since the per-message
syscall cost that io_uring removes barely registers. Every number that is not
labelled two-machine came from here.

**Two machines, same AZ, private VPC.** Server on a small instance pinned to
core 0, load generator on a larger one. 289 µs p50 TCP RTT. Removes the
contention confound and puts a real NIC in the path. On EC2 t2 hardware it is
server-bound at 64 B and **network**-bound by 4 KiB (240 MB/s, server core at
55% iowait), so only small payloads are comparable there.

**Cross-AZ validation.** A `t2.medium` client in `us-east-1d` drove a
`c7i.large` server in `us-east-1b` over private VPC addresses. Lockstep p50 was
about 0.83 ms. The T2 saturated first at 64 B and the path plateaued near
2 Gbit/s at 4 KiB, while the server stayed below 21% of one core. This proves
real-network stability and interoperability, but cannot rank the engines'
maximum throughput.

Neither rig resolves everything. An instance with a real network allowance
would settle both at once, and is what to reach for before trusting any single
headline number.

For the measured Linux connection-churn fast path, build both sides with LTO,
pin the server and client to separate logical CPUs, and use the reset-close
client:

```sh
cargo build --profile release-lto --example echo
cargo build --release --bin connect_bench

taskset -c 0 env RAMJET_MULTISHOT_ACCEPT=1 RAMJET_DEFER_TASKRUN=1 \
    target/release-lto/examples/echo 9003 127.0.0.1

taskset -c 1 target/release/connect_bench \
    127.0.0.1:9003 --workers 4 --size 64 --secs 3 --reset-close
```

The flag verifies the echoed payload exactly as normal, then closes with RST.
This prevents FIN ownership and destination-port `TIME_WAIT` history from
deciding the result. Keep the default FIN close when lifecycle semantics, not
the server's accept/read/write path, are what you intend to measure.

`RAMJET_MULTISHOT_ACCEPT` is feature-probed and falls back to ordinary accept
when deterministic synchronous cancellation is unavailable.
`RAMJET_DEFER_TASKRUN` is deliberately not assumed safe across kernels; run the
long driver fuzzer on the exact production kernel before enabling it. The final
C7i validation used:

```sh
RAMJET_MULTISHOT_ACCEPT=1 RAMJET_DEFER_TASKRUN=1 \
RAMJET_FUZZ_CASES=400 RAMJET_FUZZ_STEPS=2000 \
    cargo test --test fuzz_driver --release
```

For the current WebSocket codec comparison, build Ramjet with the same LTO
class, pin both processes, and use the exact-byte-verifying client:

```sh
cargo build --profile release-lto --example ws_echo
cargo build --release --bin ws_bench

taskset -c 0 env RAMJET_MULTISHOT_ACCEPT=1 RAMJET_DEFER_TASKRUN=1 \
    target/release-lto/examples/ws_echo 9003

# Small coalesced-frame/codec throughput:
taskset -c 1 target/release/ws_bench \
    127.0.0.1:9003 --conns 1 --size 64 --secs 3 --pipeline 256 --burst

# Ordinary one-message-at-a-time behavior:
taskset -c 1 target/release/ws_bench \
    127.0.0.1:9003 --conns 50 --size 64 --secs 3 --pipeline 1
```

`--burst` packs a pipeline into one client TCP write and drains all corresponding
echoes. It removes the load generator's one-write-syscall-per-frame ceiling and
measures coalesced-frame throughput; it is not a substitute for the lockstep
latency run. Both modes verify the opcode, length, and every payload byte.
Alternate Ramjet and uWebSockets within one run, warm each condition first, and
take at least five trials.

For a two-machine test, `ws_echo` already listens on all interfaces; point the
client at the server's private address and allow that client in the server
security group. On the latest C7i, `172.31.32.110`, ports 9003/9004 still
dropped SYNs from the same-AZ client `172.31.45.118`; no real-NIC number from
that pair is reported.

## Rules that were learned the hard way

- **Verify the server is listening before believing a number.** A silent bind
  failure reads as a bad result. One sweep here quietly benchmarked a stale
  leftover process on the port.
- **Verify the configuration under test actually took effect.** A sweep once
  ran 24 identical configs because `set -- $cfg` does not word-split in zsh,
  and a feature once benchmarked as "no improvement" because it had never been
  switched on.
- **Alternate conditions within a run and report ranges.** These boxes drift —
  one went from 610k to 222k req/s on an identical config over a session. Only
  same-run ratios survive that.
- **Three reps is not a sample.** A 64 B comparison here flipped sign between
  three reps and five. Take reps until the per-condition ranges separate, or
  report the cell as unresolvable.
- **`pkill -f <name>` matches your own command line** over SSH and kills the
  session; use `pkill -x`. Background jobs need `setsid` to survive the SSH
  exit.
- **Read the whole report, not just `req/s`.** A stall was visible only as
  `latency max: 4,003,579 µs` beside a merely-mediocre throughput figure.
