# Reproducing the benchmarks

`BENCHMARKS.md` claims every number here is reproducible. These are the exact
competitor builds and rigs it was measured against, so that claim survives the
machines being gone.

The three sources beside this file are the competitor echo servers as
benchmarked, patched only for a port argument and to disable compression and
TLS — never for speed. Diff them against upstream before trusting a comparison.

## Competitors

**uSockets** (raw TCP, epoll on Linux / kqueue on macOS)

```sh
git clone --depth 1 https://github.com/uNetworking/uSockets
cp uSockets_echo_server.c uSockets/examples/echo_server.c
cd uSockets && make                      # default target: no SSL
gcc -O3 -DLIBUS_NO_SSL -std=c11 -Isrc -o uws-echo examples/echo_server.c uSockets.a
```

Upstream's example hardcodes `SSL = 1` with paths to a developer's own cert, so
it cannot run as shipped; the patch sets `SSL = 0` and takes the port from
`argv[1]`.

**uWebSockets** (WebSocket)

```sh
git clone --depth 1 --recursive https://github.com/uNetworking/uWebSockets
cp RamjetEchoServer.cpp uWebSockets/examples/
cd uWebSockets && make -C uSockets
g++ -O3 -std=c++20 -DLIBUS_NO_SSL -DUWS_NO_ZLIB -Isrc -IuSockets/src \
    examples/RamjetEchoServer.cpp uSockets/*.o -o uws-ws-echo
```

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

Neither rig resolves everything. An instance with a real network allowance
would settle both at once, and is what to reach for before trusting any single
headline number.

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
