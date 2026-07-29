# Benchmarks

Every number here is measured, reproducible from [`bench/`](bench/), and
reported with what it does *not* prove. Rivals are their own stock echo
examples, single-threaded, compression off, `TCP_NODELAY` on.

## Throughput

| Workload | ramjet | rival | margin |
|---|---|---|---|
| WS 64 B, 200 conns, K8 — **two machines, real NIC** | **348,692** | uWebSockets 228,626 | **+52.5%**, p99 −45% |
| TCP 500 conns, K8 — loopback | **649,847** | uSockets 549,047 | +18.4%, p99 −26% |
| TCP 500 conns, K8 — loopback | **637,878** | tokio 521,797 | +22.2% |
| TCP 200 conns, lockstep — loopback | **124,379** | uSockets 113,094 | +10.0% |
| TCP 200 conns, lockstep — loopback | **123,988** | tokio 110,211 | +12.5% |

`K8` = 8 messages in flight per connection. Medians of alternating runs.

**Trust the first row most.** Client and server on separate hosts, a real NIC
in the path, verified server-bound (server core at 60% sys / 34% softirq / 0%
idle at only 31 MB/s). It also *reverses* the loopback result at the same
configuration, where uWebSockets led 733k to 389k — because loopback has no
network stack, so the per-message syscall cost that io_uring exists to remove
barely registers. Loopback systematically flatters epoll.

## Memory — 100,000 idle connections, accepted and held

| Server | total RSS | per connection |
|---|---|---|
| uSockets (TCP) | **9.8 MB** | **79 B** |
| ramjet (TCP) | 27.4 MB | 255 B |
| uWebSockets (WS) | 29.0 MB | 256 B |
| **ramjet (WS)** | **52.9 MB** | **516 B** |
| tokio (TCP) | 877.3 MB | 8,960 B |

Per-connection cost is stable between 10k and 100k for every server, which is
the check that these are real. ramjet holds 100k WebSocket connections in
53 MB where tokio needs 877 MB for plain TCP. uSockets keeps the crown — its
echo holds no per-connection buffer at all.

## Efficiency

| Property | Measurement |
|---|---|
| Syscalls under load | ~1 `io_uring_enter` per 900–1,100 requests |
| Cost of 100k idle connections to active throughput | none: 718,508 → 719,396 req/s |
| Idle server floor | 131 KB resident against a 2 MiB registered ring |
| Library dependencies | `libc` |

That third row is worth explaining: registering a provided-buffer ring hands
the kernel a descriptor array, not pinned pages, so ring buffers stay untouched
virtual memory until traffic faults them in.

## Conformance

| Check | Result |
|---|---|
| Autobahn, `ws://` | 517 cases, **0 failed** |
| Autobahn, `wss://` | 517 cases, **0 failed** — identical distribution |
| Chrome over the internet, `ws://` | 4/4, clean close |
| Chrome over the internet, `wss://` (TLS 1.3) | 4/4, clean close |
| Tests | 135 macOS, 134 Linux, fuzzer soaks clean on both backends |

Details in [CONFORMANCE.md](CONFORMANCE.md).

## Not claimed

- **4 KiB payloads on the two-machine rig** — network-bound there (29,303 req/s
  at 240 MB/s, server core 55% *iowait*, second core idle). Those comparisons
  stay on loopback, where they are at least engine-limited.
- **10k *active* connections** — the load generator is thread-per-connection
  and collapses first (9,546 req/s at p99 6.1 s). That is the client, not the
  server. Needs an event-driven generator.
- **Thread-per-core scaling** — `examples/echo_mt` works, but one box cannot
  prove it: client and server contend for the same cores.
- **uWebSockets under concurrent-accept load** — its process held 8 descriptors
  while the client reported 100k connections established, contradicting its own
  idle-matrix figure. Unexplained, so withheld.

## Rigs

**Loopback, one box.** Server pinned to core 0. Resolves large payloads;
flatters epoll; client and server share a machine.

**Two machines, same AZ, private VPC**, 289 µs p50 TCP RTT. Removes the
contention confound and puts a real NIC in the path. Server-bound at 64 B,
network-bound by 4 KiB on the instance sizes used.

Neither resolves everything. An instance with a real network allowance would
settle both at once. Build recipes and rig rules: [`bench/README.md`](bench/README.md).

## What shipped, and what was rejected

Five optimisations shipped. **Five were rejected on measurement, three before
any code was written.** Both lists are here because the rejections cost real
time and nobody should re-walk them.

**Shipped**

| Change | Effect |
|---|---|
| Multishot recv over a kernel buffer ring | 4,272 → 475 B per idle connection |
| 64 KiB buffers, 32-entry ring | +123% at 4 KiB payloads, *lower* idle memory |
| Word-at-a-time WebSocket unmask | +31.5% at 4 KiB |
| Slab op-tracking, `submit_with(user_data)`, zero-copy `WriteFrom` | hashing and per-message allocation off the hot path |
| Fairness: harvest completions even when work is ready | p99 10.3 ms → 2.1 ms at 1000 conns |

**Rejected**

| Hypothesis | Verdict |
|---|---|
| WebSocket write amplification | Did not exist — already 6.75 messages per write |
| Batch corking | ~1%, inside noise (kept anyway: strictly less work per message) |
| Eager inline `send` before the ring | **−50%** |
| `min_complete > 1` | Unbuilt: harvests already ~1,600 completions each |
| Buffer size classes with per-fd promotion | Unbuilt: two constants got the whole win at no memory cost |
| kTLS | Unbuilt: rustls consumes the connection when extracting keys |

Three deserve a sentence, because the reasoning generalises.

**Eager send** is the fast path that wins on kqueue and loses on io_uring —
same idea, opposite verdict, because the cost model inverts. Its completions
landed in the ready queue, so `wait()` stopped entering the kernel to harvest
and the read side re-armed three times as often. It removed a round trip and
destroyed a harvest.

**`min_complete`** was killed by a twenty-minute measurement instead of a day
of work. The ceiling for any fewer-syscalls lever is syscall *count* ×
per-crossing cost — never time spent *inside* the syscall, which also contains
your real I/O. Measured naively, 97% of CPU was "inside `io_uring_enter`" and
the lever looked essential; measured correctly its ceiling was 0.017%.

**kTLS** is blocked by an API rather than a number: every
`dangerous_extract_secrets` takes `self` by value, so taking the send keys
destroys the decryptor and forces RX offload too — and kTLS RX needs `recvmsg`
with control-message parsing on the hottest path in the system.

## Measurement rules this cost us

- **Verify the feature is engaged, not just that tests pass.** Multishot buffer
  rings were registered, tested, benchmarked, and *never switched on* for a
  whole round. There are counters and an engagement test now.
- **Verify the server is listening before believing a number.** One sweep
  benchmarked a stale process left on the port.
- **Alternate conditions within a run and report ranges.** These boxes drift —
  one went 610k → 222k on an identical config within a session.
- **Three reps is not a sample.** A comparison here flipped sign between three
  reps and five. Take reps until ranges separate, or call the cell unresolvable.
- **Read the whole report.** A four-second stall was visible only as
  `latency max: 4,003,579 µs` beside merely-mediocre throughput.
- **A round-trip test can pass against broken code.** Mask-then-unmask succeeds
  regardless of key phase, because XOR is self-inverse. Compare against a naive
  reference instead.
