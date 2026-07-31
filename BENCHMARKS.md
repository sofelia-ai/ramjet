# Benchmarks

This document reports measured results, not universal performance claims.
Current comparisons come first; older results retained for project history are
explicitly labelled. Exact competitor builds and commands are in
[`bench/README.md`](bench/README.md), and protocol results are in
[`CONFORMANCE.md`](CONFORMANCE.md).

Unless stated otherwise, every client verifies the opcode, length, and every
echoed payload byte. Rivals use their single-threaded echo examples with
compression disabled and `TCP_NODELAY` enabled.

## Current C7i comparison

Measured on one EC2 `c7i.large` running Linux `7.0.0-1006-aws`. The server was
pinned to CPU 0 and the client to CPU 1. These logical CPUs are sibling
hyperthreads on one physical core, so the result is a controlled loopback
comparison, not independent-core or real-network scaling.

Ramjet used fat LTO with:

```text
RAMJET_MULTISHOT_ACCEPT=1 RAMJET_DEFER_TASKRUN=1
```

uWebSockets was pinned to
`fe7da4cb05622b8d004718ec3ca05101782eb1c2`, with uSockets submodule
`86097c490263ab662d62e8e7b541390bdec7d149`. The raw uSockets comparison used
`2353808c2e605c4f38bd9f09261fff13ae2a58be`. Both rivals were built with
`-O3 -flto`, without TLS or compression.

Each result is the median of five alternating three-second trials after
warm-up. The p99 column is Ramjet followed by its rival.

| Protocol and workload | Ramjet | Rival | Throughput result | Median p99 |
|---|---:|---:|---|---:|
| WebSocket, 64 B, one connection, 256-frame burst | **1,714,653/s** | uWebSockets 1,684,539/s | **Ramjet +1.79%** | **142.0** vs 144.9 µs |
| WebSocket, 4 KiB, one connection, 64-frame burst | 301,078/s | **uWebSockets 306,158/s** | **uWS +1.69%** | 133.0 vs **129.5 µs** |
| WebSocket, 64 B, 50 connections, lockstep | 197,131/s | uWebSockets 196,524/s | tied; ranges overlap | 452.2 vs **421.0 µs** |
| TCP lifecycle, 64 B, 4 workers | **61,794/s** | uSockets 59,108/s | **Ramjet +4.5%** | **123.7** vs 133.6 µs |
| TCP lifecycle, 64 B, 16 workers | **61,292/s** | uSockets 58,619/s | **Ramjet +4.6%** | **591.1** vs 645.6 µs |

### Reading the result

- The improved WebSocket server moved from 1,693,704/s to 1,714,653/s at
  64 B: **+1.24%**. Its five-trial range, 1,708,414–1,720,959/s, did not
  overlap the original server or uWebSockets.
- The 4 KiB change is neutral relative to the original Ramjet server, while
  uWebSockets retains a measurable 1.69% lead.
- At 50 lockstep connections, throughput is unresolved and uWebSockets has a
  7.4% better p99. Ramjet does not have a universal latency lead.
- `--burst` writes one complete pipeline as a TCP batch and then drains it. It
  removes the load generator's one-write-syscall-per-frame ceiling and measures
  coalesced-frame throughput; it is not a one-message latency test.
- The TCP lifecycle is connect → 64 B write → exact echo read → RST close.
  Reset-close prevents destination-port `TIME_WAIT` history from deciding a
  same-host connection benchmark.

## Stability and correctness

| Check | Result |
|---|---|
| Final WebSocket binary, 60-second soak | 12,261,617 verified echoes; 204,245/s; p99 421.1 µs; zero errors |
| WebSocket resource hygiene | descriptors 5 → 5; RSS 2,416 → 2,812 KiB; no cgroup throttling |
| Provided-buffer ownership | 12,259,882 consumed and 12,259,882 reclaimed |
| Final TCP lifecycle binary, 60-second soak | 3,414,977 verified lifecycles; zero errors and zero `TIME_WAIT` |
| Autobahn `ws://` | 517 cases; **0 failures and 0 bad closes** |
| Autobahn `wss://` | previous full run: 517 cases and **0 failures** |
| Codec release fuzzing | 10,000 configured cases passed |
| Workspace checks | tests passed; Clippy passed with warnings denied |

The WebSocket soak observed 142 transient provided-buffer `ENOBUFS` results.
Those are handled by re-arming receive; no bytes, connections, or buffers were
lost. The exact production-kernel driver fuzzer also passed with multishot
accept and deferred task running enabled. The tested final WebSocket server's
SHA-256 is
`4946a98583e2e51665eabd0cbe720a03bc0da0ada1e4b563634cded4b71538d7`.

## Historical reference results

These measurements predate the current C7i run and remain here because they
support headline comparisons elsewhere in the repository. They must not be
combined with current numbers: the hardware and load generators differ.

| Historical workload | Ramjet | Rival | Result |
|---|---:|---:|---|
| WebSocket, 64 B, 200 connections, K8, two machines and a real NIC | **348,692/s** | uWebSockets 228,626/s | **+52.5%**, p99 45% lower |
| TCP, 64 B, 500 connections, K8, loopback | **649,847/s** | uSockets 549,047/s | **+18.4%**, p99 26% lower |
| TCP, 64 B, 500 connections, K8, loopback | **637,878/s** | tokio 521,797/s | **+22.2%** |

`K8` means eight messages in flight per connection.

The two-machine WebSocket result was server-bound at 64 B: the server core was
fully occupied while traffic was only 31 MB/s. Its 4 KiB workload was
network-bound and is intentionally excluded.

A separate T2-to-C7i private-VPC TCP validation found overlapping ranges for
Ramjet and uSockets. The T2 CPU limited small messages and the path plateaued
near 2 Gbit/s for 4 KiB messages, so that run demonstrates interoperability and
stability, not an engine winner.

## Capacity measurements

These are historical 100,000-idle-connection measurements and were not rerun
for the latest codec change.

| Server | Total RSS | Per connection |
|---|---:|---:|
| uSockets, TCP | **9.8 MB** | **79 B** |
| Ramjet, TCP | 27.4 MB | 255 B |
| uWebSockets, WebSocket | 29.0 MB | 256 B |
| Ramjet, WebSocket | 52.9 MB | 516 B |
| tokio, TCP | 877.3 MB | 8,960 B |

| Property | Measurement |
|---|---|
| Syscalls under sustained load | approximately one `io_uring_enter` per 900–1,100 requests |
| Effect of 100,000 idle connections on active throughput | none measured: 718,508 → 719,396/s |
| Idle server floor | 131 KiB resident against a 2 MiB registered ring |
| Runtime library dependencies | `libc` |

## Optimization decisions

Only changes that survived repeated A/B measurements remain in the hot path.

| Change | Decision |
|---|---|
| Fuse frame validation, unmasking, and reply compaction | shipped; removes one payload pass |
| Use 16-byte unmasking for 32–512 B and 8-byte words above it | shipped; final 64 B result +1.24%, 4 KiB neutral |
| Persistent multishot accept with deterministic descriptor ownership | shipped; changed fresh-lifecycle result from 1.7–2.3% behind to 4.5% ahead |
| Dense descriptor-indexed WebSocket connection table | removed; 0.5–0.7% slower |
| Always use 16-byte unmasking | removed; approximately 2% slower at 4 KiB |
| Manually unroll large-message unmasking | removed; 1.2–2.5% slower |

## Limits

- Burst throughput and lockstep latency answer different questions; neither
  replaces the other.
- The uSockets result uses its normal epoll backend. It does **not** test
  uNetworking's separate experimental userspace
  [`tcp`](https://github.com/uNetworking/tcp) stack.
- Thread-per-core scaling and 10,000 simultaneously active connections have not
  been demonstrated with a load generator that stays out of the way.
- Large-message performance is not a Ramjet win on the current rig.

Before making a production-wide performance claim, repeat the current matrix
between two adequately provisioned machines over their private network.

## Reproduce

Pinned revisions, build flags, CPU placement, benchmark commands, and the rules
for alternating trials are in [`bench/README.md`](bench/README.md).
