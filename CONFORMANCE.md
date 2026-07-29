# Conformance

Interop is proven by suites and real clients, not by prose.

## Autobahn testsuite — `ws://` and `wss://`

Suite: `crossbario/autobahn-testsuite` (`wstest -m fuzzingclient`), all 517
cases. Servers: `examples/ws_echo.rs` and `examples/wss_echo.rs`, both
single-threaded on the reactor, both using the `ramjet-ws` codec.

| Result | Cases | Meaning |
|---|---|---|
| OK | 296 | strict pass |
| NON-STRICT | 2 | 6.4.2 and 6.4.4 — a lenient variant the RFC permits |
| INFORMATIONAL | 3 | performance probes, not graded |
| UNIMPLEMENTED | 216 | permessage-deflate (§12–13); no extensions are offered, which is correct for a server that rejects RSV bits |
| **FAILED** | **0** | |

Close-frame behaviour: 514 OK, 3 informational.

**`wss://` scores identically, down to which two cases are non-strict.** That
equality is the point: it shows TLS and the WebSocket state machine compose,
rather than merely that a handshake succeeded. TLS is rustls 0.23, `ring`
provider, TLS 1.3 only; the suite runs with certificate validation off because
the cert is self-signed.

The receipt was re-earned after every change that touched the read or write
path — batch corking, the word-at-a-time unmask, and 64 KiB pooled buffers —
with identical counts each time.

Reproduce:

```sh
cargo run --release --example ws_echo 9001
docker run --rm --platform linux/amd64 \
  -v "$PWD/autobahn/config:/config:ro" -v "$PWD/autobahn/reports:/reports" \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -s /config/fuzzingclient.json
open autobahn/reports/index.html
```

Use `fuzzingclient-wss.json` against `wss_echo` for the TLS run, after
`./scripts/gen-certs.sh`. On Apple Silicon the amd64 image runs under Rosetta.

## Real browsers, over the real internet

Chrome on macOS against a server on an EC2 instance, across the public
internet. Not loopback, not a local shortcut — Chrome's own WebSocket and TLS
implementations.

| Case | `ws://` | `wss://` (TLS 1.3) |
|---|---|---|
| text, short | echo matches | echo matches |
| text, `héllo — 世界 🚀` | echo matches | echo matches |
| binary, 4 KiB `ArrayBuffer` | echo matches | echo matches |
| text, 200 KB — many frames, ~13 TLS records | echo matches | echo matches |
| close handshake | code 1000, clean | code 1000, clean |

**4/4 on both.** The TLS run negotiated `TLS_AES_256_GCM_SHA384`. Verified
encrypted rather than assumed: only the TLS server was listening on that port,
and plaintext HTTP to it fails. The self-signed certificate needed a manual
browser exception — a PKI fact, not a server one.

## What this covers

Autobahn exercises the protocol exhaustively: fragmentation, interleaved
control frames, close codes, and incremental UTF-8 validation with fail-fast
behaviour. The browser tests prove something Autobahn cannot — that a real
client's own implementation interoperates end to end over a real network.

Neither proves throughput. Round trips in the browser tests were 139–983 ms,
which is the internet, not the server; see [BENCHMARKS.md](BENCHMARKS.md).
