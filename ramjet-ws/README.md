# ramjet-ws

A sans-io WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) codec.
Bytes in, frames out. **No dependencies, no I/O, no runtime** — it never touches
a socket, so it works with tokio, with threads, with io_uring, or with a test
harness feeding it byte slices.

```toml
[dependencies]
ramjet-ws = "0.1"
```

**Autobahn testsuite: 517 cases, 0 failures** — the same bar uWebSockets holds.
Fragmentation, interleaved control frames, close-code validation, and
incremental UTF-8 with fail-fast rejection are all exercised there.

## Use

```rust
use ramjet_ws::{Decoder, Event, encode};

let mut decoder = Decoder::new();
decoder.feed(&bytes_from_socket);

while let Some(event) = decoder.next_event()? {
    match event {
        Event::Text(s)   => { /* a complete text message */ }
        Event::Binary(b) => { /* a complete binary message */ }
        Event::Ping(p)   => { let mut out = Vec::new(); encode::pong(&mut out, &p); }
        Event::Close { code, .. } => { /* peer is closing */ }
        _ => {}
    }
}
```

Split your input anywhere — across frames, across headers, mid-UTF-8 — and the
decoder produces identical output. That property is fuzz-tested, because it is
the whole point of sans-io.

## Notes

- **Server role.** Client frames must be masked (as the RFC requires) and are
  unmasked in place, word-at-a-time. Replies are written unmasked.
- **In-buffer echo is available.** `take_frame_at` hands back a payload's
  position inside the buffer you fed. For a pipelined echo server,
  `take_echo_frame_at` validates a complete frame, unmasks its payload directly
  into the compacted reply position, and returns a ready-to-write server frame.
  That fuses XOR and the overlapping move into one payload pass, with no second
  allocation.
- **The handshake is included** — request parsing and the `Sec-WebSocket-Accept`
  response, with SHA-1 and base64 implemented inline. SHA-1 is what RFC 6455
  mandates for this handshake; it is not used as a security primitive.
- **Bounded by construction.** Maximum message size is configurable and
  enforced, so a hostile peer cannot make you allocate without limit.
- **No extensions.** `permessage-deflate` is not offered and RSV bits are
  rejected, which is why 216 Autobahn cases report as unimplemented rather than
  failed.

## Why it exists

It is the WebSocket layer of [ramjet](https://github.com/sofelia-ai/ramjet), a
completion-based networking runtime — but it depends on nothing from it. If you
only want a correct, fast, dependency-free RFC 6455 codec, take this and ignore
the rest.

## License

MIT or Apache-2.0, at your option.
