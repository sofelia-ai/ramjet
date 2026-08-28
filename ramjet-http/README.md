# ramjet-http

Sans-io HTTP/1.1 server codec: request parser and response encoder. No
runtime, no I/O, no dependencies — the HTTP sibling of
[`ramjet-ws`](../ramjet-ws).

`parse` takes whatever bytes you have read so far and either asks for more or
hands back a complete `Request` plus the byte count it consumed, so pipelined
requests fall out of a slice-and-repeat loop. `encode::response` appends a
validated, completely framed response to a `Vec<u8>` you write however you
like. It returns an error without modifying the buffer if a header or status is
unsafe.

```rust
use ramjet_http::{Parse, parse, encode};

let wire = b"GET /hello HTTP/1.1\r\nHost: example\r\n\r\n";
let Parse::Request { request, consumed } = parse(wire).unwrap() else {
    panic!("request was complete");
};

let mut out = Vec::new();
encode::response(&mut out, 200, &[("Content-Type", "text/plain")], b"hi").unwrap();
```

For a socket loop that repeatedly appends to the same partial request, keep one
`usize` per connection and call `parse_ref_from(bytes, &mut scanned)`. It resumes
the `\r\n\r\n` search instead of rescanning the full buffer after every read.

## Scope

Server half of plain HTTP/1.1. Bodies are framed by `Content-Length` only;
`Transfer-Encoding` is rejected with a 501-mapped error rather than guessed
at. Clients, HTTP/2, and TLS are out of scope.

## License

MIT OR Apache-2.0, same as the rest of the repository.
