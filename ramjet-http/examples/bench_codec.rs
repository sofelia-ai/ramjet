// Codec throughput in isolation: parse and encode in a tight loop, no I/O.
// Run with `cargo run -p ramjet-http --example bench_codec --release`.

use std::hint::black_box;
use std::time::Instant;

use ramjet_http::{Parse, ParseRef, encode, parse, parse_ref};

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..iters / 10 {
        f(); // warm-up
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = start.elapsed().as_nanos() as f64 / f64::from(iters);
    println!("{name:<40} {ns:>8.1} ns/op  {:>7.2} M ops/s", 1000.0 / ns);
}

fn main() {
    let small_get = b"GET /api/v1/items?page=2 HTTP/1.1\r\n\
        Host: example.com\r\n\
        User-Agent: bench/1.0\r\n\
        Accept: application/json\r\n\
        Accept-Encoding: gzip, br\r\n\
        Connection: keep-alive\r\n\r\n";

    let mut post_1k = b"POST /upload HTTP/1.1\r\n\
        Host: example.com\r\n\
        Content-Type: application/octet-stream\r\n\
        Content-Length: 1024\r\n\r\n"
        .to_vec();
    post_1k.extend_from_slice(&[0xAB; 1024]);

    // Sixteen small requests back to back, sliced through like the server does.
    let pipelined: Vec<u8> = small_get.repeat(16);

    bench("parse: small GET, 6 headers", 1_000_000, || {
        black_box(parse(black_box(small_get)).unwrap());
    });

    bench("parse_ref: small GET, 6 headers", 1_000_000, || {
        black_box(parse_ref(black_box(small_get)).unwrap());
    });

    bench("parse_ref: POST with 1 KiB body", 1_000_000, || {
        black_box(parse_ref(black_box(&post_1k)).unwrap());
    });

    bench("parse_ref: sweep of 16 pipelined GETs", 62_500, || {
        let mut from = 0;
        while let ParseRef::Request { consumed, request } =
            parse_ref(black_box(&pipelined[from..])).unwrap()
        {
            black_box(&request);
            from += consumed;
            if from == pipelined.len() {
                break;
            }
        }
        assert_eq!(from, pipelined.len());
    });

    bench("parse: POST with 1 KiB body", 1_000_000, || {
        black_box(parse(black_box(&post_1k)).unwrap());
    });

    bench("parse: sweep of 16 pipelined GETs", 62_500, || {
        let mut from = 0;
        while let Parse::Request { consumed, request } =
            parse(black_box(&pipelined[from..])).unwrap()
        {
            black_box(request);
            from += consumed;
            if from == pipelined.len() {
                break;
            }
        }
        assert_eq!(from, pipelined.len());
    });

    bench("encode: 200 with 2 headers, 12 B body", 1_000_000, || {
        let mut out = Vec::with_capacity(128);
        encode::response(
            black_box(&mut out),
            200,
            &[("Content-Type", "text/plain"), ("Connection", "keep-alive")],
            b"hello world\n",
        )
        .unwrap();
        black_box(out);
    });
}
