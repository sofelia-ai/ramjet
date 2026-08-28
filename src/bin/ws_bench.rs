//! std-only WebSocket echo benchmark client.
//!
//! One thread is used per connection, with a barrier so the clock starts only
//! once every connection is up. Each worker then keeps up to `--pipeline`
//! frames in flight until the deadline and drains anything still outstanding
//! afterward. The wire protocol is an RFC 6455 upgrade followed by masked
//! binary frames.
//!
//! Framing is hand-rolled here rather than taken from `ramjet-ws`. A `src/bin`
//! target compiles against `[dependencies]`, and the codec is deliberately only
//! a `[dev-dependencies]` entry so the library stays decoupled from it; pulling
//! it in for this would drag it into every normal build. Eighty lines of
//! framing is the cheaper trade and keeps the tool std-only.
//!
//! Usage: `ws_bench <addr> [--conns N] [--size BYTES] [--secs S] [--pipeline K] [--burst]`

use std::collections::VecDeque;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// A fixed key, so the expected `Sec-WebSocket-Accept` is the constant below
/// rather than something this tool has to hash. Real clients send a fresh
/// random key; nothing about the benchmark depends on that.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// `base64(SHA-1(KEY ++ 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))` — the worked
/// example from RFC 6455 §1.3. Checking it costs one string comparison and
/// catches a server that accepts the upgrade without doing the hash.
const EXPECT_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

const OP_BINARY: u8 = 0x2;

struct Config {
    addr: String,
    conns: usize,
    size: usize,
    secs: u64,
    pipeline: usize,
    burst: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            addr: "127.0.0.1:9001".to_string(),
            conns: 50,
            size: 64,
            secs: 10,
            pipeline: 1,
            burst: false,
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: ws_bench <addr> [--conns N] [--size BYTES] [--secs S] [--pipeline K] [--burst]"
    );
    eprintln!();
    eprintln!("  addr           target address (default 127.0.0.1:9001)");
    eprintln!("  --conns N      number of concurrent connections (default 50)");
    eprintln!("  --size BYTES   payload size in bytes (default 64)");
    eprintln!("  --secs S       duration in seconds (default 10)");
    eprintln!("  --pipeline K   frames kept in flight per connection (default 1)");
    eprintln!("  --burst        write each pipeline as one batch, then drain it");
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut addr_set = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--conns" => {
                let v = args.next().ok_or("--conns requires a value")?;
                cfg.conns = v
                    .parse()
                    .map_err(|_| format!("invalid --conns value: {v}"))?;
            }
            "--size" => {
                let v = args.next().ok_or("--size requires a value")?;
                cfg.size = v
                    .parse()
                    .map_err(|_| format!("invalid --size value: {v}"))?;
            }
            "--secs" => {
                let v = args.next().ok_or("--secs requires a value")?;
                cfg.secs = v
                    .parse()
                    .map_err(|_| format!("invalid --secs value: {v}"))?;
            }
            "--pipeline" => {
                let v = args.next().ok_or("--pipeline requires a value")?;
                cfg.pipeline = v
                    .parse()
                    .map_err(|_| format!("invalid --pipeline value: {v}"))?;
            }
            "--burst" => cfg.burst = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other if !addr_set && !other.starts_with('-') => {
                cfg.addr = other.to_string();
                addr_set = true;
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    if cfg.conns == 0 {
        return Err("--conns must be >= 1".to_string());
    }
    if cfg.size == 0 {
        return Err("--size must be >= 1".to_string());
    }
    if cfg.secs == 0 {
        return Err("--secs must be >= 1".to_string());
    }
    if cfg.pipeline == 0 {
        return Err("--pipeline must be >= 1".to_string());
    }

    Ok(cfg)
}

/// A connection, plus whatever was read past the end of the upgrade response.
///
/// The server cannot speak before it is spoken to here, so the spare buffer is
/// almost always empty — but a server that pipelines would otherwise have its
/// first frame silently eaten by the handshake read.
struct Ws {
    stream: TcpStream,
    spare: Vec<u8>,
}

impl Ws {
    /// Fill `out` completely, drawing on the spare bytes before the socket.
    fn read_exact(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        let take = self.spare.len().min(out.len());
        if take > 0 {
            out[..take].copy_from_slice(&self.spare[..take]);
            self.spare.drain(..take);
        }
        if take < out.len() {
            self.stream.read_exact(&mut out[take..])?;
        }
        Ok(())
    }

    /// Send the upgrade request and check the reply is a 101 that did the hash.
    fn handshake(&mut self, host: &str) -> std::io::Result<()> {
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        self.stream.write_all(request.as_bytes())?;

        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        let end = loop {
            if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            // A server that never terminates its headers must not be allowed
            // to grow this buffer without limit.
            if head.len() > 8192 {
                return Err(std::io::Error::other("upgrade response header too large"));
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::Error::other("server closed during the upgrade"));
            }
            head.extend_from_slice(&chunk[..n]);
        };

        self.spare = head.split_off(end);
        let response = String::from_utf8_lossy(&head);
        if !response.starts_with("HTTP/1.1 101") {
            let status: String = response.lines().next().unwrap_or("").to_string();
            return Err(std::io::Error::other(format!(
                "upgrade refused: {status:?}"
            )));
        }
        if !response.contains(EXPECT_ACCEPT) {
            return Err(std::io::Error::other("Sec-WebSocket-Accept was wrong"));
        }
        Ok(())
    }
}

/// The masking key for frame `seq`.
///
/// RFC 6455 wants a fresh unpredictable key per frame, which exists so a
/// malicious script cannot steer the bytes an intermediary sees — irrelevant to
/// a load generator talking to a server on purpose. Rotating one fixed key
/// keeps every mask offset exercised without pulling in an RNG.
fn mask_for(seq: u64) -> [u8; 4] {
    const BASE: [u8; 4] = [0x5A, 0xC3, 0x11, 0x7E];
    let r = (seq % 4) as usize;
    [
        BASE[r],
        BASE[(r + 1) % 4],
        BASE[(r + 2) % 4],
        BASE[(r + 3) % 4],
    ]
}

/// Write one masked binary frame into `out`, replacing what was there.
fn encode_frame(out: &mut Vec<u8>, payload: &[u8], mask: [u8; 4]) {
    out.clear();
    out.push(0x80 | OP_BINARY); // FIN set, one frame per message
    let n = payload.len();
    // The mask bit is always set: a client frame that is not masked is a
    // protocol error the server is required to reject.
    if n < 126 {
        out.push(0x80 | n as u8);
    } else if n <= usize::from(u16::MAX) {
        out.push(0x80 | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
}

/// Read one whole server frame, returning its opcode. The payload lands in
/// `buf`, which is resized to fit.
fn read_frame(ws: &mut Ws, buf: &mut Vec<u8>) -> std::io::Result<u8> {
    let mut head = [0u8; 2];
    ws.read_exact(&mut head)?;
    let opcode = head[0] & 0x0F;
    if head[1] & 0x80 != 0 {
        return Err(std::io::Error::other("server frame was masked"));
    }
    let len = match head[1] & 0x7F {
        126 => {
            let mut wide = [0u8; 2];
            ws.read_exact(&mut wide)?;
            usize::from(u16::from_be_bytes(wide))
        }
        127 => {
            let mut wide = [0u8; 8];
            ws.read_exact(&mut wide)?;
            u64::from_be_bytes(wide) as usize
        }
        short => usize::from(short),
    };
    buf.resize(len, 0);
    ws.read_exact(buf)?;
    Ok(opcode)
}

/// Read and validate one echo. Checking every payload byte keeps a broken or
/// non-echoing implementation from winning by returning the right frame shape.
#[inline]
fn read_verified_echo(ws: &mut Ws, echo: &mut Vec<u8>, expected: &[u8]) -> Result<(), String> {
    match read_frame(ws, echo) {
        Ok(OP_BINARY) if echo == expected => Ok(()),
        Ok(OP_BINARY) if echo.len() == expected.len() => {
            let first = echo
                .iter()
                .zip(expected)
                .position(|(actual, wanted)| actual != wanted)
                .unwrap_or(0);
            Err(format!(
                "binary echo payload differed at byte {first}: got {:#04x}, expected {:#04x}",
                echo[first], expected[first]
            ))
        }
        Ok(opcode) => Err(format!(
            "expected a {}-byte binary echo, got opcode {opcode:#x} of {} bytes",
            expected.len(),
            echo.len()
        )),
        Err(e) => Err(format!("read failed: {e}")),
    }
}

/// Round-trip latencies (nanoseconds) plus an error, if the connection
/// dropped out partway through. Latencies collected before the error are
/// kept, not discarded.
struct WorkerResult {
    latencies_ns: Vec<u64>,
    error: Option<String>,
}

/// One connection's worth of work: connect, upgrade, wait at `barrier`
/// alongside every other worker (and the main thread) so the timed run starts
/// only once every connection is a live WebSocket, then keep up to
/// `pipeline` frames in flight until the deadline, draining whatever is
/// still outstanding afterward.
///
/// A worker that fails to connect or upgrade still reaches the barrier —
/// otherwise a single dead connection would hang every other thread forever.
fn worker(
    id: usize,
    addr: &str,
    size: usize,
    secs: u64,
    pipeline: usize,
    burst: bool,
    barrier: &Barrier,
) -> WorkerResult {
    macro_rules! give_up {
        ($($arg:tt)*) => {{
            barrier.wait();
            return WorkerResult {
                latencies_ns: Vec::new(),
                error: Some(format!($($arg)*)),
            };
        }};
    }

    let stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => give_up!("conn {id}: connect failed: {e}"),
    };
    if let Err(e) = stream.set_nodelay(true) {
        give_up!("conn {id}: set_nodelay failed: {e}");
    }
    let mut ws = Ws {
        stream,
        spare: Vec::new(),
    };
    if let Err(e) = ws.handshake(addr) {
        give_up!("conn {id}: handshake failed: {e}");
    }

    let payload = vec![0xABu8; size];
    let mut frame = Vec::with_capacity(size + 14);
    let mut echo = vec![0u8; size];
    let mut latencies_ns = Vec::new();
    let mut seq = 0u64;
    // FIFO queue of send times for frames still awaiting their echo.
    // Popping the front on every read is only correct because the wire is
    // a single TCP stream and the server echoes in the order it receives:
    // response N always corresponds to request N, so the oldest
    // outstanding send always matches the next frame read off the socket.
    let mut sent_at: VecDeque<Instant> = VecDeque::with_capacity(pipeline);

    // Every worker is upgraded; release together and start the clock from
    // here, so neither connect nor handshake eats into the run.
    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(secs);

    if burst {
        // A sliding pipeline still performs one client write syscall per
        // message. That can cap a same-host benchmark before the server is
        // busy. Burst mode keeps the same maximum number of in-flight frames,
        // but emits them in one write and drains the whole burst before the
        // next. Both servers therefore receive the exact same TCP byte stream
        // while the load generator spends much less time in syscalls.
        let mut batch = Vec::with_capacity((size + 14).saturating_mul(pipeline));
        while Instant::now() < deadline {
            batch.clear();
            for _ in 0..pipeline {
                encode_frame(&mut frame, &payload, mask_for(seq));
                seq = seq.wrapping_add(1);
                batch.extend_from_slice(&frame);
            }

            let start = Instant::now();
            if let Err(e) = ws.stream.write_all(&batch) {
                return WorkerResult {
                    latencies_ns,
                    error: Some(format!("conn {id}: burst write failed: {e}")),
                };
            }
            for _ in 0..pipeline {
                if let Err(e) = read_verified_echo(&mut ws, &mut echo, &payload) {
                    return WorkerResult {
                        latencies_ns,
                        error: Some(format!("conn {id}: {e}")),
                    };
                }
                latencies_ns.push(start.elapsed().as_nanos() as u64);
            }
        }

        return WorkerResult {
            latencies_ns,
            error: None,
        };
    }

    // Fill the pipeline: up to `pipeline` frames in flight before the first
    // echo is read. At pipeline=1 this sends exactly one frame, same as the
    // old lockstep loop's first iteration.
    for _ in 0..pipeline {
        if Instant::now() >= deadline {
            break;
        }
        encode_frame(&mut frame, &payload, mask_for(seq));
        seq = seq.wrapping_add(1);
        let start = Instant::now();
        if let Err(e) = ws.stream.write_all(&frame) {
            return WorkerResult {
                latencies_ns,
                error: Some(format!("conn {id}: write failed: {e}")),
            };
        }
        sent_at.push_back(start);
    }

    // Drain one echo per iteration; refill with a new frame only while
    // still inside the deadline, so anything already in flight is always
    // drained even after time runs out. At pipeline=1 this degenerates to
    // the original read-then-maybe-send-next loop.
    while let Some(start) = sent_at.pop_front() {
        if let Err(e) = read_verified_echo(&mut ws, &mut echo, &payload) {
            return WorkerResult {
                latencies_ns,
                error: Some(format!("conn {id}: {e}")),
            };
        }
        latencies_ns.push(start.elapsed().as_nanos() as u64);

        if Instant::now() < deadline {
            encode_frame(&mut frame, &payload, mask_for(seq));
            seq = seq.wrapping_add(1);
            let start = Instant::now();
            if let Err(e) = ws.stream.write_all(&frame) {
                return WorkerResult {
                    latencies_ns,
                    error: Some(format!("conn {id}: write failed: {e}")),
                };
            }
            sent_at.push_back(start);
        }
    }

    WorkerResult {
        latencies_ns,
        error: None,
    }
}

/// True nearest-rank percentile over an already-sorted slice: for percentile
/// `pct` (0.0-1.0) over `n` samples, returns the value at rank `ceil(pct *
/// n)` (1-indexed), clamped to the slice bounds.
fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

fn main() -> ExitCode {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    println!(
        "ws_bench: {} conns={} size={}B secs={} pipeline={} mode={}",
        cfg.addr,
        cfg.conns,
        cfg.size,
        cfg.secs,
        cfg.pipeline,
        if cfg.burst { "burst" } else { "sliding" }
    );

    // conns workers + this thread all rendezvous once every connection is
    // upgraded (or has failed out), so setup never counts against the run.
    let barrier = Arc::new(Barrier::new(cfg.conns + 1));
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::with_capacity(cfg.conns);
    for id in 0..cfg.conns {
        let addr = cfg.addr.clone();
        let size = cfg.size;
        let secs = cfg.secs;
        let pipeline = cfg.pipeline;
        let burst = cfg.burst;
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let result = worker(id, &addr, size, secs, pipeline, burst, &barrier);
            let _ = tx.send(result);
        }));
    }
    // Drop our own sender so the receiver loop below ends once every worker
    // thread has sent its result and dropped its clone.
    drop(tx);

    barrier.wait();
    let run_start = Instant::now();

    let mut all_latencies_ns: Vec<u64> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for result in rx {
        all_latencies_ns.extend(result.latencies_ns);
        if let Some(e) = result.error {
            errors.push(e);
        }
    }

    let mut join_errors = 0usize;
    for handle in handles {
        if handle.join().is_err() {
            join_errors += 1;
        }
    }

    // Measured wall time of the run: from release off the barrier to every
    // worker finishing and being joined. This is what req/s divides by,
    // instead of the nominal --secs value.
    let elapsed = run_start.elapsed();

    if !errors.is_empty() {
        eprintln!(
            "{} of {} connections reported an error:",
            errors.len(),
            cfg.conns
        );
        for e in errors.iter().take(10) {
            eprintln!("  {e}");
        }
        if errors.len() > 10 {
            eprintln!("  ... and {} more", errors.len() - 10);
        }
    }
    if join_errors > 0 {
        eprintln!("{join_errors} of {} worker thread(s) panicked", cfg.conns);
    }
    if all_latencies_ns.is_empty() {
        return ExitCode::FAILURE;
    }

    all_latencies_ns.sort_unstable();

    let total = all_latencies_ns.len() as u64;
    let req_per_sec = total as f64 / elapsed.as_secs_f64();
    let p50_ns = percentile(&all_latencies_ns, 0.50);
    let p99_ns = percentile(&all_latencies_ns, 0.99);
    let max_ns = all_latencies_ns.last().copied().unwrap_or(0);
    let to_us = |ns: u64| ns as f64 / 1_000.0;

    println!();
    println!("elapsed:            {:.3}s", elapsed.as_secs_f64());
    println!("total round-trips: {total}");
    println!("req/s:              {req_per_sec:.1}");
    println!("latency p50:        {:.1} us", to_us(p50_ns));
    println!("latency p99:        {:.1} us", to_us(p99_ns));
    println!("latency max:        {:.1} us", to_us(max_ns));

    ExitCode::SUCCESS
}
