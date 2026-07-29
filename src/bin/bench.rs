//! std-only TCP echo benchmark client.
//!
//! One thread per connection: connect, then wait at a barrier so every
//! connection is established before the clock starts. Once released, each
//! worker keeps up to `--pipeline` messages in flight: send that many up
//! front, then for each completed echo send the next one, until the
//! deadline; outstanding echoes are drained before the worker reports in.
//! Round-trip latency is measured send-time to matching echo (see the note
//! on `sent_at` for why FIFO order is safe to assume here).
//!
//! Usage: bench <addr> [--conns N] [--size BYTES] [--secs S] [--pipeline K]

use std::collections::VecDeque;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Config {
    addr: String,
    conns: usize,
    size: usize,
    secs: u64,
    pipeline: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            addr: "127.0.0.1:9000".to_string(),
            conns: 50,
            size: 64,
            secs: 10,
            pipeline: 1,
        }
    }
}

fn print_usage() {
    eprintln!("Usage: bench <addr> [--conns N] [--size BYTES] [--secs S] [--pipeline K]");
    eprintln!();
    eprintln!("  addr           target address (default 127.0.0.1:9000)");
    eprintln!("  --conns N      number of concurrent connections (default 50)");
    eprintln!("  --size BYTES   payload size in bytes (default 64)");
    eprintln!("  --secs S       duration in seconds (default 10)");
    eprintln!("  --pipeline K   messages kept in flight per connection (default 1)");
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

/// Round-trip latencies (nanoseconds) plus an error, if the connection
/// dropped out partway through. Latencies collected before the error are
/// kept, not discarded.
struct WorkerResult {
    latencies_ns: Vec<u64>,
    error: Option<String>,
}

/// One connection's worth of work: connect, wait at `barrier` alongside
/// every other worker (and the main thread) so the timed run starts only
/// once all connections are up, then keep up to `pipeline` messages in
/// flight until the deadline, draining whatever is still outstanding
/// afterward.
///
/// A worker that fails to connect still reaches the barrier — otherwise a
/// single dead connection would hang every other thread forever.
fn worker(
    id: usize,
    addr: &str,
    size: usize,
    secs: u64,
    pipeline: usize,
    barrier: &Barrier,
) -> WorkerResult {
    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            barrier.wait();
            return WorkerResult {
                latencies_ns: Vec::new(),
                error: Some(format!("conn {id}: connect failed: {e}")),
            };
        }
    };
    if let Err(e) = stream.set_nodelay(true) {
        barrier.wait();
        return WorkerResult {
            latencies_ns: Vec::new(),
            error: Some(format!("conn {id}: set_nodelay failed: {e}")),
        };
    }

    let send_buf = vec![0xABu8; size];
    let mut recv_buf = vec![0u8; size];
    let mut latencies_ns = Vec::new();
    // FIFO queue of send times for messages still awaiting their echo.
    // Popping the front on every read is only correct because the wire is
    // a single TCP stream and the server echoes in the order it receives:
    // response N always corresponds to request N, so the oldest
    // outstanding send always matches the next echo read off the socket.
    let mut sent_at: VecDeque<Instant> = VecDeque::with_capacity(pipeline);

    // Every worker is connected; release together and start the clock from
    // here, not from before connect (connect latency must not eat the run).
    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(secs);

    // Fill the pipeline: up to `pipeline` messages in flight before the
    // first echo is read. At pipeline=1 this sends exactly one message,
    // same as the old lockstep loop's first iteration.
    for _ in 0..pipeline {
        if Instant::now() >= deadline {
            break;
        }
        let start = Instant::now();
        if let Err(e) = stream.write_all(&send_buf) {
            return WorkerResult {
                latencies_ns,
                error: Some(format!("conn {id}: write failed: {e}")),
            };
        }
        sent_at.push_back(start);
    }

    // Drain one echo per iteration; refill with a new message only while
    // still inside the deadline, so anything already in flight is always
    // drained even after time runs out. At pipeline=1 this degenerates to
    // the original read-then-maybe-send-next loop.
    while let Some(start) = sent_at.pop_front() {
        // write_all/read_exact handle short writes/reads internally.
        if let Err(e) = stream.read_exact(&mut recv_buf) {
            return WorkerResult {
                latencies_ns,
                error: Some(format!("conn {id}: read failed: {e}")),
            };
        }
        latencies_ns.push(start.elapsed().as_nanos() as u64);

        if Instant::now() < deadline {
            let start = Instant::now();
            if let Err(e) = stream.write_all(&send_buf) {
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
        "bench: {} conns={} size={}B secs={} pipeline={}",
        cfg.addr, cfg.conns, cfg.size, cfg.secs, cfg.pipeline
    );

    // conns workers + this thread all rendezvous once every connection is
    // established (or has failed out), so connect time never counts against
    // the timed run.
    let barrier = Arc::new(Barrier::new(cfg.conns + 1));
    let (tx, rx) = mpsc::channel();

    let mut handles = Vec::with_capacity(cfg.conns);
    for id in 0..cfg.conns {
        let addr = cfg.addr.clone();
        let size = cfg.size;
        let secs = cfg.secs;
        let pipeline = cfg.pipeline;
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let result = worker(id, &addr, size, secs, pipeline, &barrier);
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
