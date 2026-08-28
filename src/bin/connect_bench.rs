//! TCP connection-churn benchmark.
//!
//! Measures the complete path a short-lived client pays:
//!
//! `connect` -> one write -> one echoed read -> close
//!
//! Usage:
//! `connect_bench <addr> [--workers N] [--size BYTES] [--secs S] [--reset-close]`

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct Config {
    addr: String,
    workers: usize,
    size: usize,
    secs: u64,
    reset_close: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:9000".to_string(),
            workers: 16,
            size: 64,
            secs: 10,
            reset_close: false,
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: connect_bench <addr> [--workers N] [--size BYTES] [--secs S] [--reset-close]"
    );
    eprintln!();
    eprintln!("  addr           target address (default 127.0.0.1:9000)");
    eprintln!("  --workers N    concurrent connection loops (default 16)");
    eprintln!("  --size BYTES   one-shot payload size (default 64)");
    eprintln!("  --secs S       duration in seconds (default 10)");
    eprintln!("  --reset-close  close with TCP RST after the verified echo");
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut addr_set = false;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--workers" => {
                let value = args.next().ok_or("--workers requires a value")?;
                cfg.workers = value
                    .parse()
                    .map_err(|_| format!("invalid --workers value: {value}"))?;
            }
            "--size" => {
                let value = args.next().ok_or("--size requires a value")?;
                cfg.size = value
                    .parse()
                    .map_err(|_| format!("invalid --size value: {value}"))?;
            }
            "--secs" => {
                let value = args.next().ok_or("--secs requires a value")?;
                cfg.secs = value
                    .parse()
                    .map_err(|_| format!("invalid --secs value: {value}"))?;
            }
            "--reset-close" => {
                cfg.reset_close = true;
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

    if cfg.workers == 0 {
        return Err("--workers must be >= 1".to_string());
    }
    if cfg.size == 0 {
        return Err("--size must be >= 1".to_string());
    }
    if cfg.secs == 0 {
        return Err("--secs must be >= 1".to_string());
    }

    Ok(cfg)
}

struct WorkerResult {
    latencies_ns: Vec<u64>,
    errors: u64,
    first_error: Option<String>,
}

#[cfg(unix)]
fn enable_reset_close(stream: &TcpStream) -> std::io::Result<()> {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `linger` is a live value of the advertised size and the fd is
    // owned by `stream` for the duration of this call.
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn enable_reset_close(_stream: &TcpStream) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "--reset-close requires a Unix socket",
    ))
}

fn worker(
    id: usize,
    addr: &str,
    size: usize,
    secs: u64,
    reset_close: bool,
    barrier: &Barrier,
) -> WorkerResult {
    let send_buf = vec![0xAB; size];
    let mut recv_buf = vec![0; size];
    let mut latencies_ns = Vec::new();
    let mut errors = 0;
    let mut first_error = None;

    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(secs);

    while Instant::now() < deadline {
        let started = Instant::now();
        let result = (|| -> std::io::Result<()> {
            let mut stream = TcpStream::connect(addr)?;
            if reset_close {
                enable_reset_close(&stream)?;
            }
            stream.write_all(&send_buf)?;
            stream.read_exact(&mut recv_buf)?;
            if recv_buf != send_buf {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "echo payload did not match",
                ));
            }
            Ok(())
        })();

        match result {
            Ok(()) => latencies_ns.push(started.elapsed().as_nanos() as u64),
            Err(error) => {
                errors += 1;
                if first_error.is_none() {
                    first_error = Some(format!("worker {id}: {error}"));
                }
                // A closed listener fails immediately. Yielding prevents an
                // accidental server outage from becoming a client-side spin.
                thread::yield_now();
            }
        }
    }

    WorkerResult {
        latencies_ns,
        errors,
        first_error,
    }
}

/// True nearest-rank percentile over an already-sorted slice.
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
        Err(error) => {
            eprintln!("error: {error}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    println!(
        "connect_bench: {} workers={} size={}B secs={} close={}",
        cfg.addr,
        cfg.workers,
        cfg.size,
        cfg.secs,
        if cfg.reset_close { "rst" } else { "fin" }
    );

    let barrier = Arc::new(Barrier::new(cfg.workers + 1));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(cfg.workers);

    for id in 0..cfg.workers {
        let addr = cfg.addr.clone();
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        let size = cfg.size;
        let secs = cfg.secs;
        let reset_close = cfg.reset_close;
        handles.push(thread::spawn(move || {
            let _ = tx.send(worker(id, &addr, size, secs, reset_close, &barrier));
        }));
    }
    drop(tx);

    barrier.wait();
    let run_started = Instant::now();

    let mut latencies_ns = Vec::new();
    let mut errors = 0;
    let mut first_errors = Vec::new();
    for result in rx {
        latencies_ns.extend(result.latencies_ns);
        errors += result.errors;
        if let Some(error) = result.first_error {
            first_errors.push(error);
        }
    }

    let mut panics = 0;
    for handle in handles {
        panics += usize::from(handle.join().is_err());
    }
    let elapsed = run_started.elapsed();

    latencies_ns.sort_unstable();
    let successful = latencies_ns.len() as u64;
    let attempts = successful + errors;
    let success_rate = if attempts == 0 {
        0.0
    } else {
        successful as f64 * 100.0 / attempts as f64
    };
    let conn_per_sec = successful as f64 / elapsed.as_secs_f64();
    let to_us = |ns: u64| ns as f64 / 1_000.0;

    println!();
    println!("elapsed:             {:.3}s", elapsed.as_secs_f64());
    println!("successful connects: {successful}");
    println!("connection errors:   {errors}");
    println!("success rate:        {success_rate:.5}%");
    println!("connections/s:       {conn_per_sec:.1}");
    println!(
        "latency p50:         {:.1} us",
        to_us(percentile(&latencies_ns, 0.50))
    );
    println!(
        "latency p99:         {:.1} us",
        to_us(percentile(&latencies_ns, 0.99))
    );
    println!(
        "latency max:         {:.1} us",
        to_us(latencies_ns.last().copied().unwrap_or(0))
    );

    if !first_errors.is_empty() {
        eprintln!("first error from each affected worker:");
        for error in first_errors.iter().take(10) {
            eprintln!("  {error}");
        }
        if first_errors.len() > 10 {
            eprintln!("  ... and {} more", first_errors.len() - 10);
        }
    }
    if panics > 0 {
        eprintln!("{panics} of {} worker thread(s) panicked", cfg.workers);
    }

    if successful == 0 || errors > 0 || panics > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
