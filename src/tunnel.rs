use crate::types::{ForwardType, Tunnel};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const STDERR_LOG_CAP: usize = 200;

#[derive(Default)]
pub struct Counters {
    /// Bytes sent from local clients into the tunnel.
    pub tx: AtomicU64,
    /// Bytes received from the tunnel back to local clients.
    pub rx: AtomicU64,
    pub active_conns: AtomicU64,
    pub total_conns: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Connecting,
    Up,
    Failed,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Up => "up",
            Self::Failed => "failed",
        }
    }
}

pub struct ActiveTunnel {
    child: Child,
    pub status: Status,
    pub error: Option<String>,
    pub started_at: Instant,
    pub counters: Arc<Counters>,
    pub stderr_log: Arc<Mutex<Vec<String>>>,
    /// Port ssh actually listens on for -L/-D; our relay sits in front of it.
    internal_port: Option<u16>,
    stop_flag: Arc<AtomicBool>,
    last_sample: (u64, u64),
    pub rate_tx: u64,
    pub rate_rx: u64,
    pub restarts: u32,
}

/// Spawn ssh for the given tunnel. For Local/Dynamic forwards ssh binds an
/// internal loopback port and a relay thread listens on the configured port,
/// counting bytes in both directions.
pub fn spawn(tunnel: &Tunnel) -> Result<ActiveTunnel> {
    let mut args: Vec<String> = vec![
        "-N".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
    ];

    let internal_port = match tunnel.forward {
        ForwardType::Local => {
            let port = free_port()?;
            args.push("-L".into());
            args.push(format!(
                "127.0.0.1:{}:{}:{}",
                port, tunnel.remote_host, tunnel.remote_port
            ));
            Some(port)
        }
        ForwardType::Dynamic => {
            let port = free_port()?;
            args.push("-D".into());
            args.push(format!("127.0.0.1:{port}"));
            Some(port)
        }
        ForwardType::Remote => {
            args.push("-R".into());
            args.push(format!(
                "{}:{}:{}",
                tunnel.remote_port,
                tunnel.dest_host(),
                tunnel.local_port
            ));
            None
        }
    };

    args.extend(tunnel.extra_args.split_whitespace().map(String::from));
    args.push(tunnel.ssh_host.clone());

    let mut child = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning ssh")?;

    let stderr_log = Arc::new(Mutex::new(Vec::new()));
    if let Some(stderr) = child.stderr.take() {
        let log = Arc::clone(&stderr_log);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut log = log.lock().unwrap();
                if log.len() >= STDERR_LOG_CAP {
                    log.remove(0);
                }
                log.push(line);
            }
        });
    }

    let counters = Arc::new(Counters::default());
    let stop_flag = Arc::new(AtomicBool::new(false));

    if let Some(internal) = internal_port {
        if let Err(e) = start_relay(
            tunnel.local_port,
            internal,
            Arc::clone(&counters),
            Arc::clone(&stop_flag),
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }

    Ok(ActiveTunnel {
        child,
        status: Status::Connecting,
        error: None,
        started_at: Instant::now(),
        counters,
        stderr_log,
        internal_port,
        stop_flag,
        last_sample: (0, 0),
        rate_tx: 0,
        rate_rx: 0,
        restarts: 0,
    })
}

impl ActiveTunnel {
    /// Called once per tick: detect ssh exit and probe for readiness.
    pub fn poll(&mut self) {
        if self.status == Status::Failed {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(code)) => {
                self.stop_flag.store(true, Ordering::SeqCst);
                let last_err = self
                    .stderr_log
                    .lock()
                    .unwrap()
                    .last()
                    .cloned()
                    .unwrap_or_else(|| format!("ssh exited ({code})"));
                self.error = Some(last_err);
                self.status = Status::Failed;
            }
            Ok(None) => {
                if self.status == Status::Connecting {
                    match self.internal_port {
                        Some(port) => {
                            // ssh binds the internal port only after auth succeeds.
                            let addr = SocketAddr::from(([127, 0, 0, 1], port));
                            if let Ok(s) =
                                TcpStream::connect_timeout(&addr, Duration::from_millis(100))
                            {
                                let _ = s.shutdown(Shutdown::Both);
                                self.status = Status::Up;
                            }
                        }
                        None => {
                            // Remote forwards have no local socket to probe;
                            // ExitOnForwardFailure kills ssh on failure, so
                            // "still alive after a grace period" means up.
                            if self.started_at.elapsed() > Duration::from_secs(3) {
                                self.status = Status::Up;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                self.error = Some(format!("wait failed: {e}"));
                self.status = Status::Failed;
            }
        }
    }

    /// Update tx/rx rates from counter deltas; `dt` is seconds since last call.
    pub fn sample_rates(&mut self, dt: f64) {
        let tx = self.counters.tx.load(Ordering::Relaxed);
        let rx = self.counters.rx.load(Ordering::Relaxed);
        if dt > 0.0 {
            self.rate_tx = ((tx - self.last_sample.0) as f64 / dt) as u64;
            self.rate_rx = ((rx - self.last_sample.1) as f64 / dt) as u64;
        }
        self.last_sample = (tx, rx);
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn recent_stderr(&self, n: usize) -> Vec<String> {
        let log = self.stderr_log.lock().unwrap();
        log.iter().rev().take(n).rev().cloned().collect()
    }
}

fn free_port() -> Result<u16> {
    let listener =
        TcpListener::bind("127.0.0.1:0").context("finding a free internal port")?;
    Ok(listener.local_addr()?.port())
}

/// Listen on `listen_port` and relay every connection to 127.0.0.1:`internal_port`
/// (where ssh listens), counting bytes in both directions.
fn start_relay(
    listen_port: u16,
    internal_port: u16,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .with_context(|| format!("binding 127.0.0.1:{listen_port} (port in use?)"))?;
    listener
        .set_nonblocking(true)
        .context("setting listener non-blocking")?;

    thread::spawn(move || {
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((client, _)) => {
                    let counters = Arc::clone(&counters);
                    let stop = Arc::clone(&stop);
                    thread::spawn(move || handle_conn(client, internal_port, counters, stop));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });
    Ok(())
}

fn handle_conn(
    client: TcpStream,
    internal_port: u16,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
) {
    // ssh may still be authenticating; retry the upstream connect briefly.
    let addr = SocketAddr::from(([127, 0, 0, 1], internal_port));
    let mut upstream = None;
    for _ in 0..60 {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(s) => {
                upstream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
    let Some(upstream) = upstream else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };

    counters.total_conns.fetch_add(1, Ordering::Relaxed);
    counters.active_conns.fetch_add(1, Ordering::Relaxed);

    let (Ok(client2), Ok(upstream2)) = (client.try_clone(), upstream.try_clone()) else {
        counters.active_conns.fetch_sub(1, Ordering::Relaxed);
        return;
    };

    let tx_counter = Arc::clone(&counters);
    let t = thread::spawn(move || pipe(client2, upstream2, &tx_counter.tx));
    pipe(upstream, client, &counters.rx);
    let _ = t.join();

    counters.active_conns.fetch_sub(1, Ordering::Relaxed);
}

fn pipe(mut from: TcpStream, mut to: TcpStream, counter: &AtomicU64) {
    let mut buf = [0u8; 16384];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}

pub fn which_bin(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join(name);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

pub fn which_ssh() -> Option<std::path::PathBuf> {
    which_bin("ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_forwards_and_counts_bytes() {
        // Stand-in for the ssh-bound internal port: an echo server.
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let internal_port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in echo.incoming().flatten() {
                thread::spawn(move || {
                    let mut a = stream.try_clone().unwrap();
                    let mut b = stream;
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = a.read(&mut buf) {
                        if n == 0 || b.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let listen_port = free_port().unwrap();
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        start_relay(listen_port, internal_port, Arc::clone(&counters), Arc::clone(&stop))
            .unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", listen_port)).unwrap();
        let payload = b"hello through the tunnel";
        client.write_all(payload).unwrap();
        let mut back = vec![0u8; payload.len()];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, payload);

        assert_eq!(counters.tx.load(Ordering::Relaxed), payload.len() as u64);
        assert_eq!(counters.rx.load(Ordering::Relaxed), payload.len() as u64);
        assert_eq!(counters.total_conns.load(Ordering::Relaxed), 1);

        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn relay_bind_conflict_reports_error() {
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let err = start_relay(port, 1, counters, stop).unwrap_err();
        assert!(err.to_string().contains("port in use"));
    }
}
