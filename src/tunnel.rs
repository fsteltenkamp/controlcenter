use crate::logs::{Entry, Ring};
use crate::types::{ForwardType, Tunnel};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How long the accept loop sleeps between polls; also the worst-case delay
/// before stop() can return.
const RELAY_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
    pub stderr_log: Arc<Ring>,
    /// The command line this tunnel was started with, for the log pane and the
    /// report it exports. ssh picks the internal port at spawn time, so the
    /// argv is only knowable once it has been built.
    pub argv: Vec<String>,
    /// Port ssh actually listens on for -L/-D; our relay sits in front of it.
    internal_port: Option<u16>,
    stop_flag: Arc<AtomicBool>,
    /// Owns the listening socket; joined on stop so the port is free the moment
    /// stop() returns and a replacement tunnel can bind it.
    relay: Option<thread::JoinHandle<()>>,
    last_sample: (u64, u64),
    pub rate_tx: u64,
    pub rate_rx: u64,
    pub restarts: u32,
}

/// The ssh arguments for a tunnel, in the order they are passed.
///
/// `internal` is the loopback port ssh binds for -L/-D, which is chosen when the
/// tunnel starts; `None` renders it as a placeholder, for the command line the
/// report shows for a tunnel that is not running.
pub fn build_args(tunnel: &Tunnel, internal: Option<u16>) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "ssh".into(),
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
    let port = match internal {
        Some(p) => p.to_string(),
        None => "<port>".to_string(),
    };
    match tunnel.forward {
        ForwardType::Local => {
            args.push("-L".into());
            args.push(format!(
                "127.0.0.1:{}:{}:{}",
                port, tunnel.remote_host, tunnel.remote_port
            ));
        }
        ForwardType::Dynamic => {
            args.push("-D".into());
            args.push(format!("127.0.0.1:{port}"));
        }
        ForwardType::Remote => {
            args.push("-R".into());
            args.push(format!(
                "{}:{}:{}",
                tunnel.remote_port,
                tunnel.dest_host(),
                tunnel.local_port
            ));
        }
    }
    args.extend(tunnel.extra_args.split_whitespace().map(String::from));
    args.push(tunnel.ssh_host.clone());
    args
}

/// Spawn ssh for the given tunnel. For Local/Dynamic forwards ssh binds an
/// internal loopback port and a relay thread listens on the configured port,
/// counting bytes in both directions.
pub fn spawn(tunnel: &Tunnel) -> Result<ActiveTunnel> {
    let internal_port = match tunnel.forward {
        ForwardType::Local | ForwardType::Dynamic => Some(free_port()?),
        ForwardType::Remote => None,
    };
    let argv = build_args(tunnel, internal_port);
    // argv[0] is the program; ssh itself takes the rest.
    let args = &argv[1..];

    let mut child = Command::new(crate::platform::program("ssh"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning ssh")?;

    let stderr_log = Arc::new(Ring::new("ssh"));
    if let Some(stderr) = child.stderr.take() {
        let log = Arc::clone(&stderr_log);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                log.push(line);
            }
        });
    }

    let counters = Arc::new(Counters::default());
    let stop_flag = Arc::new(AtomicBool::new(false));

    let mut relay = None;
    if let Some(internal) = internal_port {
        match start_relay(
            tunnel.local_port,
            internal,
            Arc::clone(&counters),
            Arc::clone(&stop_flag),
        ) {
            Ok(handle) => relay = Some(handle),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    }

    Ok(ActiveTunnel {
        child,
        status: Status::Connecting,
        error: None,
        started_at: Instant::now(),
        counters,
        stderr_log,
        argv,
        internal_port,
        stop_flag,
        relay,
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
                    .last_text()
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
        // Wait for the accept loop to drop the listener, otherwise starting a
        // tunnel on the same port right after this returns hits EADDRINUSE.
        if let Some(relay) = self.relay.take() {
            let _ = relay.join();
        }
    }

    pub fn recent_stderr(&self, n: usize) -> Vec<Entry> {
        self.stderr_log.recent(n)
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
) -> Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", listen_port))
        .with_context(|| format!("binding 127.0.0.1:{listen_port} (port in use?)"))?;
    listener
        .set_nonblocking(true)
        .context("setting listener non-blocking")?;

    let handle = thread::spawn(move || {
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
                    thread::sleep(RELAY_POLL_INTERVAL);
                }
                Err(_) => break,
            }
        }
        // Dropping `listener` here releases the port.
    });
    Ok(handle)
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

pub fn which_ssh() -> Option<std::path::PathBuf> {
    crate::platform::which_bin("ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests that bind a port take this first.
    ///
    /// `free_port` lets go of the port before the relay binds it, so two of
    /// these running at once can be handed the same one by the kernel and the
    /// loser fails on a race that says nothing about the relay.
    static PORT_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
        // A test that panicked poisons the lock; the next one still wants it.
        PORT_TESTS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A relay on a port that [`free_port`] proposed and the bind accepted.
    ///
    /// Asking for port 0 can be answered with a port whose only occupant is a
    /// socket in TIME_WAIT — left behind by an earlier test — which the
    /// explicit bind that follows then refuses. Trying again picks a different
    /// one; it is the connections the relay carries that are under test, not
    /// which port it happened to get.
    fn relay_on_a_free_port(
        internal_port: u16,
        counters: &Arc<Counters>,
        stop: &Arc<AtomicBool>,
    ) -> (u16, thread::JoinHandle<()>) {
        for _ in 0..20 {
            let port = free_port().unwrap();
            if let Ok(handle) =
                start_relay(port, internal_port, Arc::clone(counters), Arc::clone(stop))
            {
                return (port, handle);
            }
        }
        panic!("twenty ports in a row were already taken");
    }

    fn tunnel(forward: ForwardType) -> Tunnel {
        Tunnel {
            name: "db".into(),
            group: String::new(),
            ssh_host: "bastion".into(),
            forward,
            local_port: 5432,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            extra_args: "-J jump".into(),
            auto_reconnect: false,
            requires_vpn: String::new(),
            depends_on: String::new(),
        }
    }

    #[test]
    fn a_local_forward_binds_the_internal_port_and_the_relay_takes_the_real_one() {
        let args = build_args(&tunnel(ForwardType::Local), Some(40001));
        assert_eq!(args[0], "ssh");
        assert!(args.contains(&"-L".to_string()));
        assert!(args.contains(&"127.0.0.1:40001:db.internal:5432".to_string()));
        // extra args come before the destination, which is always last.
        assert_eq!(args.last().unwrap(), "bastion");
        assert!(args.contains(&"-J".to_string()));
    }

    #[test]
    fn a_remote_forward_has_no_internal_port_at_all() {
        let args = build_args(&tunnel(ForwardType::Remote), None);
        assert!(args.contains(&"5432:db.internal:5432".to_string()));
        assert!(!args.iter().any(|a| a.contains("<port>")));
    }

    #[test]
    fn without_a_port_the_preview_says_so_rather_than_inventing_one() {
        // What the report prints for a tunnel that is not running.
        let args = build_args(&tunnel(ForwardType::Dynamic), None);
        assert!(args.contains(&"127.0.0.1:<port>".to_string()));
    }

    #[test]
    fn relay_forwards_and_counts_bytes() {
        let _guard = one_at_a_time();
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

        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (listen_port, _relay) = relay_on_a_free_port(internal_port, &counters, &stop);

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
    fn stopping_a_relay_frees_the_port_for_the_next_tunnel() {
        let _guard = one_at_a_time();
        // Evicting a conflicting tunnel is only useful if its port is free by
        // the time the replacement binds.
        //
        // Something else on the machine can own the port by then — an earlier
        // connection of ours still in TIME_WAIT, or another process — so a
        // single refusal proves nothing and the whole thing is tried again on
        // a fresh port. A relay that really held on would fail every time.
        let mut refused = None;
        for _ in 0..20 {
            let counters = Arc::new(Counters::default());
            let stop = Arc::new(AtomicBool::new(false));
            let (listen_port, handle) = relay_on_a_free_port(1, &counters, &stop);

            stop.store(true, Ordering::SeqCst);
            handle.join().unwrap();

            let stop2 = Arc::new(AtomicBool::new(false));
            match start_relay(listen_port, 1, Arc::new(Counters::default()), Arc::clone(&stop2)) {
                Ok(again) => {
                    stop2.store(true, Ordering::SeqCst);
                    again.join().unwrap();
                    return;
                }
                Err(e) => refused = Some(e),
            }
        }
        panic!("port never came free: {:?}", refused);
    }

    #[test]
    fn relay_bind_conflict_reports_error() {
        let _guard = one_at_a_time();
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let err = start_relay(port, 1, counters, stop).unwrap_err();
        assert!(err.to_string().contains("port in use"));
    }
}
