use crate::logs::{Entry, Ring};
use crate::types::RdpConnection;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpStatus {
    Running,
    Exited(i32),
}

impl RdpStatus {
    pub fn label(self) -> String {
        match self {
            Self::Running => "running".into(),
            Self::Exited(0) => "closed".into(),
            Self::Exited(c) => format!("exited ({c})"),
        }
    }
}

pub struct ActiveRdp {
    child: Child,
    pub status: RdpStatus,
    pub started_at: Instant,
    pub log: Arc<Ring>,
    /// The command line the session was started with, for the log pane and the
    /// report it exports.
    pub argv: Vec<String>,
}

fn tail_lines(reader: impl Read + Send + 'static, log: Arc<Ring>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let trimmed = line.trim_end();
            if !trimmed.is_empty() {
                log.push(trimmed);
            }
        }
    });
}

/// The xfreerdp3 arguments for a connection, in the order they are passed.
///
/// The password is not among them and never will be: `/from-stdin` makes
/// xfreerdp read it from the pipe we hold, so it stays out of the process list
/// and out of shell history — the same shape rdp.sh used.
pub fn build_args(conn: &RdpConnection) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "xfreerdp3".into(),
        format!("/v:{}:{}", conn.host, conn.port),
        format!("/u:{}", conn.username),
        "/dynamic-resolution".into(),
        "/cert:ignore".into(),
        "/from-stdin".into(),
    ];
    if !conn.domain.is_empty() {
        args.push(format!("/d:{}", conn.domain));
    }
    args.extend(conn.extra_args.split_whitespace().map(String::from));
    args
}

/// Spawn xfreerdp3 detached from the TUI.
pub fn spawn(conn: &RdpConnection, password: &str) -> Result<ActiveRdp> {
    let argv = build_args(conn);
    // argv[0] is the program; xfreerdp itself takes the rest.
    let args = &argv[1..];

    let mut child = Command::new("xfreerdp3")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning xfreerdp3 (is freerdp3 installed?)")?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{password}");
        // Dropping stdin closes it so xfreerdp cannot wait on further prompts.
    }

    let log = Arc::new(Ring::new("xfreerdp"));
    if let Some(stdout) = child.stdout.take() {
        tail_lines(stdout, Arc::clone(&log));
    }
    if let Some(stderr) = child.stderr.take() {
        tail_lines(stderr, Arc::clone(&log));
    }

    Ok(ActiveRdp {
        child,
        status: RdpStatus::Running,
        started_at: Instant::now(),
        log,
        argv,
    })
}

impl ActiveRdp {
    /// Called once per tick: detect session exit.
    pub fn poll(&mut self) {
        if matches!(self.status, RdpStatus::Exited(_)) {
            return;
        }
        if let Ok(Some(status)) = self.child.try_wait() {
            let code = status.code().unwrap_or(-1);
            self.status = RdpStatus::Exited(code);
            self.log.push(format!("── xfreerdp exited ({code}) ──"));
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.status == RdpStatus::Running {
            self.status = RdpStatus::Exited(-1);
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<Entry> {
        self.log.recent(n)
    }
}

pub fn installed() -> bool {
    crate::tunnel::which_bin("xfreerdp3").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::default_rdp_port;

    fn conn(domain: &str, extra: &str) -> RdpConnection {
        RdpConnection {
            name: "desk".into(),
            group: String::new(),
            host: "10.0.0.5".into(),
            port: default_rdp_port(),
            domain: domain.into(),
            username: "flo".into(),
            extra_args: extra.into(),
            depends_on: String::new(),
            requires_vpn: String::new(),
        }
    }

    #[test]
    fn the_password_is_never_an_argument() {
        let args = build_args(&conn("acme", ""));
        assert!(args.contains(&"/from-stdin".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("/p:")));
        assert!(args.contains(&"/d:acme".to_string()));
    }

    #[test]
    fn no_domain_means_no_domain_flag_at_all() {
        let args = build_args(&conn("", "/f /sound"));
        assert!(!args.iter().any(|a| a.starts_with("/d:")));
        // Extra args are appended in the order they were typed.
        assert_eq!(&args[args.len() - 2..], &["/f".to_string(), "/sound".to_string()]);
    }
}
