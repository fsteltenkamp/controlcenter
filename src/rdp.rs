use crate::types::RdpConnection;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

const LOG_CAP: usize = 400;

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
    pub log: Arc<Mutex<Vec<String>>>,
}

fn push_log(log: &Arc<Mutex<Vec<String>>>, line: String) {
    let mut log = log.lock().unwrap();
    if log.len() >= LOG_CAP {
        log.remove(0);
    }
    log.push(line);
}

fn tail_lines(reader: impl Read + Send + 'static, log: Arc<Mutex<Vec<String>>>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let trimmed = line.trim_end();
            if !trimmed.is_empty() {
                push_log(&log, trimmed.to_string());
            }
        }
    });
}

/// Spawn xfreerdp3 detached from the TUI. The password is written to the child's
/// stdin (`/from-stdin`), never placed on the command line, mirroring rdp.sh:
/// it stays out of the process list and shell history.
pub fn spawn(conn: &RdpConnection, password: &str) -> Result<ActiveRdp> {
    let mut args: Vec<String> = vec![
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

    let mut child = Command::new("xfreerdp3")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning xfreerdp3 (is freerdp3 installed?)")?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{password}");
        // Dropping stdin closes it so xfreerdp cannot wait on further prompts.
    }

    let log = Arc::new(Mutex::new(Vec::new()));
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
            push_log(&self.log, format!("── xfreerdp exited ({code}) ──"));
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.status == RdpStatus::Running {
            self.status = RdpStatus::Exited(-1);
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<String> {
        let log = self.log.lock().unwrap();
        log.iter().rev().take(n).rev().cloned().collect()
    }
}

pub fn installed() -> bool {
    crate::tunnel::which_bin("xfreerdp3").is_some()
}
