//! Running a command as root without ever handling a password ourselves.
//!
//! `pkexec` is tried first: a polkit agent puts the prompt in front of the user
//! and controlcenter never sees the password. When there is no agent to answer —
//! a bare tty, an ssh session — pkexec exits 126 or 127 and we fall back to
//! `sudo -n`, which succeeds only if the user already has a valid sudo ticket.
//! If neither works the error says exactly what to do about it.

use crate::tunnel::which_bin;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// pkexec's exit codes for "the dialog was dismissed" and "not authorized".
const PKEXEC_DISMISSED: i32 = 126;
const PKEXEC_NOT_AUTHORIZED: i32 = 127;

pub const NO_ESCALATION: &str = "needs root, but neither pkexec nor a cached sudo ticket worked — \
run `sudo -v` in another terminal, or start a polkit agent";

/// pkexec scrubs the environment, so PATH lookup inside it is not dependable:
/// resolve the binary here and hand it over absolute.
fn resolve(program: &str) -> Result<PathBuf, String> {
    which_bin(program).ok_or_else(|| format!("{program} was not found on PATH"))
}

pub fn available() -> bool {
    which_bin("pkexec").is_some() || which_bin("sudo").is_some()
}

fn escalated(escalator: &str, program: &PathBuf, args: &[String]) -> Command {
    let mut c = Command::new(escalator);
    if escalator == "sudo" {
        // Never prompt: a sudo password prompt on a piped stdin would hang
        // invisibly behind the TUI.
        c.arg("-n");
    }
    c.arg(program);
    c.args(args);
    c
}

/// Run `argv` as root and return its stdout.
pub fn run(argv: &[String]) -> Result<String, String> {
    let (program, args) = argv.split_first().ok_or("no command given")?;
    let program = resolve(program)?;

    let mut last: Option<String> = None;

    if which_bin("pkexec").is_some() {
        let out = escalated("pkexec", &program, args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("running pkexec: {e}"))?;
        match out.status.code() {
            Some(PKEXEC_DISMISSED) | Some(PKEXEC_NOT_AUTHORIZED) => {
                // No agent answered, or it was dismissed — try a sudo ticket.
                last = Some(describe(&out));
            }
            _ if out.status.success() => {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            _ => return Err(describe(&out)),
        }
    }

    if which_bin("sudo").is_some() {
        let out = escalated("sudo", &program, args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("running sudo: {e}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        last = Some(describe(&out));
    }

    Err(match last {
        Some(e) if !e.is_empty() => format!("{NO_ESCALATION} ({e})"),
        _ => NO_ESCALATION.to_string(),
    })
}

/// A `Command` that will run `argv` as root, for output that has to be streamed
/// rather than collected. There is no fallback here — a child can only be
/// spawned once — so pkexec wins when it is present.
pub fn command(argv: &[String]) -> Result<Command, String> {
    let (program, args) = argv.split_first().ok_or("no command given")?;
    let program = resolve(program)?;
    let escalator = if which_bin("pkexec").is_some() {
        "pkexec"
    } else if which_bin("sudo").is_some() {
        "sudo"
    } else {
        return Err(NO_ESCALATION.to_string());
    };
    Ok(escalated(escalator, &program, args))
}

/// The most useful line of a failed command: stderr, else stdout, else the code.
fn describe(out: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let msg = stderr.trim();
    let msg = if msg.is_empty() { stdout.trim() } else { msg };
    if msg.is_empty() {
        format!("exited with {}", out.status)
    } else {
        msg.lines().next().unwrap_or(msg).to_string()
    }
}
