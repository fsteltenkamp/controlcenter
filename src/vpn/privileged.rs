//! Running a command as root without ever handling a password ourselves.
//!
//! `pkexec` is tried first: a polkit agent puts the prompt in front of the user
//! and controlcenter never sees the password. When there is no agent to answer —
//! a bare tty, an ssh session — pkexec exits 126 or 127 and we fall back to
//! `sudo -n`, which succeeds only if the user already has a valid sudo ticket.
//! If neither works the error says exactly what to do about it.
//!
//! That order is reversed when controlcenter was allowed to take a sudo ticket
//! at startup, because a dialog that can be dismissed is the wrong thing to
//! stand between the user and a connection they are trying to take down. See
//! [`warm_up`].

use crate::tunnel::which_bin;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

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

// ---------------------------------------------------------------------------
// The sudo ticket
//
// pkexec is the right escalation for one deliberate act — the polkit agent puts
// a dialog in front of the user and controlcenter never sees the password. It
// is the wrong one for taking a connection *down*: a dialog per kill means the
// panic button asks four times, and a dialog that is dismissed, or that never
// appears because there is no agent, leaves a root openvpn running that nothing
// can reach any more.
//
// So controlcenter can be told to take a sudo ticket once, on the terminal it
// was started from, before the TUI takes the screen. While that ticket is valid
// `sudo -n` needs no dialog and cannot be dismissed, so it goes first — see
// `run` and `command`. Without one, nothing changes: pkexec first, as before.
// ---------------------------------------------------------------------------

/// Whether a sudo ticket was taken at startup and is expected to still be good.
static TICKET: AtomicBool = AtomicBool::new(false);

/// What controlcenter may do about root before the TUI starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warmup {
    /// Ask for a password if there is no ticket already. The default: it is the
    /// one moment in the program's life where a prompt can be typed at.
    Ask,
    /// Use a ticket that is already there, never ask for one.
    Auto,
    /// Leave sudo alone; every escalation goes through polkit.
    Never,
}

impl Warmup {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "never" | "off" | "no" => Self::Never,
            _ => Self::Ask,
        }
    }
}

/// How the warm-up went, said once on the terminal it happened on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warmed {
    /// A ticket is good; taking connections down will not need a dialog.
    Ticket { asked: bool },
    /// No ticket, and why. Not fatal — pkexec is still there.
    None(String),
    /// Not attempted.
    Skipped,
}

impl Warmed {
    /// The line to print. `None` when there is nothing worth saying.
    pub fn line(&self) -> Option<String> {
        match self {
            Self::Ticket { asked: true } => {
                Some("controlcenter: sudo ticket taken — VPN sessions can be stopped without a dialog.".into())
            }
            Self::Ticket { asked: false } => None,
            Self::None(why) => Some(format!(
                "controlcenter: no sudo ticket ({why}); stopping a VPN will ask through polkit instead."
            )),
            Self::Skipped => None,
        }
    }
}

/// Whether an escalation can currently be expected to run without a dialog.
pub fn has_ticket() -> bool {
    TICKET.load(Ordering::Relaxed)
}

/// Is a ticket already valid? `-n` never prompts, so this is safe to call with
/// the TUI on screen.
fn ticket_valid() -> bool {
    Command::new("sudo")
        .args(["-n", "-v"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether [`warm_up`] would put a password prompt on the terminal, so that
/// the reason for it can be printed above it rather than after.
pub fn will_ask(mode: Warmup) -> bool {
    mode == Warmup::Ask && which_bin("sudo").is_some() && !ticket_valid()
}

/// Take a sudo ticket before the TUI starts, so that taking a VPN down later is
/// one silent `sudo -n` rather than a polkit dialog that can be dismissed.
///
/// This is the only place in the program that lets sudo prompt: it runs before
/// the alternate screen is entered, with the terminal still the user's, so the
/// password prompt is a normal one. Nothing here handles the password itself.
pub fn warm_up(mode: Warmup) -> Warmed {
    if mode == Warmup::Never {
        return Warmed::Skipped;
    }
    if which_bin("sudo").is_none() {
        return Warmed::None("sudo is not on PATH".into());
    }
    if ticket_valid() {
        TICKET.store(true, Ordering::Relaxed);
        return Warmed::Ticket { asked: false };
    }
    if mode == Warmup::Auto {
        return Warmed::Skipped;
    }
    // Inherited stdio: this is the user's terminal and sudo's prompt belongs on it.
    match Command::new("sudo").arg("-v").status() {
        Ok(s) if s.success() => {
            TICKET.store(true, Ordering::Relaxed);
            Warmed::Ticket { asked: true }
        }
        Ok(_) => Warmed::None("sudo declined".into()),
        Err(e) => Warmed::None(format!("running sudo: {e}")),
    }
}

/// Keep the ticket alive. sudo forgets it after a few minutes of not being
/// used, and the moment it is wanted is the moment nothing may block, so it is
/// refreshed on a timer instead. Never prompts: if the ticket is gone it stays
/// gone and escalation falls back to polkit.
pub fn keep_warm() {
    if !has_ticket() {
        return;
    }
    std::thread::spawn(|| {
        TICKET.store(ticket_valid(), Ordering::Relaxed);
    });
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
///
/// pkexec first, `sudo -n` as the fallback — unless a ticket was taken at
/// startup, in which case sudo goes first: it is the escalation that cannot be
/// dismissed, and the commands that matter most here are the ones that take a
/// connection *down*.
pub fn run(argv: &[String]) -> Result<String, String> {
    let (program, args) = argv.split_first().ok_or("no command given")?;
    let program = resolve(program)?;

    let mut last: Option<String> = None;
    let mut sudo_tried = false;

    if has_ticket() {
        sudo_tried = true;
        let out = escalated("sudo", &program, args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("running sudo: {e}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        // The ticket has expired or was never as good as it looked; stop
        // claiming it and let polkit have the attempt.
        TICKET.store(false, Ordering::Relaxed);
        last = Some(describe(&out));
    }

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

    if !sudo_tried && which_bin("sudo").is_some() {
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
    let escalator = if has_ticket() {
        "sudo"
    } else if which_bin("pkexec").is_some() {
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
