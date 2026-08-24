use crate::types::SshHost;
use anyhow::{Context, Result};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Result of a finished interactive session, kept for the details panel.
#[derive(Debug, Clone, Copy)]
pub struct SessionOutcome {
    pub code: i32,
    pub duration: Duration,
    pub finished_at: Instant,
    /// The session ran in a terminal window of its own. Emulators rarely pass
    /// ssh's exit code back, so the code is only trusted for inline sessions.
    pub windowed: bool,
}

impl SessionOutcome {
    pub fn label(&self) -> String {
        match (self.windowed, self.code) {
            (true, _) => "window closed".into(),
            (false, 0) => "closed".into(),
            (false, c) => format!("exited ({c})"),
        }
    }

    /// Whether the outcome should be shown as a problem.
    pub fn failed(&self) -> bool {
        !self.windowed && self.code != 0
    }
}

/// The ssh arguments for an interactive login, in the order they are passed.
pub fn build_args(host: &SshHost) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if host.port != 22 {
        args.push("-p".into());
        args.push(host.port.to_string());
    }
    if !host.key_path.is_empty() {
        args.push("-i".into());
        args.push(expand_tilde(&host.key_path));
        // A configured key is the intent; don't let the agent shadow it.
        args.push("-o".into());
        args.push("IdentitiesOnly=yes".into());
    }
    if host.skip_host_key_check {
        args.push("-o".into());
        args.push("StrictHostKeyChecking=no".into());
        args.push("-o".into());
        args.push("UserKnownHostsFile=/dev/null".into());
        // Otherwise every connect prints a "permanently added" warning.
        args.push("-o".into());
        args.push("LogLevel=ERROR".into());
    }
    if !host.password.is_empty() {
        // sshpass answers exactly one prompt; more means the password is wrong
        // and we would otherwise loop.
        args.push("-o".into());
        args.push("NumberOfPasswordPrompts=1".into());
    }
    args.extend(host.extra_args.split_whitespace().map(String::from));
    args.push(host.destination());
    args
}

/// The command line as the user would type it, for the details panel.
/// A stored password is never shown — it goes through the environment.
pub fn command_preview(host: &SshHost) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !host.password.is_empty() {
        parts.push("sshpass".into());
        parts.push("-e".into());
    }
    parts.push("ssh".into());
    parts.extend(build_args(host));
    parts.join(" ")
}

/// Run ssh attached to the current terminal and wait for it to finish.
/// The caller must have left the alternate screen and raw mode first.
pub fn run_interactive(host: &SshHost) -> Result<SessionOutcome> {
    let args = build_args(host);
    let started = Instant::now();

    let mut cmd = if host.password.is_empty() {
        let mut c = Command::new("ssh");
        c.args(&args);
        c
    } else {
        // -e reads the password from SSHPASS so it never lands in the process
        // list, where any user on the box could read it.
        let mut c = Command::new("sshpass");
        c.arg("-e").arg("ssh").args(&args);
        c.env("SSHPASS", &host.password);
        c
    };

    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            if host.password.is_empty() {
                "spawning ssh".to_string()
            } else {
                "spawning sshpass (is sshpass installed?)".to_string()
            }
        })?;
    let status = child.wait().context("waiting for ssh")?;

    Ok(SessionOutcome {
        code: status.code().unwrap_or(-1),
        duration: started.elapsed(),
        finished_at: Instant::now(),
        windowed: false,
    })
}

// ---------------------------------------------------------------------------
// Opening a session in a terminal window of its own
// ---------------------------------------------------------------------------

/// A terminal emulator and the arguments that make it run a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    pub program: String,
    /// Passed before the command. A `{cmd}` placeholder in a user-configured
    /// value is replaced by the shell command; without one the command is
    /// appended as `sh -c <script>`.
    pub args: Vec<String>,
}

impl Terminal {
    /// What to call it in the UI: a configured path is a mouthful, its name is not.
    pub fn name(&self) -> String {
        std::path::Path::new(&self.program)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.program.clone())
    }
}

/// How an interactive session is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// A window of its own, so the TUI keeps running alongside it.
    Window(Terminal),
    /// The current terminal, handed over until the session ends.
    Inline,
}

impl Launch {
    /// What the details panel and the status message call it.
    pub fn label(&self) -> String {
        match self {
            Self::Window(t) => format!("a new {} window", t.name()),
            Self::Inline => "this terminal".into(),
        }
    }
}

/// Emulators in the order they are tried, with the flag that makes each one run
/// a command. Those that take the command with no flag at all get an empty list.
const TERMINALS: &[(&str, &[&str])] = &[
    // The freedesktop indirection comes first: it opens whichever terminal the
    // desktop is already configured to use, and takes the command as-is.
    ("xdg-terminal-exec", &[]),
    ("ghostty", &["-e"]),
    ("kitty", &[]),
    ("alacritty", &["-e"]),
    ("foot", &[]),
    ("wezterm", &["start", "--"]),
    ("konsole", &["-e"]),
    ("gnome-terminal", &["--"]),
    ("xfce4-terminal", &["-x"]),
    ("terminator", &["-x"]),
    ("tilix", &["-e"]),
    ("urxvt", &["-e"]),
    ("st", &["-e"]),
    ("xterm", &["-e"]),
];

/// Resolve the configured preference: `auto` picks the first emulator found,
/// `inline` keeps the old behaviour, anything else is a command line to run.
pub fn resolve_launch(pref: &str) -> Launch {
    let pref = pref.trim();
    match pref {
        "inline" => Launch::Inline,
        "" | "auto" => detect_terminal().map(Launch::Window).unwrap_or(Launch::Inline),
        custom => match parse_terminal(custom) {
            Some(t) => Launch::Window(t),
            None => Launch::Inline,
        },
    }
}

fn parse_terminal(spec: &str) -> Option<Terminal> {
    let mut words = spec.split_whitespace().map(String::from);
    let program = words.next()?;
    Some(Terminal {
        program,
        args: words.collect(),
    })
}

/// $TERMINAL wins if it is installed — it is what the user already chose for
/// everything else — then the table order.
fn detect_terminal() -> Option<Terminal> {
    if let Some(pref) = std::env::var_os("TERMINAL") {
        let pref = pref.to_string_lossy().into_owned();
        if let Some(t) = parse_terminal(&pref) {
            if crate::tunnel::which_bin(&t.program).is_some() {
                // A bare $TERMINAL carries no flags of its own; use the ones we
                // know for it, falling back to the near-universal -e.
                if t.args.is_empty() {
                    return Some(known_terminal(&t.program));
                }
                return Some(t);
            }
        }
    }
    TERMINALS
        .iter()
        .find(|(bin, _)| crate::tunnel::which_bin(bin).is_some())
        .map(|(bin, args)| Terminal {
            program: (*bin).to_string(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
        })
}

fn known_terminal(program: &str) -> Terminal {
    let name = std::path::Path::new(program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string());
    let args = TERMINALS
        .iter()
        .find(|(bin, _)| *bin == name)
        .map(|(_, args)| args.iter().map(|a| (*a).to_string()).collect())
        .unwrap_or_else(|| vec!["-e".to_string()]);
    Terminal {
        program: program.to_string(),
        args,
    }
}

/// A session running in its own window, polled like an RDP session.
pub struct WindowSession {
    child: Child,
    pub started_at: Instant,
    done: bool,
}

impl WindowSession {
    /// Close the window from here. Only the panic button does this — normally
    /// a session ends when the user closes its window.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.done = true;
    }

    /// Called once per tick; yields the outcome on the tick the window closes.
    pub fn poll(&mut self) -> Option<SessionOutcome> {
        if self.done {
            return None;
        }
        let status = self.child.try_wait().ok().flatten()?;
        self.done = true;
        Some(SessionOutcome {
            code: status.code().unwrap_or(-1),
            duration: self.started_at.elapsed(),
            finished_at: Instant::now(),
            windowed: true,
        })
    }
}

/// The shell command the window runs: ssh, and on failure a pause so the error
/// is still readable after the session dies.
fn session_script(host: &SshHost) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !host.password.is_empty() {
        parts.push("sshpass".into());
        parts.push("-e".into());
    }
    parts.push("ssh".into());
    parts.extend(build_args(host).iter().map(|a| shell_quote(a)));
    let cmd = parts.join(" ");
    format!(
        "{cmd}; s=$?; if [ \"$s\" -ne 0 ]; then printf '\\n[controlcenter] ssh exited %s — press Enter to close ' \"$s\"; read -r _; fi; exit $s"
    )
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Open the session in its own window and return immediately.
pub fn spawn_windowed(host: &SshHost, term: &Terminal) -> Result<WindowSession> {
    let script = session_script(host);
    let mut cmd = Command::new(&term.program);
    let mut placed = false;
    for arg in &term.args {
        if arg.contains("{cmd}") {
            cmd.arg(arg.replace("{cmd}", &script));
            placed = true;
        } else {
            cmd.arg(arg);
        }
    }
    if !placed {
        cmd.arg("sh").arg("-c").arg(&script);
    }
    if !host.password.is_empty() {
        // Same as inline: through the environment, never the command line.
        cmd.env("SSHPASS", &host.password);
    }
    let child = cmd
        // The window has its own; ours stays with the TUI.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {}", term.program))?;

    Ok(WindowSession {
        child,
        started_at: Instant::now(),
        done: false,
    })
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => format!("{}/{}", home.to_string_lossy(), rest),
            None => path.to_string(),
        },
        None => path.to_string(),
    }
}

pub fn sshpass_available() -> bool {
    crate::tunnel::which_bin("sshpass").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> SshHost {
        SshHost {
            name: "h".into(),
            group: String::new(),
            host: "example.com".into(),
            port: 22,
            username: String::new(),
            key_path: String::new(),
            password: String::new(),
            skip_host_key_check: false,
            extra_args: String::new(),
            depends_on: String::new(),
            requires_vpn: String::new(),
        }
    }

    #[test]
    fn default_port_and_user_stay_off_the_command_line() {
        assert_eq!(build_args(&host()), vec!["example.com".to_string()]);
    }

    #[test]
    fn user_port_key_and_extra_args_are_passed() {
        let h = SshHost {
            username: "root".into(),
            port: 2222,
            key_path: "/keys/id_ed25519".into(),
            extra_args: "-A".into(),
            ..host()
        };
        assert_eq!(
            build_args(&h),
            vec![
                "-p",
                "2222",
                "-i",
                "/keys/id_ed25519",
                "-o",
                "IdentitiesOnly=yes",
                "-A",
                "root@example.com",
            ]
        );
    }

    #[test]
    fn skipping_host_key_verification_disables_both_checks() {
        let h = SshHost {
            skip_host_key_check: true,
            ..host()
        };
        let args = build_args(&h);
        assert!(args.contains(&"StrictHostKeyChecking=no".to_string()));
        assert!(args.contains(&"UserKnownHostsFile=/dev/null".to_string()));
    }

    #[test]
    fn a_windowed_session_script_quotes_what_the_shell_would_eat() {
        let h = SshHost {
            extra_args: "-o ProxyCommand=none".into(),
            ..host()
        };
        let script = session_script(&h);
        assert!(script.starts_with("ssh -o ProxyCommand=none example.com;"));
        // The window stays up after a failure so the error can be read.
        assert!(script.contains("read -r _"));
    }

    #[test]
    fn a_password_goes_into_the_window_through_the_environment() {
        let h = SshHost {
            password: "hunter2".into(),
            ..host()
        };
        let script = session_script(&h);
        assert!(script.starts_with("sshpass -e ssh"));
        assert!(!script.contains("hunter2"));
    }

    #[test]
    fn quoting_survives_spaces_and_quotes() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote("/home/me/id rsa"), "'/home/me/id rsa'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    /// Run a windowed launch against a stand-in "terminal" that only records
    /// what it was handed, and give back (recorded argument, SSHPASS seen).
    fn record_launch(host: &SshHost, term: Terminal, out: &std::path::Path) -> String {
        let mut session = spawn_windowed(host, &term).expect("spawning the stand-in terminal");
        for _ in 0..200 {
            if session.poll().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::read_to_string(out).unwrap_or_default()
    }

    #[test]
    fn a_terminal_without_a_placeholder_gets_the_script_appended() {
        let out = std::env::temp_dir().join("controlcenter-launch-append");
        let _ = std::fs::remove_file(&out);
        let term = Terminal {
            program: "sh".into(),
            // The launcher appends `sh -c <script>`, so the script is $2 here.
            args: vec!["-c".into(), format!("printf '%s' \"$2\" > {}", out.display())],
        };
        let recorded = record_launch(&host(), term, &out);
        assert!(recorded.starts_with("ssh example.com;"), "got {recorded}");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn a_placeholder_takes_the_script_wherever_it_sits() {
        let out = std::env::temp_dir().join("controlcenter-launch-placeholder");
        let _ = std::fs::remove_file(&out);
        let term = Terminal {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("printf '%s' \"$0\" > {}", out.display()),
                "{cmd}".into(),
            ],
        };
        let recorded = record_launch(&host(), term, &out);
        assert!(recorded.starts_with("ssh example.com;"), "got {recorded}");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn the_window_reads_the_password_from_the_environment() {
        let out = std::env::temp_dir().join("controlcenter-launch-env");
        let _ = std::fs::remove_file(&out);
        let h = SshHost {
            password: "hunter2".into(),
            ..host()
        };
        let term = Terminal {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("printf '%s' \"$SSHPASS\" > {}", out.display()),
            ],
        };
        assert_eq!(record_launch(&h, term, &out), "hunter2");
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn the_launch_preference_picks_the_mode() {
        assert_eq!(resolve_launch("inline"), Launch::Inline);
        assert_eq!(
            resolve_launch("alacritty -e"),
            Launch::Window(Terminal {
                program: "alacritty".into(),
                args: vec!["-e".into()],
            })
        );
    }

    #[test]
    fn stored_password_never_appears_in_the_preview() {
        let h = SshHost {
            password: "hunter2".into(),
            ..host()
        };
        let preview = command_preview(&h);
        assert!(!preview.contains("hunter2"));
        assert!(preview.starts_with("sshpass -e ssh"));
    }
}
