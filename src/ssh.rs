use crate::platform;
use crate::types::SshHost;
use anyhow::{Context, Result};
use std::path::PathBuf;
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
    let mut args = connection_args(host);
    args.push(host.destination());
    args
}

/// Everything a host says about *how* to reach it — port, key, host-key
/// handling, its own extra args — without the destination itself.
///
/// Split out because a tunnel riding this host puts its own forward and extra
/// args between the two, and there must be one function that decides what a
/// configured host turns into on a command line.
pub fn connection_args(host: &SshHost) -> Vec<String> {
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
        args.push(format!("UserKnownHostsFile={}", platform::NULL_DEVICE));
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
    args
}

/// The same options for the file-transfer clients. `sftp` and `scp` take
/// everything ssh does bar the port, which they spell `-P` because `-p` means
/// "preserve the timestamps" to them.
///
/// Derived from [`connection_args`] rather than written out again, so a field
/// added to `SshHost` reaches a transfer along with everything else. The flag
/// is swapped by position — it is the one this function put there — and never
/// by search, because `extra_args` is free text and may hold a `-p` of its own.
pub fn transfer_args(host: &SshHost) -> Vec<String> {
    let mut args = connection_args(host);
    if host.port != 22 && args.first().map(String::as_str) == Some("-p") {
        args[0] = "-P".into();
    }
    args
}

/// The command line as the user would type it, for the details panel.
/// A stored password is never shown — it goes through the environment.
pub fn command_preview(host: &SshHost, helper: &PasswordHelper) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !host.password.is_empty() && *helper == PasswordHelper::Sshpass {
        parts.push("sshpass".into());
        parts.push("-e".into());
    }
    parts.push("ssh".into());
    parts.extend(build_args(host));
    parts.join(" ")
}

/// Run ssh attached to the current terminal and wait for it to finish.
/// The caller must have left the alternate screen and raw mode first.
pub fn run_interactive(host: &SshHost, helper: &PasswordHelper) -> Result<SessionOutcome> {
    let args = build_args(host);
    let started = Instant::now();

    let sshpass = !host.password.is_empty() && *helper == PasswordHelper::Sshpass;
    let mut cmd = if sshpass {
        // -e reads the password from SSHPASS so it never lands in the process
        // list, where any user on the box could read it.
        let mut c = Command::new(platform::program("sshpass"));
        c.arg("-e").arg("ssh").args(&args);
        c
    } else {
        let mut c = Command::new(platform::program("ssh"));
        c.args(&args);
        c
    };
    carry_password(&mut cmd, &host.password, helper);

    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            if sshpass {
                "spawning sshpass (is sshpass installed?)".to_string()
            } else {
                "spawning ssh".to_string()
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
// Getting a stored password to ssh
// ---------------------------------------------------------------------------

/// How a stored password reaches ssh without ever being an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordHelper {
    /// `sshpass -e`, which reads it out of `SSHPASS` in the environment. The
    /// Unix answer, and the one used wherever sshpass is installed.
    Sshpass,
    /// controlcenter answers ssh's own prompt: ssh runs the program named by
    /// `SSH_ASKPASS` when it wants a password, and the program named is this
    /// one, re-run with `CONTROLCENTER_ASKPASS` set. It reads the password out
    /// of the same `SSHPASS` variable and prints it.
    ///
    /// This is what Windows uses, where sshpass — a Unix program built around
    /// pseudo-terminals — does not exist and cannot. It is also the fallback on
    /// a Unix box that simply has not got sshpass installed.
    Askpass(PathBuf),
    /// Nothing here can carry it; ssh will ask the user itself.
    None,
}

impl PasswordHelper {
    /// What the details panel says a stored password is done with.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sshpass => "passed to ssh through sshpass",
            Self::Askpass(_) => "answered at ssh's own prompt, through SSH_ASKPASS",
            Self::None => "not usable — ssh will ask for it",
        }
    }

    pub fn usable(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Which helper this machine can use. sshpass first where it exists: it is what
/// the Unix half has always used and what a user's own scripts expect.
pub fn password_helper() -> PasswordHelper {
    if platform::which_bin("sshpass").is_some() {
        return PasswordHelper::Sshpass;
    }
    match std::env::current_exe() {
        Ok(exe) => PasswordHelper::Askpass(exe),
        Err(_) => PasswordHelper::None,
    }
}

/// The environment variable ssh's askpass helper reads the password out of.
/// The same name sshpass uses, because it means the same thing.
pub const PASSWORD_ENV: &str = "SSHPASS";

/// Set on the child so that a controlcenter started by ssh knows it is being
/// asked for a password rather than being started by a person.
pub const ASKPASS_ENV: &str = "CONTROLCENTER_ASKPASS";

/// Put the password where the chosen helper will find it, and — for askpass —
/// point ssh at the helper. Never an argument, on either path.
pub fn carry_password(cmd: &mut Command, password: &str, helper: &PasswordHelper) {
    if password.is_empty() {
        return;
    }
    cmd.env(PASSWORD_ENV, password);
    if let PasswordHelper::Askpass(exe) = helper {
        cmd.env("SSH_ASKPASS", exe);
        // Without `force`, ssh only reaches for the helper when it has no
        // terminal to ask at — and an inline session has one.
        cmd.env("SSH_ASKPASS_REQUIRE", "force");
        cmd.env(ASKPASS_ENV, "1");
    }
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
///
/// Windows has one entry and needs no more: `cmd.exe` is always there, and a
/// child given a console of its own *is* a new window — see [`spawn_windowed`].
/// A user who would rather have Windows Terminal says so in `ssh.terminal`,
/// e.g. `wt.exe cmd /C {cmd}`.
#[cfg(not(windows))]
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

#[cfg(windows)]
const TERMINALS: &[(&str, &[&str])] = &[("cmd", &["/C", "{cmd}"])];

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
            if crate::platform::which_bin(&t.program).is_some() {
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
        .find(|(bin, _)| crate::platform::which_bin(bin).is_some())
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

/// The command the window runs: ssh, and on failure a pause so the error is
/// still readable after the session dies.
///
/// Two dialects, because the window is a shell's and the shells do not agree —
/// on how a status is read back, on how a line is held, or on what a quote
/// means. Both say the same thing.
fn session_script(host: &SshHost, helper: &PasswordHelper) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !host.password.is_empty() && *helper == PasswordHelper::Sshpass {
        parts.push("sshpass".into());
        parts.push("-e".into());
    }
    parts.push("ssh".into());
    parts.extend(build_args(host).iter().map(|a| shell_quote(a)));
    let cmd = parts.join(" ");

    #[cfg(not(windows))]
    {
        format!(
            "{cmd}; s=$?; if [ \"$s\" -ne 0 ]; then printf '\\n[controlcenter] ssh exited %s — press Enter to close ' \"$s\"; read -r _; fi; exit $s"
        )
    }
    #[cfg(windows)]
    {
        // `||` runs the right-hand side only on a non-zero exit, which is the
        // whole of what the shell form above does with $?.
        format!("{cmd} || (echo. & echo [controlcenter] ssh failed & pause)")
    }
}

/// Quote an argument for the shell the window runs.
#[cfg(not(windows))]
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

/// cmd.exe has no escape character inside a quoted string and no way to put a
/// literal `"` in one, so an argument that needs quoting gets quoted and one
/// that contains a quote gets it dropped — an ssh argument never legitimately
/// carries one, and a silently mangled command line is better than a window
/// that runs something else.
#[cfg(windows)]
fn shell_quote(arg: &str) -> String {
    let arg = arg.replace('"', "");
    if !arg.is_empty() && !arg.chars().any(|c| c.is_whitespace() || "&|<>^()%!".contains(c)) {
        return arg;
    }
    format!("\"{arg}\"")
}

/// Open the session in its own window and return immediately.
///
/// The `{cmd}` placeholder is where the script goes; a terminal that names no
/// placeholder is handed the command as `sh -c <script>` on Unix, and the line
/// itself on Windows, where the terminal is a shell rather than an emulator
/// that runs one.
pub fn spawn_windowed(
    host: &SshHost,
    term: &Terminal,
    helper: &PasswordHelper,
) -> Result<WindowSession> {
    let script = session_script(host, helper);
    let mut cmd = Command::new(platform::program(&term.program));
    let mut placed = false;
    for arg in &term.args {
        if arg.contains("{cmd}") {
            place_script(&mut cmd, &arg.replace("{cmd}", &script));
            placed = true;
        } else {
            cmd.arg(arg);
        }
    }
    if !placed {
        #[cfg(not(windows))]
        {
            cmd.arg("sh").arg("-c").arg(&script);
        }
        #[cfg(windows)]
        {
            place_script(&mut cmd, &script);
        }
    }
    carry_password(&mut cmd, &host.password, helper);
    // A console of its own is what makes this a window on Windows; elsewhere
    // the emulator opens one and this is not a thing that exists.
    #[cfg(windows)]
    {
        platform::new_console(&mut cmd);
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

/// Hand a whole command line to the terminal.
///
/// cmd.exe parses `/C` by its own rules and Rust's argument quoting — written
/// for programs that use `CommandLineToArgvW` — mangles what it gets, so on
/// Windows the line crosses raw and the quoting done in [`shell_quote`] is the
/// only quoting there is.
fn place_script(cmd: &mut Command, script: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.raw_arg(script);
    }
    #[cfg(not(windows))]
    {
        cmd.arg(script);
    }
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match platform::home() {
            Some(home) => home.join(rest).to_string_lossy().into_owned(),
            None => path.to_string(),
        },
        None => path.to_string(),
    }
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
            remote_dir: String::new(),
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
    fn a_transfer_gets_the_same_options_with_the_port_flag_sftp_understands() {
        let h = SshHost {
            port: 2222,
            key_path: "/keys/id_ed25519".into(),
            // A `-p` of the user's own must not be mistaken for the port flag.
            extra_args: "-o Compression=yes -p".into(),
            ..host()
        };
        assert_eq!(
            transfer_args(&h),
            vec![
                "-P",
                "2222",
                "-i",
                "/keys/id_ed25519",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "Compression=yes",
                "-p",
            ]
        );
        // A default port is not on the command line at all, so nothing is swapped.
        assert_eq!(transfer_args(&host()), Vec::<String>::new());
    }

    #[test]
    fn skipping_host_key_verification_disables_both_checks() {
        let h = SshHost {
            skip_host_key_check: true,
            ..host()
        };
        let args = build_args(&h);
        assert!(args.contains(&"StrictHostKeyChecking=no".to_string()));
        assert!(args
            .iter()
            .any(|a| a.starts_with("UserKnownHostsFile=") && a.ends_with(platform::NULL_DEVICE)));
    }

    #[test]
    fn a_windowed_session_script_quotes_what_the_shell_would_eat() {
        let h = SshHost {
            extra_args: "-o ProxyCommand=none".into(),
            ..host()
        };
        let script = session_script(&h, &PasswordHelper::Sshpass);
        assert!(script.starts_with("ssh -o ProxyCommand=none example.com"));
        // The window stays up after a failure so the error can be read.
        assert!(script.contains(if cfg!(windows) { "pause" } else { "read -r _" }));
    }

    #[test]
    fn a_password_goes_into_the_window_through_the_environment() {
        let h = SshHost {
            password: "hunter2".into(),
            ..host()
        };
        let script = session_script(&h, &PasswordHelper::Sshpass);
        assert!(script.starts_with("sshpass -e ssh"));
        assert!(!script.contains("hunter2"));

        // With no sshpass to wrap it, ssh is run directly and answers its own
        // prompt — but the password is still nowhere near the command line.
        let askpass = PasswordHelper::Askpass(std::path::PathBuf::from("/opt/controlcenter"));
        let script = session_script(&h, &askpass);
        assert!(script.starts_with("ssh "));
        assert!(!script.contains("hunter2"));
    }

    #[test]
    #[cfg(not(windows))]
    fn quoting_survives_spaces_and_quotes() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote("/home/me/id rsa"), "'/home/me/id rsa'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    #[cfg(windows)]
    fn quoting_survives_what_cmd_would_otherwise_eat() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote(r"C:\Users\me\id rsa"), "\"C:\\Users\\me\\id rsa\"");
        // `&` starts a second command as far as cmd is concerned.
        assert_eq!(shell_quote("a&b"), "\"a&b\"");
    }

    /// Run a windowed launch against a stand-in "terminal" that only records
    /// what it was handed, and give back (recorded argument, SSHPASS seen).
    ///
    /// The stand-in is `sh`, so these three cover the Unix launch path only —
    /// cmd.exe takes its line by a different route entirely (see
    /// [`place_script`]) and there is no shell common to both to write them in.
    #[cfg(not(windows))]
    fn record_launch(host: &SshHost, term: Terminal, out: &std::path::Path) -> String {
        let mut session = spawn_windowed(host, &term, &PasswordHelper::Sshpass)
            .expect("spawning the stand-in terminal");
        for _ in 0..200 {
            if session.poll().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::read_to_string(out).unwrap_or_default()
    }

    #[test]
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
    #[cfg(not(windows))]
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
        let preview = command_preview(&h, &PasswordHelper::Sshpass);
        assert!(!preview.contains("hunter2"));
        assert!(preview.starts_with("sshpass -e ssh"));
        // Nothing to wrap ssh with means nothing is claimed to wrap it.
        let preview = command_preview(&h, &PasswordHelper::None);
        assert!(preview.starts_with("ssh "));
        assert!(!preview.contains("hunter2"));
    }
}
