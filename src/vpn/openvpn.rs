//! OpenVPN as a managed child process.
//!
//! Unlike the other providers there is no daemon to ask for status: an OpenVPN
//! connection *is* the process, so a session is owned the same way an RDP session
//! is — a child, a tailed log, and a status derived from both.
//!
//! The process runs as root via pkexec, which means the unprivileged TUI cannot
//! signal it: `child.kill()` only ever reaches pkexec. That is why openvpn is
//! started with `--writepid` and stopped by an escalated `kill`.

use super::{privileged, scan};
use crate::logs::Ring;
use crate::types::OpenvpnProfile;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// openvpn says this once, and only once the tunnel is actually usable.
const CONNECTED_MARKER: &str = "Initialization Sequence Completed";
const AUTH_FAILED_MARKER: &str = "AUTH_FAILED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OvpnStatus {
    Connecting,
    Connected,
    Exited(i32),
}

impl OvpnStatus {
    pub fn label(self) -> String {
        match self {
            Self::Connecting => "connecting".into(),
            Self::Connected => "connected".into(),
            Self::Exited(0) => "stopped".into(),
            Self::Exited(c) => format!("exited ({c})"),
        }
    }
}

pub struct ActiveOvpn {
    child: Child,
    pub status: OvpnStatus,
    pub started_at: Instant,
    pub log: Arc<Ring>,
    /// The command line the session was started with, for the log pane and the
    /// report it exports. openvpn runs as root, so this is what pkexec was
    /// handed rather than a shell command anyone could repeat.
    pub argv: Vec<String>,
    /// Set once openvpn reports the tunnel is up.
    connected: Arc<Mutex<bool>>,
    /// Set when openvpn reports something the user has to fix, e.g. bad
    /// credentials — otherwise a wrong password just looks like "exited (1)".
    fault: Arc<Mutex<Option<String>>>,
    /// The interface openvpn said it opened. Read as the log goes past rather
    /// than searched for afterwards — see [`ActiveOvpn::device`].
    device: Arc<Mutex<Option<String>>>,
    /// Where openvpn wrote the pid of the process that actually holds the tunnel.
    pid_file: PathBuf,
    /// The `.ovpn` this session is running. Kept so the process can still be
    /// found when the pid file cannot be read — see [`ActiveOvpn::holders`].
    config: PathBuf,
}

/// Tail the child's output, and pick the two lines out of it that mean something.
fn tail_lines(
    reader: impl Read + Send + 'static,
    log: Arc<Ring>,
    connected: Arc<Mutex<bool>>,
    fault: Arc<Mutex<Option<String>>>,
    device: Arc<Mutex<Option<String>>>,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains(CONNECTED_MARKER) {
                *connected.lock().unwrap() = true;
            }
            if let Some(fatal) = fault_in(trimmed) {
                *fault.lock().unwrap() = Some(fatal);
            }
            if let Some(dev) = device_in_line(trimmed) {
                *device.lock().unwrap() = Some(dev.to_string());
            }
            log.push(trimmed);
        }
    });
}

/// The log lines that mean "this will not work until you change something".
fn fault_in(line: &str) -> Option<String> {
    if line.contains(AUTH_FAILED_MARKER) {
        return Some("authentication failed — check the username and password".into());
    }
    if line.contains("Cannot resolve host address") {
        return Some("the remote host could not be resolved".into());
    }
    if line.contains("TLS Error: TLS handshake failed") {
        return Some("TLS handshake failed — check the certificates in the config".into());
    }
    None
}

/// The openvpn argv for a profile.
///
/// Credentials never appear here. `--auth-user-pass /dev/stdin` makes openvpn
/// read them from the pipe we hold, the same shape as the RDP `/from-stdin`
/// handling, so they stay out of the process list and off disk. Note that this
/// rules out `--auth-nocache`: openvpn has to keep them in memory, because on
/// renegotiation there is no stdin left to read them from a second time.
///
/// `--cd` is what makes the certificates resolve: openvpn reads paths in a
/// config relative to the working directory, not to the config file, so it is
/// pointed at the directory the config lives in.
///
/// The credentials go through a pipe where there is one to go through. Windows
/// has no `/dev/stdin` for a program to open, and openvpn there reads a console
/// rather than a handed-down stdin, so the only way in that does not put them on
/// a command line is a file — written 0600-equivalent in a directory only its
/// owner can open, and unlinked the moment openvpn has read it. See
/// [`auth_file`] and [`write_auth_file`].
///
/// `--verb` and `--mute` come *after* `--config` on purpose. openvpn applies
/// options in the order it reads them, so anything meant to override the
/// profile's own settings has to follow the `--config` that pulls them in.
/// `--mute 0` is not cosmetic: a profile carrying `mute 20` suppresses whole
/// runs of consecutive status lines, and [`CONNECTED_MARKER`] is one of the
/// lines that gets swallowed — leaving a tunnel that is genuinely up looking
/// stuck at "connecting" forever. Muting is turned off for the log we parse.
pub fn build_args(p: &OpenvpnProfile, config: &Path, pid_file: &Path) -> Vec<String> {
    let mut args = vec!["openvpn".to_string()];
    if let Some(dir) = config.parent().filter(|d| !d.as_os_str().is_empty()) {
        args.push("--cd".into());
        args.push(dir.to_string_lossy().into_owned());
    }
    args.extend([
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
        "--writepid".into(),
        pid_file.to_string_lossy().into_owned(),
        "--verb".into(),
        "3".into(),
        "--mute".into(),
        "0".into(),
    ]);
    if !p.username.is_empty() {
        args.push("--auth-user-pass".into());
        args.push(match auth_file(pid_file) {
            Some(path) => path.to_string_lossy().into_owned(),
            None => "/dev/stdin".to_string(),
        });
    }
    args.extend(p.extra_args.split_whitespace().map(String::from));
    args
}

/// Where openvpn is told to read the credentials from, when that is a file
/// rather than a pipe. Derived from the pid file so a report can name it
/// without a session having been started.
///
/// `None` means the pipe, which is what every system with a `/dev/stdin` uses.
#[cfg(windows)]
pub fn auth_file(pid_file: &Path) -> Option<PathBuf> {
    Some(pid_file.with_extension("auth"))
}

#[cfg(not(windows))]
pub fn auth_file(_pid_file: &Path) -> Option<PathBuf> {
    None
}

/// Write the credentials openvpn will read, and take them away again.
///
/// The file is two lines, the format openvpn's `--auth-user-pass <file>`
/// expects. It is written into the run directory, which is locked to its owner,
/// and removed once openvpn has had time to read it — openvpn reads it while it
/// starts and keeps what it found in memory, so it does not have to outlive the
/// launch, and holding a password it should not.
#[cfg(windows)]
fn write_auth_file(path: &Path, username: &str, password: &str) -> Result<(), String> {
    std::fs::write(path, format!("{username}\n{password}\n"))
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    super::restrict_file(path)
}

#[cfg(windows)]
fn sweep_auth_file(path: PathBuf) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let _ = std::fs::remove_file(path);
    });
}

// ---------------------------------------------------------------------------
// Importing a profile and the files it ships with
// ---------------------------------------------------------------------------

/// Config directives whose argument names a file openvpn has to read.
///
/// A downloaded profile is almost always a `.ovpn` plus a handful of these —
/// `ca.crt`, `client.crt`, `client.key`, `ta.key` — sitting next to it, so
/// pointing at the download folder means the profile breaks as soon as that
/// folder is tidied away. Importing copies every one of them in.
const FILE_DIRECTIVES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "extra-certs",
    "dh",
    "pkcs12",
    "secret",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "crl-verify",
    "askpass",
    "auth-user-pass",
    "http-proxy-user-pass",
];

/// What openvpn writes in place of a filename when the file is inlined instead.
const INLINE_MARKER: &str = "[inline]";

/// One file the config points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referenced {
    /// The directive that named it, for the message and for disambiguating.
    pub directive: String,
    /// As written in the config.
    pub original: String,
    /// Where it was found, if it was.
    pub source: Option<PathBuf>,
    /// The bare name it is stored under inside the profile directory.
    pub stored_as: String,
}

/// A `.ovpn` rewritten to stand on its own, plus the files to bring with it.
#[derive(Debug, Clone, Default)]
pub struct Import {
    /// The config with every file reference rewritten to a bare name.
    pub config: String,
    pub files: Vec<Referenced>,
}

impl Import {
    /// Files the config names that are nowhere to be found. openvpn would fail
    /// on these, so it is worth saying so at import time rather than at connect.
    pub fn missing(&self) -> Vec<&Referenced> {
        self.files.iter().filter(|f| f.source.is_none()).collect()
    }

    pub fn found(&self) -> usize {
        self.files.iter().filter(|f| f.source.is_some()).count()
    }
}

/// Split a config line into tokens, honouring the double quotes openvpn allows
/// around paths that contain spaces.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has_token = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

fn requote(token: &str) -> String {
    if token.contains(char::is_whitespace) {
        format!("\"{token}\"")
    } else {
        token.to_string()
    }
}

/// `crl-verify <path> dir` names a directory, not a file.
fn names_a_directory(directive: &str, tokens: &[String]) -> bool {
    directive == "crl-verify" && tokens.get(2).map(String::as_str) == Some("dir")
}

/// Work out what a config would have to bring with it to stand on its own.
/// Nothing is read or written here, so this is testable on a string alone.
pub fn plan_import(config: &str, source_dir: &Path) -> Import {
    let mut out = String::with_capacity(config.len());
    let mut files: Vec<Referenced> = Vec::new();
    let mut used: Vec<String> = Vec::new();
    // Inline `<ca>…</ca>` blocks are already self-contained; copy them through
    // untouched and never treat their contents as directives.
    let mut inline_block: Option<String> = None;

    for line in config.lines() {
        let trimmed = line.trim();

        if let Some(open) = &inline_block {
            out.push_str(line);
            out.push('\n');
            if trimmed == format!("</{open}>") {
                inline_block = None;
            }
            continue;
        }
        if trimmed.starts_with('<') && trimmed.ends_with('>') && !trimmed.starts_with("</") {
            inline_block = Some(trimmed[1..trimmed.len() - 1].to_string());
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let tokens = tokenize(trimmed);
        let directive = tokens.first().map(String::as_str).unwrap_or("");
        // `--ca foo` is as valid as `ca foo` in a config file.
        let name = directive.trim_start_matches("--");

        let is_comment = trimmed.starts_with('#') || trimmed.starts_with(';');
        let referenced = !is_comment
            && FILE_DIRECTIVES.contains(&name)
            && tokens.len() > 1
            && tokens[1] != INLINE_MARKER
            && !names_a_directory(name, &tokens);

        if !referenced {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let original = tokens[1].clone();
        let base = Path::new(&original)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| original.clone());
        // Two directives can name different files with the same basename.
        let stored_as = if used.contains(&base) {
            format!("{name}-{base}")
        } else {
            base
        };
        used.push(stored_as.clone());

        let candidate = if Path::new(&original).is_absolute() {
            PathBuf::from(&original)
        } else {
            source_dir.join(&original)
        };
        let source = candidate.is_file().then_some(candidate);

        // Rewrite the line to the bare name, keeping whatever followed it —
        // `tls-auth ta.key 1` has to keep its direction argument.
        let mut rebuilt = vec![directive.to_string(), requote(&stored_as)];
        rebuilt.extend(tokens[2..].iter().map(|t| requote(t)));
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        out.push_str(&indent);
        out.push_str(&rebuilt.join(" "));
        out.push('\n');

        files.push(Referenced {
            directive: name.to_string(),
            original,
            source,
            stored_as,
        });
    }

    Import { config: out, files }
}

/// Copy `source` and everything it references into `dir`, which controlcenter
/// then owns. Returns what came with it.
pub fn import_into(source: &Path, dir: &Path, config_name: &str) -> Result<Import, String> {
    let raw = std::fs::read_to_string(source)
        .map_err(|e| format!("reading {}: {e}", source.display()))?;
    let source_dir = source.parent().unwrap_or(Path::new("."));
    let plan = plan_import(&raw, source_dir);

    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    super::restrict_dir(dir)?;

    for file in &plan.files {
        let Some(from) = &file.source else { continue };
        let to = dir.join(&file.stored_as);
        // Copying onto itself would truncate the file being read.
        if from == &to {
            continue;
        }
        std::fs::copy(from, &to).map_err(|e| format!("copying {}: {e}", from.display()))?;
        super::restrict_file(&to)?;
    }

    let config_path = dir.join(config_name);
    std::fs::write(&config_path, &plan.config)
        .map_err(|e| format!("writing {}: {e}", config_path.display()))?;
    super::restrict_file(&config_path)?;

    Ok(plan)
}

impl OpenvpnProfile {
    /// Where controlcenter keeps its own copy of this profile.
    pub fn dir(&self, base: &Path) -> PathBuf {
        base.join(&self.name)
    }

    /// The `.ovpn` openvpn is actually handed: the imported copy, or the
    /// original when the profile is left where it sits.
    pub fn runtime_config(&self, base: &Path) -> PathBuf {
        if self.import {
            self.dir(base).join(Self::CONFIG_NAME)
        } else {
            PathBuf::from(&self.config_path)
        }
    }

    /// Every imported profile's config has the same name, so the directory is
    /// self-describing whatever the download was called.
    pub const CONFIG_NAME: &'static str = "config.ovpn";

    /// What the profile list shows next to the name.
    pub fn summary(&self, base: &Path) -> String {
        if self.import {
            match std::fs::read_dir(self.dir(base)) {
                // The config itself is not a file it "came with".
                Ok(entries) => match entries.count().saturating_sub(1) {
                    0 => "imported".to_string(),
                    n => format!("imported +{n} file(s)"),
                },
                Err(_) => "not imported yet".to_string(),
            }
        } else {
            self.config_path.clone()
        }
    }
}

/// Remove the directory controlcenter imported a profile into.
pub fn remove_import(p: &OpenvpnProfile, base: &Path) {
    if p.import && !p.name.is_empty() {
        let _ = std::fs::remove_dir_all(p.dir(base));
    }
}

pub fn pid_file_for(name: &str, dir: &Path) -> PathBuf {
    dir.join(format!("openvpn-{name}.pid"))
}

/// Start a session. The config file is read by openvpn itself, as root.
pub fn spawn(p: &OpenvpnProfile, base: &Path, run_dir: &Path) -> Result<ActiveOvpn, String> {
    if p.config_path.is_empty() {
        return Err("no config file set for this profile".into());
    }
    let config = p.runtime_config(base);
    if !config.exists() {
        return Err(if p.import {
            format!(
                "{} has not been imported yet — edit the profile and save it again",
                p.name
            )
        } else {
            format!("{} does not exist", config.display())
        });
    }
    std::fs::create_dir_all(run_dir).map_err(|e| format!("creating {}: {e}", run_dir.display()))?;
    let pid_file = pid_file_for(&p.name, run_dir);
    let _ = std::fs::remove_file(&pid_file);

    let argv = build_args(p, &config, &pid_file);
    #[cfg(windows)]
    {
        if !p.username.is_empty() {
            if let Some(auth) = auth_file(&pid_file) {
                write_auth_file(&auth, &p.username, &p.password)?;
                sweep_auth_file(auth);
            }
        }
    }
    let mut cmd = privileged::command(&argv)?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning openvpn: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        // Only where openvpn was pointed at the pipe; where it was pointed at a
        // file, this just closes so it cannot sit on a further prompt.
        if !p.username.is_empty() && auth_file(&pid_file).is_none() {
            let _ = writeln!(stdin, "{}", p.username);
            let _ = writeln!(stdin, "{}", p.password);
        }
    }

    let log = Arc::new(Ring::new("openvpn"));
    let connected = Arc::new(Mutex::new(false));
    let fault = Arc::new(Mutex::new(None));
    let device = Arc::new(Mutex::new(None));
    if let Some(stdout) = child.stdout.take() {
        tail_lines(
            stdout,
            Arc::clone(&log),
            Arc::clone(&connected),
            Arc::clone(&fault),
            Arc::clone(&device),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        tail_lines(
            stderr,
            Arc::clone(&log),
            Arc::clone(&connected),
            Arc::clone(&fault),
            Arc::clone(&device),
        );
    }

    Ok(ActiveOvpn {
        child,
        status: OvpnStatus::Connecting,
        started_at: Instant::now(),
        log,
        argv,
        connected,
        fault,
        device,
        pid_file,
        config,
    })
}

impl ActiveOvpn {
    /// Called once per tick: promote to connected, or notice the process is gone.
    pub fn poll(&mut self) {
        if matches!(self.status, OvpnStatus::Exited(_)) {
            return;
        }
        if let Ok(Some(status)) = self.child.try_wait() {
            let code = status.code().unwrap_or(-1);
            self.status = OvpnStatus::Exited(code);
            self.log.push(format!("── openvpn exited ({code}) ──"));
            let _ = std::fs::remove_file(&self.pid_file);
            return;
        }
        if *self.connected.lock().unwrap() {
            self.status = OvpnStatus::Connected;
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self.status, OvpnStatus::Connected)
    }

    /// Why the session will not come up, when openvpn said so plainly.
    pub fn fault(&self) -> Option<String> {
        self.fault.lock().unwrap().clone()
    }

    /// The file openvpn was told to write its pid into. Identifies the session
    /// from the outside: a process carrying this `--writepid` is this session,
    /// whether or not it has got round to writing the file yet.
    pub fn pid_file(&self) -> &Path {
        &self.pid_file
    }

    /// The pid openvpn wrote, i.e. the root process actually holding the tunnel.
    pub fn root_pid(&self) -> Option<u32> {
        std::fs::read_to_string(&self.pid_file)
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Every process holding this session's tunnel.
    ///
    /// Normally exactly one, and normally the pid `--writepid` left behind. The
    /// pid file is not enough on its own: openvpn writes it a moment after it
    /// starts, so a session cancelled during connect has none, and a session
    /// that restarted itself can leave a stale one. `/proc` is asked as well
    /// and anything running this session's config, or writing this session's
    /// pid file, is counted — the whole point of stopping is that nothing is
    /// left behind, so this errs towards finding one process too many rather
    /// than one too few.
    pub fn holders(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = Vec::new();
        if let Some(pid) = self.root_pid().filter(|p| alive(*p)) {
            pids.push(pid);
        }
        for p in scan::scan().processes_of(crate::vpn::ProviderId::Openvpn) {
            let same_config = p.config().is_some_and(|c| Path::new(c) == self.config);
            let same_pid_file = p.pid_file().is_some_and(|f| Path::new(f) == self.pid_file);
            if (same_config || same_pid_file) && !pids.contains(&p.pid) {
                pids.push(p.pid);
            }
        }
        pids
    }

    /// Stop the session. The tunnel process runs as root, so killing our own
    /// child would only take down pkexec and leave the tunnel up; the pids are
    /// signalled through the escalation helper instead.
    ///
    /// A `SIGTERM` that is not obeyed is followed by a `SIGKILL`: an openvpn
    /// left running is not a cosmetic failure, it keeps holding the server's
    /// slot and the next connection to the same profile gets thrown off it
    /// every couple of minutes by the one that is still there.
    pub fn stop(&mut self) -> Option<String> {
        let pids = self.holders();
        for pid in &pids {
            let argv = kill_argv(*pid, false);
            self.log.push(format!("── stopping: {} ──", argv.join(" ")));
            if let Err(e) = privileged::run(&argv) {
                // Not a failure yet. A process that will not close politely is
                // exactly what the forceful stop below is for — and on Windows
                // a console program with no window refuses this one by design.
                // What went wrong is written down; whether it stopped is
                // decided after.
                self.log.push(format!("── pid {pid}: {e} ──"));
            }
        }
        // Always tear down our own side, so a dismissed prompt cannot leave a
        // half-dead session in the list.
        let _ = self.child.kill();
        let _ = self.child.wait();

        let mut err = None;
        for pid in pids {
            if let Some(e) = wait_out_or_kill(pid, &self.log) {
                err = Some(e);
            }
        }
        let _ = std::fs::remove_file(&self.pid_file);
        if !matches!(self.status, OvpnStatus::Exited(_)) {
            self.status = OvpnStatus::Exited(-1);
        }
        err
    }

    /// The last line worth showing next to the status.
    pub fn last_line(&self) -> Option<String> {
        self.log.last_text()
    }

    /// The interface this session is using.
    ///
    /// There is nowhere else to get it: `dev tun` in the config asks for the
    /// first free number rather than a name, and a device is not labelled with
    /// the process that opened it. openvpn does say which one it got, and the
    /// last thing it said is the one it is on — a reconnect can move it.
    /// Without this a live session's device would look like a leaked one.
    pub fn device(&self) -> Option<String> {
        self.device.lock().unwrap().clone()
    }
}

/// The interface named in a line of openvpn output, in any of the ways openvpn
/// has of naming it.
fn device_in_line(line: &str) -> Option<&str> {
    let after = |marker: &str| {
        line.split_once(marker)
            .map(|(_, rest)| rest.trim_start())
            .and_then(|rest| rest.split([' ', ',']).next())
            .filter(|name| !name.is_empty())
    };
    // DCO: "net_iface_new: add tun2 type ovpn", "DCO device tun2 opened",
    // "ovpn-dco device [tun2] opened". Without it: "TUN/TAP device tun0
    // opened", and on a soft restart "Preserving previous TUN/TAP instance:
    // tun2".
    for marker in [
        "net_iface_new: add ",
        "DCO device ",
        "TUN/TAP device ",
        "Preserving previous TUN/TAP instance: ",
    ] {
        if let Some(name) = after(marker) {
            return Some(name);
        }
    }
    line.split_once("device [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(name, _)| name)
        .filter(|name| !name.is_empty())
}

/// Stopping a pid, built in one place so a report shows what actually ran. What
/// that command is differs per system; see [`crate::platform::kill_argv`].
pub use crate::platform::kill_argv;

use crate::platform::process_alive as alive;

/// How long the polite stop is given before the session is killed outright.
/// openvpn tears its interface down and exits well inside this; anything that
/// does not is stuck, and stuck is the case this whole path exists for.
const TERM_GRACE: Duration = Duration::from_millis(1500);

/// Wait for a signalled process to go, and kill it if it will not.
fn wait_out_or_kill(pid: u32, log: &Ring) -> Option<String> {
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if !alive(pid) {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let argv = kill_argv(pid, true);
    log.push(format!("── {pid} would not stop; forcing: {} ──", argv.join(" ")));
    if let Err(e) = privileged::run(&argv) {
        return Some(format!("pid {pid} would not stop: {e}"));
    }
    thread::sleep(Duration::from_millis(200));
    alive(pid).then(|| format!("pid {pid} is still running after being killed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> OpenvpnProfile {
        OpenvpnProfile {
            name: "work".into(),
            config_path: "/home/me/vpn/work.ovpn".into(),
            import: true,
            username: "me".into(),
            password: "hunter2".into(),
            extra_args: "--pull-filter ignore redirect-gateway".into(),
        }
    }

    fn args_of(p: &OpenvpnProfile) -> Vec<String> {
        build_args(
            p,
            Path::new("/home/me/.config/controlcenter/openvpn/work/config.ovpn"),
            Path::new("/run/user/1000/openvpn-work.pid"),
        )
    }

    #[test]
    fn credentials_never_reach_the_command_line() {
        let joined = args_of(&profile()).join(" ");
        assert!(!joined.contains("hunter2"));
        assert!(!joined.contains(" me "));
        // Through a pipe where there is one, through an owner-only file where
        // there is not — an argument in neither case.
        assert!(joined.contains("--auth-user-pass"));
        match auth_file(Path::new("/run/user/1000/openvpn-work.pid")) {
            Some(path) => assert!(joined.contains(&path.to_string_lossy().into_owned())),
            None => assert!(joined.contains("--auth-user-pass /dev/stdin")),
        }
    }

    #[test]
    fn a_profile_without_a_username_is_not_asked_for_one() {
        let p = OpenvpnProfile {
            username: String::new(),
            password: String::new(),
            ..profile()
        };
        assert!(!args_of(&p).contains(&"--auth-user-pass".to_string()));
    }

    #[test]
    fn the_config_and_pid_file_are_passed_through() {
        let args = args_of(&profile());
        assert_eq!(args[0], "openvpn");
        let joined = args.join(" ");
        assert!(joined.contains("--config /home/me/.config/controlcenter/openvpn/work/config.ovpn"));
        assert!(joined.contains("--writepid /run/user/1000/openvpn-work.pid"));
        assert!(joined.contains("--pull-filter ignore redirect-gateway"));
    }

    #[test]
    fn a_profiles_own_mute_cannot_swallow_the_line_the_status_is_read_from() {
        // A profile carrying `mute 20` suppresses runs of consecutive status
        // lines, and CONNECTED_MARKER is one of them — a tunnel that is up then
        // reads as stuck at "connecting". `--mute 0` turns that off, but only
        // if openvpn reads it after the --config that set it.
        let args = args_of(&profile());
        let at = |flag: &str| args.iter().position(|a| a == flag);
        let mute = at("--mute").expect("--mute is always passed");
        assert_eq!(args[mute + 1], "0");
        assert!(mute > at("--config").expect("--config is always passed"));
        assert!(at("--verb").expect("--verb is always passed") > at("--config").unwrap());
    }

    #[test]
    fn openvpn_is_pointed_at_the_profile_directory_so_certificates_resolve() {
        // Relative paths in a config are read against the working directory,
        // not the config's own directory, so --cd is what makes "ca ca.crt" work.
        let joined = args_of(&profile()).join(" ");
        assert!(joined.contains("--cd /home/me/.config/controlcenter/openvpn/work"));
    }

    #[test]
    fn a_profile_left_in_place_runs_the_file_it_points_at() {
        let p = OpenvpnProfile {
            import: false,
            ..profile()
        };
        let base = Path::new("/home/me/.config/controlcenter/openvpn");
        assert_eq!(
            p.runtime_config(base),
            PathBuf::from("/home/me/vpn/work.ovpn")
        );
    }

    #[test]
    fn an_imported_profile_runs_controlcenters_own_copy() {
        let base = Path::new("/home/me/.config/controlcenter/openvpn");
        assert_eq!(
            profile().runtime_config(base),
            base.join("work").join("config.ovpn")
        );
    }

    // ----- importing ------------------------------------------------------

    const SHIPPED: &str = "\
client
dev tun
remote vpn.example.com 1194 udp
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
remote-cert-tls server
verb 3
";

    fn dir() -> PathBuf {
        PathBuf::from("/home/me/Downloads/acme-vpn")
    }

    #[test]
    fn every_certificate_the_config_names_is_collected() {
        let plan = plan_import(SHIPPED, &dir());
        let names: Vec<&str> = plan.files.iter().map(|f| f.stored_as.as_str()).collect();
        assert_eq!(names, ["ca.crt", "client.crt", "client.key", "ta.key"]);
        // Nothing exists at that path, so every one is reported missing.
        assert_eq!(plan.missing().len(), 4);
        assert_eq!(plan.found(), 0);
    }

    #[test]
    fn a_rewritten_config_points_at_bare_names_and_keeps_everything_else() {
        let plan = plan_import(SHIPPED, &dir());
        assert!(plan.config.contains("\nca ca.crt\n"));
        // The direction argument after tls-auth must survive.
        assert!(plan.config.contains("\ntls-auth ta.key 1\n"));
        assert!(plan.config.contains("\nremote vpn.example.com 1194 udp\n"));
        assert!(plan.config.contains("\nremote-cert-tls server\n"));
    }

    #[test]
    fn absolute_and_nested_paths_are_flattened_to_the_profile_directory() {
        let raw = "ca /etc/openvpn/keys/ca.crt\ncert certs/client.crt\n";
        let plan = plan_import(raw, &dir());
        assert_eq!(plan.files[0].stored_as, "ca.crt");
        assert_eq!(plan.files[1].stored_as, "client.crt");
        assert!(plan.config.contains("ca ca.crt"));
        assert!(plan.config.contains("cert client.crt"));
    }

    #[test]
    fn inline_blocks_are_already_self_contained_and_are_left_alone() {
        let raw = "client\n<ca>\n-----BEGIN CERTIFICATE-----\nkey ignore-this-line\n-----END CERTIFICATE-----\n</ca>\nca [inline]\n";
        let plan = plan_import(raw, &dir());
        assert!(plan.files.is_empty(), "{:?}", plan.files);
        assert_eq!(plan.config, raw);
    }

    #[test]
    fn two_files_with_the_same_name_do_not_overwrite_each_other() {
        let raw = "ca one/shared.pem\ncert two/shared.pem\n";
        let plan = plan_import(raw, &dir());
        assert_eq!(plan.files[0].stored_as, "shared.pem");
        assert_eq!(plan.files[1].stored_as, "cert-shared.pem");
        assert!(plan.config.contains("cert cert-shared.pem"));
    }

    #[test]
    fn quoted_paths_with_spaces_survive_the_round_trip() {
        let raw = "ca \"my certs/ca file.crt\"\n";
        let plan = plan_import(raw, &dir());
        assert_eq!(plan.files[0].stored_as, "ca file.crt");
        assert!(plan.config.contains("ca \"ca file.crt\""));
    }

    #[test]
    fn a_crl_directory_is_not_mistaken_for_a_file() {
        let plan = plan_import("crl-verify /etc/openvpn/crls dir\n", &dir());
        assert!(plan.files.is_empty());
        assert_eq!(plan.config, "crl-verify /etc/openvpn/crls dir\n");
    }

    #[test]
    fn commented_out_directives_are_not_followed() {
        let plan = plan_import("# ca old-ca.crt\n;cert old.crt\nca ca.crt\n", &dir());
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].stored_as, "ca.crt");
    }

    #[test]
    fn a_bare_auth_user_pass_names_no_file() {
        // With no argument openvpn prompts; with one it reads that file.
        assert!(plan_import("auth-user-pass\n", &dir()).files.is_empty());
        assert_eq!(
            plan_import("auth-user-pass creds.txt\n", &dir()).files[0].stored_as,
            "creds.txt"
        );
    }

    #[test]
    fn importing_copies_the_config_and_its_files_and_locks_them_down() {
        let base = std::env::temp_dir().join(format!("cc-ovpn-test-{}", std::process::id()));
        let src = base.join("download");
        let dest = base.join("profile");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("work.ovpn"), SHIPPED).unwrap();
        for f in ["ca.crt", "client.crt", "client.key", "ta.key"] {
            std::fs::write(src.join(f), format!("contents of {f}")).unwrap();
        }

        let plan = import_into(&src.join("work.ovpn"), &dest, "work.ovpn").unwrap();
        assert_eq!(plan.found(), 4);
        assert!(plan.missing().is_empty());
        for f in ["ca.crt", "client.crt", "client.key", "ta.key", "work.ovpn"] {
            assert!(dest.join(f).is_file(), "{f} was not imported");
        }
        assert_eq!(
            std::fs::read_to_string(dest.join("client.key")).unwrap(),
            "contents of client.key"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(dest.join("client.key")), 0o600);
            assert_eq!(mode(dest.clone()), 0o700);
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_config_naming_files_that_are_not_there_still_imports_and_says_which() {
        let base = std::env::temp_dir().join(format!("cc-ovpn-miss-{}", std::process::id()));
        let src = base.join("download");
        let dest = base.join("profile");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("work.ovpn"), SHIPPED).unwrap();
        std::fs::write(src.join("ca.crt"), "ca").unwrap();

        let plan = import_into(&src.join("work.ovpn"), &dest, "work.ovpn").unwrap();
        assert_eq!(plan.found(), 1);
        let missing: Vec<&str> = plan
            .missing()
            .iter()
            .map(|f| f.stored_as.as_str())
            .collect();
        assert_eq!(missing, ["client.crt", "client.key", "ta.key"]);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_device_a_session_is_on_is_read_out_of_every_way_openvpn_names_it() {
        let dev = |l: &str| device_in_line(l).map(str::to_string);
        assert_eq!(dev("2026-08-26 14:17:28 net_iface_new: add tun2 type ovpn"), Some("tun2".into()));
        assert_eq!(dev("2026-08-26 14:17:28 DCO device tun2 opened"), Some("tun2".into()));
        assert_eq!(dev("2026-08-26 14:17:28 ovpn-dco device [tun2] opened"), Some("tun2".into()));
        assert_eq!(dev("Mon Aug 24 TUN/TAP device tun0 opened"), Some("tun0".into()));
        assert_eq!(
            dev("2026-08-26 14:20:23 Preserving previous TUN/TAP instance: tun2"),
            Some("tun2".into())
        );
        assert_eq!(dev("2026-08-26 14:17:28 Initialization Sequence Completed"), None);
    }

    #[test]
    fn the_connected_marker_is_the_one_openvpn_prints_when_the_tunnel_is_usable() {
        let line = "Mon Aug 24 10:00:00 2026 Initialization Sequence Completed";
        assert!(line.contains(CONNECTED_MARKER));
        assert!(fault_in(line).is_none());
    }

    #[test]
    fn the_log_lines_worth_repeating_to_the_user_are_picked_out() {
        assert!(fault_in("AUTH: Received control message: AUTH_FAILED")
            .unwrap()
            .contains("authentication failed"));
        assert!(
            fault_in("RESOLVE: Cannot resolve host address: vpn.example.com")
                .unwrap()
                .contains("could not be resolved")
        );
        assert!(fault_in("Mon Aug 24 TLS Error: TLS handshake failed").is_some());
        assert!(fault_in("Mon Aug 24 TCP connection established").is_none());
    }
}
