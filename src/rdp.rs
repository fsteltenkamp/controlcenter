//! RDP sessions.
//!
//! Two clients, because the two systems have different native answers. On Linux
//! it is `xfreerdp3`, driven entirely from its command line. On Windows it is
//! `mstsc`, the client that is already installed and already integrated with
//! the machine's displays, smart cards and printers — and which takes no
//! settings on its command line at all: everything goes into a `.rdp` file it
//! is handed.
//!
//! Neither one is given the password as an argument. xfreerdp reads it from the
//! pipe we hold (`/from-stdin`); mstsc reads it out of the `.rdp` file, where it
//! is stored the way Windows stores one — sealed with DPAPI to the account that
//! wrote it, so the file is useless to anyone else even before its ACL is
//! considered.

use crate::logs::{Entry, Ring};
use crate::types::RdpConnection;
use anyhow::{anyhow, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Which client opens a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// `xfreerdp3`, configured through its command line.
    Freerdp,
    /// Windows' own Remote Desktop Connection, configured through a `.rdp` file.
    Mstsc,
}

impl Client {
    /// What `rdp.client = "auto"` resolves to: the client the system ships.
    pub fn native() -> Self {
        if cfg!(windows) {
            Self::Mstsc
        } else {
            Self::Freerdp
        }
    }

    pub fn program(self) -> &'static str {
        match self {
            Self::Freerdp => "xfreerdp3",
            Self::Mstsc => "mstsc",
        }
    }

    /// Shown when the client is not on the machine.
    pub fn install_hint(self) -> &'static str {
        match self {
            Self::Freerdp => "install the 'freerdp3' package (xfreerdp3)",
            Self::Mstsc => "mstsc.exe is part of Windows; check %SystemRoot%\\System32",
        }
    }

    /// What the extra-args field of the form is asking for.
    pub fn extra_args_hint(self) -> &'static str {
        match self {
            Self::Freerdp => "Extra xfreerdp args (optional)",
            Self::Mstsc => "Extra mstsc switches or .rdp settings (optional)",
        }
    }
}

/// Resolve the configured preference. Anything unrecognised is the native
/// client, which is also what `auto` and an empty setting mean.
pub fn resolve_client(pref: &str) -> Client {
    match pref.trim().to_ascii_lowercase().as_str() {
        "freerdp" | "xfreerdp" | "xfreerdp3" => Client::Freerdp,
        "mstsc" | "windows" => Client::Mstsc,
        _ => Client::native(),
    }
}

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
    pub client: Client,
    /// The `.rdp` mstsc was handed. It holds the sealed password, so it is
    /// removed as soon as mstsc has read it — see [`sweep_file`].
    file: Option<PathBuf>,
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

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/// The arguments a connection is opened with, in the order they are passed.
///
/// `file` is the `.rdp` mstsc will be handed, which only exists once a session
/// is actually being started; `None` renders it as a placeholder, for the
/// command line a report shows for a connection that is not running.
///
/// The password is not among them for either client and never will be.
pub fn build_args(conn: &RdpConnection, client: Client, file: Option<&Path>) -> Vec<String> {
    match client {
        Client::Freerdp => freerdp_args(conn),
        Client::Mstsc => mstsc_args(conn, file),
    }
}

fn freerdp_args(conn: &RdpConnection) -> Vec<String> {
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

/// mstsc takes the connection itself in the file and almost nothing else, so
/// the only arguments are the file and whichever switches the user added.
fn mstsc_args(conn: &RdpConnection, file: Option<&Path>) -> Vec<String> {
    let mut args: Vec<String> = vec!["mstsc".into()];
    args.push(match file {
        Some(p) => p.to_string_lossy().into_owned(),
        None => format!("<{}.rdp>", conn.name),
    });
    args.extend(split_extra(&conn.extra_args).switches);
    args
}

/// What `extra_args` means for mstsc.
///
/// The field is one line of free text and has to keep meaning something on
/// Windows, where the client takes its settings in a file rather than on a
/// command line. So an entry that looks like a `.rdp` setting — `key:s:value`,
/// `key:i:0`, `key:b:…` — is one, and goes into the file; anything else is a
/// switch for mstsc itself. That is what lets `/f` and
/// `redirectclipboard:i:0` sit side by side in the same field.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtraArgs {
    /// Lines to merge into the generated `.rdp`.
    pub settings: Vec<String>,
    /// Arguments passed to mstsc.
    pub switches: Vec<String>,
}

pub fn split_extra(extra: &str) -> ExtraArgs {
    let mut out = ExtraArgs::default();
    // A `.rdp` setting can contain spaces on either side of the colons
    // ("full address:s:host"), so the field is split on whitespace only for
    // switches — settings are taken as whole comma-separated entries.
    for part in extra.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if rdp_setting_key(part).is_some() {
            out.settings.push(part.to_string());
        } else {
            out.switches.extend(part.split_whitespace().map(String::from));
        }
    }
    out
}

/// The key of a `.rdp` line, i.e. everything before the `:s:`/`:i:`/`:b:`.
fn rdp_setting_key(line: &str) -> Option<&str> {
    let (key, rest) = line.split_once(':')?;
    let (kind, _) = rest.split_once(':')?;
    if key.is_empty() || !matches!(kind, "s" | "i" | "b") {
        return None;
    }
    Some(key)
}

// ---------------------------------------------------------------------------
// The .rdp file
// ---------------------------------------------------------------------------

/// The `.rdp` mstsc is handed.
///
/// `sealed_password` is the DPAPI blob from [`seal_password`], hex encoded —
/// what Remote Desktop itself writes into a saved connection. `None` leaves the
/// field out entirely and mstsc asks for the password, which is what happens
/// when there is no password stored or when Windows declined to seal it.
///
/// User settings from `extra_args` replace a generated line with the same key
/// rather than being appended after it, so a setting can actually be overridden
/// instead of appearing twice and leaving which one wins to the client.
pub fn render_rdp_file(
    conn: &RdpConnection,
    sealed_password: Option<&str>,
) -> String {
    let user = if conn.domain.is_empty() {
        conn.username.clone()
    } else {
        format!("{}\\{}", conn.domain, conn.username)
    };
    let mut lines: Vec<String> = vec![
        format!("full address:s:{}:{}", conn.host, conn.port),
        format!("username:s:{user}"),
        // A window rather than the whole screen, which is what xfreerdp does
        // without /f — the two clients should not disagree about that.
        "screen mode id:i:1".to_string(),
        // The freerdp side asks for /dynamic-resolution; this is the same thing.
        "dynamic resolution:i:1".to_string(),
        // `/cert:ignore`: connect to a host whose certificate does not verify
        // rather than refusing. Same trade, said the way mstsc says it.
        "authentication level:i:0".to_string(),
        "prompt for credentials:i:0".to_string(),
        "redirectclipboard:i:1".to_string(),
    ];
    if let Some(blob) = sealed_password {
        lines.push(format!("password 51:b:{blob}"));
    }
    for setting in split_extra(&conn.extra_args).settings {
        let Some(key) = rdp_setting_key(&setting) else {
            continue;
        };
        match lines
            .iter()
            .position(|l| rdp_setting_key(l) == Some(key))
        {
            Some(i) => lines[i] = setting,
            None => lines.push(setting),
        }
    }
    // mstsc reads the file as Windows text.
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out
}

pub fn rdp_file_for(name: &str, run_dir: &Path) -> PathBuf {
    // The name is a user's; keep it from reaching out of the run directory.
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' })
        .collect();
    run_dir.join(format!("rdp-{safe}.rdp"))
}

/// Remove the `.rdp` once mstsc has read it.
///
/// mstsc parses the file while it starts and never looks at it again, so it
/// does not have to outlive the launch — and it holds a password, so it should
/// not. The wait is generous because the cost of being early is a session that
/// does not start, and the cost of being late is a sealed blob sitting in a
/// directory only its owner can open for a few more seconds.
fn sweep_file(path: PathBuf) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(20));
        let _ = std::fs::remove_file(path);
    });
}

// ---------------------------------------------------------------------------
// Sealing a password the way Windows does
// ---------------------------------------------------------------------------

/// Seal `password` for the current account, hex encoded for a `.rdp` file.
///
/// DPAPI, which is what Remote Desktop uses for the same field: the blob can
/// only be opened by the account that made it, on the machine that made it. It
/// is the only way to put a password in front of mstsc without putting it on a
/// command line, and it is strictly better than the file mode that guards it —
/// a copy of the file taken elsewhere is not a password.
///
/// `None` means Windows would not seal it; the caller then leaves the field out
/// and mstsc asks the user, which is a working session rather than a failed one.
#[cfg(windows)]
pub fn seal_password(password: &str) -> Option<String> {
    /// CRYPTPROTECT_UI_FORBIDDEN — never put a dialog in front of the TUI.
    const UI_FORBIDDEN: u32 = 0x1;

    // mstsc stores the UTF-16 bytes of the password, with no terminator.
    let wide: Vec<u16> = password.encode_utf16().collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(wide.len() * 2);
    for unit in &wide {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    unsafe {
        let input = dpapi::Blob {
            len: bytes.len() as u32,
            data: bytes.as_mut_ptr(),
        };
        let mut output = dpapi::Blob {
            len: 0,
            data: std::ptr::null_mut(),
        };
        let ok = dpapi::CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            UI_FORBIDDEN,
            &mut output,
        );
        if ok == 0 || output.data.is_null() {
            return None;
        }
        let sealed = std::slice::from_raw_parts(output.data, output.len as usize);
        let hex = to_hex(sealed);
        dpapi::LocalFree(output.data.cast());
        Some(hex)
    }
}

#[cfg(not(windows))]
pub fn seal_password(_password: &str) -> Option<String> {
    None
}

/// Uppercase, unseparated — the encoding a `.rdp` file uses.
#[cfg(any(windows, test))]
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

#[cfg(windows)]
mod dpapi {
    use std::ffi::c_void;

    /// `DATA_BLOB`: a length and a pointer, in that order.
    #[repr(C)]
    pub struct Blob {
        pub len: u32,
        pub data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        pub fn CryptProtectData(
            data_in: *const Blob,
            description: *const u16,
            entropy: *const Blob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut Blob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }
}

// ---------------------------------------------------------------------------
// Starting a session
// ---------------------------------------------------------------------------

/// Start a session, detached from the TUI.
pub fn spawn(
    conn: &RdpConnection,
    password: &str,
    client: Client,
    run_dir: &Path,
) -> Result<ActiveRdp> {
    match client {
        Client::Freerdp => spawn_freerdp(conn, password),
        Client::Mstsc => spawn_mstsc(conn, password, run_dir),
    }
}

fn spawn_freerdp(conn: &RdpConnection, password: &str) -> Result<ActiveRdp> {
    let argv = build_args(conn, Client::Freerdp, None);
    // argv[0] is the program; xfreerdp itself takes the rest.
    let args = &argv[1..];

    let mut child = Command::new(crate::platform::program("xfreerdp3"))
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
        client: Client::Freerdp,
        file: None,
    })
}

fn spawn_mstsc(conn: &RdpConnection, password: &str, run_dir: &Path) -> Result<ActiveRdp> {
    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("creating {}", run_dir.display()))?;
    crate::platform::restrict_dir(run_dir).map_err(|e| anyhow!(e))?;

    let log = Arc::new(Ring::new("mstsc"));
    let sealed = if password.is_empty() {
        None
    } else {
        let blob = seal_password(password);
        if blob.is_none() {
            log.push("── Windows would not seal the password; mstsc will ask for it ──");
        }
        blob
    };

    let path = rdp_file_for(&conn.name, run_dir);
    std::fs::write(&path, render_rdp_file(conn, sealed.as_deref()))
        .with_context(|| format!("writing {}", path.display()))?;
    // It holds a sealed password: nobody else gets to read it, and it does not
    // stay on disk any longer than mstsc needs it.
    crate::platform::restrict_file(&path).map_err(|e| anyhow!(e))?;

    let argv = build_args(conn, Client::Mstsc, Some(&path));
    let args = &argv[1..];
    let child = Command::new(crate::platform::program("mstsc"))
        .args(args)
        // mstsc has a window of its own and says nothing on a pipe; holding
        // one open would only keep a handle alive for no reader.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!("spawning mstsc ({})", Client::Mstsc.install_hint())
        });
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };

    // mstsc is a window, not a log: what it was asked for is the only thing
    // controlcenter can say about it, so it is said here rather than nowhere.
    log.push(format!("── mstsc launched with {} ──", path.display()));
    if sealed.is_some() {
        log.push("── the password was sealed to this account and passed in the file ──");
    }
    sweep_file(path.clone());

    Ok(ActiveRdp {
        child,
        status: RdpStatus::Running,
        started_at: Instant::now(),
        log,
        argv,
        client: Client::Mstsc,
        file: Some(path),
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
            self.log
                .push(format!("── {} exited ({code}) ──", self.client.program()));
            self.forget_file();
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.status == RdpStatus::Running {
            self.status = RdpStatus::Exited(-1);
        }
        self.forget_file();
    }

    fn forget_file(&mut self) {
        if let Some(path) = self.file.take() {
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn recent_log(&self, n: usize) -> Vec<Entry> {
        self.log.recent(n)
    }
}

pub fn installed(client: Client) -> bool {
    crate::platform::which_bin(client.program()).is_some()
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
        let args = build_args(&conn("acme", ""), Client::Freerdp, None);
        assert!(args.contains(&"/from-stdin".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("/p:")));
        assert!(args.contains(&"/d:acme".to_string()));
    }

    #[test]
    fn no_domain_means_no_domain_flag_at_all() {
        let args = build_args(&conn("", "/f /sound"), Client::Freerdp, None);
        assert!(!args.iter().any(|a| a.starts_with("/d:")));
        // Extra args are appended in the order they were typed.
        assert_eq!(&args[args.len() - 2..], &["/f".to_string(), "/sound".to_string()]);
    }

    #[test]
    fn mstsc_is_handed_the_file_and_nothing_that_describes_the_connection() {
        let path = Path::new("/run/controlcenter/rdp-desk.rdp");
        let args = build_args(&conn("acme", "/f"), Client::Mstsc, Some(path));
        assert_eq!(args[0], "mstsc");
        assert_eq!(args[1], path.to_string_lossy());
        assert_eq!(args[2], "/f");
        // Everything about the host lives in the file, never in the argv.
        assert!(!args.iter().any(|a| a.contains("10.0.0.5")));
    }

    #[test]
    fn without_a_file_the_preview_says_so_rather_than_inventing_one() {
        let args = build_args(&conn("", ""), Client::Mstsc, None);
        assert_eq!(args[1], "<desk.rdp>");
    }

    #[test]
    fn extra_args_are_split_into_settings_and_switches() {
        let split = split_extra("/f, redirectclipboard:i:0, /multimon");
        assert_eq!(split.switches, vec!["/f", "/multimon"]);
        assert_eq!(split.settings, vec!["redirectclipboard:i:0"]);
    }

    #[test]
    fn a_bare_run_of_switches_is_still_a_run_of_switches() {
        // The freerdp form of the field — no commas at all — has to keep working.
        let split = split_extra("/f /sound /multimon");
        assert_eq!(split.switches, vec!["/f", "/sound", "/multimon"]);
        assert!(split.settings.is_empty());
    }

    #[test]
    fn a_generated_file_carries_the_connection_and_no_password() {
        let file = render_rdp_file(&conn("acme", ""), None);
        assert!(file.contains("full address:s:10.0.0.5:3389"));
        assert!(file.contains("username:s:acme\\flo"));
        assert!(file.contains("authentication level:i:0"));
        assert!(!file.contains("password"));
        // mstsc reads the file as Windows text.
        assert!(file.ends_with("\r\n"));
    }

    #[test]
    fn without_a_domain_the_username_stands_alone() {
        assert!(render_rdp_file(&conn("", ""), None).contains("username:s:flo\r\n"));
    }

    #[test]
    fn a_sealed_password_goes_in_as_the_field_windows_uses() {
        let file = render_rdp_file(&conn("", ""), Some("DEADBEEF"));
        assert!(file.contains("password 51:b:DEADBEEF"));
    }

    #[test]
    fn a_user_setting_replaces_the_generated_one_instead_of_fighting_it() {
        let file = render_rdp_file(&conn("", "screen mode id:i:2, audiomode:i:2"), None);
        assert!(file.contains("screen mode id:i:2"));
        assert!(!file.contains("screen mode id:i:1"));
        // One that has no generated counterpart is simply added.
        assert!(file.contains("audiomode:i:2"));
    }

    #[test]
    fn a_connection_name_cannot_walk_out_of_the_run_directory() {
        let path = rdp_file_for("../../etc/passwd", Path::new("/run/cc"));
        assert_eq!(path, Path::new("/run/cc/rdp-.._.._etc_passwd.rdp"));
    }

    #[test]
    fn the_client_preference_picks_the_client() {
        assert_eq!(resolve_client("freerdp"), Client::Freerdp);
        assert_eq!(resolve_client("mstsc"), Client::Mstsc);
        assert_eq!(resolve_client("auto"), Client::native());
        assert_eq!(resolve_client(""), Client::native());
    }

    #[test]
    fn a_sealed_blob_is_hex_the_way_the_file_wants_it() {
        assert_eq!(to_hex(&[0x01, 0xab, 0xff]), "01ABFF");
    }
}
