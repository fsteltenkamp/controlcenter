//! What differs between the systems controlcenter runs on.
//!
//! Everything here is a fact about the operating system rather than about a
//! client: where a binary is found, what "throw this away" is called, how a
//! file is made private, how a process is looked up and stopped. The client
//! modules ask this module rather than each growing a `#[cfg]` of its own —
//! and the parsing the Windows halves need is written so it can still be unit
//! tested on the machine the tests actually run on.

use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

/// The path that means "throw this away". ssh is pointed at it for the known
/// hosts file when a host key is deliberately not checked.
#[cfg(unix)]
pub const NULL_DEVICE: &str = "/dev/null";
#[cfg(windows)]
pub const NULL_DEVICE: &str = "NUL";

/// The user's home directory, for `~` in a typed path.
pub fn home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("USERPROFILE") {
            return Some(PathBuf::from(p));
        }
        // A domain account can have the two halves set and USERPROFILE not.
        let drive = std::env::var("HOMEDRIVE").ok()?;
        let path = std::env::var("HOMEPATH").ok()?;
        Some(PathBuf::from(format!("{drive}{path}")))
    }
}

// ---------------------------------------------------------------------------
// Finding a binary
// ---------------------------------------------------------------------------

/// Directories searched after `PATH`.
///
/// On Linux everything controlcenter drives is a package that puts itself on
/// `PATH`. On Windows almost none of it does: the WireGuard, OpenVPN, Tailscale,
/// NetBird and Pangolin installers drop their binaries under Program Files and
/// leave `PATH` alone, so a search that stopped at `PATH` would report every
/// client as missing on a machine that has all of them installed.
#[cfg(windows)]
fn extra_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        let Some(base) = std::env::var_os(var).map(PathBuf::from) else {
            continue;
        };
        dirs.push(base.join("WireGuard"));
        dirs.push(base.join("OpenVPN").join("bin"));
        dirs.push(base.join("Tailscale"));
        dirs.push(base.join("Netbird"));
        dirs.push(base.join("Pangolin"));
    }
    // Pangolin's installer is a per-user one and does not go near Program Files.
    if let Some(base) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        dirs.push(base.join("Programs").join("Pangolin"));
        dirs.push(base.join("Pangolin"));
    }
    if let Some(root) = std::env::var_os("SystemRoot").map(PathBuf::from) {
        dirs.push(root.join("System32"));
    }
    dirs
}

#[cfg(not(windows))]
fn extra_dirs() -> Vec<PathBuf> {
    Vec::new()
}

/// The file names a bare program name can have. On Windows `ssh` is `ssh.exe`,
/// and which suffixes count is `PATHEXT`'s to say.
#[cfg(windows)]
fn candidates(name: &str) -> Vec<String> {
    let exts = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    // An extension that is already there is the name; don't make `ssh.exe.exe`.
    if exts
        .split(';')
        .any(|e| !e.is_empty() && name.to_ascii_uppercase().ends_with(&e.to_ascii_uppercase()))
    {
        return vec![name.to_string()];
    }
    let mut out: Vec<String> = exts
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| format!("{name}{e}"))
        .collect();
    // A name with no extension at all is still worth trying, last.
    out.push(name.to_string());
    out
}

#[cfg(not(windows))]
fn candidates(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

/// Where `name` is on this machine, if it is anywhere.
pub fn which_bin(name: &str) -> Option<PathBuf> {
    // An absolute or explicitly relative path is not a name to look up.
    let as_path = Path::new(name);
    if as_path.is_absolute() || name.contains('/') || name.contains('\\') {
        return as_path.is_file().then(|| as_path.to_path_buf());
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(extra_dirs());
    for dir in dirs {
        for candidate in candidates(name) {
            let full = dir.join(&candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// The program to hand [`std::process::Command::new`].
///
/// On Unix this is the name back: everything controlcenter runs is on `PATH`.
/// On Windows `CreateProcess` searches `PATH` and nothing else, and the VPN
/// clients install outside it — so the name is resolved the way [`which_bin`]
/// resolves it, which knows where the installers put things. The name is what
/// stays in the argv a report prints; only the spawn takes the long form.
pub fn program(name: &str) -> std::ffi::OsString {
    #[cfg(windows)]
    {
        if let Some(path) = which_bin(name) {
            return path.into_os_string();
        }
    }
    std::ffi::OsString::from(name)
}

// ---------------------------------------------------------------------------
// Keeping a file to its owner
// ---------------------------------------------------------------------------

/// Make a file readable by its owner and nobody else.
///
/// Unix says this in one call. Windows needs the inherited ACL taken off first,
/// because a file under `%APPDATA%` inherits entries that grant the machine's
/// administrators — and a password is a password.
#[cfg(unix)]
pub fn restrict_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("locking down {}: {e}", path.display()))
}

#[cfg(windows)]
pub fn restrict_file(path: &Path) -> Result<(), String> {
    icacls(path, false)
}

/// The directory equivalent: nothing that is not the owner may even list it.
#[cfg(unix)]
pub fn restrict_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("locking down {}: {e}", path.display()))
}

#[cfg(windows)]
pub fn restrict_dir(path: &Path) -> Result<(), String> {
    icacls(path, true)
}

/// Who the ACL is written for, most specific first.
///
/// `icacls` resolves a trustee by name, and a name can fail to resolve —
/// a domain account whose `USERDOMAIN` names the machine rather than the
/// domain, an environment where neither variable is set the way it usually is.
/// So the account is named three ways and the first that resolves wins; the
/// last is the well-known SID for "whoever owns this object", which needs no
/// lookup at all and so cannot fail to resolve.
#[cfg(windows)]
fn trustees() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.is_empty() {
            if let Ok(domain) = std::env::var("USERDOMAIN") {
                if !domain.is_empty() {
                    out.push(format!("{domain}\\{user}"));
                }
            }
            out.push(user);
        }
    }
    // *S-1-3-4 is OWNER RIGHTS: the account that owns the file, which is the
    // account that just created it.
    out.push("*S-1-3-4".to_string());
    out
}

/// `/inheritance:r` drops everything the parent granted; `/grant:r` then makes
/// the owner the only entry left. `(OI)(CI)` is what makes a directory's rule
/// apply to what is created inside it later.
#[cfg(windows)]
fn icacls(path: &Path, dir: bool) -> Result<(), String> {
    let mut last = "no trustee could be named".to_string();
    for account in trustees() {
        let grant = if dir {
            format!("{account}:(OI)(CI)F")
        } else {
            format!("{account}:F")
        };
        let mut cmd = Command::new("icacls");
        cmd.arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant);
        hidden(&mut cmd);
        match cmd.output() {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                // icacls says why on stdout as often as on stderr.
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let msg = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
                last = if msg.is_empty() {
                    format!("icacls refused {grant}")
                } else {
                    msg.lines().next().unwrap_or(msg).to_string()
                };
            }
            Err(e) => return Err(format!("locking down {}: running icacls: {e}", path.display())),
        }
    }
    Err(format!("locking down {}: {last}", path.display()))
}

// ---------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------

/// Keep a helper process from flashing a console window of its own.
/// Windows only — nothing else opens one uninvited.
#[cfg(windows)]
pub fn hidden(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    /// CREATE_NO_WINDOW
    const NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(NO_WINDOW);
}

/// Give the child a console of its own, so it becomes the window an
/// interactive session runs in. Windows only — elsewhere a terminal emulator
/// is the thing that opens a window.
#[cfg(windows)]
pub fn new_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    /// CREATE_NEW_CONSOLE
    const NEW_CONSOLE: u32 = 0x0000_0010;
    cmd.creation_flags(NEW_CONSOLE);
}

/// Run a PowerShell one-liner and give back its stdout.
///
/// PowerShell rather than `netsh`, `sc` or `wmic`: those either print localised
/// field names that a parser cannot rely on, or are gone from current Windows.
/// The cmdlets used here are asked for named properties in CSV, which is the
/// same text on every machine.
#[cfg(windows)]
pub fn powershell(script: &str) -> Result<String, String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    hidden(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("running powershell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if msg.is_empty() {
            "powershell failed".to_string()
        } else {
            msg.lines().next().unwrap_or(&msg).to_string()
        })
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// Is the process still there?
///
/// `/proc` rather than `kill -0` on Unix, because a root process cannot be
/// signalled from here just to ask. On Windows the handle is opened with
/// `PROCESS_QUERY_LIMITED_INFORMATION`, which is granted across integrity
/// levels for exactly this question and escalates nothing.
#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    unsafe {
        let handle = win32::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let still_running = win32::WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
        win32::CloseHandle(handle);
        still_running
    }
}

/// How to stop a process, built in one place so a report shows what was run.
///
/// Windows has no signals: `taskkill` without `/F` asks a process to close and
/// refuses outright for a console program that has no window to ask, which is
/// what openvpn is — so the forceful form is not an afterthought there, it is
/// the one that does the work. The polite attempt is still made first, because
/// a client that *can* close cleanly should be allowed to.
pub fn kill_argv(pid: u32, force: bool) -> Vec<String> {
    #[cfg(not(windows))]
    {
        vec![
            "kill".to_string(),
            if force { "-KILL" } else { "-TERM" }.to_string(),
            pid.to_string(),
        ]
    }
    #[cfg(windows)]
    {
        let mut argv = vec![
            "taskkill".to_string(),
            "/PID".to_string(),
            pid.to_string(),
            "/T".to_string(),
        ];
        if force {
            argv.push("/F".to_string());
        }
        argv
    }
}

// ---------------------------------------------------------------------------
// Being root
// ---------------------------------------------------------------------------

/// Whether this process is already running with the rights a VPN client needs.
///
/// On Windows there is no ticket to take and no agent to ask: a process is
/// elevated or it is not, decided when it started. Asking the token is the only
/// honest answer, and it is a read of our own process — nothing escalates.
#[cfg(windows)]
pub fn elevated() -> bool {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: i32 = 20;
    unsafe {
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if win32::OpenProcessToken(win32::GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: u32 = 0;
        let mut returned: u32 = 0;
        let ok = win32::GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            (&mut elevation as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        );
        win32::CloseHandle(token);
        ok != 0 && elevation != 0
    }
}

/// The handful of Win32 calls controlcenter makes directly.
///
/// Declared here rather than pulled in as a dependency: it is six functions
/// with signatures that have not changed since Windows 2000, and the crates
/// that wrap them are a great deal larger than what is used of them.
#[cfg(windows)]
mod win32 {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        pub fn WaitForSingleObject(handle: *mut c_void, millis: u32) -> u32;
        pub fn CloseHandle(handle: *mut c_void) -> i32;
        pub fn GetCurrentProcess() -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(
            token: *mut c_void,
            class: i32,
            info: *mut c_void,
            len: u32,
            returned: *mut u32,
        ) -> i32;
    }
}

// ---------------------------------------------------------------------------
// Command lines
// ---------------------------------------------------------------------------

/// Split a Windows command line back into arguments.
///
/// `Win32_Process` reports the whole line as one string, so the scan has to
/// undo the quoting to get at the `--config` an openvpn was started with. These
/// are the rules `CommandLineToArgvW` follows: a backslash only escapes when a
/// run of them is followed by a quote, and `""` inside a quoted run is a
/// literal quote.
#[cfg(any(windows, test))]
pub fn split_command_line(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;
    let mut backslashes = 0usize;

    let flush_backslashes = |current: &mut String, n: &mut usize| {
        for _ in 0..*n {
            current.push('\\');
        }
        *n = 0;
    };

    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                backslashes += 1;
                started = true;
            }
            '"' => {
                // Every pair of backslashes is one literal backslash; an odd
                // one left over escapes this quote instead of ending the run.
                let escaped = backslashes % 2 == 1;
                let literal = backslashes / 2;
                backslashes = 0;
                for _ in 0..literal {
                    current.push('\\');
                }
                started = true;
                if escaped {
                    current.push('"');
                } else if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                flush_backslashes(&mut current, &mut backslashes);
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                flush_backslashes(&mut current, &mut backslashes);
                current.push(c);
                started = true;
            }
        }
    }
    flush_backslashes(&mut current, &mut backslashes);
    if started {
        args.push(current);
    }
    args
}

/// The rows of a `ConvertTo-Csv -NoTypeInformation` table, as
/// `(header, value)` pairs per row.
///
/// PowerShell quotes every field and doubles a quote inside one, which is the
/// same dialect as the command line above but simpler — there are no
/// backslash rules in it at all.
#[cfg(any(windows, test))]
pub fn parse_csv(raw: &str) -> Vec<Vec<(String, String)>> {
    let mut lines = raw.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next().map(csv_row) else {
        return Vec::new();
    };
    lines
        .map(|line| {
            header
                .iter()
                .cloned()
                .zip(csv_row(line))
                .collect::<Vec<(String, String)>>()
        })
        .collect()
}

#[cfg(any(windows, test))]
fn csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                chars.next();
                current.push('"');
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/// The value of one column of a row read by [`parse_csv`].
#[cfg(any(windows, test))]
pub fn csv_field<'a>(row: &'a [(String, String)], key: &str) -> Option<&'a str> {
    row.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_command_line_splits_the_way_the_kernel_wrote_it() {
        assert_eq!(
            split_command_line(r#""C:\Program Files\OpenVPN\bin\openvpn.exe" --config "C:\a b\config.ovpn""#),
            vec![
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                "--config",
                r"C:\a b\config.ovpn",
            ]
        );
    }

    #[test]
    fn a_trailing_backslash_before_a_quote_is_a_backslash() {
        // "C:\dir\" is a path ending in a separator, not an unterminated quote.
        assert_eq!(
            split_command_line(r#"openvpn --cd "C:\dir\\" --verb 3"#),
            vec!["openvpn", "--cd", r"C:\dir\", "--verb", "3"]
        );
    }

    #[test]
    fn an_empty_command_line_has_no_arguments() {
        assert!(split_command_line("").is_empty());
        assert!(split_command_line("   ").is_empty());
    }

    #[test]
    fn csv_rows_come_back_keyed_by_their_header() {
        let raw = "\"Name\",\"Status\"\r\n\"wg0\",\"Up\"\r\n\"Ethernet\",\"Disconnected\"\r\n";
        let rows = parse_csv(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(csv_field(&rows[0], "Name"), Some("wg0"));
        assert_eq!(csv_field(&rows[1], "status"), Some("Disconnected"));
        assert_eq!(csv_field(&rows[0], "nothing"), None);
    }

    #[test]
    fn a_comma_inside_a_quoted_field_is_not_a_separator() {
        let raw = "\"Name\",\"Description\"\n\"wg0\",\"WireGuard Tunnel, v0.5\"\n";
        let rows = parse_csv(raw);
        assert_eq!(
            csv_field(&rows[0], "Description"),
            Some("WireGuard Tunnel, v0.5")
        );
    }

    #[test]
    fn an_empty_column_reads_as_absent() {
        // PowerShell writes a null property as an empty field, which is what a
        // command line we are not allowed to read looks like.
        let raw = "\"ProcessId\",\"CommandLine\"\n\"1234\",\"\"\n";
        let rows = parse_csv(raw);
        assert_eq!(csv_field(&rows[0], "ProcessId"), Some("1234"));
        assert_eq!(csv_field(&rows[0], "CommandLine"), None);
    }

    #[test]
    fn a_home_relative_path_needs_a_home_to_resolve_against() {
        // Whatever the platform calls it, `home` either answers or it does not;
        // the callers all have a fallback and none of them may panic.
        let _ = home();
    }

    #[test]
    fn an_absolute_path_is_not_looked_up_on_path() {
        assert!(which_bin("/definitely/not/here").is_none());
    }
}
