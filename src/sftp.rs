//! Copying files to and from a configured SSH host, and the remote half of the
//! two-pane browser that does it.
//!
//! One `sftp` process per open browser, driven on its stdin, rather than an
//! `scp` per file: listing a directory and copying out of it are the same
//! conversation, so they should be the same connection — one authentication,
//! no handshake between keystrokes, and a password that is asked for once or
//! not at all. It is also the only shape that works on both systems, where
//! `ControlMaster` would have done on neither but Unix.
//!
//! The protocol is sftp's own, used the way it documents itself:
//!
//! - reading commands from a pipe, sftp echoes each one back prefixed with its
//!   prompt, so [`ECHO`] lines are ours coming home and are dropped
//! - a command prefixed with `-` does not end the session when it fails, which
//!   is what keeps a typo'd path from costing the connection
//! - every command is followed by a `pwd`, whose reply is unmistakable and
//!   cannot be produced by a listing, so [`PWD_MARKER`] is where one command's
//!   output ends and the next begins
//!
//! Errors come back on stderr, out of step with the stdout we are parsing, so
//! they are collected by a thread of their own and read off once the marker
//! says the command is done.

use crate::logs::Ring;
use crate::platform;
use crate::ssh::{self, PasswordHelper};
use crate::types::SshHost;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// sftp's reply to `pwd`, and so the end of the command before it.
const PWD_MARKER: &str = "Remote working directory: ";
/// What sftp prefixes a command with when it reads one from a pipe.
const ECHO: &str = "sftp> ";
/// Given to stderr after the marker lands, because the two streams arrive
/// independently and an error written just before the reply ended would
/// otherwise be read as the *next* command's. Invisible next to a directory
/// listing over a network, and shorter than a single frame of the TUI.
const STDERR_SETTLE: Duration = Duration::from_millis(30);

// ---------------------------------------------------------------------------
// What a listing is made of
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKind {
    Dir,
    File,
    /// A symlink, whose target may be either. The server's listing does not
    /// say which, so walking into one is an attempt rather than a certainty —
    /// see [`Listing::single_file`].
    Link,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub kind: RemoteKind,
    pub size: u64,
}

impl RemoteEntry {
    pub fn is_dir(&self) -> bool {
        self.kind == RemoteKind::Dir
    }

    /// Whether Enter should try to walk into it.
    pub fn navigable(&self) -> bool {
        matches!(self.kind, RemoteKind::Dir | RemoteKind::Link)
    }
}

/// What came back from one `ls`.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub entries: Vec<RemoteEntry>,
    /// The listing had a `.` in it, so whatever was listed was a directory and
    /// nothing below has to be inferred.
    listed_self: bool,
}

impl Listing {
    /// `ls` on a file lists the file, so a listing of `path` that is exactly
    /// the one entry `path` names was never a directory. That is how a symlink
    /// to a file, and a file path typed by hand, are told apart from a
    /// directory without asking the server a second question.
    ///
    /// A directory of one file that happens to share its name would look the
    /// same, which is why `.` is believed over the guess wherever the server
    /// returns one — and every server worth the name does.
    pub fn single_file(&self, path: &str) -> bool {
        if self.listed_self {
            return false;
        }
        match self.entries.as_slice() {
            [only] => !only.is_dir() && only.name == base_name(path),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Talking to sftp
// ---------------------------------------------------------------------------

/// What the browser asks the session to do. Served in order, on the session's
/// own thread: a listing queued behind a transfer waits for it, which is also
/// what the user sees.
enum Request {
    List(String),
    Get { remote: String, local: String },
    Put { local: String, remote: String },
}

/// News from a session, tagged with the generation it belongs to so a reply
/// from a session that has already been closed is dropped rather than shown
/// over the one that replaced it.
pub struct SftpMsg {
    pub gen: u64,
    pub kind: MsgKind,
}

pub enum MsgKind {
    /// The session is up. `cwd` is where the login landed.
    Ready { cwd: String },
    Listed {
        dir: String,
        listing: Listing,
        error: Option<String>,
    },
    Transferred {
        error: Option<String>,
        took: Duration,
    },
    /// The session is gone and the handle is dead.
    Closed { error: String },
}

/// A live sftp process, and the only way to it.
pub struct Session {
    pub gen: u64,
    /// The command line it was started with, for the log and the report.
    pub argv: Vec<String>,
    tx: Sender<Request>,
    /// Shared with nothing that reads it — held so the session can be cut off
    /// mid-transfer. Closing stdin would be tidier but a `get` half way
    /// through a large file would not notice for as long as it took.
    child: Arc<Mutex<Child>>,
}

impl Session {
    /// Start sftp and hand the conversation to a thread. Returns as soon as
    /// the process is spawned; [`MsgKind::Ready`] follows when it has
    /// authenticated, or [`MsgKind::Closed`] when it could not.
    pub fn open(
        host: &SshHost,
        helper: &PasswordHelper,
        gen: u64,
        log: Arc<Ring>,
        out: Sender<SftpMsg>,
    ) -> Result<Self> {
        let argv = command_line(host, helper);
        let mut cmd = Command::new(platform::program(&argv[0]));
        cmd.args(&argv[1..]);
        // The same two ways in as everywhere else, and neither is an argument.
        ssh::carry_password(&mut cmd, &host.password, helper);
        #[cfg(windows)]
        platform::hidden(&mut cmd);

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                if argv[0] == "sshpass" {
                    "spawning sshpass (is sshpass installed?)".to_string()
                } else {
                    "spawning sftp".to_string()
                }
            })?;

        let stdin = child.stdin.take().context("sftp stdin")?;
        let stdout = child.stdout.take().context("sftp stdout")?;
        let stderr = child.stderr.take().context("sftp stderr")?;

        // Diagnostics land here: ssh's own complaints and sftp's "Can't ls".
        // Kept for the log pane as well, because a failed transfer explains
        // itself on this stream and nowhere else.
        let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let errors = Arc::clone(&errors);
            let log = Arc::clone(&log);
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    log.push(line.clone());
                    errors.lock().unwrap().push(line);
                }
            });
        }

        let (tx, rx) = channel::<Request>();
        let mut worker = Worker {
            gen,
            stdin,
            reader: BufReader::new(stdout),
            log,
            errors,
            out,
        };
        thread::spawn(move || {
            match worker.handshake() {
                Ok(cwd) => worker.send(MsgKind::Ready { cwd }),
                Err(e) => {
                    worker.send(MsgKind::Closed { error: e });
                    return;
                }
            }
            while let Ok(req) = rx.recv() {
                if !worker.serve(req) {
                    return;
                }
            }
        });

        Ok(Self {
            gen,
            argv,
            tx,
            child: Arc::new(Mutex::new(child)),
        })
    }

    pub fn list(&self, dir: &str) {
        let _ = self.tx.send(Request::List(dir.to_string()));
    }

    pub fn get(&self, remote: &str, local: &str) {
        let _ = self.tx.send(Request::Get {
            remote: remote.to_string(),
            local: local.to_string(),
        });
    }

    pub fn put(&self, local: &str, remote: &str) {
        let _ = self.tx.send(Request::Put {
            local: local.to_string(),
            remote: remote.to_string(),
        });
    }

    /// End it now, whatever it is doing. A transfer in flight is cut off, which
    /// is what closing the browser during one means.
    pub fn close(&self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The command line, as the log and the report show it. `sftp` takes every
/// connection option ssh does, so a host is described once and reached the
/// same way whichever of the two is doing the reaching.
pub fn command_line(host: &SshHost, helper: &PasswordHelper) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    if !host.password.is_empty() && *helper == PasswordHelper::Sshpass {
        argv.push("sshpass".into());
        argv.push("-e".into());
    }
    argv.push("sftp".into());
    argv.extend(ssh::transfer_args(host));
    if host.password.is_empty() {
        // Nothing here can answer a prompt: sftp's stdin is the pipe these
        // commands go down, and the only terminal it could ask at is the one
        // the TUI is drawing on. BatchMode turns a question we could not show
        // into an error we can report — including an unknown host key, which
        // would otherwise wait for a "yes" that never comes.
        argv.push("-o".into());
        argv.push("BatchMode=yes".into());
    }
    argv.push(host.destination());
    argv
}

struct Worker {
    gen: u64,
    stdin: ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    log: Arc<Ring>,
    errors: Arc<Mutex<Vec<String>>>,
    out: Sender<SftpMsg>,
}

/// One command's reply.
struct Reply {
    lines: Vec<String>,
    cwd: String,
}

impl Worker {
    fn send(&self, kind: MsgKind) {
        let _ = self.out.send(SftpMsg { gen: self.gen, kind });
    }

    /// Get the session into a known state: the progress meter off, and the
    /// directory the login landed in.
    ///
    /// The meter is a command rather than `-q`, which would also silence the
    /// ssh diagnostics that explain a refusal. It toggles, so what it prints
    /// is checked rather than assumed.
    fn handshake(&mut self) -> Result<String, String> {
        let reply = self.exchange("-progress", false)?;
        if reply.lines.iter().any(|l| l.contains("enabled")) {
            self.exchange("-progress", false)?;
        }
        Ok(reply.cwd)
    }

    /// Run one request and report it. `false` means the session is gone and
    /// the thread should stop.
    fn serve(&mut self, req: Request) -> bool {
        match req {
            Request::List(dir) => {
                let cmd = format!("-ls -la {}", quote(&dir));
                match self.exchange(&cmd, false) {
                    Ok(reply) => {
                        let listing = parse_listing(&reply.lines);
                        // stderr is where a refusal lands, but a listing that
                        // came back is not a failure whatever else was said on
                        // the way to it.
                        let error = listing.entries.is_empty().then(|| self.take_error()).flatten();
                        self.send(MsgKind::Listed {
                            dir,
                            listing,
                            error,
                        });
                        true
                    }
                    Err(e) => {
                        self.send(MsgKind::Closed { error: e });
                        false
                    }
                }
            }
            Request::Get { remote, local } => {
                let cmd = format!("-get {} {}", quote(&remote), quote(&local));
                self.transfer(&cmd)
            }
            Request::Put { local, remote } => {
                let cmd = format!("-put {} {}", quote(&local), quote(&remote));
                self.transfer(&cmd)
            }
        }
    }

    fn transfer(&mut self, cmd: &str) -> bool {
        self.log.push(format!("{ECHO}{cmd}"));
        let started = Instant::now();
        match self.exchange(cmd, true) {
            Ok(_) => {
                let error = self.take_error();
                self.send(MsgKind::Transferred {
                    error,
                    took: started.elapsed(),
                });
                true
            }
            Err(e) => {
                self.send(MsgKind::Closed { error: e });
                false
            }
        }
    }

    /// Send a command, then a `pwd`, and read until the `pwd` answers.
    fn exchange(&mut self, cmd: &str, log_output: bool) -> Result<Reply, String> {
        self.errors.lock().unwrap().clear();
        writeln!(self.stdin, "{cmd}")
            .and_then(|_| writeln!(self.stdin, "-pwd"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("sftp is gone: {e}"))?;

        let mut lines = Vec::new();
        let mut buf = String::new();
        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => return Err(self.death_note()),
                Ok(_) => {}
                Err(e) => return Err(format!("reading from sftp: {e}")),
            }
            match reply_line(&buf) {
                LineKind::Marker(cwd) => return Ok(Reply { lines, cwd }),
                LineKind::Skip => {}
                LineKind::Output(text) => {
                    if log_output {
                        self.log.push(text.clone());
                    }
                    lines.push(text);
                }
            }
        }
    }

    /// What stderr had to say about the command that just ran.
    ///
    /// The last line is the complaint; anything before it is ssh narrating its
    /// way there. Two of those lines are routine and are not complaints at
    /// all — a host key being remembered, and the connection being made — and
    /// reporting either as the reason a listing came back empty would be a
    /// lie in the one place a user goes looking for the truth.
    fn take_error(&self) -> Option<String> {
        thread::sleep(STDERR_SETTLE);
        let lines = self.errors.lock().unwrap();
        lines
            .iter()
            .rev()
            .find(|l| !is_chatter(l))
            .map(|l| l.trim().to_string())
    }

    /// Why the process stopped answering, in the words it left behind.
    fn death_note(&self) -> String {
        thread::sleep(STDERR_SETTLE);
        let lines = self.errors.lock().unwrap();
        match lines.iter().rev().find(|l| !is_chatter(l)) {
            Some(last) => format!("sftp ended: {}", last.trim()),
            None => "sftp ended without saying why".to_string(),
        }
    }
}

/// Lines ssh and sftp write to stderr on the way to succeeding.
fn is_chatter(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with("Warning:") || line.starts_with("Connected to ")
}

/// What one line of sftp's stdout is.
#[derive(Debug, PartialEq, Eq)]
enum LineKind {
    /// The `pwd` reply: the command before it is finished, and this is where.
    Marker(String),
    /// Our own command coming back, or a blank.
    Skip,
    Output(String),
}

fn reply_line(raw: &str) -> LineKind {
    let text = raw.trim_end_matches(['\n', '\r']);
    // The progress meter, were it ever on, redraws with a carriage return and
    // arrives as one long line; keep the last state it drew rather than all of
    // them, so a log line stays a line.
    let text = text.rsplit('\r').next().unwrap_or(text);
    if let Some(cwd) = text.strip_prefix(PWD_MARKER) {
        return LineKind::Marker(cwd.trim().to_string());
    }
    if text.trim().is_empty() || text.starts_with(ECHO) {
        return LineKind::Skip;
    }
    LineKind::Output(text.to_string())
}

// ---------------------------------------------------------------------------
// Reading a listing
// ---------------------------------------------------------------------------

/// Turn `ls -la` output into a listing, dropping what does not parse.
///
/// The lines are the server's own `longname` field, which every SFTP server
/// worth the name formats as `ls -l` does. A line that is not in that shape is
/// skipped rather than guessed at: a listing missing an entry is a nuisance,
/// and a listing with an invented one is a lie.
pub fn parse_listing(lines: &[String]) -> Listing {
    let parsed: Vec<RemoteEntry> = lines.iter().filter_map(|l| parse_ls_line(l)).collect();
    let listed_self = parsed.iter().any(|e| e.name == ".");
    let mut entries: Vec<RemoteEntry> = parsed
        .into_iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect();
    sort_entries(&mut entries);
    Listing {
        entries,
        listed_self,
    }
}

/// `drwxr-xr-x 5 user group 4096 Sep 20 11:23 name with spaces`
fn parse_ls_line(line: &str) -> Option<RemoteEntry> {
    let mode = line.split_whitespace().next()?;
    let kind = match mode.chars().next()? {
        'd' => RemoteKind::Dir,
        'l' => RemoteKind::Link,
        '-' => RemoteKind::File,
        // A socket, a device, a "total" header: not something to transfer.
        _ => return None,
    };
    if mode.len() < 10 {
        return None;
    }
    // The name is everything after the eighth field, which is the only way to
    // keep one that has spaces in it.
    let (fields, rest) = split_fields(line, 8)?;
    let size: u64 = fields.get(4)?.parse().ok()?;
    let name = match kind {
        // `name -> target`, where the server says so; the arrow belongs to the
        // listing and not to the name.
        RemoteKind::Link => rest.split(" -> ").next().unwrap_or(rest),
        _ => rest,
    };
    // `ls` echoes each entry the way it was asked for, so listing a directory
    // by its absolute path gives absolute paths back. What the pane shows and
    // joins onto its own directory is the last segment.
    let name = base_name(name.trim());
    if name.is_empty() {
        return None;
    }
    Some(RemoteEntry { name, kind, size })
}

/// The first `n` whitespace-separated fields, and the rest of the line
/// untouched — spaces in a filename included.
fn split_fields(line: &str, n: usize) -> Option<(Vec<&str>, &str)> {
    let mut fields = Vec::with_capacity(n);
    let mut rest = line;
    for _ in 0..n {
        let start = rest.find(|c: char| !c.is_whitespace())?;
        rest = &rest[start..];
        let end = rest.find(char::is_whitespace)?;
        fields.push(&rest[..end]);
        rest = &rest[end..];
    }
    let start = rest.find(|c: char| !c.is_whitespace())?;
    Some((fields, &rest[start..]))
}

fn sort_entries(entries: &mut [RemoteEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir()
            .cmp(&a.is_dir())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// Quote a path for sftp's own command parser.
///
/// Double quotes and backslash escapes are what it understands, and quoting is
/// also what keeps a name with a space in it one argument. A name containing a
/// quote or a backslash is beyond what this can promise — the command lands in
/// the log either way, so a refusal says what was asked for.
fn quote(path: &str) -> String {
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ---------------------------------------------------------------------------
// Remote paths
// ---------------------------------------------------------------------------

/// Split a typed remote path into the directory to list and the segment being
/// typed, the same way the local browser does — except that remote paths are
/// POSIX whatever this machine is, because that is what the SFTP protocol
/// speaks.
pub fn split_remote(input: &str) -> (String, String) {
    match input.rfind('/') {
        None => (".".to_string(), input.to_string()),
        Some(0) => ("/".to_string(), input[1..].to_string()),
        Some(cut) => (input[..cut].to_string(), input[cut + 1..].to_string()),
    }
}

pub fn join_remote(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// One level up, staying inside the remote's own path rules.
pub fn parent_remote(dir: &str) -> String {
    let rooted = dir.starts_with('/');
    let trimmed = dir.trim_end_matches('/');
    match trimmed.rfind('/') {
        // The root is its own parent; there is nowhere further up to go.
        Some(0) => "/".to_string(),
        Some(cut) => trimmed[..cut].to_string(),
        None if rooted => "/".to_string(),
        None => ".".to_string(),
    }
}

pub fn base_name(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_string()
}

// ---------------------------------------------------------------------------
// The remote pane
// ---------------------------------------------------------------------------

/// The remote half of the transfer browser: the same contract as
/// [`crate::browser::FileBrowser`] — the typed path is the truth and the
/// listing follows it — with the listing a round trip away instead of a
/// `read_dir`.
///
/// Typing filters what is already here rather than asking again; only a change
/// of directory is a question for the server. That is what [`Self::needs`] is
/// for: it names the directory that has to be fetched, once, and
/// [`Self::apply`] takes the answer.
#[derive(Debug, Clone)]
pub struct RemoteBrowser {
    /// The typed path, exactly as shown in the pane.
    pub input: String,
    /// The directory the listing came from.
    pub dir: String,
    /// Everything `dir` holds, and the part of it the typed segment matches.
    pub all: Vec<RemoteEntry>,
    pub entries: Vec<RemoteEntry>,
    pub selected: usize,
    pub error: Option<String>,
    /// A listing has been asked for and has not come back.
    pub pending: Option<String>,
    /// The entry to put the cursor on once the listing arrives — the directory
    /// we just came out of, or what was selected before a re-read.
    pending_select: Option<String>,
    /// The directory on screen has been written into and is no longer what the
    /// listing says it is.
    stale: bool,
}

impl RemoteBrowser {
    /// `start` empty means the pane has nowhere to be yet: the session says
    /// where the login landed, and [`Self::start_at`] puts it there.
    pub fn new(start: &str) -> Self {
        let input = match start {
            "" => String::new(),
            s if s.ends_with('/') => s.to_string(),
            s => format!("{s}/"),
        };
        Self {
            input,
            dir: String::new(),
            all: Vec::new(),
            entries: Vec::new(),
            selected: 0,
            error: None,
            pending: None,
            pending_select: None,
            stale: false,
        }
    }

    /// Where the login landed, for a pane that was not told where to start.
    pub fn start_at(&mut self, cwd: &str) {
        if self.input.is_empty() {
            self.input = if cwd.ends_with('/') {
                cwd.to_string()
            } else {
                format!("{cwd}/")
            };
        }
    }

    /// Say that what is on screen has been written into, so the next look asks
    /// again even though the typed path has not moved.
    pub fn mark_stale(&mut self) {
        self.stale = true;
        self.pending_select = self.selected_entry().map(|e| e.name.clone());
    }

    /// The directory that now needs listing, if the typed path has moved away
    /// from what is on screen. The caller sends it and hands the answer back.
    pub fn needs(&mut self) -> Option<String> {
        if self.input.is_empty() {
            return None;
        }
        let want = split_remote(&self.input).0;
        let settled = want == self.dir && !self.stale;
        if settled || self.pending.as_deref() == Some(want.as_str()) {
            return None;
        }
        self.stale = false;
        self.pending = Some(want.clone());
        Some(want)
    }

    /// Give up on a listing that turned out not to be a directory, and go back
    /// to the one that is still on screen.
    pub fn cancel(&mut self, dir: &str) {
        if self.pending.as_deref() != Some(dir) {
            return;
        }
        self.pending = None;
        self.input = if self.dir.ends_with('/') {
            self.dir.clone()
        } else {
            format!("{}/", self.dir)
        };
    }

    /// Take a listing. One for a directory that is no longer being asked about
    /// is dropped: the user has typed on since.
    pub fn apply(&mut self, dir: &str, listing: Listing, error: Option<String>) {
        if self.pending.as_deref() != Some(dir) {
            return;
        }
        self.pending = None;
        self.dir = dir.to_string();
        self.all = listing.entries;
        self.error = error;
        self.selected = 0;
        self.refilter();
        if let Some(name) = self.pending_select.take() {
            if let Some(i) = self.entries.iter().position(|e| e.name == name) {
                self.selected = i;
            }
        }
    }

    /// Narrow the listing to the segment being typed.
    pub fn refilter(&mut self) {
        let (_, filter) = split_remote(&self.input);
        let filter = filter.to_lowercase();
        self.entries = self
            .all
            .iter()
            .filter(|e| filter.is_empty() || e.name.to_lowercase().starts_with(&filter))
            .cloned()
            .collect();
        if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
    }

    pub fn push(&mut self, c: char) {
        self.input.push(c);
        self.selected = 0;
        self.refilter();
    }

    pub fn backspace(&mut self) {
        self.input.pop();
        self.selected = 0;
        self.refilter();
    }

    pub fn down(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn up(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + self.entries.len() - 1) % self.entries.len();
        }
    }

    pub fn selected_entry(&self) -> Option<&RemoteEntry> {
        self.entries.get(self.selected)
    }

    /// Walk into the selected entry. A symlink is tried the same way a
    /// directory is; if it turns out to be a file the listing says so and
    /// [`Listing::single_file`] catches it.
    pub fn descend(&mut self) {
        let Some(entry) = self.selected_entry().filter(|e| e.navigable()).cloned() else {
            return;
        };
        self.input = format!("{}/", join_remote(&self.dir, &entry.name));
        self.selected = 0;
    }

    pub fn ascend(&mut self) {
        let leaf = base_name(&self.dir);
        let parent = parent_remote(&self.dir);
        self.input = if parent.ends_with('/') {
            parent
        } else {
            format!("{parent}/")
        };
        self.selected = 0;
        // Leave the directory we came out of under the cursor, once its parent
        // has been listed.
        self.pending_select = Some(leaf);
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
            username: "app".into(),
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
    fn a_listing_line_gives_the_kind_the_size_and_the_whole_name() {
        let e = parse_ls_line("-rw-r--r--    1 app  app      124000 Sep 20 11:23 a file.txt")
            .expect("a file");
        assert_eq!(e.name, "a file.txt");
        assert_eq!(e.kind, RemoteKind::File);
        assert_eq!(e.size, 124_000);

        let d = parse_ls_line("drwxr-xr-x    5 app  app        4096 Sep 20 11:23 logs")
            .expect("a directory");
        assert!(d.is_dir());
        assert_eq!(d.name, "logs");
    }

    #[test]
    fn a_listing_asked_for_by_path_comes_back_by_path_and_is_read_by_name() {
        // `ls -la /srv/app` answers with what it matched, in full.
        let e = parse_ls_line("-rw-r--r-- 1 app app 22 Sep 20 11:23 /srv/app/notes.txt")
            .expect("a file");
        assert_eq!(e.name, "notes.txt");
        let lines = vec![
            "drwxr-xr-x ? app app 120 Sep 20 11:23 /srv/app/.".to_string(),
            "drwxr-xr-x ? app app 240 Sep 20 11:23 /srv/app/..".to_string(),
            "-rw-r--r-- ? app app  22 Sep 20 11:23 /srv/app/notes.txt".to_string(),
        ];
        let names: Vec<String> = parse_listing(&lines)
            .entries
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["notes.txt"]);
    }

    #[test]
    fn getting_there_is_not_an_error_however_much_ssh_says_about_it() {
        assert!(is_chatter("Connected to 127.0.0.1."));
        assert!(is_chatter(
            "Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts."
        ));
        assert!(!is_chatter("remote readdir(\"/root\"): Permission denied"));
    }

    #[test]
    fn a_symlink_keeps_its_name_and_not_its_target() {
        let l = parse_ls_line("lrwxrwxrwx    1 app  app           7 Sep 20 11:23 current -> v3")
            .expect("a link");
        assert_eq!(l.name, "current");
        assert_eq!(l.kind, RemoteKind::Link);
        // Walking into one is worth a try; the listing that comes back says
        // whether it was a directory.
        assert!(l.navigable());
    }

    #[test]
    fn a_line_that_is_not_a_listing_is_dropped_rather_than_guessed_at() {
        assert!(parse_ls_line("total 48").is_none());
        assert!(parse_ls_line("srwxr-xr-x 1 app app 0 Sep 20 11:23 sock").is_none());
        assert!(parse_ls_line("").is_none());
        assert!(parse_ls_line("-rw-r--r-- 1 app app").is_none());
    }

    #[test]
    fn dot_entries_go_and_folders_come_first() {
        let lines: Vec<String> = [
            "drwxr-xr-x 5 app app 4096 Sep 20 11:23 .",
            "drwxr-xr-x 5 app app 4096 Sep 20 11:23 ..",
            "-rw-r--r-- 1 app app   12 Sep 20 11:23 b.conf",
            "drwxr-xr-x 2 app app 4096 Sep 20 11:23 Zeta",
            "-rw-r--r-- 1 app app   12 Sep 20 11:23 a.conf",
            "drwxr-xr-x 2 app app 4096 Sep 20 11:23 alpha",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let names: Vec<String> = parse_listing(&lines)
            .entries
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["alpha", "Zeta", "a.conf", "b.conf"]);
    }

    #[test]
    fn listing_a_file_gives_back_the_file_itself() {
        let listing =
            parse_listing(&["-rw-r--r-- 1 app app 12 Sep 20 11:23 /srv/notes.txt".to_string()]);
        assert!(listing.single_file("/srv/notes.txt"));
        assert!(!listing.single_file("/srv/other.txt"));

        // A directory of one file that shares its name is still a directory,
        // and says so by listing itself.
        let dir = parse_listing(&[
            "drwxr-xr-x ? app app 60 Sep 20 11:23 /srv/app/.".to_string(),
            "drwxr-xr-x ? app app 80 Sep 20 11:23 /srv/app/..".to_string(),
            "-rw-r--r-- ? app app 12 Sep 20 11:23 /srv/app/app".to_string(),
        ]);
        assert!(!dir.single_file("/srv/app"));
    }

    #[test]
    fn the_pwd_reply_ends_a_command_and_the_echo_is_our_own() {
        assert_eq!(
            reply_line("Remote working directory: /srv/app\n"),
            LineKind::Marker("/srv/app".into())
        );
        assert_eq!(reply_line("sftp> -ls -la \"/srv\"\n"), LineKind::Skip);
        assert_eq!(reply_line("\n"), LineKind::Skip);
        assert_eq!(
            reply_line("Fetching /srv/a to /tmp/a\n"),
            LineKind::Output("Fetching /srv/a to /tmp/a".into())
        );
        // A meter that redrew itself is one line, not the whole reel of them.
        assert_eq!(
            reply_line("a  10%\ra  60%\ra 100%\n"),
            LineKind::Output("a 100%".into())
        );
    }

    #[test]
    fn a_path_is_quoted_so_a_space_stays_one_argument() {
        assert_eq!(quote("/srv/a file"), "\"/srv/a file\"");
        assert_eq!(quote("/srv/say \"hi\""), "\"/srv/say \\\"hi\\\"\"");
    }

    #[test]
    fn remote_paths_are_posix_whatever_this_machine_is() {
        assert_eq!(split_remote("/srv/app/"), ("/srv/app".into(), "".into()));
        assert_eq!(split_remote("/srv/ap"), ("/srv".into(), "ap".into()));
        assert_eq!(split_remote("/sr"), ("/".into(), "sr".into()));
        assert_eq!(split_remote("notes"), (".".into(), "notes".into()));

        assert_eq!(parent_remote("/srv/app/"), "/srv");
        assert_eq!(parent_remote("/srv"), "/");
        assert_eq!(parent_remote("/"), "/");
        assert_eq!(join_remote("/srv", "a"), "/srv/a");
        assert_eq!(join_remote("/", "a"), "/a");
        assert_eq!(base_name("/srv/app/"), "app");
    }

    fn listing(names: &[(&str, bool)]) -> Listing {
        Listing {
            entries: names
                .iter()
                .map(|(n, dir)| RemoteEntry {
                    name: (*n).to_string(),
                    kind: if *dir { RemoteKind::Dir } else { RemoteKind::File },
                    size: 0,
                })
                .collect(),
            listed_self: true,
        }
    }

    #[test]
    fn typing_filters_what_is_here_and_only_a_new_directory_is_asked_for() {
        let mut b = RemoteBrowser::new("/srv");
        assert_eq!(b.needs().as_deref(), Some("/srv"));
        // Asked once: until it comes back, typing must not ask again.
        assert_eq!(b.needs(), None);
        b.apply(
            "/srv",
            listing(&[("app", true), ("notes.txt", false), ("nope.txt", false)]),
            None,
        );
        assert_eq!(b.entries.len(), 3);

        for c in "not".chars() {
            b.push(c);
        }
        // Still the same directory, so nothing is asked for.
        assert_eq!(b.needs(), None);
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries[0].name, "notes.txt");

        b.backspace();
        b.backspace();
        b.backspace();
        assert_eq!(b.entries.len(), 3);
    }

    #[test]
    fn walking_in_and_out_asks_for_the_directory_either_way() {
        let mut b = RemoteBrowser::new("/srv");
        b.needs();
        b.apply("/srv", listing(&[("app", true), ("keep.txt", false)]), None);

        b.descend();
        assert_eq!(b.input, "/srv/app/");
        assert_eq!(b.needs().as_deref(), Some("/srv/app"));
        b.apply("/srv/app", listing(&[("inner.txt", false)]), None);
        assert_eq!(b.entries[0].name, "inner.txt");

        b.ascend();
        assert_eq!(b.needs().as_deref(), Some("/srv"));
        b.apply("/srv", listing(&[("app", true), ("keep.txt", false)]), None);
        // Back where we came from, with it under the cursor.
        assert_eq!(b.selected_entry().map(|e| e.name.as_str()), Some("app"));
    }

    #[test]
    fn a_listing_for_a_directory_nobody_is_looking_at_any_more_is_dropped() {
        let mut b = RemoteBrowser::new("/srv");
        b.needs();
        b.apply("/etc", listing(&[("passwd", false)]), None);
        assert!(b.entries.is_empty());
        assert_eq!(b.dir, "");
    }

    #[test]
    fn a_host_without_a_password_cannot_be_asked_for_one() {
        let argv = command_line(&host(), &PasswordHelper::Sshpass);
        assert_eq!(argv[0], "sftp");
        assert!(argv.windows(2).any(|w| w == ["-o", "BatchMode=yes"]));
        assert_eq!(argv.last().unwrap(), "app@example.com");
    }

    #[test]
    fn a_stored_password_goes_through_sshpass_and_never_an_argument() {
        let h = SshHost {
            password: "hunter2".into(),
            port: 2222,
            ..host()
        };
        let argv = command_line(&h, &PasswordHelper::Sshpass);
        assert_eq!(&argv[..3], &["sshpass", "-e", "sftp"]);
        assert!(!argv.iter().any(|a| a.contains("hunter2")));
        // sftp spells the port `-P`, and BatchMode would forbid the very
        // password we have.
        assert!(argv.windows(2).any(|w| w == ["-P", "2222"]));
        assert!(!argv.iter().any(|a| a == "BatchMode=yes"));
    }
}

