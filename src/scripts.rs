//! Scripts: run a file from a library on an SSH host or in a container, and
//! show what it printed in the log pane.
//!
//! A script is never copied anywhere. It is fed to its interpreter on stdin —
//! `sh -s -- <args>` for a shell, `python3 - <args>` for anything else — over
//! the same ssh, or the same `docker exec -i`, that every other command to that
//! host or container goes through. So nothing is left behind on the far side,
//! there is no temporary path to clean up or to race on, and the arguments are
//! the only thing that has to be quoted for the remote shell.
//!
//! The cost is that the script's stdin is the script: one that reads from the
//! terminal — `sudo` asking for a password, `read` waiting on a person — gets
//! end-of-file instead. That is said in the docs rather than worked around,
//! because a terminal on the far side would echo the script back into its own
//! output.
//!
//! The library has three shelves, and the chooser shows them as folders:
//! the scripts compiled into the program, a directory of the user's own, and
//! any number of git repositories, cloned into the cache and brought up to date
//! with the `git` CLI — whose credentials are the user's and none of ours.

use crate::chooser::Choice;
use crate::config::ScriptRepo;
use crate::docker;
use crate::logs::{LogTarget, Ring};
use crate::platform;
use crate::ssh::{self, PasswordHelper};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The scripts that ship with the program. POSIX `sh`, and careful about which
/// tools they assume, because the same file has to say something useful on a
/// full server and in a busybox container.
const BUILTIN: &[(&str, &str)] = &[
    ("overview.sh", include_str!("scripts/builtin/overview.sh")),
    ("disk-usage.sh", include_str!("scripts/builtin/disk-usage.sh")),
    ("memory.sh", include_str!("scripts/builtin/memory.sh")),
    ("listening-ports.sh", include_str!("scripts/builtin/listening-ports.sh")),
    ("failed-units.sh", include_str!("scripts/builtin/failed-units.sh")),
    ("journal-errors.sh", include_str!("scripts/builtin/journal-errors.sh")),
    ("pending-updates.sh", include_str!("scripts/builtin/pending-updates.sh")),
    ("cert-expiry.sh", include_str!("scripts/builtin/cert-expiry.sh")),
    ("docker-summary.sh", include_str!("scripts/builtin/docker-summary.sh")),
];

/// The chooser's folder for the scripts above.
const BUILTIN_FOLDER: &str = "built-in";
/// The chooser's folder for the user's own directory.
const LOCAL_FOLDER: &str = "local";

/// Bigger than this is not a script anyone meant to feed through a pipe.
const MAX_SCRIPT: u64 = 512 * 1024;
/// How deep a library directory is walked, and how many files are looked at
/// in all, so that pointing a repo at something enormous costs a short list
/// rather than a hung picker.
const MAX_DEPTH: usize = 6;
const MAX_FILES: usize = 2000;
/// Files without a `#!` line still count as scripts with one of these.
const EXTENSIONS: &[&str] = &["sh", "bash", "py", "pl", "rb"];
/// Interpreters that take a script on stdin with `-s`, and arguments after
/// `--`. Everything else is handed `-`, which python, perl, ruby and node all
/// read as "the program is on stdin".
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash"];

/// Where a script came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Builtin,
    Local,
    /// The repository of this name in `config.toml`.
    Repo(String),
}

/// One script, read and ready to show — and, once it is, exactly what runs.
#[derive(Debug, Clone)]
pub struct Script {
    /// How the run form and the chooser refer to it: `builtin:overview.sh`,
    /// `local:net/ports.sh`, `repo:<repo>/<path>`.
    pub id: String,
    /// The path inside its shelf, `/`-separated.
    pub path: String,
    pub source: Source,
    /// On disk, for a local or repo script; none for a built-in one.
    pub file: Option<PathBuf>,
    pub body: String,
}

impl Script {
    /// The file's own name.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn header(&self) -> Header {
        header(&self.body)
    }

    /// Where it came from, for the run form and the report.
    pub fn origin(&self) -> String {
        match (&self.source, &self.file) {
            (Source::Builtin, _) => "built into controlcenter".into(),
            (Source::Local, Some(f)) => f.display().to_string(),
            (Source::Repo(name), Some(f)) => match repo_commit(f) {
                Some(commit) => format!("repo '{name}' at {commit} · {}", self.path),
                None => format!("repo '{name}' · {}", self.path),
            },
            (_, None) => self.path.clone(),
        }
    }
}

/// What a script says about itself in the comments at its top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// `# description: …` — the line the chooser shows beside the name.
    pub description: String,
    /// `# args: …` — what the arguments field is for, shown under it.
    pub args: String,
}

/// Read the header: comment lines after the `#!`, up to the first line that is
/// not one. Keys are case-insensitive, and anything that is not a key is just
/// a comment.
pub fn header(body: &str) -> Header {
    let mut out = Header::default();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("#!") || line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix('#') else {
            break;
        };
        let Some((key, value)) = comment.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "description" if out.description.is_empty() => out.description = value,
            "args" if out.args.is_empty() => out.args = value,
            _ => {}
        }
    }
    out
}

/// The interpreter a script asks for in its `#!` line, with whatever makes it
/// read the program from stdin. No `#!` at all means `sh`, which is what a
/// shell would have run it with too.
///
/// `#!/usr/bin/env python3` becomes `python3 -` rather than `/usr/bin/env
/// python3 -`: env is only there to search the PATH, and the remote shell does
/// that anyway. A full path is kept as it was written — that is what the
/// script said it needs.
pub fn interpreter(body: &str) -> Vec<String> {
    let fallback = || vec!["sh".to_string(), "-s".to_string(), "--".to_string()];
    let first = body.lines().next().unwrap_or("");
    let Some(line) = first.strip_prefix("#!") else {
        return fallback();
    };
    let mut words = line.split_whitespace().map(String::from);
    let Some(mut program) = words.next() else {
        return fallback();
    };
    let mut rest: Vec<String> = words.collect();
    if basename(&program) == "env" {
        // `env -S` and its kind are env's own flags, not the interpreter's.
        let mut after = rest.into_iter().skip_while(|w| w.starts_with('-'));
        let Some(p) = after.next() else {
            return fallback();
        };
        program = p;
        rest = after.collect();
    }
    let shell = SHELLS.contains(&basename(&program));
    let mut argv = vec![program];
    argv.extend(rest);
    if shell {
        argv.push("-s".into());
        argv.push("--".into());
    } else {
        argv.push("-".into());
    }
    argv
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Split the arguments field the way a POSIX shell splits words: on blanks,
/// with `'…'`, `"…"` and `\` to keep one together. Nothing is expanded — what
/// is typed is what the script gets.
pub fn split_args(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(x) => word.push(x),
                        None => return Err("a ' is never closed".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        // Inside double quotes a backslash only escapes what
                        // would otherwise end or expand the string.
                        Some('\\') => match chars.next() {
                            Some(x @ ('"' | '\\' | '$' | '`')) => word.push(x),
                            Some(x) => {
                                word.push('\\');
                                word.push(x);
                            }
                            None => return Err("a \" is never closed".into()),
                        },
                        Some(x) => word.push(x),
                        None => return Err("a \" is never closed".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.push(chars.next().unwrap_or('\\'));
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        out.push(word);
    }
    Ok(out)
}

/// What the far side runs: the interpreter, then the arguments.
pub fn remote_words(body: &str, args: &[String]) -> Vec<String> {
    let mut words = interpreter(body);
    words.extend(args.iter().cloned());
    words
}

/// The one string an SSH host's shell is handed for `words`.
pub fn remote_line(words: &[String]) -> String {
    words
        .iter()
        .map(|w| ssh::posix_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// The library
// ---------------------------------------------------------------------------

/// Where a repository's clone lives. By a name made safe for a path rather
/// than the name itself, which is free text in `config.toml`.
pub fn repo_dir(repos_dir: &Path, repo: &ScriptRepo) -> PathBuf {
    repos_dir.join(repo_key(&repo.name))
}

fn repo_key(name: &str) -> String {
    let key: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let key = key.trim_matches(|c| c == '-' || c == '.').to_string();
    if key.is_empty() {
        "repo".into()
    } else {
        key
    }
}

/// Every script on every shelf, built-in first, each shelf in path order.
pub fn catalog(local_dir: &Path, repos_dir: &Path, repos: &[ScriptRepo]) -> Vec<Script> {
    let mut out: Vec<Script> = BUILTIN
        .iter()
        .map(|(name, body)| Script {
            id: format!("builtin:{name}"),
            path: (*name).to_string(),
            source: Source::Builtin,
            file: None,
            body: (*body).to_string(),
        })
        .collect();
    for (path, file, body) in walk(local_dir) {
        out.push(Script {
            id: format!("local:{path}"),
            path,
            source: Source::Local,
            file: Some(file),
            body,
        });
    }
    for repo in repos {
        let key = repo_key(&repo.name);
        for (path, file, body) in walk(&repos_dir.join(&key)) {
            out.push(Script {
                id: format!("repo:{key}/{path}"),
                path,
                source: Source::Repo(repo.name.clone()),
                file: Some(file),
                body,
            });
        }
    }
    out
}

/// One script by its id, read again from where it lives so that what the run
/// form shows is what is on disk now.
pub fn load(id: &str, local_dir: &Path, repos_dir: &Path, repos: &[ScriptRepo]) -> Result<Script, String> {
    let (source, file, path) = if let Some(name) = id.strip_prefix("builtin:") {
        let body = BUILTIN
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| (*b).to_string())
            .ok_or_else(|| format!("no built-in script is called {name}"))?;
        return Ok(Script {
            id: id.into(),
            path: name.into(),
            source: Source::Builtin,
            file: None,
            body,
        });
    } else if let Some(path) = id.strip_prefix("local:") {
        (Source::Local, local_dir.join(path), path.to_string())
    } else if let Some(rest) = id.strip_prefix("repo:") {
        let (key, path) = rest
            .split_once('/')
            .ok_or_else(|| format!("'{id}' names no script"))?;
        let repo = repos
            .iter()
            .find(|r| repo_key(&r.name) == key)
            .ok_or_else(|| format!("no repository '{key}' is configured any more"))?;
        (
            Source::Repo(repo.name.clone()),
            repos_dir.join(key).join(path),
            path.to_string(),
        )
    } else {
        return Err(format!("'{id}' names no script"));
    };
    if path.split('/').any(|seg| seg == "..") {
        return Err(format!("'{id}' points outside its library"));
    }
    let body = read_script(&file).ok_or_else(|| format!("{} cannot be read as a script", file.display()))?;
    Ok(Script {
        id: id.into(),
        path,
        source,
        file: Some(file),
        body,
    })
}

/// The chooser's view of the library: a shelf is a folder, and so is every
/// directory inside one. A description goes beside the name, so typing
/// searches it as well.
pub fn choices(scripts: &[Script], repos: &[ScriptRepo]) -> Vec<Choice> {
    scripts
        .iter()
        .map(|s| {
            let mut folder = vec![match &s.source {
                Source::Builtin => BUILTIN_FOLDER.to_string(),
                Source::Local => LOCAL_FOLDER.to_string(),
                Source::Repo(name) => repos
                    .iter()
                    .find(|r| &r.name == name)
                    .map_or_else(|| name.clone(), |r| r.name.clone()),
            }];
            let mut parts: Vec<&str> = s.path.split('/').collect();
            parts.pop();
            folder.extend(parts.into_iter().map(String::from));
            let desc = s.header().description;
            let label = if desc.is_empty() {
                s.name().to_string()
            } else {
                format!("{} — {desc}", s.name())
            };
            Choice::in_path(s.id.clone(), label, folder)
        })
        .collect()
}

/// Every script under `root`: `(path inside it, file, body)`. Hidden entries
/// are skipped, which is what keeps a clone's `.git` out of the list.
fn walk(root: &Path) -> Vec<(String, PathBuf, String)> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    walk_into(root, "", 0, &mut seen, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk_into(
    dir: &Path,
    prefix: &str,
    depth: usize,
    seen: &mut usize,
    out: &mut Vec<(String, PathBuf, String)>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if *seen >= MAX_FILES {
            return;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk_into(&entry.path(), &path, depth + 1, seen, out);
        } else {
            *seen += 1;
            let file = entry.path();
            if let Some(body) = read_script(&file) {
                out.push((path, file, body));
            }
        }
    }
}

/// A file's text, if it is a script: small, text, and either starting with
/// `#!` or named like one. A README beside the scripts is not one.
fn read_script(file: &Path) -> Option<String> {
    let meta = std::fs::metadata(file).ok()?;
    if !meta.is_file() || meta.len() > MAX_SCRIPT {
        return None;
    }
    let body = std::fs::read_to_string(file).ok()?;
    let named_like_one = file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXTENSIONS.contains(&e));
    (body.starts_with("#!") || named_like_one).then_some(body)
}

/// The commit the clone a file is in is on.
fn repo_commit(file: &Path) -> Option<String> {
    head_commit(file.ancestors().find(|p| p.join(".git").is_dir())?)
}

/// The commit a clone is on, read out of `.git/HEAD` rather than by running
/// git: a sync leaves it detached, so the file *is* the commit.
pub fn head_commit(dir: &Path) -> Option<String> {
    let head = std::fs::read_to_string(dir.join(".git").join("HEAD")).ok()?;
    let head = head.trim();
    (!head.is_empty() && !head.starts_with("ref:")).then(|| head.chars().take(10).collect())
}

/// A repository URL without the `user:token@` an https URL can carry, for
/// anything that writes it down.
pub fn display_url(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        if let Some((auth, host)) = rest.split_once('@') {
            if !auth.contains('/') {
                return format!("{scheme}://{host}");
            }
        }
    }
    url.to_string()
}

// ---------------------------------------------------------------------------
// Keeping a repository up to date
// ---------------------------------------------------------------------------

/// The git commands that bring a clone to what its repository says now: a
/// shallow fetch of the ref, checked out detached, and anything left over from
/// a previous ref swept away. The same steps make a new clone, after an
/// `init`, so a ref that is a commit rather than a branch works the same way.
/// The directory is ours alone, so nothing in it is anyone's work to lose.
pub fn sync_commands(repo: &ScriptRepo, dir: &Path) -> Vec<Vec<String>> {
    let d = dir.display().to_string();
    let git = |args: &[&str]| -> Vec<String> {
        std::iter::once("git".to_string())
            .chain(["-C".to_string(), d.clone()])
            .chain(args.iter().map(|a| a.to_string()))
            .collect()
    };
    let mut cmds = Vec::new();
    if !dir.join(".git").is_dir() {
        cmds.push(vec!["git".into(), "init".into(), "-q".into(), d.clone()]);
        cmds.push(git(&["remote", "add", "origin", &repo.url]));
    } else {
        cmds.push(git(&["remote", "set-url", "origin", &repo.url]));
    }
    let reference = if repo.reference.trim().is_empty() {
        "HEAD"
    } else {
        repo.reference.trim()
    };
    cmds.push(git(&["fetch", "-q", "--depth", "1", "origin", reference]));
    cmds.push(git(&["checkout", "-q", "--force", "--detach", "FETCH_HEAD"]));
    cmds.push(git(&["clean", "-q", "-fdx"]));
    cmds
}

pub enum ScriptMsg {
    /// A run has ended, by itself or because it was stopped.
    Finished {
        id: u64,
        result: Result<i32, String>,
    },
    /// A repository sync has ended.
    Synced {
        repo: String,
        result: Result<(), String>,
    },
}

/// Bring a repository up to date on a thread, with what git prints in `ring`.
///
/// git is told it has no one to ask: a credential prompt would wait forever on
/// a terminal the TUI owns. A repository that needs a password needs a
/// credential helper or a key in the agent, which is how git is used from any
/// other program as well.
pub fn spawn_sync(repo: ScriptRepo, dir: PathBuf, ring: Arc<Ring>, tx: Sender<ScriptMsg>) {
    thread::spawn(move || {
        // git's own messages can repeat the URL too, so every line is cleaned.
        let shown = display_url(&repo.url);
        let scrub = |line: &str| line.replace(&repo.url, &shown);
        let result = (|| {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            for argv in sync_commands(&repo, &dir) {
                ring.push(scrub(&format!("$ {}", crate::report::command_line(&argv))));
                let mut cmd = Command::new(platform::program(&argv[0]));
                cmd.args(&argv[1..])
                    .env("GIT_TERMINAL_PROMPT", "0")
                    .stdin(Stdio::null());
                if std::env::var_os("GIT_SSH_COMMAND").is_none() {
                    cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
                }
                #[cfg(windows)]
                platform::hidden(&mut cmd);
                let out = cmd.output().map_err(|e| format!("running git: {e}"))?;
                let said = String::from_utf8_lossy(&out.stderr);
                for line in said.lines().filter(|l| !l.trim().is_empty()) {
                    ring.push(scrub(line));
                }
                if !out.status.success() {
                    let why = said
                        .lines()
                        .rev()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("git failed");
                    return Err(scrub(why));
                }
            }
            Ok(())
        })();
        let _ = tx.send(ScriptMsg::Synced {
            repo: repo.name,
            result,
        });
    });
}

// ---------------------------------------------------------------------------
// Running one
// ---------------------------------------------------------------------------

/// How a finished run ended.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The exit code, or why there is none.
    pub result: Result<i32, String>,
    pub duration: Duration,
    /// Ended from here rather than by itself.
    pub stopped: bool,
}

impl Outcome {
    pub fn label(&self) -> String {
        match (&self.result, self.stopped) {
            (_, true) => "stopped".into(),
            (Ok(0), _) => "exited 0".into(),
            (Ok(c), _) => format!("exited {c}"),
            (Err(e), _) => e.clone(),
        }
    }

    pub fn failed(&self) -> bool {
        !self.stopped && !matches!(self.result, Ok(0))
    }
}

/// One run: the process, and the ring it is filling.
pub struct Run {
    pub id: u64,
    pub target: LogTarget,
    /// The script's file name.
    pub script: String,
    /// Where it came from — see [`Script::origin`].
    pub origin: String,
    pub argv: Vec<String>,
    /// The `docker exec` user, where it ran in a container as someone.
    pub user: String,
    pub started: Instant,
    pub ring: Arc<Ring>,
    pub outcome: Option<Outcome>,
    child: Arc<Mutex<Option<Child>>>,
    stopping: Arc<AtomicBool>,
}

impl Run {
    pub fn running(&self) -> bool {
        self.outcome.is_none()
    }

    /// Kill it. The waiting thread sees it go and reports the end as usual.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(c) = self.child.lock().unwrap().as_mut() {
            let _ = c.kill();
        }
    }

    pub fn finish(&mut self, result: Result<i32, String>) {
        self.outcome = Some(Outcome {
            result,
            duration: self.started.elapsed(),
            stopped: self.stopping.load(Ordering::SeqCst),
        });
    }
}

/// What a run is, before it is one.
pub struct Launch {
    /// What it runs on: an SSH host or a container.
    pub on: LogTarget,
    pub script: Script,
    pub argv: Vec<String>,
    pub password: String,
    pub user: String,
}

/// Start a run: the argv — from [`ssh::remote_argv`] or
/// [`docker::command_line`] — with the script written to its stdin, and what it
/// prints in a ring of its own.
pub fn start(id: u64, launch: Launch, helper: &PasswordHelper, tx: Sender<ScriptMsg>) -> Result<Run, String> {
    let mut cmd = ssh::command(&launch.argv, &launch.password, helper);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running {}: {e}", launch.argv[0]))?;
    let ring = Arc::new(Ring::new("script"));

    // Written from a thread of its own: a script bigger than the pipe would
    // otherwise wait on output nobody is reading yet.
    if let Some(mut stdin) = child.stdin.take() {
        let body = launch.script.body.clone();
        thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
    }
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        let ring = Arc::clone(&ring);
        readers.push(thread::spawn(move || pump(out, |l| ring.push(l))));
    }
    if let Some(err) = child.stderr.take() {
        let ring = Arc::clone(&ring);
        readers.push(thread::spawn(move || pump(err, |l| ring.push_err(l))));
    }

    let child = Arc::new(Mutex::new(Some(child)));
    let waiting = Arc::clone(&child);
    thread::spawn(move || {
        let result = loop {
            let state = match waiting.lock().unwrap().as_mut() {
                Some(c) => c.try_wait(),
                None => break Err("gone".to_string()),
            };
            match state {
                Ok(Some(status)) => {
                    break status.code().ok_or_else(|| "killed by a signal".to_string())
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => break Err(e.to_string()),
            }
        };
        for r in readers {
            let _ = r.join();
        }
        waiting.lock().unwrap().take();
        let _ = tx.send(ScriptMsg::Finished { id, result });
    });

    Ok(Run {
        id,
        target: LogTarget::script(launch.on, launch.script.name(), id),
        script: launch.script.name().to_string(),
        origin: launch.script.origin(),
        argv: launch.argv,
        user: launch.user,
        started: Instant::now(),
        ring,
        outcome: None,
        child,
        stopping: Arc::new(AtomicBool::new(false)),
    })
}

/// Line by line into `push`, whatever the bytes are: a script that prints
/// something that is not UTF-8 must not end its own log there. Escapes go,
/// the same as in a container's log.
fn pump(stream: impl Read, push: impl Fn(String)) {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf);
                push(docker::strip_escapes(line.trim_end_matches(['\n', '\r'])));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_shell_reads_its_script_from_stdin_and_its_arguments_after_dashes() {
        assert_eq!(interpreter("#!/bin/sh\necho hi"), words(&["/bin/sh", "-s", "--"]));
        assert_eq!(
            interpreter("#!/usr/bin/env bash\n"),
            words(&["bash", "-s", "--"])
        );
        assert_eq!(interpreter("#!/bin/bash -e\n"), words(&["/bin/bash", "-e", "-s", "--"]));
        // No #! at all is what any shell would have run it with.
        assert_eq!(interpreter("echo hi"), words(&["sh", "-s", "--"]));
        assert_eq!(interpreter(""), words(&["sh", "-s", "--"]));
    }

    #[test]
    fn anything_else_is_handed_a_dash_for_stdin() {
        assert_eq!(interpreter("#!/usr/bin/env python3\n"), words(&["python3", "-"]));
        assert_eq!(interpreter("#!/usr/bin/env -S python3 -u\n"), words(&["python3", "-u", "-"]));
        assert_eq!(interpreter("#!/usr/bin/perl -w\n"), words(&["/usr/bin/perl", "-w", "-"]));
    }

    #[test]
    fn the_header_is_read_until_the_first_line_that_is_not_a_comment() {
        let h = header(
            "#!/bin/sh\n# Some prose first.\n# Description: what it does\n# args: [path]\n\necho\n# description: not this\n",
        );
        assert_eq!(h.description, "what it does");
        assert_eq!(h.args, "[path]");
        assert_eq!(header("echo hi\n# description: too late"), Header::default());
    }

    #[test]
    fn arguments_split_like_a_shell_would_split_them() {
        assert_eq!(split_args("").unwrap(), Vec::<String>::new());
        assert_eq!(split_args("  /var   10 ").unwrap(), words(&["/var", "10"]));
        assert_eq!(
            split_args(r#"'a b' "c \"d\"" e\ f g'h'"#).unwrap(),
            words(&["a b", "c \"d\"", "e f", "gh"])
        );
        assert_eq!(split_args("''").unwrap(), words(&[""]));
        // Nothing is expanded: a $ is a $.
        assert_eq!(split_args("$HOME").unwrap(), words(&["$HOME"]));
        assert!(split_args("'open").is_err());
        assert!(split_args("\"open").is_err());
    }

    #[test]
    fn the_remote_line_quotes_every_argument_for_the_far_shell() {
        let w = remote_words("#!/bin/sh\n", &words(&["/var/lib", "it's; rm -rf /"]));
        assert_eq!(remote_line(&w), r"/bin/sh -s -- /var/lib 'it'\''s; rm -rf /'");
    }

    #[test]
    fn every_builtin_script_is_sh_and_says_what_it_does() {
        for (name, body) in BUILTIN {
            assert!(body.starts_with("#!/bin/sh\n"), "{name} is not sh");
            assert!(!header(body).description.is_empty(), "{name} has no description");
            assert!(!body.contains('\r'), "{name} has CRLF line endings");
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("controlcenter-scripts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_library_lists_scripts_by_folder_and_leaves_out_everything_else() {
        let local = scratch("local");
        std::fs::create_dir_all(local.join("net")).unwrap();
        std::fs::create_dir_all(local.join(".git")).unwrap();
        std::fs::write(local.join("net/ports.sh"), "echo ports\n").unwrap();
        std::fs::write(local.join("check"), "#!/bin/sh\n# description: a check\n").unwrap();
        std::fs::write(local.join("README.md"), "# not a script\n").unwrap();
        std::fs::write(local.join(".git/hook.sh"), "#!/bin/sh\n").unwrap();

        let repos = scratch("repos");
        let repo = ScriptRepo {
            name: "Ops Team".into(),
            url: "https://example.com/ops.git".into(),
            reference: String::new(),
        };
        let dir = repo_dir(&repos, &repo);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deploy.py"), "#!/usr/bin/env python3\n").unwrap();

        let all = catalog(&local, &repos, std::slice::from_ref(&repo));
        let ids: Vec<&str> = all.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"local:net/ports.sh"));
        assert!(ids.contains(&"local:check"));
        assert!(ids.contains(&"repo:Ops-Team/deploy.py"));
        assert!(!ids.iter().any(|i| i.contains("README") || i.contains(".git")));

        let listed = choices(&all, std::slice::from_ref(&repo));
        let check = listed.iter().find(|c| c.value == "local:check").unwrap();
        assert_eq!(check.folder, words(&["local"]));
        assert_eq!(check.name, "check — a check");
        let ports = listed.iter().find(|c| c.value == "local:net/ports.sh").unwrap();
        assert_eq!(ports.folder, words(&["local", "net"]));
        let deploy = listed.iter().find(|c| c.value.starts_with("repo:")).unwrap();
        assert_eq!(deploy.folder, words(&["Ops Team"]));

        // Loading by id reads the file again, and nothing climbs out.
        let s = load("local:net/ports.sh", &local, &repos, &[]).unwrap();
        assert_eq!(s.body, "echo ports\n");
        assert!(load("local:../etc/passwd", &local, &repos, &[]).is_err());
        assert!(load("builtin:overview.sh", &local, &repos, &[]).is_ok());
        assert!(load("repo:Ops-Team/deploy.py", &local, &repos, &[]).is_err());
        assert!(load("repo:Ops-Team/deploy.py", &local, &repos, &[repo]).is_ok());
        let _ = std::fs::remove_dir_all(&local);
        let _ = std::fs::remove_dir_all(&repos);
    }

    #[test]
    fn a_token_in_a_repository_url_is_never_written_down() {
        assert_eq!(
            display_url("https://me:ghp_secret@github.com/me/ops.git"),
            "https://github.com/me/ops.git"
        );
        assert_eq!(display_url("git@github.com:me/ops.git"), "git@github.com:me/ops.git");
        assert_eq!(display_url("https://github.com/a@b/ops.git"), "https://github.com/a@b/ops.git");
    }

    #[test]
    fn a_new_clone_and_an_update_end_on_the_same_detached_checkout() {
        let repo = ScriptRepo {
            name: "ops".into(),
            url: "git@example.com:ops.git".into(),
            reference: "v2".into(),
        };
        let dir = scratch("sync").join("ops");
        let fresh = sync_commands(&repo, &dir);
        assert_eq!(fresh[0][1], "init");
        assert!(fresh.iter().any(|c| c.ends_with(&words(&["fetch", "-q", "--depth", "1", "origin", "v2"]))));
        assert!(fresh.iter().any(|c| c.ends_with(&words(&["--detach", "FETCH_HEAD"]))));
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let again = sync_commands(&repo, &dir);
        assert!(again[0].ends_with(&words(&["set-url", "origin", "git@example.com:ops.git"])));
        let head = ScriptRepo {
            reference: " ".into(),
            ..repo
        };
        assert!(sync_commands(&head, &dir)
            .iter()
            .any(|c| c.ends_with(&words(&["origin", "HEAD"]))));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    #[cfg(not(windows))]
    fn a_run_feeds_its_script_on_stdin_and_keeps_stderr_apart() {
        let (tx, rx) = std::sync::mpsc::channel();
        let script = Script {
            id: "builtin:test".into(),
            path: "test.sh".into(),
            source: Source::Builtin,
            file: None,
            body: "echo out \"$1\"\necho err >&2\nexit 3\n".into(),
        };
        let mut argv = vec!["sh".to_string()];
        argv.extend(remote_words(&script.body, &words(&["two words"])));
        // The interpreter is `sh -s --`, so this runs `sh sh -s -- …`: drop the
        // second sh, since locally there is no remote shell to hand it to.
        argv.remove(0);
        let launch = Launch {
            on: LogTarget::Ssh("h".into()),
            script,
            argv,
            password: String::new(),
            user: String::new(),
        };
        let mut run = start(1, launch, &PasswordHelper::None, tx).unwrap();
        let ScriptMsg::Finished { id, result } = rx.recv_timeout(Duration::from_secs(10)).unwrap() else {
            panic!("expected the run to finish");
        };
        assert_eq!(id, 1);
        run.finish(result);
        assert_eq!(run.outcome.as_ref().unwrap().label(), "exited 3");
        let lines = run.ring.all();
        assert!(lines.iter().any(|e| e.text == "out two words" && !e.error));
        assert!(lines.iter().any(|e| e.text == "err" && e.error));
    }
}
