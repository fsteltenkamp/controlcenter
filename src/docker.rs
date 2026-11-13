//! Docker: the containers and compose stacks on this machine, and on any SSH
//! host that says it runs docker.
//!
//! Everything goes through the `docker` CLI, the same as every VPN client goes
//! through its own. A remote engine is the same CLI run *on the host* over ssh,
//! with the host's port, key, password and options from `ssh::connection_args`
//! — not `docker -H ssh://`, whose ssh helper takes none of those and would put
//! `~/.ssh/config` back in charge of hosts this program already describes.
//!
//! A stack is a compose project as docker labels it. Nothing here reads a
//! compose file: what is running says which project it belongs to, so a stack
//! started from any directory, by any tool, shows up without being configured.

use crate::logs::{self, LogTarget, Ring};
use crate::platform;
use crate::ssh::{self, PasswordHelper};
use crate::types::SshHost;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// How many lines a container's log starts with. The ring keeps
/// [`logs::RING_CAP`]; this is how far back the first look goes.
const LOG_TAIL: usize = 1000;

/// Where docker runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Engine {
    Local,
    /// The SSH-tab host of this name.
    Ssh(String),
}

impl Engine {
    pub fn label(&self) -> String {
        match self {
            Self::Local => "this machine".into(),
            Self::Ssh(n) => n.clone(),
        }
    }

    /// How a [`LogTarget::Docker`] names it: empty for this machine, which no
    /// SSH host can be called.
    pub fn key(&self) -> &str {
        match self {
            Self::Local => "",
            Self::Ssh(n) => n,
        }
    }

    pub fn from_key(key: &str) -> Self {
        if key.is_empty() {
            Self::Local
        } else {
            Self::Ssh(key.to_string())
        }
    }

    pub fn target(&self) -> LogTarget {
        LogTarget::docker(self.key(), "", "")
    }
}

/// How much a container needs looking at, in increasing order, so the worst
/// of a stack is its `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    /// Stopped on purpose, or never started.
    Idle,
    Good,
    /// Coming up, paused, or a health check still deciding.
    Warn,
    /// Crashed, unhealthy, dead, or restarting in a loop.
    Bad,
}

/// The worst condition in a stack: one crashed service is the stack's story.
pub fn worst<'a>(containers: impl IntoIterator<Item = &'a Container>) -> Condition {
    containers
        .into_iter()
        .map(|c| c.condition().0)
        .max()
        .unwrap_or(Condition::Idle)
}

/// One container, as `docker ps` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    /// `running`, `exited`, `paused`, `restarting`, `created`, `dead`.
    pub state: String,
    /// docker's own sentence: `Up 3 hours (healthy)`, `Exited (0) 2 days ago`.
    pub status: String,
    pub ports: String,
    /// The compose project; empty for a container nothing composed.
    pub project: String,
    pub service: String,
    pub working_dir: String,
    /// Comma separated, as compose labels them.
    pub config_files: String,
    pub created: String,
}

impl Container {
    /// Up in the sense `Enter` means: the next press would stop it.
    pub fn is_running(&self) -> bool {
        matches!(self.state.as_str(), "running" | "restarting" | "paused")
    }

    /// `healthy`, `unhealthy` or `health: starting`, when the image has a check.
    pub fn health(&self) -> Option<&str> {
        let open = self.status.rfind('(')?;
        let inner = self.status[open + 1..].strip_suffix(')')?;
        (inner.contains("health")).then_some(inner)
    }

    /// The code in `Exited (137) 2 hours ago`.
    pub fn exit_code(&self) -> Option<i32> {
        let rest = self.status.strip_prefix("Exited (")?;
        rest.split_once(')')?.0.parse().ok()
    }

    /// The one word that says whether something is wrong, and how wrong.
    ///
    /// An exit code is read the way a person stopping a container would read
    /// it: 0 is a clean stop, and so are 130 and 143 — SIGINT and SIGTERM, which
    /// is what `docker stop` sends. Anything else is a crash, including 137: a
    /// stop that had to fall back to SIGKILL and the OOM killer look the same.
    pub fn condition(&self) -> (Condition, String) {
        match (self.state.as_str(), self.health()) {
            (_, Some("unhealthy")) => (Condition::Bad, "unhealthy".into()),
            ("running", Some("healthy")) => (Condition::Good, "healthy".into()),
            ("running", Some(_)) => (Condition::Warn, "starting".into()),
            ("running", None) => (Condition::Good, "running".into()),
            ("restarting", _) => (Condition::Bad, "restarting".into()),
            ("paused", _) => (Condition::Warn, "paused".into()),
            ("dead", _) => (Condition::Bad, "dead".into()),
            ("exited", _) => match self.exit_code() {
                Some(0 | 130 | 143) | None => (Condition::Idle, "stopped".into()),
                Some(code) => (Condition::Bad, format!("crashed ({code})")),
            },
            ("created", _) => (Condition::Idle, "created".into()),
            (other, _) => (Condition::Warn, other.to_string()),
        }
    }

    /// What a pane or a report calls it: the service, where compose gave it one.
    pub fn label(&self) -> &str {
        if self.service.is_empty() {
            &self.name
        } else {
            &self.service
        }
    }

    pub fn target(&self, engine: &Engine) -> LogTarget {
        LogTarget::docker(engine.key(), &self.project, &self.name)
    }
}

/// How the stack list names the containers that belong to no project.
pub const STANDALONE: &str = "(no stack)";

/// A compose project and the containers in it, or — with an empty name — every
/// container that belongs to none.
pub struct Stack<'a> {
    pub name: &'a str,
    pub containers: Vec<&'a Container>,
}

impl Stack<'_> {
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            STANDALONE
        } else {
            self.name
        }
    }

    pub fn running(&self) -> usize {
        self.containers.iter().filter(|c| c.is_running()).count()
    }

    /// Where compose was run from and with which files, taken from whichever
    /// container says so — every container of one project carries the same.
    pub fn working_dir(&self) -> &str {
        self.containers
            .iter()
            .map(|c| c.working_dir.as_str())
            .find(|w| !w.is_empty())
            .unwrap_or("")
    }

    pub fn config_files(&self) -> Vec<&str> {
        self.containers
            .iter()
            .map(|c| c.config_files.as_str())
            .find(|f| !f.is_empty())
            .map(|f| f.split(',').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }
}

/// The stacks on one engine: projects by name, then the containers that belong
/// to none. Sorted rather than in docker's order, which is by creation and
/// moves a stack every time one of its containers is recreated.
pub fn stacks(containers: &[Container]) -> Vec<Stack<'_>> {
    let mut names: Vec<&str> = containers.iter().map(|c| c.project.as_str()).collect();
    names.sort_unstable_by(|a, b| (a.is_empty(), *a).cmp(&(b.is_empty(), *b)));
    names.dedup();
    names
        .into_iter()
        .map(|name| Stack {
            name,
            containers: members(containers, name),
        })
        .collect()
}

/// The containers of one project, by service and then by name.
pub fn members<'a>(containers: &'a [Container], project: &str) -> Vec<&'a Container> {
    let mut out: Vec<&Container> = containers.iter().filter(|c| c.project == project).collect();
    out.sort_by(|a, b| (a.label(), &a.name).cmp(&(b.label(), &b.name)));
    out
}

// ---------------------------------------------------------------------------
// Command lines
// ---------------------------------------------------------------------------

/// What `docker ps` is asked to print: one container a line, tab separated.
/// Labels are asked for one at a time because `{{.Labels}}` joins them all with
/// commas, and compose's own `config_files` label is a comma separated list.
const PS_FORMAT: &str = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t\
{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t\
{{.Label \"com.docker.compose.project.working_dir\"}}\t\
{{.Label \"com.docker.compose.project.config_files\"}}\t{{.RunningFor}}";

pub fn list_args() -> Vec<String> {
    vec![
        "ps".into(),
        "--all".into(),
        "--no-trunc".into(),
        "--format".into(),
        PS_FORMAT.into(),
    ]
}

/// `docker ps` output, one [`Container`] per line that has every field.
pub fn parse_ps(out: &str) -> Vec<Container> {
    out.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 11 {
                return None;
            }
            Some(Container {
                // --no-trunc is for the names; an id reads fine at the usual length.
                id: f[0].chars().take(12).collect(),
                // A container linked from another lists every alias it has.
                name: f[1].split(',').next().unwrap_or("").to_string(),
                image: f[2].into(),
                state: f[3].into(),
                status: f[4].into(),
                ports: f[5].into(),
                project: f[6].into(),
                service: f[7].into(),
                working_dir: f[8].into(),
                config_files: f[9].into(),
                created: f[10].into(),
            })
        })
        .collect()
}

/// `docker compose -p <project> <verb>`. By project name alone, with no
/// compose file: compose finds the containers by their labels, so a stack can
/// be stopped, started and taken down even when the file has moved or was a
/// temporary one an editor wrote.
pub fn compose_args(project: &str, verb: &str) -> Vec<String> {
    vec!["compose".into(), "-p".into(), project.into(), verb.into()]
}

pub fn container_args(verb: &str, name: &str) -> Vec<String> {
    vec![verb.into(), name.into()]
}

/// `docker logs`, following, with docker's own timestamps so a line is stamped
/// with when the container printed it rather than when it arrived here. A
/// follow that is picked up again starts where the last one stopped.
pub fn logs_args(name: &str, since: Option<SystemTime>) -> Vec<String> {
    let mut args = vec!["logs".into(), "--follow".into(), "--timestamps".into()];
    match since.and_then(|s| s.duration_since(UNIX_EPOCH).ok()) {
        Some(d) => {
            args.push("--since".into());
            args.push(format!("{}.{:09}", d.as_secs(), d.subsec_nanos()));
        }
        None => {
            args.push("--tail".into());
            args.push(LOG_TAIL.to_string());
        }
    }
    args.push(name.into());
    args
}

/// The argv that runs `docker <args>` on an engine — what is spawned and what
/// the log and the report show, from the one function.
///
/// A remote engine runs over ssh with everything the SSH-tab entry says about
/// reaching the host. ssh hands the remote side one string for its shell, so
/// every argument is quoted for a POSIX shell: a docker host is a Unix host.
pub fn command_line(
    engine: &Engine,
    host: Option<&SshHost>,
    helper: &PasswordHelper,
    args: &[String],
) -> Vec<String> {
    let Engine::Ssh(_) = engine else {
        let mut argv = vec!["docker".to_string()];
        argv.extend(args.iter().cloned());
        return argv;
    };
    let Some(host) = host else {
        // The caller checks the host exists before anything is run; this is
        // only reached by a report on an entry that has since been deleted.
        let mut argv = vec!["ssh".to_string(), "?".to_string(), "docker".to_string()];
        argv.extend(args.iter().cloned());
        return argv;
    };
    let mut argv: Vec<String> = Vec::new();
    if !host.password.is_empty() && *helper == PasswordHelper::Sshpass {
        argv.push("sshpass".into());
        argv.push("-e".into());
    }
    argv.push("ssh".into());
    argv.extend(ssh::connection_args(host));
    if host.password.is_empty() {
        // Nothing here can answer a prompt — the TUI has the terminal — so a
        // question becomes an error that can be shown, the same as for sftp.
        argv.push("-o".into());
        argv.push("BatchMode=yes".into());
    }
    argv.push("-o".into());
    argv.push("ConnectTimeout=10".into());
    argv.push(host.destination());
    let remote: Vec<String> = std::iter::once("docker".to_string())
        .chain(args.iter().map(|a| posix_quote(a)))
        .collect();
    argv.push(remote.join(" "));
    argv
}

fn posix_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c))
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// A `Command` for an argv from [`command_line`], with the host's password
/// where the helper looks for it and never on the line itself.
fn command(argv: &[String], host: Option<&SshHost>, helper: &PasswordHelper) -> Command {
    let mut cmd = Command::new(platform::program(&argv[0]));
    cmd.args(&argv[1..]);
    if let Some(h) = host {
        if argv[0] != "docker" {
            ssh::carry_password(&mut cmd, &h.password, helper);
        }
    }
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    platform::hidden(&mut cmd);
    cmd
}

pub fn installed() -> bool {
    platform::which_bin("docker").is_some()
}

/// What a failed docker command said, cut down to the line that says why.
fn failure(stderr: &str, code: Option<i32>) -> String {
    let said: Vec<&str> = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    match said.last() {
        // The daemon socket belongs to root and the docker group. Saying so is
        // all this can do: nothing that only looks escalates.
        Some(l) if l.contains("permission denied") && l.contains("docker") => {
            format!("{l} — is this user in the docker group?")
        }
        Some(l) => l.to_string(),
        None => format!("exited with {}", code.map_or("a signal".into(), |c| c.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Running them
// ---------------------------------------------------------------------------

pub enum DockerMsg {
    Listed {
        engine: Engine,
        result: Result<Vec<Container>, String>,
    },
    /// An action on a stack or a container has finished.
    Done {
        target: LogTarget,
        what: String,
        result: Result<(), String>,
    },
}

/// List an engine's containers on a thread.
pub fn spawn_list(
    engine: Engine,
    argv: Vec<String>,
    host: Option<SshHost>,
    helper: PasswordHelper,
    tx: Sender<DockerMsg>,
) {
    thread::spawn(move || {
        let result = match command(&argv, host.as_ref(), &helper).output() {
            Ok(out) if out.status.success() => {
                Ok(parse_ps(&String::from_utf8_lossy(&out.stdout)))
            }
            Ok(out) => Err(failure(&String::from_utf8_lossy(&out.stderr), out.status.code())),
            Err(e) => Err(format!("running {}: {e}", argv[0])),
        };
        let _ = tx.send(DockerMsg::Listed { engine, result });
    });
}

/// Run a start, stop or the like on a thread, with everything it prints in
/// `ring` — compose narrates each container as it goes, and that is the log of
/// what the action did.
pub fn spawn_action(
    target: LogTarget,
    what: String,
    argv: Vec<String>,
    host: Option<SshHost>,
    helper: PasswordHelper,
    ring: Arc<Ring>,
    tx: Sender<DockerMsg>,
) {
    thread::spawn(move || {
        let result = (|| {
            let mut child = command(&argv, host.as_ref(), &helper)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("running {}: {e}", argv[0]))?;
            let out = child.stdout.take();
            let reader = out.map(|o| {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    for line in BufReader::new(o).lines().map_while(Result::ok) {
                        ring.push(line);
                    }
                })
            });
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut stderr);
            }
            for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
                ring.push(line);
            }
            if let Some(r) = reader {
                let _ = r.join();
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err(failure(&stderr, status.code()))
            }
        })();
        let _ = tx.send(DockerMsg::Done {
            target,
            what,
            result,
        });
    });
}

// ---------------------------------------------------------------------------
// Following a container's log
// ---------------------------------------------------------------------------

/// One container's log: the lines seen so far, and the `docker logs --follow`
/// filling them while a pane is open on it.
///
/// The ring outlives the follower. Closing the pane stops the process — a
/// follow per container ever looked at would be an ssh connection each on a
/// remote engine — and opening it again picks up from the last line seen.
pub struct ContainerLog {
    pub ring: Arc<Ring>,
    /// The newest timestamp read, kept apart from the ring so that clearing
    /// the pane does not bring back everything it cleared.
    seen: Arc<Mutex<Option<SystemTime>>>,
    child: Option<Child>,
    pub started: Option<Instant>,
}

impl ContainerLog {
    pub fn new() -> Self {
        Self {
            ring: Arc::new(Ring::new("docker")),
            seen: Arc::new(Mutex::new(None)),
            child: None,
            started: None,
        }
    }

    pub fn since(&self) -> Option<SystemTime> {
        *self.seen.lock().unwrap()
    }

    pub fn following(&mut self) -> bool {
        match &mut self.child {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Start following with an argv from [`command_line`] over [`logs_args`].
    /// `docker logs` keeps stdout and stderr apart; both are the container's
    /// log and both go in the ring.
    pub fn follow(
        &mut self,
        argv: &[String],
        host: Option<&SshHost>,
        helper: &PasswordHelper,
    ) -> Result<(), String> {
        self.stop();
        self.started = Some(Instant::now());
        let mut child = command(argv, host, helper)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("running {}: {e}", argv[0]))?;
        let after = self.since();
        let streams: Vec<Box<dyn Read + Send>> = [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        .collect();
        for stream in streams {
            let ring = Arc::clone(&self.ring);
            let seen = Arc::clone(&self.seen);
            thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let line = strip_escapes(&line);
                    let (at, text) = split_stamp(&line);
                    match at {
                        // `--since` counts whole lines from that instant on, so
                        // the last one seen comes round again.
                        Some(t) if after.is_some_and(|a| t <= a) => continue,
                        Some(t) => {
                            let mut s = seen.lock().unwrap();
                            if s.is_none_or(|old| t > old) {
                                *s = Some(t);
                            }
                            drop(s);
                            ring.push_at(t, text);
                        }
                        // ssh's own complaints, and docker's: not the
                        // container's, but they explain an empty pane.
                        None => ring.push(text),
                    }
                }
            });
        }
        self.child = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Default for ContainerLog {
    fn default() -> Self {
        Self::new()
    }
}

/// A line without the terminal escapes a container wrote for its own console.
/// Colour codes are noise in a pane, and the rest — cursor movement, a title,
/// clearing the screen — would be acted on by the terminal the TUI is drawing
/// on, which is nothing a log line should be able to do.
pub fn strip_escapes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            if !c.is_control() || c == '\t' {
                out.push(c);
            }
            continue;
        }
        match chars.next() {
            // CSI: parameters and intermediates, ended by a final byte.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: ended by BEL or by ESC \.
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// `2026-11-13T09:12:01.123456789Z message` into the time and the message.
/// A line without one is returned whole.
pub fn split_stamp(line: &str) -> (Option<SystemTime>, &str) {
    match line.split_once(' ') {
        Some((stamp, rest)) => match logs::parse_rfc3339(stamp) {
            Some(t) => (Some(t), rest),
            None => (None, line),
        },
        None => match logs::parse_rfc3339(line) {
            Some(t) => (Some(t), ""),
            None => (None, line),
        },
    }
}

// ---------------------------------------------------------------------------
// The tab's state
// ---------------------------------------------------------------------------

/// One engine as the tab sees it.
pub struct EngineState {
    pub engine: Engine,
    pub containers: Vec<Container>,
    /// Whether a listing has ever come back, so an engine that has simply not
    /// answered yet is not drawn as one with nothing on it.
    pub listed: bool,
    pub error: Option<String>,
    /// What has to come up before this engine can be reached — a remote
    /// engine's VPN or tunnel, which a poll never brings up on its own.
    pub blocked: Option<String>,
    pub pending: bool,
    pub polled_at: Option<Instant>,
}

impl EngineState {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            containers: Vec::new(),
            listed: false,
            error: None,
            blocked: None,
            pending: false,
            polled_at: None,
        }
    }

    pub fn running(&self) -> usize {
        self.containers.iter().filter(|c| c.is_running()).count()
    }
}

/// A row of the left-hand list: an engine, or a stack on one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    Engine(Engine),
    Stack(Engine, String),
}

impl Row {
    pub fn engine(&self) -> &Engine {
        match self {
            Self::Engine(e) | Self::Stack(e, _) => e,
        }
    }
}

/// Which of the tab's two lists has the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerPane {
    Stacks,
    Containers,
}

/// The selection is held by name rather than by position: the lists are
/// rebuilt from every poll, and a stack coming or going above the cursor must
/// not move it onto something else.
pub struct DockerView {
    pub engines: Vec<EngineState>,
    /// The engines whose stacks are listed under them. Everything starts
    /// folded: a host with dozens of stacks would push every other engine
    /// off the screen, and the engine's own mark already says whether
    /// anything on it needs a look.
    pub expanded: std::collections::HashSet<Engine>,
    pub selected: Row,
    /// The container under the cursor, by name.
    pub container: String,
    pub focus: DockerPane,
}

impl DockerView {
    pub fn new() -> Self {
        Self {
            engines: vec![EngineState::new(Engine::Local)],
            expanded: std::collections::HashSet::new(),
            selected: Row::Engine(Engine::Local),
            container: String::new(),
            focus: DockerPane::Stacks,
        }
    }

    /// Make the engines exactly `wanted`, in that order, keeping what is known
    /// about the ones that stay.
    pub fn sync(&mut self, wanted: Vec<Engine>) {
        if self.engines.iter().map(|e| &e.engine).eq(wanted.iter()) {
            return;
        }
        let mut old = std::mem::take(&mut self.engines);
        self.engines = wanted
            .into_iter()
            .map(|e| match old.iter().position(|s| s.engine == e) {
                Some(i) => old.swap_remove(i),
                None => EngineState::new(e),
            })
            .collect();
    }

    pub fn get(&self, engine: &Engine) -> Option<&EngineState> {
        self.engines.iter().find(|e| &e.engine == engine)
    }

    pub fn get_mut(&mut self, engine: &Engine) -> Option<&mut EngineState> {
        self.engines.iter_mut().find(|e| &e.engine == engine)
    }

    pub fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        for e in &self.engines {
            rows.push(Row::Engine(e.engine.clone()));
            if !self.expanded.contains(&e.engine) {
                continue;
            }
            for s in stacks(&e.containers) {
                rows.push(Row::Stack(e.engine.clone(), s.name.to_string()));
            }
        }
        rows
    }

    /// The row under the cursor, falling back to its engine when the stack has
    /// gone — taken down, or not listed by a poll that failed.
    pub fn row_index(&self) -> usize {
        let rows = self.rows();
        rows.iter()
            .position(|r| *r == self.selected)
            .or_else(|| rows.iter().position(|r| r == &Row::Engine(self.selected.engine().clone())))
            .unwrap_or(0)
    }

    pub fn current_row(&self) -> Row {
        self.rows()
            .get(self.row_index())
            .cloned()
            .unwrap_or(Row::Engine(Engine::Local))
    }

    /// `→` on the stack list, the way the tree picker walks: open a folded
    /// engine, and step into one that is already open.
    pub fn expand(&mut self) {
        let Row::Engine(e) = self.current_row() else {
            return;
        };
        if self.expanded.insert(e) {
            return;
        }
        let at = self.row_index() + 1;
        if matches!(self.rows().get(at), Some(Row::Stack(..))) {
            self.select_row(at);
        }
    }

    /// `←` on the stack list: fold the engine under the cursor, and land on
    /// it when the cursor was on one of its stacks.
    pub fn collapse(&mut self) {
        let e = self.current_row().engine().clone();
        self.expanded.remove(&e);
        self.selected = Row::Engine(e);
    }

    pub fn select_row(&mut self, at: usize) {
        if let Some(r) = self.rows().get(at) {
            self.selected = r.clone();
        }
    }

    /// The containers the middle pane lists: those of the stack under the
    /// cursor, and none for an engine row.
    pub fn stack_containers(&self) -> Vec<&Container> {
        match self.current_row() {
            Row::Engine(_) => Vec::new(),
            Row::Stack(e, s) => self
                .get(&e)
                .map(|st| members(&st.containers, &s))
                .unwrap_or_default(),
        }
    }

    pub fn container_index(&self) -> usize {
        self.stack_containers()
            .iter()
            .position(|c| c.name == self.container)
            .unwrap_or(0)
    }

    pub fn select_container(&mut self, at: usize) {
        let name = self.stack_containers().get(at).map(|c| c.name.clone());
        if let Some(n) = name {
            self.container = n;
        }
    }

    /// The container the keys act on: the one under the cursor while the
    /// middle pane has the keyboard, and none while the stack list has it.
    pub fn selected_container(&self) -> Option<&Container> {
        if self.focus != DockerPane::Containers {
            return None;
        }
        let list = self.stack_containers();
        let at = self.container_index();
        list.into_iter().nth(at)
    }

    /// What `l` and `s` are about.
    pub fn selection_target(&self) -> LogTarget {
        let row = self.current_row();
        if let Some(c) = self.selected_container() {
            return c.target(row.engine());
        }
        match row {
            Row::Engine(e) => e.target(),
            Row::Stack(e, s) => LogTarget::docker(e.key(), &s, ""),
        }
    }
}

impl Default for DockerView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn line(name: &str, state: &str, project: &str, service: &str) -> String {
        [
            "0123456789abcdef0123",
            name,
            "redis:7",
            state,
            "Up 2 hours (healthy)",
            "6379/tcp",
            project,
            service,
            "/srv/app",
            "/srv/app/compose.yml,/srv/app/compose.override.yml",
            "3 weeks ago",
        ]
        .join("\t")
    }

    fn sample() -> Vec<Container> {
        parse_ps(
            &[
                line("web-1", "running", "web", "app"),
                line("lonely", "exited", "", ""),
                line("web-db-1", "exited", "web", "db"),
                line("api-1", "running", "api", "api"),
            ]
            .join("\n"),
        )
    }

    #[test]
    fn a_listing_is_read_field_by_field() {
        let c = &sample()[0];
        assert_eq!(c.id, "0123456789ab");
        assert_eq!(c.name, "web-1");
        assert_eq!(c.project, "web");
        assert_eq!(c.service, "app");
        assert_eq!(c.health(), Some("healthy"));
        assert!(c.is_running());
        // A line docker cut short is not half a container.
        assert!(parse_ps("abc\tonly\tthree").is_empty());
    }

    #[test]
    fn a_crash_is_told_apart_from_a_stop() {
        let c = |state: &str, status: &str| Container {
            state: state.into(),
            status: status.into(),
            ..Default::default()
        };
        assert_eq!(c("exited", "Exited (0) 2 hours ago").condition().0, Condition::Idle);
        assert_eq!(c("exited", "Exited (143) 1 minute ago").condition().0, Condition::Idle);
        assert_eq!(
            c("exited", "Exited (1) 5 seconds ago").condition(),
            (Condition::Bad, "crashed (1)".into())
        );
        assert_eq!(c("running", "Up 3 hours (unhealthy)").condition().0, Condition::Bad);
        assert_eq!(c("running", "Up 3 seconds (health: starting)").condition().0, Condition::Warn);
        assert_eq!(c("restarting", "Restarting (1) 2 seconds ago").condition().0, Condition::Bad);
        // A stack is as well as its worst member.
        let all = [c("running", "Up 1 hour"), c("exited", "Exited (2) now")];
        assert_eq!(worst(&all), Condition::Bad);
        assert_eq!(worst(&[]), Condition::Idle);
    }

    #[test]
    fn stacks_are_listed_by_name_with_the_loose_containers_last() {
        let all = sample();
        let s = stacks(&all);
        let names: Vec<&str> = s.iter().map(|s| s.label()).collect();
        assert_eq!(names, ["api", "web", STANDALONE]);
        // Within a stack, by service.
        let web: Vec<&str> = s[1].containers.iter().map(|c| c.service.as_str()).collect();
        assert_eq!(web, ["app", "db"]);
        assert_eq!(s[1].running(), 1);
        assert_eq!(
            s[1].config_files(),
            ["/srv/app/compose.yml", "/srv/app/compose.override.yml"]
        );
    }

    #[test]
    fn a_local_engine_runs_docker_itself() {
        let argv = command_line(&Engine::Local, None, &PasswordHelper::None, &list_args());
        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "ps");
        assert_eq!(argv.last().unwrap(), PS_FORMAT);
    }

    fn host(password: &str) -> SshHost {
        SshHost {
            name: "box".into(),
            group: String::new(),
            host: "10.0.0.5".into(),
            port: 2222,
            username: "ops".into(),
            key_path: String::new(),
            password: password.into(),
            skip_host_key_check: false,
            extra_args: String::new(),
            depends_on: String::new(),
            requires_vpn: String::new(),
            remote_dir: String::new(),
            docker: true,
        }
    }

    #[test]
    fn a_remote_engine_runs_docker_over_the_hosts_own_ssh_options() {
        let h = host("");
        let argv = command_line(
            &Engine::Ssh("box".into()),
            Some(&h),
            &PasswordHelper::Sshpass,
            &compose_args("my app", "stop"),
        );
        assert_eq!(argv[0], "ssh");
        assert!(argv.windows(2).any(|w| w == ["-p", "2222"]));
        // No password to answer with, so no prompt to hang on.
        assert!(argv.windows(2).any(|w| w == ["-o", "BatchMode=yes"]));
        assert_eq!(argv[argv.len() - 2], "ops@10.0.0.5");
        // One string for the remote shell, quoted where it has to be.
        assert_eq!(argv.last().unwrap(), "docker compose -p 'my app' stop");
    }

    #[test]
    fn a_stored_password_goes_through_sshpass_and_never_onto_the_line() {
        let h = host("hunter2");
        let argv = command_line(
            &Engine::Ssh("box".into()),
            Some(&h),
            &PasswordHelper::Sshpass,
            &list_args(),
        );
        assert_eq!(&argv[..3], ["sshpass", "-e", "ssh"]);
        assert!(!argv.iter().any(|a| a.contains("hunter2")));
        assert!(!argv.iter().any(|a| a == "BatchMode=yes"));
    }

    #[test]
    fn the_ps_template_survives_the_remote_shell() {
        let quoted = posix_quote(PS_FORMAT);
        assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
        assert_eq!(posix_quote("it's"), r"'it'\''s'");
        assert_eq!(posix_quote("web-1"), "web-1");
        assert_eq!(posix_quote(""), "''");
    }

    #[test]
    fn a_log_line_is_stamped_with_when_the_container_printed_it() {
        let (at, text) = split_stamp("2024-02-29T00:00:01.500000000Z GET / 200");
        assert_eq!(text, "GET / 200");
        let d = at.unwrap().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(d.as_secs(), 1_709_164_801);
        assert_eq!(d.subsec_millis(), 500);
        // Something that is not docker's, such as ssh complaining, stays whole.
        assert_eq!(split_stamp("Connection refused"), (None, "Connection refused"));
    }

    #[test]
    fn a_containers_terminal_escapes_never_reach_ours() {
        assert_eq!(
            strip_escapes("\x1b[2m2026\x1b[0m \x1b[32m INFO\x1b[0m ok"),
            "2026  INFO ok"
        );
        assert_eq!(strip_escapes("\x1b]0;title\x07after"), "after");
        assert_eq!(strip_escapes("\x1b]8;;http://x\x1b\\link"), "link");
        assert_eq!(strip_escapes("a\rb\tc"), "ab\tc");
    }

    #[test]
    fn a_follow_picks_up_where_the_last_one_stopped() {
        let first = logs_args("web-1", None);
        assert!(first.windows(2).any(|w| w == ["--tail", "1000"]));
        // Hundreds of nanoseconds: as fine as a Windows clock goes.
        let at = UNIX_EPOCH + Duration::new(1_709_164_801, 500);
        let again = logs_args("web-1", Some(at));
        assert!(again.windows(2).any(|w| w == ["--since", "1709164801.000000500"]));
        assert_eq!(again.last().unwrap(), "web-1");
    }

    #[test]
    fn the_cursor_stays_on_a_stack_by_name_and_falls_back_to_its_engine() {
        let mut v = DockerView::new();
        v.expanded.insert(Engine::Local);
        v.engines[0].containers = sample();
        v.select_row(2);
        assert_eq!(v.selected, Row::Stack(Engine::Local, "web".into()));
        // A stack appearing above it does not move the cursor off it.
        let mut more = sample();
        more.push(Container {
            name: "aaa-1".into(),
            project: "aaa".into(),
            ..Default::default()
        });
        v.engines[0].containers = more;
        assert_eq!(v.current_row(), Row::Stack(Engine::Local, "web".into()));
        // And when it goes, the cursor lands on its engine.
        v.engines[0].containers.retain(|c| c.project != "web");
        assert_eq!(v.current_row(), Row::Engine(Engine::Local));
    }

    #[test]
    fn the_keys_act_on_a_container_only_while_its_pane_has_them() {
        let mut v = DockerView::new();
        v.expanded.insert(Engine::Local);
        v.engines[0].containers = sample();
        v.selected = Row::Stack(Engine::Local, "web".into());
        v.select_container(1);
        assert!(v.selected_container().is_none());
        assert_eq!(v.selection_target(), LogTarget::docker("", "web", ""));
        v.focus = DockerPane::Containers;
        assert_eq!(v.selected_container().unwrap().name, "web-db-1");
        assert_eq!(v.selection_target(), LogTarget::docker("", "web", "web-db-1"));
    }

    #[test]
    fn an_engine_starts_folded_and_opens_and_closes_like_a_folder() {
        let mut v = DockerView::new();
        v.engines[0].containers = sample();
        assert_eq!(v.rows(), [Row::Engine(Engine::Local)]);
        v.expand();
        assert_eq!(v.rows().len(), 4);
        // Still on the engine; a second → steps onto its first stack.
        assert_eq!(v.current_row(), Row::Engine(Engine::Local));
        v.expand();
        assert_eq!(v.current_row(), Row::Stack(Engine::Local, "api".into()));
        // ← from a stack folds its engine and lands on it.
        v.collapse();
        assert_eq!(v.current_row(), Row::Engine(Engine::Local));
        assert_eq!(v.rows().len(), 1);
    }

    #[test]
    fn engines_keep_what_is_known_about_them_across_a_change_of_hosts() {
        let mut v = DockerView::new();
        v.engines[0].listed = true;
        v.sync(vec![Engine::Local, Engine::Ssh("box".into())]);
        assert!(v.engines[0].listed);
        assert_eq!(v.engines[1].engine, Engine::Ssh("box".into()));
        v.sync(vec![Engine::Local]);
        assert_eq!(v.engines.len(), 1);
    }
}
