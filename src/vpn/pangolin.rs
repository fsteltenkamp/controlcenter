//! Pangolin, driven through its own CLI and through the running client's
//! control socket.
//!
//! The shape is NetBird's: the client keeps its own profiles, controlcenter only
//! reads them and asks the CLI to switch. Pangolin calls them *accounts* — one
//! per login, each an email against a host — and `pangolin select account`
//! switches between them.
//!
//! Three things differ from NetBird, and all three are the client's, not ours:
//!
//! * There is no non-interactive way to list accounts. `pangolin select account`
//!   prints a menu and waits, so the list is read from the account store the CLI
//!   itself writes, whose directory `pangolin config path` names. Only the email,
//!   host and org are taken from it; the file also holds a session token, which
//!   is why nothing here ever echoes it back.
//! * `pangolin up` escalates itself — it re-executes under `sudo` to create the
//!   tunnel device — so it is run unprivileged and *not* through
//!   [`super::privileged`], which would leave two escalations racing for the same
//!   command. What makes that work without a dialog is the same startup sudo
//!   ticket `privileged::warm_up` takes; without one, sudo has no terminal to ask
//!   on and says so, which is what [`SUDO_HINT`] explains.
//! * Status and stopping do not go through the CLI at all; they go to
//!   [`CONTROL`], the socket the running client serves. Both of the CLI's own
//!   subcommands for them are unusable from inside a TUI:
//!
//!   - `pangolin down` opens `/dev/tty` to draw a progress view while the client
//!     shuts down. From here that is *controlcenter's* terminal, which it would
//!     draw over and read keys from; and it exits non-zero when there was
//!     nothing to stop, so a no-op reads as a failure.
//!   - `pangolin status --json` prints its JSON on the same stdout it prints an
//!     update banner and one-time notices on, so the answer to a poll is only
//!     parseable until the day the next CLI is released.
//!
//!   The socket is the same address those two subcommands dial, and olm makes it
//!   world-writable on purpose, so nothing here escalates to reach it: a status
//!   poll stays unprivileged by construction, like every other client's.

use super::{ProviderId, VpnMsg, VpnProfile, VpnStatus};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

const ME: ProviderId = ProviderId::Pangolin;

/// The sudo `pangolin up` runs for itself cannot prompt from inside the TUI.
const SUDO_HINT: &str = "pangolin escalates itself; controlcenter's sudo ticket is what lets it \
                         (set vpn.sudo = \"ask\" in config.toml, or run `sudo -v` first)";

fn run(args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(crate::platform::program("pangolin"));
    #[cfg(windows)]
    {
        crate::platform::hidden(&mut cmd);
    }
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("running pangolin: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr.trim();
        let msg = if msg.is_empty() { stdout.trim() } else { msg };
        Err(if msg.is_empty() {
            format!("pangolin {} failed ({})", args.join(" "), out.status)
        } else {
            msg.to_string()
        })
    }
}

/// Say what a failed `up` actually needs, because the CLI reports its own sudo
/// failing as "failed to start subprocess".
fn with_sudo_hint(e: String) -> String {
    let low = e.to_ascii_lowercase();
    let sudo_shaped = low.contains("sudo")
        || low.contains("terminal is required")
        || low.contains("failed to start subprocess");
    if sudo_shaped {
        format!("{e}\n{SUDO_HINT}")
    } else {
        e
    }
}

// ---------------------------------------------------------------------------
// The running client's control socket
// ---------------------------------------------------------------------------

/// Where a running client answers: a small HTTP server on a Unix socket, or on a
/// named pipe on Windows. Both addresses are the client's own defaults and the
/// ones its CLI dials, and both are created wide open — mode 0666 here, an SDDL
/// granting everyone access there — because the client runs as root and the
/// person driving it does not.
#[cfg(unix)]
const CONTROL: &str = "/var/run/olm.sock";
#[cfg(windows)]
const CONTROL: &str = r"\\.\pipe\pangolin-olm";

/// How long one control request may take. The client's own CLI gives itself five
/// seconds; a poll that hangs longer than that has answered the question. Unix
/// only, because a named pipe handle has no timeout to set — see [`dial`].
#[cfg(unix)]
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`stop`] waits for the client to finish going away, and how often it
/// looks. Shutting down means restoring DNS and tearing routes and the device
/// down, so it is not instant — and `pangolin up` refuses while any of it is
/// still true.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_POLL: Duration = Duration::from_millis(250);

#[cfg(unix)]
fn dial() -> std::io::Result<std::os::unix::net::UnixStream> {
    let sock = std::os::unix::net::UnixStream::connect(CONTROL)?;
    sock.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    sock.set_write_timeout(Some(CONTROL_TIMEOUT))?;
    Ok(sock)
}

/// A named pipe opens like a file, and olm's is a byte-mode one, so the same
/// request and the same reply framing work on it. There is no per-handle timeout
/// to set the way there is on a socket; the client answers these three requests
/// out of memory, so there is nothing for it to block on.
#[cfg(windows)]
fn dial() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(CONTROL)
}

/// One request to the running client.
///
/// `Ok(None)` means nothing was listening, which is the answer "no client is
/// running" rather than a failure. Whether the socket *file* exists is never the
/// test: the client leaves it behind when it exits, so only a connection that is
/// answered counts.
fn control(method: &str, path: &str) -> Result<Option<String>, String> {
    use std::io::ErrorKind;
    let mut sock = match dial() {
        Ok(sock) => sock,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            return Ok(None)
        }
        Err(e) => return Err(format!("pangolin control socket {CONTROL}: {e}")),
    };
    // `Connection: close` is what makes the reply end at EOF, so nothing here
    // has to understand keep-alive or chunking.
    let req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut raw = Vec::new();
    sock.write_all(req.as_bytes())
        .and_then(|()| sock.read_to_end(&mut raw).map(|_| ()))
        .map_err(|e| format!("pangolin control socket {CONTROL}: {e}"))?;
    http_body(&String::from_utf8_lossy(&raw)).map(Some)
}

/// The body of the client's reply, or what went wrong.
///
/// Its own function so that the framing is exercised by the tests below on
/// either system: [`dial`] is the only part that differs between them, and it
/// parses nothing.
fn http_body(raw: &str) -> Result<String, String> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .ok_or("pangolin client sent no reply")?;
    let status = head.lines().next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code == "200" {
        Ok(body.to_string())
    } else {
        let detail = body.trim();
        let detail = if detail.is_empty() { status.trim() } else { detail };
        Err(format!("pangolin client answered {code}: {detail}"))
    }
}

/// Whether a client is up and answering.
fn running() -> Result<bool, String> {
    Ok(control("GET", "/health")?.is_some())
}

/// Stop the running client, and do not come back until it is really gone.
///
/// The wait is the point. `/exit` answers *before* the shutdown starts, and
/// `pangolin up` refuses to start while any client is still running — so a
/// switch that did not wait would take the old account down and then fail to
/// bring the new one up, leaving the tab showing an account that is selected
/// over a tunnel that is not there.
fn stop() -> Result<(), String> {
    if control("POST", "/exit")?.is_none() {
        // Nothing was running. Being asked to stop it again is not a failure.
        return Ok(());
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        thread::sleep(STOP_POLL);
        if !running()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "pangolin client did not stop within {}s",
                STOP_TIMEOUT.as_secs()
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Accounts, which are what the tab lists as profiles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub user_id: String,
    pub email: String,
    pub host: String,
    pub org: String,
}

/// Where the CLI keeps its accounts. Asked of the CLI rather than assumed: the
/// directory is not the same on every system and `config path` is the only
/// statement of it that cannot drift.
fn store_path() -> Result<PathBuf, String> {
    let out = run(&["config", "path"])?;
    let cfg = PathBuf::from(config_path_line(&out)?);
    let dir = cfg
        .parent()
        .ok_or("pangolin config path named no directory")?;
    Ok(dir.join("accounts.json"))
}

/// The path out of what `pangolin config path` printed.
///
/// The last line rather than the whole of it: any command can be preceded on
/// stdout by a one-time notice or an "a new version is available" banner, and
/// the answer is what it prints last.
fn config_path_line(out: &str) -> Result<&str, String> {
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .next_back()
        .ok_or_else(|| "pangolin config path printed nothing".to_string())
}

/// The accounts and which one is selected. Order is the store's map order, which
/// has none of its own, so it is sorted by name to keep the list from shuffling
/// between polls.
fn parse_accounts(raw: &str) -> Result<(Vec<Account>, Option<String>), String> {
    let v: Value = serde_json::from_str(raw).map_err(|e| format!("reading accounts: {e}"))?;
    let active = v
        .get("activeuserid")
        .or_else(|| v.get("activeUserId"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut accounts: Vec<Account> = v
        .get("accounts")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(id, a)| {
                    let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                    let email = match s("email") {
                        e if e.is_empty() => s("username"),
                        e => e,
                    };
                    Account {
                        user_id: match s("userId") {
                            u if u.is_empty() => id.clone(),
                            u => u,
                        },
                        email: match email.is_empty() {
                            true => id.clone(),
                            false => email,
                        },
                        host: s("host"),
                        org: s("orgId"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    accounts.sort_by(|a, b| (&a.email, &a.host).cmp(&(&b.email, &b.host)));
    Ok((accounts, active))
}

/// The name the row carries. The CLI writes an account as `email @ host`, but
/// this name also goes into `requires_vpn`, so the short form is used wherever
/// it is unambiguous and only a repeated email pulls the host in.
fn display_name(a: &Account, all: &[Account]) -> String {
    if all.iter().filter(|o| o.email == a.email).count() > 1 {
        format!("{} @ {}", a.email, a.host)
    } else {
        a.email.clone()
    }
}

/// The host without its scheme — the whole URL is what `--host` wants, but not
/// what a narrow list wants to spend its width on.
fn summarise(a: &Account) -> String {
    let host = a
        .host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    match (host.is_empty(), a.org.is_empty()) {
        (true, true) => String::new(),
        (true, false) => a.org.clone(),
        (false, true) => host.to_string(),
        (false, false) => format!("{host} · {}", a.org),
    }
}

/// The rows the tab lists.
///
/// A row is marked active when this account is the selected one *and* a client
/// is actually up. That mark is what `Enter` reads to choose between connecting
/// and disconnecting, and what the conflict rules read as "the profile that is
/// currently up", so the account store cannot answer it alone: a selection
/// outlives every client started from it, and going by the store would leave
/// the row green over a tunnel that is not there — with `Enter` on it trying to
/// disconnect something that is already gone.
///
/// Naming the running client's account from the store is exact rather than a
/// guess: a client is started from the selected account's credentials, and
/// `pangolin select account` stops any client that is running before it changes
/// the selection, so the two cannot drift apart.
fn profiles_of(accounts: &[Account], active: Option<&str>, connected: bool) -> Vec<VpnProfile> {
    accounts
        .iter()
        .map(|a| VpnProfile {
            name: display_name(a, accounts),
            active: connected && active == Some(a.user_id.as_str()),
            detail: summarise(a),
            foreign: None,
        })
        .collect()
}

fn accounts_now() -> Result<(Vec<Account>, Option<String>), String> {
    let path = store_path()?;
    match std::fs::read_to_string(&path) {
        Ok(raw) => parse_accounts(&raw),
        // Logged out, or never logged in: an empty list, not a broken tab.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), None)),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn find_account(accounts: &[Account], name: &str) -> Option<Account> {
    accounts
        .iter()
        .find(|a| display_name(a, accounts) == name)
        // A requirement written before a second login made the email ambiguous
        // still means the account it named.
        .or_else(|| accounts.iter().find(|a| a.email == name))
        .cloned()
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str().filter(|s| !s.is_empty())
}

fn bool_at(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A Go `time.Duration` — nanoseconds — as milliseconds, which is the only scale
/// any of these are worth reading at.
fn millis(v: &Value, key: &str) -> Option<String> {
    let ns = v.get(key)?.as_f64()?;
    (ns > 0.0).then(|| format!("{:.0}ms", ns / 1_000_000.0))
}

/// Whether a site that is up is being reached the long way round. The client
/// reports the two exceptions and direct is what is left, the same way its own
/// status table reads them.
fn relayed(peer: &Value) -> bool {
    bool_at(peer, "isRelay") && !bool_at(peer, "isLocal")
}

fn parse_status(raw: &str) -> VpnStatus {
    let raw = raw.trim();
    if raw.is_empty() {
        return VpnStatus::default();
    }
    let Ok(v): Result<Value, _> = serde_json::from_str(raw) else {
        return VpnStatus::failed("could not read the pangolin client's status".into());
    };

    // Both halves have to be true: a client can hold the tunnel open while the
    // server has not registered it, and that carries no traffic.
    let registered = bool_at(&v, "registered");
    let connected = bool_at(&v, "connected") && registered;

    let mut fields = Vec::new();
    let mut push = |k: &str, val: Option<String>| {
        if let Some(val) = val {
            fields.push((k.to_string(), val));
        }
    };
    // Which program's client this is. Worth a line because it decides what can
    // be done about it: pangolin's own CLI refuses to stop a client the desktop
    // app started, and anything else reaching for this socket should say whose
    // it is before it does.
    push("Client", str_at(&v, "agent").map(str::to_string));
    push("Version", str_at(&v, "version").map(str::to_string));
    push("Organisation", str_at(&v, "orgId").map(str::to_string));

    let net = v.get("networkSettings");
    let joined = |key: &str| {
        net.and_then(|n| n.get(key))?
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|s| !s.is_empty())
    };
    // "Tunnel IP" is also what the sweep matches this client's device on, so it
    // has to keep reading as an address; see `App::claimant`. The client never
    // names the interface it made, so its address is the only thread between the
    // two halves of the sweep there is.
    push("Tunnel IP", joined("ipv4_addresses"));
    push("DNS", joined("dns_servers"));
    push(
        "MTU",
        net.and_then(|n| n.get("mtu"))
            .and_then(Value::as_i64)
            .map(|m| m.to_string()),
    );

    // The client's own link to the Pangolin server, which is what resources
    // hosted on the exit node ride.
    if let Some(exit) = v.get("exitNode") {
        let mut parts = vec![match bool_at(exit, "connected") {
            true => "connected".to_string(),
            false => "not connected".to_string(),
        }];
        parts.extend(str_at(exit, "endpoint").map(str::to_string));
        parts.extend(millis(exit, "rtt"));
        push("Server", Some(parts.join(" · ")));
    }

    // `peers` is an object keyed by site id, not a list.
    if let Some(sites) = v.get("peers").and_then(Value::as_object) {
        let up = sites.values().filter(|p| bool_at(p, "connected")).count();
        push("Sites", Some(format!("{up}/{} connected", sites.len())));
        let named = |want_connected: bool, extra: &dyn Fn(&Value) -> bool| {
            let mut names: Vec<String> = sites
                .values()
                .filter(|p| bool_at(p, "connected") == want_connected && extra(p))
                .map(|p| str_at(p, "name").unwrap_or("?").to_string())
                .collect();
            names.sort();
            names
        };
        // Only the sites that are not right get a line: one that is up and
        // direct needs no telling, and a large organisation would otherwise
        // fill the panel with sites that are fine.
        let long_way = named(true, &relayed);
        if !long_way.is_empty() {
            push("Relayed", Some(long_way.join(", ")));
        }
        for name in named(false, &|_| true) {
            fields.push((format!("site {name}"), "not connected".into()));
        }
    }

    // Only worth a line when it is the thing that is wrong: a tunnel that is up
    // and registered needs no telling.
    if bool_at(&v, "connected") && !registered {
        fields.push((
            "Registered".into(),
            "no — the server has not accepted this client yet".into(),
        ));
    }
    if bool_at(&v, "terminated") {
        fields.push(("Terminated".into(), "yes".into()));
    }

    // An error is an object carrying a code, not a string.
    let error = v.get("error").and_then(|e| {
        let msg = str_at(e, "message")?;
        Some(match str_at(e, "code") {
            Some(code) => format!("{code}: {msg}"),
            None => msg.to_string(),
        })
    });

    VpnStatus {
        connected,
        // Which account is up is the account store's to say; the client reports
        // an org and an agent, and neither of those is a profile name.
        active_profile: None,
        fields,
        error,
        ..Default::default()
    }
}

/// How a status poll is made, for a report that has to say where its answer came
/// from. Every other client's says a command line; this one's is a request.
pub fn status_probe() -> String {
    format!("GET /status → {CONTROL}")
}

/// Ask the running client how it is doing. Nothing listening is a state and not
/// a failure: it means no client is up.
fn status_now() -> VpnStatus {
    match control("GET", "/status") {
        Ok(Some(body)) => parse_status(&body),
        Ok(None) => VpnStatus::default(),
        Err(e) => VpnStatus::failed(e),
    }
}

// ---------------------------------------------------------------------------
// Driving it
// ---------------------------------------------------------------------------

/// Fetch accounts and status on a background thread.
pub fn refresh(tx: Sender<VpnMsg>) {
    thread::spawn(move || {
        let store = accounts_now();
        let mut status = status_now();
        let profiles = match &store {
            Ok((accounts, active)) => {
                Ok(profiles_of(accounts, active.as_deref(), status.connected))
            }
            Err(e) => Err(e.clone()),
        };
        // The client names an org and an agent, never an account, so the
        // selected account is the only answer to "which profile is this" — and
        // only while something is actually up, or a plan that asked for this
        // account would be told it already had it.
        if status.connected {
            if let Ok((accounts, Some(active))) = &store {
                status.active_profile = accounts
                    .iter()
                    .find(|a| &a.user_id == active)
                    .map(|a| display_name(a, accounts));
            }
        }
        let _ = tx.send(VpnMsg::Refreshed {
            provider: ME,
            profiles,
            status,
        });
    });
}

/// One thing an action takes. Not all of them are commands: making room for a
/// new client means waiting until the old one is *gone*, and only the control
/// socket can say when that is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `pangolin <args>`.
    Run(Vec<String>),
    /// Stop whatever client is running, and wait for it to finish going away.
    Stop,
}

impl Step {
    /// The step as the log records it. A command line is written the way it ran;
    /// the stop is written as the request it is, because that is what a reader
    /// would have to repeat to get the same effect.
    pub fn describe(&self) -> String {
        match self {
            Self::Run(args) => format!("pangolin {}", args.join(" ")),
            Self::Stop => format!("POST /exit → {CONTROL}"),
        }
    }

    fn perform(&self) -> Result<(), String> {
        match self {
            Self::Run(args) => {
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                run(&argv).map(|_| ())
            }
            Self::Stop => stop(),
        }
    }
}

/// Run a sequence of steps, stopping at the first failure, then refresh.
pub fn action(tx: Sender<VpnMsg>, desc: String, steps: Vec<Step>) {
    thread::spawn(move || {
        let mut error = None;
        for step in &steps {
            if let Err(e) = step.perform() {
                error = Some(with_sudo_hint(e));
                break;
            }
        }
        let _ = tx.send(VpnMsg::ActionDone {
            provider: ME,
            desc,
            error,
        });
        refresh(tx);
    });
}

/// What bringing an account up takes, given whether a client is already running.
///
/// The stop comes first and is not optional. `pangolin up` refuses outright
/// while a client is running, and `pangolin select account` shuts one down
/// itself the moment the selection changes — without waiting for it to be gone.
/// Left to those two, switching accounts reliably ends with the old account
/// down, the `up` refused, and nothing connected at all. Doing the stop here is
/// also what puts it in the log beside the rest of the switch.
///
/// `--silent` on the `up` is not optional either: without it a detached `up`
/// draws a progress view of its own into the terminal controlcenter is holding.
pub fn connect_plan(account: Option<&Account>, client_running: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    if client_running {
        steps.push(Step::Stop);
    }
    if let Some(a) = account {
        let mut select = vec![
            "select".to_string(),
            "account".to_string(),
            "-a".to_string(),
            a.email.clone(),
        ];
        // Two logins can share an email on different hosts; the host is what
        // makes the selection exact.
        if !a.host.is_empty() {
            select.push("--host".into());
            select.push(a.host.clone());
        }
        steps.push(Step::Run(select));
    }
    steps.push(Step::Run(vec!["up".into(), "--silent".into()]));
    steps
}

/// Bring an account up. Returns what it launched, for the log.
pub fn connect(tx: Sender<VpnMsg>, profile: Option<&str>) -> Result<Vec<String>, String> {
    let account = match profile {
        Some(name) => {
            let (accounts, _) = accounts_now()?;
            Some(find_account(&accounts, name).ok_or_else(|| {
                format!("pangolin account '{name}' is not logged in — run `pangolin login`")
            })?)
        }
        None => None,
    };
    let desc = match &account {
        Some(a) => format!("switching to account '{}'", a.email),
        None => "connecting".to_string(),
    };
    // A socket that cannot be reached at all is no reason to refuse to try: the
    // worst it costs is the `up` below saying a client is already running.
    let steps = connect_plan(account.as_ref(), running().unwrap_or(false));
    let ran = steps.iter().map(Step::describe).collect();
    action(tx, desc, steps);
    Ok(ran)
}

pub fn disconnect(tx: Sender<VpnMsg>) -> Vec<String> {
    let steps = vec![Step::Stop];
    let ran = steps.iter().map(Step::describe).collect();
    action(tx, "disconnecting".into(), steps);
    ran
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &str = r#"{
      "accounts": {
        "9v4awzt468de0fn": {
          "userId": "9v4awzt468de0fn",
          "host": "https://pangolin.example.de",
          "email": "someone@example.net",
          "username": "someone@example.net",
          "sessionToken": "s3cr3t",
          "orgId": "acme"
        },
        "aaaa1111": {
          "userId": "aaaa1111",
          "host": "https://other.example.com",
          "email": "zed@example.net",
          "orgId": "other"
        }
      },
      "activeuserid": "9v4awzt468de0fn"
    }"#;

    /// What a connected client answers on `/status`, shaped the way the client
    /// writes it: a map of sites rather than a list, the addressing under
    /// `networkSettings`, and no `tunnelIP` anywhere.
    const CONNECTED: &str = r#"{
      "connected": true, "registered": true, "terminated": false,
      "version": "0.17.0", "agent": "Pangolin CLI", "orgId": "acme",
      "peers": {
        "1": {"siteId":1,"name":"Homelab","connected":true,"rtt":49237387,
              "endpoint":"pangolin.example.de","isRelay":true,"isLocal":false},
        "2": {"siteId":2,"name":"Branch","connected":true,"rtt":33202273,
              "endpoint":"198.51.100.7:52398","isRelay":false,"isLocal":false},
        "3": {"siteId":3,"name":"Attic","connected":false,"rtt":0,
              "isRelay":false,"isLocal":false}
      },
      "networkSettings": {
        "dns_servers": ["100.96.128.1"],
        "ipv4_addresses": ["100.90.128.7"],
        "ipv4_subnet_masks": ["255.255.240.0"],
        "mtu": 1280
      },
      "exitNode": {"connected": true, "rtt": 21000000, "endpoint": "198.51.100.1:51820"}
    }"#;

    #[test]
    fn reads_the_account_store() {
        let (accounts, active) = parse_accounts(STORE).unwrap();
        assert_eq!(accounts.len(), 2);
        // Sorted by email, so the store's map order cannot shuffle the list.
        assert_eq!(accounts[0].email, "someone@example.net");
        assert_eq!(accounts[0].org, "acme");
        assert_eq!(active.as_deref(), Some("9v4awzt468de0fn"));
    }

    #[test]
    fn lists_accounts_as_profiles_with_the_running_one_active() {
        let (accounts, active) = parse_accounts(STORE).unwrap();
        let profiles = profiles_of(&accounts, active.as_deref(), true);
        assert_eq!(profiles[0].name, "someone@example.net");
        assert!(profiles[0].active);
        assert_eq!(profiles[0].detail, "pangolin.example.de · acme");
        assert!(!profiles[1].active);
    }

    #[test]
    fn a_selected_account_with_no_client_up_is_not_active() {
        // The selection outlives the client, so the store alone would leave this
        // row green over a tunnel that is not there — and Enter on it would try
        // to disconnect rather than connect.
        let (accounts, active) = parse_accounts(STORE).unwrap();
        let profiles = profiles_of(&accounts, active.as_deref(), false);
        assert!(profiles.iter().all(|p| !p.active));
    }

    #[test]
    fn a_repeated_email_is_named_with_its_host() {
        let raw = STORE.replace("zed@example.net", "someone@example.net");
        let (accounts, _) = parse_accounts(&raw).unwrap();
        let names: Vec<String> = accounts.iter().map(|a| display_name(a, &accounts)).collect();
        assert_eq!(
            names,
            [
                "someone@example.net @ https://other.example.com",
                "someone@example.net @ https://pangolin.example.de",
            ]
        );
        // And the long name is what selects it again.
        let a = find_account(&accounts, &names[1]).unwrap();
        assert_eq!(a.host, "https://pangolin.example.de");
    }

    #[test]
    fn an_empty_store_is_no_accounts_rather_than_an_error() {
        let (accounts, active) = parse_accounts("{}").unwrap();
        assert!(accounts.is_empty());
        assert!(active.is_none());
    }

    #[test]
    fn nothing_running_is_a_state_not_an_error() {
        let st = parse_status("");
        assert!(!st.connected);
        assert!(st.error.is_none());
        assert!(st.fields.is_empty());
    }

    #[test]
    fn parses_a_connected_client() {
        let st = parse_status(CONNECTED);
        assert!(st.connected);
        assert_eq!(st.field("Client"), Some("Pangolin CLI"));
        assert_eq!(st.field("Version"), Some("0.17.0"));
        assert_eq!(st.field("Organisation"), Some("acme"));
        // The address the sweep matches the device on.
        assert_eq!(st.field("Tunnel IP"), Some("100.90.128.7"));
        assert_eq!(st.field("DNS"), Some("100.96.128.1"));
        assert_eq!(st.field("MTU"), Some("1280"));
        assert_eq!(
            st.field("Server"),
            Some("connected · 198.51.100.1:51820 · 21ms")
        );
        // Nothing to explain while it is registered.
        assert_eq!(st.field("Registered"), None);
    }

    #[test]
    fn counts_the_sites_and_names_only_the_ones_that_are_wrong() {
        let st = parse_status(CONNECTED);
        assert_eq!(st.field("Sites"), Some("2/3 connected"));
        // The one that is down is named; the two that are up are not.
        assert_eq!(st.field("site Attic"), Some("not connected"));
        assert_eq!(st.field("site Homelab"), None);
        assert_eq!(st.field("site Branch"), None);
        // Going the long way round is worth saying; going direct is not.
        assert_eq!(st.field("Relayed"), Some("Homelab"));
    }

    #[test]
    fn a_tunnel_the_server_has_not_accepted_is_not_connected() {
        let raw = r#"{"connected": true, "registered": false}"#;
        let st = parse_status(raw);
        assert!(!st.connected);
        assert!(st.field("Registered").is_some());
    }

    #[test]
    fn reads_the_error_object_the_client_reports() {
        let raw = r#"{"connected": false, "registered": false,
                      "error": {"code": "UNAUTHORIZED", "message": "olm not found"}}"#;
        let st = parse_status(raw);
        assert_eq!(st.error.as_deref(), Some("UNAUTHORIZED: olm not found"));
    }

    #[test]
    fn connecting_with_nothing_running_stops_nothing() {
        assert_eq!(
            connect_plan(None, false),
            vec![Step::Run(vec!["up".into(), "--silent".into()])]
        );
    }

    #[test]
    fn switching_stops_the_running_client_before_it_selects() {
        let (accounts, _) = parse_accounts(STORE).unwrap();
        let steps = connect_plan(Some(&accounts[0]), true);
        // The stop has to come first: `up` refuses while a client is running,
        // and `select account` would take it down without waiting.
        assert_eq!(steps[0], Step::Stop);
        assert_eq!(
            steps[1],
            Step::Run(vec![
                "select".into(),
                "account".into(),
                "-a".into(),
                "someone@example.net".into(),
                "--host".into(),
                "https://pangolin.example.de".into(),
            ])
        );
        assert_eq!(steps[2], Step::Run(vec!["up".into(), "--silent".into()]));
    }

    #[test]
    fn every_step_says_what_it_did_for_the_log() {
        let (accounts, _) = parse_accounts(STORE).unwrap();
        let lines: Vec<String> = connect_plan(Some(&accounts[1]), true)
            .iter()
            .map(Step::describe)
            .collect();
        assert!(lines[0].contains("/exit"), "{}", lines[0]);
        assert_eq!(
            lines[1],
            "pangolin select account -a zed@example.net --host https://other.example.com"
        );
        assert_eq!(lines[2], "pangolin up --silent");
    }

    #[test]
    fn a_failed_up_says_what_sudo_needed() {
        let e = with_sudo_hint("Error: failed to start subprocess: exit status 1".into());
        assert!(e.contains(SUDO_HINT));
        assert!(!with_sudo_hint("no such host".into()).contains(SUDO_HINT));
    }

    #[test]
    fn reads_the_body_out_of_the_clients_reply() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"connected\":true}";
        assert_eq!(http_body(raw).unwrap(), "{\"connected\":true}");
    }

    #[test]
    fn a_reply_that_is_not_ok_is_an_error_carrying_what_it_said() {
        let raw = "HTTP/1.1 405 Method Not Allowed\r\n\r\nMethod not allowed\n";
        let e = http_body(raw).unwrap_err();
        assert!(e.contains("405"), "{e}");
        assert!(e.contains("Method not allowed"), "{e}");
        assert!(http_body("garbage").is_err());
    }

    #[test]
    fn a_banner_before_the_answer_does_not_hide_the_config_path() {
        // Any command can be preceded on stdout by an update banner.
        let out = "A new version is available: 0.18.0 (current: 0.17.0)\n\
                   Run 'pangolin update' to update to the latest version\n\n\
                   /home/u/.config/pangolin/config.json\n";
        assert_eq!(
            config_path_line(out).unwrap(),
            "/home/u/.config/pangolin/config.json"
        );
        assert!(config_path_line("  \n ").is_err());
    }
}
