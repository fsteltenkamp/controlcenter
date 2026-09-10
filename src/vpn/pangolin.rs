//! Pangolin, driven through its own CLI.
//!
//! The shape is NetBird's: the client keeps its own profiles, controlcenter only
//! reads them and asks the CLI to switch. Pangolin calls them *accounts* — one
//! per login, each an email against a host — and `pangolin select account`
//! switches between them.
//!
//! Two things differ from NetBird and both are the client's, not ours:
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
//!   on and says so, which is what [`SUDO_HINT`] explains. Status is never
//!   escalated: the running client's socket answers the plain user.

use super::{ProviderId, VpnMsg, VpnProfile, VpnStatus};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;

const ME: ProviderId = ProviderId::Pangolin;

/// What `pangolin status` says when nothing is up. It is prose rather than JSON
/// even under `--json`, and it exits 0: not an error, just the answer.
const NOT_RUNNING: &str = "no client is currently running";

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
    let cfg = PathBuf::from(out.trim());
    let dir = cfg
        .parent()
        .ok_or("pangolin config path named no directory")?;
    Ok(dir.join("accounts.json"))
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

fn profiles_of(accounts: &[Account], active: Option<&str>) -> Vec<VpnProfile> {
    accounts
        .iter()
        .map(|a| VpnProfile {
            name: display_name(a, accounts),
            active: active == Some(a.user_id.as_str()),
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

/// The sites the client is meshed with, whichever of the shapes the CLI has
/// used to report them.
fn peers(v: &Value) -> Option<&Vec<Value>> {
    ["sites", "peers", "peerStatuses"]
        .into_iter()
        .find_map(|k| v.get(k).and_then(Value::as_array))
}

fn parse_status(raw: &str) -> VpnStatus {
    let raw = raw.trim();
    if raw.is_empty() || raw.to_ascii_lowercase().starts_with(NOT_RUNNING) {
        return VpnStatus::default();
    }
    let Ok(v): Result<Value, _> = serde_json::from_str(raw) else {
        return VpnStatus::failed("could not parse `pangolin status --json`".into());
    };

    // Both halves have to be true: a client can hold the tunnel open while the
    // server has not registered it, and that carries no traffic.
    let registered = bool_at(&v, "registered");
    let connected = bool_at(&v, "connected") && registered;

    let mut fields = Vec::new();
    let mut push = |k: &str, val: Option<&str>| {
        if let Some(val) = val {
            fields.push((k.to_string(), val.to_string()));
        }
    };
    push("Client", str_at(&v, "olmId"));
    push("Version", str_at(&v, "version"));
    push("Organisation", str_at(&v, "orgId"));
    // "Tunnel IP" is also what the sweep matches this client's device on, so it
    // has to keep reading as an address; see `App::claimant`.
    push("Tunnel IP", str_at(&v, "tunnelIP"));
    push("Server IP", str_at(&v, "serverIP"));
    let exit = v
        .get("exitNode")
        .and_then(|e| str_at(e, "exitNodeName").or_else(|| str_at(e, "name")))
        .or_else(|| str_at(&v, "exitNodeName"));
    push("Exit node", exit);
    if let Some(list) = peers(&v) {
        let up = list.iter().filter(|p| bool_at(p, "connected")).count();
        fields.push(("Sites".into(), format!("{up}/{} connected", list.len())));
    }
    // Only worth a line when it is the thing that is wrong: a tunnel that is up
    // and registered needs no telling.
    if bool_at(&v, "connected") && !registered {
        fields.push(("Registered".into(), "no — the server has not accepted this client yet".into()));
    }
    if bool_at(&v, "terminated") {
        fields.push(("Terminated".into(), "yes".into()));
    }

    VpnStatus {
        connected,
        // Which account is up is the account store's to say; the client reports
        // an org and an id, neither of which is a profile name.
        active_profile: None,
        fields,
        error: str_at(&v, "error").map(str::to_string),
    }
}

// ---------------------------------------------------------------------------
// Driving it
// ---------------------------------------------------------------------------

/// Fetch accounts and status on a background thread.
pub fn refresh(tx: Sender<VpnMsg>) {
    thread::spawn(move || {
        let store = accounts_now();
        let mut status = match run(&["status", "--json"]) {
            Ok(out) => parse_status(&out),
            Err(e) => VpnStatus::failed(e),
        };
        let profiles = match &store {
            Ok((accounts, active)) => Ok(profiles_of(accounts, active.as_deref())),
            Err(e) => Err(e.clone()),
        };
        // The client names an org, never an account, so the selected account is
        // the only answer to "which profile is this".
        if let Ok((accounts, Some(active))) = &store {
            status.active_profile = accounts
                .iter()
                .find(|a| &a.user_id == active)
                .map(|a| display_name(a, accounts));
        }
        let _ = tx.send(VpnMsg::Refreshed {
            provider: ME,
            profiles,
            status,
        });
    });
}

/// Run a sequence of pangolin commands (stopping at the first failure), then
/// refresh.
pub fn action(tx: Sender<VpnMsg>, desc: String, cmds: Vec<Vec<String>>) {
    thread::spawn(move || {
        let mut error = None;
        for cmd in &cmds {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            if let Err(e) = run(&args) {
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

/// The argv for bringing an account up, or just connecting when `account` is
/// None. `--silent` is not optional: without it a detached `up` draws a TUI of
/// its own into the terminal controlcenter is holding.
pub fn connect_cmds(account: Option<&Account>) -> Vec<Vec<String>> {
    let up = vec!["up".to_string(), "--silent".to_string()];
    match account {
        Some(a) => {
            let mut select = vec![
                "select".into(),
                "account".into(),
                "-a".into(),
                a.email.clone(),
            ];
            // Two logins can share an email on different hosts; the host is what
            // makes the selection exact.
            if !a.host.is_empty() {
                select.push("--host".into());
                select.push(a.host.clone());
            }
            vec![select, up]
        }
        None => vec![up],
    }
}

/// Bring an account up. Returns the command lines it launched, for the log.
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
    let cmds = connect_cmds(account.as_ref());
    let ran = cmds
        .iter()
        .map(|c| format!("pangolin {}", c.join(" ")))
        .collect();
    action(tx, desc, cmds);
    Ok(ran)
}

pub fn disconnect(tx: Sender<VpnMsg>) -> Vec<String> {
    action(tx, "disconnecting".into(), vec![vec!["down".into()]]);
    vec!["pangolin down".to_string()]
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
    fn lists_accounts_as_profiles_with_the_selected_one_active() {
        let (accounts, active) = parse_accounts(STORE).unwrap();
        let profiles = profiles_of(&accounts, active.as_deref());
        assert_eq!(profiles[0].name, "someone@example.net");
        assert!(profiles[0].active);
        assert_eq!(profiles[0].detail, "pangolin.example.de · acme");
        assert!(!profiles[1].active);
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
        let st = parse_status("No client is currently running");
        assert!(!st.connected);
        assert!(st.error.is_none());
        assert!(st.fields.is_empty());
    }

    #[test]
    fn parses_a_connected_client() {
        let raw = r#"{
          "connected": true, "registered": true, "terminated": false,
          "olmId": "olm-123", "version": "0.16.0", "orgId": "acme",
          "tunnelIP": "100.90.128.4", "serverIP": "10.0.0.1",
          "exitNode": {"exitNodeName": "fra-1"},
          "sites": [{"siteId": 1, "connected": true}, {"siteId": 2, "connected": false}]
        }"#;
        let st = parse_status(raw);
        assert!(st.connected);
        assert_eq!(st.field("Tunnel IP"), Some("100.90.128.4"));
        assert_eq!(st.field("Exit node"), Some("fra-1"));
        assert_eq!(st.field("Sites"), Some("1/2 connected"));
        assert_eq!(st.field("Organisation"), Some("acme"));
        // Nothing to explain while it is registered.
        assert_eq!(st.field("Registered"), None);
    }

    #[test]
    fn a_tunnel_the_server_has_not_accepted_is_not_connected() {
        let raw = r#"{"connected": true, "registered": false}"#;
        let st = parse_status(raw);
        assert!(!st.connected);
        assert!(st.field("Registered").is_some());
    }

    #[test]
    fn connecting_without_an_account_does_not_switch() {
        assert_eq!(
            connect_cmds(None),
            vec![vec!["up".to_string(), "--silent".to_string()]]
        );
    }

    #[test]
    fn switching_pins_the_account_to_its_host() {
        let (accounts, _) = parse_accounts(STORE).unwrap();
        let cmds = connect_cmds(Some(&accounts[0]));
        assert_eq!(
            cmds[0],
            [
                "select",
                "account",
                "-a",
                "someone@example.net",
                "--host",
                "https://pangolin.example.de"
            ]
        );
        assert_eq!(cmds[1], ["up", "--silent"]);
    }

    #[test]
    fn a_failed_up_says_what_sudo_needed() {
        let e = with_sudo_hint("Error: failed to start subprocess: exit status 1".into());
        assert!(e.contains(SUDO_HINT));
        assert!(!with_sudo_hint("no such host".into()).contains(SUDO_HINT));
    }
}
