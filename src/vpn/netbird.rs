//! NetBird, driven through its own CLI. `netbird` talks to its daemon over a
//! socket it owns, so nothing here needs to escalate.
//!
//! Two kinds of peer reach the same network and only one of them comes up
//! without a person. A peer registered with a setup key holds credentials of its
//! own and `netbird up` is the whole story. A **user device** is bound to an
//! account instead: it has to be logged in through a browser, and because that
//! SSO session expires, the login comes round again — every day, on the default
//! cloud setting.
//!
//! `netbird up` does that login itself, but it does it by printing a URL and a
//! code and then waiting, which is why `up` is the one command here that is not
//! run with `output()`: both its pipes are tailed as they fill, so the URL
//! reaches the person while it is still worth something ([`VpnMsg::LoginNeeded`])
//! and the whole exchange lands in the client's log ring rather than being
//! swallowed. When it ends without a session, that is reported as the login
//! problem it is rather than as a command that failed — `up` says the same
//! `daemon up failed` whatever the reason, so what it asked for on the way and
//! what the daemon says afterwards are what settle it.

use super::{ProviderId, Verification, VpnMsg, VpnProfile, VpnStatus};
use crate::logs::Ring;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

const ME: ProviderId = ProviderId::Netbird;

/// What the status pane says while the daemon has no session. Short on purpose:
/// the popup [`VpnMsg::LoginNeeded`] raises is where the URL and the way out go.
const LOGIN_HINT: &str =
    "no SSO session — this profile is a user device rather than a setup key.\n\
     Enter logs in: netbird opens a browser and controlcenter shows the code.";

fn run(args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(crate::platform::program("netbird"));
    #[cfg(windows)]
    {
        crate::platform::hidden(&mut cmd);
    }
    let out = cmd
        .args(args)
        .output()
        .map_err(|e| format!("running netbird: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr.trim();
        let msg = if msg.is_empty() { stdout.trim() } else { msg };
        Err(if msg.is_empty() {
            format!("netbird {} failed ({})", args.join(" "), out.status)
        } else {
            msg.to_string()
        })
    }
}

fn parse_profiles(raw: &str) -> Vec<VpnProfile> {
    raw.lines()
        .skip(1) // "NAME  ACTIVE" header
        .filter_map(|line| {
            let name = line.split_whitespace().next()?.to_string();
            let rest = &line[line.find(&name).unwrap_or(0) + name.len()..];
            Some(VpnProfile {
                active: !rest.trim().is_empty(),
                name,
                detail: String::new(),
                foreign: None,
            })
        })
        .collect()
}

/// Whether the daemon is saying the peer has no session — a user device that has
/// never been logged in, or one whose SSO session has run out.
///
/// NetBird reports this as a state of its own rather than as an error, and has
/// spelled it `NeedsLogin`, `LoginRequired` and `SessionExpired` across
/// releases, so the value is compared with the case and punctuation taken out of
/// it. The prose the same command prints underneath is checked too: it is the
/// only statement of the state on a daemon that carries no field for it.
fn daemon_needs_login(fields: &[(String, String)], raw: &str) -> bool {
    fn squashed(s: &str) -> String {
        s.chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase()
    }
    let in_field = fields.iter().any(|(k, v)| {
        (k.eq_ignore_ascii_case("Daemon status") || k.eq_ignore_ascii_case("Status"))
            && matches!(
                squashed(v).as_str(),
                "needslogin" | "loginrequired" | "loginfailed" | "sessionexpired"
            )
    });
    let low = raw.to_ascii_lowercase();
    in_field || low.contains("run up command to log in with sso")
}

fn parse_status(raw: &str) -> VpnStatus {
    let mut fields = Vec::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() {
                fields.push((k.to_string(), v.to_string()));
            }
        }
    }
    let connected = fields
        .iter()
        .any(|(k, v)| k == "Management" && v.starts_with("Connected"));
    let active_profile = fields
        .iter()
        .find(|(k, _)| k == "Profile")
        .map(|(_, v)| v.clone());
    // A peer that needs a login is not a broken client, the same way a tailscale
    // node that needs one is not: it is a state with something to do about it,
    // so it is reported as one and the pane says what that is.
    let needs_login = daemon_needs_login(&fields, raw);
    VpnStatus {
        connected,
        active_profile,
        fields,
        error: needs_login.then(|| LOGIN_HINT.to_string()),
        needs_login,
    }
}

/// Whether the daemon says a login is what it is missing, asked straight after
/// something failed. A `status` that cannot be run at all answers nothing, so
/// its own complaint is read as the status text: it holds no login state either
/// way, and a second error message about the same binary is no use to anyone.
fn login_required_now() -> bool {
    let raw = match run(&["status"]) {
        Ok(out) => out,
        Err(e) => e,
    };
    parse_status(&raw).needs_login
}

// ---------------------------------------------------------------------------
// The browser login
// ---------------------------------------------------------------------------

/// Picks the browser-login prompt out of a stream of netbird's output.
///
/// The URL and the code are taken from wherever they land rather than matched
/// against netbird's exact wording, which has changed between releases — but
/// only after a line has said a browser is being sent somewhere, so that a
/// management or admin URL printed for any other reason, in an error that
/// happens to mention a login, cannot be mistaken for one.
#[derive(Default)]
struct SsoWatch {
    armed: bool,
    /// Whether the prompt has been seen at all. Read back after the command has
    /// finished: a failure that came after netbird asked for a login is a login
    /// that did not finish, whatever the daemon says about itself afterwards.
    sent: bool,
}

impl SsoWatch {
    /// The verification to show, if this line is the one that carries it. Only
    /// the first is ever returned: one `up` asks for one login. `pid` is the
    /// process that is waiting, which is the caller's to name.
    fn line(&mut self, line: &str, pid: Option<u32>) -> Option<Verification> {
        if self.sent {
            return None;
        }
        let low = line.to_ascii_lowercase();
        self.armed |= low.contains("sso login")
            || low.contains("browser")
            || low.contains("verification")
            || low.contains("url to log in");
        if !self.armed {
            return None;
        }
        let url = line
            .split_whitespace()
            .find(|w| w.starts_with("https://") || w.starts_with("http://"))?
            .trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ')' | '"' | '\'' | '>'));
        // The code is only worth showing when the URL does not already carry it:
        // netbird hands the browser the complete URL wherever the provider
        // accepts one, and then there is nothing for anyone to type.
        let code = code_in_line(line).filter(|c| !url.contains(c.as_str()));
        self.sent = true;
        Some(Verification {
            url: url.to_string(),
            code,
            pid,
        })
    }
}

/// `… and enter the code ABCD-EFGH to log in.` — the word after "code".
fn code_in_line(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words
        .iter()
        .position(|w| w.trim_end_matches(':').eq_ignore_ascii_case("code"))?;
    let code = words.get(at + 1)?.trim_matches(|c: char| {
        !c.is_ascii_alphanumeric() && c != '-' && c != '_'
    });
    (!code.is_empty()).then(|| code.to_string())
}

/// Tail one of the child's pipes into the log, watching for the login prompt.
fn tail<R: Read + Send + 'static>(
    reader: R,
    log: Arc<Ring>,
    said: Arc<Mutex<Vec<String>>>,
    watch: Arc<Mutex<SsoWatch>>,
    tx: Sender<VpnMsg>,
    profile: String,
    pid: Option<u32>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            log.push(line);
            said.lock().unwrap().push(line.to_string());
            if let Some(waiting) = watch.lock().unwrap().line(line, pid) {
                let _ = tx.send(VpnMsg::LoginNeeded {
                    provider: ME,
                    profile: profile.clone(),
                    waiting: Some(waiting),
                    error: None,
                });
            }
        }
    })
}

/// What a failed streamed command is reported as. netbird prints the reason as
/// its last words — `Error: …` — and everything before it is in the log pane
/// already, so that one line is what goes in front of the user.
fn failure_message(said: &[String], args: &[String], status: ExitStatus) -> String {
    if let Some(err) = said
        .iter()
        .rev()
        .find(|l| l.to_ascii_lowercase().starts_with("error"))
    {
        return err.trim().to_string();
    }
    // Stopped rather than finished — a signal, which from here means the login it
    // was waiting on was called off. The last thing it printed was the invitation
    // to that login, which explains nothing about why it ended.
    if status.code().is_none() {
        return format!("netbird {} was stopped", args.join(" "));
    }
    said.iter()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| format!("netbird {} failed ({status})", args.join(" ")))
}

/// Run one netbird command with its output streamed rather than collected.
///
/// `up` can sit for minutes while a person works through a browser, and the URL
/// it prints on the way is worth nothing once the command has finished — so the
/// pipes are read as they fill and the prompt is sent on the moment it appears.
fn run_streamed(
    args: &[String],
    profile: &str,
    log: &Arc<Ring>,
    tx: &Sender<VpnMsg>,
    watch: &Arc<Mutex<SsoWatch>>,
) -> Result<(), String> {
    let mut cmd = Command::new(crate::platform::program("netbird"));
    #[cfg(windows)]
    {
        crate::platform::hidden(&mut cmd);
    }
    let mut child = cmd
        .args(args)
        // There is no terminal here for netbird to ask anything on, and a pipe
        // nothing will ever write to would only let it wait on one: the login
        // happens in the browser or not at all.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running netbird: {e}"))?;

    let said = Arc::new(Mutex::new(Vec::new()));
    // Named so the login can be called off: this is the process that would bring
    // the tunnel up once the browser is done with it.
    let pid = Some(child.id());
    // Both pipes: netbird prints the login prompt on stdout and the reason it
    // gave up on stderr, and either can be the line that explains the outcome.
    let tails: Vec<_> = [
        child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
        child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|pipe| {
        tail(
            pipe,
            Arc::clone(log),
            Arc::clone(&said),
            Arc::clone(watch),
            tx.clone(),
            profile.to_string(),
            pid,
        )
    })
    .collect();

    let status = child
        .wait()
        .map_err(|e| format!("waiting for netbird: {e}"))?;
    // Joined before the outcome is judged, so the last line is in hand and
    // nothing is still being pushed into the log after the action reports.
    for t in tails {
        let _ = t.join();
    }
    if status.success() {
        Ok(())
    } else {
        Err(failure_message(&said.lock().unwrap(), args, status))
    }
}

// ---------------------------------------------------------------------------
// Driving it
// ---------------------------------------------------------------------------

/// Fetch profiles and status on a background thread.
pub fn refresh(tx: Sender<VpnMsg>) {
    thread::spawn(move || {
        let profiles = run(&["profile", "list"]).map(|out| parse_profiles(&out));
        let mut status = match run(&["status"]) {
            Ok(out) => parse_status(&out),
            Err(e) => VpnStatus::failed(e),
        };
        // `netbird status` omits the profile when it is not connected; fall back
        // to whichever one the profile list flags as active.
        if status.active_profile.is_none() {
            if let Ok(list) = &profiles {
                status.active_profile = list.iter().find(|p| p.active).map(|p| p.name.clone());
            }
        }
        let _ = tx.send(VpnMsg::Refreshed {
            provider: ME,
            profiles,
            status,
        });
    });
}

/// Run a sequence of netbird commands (stopping at the first failure), then
/// refresh. `up` is streamed rather than collected — see [`run_streamed`] — and
/// may sit through a browser login before it answers.
pub fn action(
    tx: Sender<VpnMsg>,
    desc: String,
    cmds: Vec<Vec<String>>,
    profile: String,
    log: Arc<Ring>,
) {
    thread::spawn(move || {
        let watch = Arc::new(Mutex::new(SsoWatch::default()));
        let mut error = None;
        for cmd in &cmds {
            let result = if cmd.first().is_some_and(|a| a == "up") {
                run_streamed(cmd, &profile, &log, &tx, &watch)
            } else {
                let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
                run(&args).map(|_| ())
            };
            if let Err(e) = result {
                error = Some(e);
                break;
            }
        }
        let _ = tx.send(VpnMsg::ActionDone {
            provider: ME,
            desc,
            error: error.clone(),
        });
        // A profile that would not come up because it was never logged in is the
        // one failure with something a person can do about it, so it is reported
        // as itself. Two things say that is what happened, and either is enough:
        // netbird having asked for a login that then did not finish, and the
        // daemon still saying it has no session. Asking the daemon alone is not
        // enough — `up` says "daemon up failed" whatever the reason, and by the
        // time it is asked the daemon can have moved on to another state.
        let asked_for_a_login = watch.lock().unwrap().sent;
        if let Some(e) = error.filter(|_| asked_for_a_login || login_required_now()) {
            let _ = tx.send(VpnMsg::LoginNeeded {
                provider: ME,
                profile,
                waiting: None,
                error: Some(e),
            });
        }
        refresh(tx);
    });
}

/// The argv for bringing a profile up, or just connecting when `profile` is None.
pub fn connect_cmds(profile: Option<&str>) -> Vec<Vec<String>> {
    match profile {
        Some(p) => vec![
            vec!["profile".into(), "select".into(), p.to_string()],
            vec!["up".into()],
        ],
        None => vec![vec!["up".into()]],
    }
}

/// Bring a profile up. Returns the command lines it launched, for the log.
pub fn connect(tx: Sender<VpnMsg>, profile: Option<&str>, log: Arc<Ring>) -> Vec<String> {
    let desc = match profile {
        Some(p) => format!("switching to profile '{p}'"),
        None => "connecting".to_string(),
    };
    let cmds = connect_cmds(profile);
    let ran = cmds.iter().map(|c| format!("netbird {}", c.join(" "))).collect();
    action(
        tx,
        desc,
        cmds,
        profile.unwrap_or_default().to_string(),
        log,
    );
    ran
}

pub fn disconnect(tx: Sender<VpnMsg>, log: Arc<Ring>) -> Vec<String> {
    action(
        tx,
        "disconnecting".into(),
        vec![vec!["down".into()]],
        String::new(),
        log,
    );
    vec!["netbird down".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_list() {
        let raw = "NAME     ACTIVE\ndefault  \nmup      \ntn       ✓\n";
        let profiles = parse_profiles(raw);
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].name, "default");
        assert!(!profiles[0].active);
        assert_eq!(profiles[2].name, "tn");
        assert!(profiles[2].active);
    }

    #[test]
    fn parses_status_connected() {
        let raw = "OS: linux/amd64\nDaemon version: 0.75.0\nProfile: tn\nManagement: Connected\nSignal: Connected\nNetBird IP: 100.120.192.110/16\nPeers count: 12/26 Connected\n";
        let st = parse_status(raw);
        assert!(st.connected);
        assert_eq!(st.field("Profile"), Some("tn"));
        assert_eq!(st.active_profile.as_deref(), Some("tn"));
        assert_eq!(st.field("NetBird IP"), Some("100.120.192.110/16"));
        assert!(!st.needs_login);
        assert!(st.error.is_none());
    }

    #[test]
    fn parses_status_disconnected() {
        let raw = "Daemon status: NeedsLogin\nManagement: Disconnected\n";
        let st = parse_status(raw);
        assert!(!st.connected);
    }

    #[test]
    fn a_daemon_out_of_session_is_reported_as_needing_a_login() {
        // What `netbird status` prints for a user device that has to log in:
        // the state, then the prose telling a human to run `up`.
        let raw = "Daemon status: NeedsLogin\n\n\
                   Run UP command to log in with SSO (interactive login):\n\n\
                   netbird up\n";
        let st = parse_status(raw);
        assert!(st.needs_login);
        assert!(!st.connected);
        assert!(st.error.is_some());

        // The same state under the spellings other releases use for it.
        for value in ["LoginRequired", "Login required", "SessionExpired", "LoginFailed"] {
            let st = parse_status(&format!("Daemon status: {value}\nManagement: Disconnected\n"));
            assert!(st.needs_login, "{value} should mean a login is needed");
        }

        // And a daemon that is simply not connected yet is not out of session.
        let st = parse_status("Daemon status: Connecting\nManagement: Disconnected\n");
        assert!(!st.needs_login);
        assert!(st.error.is_none());
    }

    #[test]
    fn picks_the_login_url_out_of_the_stream() {
        let mut watch = SsoWatch::default();
        assert!(watch.line("Daemon version: 0.79.0", None).is_none());
        assert!(watch
            .line("Please do the SSO login in your browser. ", None)
            .is_none());
        assert!(watch
            .line("If your browser didn't open automatically, use this URL to log in:", None)
            .is_none());
        let v = watch
            .line("https://login.example.com/device?user_code=WDXQ-KRFL ", None)
            .expect("the URL line carries the verification");
        assert_eq!(v.url, "https://login.example.com/device?user_code=WDXQ-KRFL");
        // The URL already has the code in it, so there is nothing to type.
        assert!(v.code.is_none());
        // One login per command: a later URL is not a second prompt.
        assert!(watch.line("https://app.netbird.io/peers", None).is_none());
    }

    #[test]
    fn keeps_the_code_when_the_url_does_not_carry_it() {
        // netbird appends its code sentence to the URL line, and has ended it
        // with both "to authenticate." and "to log in." across releases; the word
        // after "code" is what is read, so neither wording is depended on.
        for tail in ["to authenticate.", "to log in."] {
            let mut watch = SsoWatch::default();
            watch.line("If your browser didn't open automatically, use this URL to log in:", None);
            let v = watch
                .line(
                    &format!(
                        "https://login.example.com/device and enter the code WDXQ-KRFL {tail}"
                    ),
                    None,
                )
                .expect("URL and code on one line");
            assert_eq!(v.url, "https://login.example.com/device");
            assert_eq!(v.code.as_deref(), Some("WDXQ-KRFL"));
        }
    }

    #[test]
    fn a_url_that_is_not_a_login_prompt_is_not_one() {
        // Nothing has sent a browser anywhere, so these are just URLs — the
        // second is the shape that matters: a complaint that mentions a login
        // and names the management server must not be shown as one.
        for line in [
            "Management: Connected to https://api.netbird.io:443",
            "Error: login required for https://api.netbird.io:443",
        ] {
            let mut watch = SsoWatch::default();
            assert!(watch.line(line, None).is_none(), "{line}");
        }
    }

    #[test]
    fn reports_the_reason_netbird_gave() {
        let args = vec!["up".to_string()];
        let said = vec![
            "Please do the SSO login in your browser. ".to_string(),
            "Error: daemon up failed: rpc error: code = Unauthenticated".to_string(),
        ];
        let status = failed_status();
        assert_eq!(
            failure_message(&said, &args, status),
            "Error: daemon up failed: rpc error: code = Unauthenticated"
        );
        // Nothing said at all still names the command that failed.
        assert!(failure_message(&[], &args, status).starts_with("netbird up failed"));
    }

    /// A non-zero exit to report on, without running anything that needs a
    /// network or a netbird: `false` is on every system this builds for.
    fn failed_status() -> ExitStatus {
        Command::new(if cfg!(windows) { "cmd" } else { "false" })
            .args(if cfg!(windows) {
                vec!["/C", "exit 1"]
            } else {
                vec![]
            })
            .status()
            .expect("a process that exits non-zero")
    }

    #[test]
    fn connecting_without_a_profile_does_not_switch() {
        assert_eq!(connect_cmds(None), vec![vec!["up".to_string()]]);
        assert_eq!(connect_cmds(Some("tn"))[0][2], "tn");
    }
}
