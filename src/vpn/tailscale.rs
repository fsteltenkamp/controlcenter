//! Tailscale. There is no profile concept in tailscale itself — a node is in one
//! state at a time — so a "profile" here is a named set of `tailscale up` flags,
//! and the active profile is whichever stored one matches the daemon's current
//! preferences.

use super::{privileged, ProviderId, VpnMsg, VpnProfile, VpnStatus};
use crate::types::TailscaleProfile;
use serde_json::Value;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;

const ME: ProviderId = ProviderId::Tailscale;
const DEFAULT_CONTROL_URL: &str = "https://controlplane.tailscale.com";

/// The unprivileged half: `status` and `debug prefs` normally work as the plain
/// user, and escalating a five-second poll would spam the polkit agent.
fn run(args: &[&str]) -> Result<String, String> {
    let out = Command::new("tailscale")
        .args(args)
        .output()
        .map_err(|e| format!("running tailscale: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let msg = stderr.trim();
    Err(if msg.is_empty() {
        format!("tailscale {} failed ({})", args.join(" "), out.status)
    } else {
        msg.to_string()
    })
}

/// tailscaled's socket is root-owned unless the user was made its operator.
fn is_permission_error(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("permission denied") || e.contains("access denied") || e.contains("operator")
}

const OPERATOR_HINT: &str =
    "run `sudo tailscale set --operator=$USER` to use tailscale without root";

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

fn parse_status(raw: &str) -> VpnStatus {
    let Ok(v): Result<Value, _> = serde_json::from_str(raw) else {
        return VpnStatus::failed("could not parse `tailscale status --json`".into());
    };
    let state = str_at(&v, "BackendState").unwrap_or("Unknown");
    let mut fields = vec![("Backend".to_string(), state.to_string())];

    if let Some(me) = v.get("Self") {
        if let Some(dns) = str_at(me, "DNSName") {
            fields.push(("DNS name".into(), dns.trim_end_matches('.').to_string()));
        }
        if let Some(ip) = me
            .get("TailscaleIPs")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
        {
            fields.push(("Tailscale IP".into(), ip.to_string()));
        }
    }
    if let Some(net) = v.get("CurrentTailnet").and_then(|t| str_at(t, "Name")) {
        fields.push(("Tailnet".into(), net.to_string()));
    }
    if let Some(peers) = v.get("Peer").and_then(Value::as_object) {
        let online = peers
            .values()
            .filter(|p| p.get("Online").and_then(Value::as_bool) == Some(true))
            .count();
        fields.push(("Peers".into(), format!("{online}/{} online", peers.len())));
    }
    if let Some(exit) = v.get("ExitNodeStatus") {
        let ip = exit
            .get("TailscaleIPs")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("");
        let online = exit.get("Online").and_then(Value::as_bool) == Some(true);
        fields.push((
            "Exit node".into(),
            format!("{ip}{}", if online { "" } else { " (offline)" }),
        ));
    }

    // A node that needs a login is not an error — it is a state to act on.
    let error = match state {
        "NeedsLogin" | "NeedsMachineAuth" => v
            .get("AuthURL")
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty())
            .map(|u| format!("log in first: {u}")),
        _ => None,
    };

    VpnStatus {
        connected: state == "Running",
        active_profile: None, // filled in from prefs by refresh
        fields,
        error,
    }
}

/// Which stored profile, if any, describes the daemon's current preferences.
/// Tailscale cannot tell us a profile name, so this is the only honest answer.
fn match_prefs(raw: &str, profiles: &[TailscaleProfile]) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let control = str_at(&v, "ControlURL").unwrap_or(DEFAULT_CONTROL_URL);
    let exit_node = str_at(&v, "ExitNodeIP").unwrap_or("");
    let route_all = v.get("RouteAll").and_then(Value::as_bool).unwrap_or(false);
    let corp_dns = v.get("CorpDNS").and_then(Value::as_bool).unwrap_or(false);
    let run_ssh = v.get("RunSSH").and_then(Value::as_bool).unwrap_or(false);
    let shields = v.get("ShieldsUp").and_then(Value::as_bool).unwrap_or(false);
    let hostname = str_at(&v, "Hostname").unwrap_or("");
    let routes: Vec<String> = v
        .get("AdvertiseRoutes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    profiles
        .iter()
        .find(|p| {
            let want_control = if p.login_server.is_empty() {
                DEFAULT_CONTROL_URL
            } else {
                p.login_server.trim_end_matches('/')
            };
            want_control == control.trim_end_matches('/')
                && p.exit_node == exit_node
                && p.accept_routes == route_all
                && p.accept_dns == corp_dns
                && p.ssh == run_ssh
                && p.shields_up == shields
                && p.hostname == hostname
                && same_routes(&p.advertise_routes, &routes)
        })
        .map(|p| p.name.clone())
}

fn same_routes(configured: &str, actual: &[String]) -> bool {
    let mut want: Vec<&str> = configured
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut have: Vec<&str> = actual.iter().map(String::as_str).collect();
    want.sort_unstable();
    have.sort_unstable();
    want == have
}

/// The flags a profile turns into. Everything is stated explicitly and paired
/// with `--reset`, because `tailscale up` otherwise merges into whatever flags
/// were set before and a profile would not mean a fixed state.
pub fn up_args(p: &TailscaleProfile) -> Vec<String> {
    let mut a: Vec<String> = vec!["up".into(), "--reset".into()];
    a.push(format!("--accept-routes={}", p.accept_routes));
    a.push(format!("--accept-dns={}", p.accept_dns));
    a.push(format!("--ssh={}", p.ssh));
    a.push(format!("--shields-up={}", p.shields_up));
    a.push(format!("--advertise-exit-node={}", p.advertise_exit_node));
    if !p.login_server.is_empty() {
        a.push(format!("--login-server={}", p.login_server));
    }
    if !p.exit_node.is_empty() {
        a.push(format!("--exit-node={}", p.exit_node));
        a.push(format!(
            "--exit-node-allow-lan-access={}",
            p.exit_node_allow_lan
        ));
    }
    if !p.hostname.is_empty() {
        a.push(format!("--hostname={}", p.hostname));
    }
    if !p.advertise_routes.is_empty() {
        let routes: Vec<&str> = p
            .advertise_routes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        a.push(format!("--advertise-routes={}", routes.join(",")));
    }
    a.extend(p.extra_args.split_whitespace().map(String::from));
    a
}

fn summarise(p: &TailscaleProfile) -> String {
    let mut bits = Vec::new();
    if !p.login_server.is_empty() {
        bits.push(p.login_server.clone());
    }
    if !p.exit_node.is_empty() {
        bits.push(format!("exit {}", p.exit_node));
    }
    if p.ssh {
        bits.push("ssh".into());
    }
    if !p.advertise_routes.is_empty() {
        bits.push("subnet router".into());
    }
    bits.join(" · ")
}

pub fn refresh(tx: Sender<VpnMsg>, stored: Vec<TailscaleProfile>) {
    thread::spawn(move || {
        let mut status = match run(&["status", "--json"]) {
            Ok(out) => parse_status(&out),
            Err(e) if is_permission_error(&e) => VpnStatus::failed(format!("{e}\n{OPERATOR_HINT}")),
            Err(e) => VpnStatus::failed(e),
        };
        // `debug prefs` is how a stored profile is matched to the live state;
        // without it the tab still works, it just marks nothing active.
        if status.error.is_none() {
            if let Ok(prefs) = run(&["debug", "prefs"]) {
                status.active_profile = match_prefs(&prefs, &stored);
            }
        }
        let active = status.active_profile.clone();
        let profiles = stored
            .iter()
            .map(|p| VpnProfile {
                active: status.connected && active.as_deref() == Some(p.name.as_str()),
                name: p.name.clone(),
                detail: summarise(p),
                foreign: None,
            })
            .collect();
        let _ = tx.send(VpnMsg::Refreshed {
            provider: ME,
            profiles: Ok(profiles),
            status,
        });
    });
}

/// `up` and `down` change system state, so they go through the escalation
/// helper — unlike the status poll.
fn action(tx: Sender<VpnMsg>, desc: String, args: Vec<String>, stored: Vec<TailscaleProfile>) {
    thread::spawn(move || {
        let mut argv = vec!["tailscale".to_string()];
        argv.extend(args);
        let error = privileged::run(&argv).err();
        let _ = tx.send(VpnMsg::ActionDone {
            provider: ME,
            desc,
            error,
        });
        refresh(tx, stored);
    });
}

/// Bring a profile up. Returns the command line it launched, for the log.
pub fn connect(
    tx: Sender<VpnMsg>,
    profile: TailscaleProfile,
    stored: Vec<TailscaleProfile>,
) -> Vec<String> {
    let desc = format!("bringing up '{}'", profile.name);
    let args = up_args(&profile);
    let ran = vec![as_root(&args)];
    action(tx, desc, args, stored);
    ran
}

pub fn disconnect(tx: Sender<VpnMsg>, stored: Vec<TailscaleProfile>) -> Vec<String> {
    let args = vec!["down".to_string()];
    let ran = vec![as_root(&args)];
    action(tx, "disconnecting".into(), args, stored);
    ran
}

/// How the log writes a command that went through the escalation helper.
fn as_root(args: &[String]) -> String {
    format!("tailscale {} (as root)", args.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> TailscaleProfile {
        TailscaleProfile {
            name: name.into(),
            ..Default::default()
        }
    }

    const RUNNING: &str = r#"{
      "BackendState": "Running",
      "TailscaleIPs": ["100.64.0.1"],
      "Self": { "DNSName": "laptop.tail1234.ts.net.", "TailscaleIPs": ["100.64.0.1"] },
      "CurrentTailnet": { "Name": "example.com" },
      "Peer": { "a": { "Online": true }, "b": { "Online": false } },
      "ExitNodeStatus": { "Online": true, "TailscaleIPs": ["100.64.0.9/32"] }
    }"#;

    #[test]
    fn parses_a_running_node() {
        let st = parse_status(RUNNING);
        assert!(st.connected);
        assert_eq!(st.field("DNS name"), Some("laptop.tail1234.ts.net"));
        assert_eq!(st.field("Tailnet"), Some("example.com"));
        assert_eq!(st.field("Peers"), Some("1/2 online"));
        assert_eq!(st.field("Exit node"), Some("100.64.0.9/32"));
        assert!(st.error.is_none());
    }

    #[test]
    fn a_node_needing_login_is_not_connected_and_says_where_to_log_in() {
        let raw = r#"{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/abc"}"#;
        let st = parse_status(raw);
        assert!(!st.connected);
        assert!(st
            .error
            .unwrap()
            .contains("https://login.tailscale.com/a/abc"));
    }

    #[test]
    fn a_stopped_node_is_neither_connected_nor_an_error() {
        let st = parse_status(r#"{"BackendState":"Stopped"}"#);
        assert!(!st.connected);
        assert!(st.error.is_none());
        assert_eq!(st.field("Backend"), Some("Stopped"));
    }

    #[test]
    fn prefs_pick_out_the_profile_that_describes_them() {
        let prefs = r#"{
          "ControlURL": "https://controlplane.tailscale.com",
          "RouteAll": true, "CorpDNS": true, "RunSSH": false, "ShieldsUp": false,
          "ExitNodeIP": "100.64.0.9", "Hostname": "", "AdvertiseRoutes": null
        }"#;
        let plain = profile("plain");
        let with_exit = TailscaleProfile {
            exit_node: "100.64.0.9".into(),
            ..profile("via-exit")
        };
        let both = vec![plain, with_exit];
        assert_eq!(match_prefs(prefs, &both).as_deref(), Some("via-exit"));
    }

    #[test]
    fn no_stored_profile_matches_an_unfamiliar_state() {
        let prefs = r#"{"ControlURL":"https://headscale.example.com","RouteAll":false,
                        "CorpDNS":false,"RunSSH":false,"ShieldsUp":false,
                        "ExitNodeIP":"","Hostname":"","AdvertiseRoutes":null}"#;
        assert_eq!(match_prefs(prefs, &[profile("plain")]), None);
    }

    #[test]
    fn up_always_resets_so_a_profile_means_a_fixed_state() {
        let p = TailscaleProfile {
            exit_node: "100.64.0.9".into(),
            advertise_routes: "10.0.0.0/24, 192.168.1.0/24".into(),
            ssh: true,
            ..profile("work")
        };
        let args = up_args(&p);
        assert_eq!(args[0], "up");
        assert!(args.contains(&"--reset".to_string()));
        assert!(args.contains(&"--ssh=true".to_string()));
        assert!(args.contains(&"--exit-node=100.64.0.9".to_string()));
        assert!(args.contains(&"--advertise-routes=10.0.0.0/24,192.168.1.0/24".to_string()));
    }

    #[test]
    fn advertised_routes_compare_regardless_of_spacing_and_order() {
        let actual = vec!["192.168.1.0/24".to_string(), "10.0.0.0/24".to_string()];
        assert!(same_routes("10.0.0.0/24, 192.168.1.0/24", &actual));
        assert!(!same_routes("10.0.0.0/24", &actual));
        assert!(same_routes("", &[]));
    }
}
