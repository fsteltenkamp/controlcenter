//! NetBird, driven through its own CLI. `netbird` talks to its daemon over a
//! socket it owns, so nothing here needs to escalate.

use super::{ProviderId, VpnMsg, VpnProfile, VpnStatus};
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;

const ME: ProviderId = ProviderId::Netbird;

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
    VpnStatus {
        connected,
        active_profile,
        fields,
        error: None,
    }
}

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
/// refresh. `netbird up` may block until a browser login completes.
pub fn action(tx: Sender<VpnMsg>, desc: String, cmds: Vec<Vec<String>>) {
    thread::spawn(move || {
        let mut error = None;
        for cmd in &cmds {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            if let Err(e) = run(&args) {
                error = Some(e);
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
pub fn connect(tx: Sender<VpnMsg>, profile: Option<&str>) -> Vec<String> {
    let desc = match profile {
        Some(p) => format!("switching to profile '{p}'"),
        None => "connecting".to_string(),
    };
    let cmds = connect_cmds(profile);
    let ran = cmds.iter().map(|c| format!("netbird {}", c.join(" "))).collect();
    action(tx, desc, cmds);
    ran
}

pub fn disconnect(tx: Sender<VpnMsg>) -> Vec<String> {
    action(tx, "disconnecting".into(), vec![vec!["down".into()]]);
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
    }

    #[test]
    fn parses_status_disconnected() {
        let raw = "Daemon status: NeedsLogin\nManagement: Disconnected\n";
        let st = parse_status(raw);
        assert!(!st.connected);
    }

    #[test]
    fn connecting_without_a_profile_does_not_switch() {
        assert_eq!(connect_cmds(None), vec![vec!["up".to_string()]]);
        assert_eq!(connect_cmds(Some("tn"))[0][2], "tn");
    }
}
