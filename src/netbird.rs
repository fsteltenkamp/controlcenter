use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub active: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NbStatus {
    pub connected: bool,
    /// Ordered `key: value` pairs from `netbird status`.
    pub fields: Vec<(String, String)>,
    pub error: Option<String>,
}

impl NbStatus {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

pub enum NbMsg {
    Refreshed {
        profiles: Result<Vec<Profile>, String>,
        status: NbStatus,
    },
    ActionDone {
        desc: String,
        error: Option<String>,
    },
}

pub fn installed() -> bool {
    crate::tunnel::which_bin("netbird").is_some()
}

fn run(args: &[&str]) -> Result<String, String> {
    let out = Command::new("netbird")
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

fn parse_profiles(raw: &str) -> Vec<Profile> {
    raw.lines()
        .skip(1) // "NAME  ACTIVE" header
        .filter_map(|line| {
            let name = line.split_whitespace().next()?.to_string();
            let rest = &line[line.find(&name).unwrap_or(0) + name.len()..];
            Some(Profile {
                active: !rest.trim().is_empty(),
                name,
            })
        })
        .collect()
}

fn parse_status(raw: &str) -> NbStatus {
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
    NbStatus {
        connected,
        fields,
        error: None,
    }
}

/// Fetch profiles and status on a background thread; result arrives as `NbMsg::Refreshed`.
pub fn refresh(tx: Sender<NbMsg>) {
    thread::spawn(move || {
        let profiles = run(&["profile", "list"]).map(|out| parse_profiles(&out));
        let status = match run(&["status"]) {
            Ok(out) => parse_status(&out),
            Err(e) => NbStatus {
                connected: false,
                fields: Vec::new(),
                error: Some(e),
            },
        };
        let _ = tx.send(NbMsg::Refreshed { profiles, status });
    });
}

/// Run a sequence of netbird commands on a background thread (stops at the first
/// failure), then refresh. `netbird up` may block until login completes.
pub fn action(tx: Sender<NbMsg>, desc: String, cmds: Vec<Vec<String>>) {
    thread::spawn(move || {
        let mut error = None;
        for cmd in &cmds {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            if let Err(e) = run(&args) {
                error = Some(e);
                break;
            }
        }
        let _ = tx.send(NbMsg::ActionDone { desc, error });
        refresh(tx);
    });
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
        assert_eq!(st.field("NetBird IP"), Some("100.120.192.110/16"));
    }

    #[test]
    fn parses_status_disconnected() {
        let raw = "Daemon status: NeedsLogin\nManagement: Disconnected\n";
        let st = parse_status(raw);
        assert!(!st.connected);
    }
}
