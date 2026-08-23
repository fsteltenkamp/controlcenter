use crate::types::SshHost;
use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Result of a finished interactive session, kept for the details panel.
#[derive(Debug, Clone, Copy)]
pub struct SessionOutcome {
    pub code: i32,
    pub duration: Duration,
    pub finished_at: Instant,
}

impl SessionOutcome {
    pub fn label(&self) -> String {
        match self.code {
            0 => "closed".into(),
            c => format!("exited ({c})"),
        }
    }
}

/// The ssh arguments for an interactive login, in the order they are passed.
pub fn build_args(host: &SshHost) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if host.port != 22 {
        args.push("-p".into());
        args.push(host.port.to_string());
    }
    if !host.key_path.is_empty() {
        args.push("-i".into());
        args.push(expand_tilde(&host.key_path));
        // A configured key is the intent; don't let the agent shadow it.
        args.push("-o".into());
        args.push("IdentitiesOnly=yes".into());
    }
    if host.skip_host_key_check {
        args.push("-o".into());
        args.push("StrictHostKeyChecking=no".into());
        args.push("-o".into());
        args.push("UserKnownHostsFile=/dev/null".into());
        // Otherwise every connect prints a "permanently added" warning.
        args.push("-o".into());
        args.push("LogLevel=ERROR".into());
    }
    if !host.password.is_empty() {
        // sshpass answers exactly one prompt; more means the password is wrong
        // and we would otherwise loop.
        args.push("-o".into());
        args.push("NumberOfPasswordPrompts=1".into());
    }
    args.extend(host.extra_args.split_whitespace().map(String::from));
    args.push(host.destination());
    args
}

/// The command line as the user would type it, for the details panel.
/// A stored password is never shown — it goes through the environment.
pub fn command_preview(host: &SshHost) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !host.password.is_empty() {
        parts.push("sshpass".into());
        parts.push("-e".into());
    }
    parts.push("ssh".into());
    parts.extend(build_args(host));
    parts.join(" ")
}

/// Run ssh attached to the current terminal and wait for it to finish.
/// The caller must have left the alternate screen and raw mode first.
pub fn run_interactive(host: &SshHost) -> Result<SessionOutcome> {
    let args = build_args(host);
    let started = Instant::now();

    let mut cmd = if host.password.is_empty() {
        let mut c = Command::new("ssh");
        c.args(&args);
        c
    } else {
        // -e reads the password from SSHPASS so it never lands in the process
        // list, where any user on the box could read it.
        let mut c = Command::new("sshpass");
        c.arg("-e").arg("ssh").args(&args);
        c.env("SSHPASS", &host.password);
        c
    };

    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            if host.password.is_empty() {
                "spawning ssh".to_string()
            } else {
                "spawning sshpass (is sshpass installed?)".to_string()
            }
        })?;
    let status = child.wait().context("waiting for ssh")?;

    Ok(SessionOutcome {
        code: status.code().unwrap_or(-1),
        duration: started.elapsed(),
        finished_at: Instant::now(),
    })
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => format!("{}/{}", home.to_string_lossy(), rest),
            None => path.to_string(),
        },
        None => path.to_string(),
    }
}

pub fn sshpass_available() -> bool {
    crate::tunnel::which_bin("sshpass").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> SshHost {
        SshHost {
            name: "h".into(),
            host: "example.com".into(),
            port: 22,
            username: String::new(),
            key_path: String::new(),
            password: String::new(),
            skip_host_key_check: false,
            extra_args: String::new(),
            depends_on: String::new(),
            requires_vpn: String::new(),
        }
    }

    #[test]
    fn default_port_and_user_stay_off_the_command_line() {
        assert_eq!(build_args(&host()), vec!["example.com".to_string()]);
    }

    #[test]
    fn user_port_key_and_extra_args_are_passed() {
        let h = SshHost {
            username: "root".into(),
            port: 2222,
            key_path: "/keys/id_ed25519".into(),
            extra_args: "-A".into(),
            ..host()
        };
        assert_eq!(
            build_args(&h),
            vec![
                "-p",
                "2222",
                "-i",
                "/keys/id_ed25519",
                "-o",
                "IdentitiesOnly=yes",
                "-A",
                "root@example.com",
            ]
        );
    }

    #[test]
    fn skipping_host_key_verification_disables_both_checks() {
        let h = SshHost {
            skip_host_key_check: true,
            ..host()
        };
        let args = build_args(&h);
        assert!(args.contains(&"StrictHostKeyChecking=no".to_string()));
        assert!(args.contains(&"UserKnownHostsFile=/dev/null".to_string()));
    }

    #[test]
    fn stored_password_never_appears_in_the_preview() {
        let h = SshHost {
            password: "hunter2".into(),
            ..host()
        };
        let preview = command_preview(&h);
        assert!(!preview.contains("hunter2"));
        assert!(preview.starts_with("sshpass -e ssh"));
    }
}
