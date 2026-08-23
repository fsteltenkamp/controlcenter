use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardType {
    /// -L: listen on a local port, forward to remote_host:remote_port via the ssh host.
    #[default]
    Local,
    /// -R: listen on a port on the ssh host, forward back to a local destination.
    Remote,
    /// -D: local SOCKS5 proxy through the ssh host.
    Dynamic,
}

impl ForwardType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "Local (-L)",
            Self::Remote => "Remote (-R)",
            Self::Dynamic => "Dynamic / SOCKS (-D)",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Dynamic,
            Self::Dynamic => Self::Local,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Local => Self::Dynamic,
            Self::Remote => Self::Local,
            Self::Dynamic => Self::Remote,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub name: String,
    /// Empty string means ungrouped.
    #[serde(default)]
    pub group: String,
    /// Anything ssh accepts as destination: host alias, user@host, user@host:port via extra args.
    pub ssh_host: String,
    #[serde(default)]
    pub forward: ForwardType,
    /// Local: listen port. Remote: local destination port. Dynamic: SOCKS listen port.
    pub local_port: u16,
    /// Local: destination host as seen from the ssh host. Remote: local destination host
    /// (empty = 127.0.0.1). Dynamic: unused.
    #[serde(default)]
    pub remote_host: String,
    /// Local: destination port. Remote: listen port on the ssh host. Dynamic: unused.
    #[serde(default)]
    pub remote_port: u16,
    /// Extra ssh flags, whitespace separated (e.g. "-J jumphost -p 2222").
    #[serde(default)]
    pub extra_args: String,
    #[serde(default)]
    pub auto_reconnect: bool,
    /// VPN profile that must be active first. Empty = none, `*` = any profile
    /// as long as the VPN is connected.
    #[serde(default)]
    pub requires_vpn: String,
    /// Tunnel that must be up first — stacking a tunnel on another tunnel's
    /// local end. Empty = none.
    #[serde(default)]
    pub depends_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpConnection {
    pub name: String,
    pub host: String,
    #[serde(default = "default_rdp_port")]
    pub port: u16,
    /// Empty = no domain.
    #[serde(default)]
    pub domain: String,
    pub username: String,
    /// Extra xfreerdp3 flags, whitespace separated (e.g. "/f /sound").
    #[serde(default)]
    pub extra_args: String,
    /// Name of a tunnel that must be up before connecting. Empty = none.
    #[serde(default)]
    pub depends_on: String,
    /// VPN profile that must be active first. Empty = none, `*` = any profile.
    #[serde(default)]
    pub requires_vpn: String,
}

pub fn default_rdp_port() -> u16 {
    3389
}

impl RdpConnection {
    pub fn login_summary(&self) -> String {
        if self.domain.is_empty() {
            self.username.clone()
        } else {
            format!("{}\\{}", self.domain, self.username)
        }
    }

    pub fn target_summary(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Tunnel {
    pub fn forward_summary(&self) -> String {
        match self.forward {
            ForwardType::Local => format!(
                ":{} → {}:{}",
                self.local_port, self.remote_host, self.remote_port
            ),
            ForwardType::Remote => format!(
                "remote:{} → {}:{}",
                self.remote_port,
                self.dest_host(),
                self.local_port
            ),
            ForwardType::Dynamic => format!("SOCKS :{}", self.local_port),
        }
    }

    pub fn dest_host(&self) -> &str {
        if self.remote_host.is_empty() {
            "127.0.0.1"
        } else {
            &self.remote_host
        }
    }
}

/// An interactive SSH login. Unlike a tunnel this is a foreground session: the
/// TUI suspends itself and hands the terminal to ssh until the session ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshHost {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Empty = let ssh decide (ssh_config / current user).
    #[serde(default)]
    pub username: String,
    /// Private key passed as `-i`. Empty = agent or ssh_config default.
    #[serde(default)]
    pub key_path: String,
    /// Stored in cleartext in ssh.toml and used through `sshpass -e`.
    /// Empty = no stored password (ssh prompts in the session itself).
    #[serde(default)]
    pub password: String,
    /// StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null — for hosts
    /// reached through a tunnel on 127.0.0.1, whose key changes per target.
    #[serde(default)]
    pub skip_host_key_check: bool,
    /// Extra ssh flags, whitespace separated (e.g. "-A -o Compression=yes").
    #[serde(default)]
    pub extra_args: String,
    /// Name of a tunnel that must be up before connecting. Empty = none.
    #[serde(default)]
    pub depends_on: String,
    /// VPN profile that must be active first. Empty = none, `*` = any profile.
    #[serde(default)]
    pub requires_vpn: String,
}

pub fn default_ssh_port() -> u16 {
    22
}

impl SshHost {
    pub fn target_summary(&self) -> String {
        if self.username.is_empty() {
            format!("{}:{}", self.host, self.port)
        } else {
            format!("{}@{}:{}", self.username, self.host, self.port)
        }
    }

    /// The `[user@]host` argument handed to ssh.
    pub fn destination(&self) -> String {
        if self.username.is_empty() {
            self.host.clone()
        } else {
            format!("{}@{}", self.username, self.host)
        }
    }

    pub fn auth_summary(&self) -> String {
        match (self.key_path.is_empty(), self.password.is_empty()) {
            (false, false) => format!("key {} + password", self.key_path),
            (false, true) => format!("key {}", self.key_path),
            (true, false) => "stored password".into(),
            (true, true) => "agent / ssh_config".into(),
        }
    }
}

impl Tunnel {
    /// The endpoint this tunnel binds while it runs: a local listen port for
    /// -L/-D, or a port on the ssh host for -R. Two tunnels can only be up at
    /// the same time if their bindings differ.
    pub fn binding(&self) -> String {
        match self.forward {
            ForwardType::Local | ForwardType::Dynamic => {
                format!("local port {}", self.local_port)
            }
            ForwardType::Remote => {
                format!("port {} on {}", self.remote_port, self.ssh_host)
            }
        }
    }
}

/// A VPN requirement of "any profile, just be connected".
pub const VPN_ANY: &str = "*";

/// How a VPN requirement reads in the UI.
pub fn vpn_requirement_label(req: &str) -> String {
    match req {
        "" => "—".into(),
        VPN_ANY => "any profile".into(),
        name => name.to_string(),
    }
}

/// What a connection needs before it can start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requires {
    pub vpn: String,
    pub tunnel: String,
}

impl Tunnel {
    pub fn requires(&self) -> Requires {
        Requires {
            vpn: self.requires_vpn.clone(),
            tunnel: self.depends_on.clone(),
        }
    }
}

impl SshHost {
    pub fn requires(&self) -> Requires {
        Requires {
            vpn: self.requires_vpn.clone(),
            tunnel: self.depends_on.clone(),
        }
    }
}

impl RdpConnection {
    pub fn requires(&self) -> Requires {
        Requires {
            vpn: self.requires_vpn.clone(),
            tunnel: self.depends_on.clone(),
        }
    }
}

/// `Some(reason)` when `a` and `b` would fight over the same bound endpoint.
pub fn tunnel_conflict(a: &Tunnel, b: &Tunnel) -> Option<String> {
    let (binding_a, binding_b) = (a.binding(), b.binding());
    (binding_a == binding_b).then_some(binding_a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(name: &str, forward: ForwardType, local: u16, remote: u16) -> Tunnel {
        Tunnel {
            name: name.into(),
            group: String::new(),
            ssh_host: "bastion".into(),
            forward,
            local_port: local,
            remote_host: "db.internal".into(),
            remote_port: remote,
            extra_args: String::new(),
            auto_reconnect: false,
            requires_vpn: String::new(),
            depends_on: String::new(),
        }
    }

    #[test]
    fn same_local_listen_port_conflicts_across_forward_types() {
        let a = tunnel("a", ForwardType::Local, 5432, 5432);
        let b = tunnel("b", ForwardType::Dynamic, 5432, 0);
        assert_eq!(tunnel_conflict(&a, &b), Some("local port 5432".into()));
    }

    #[test]
    fn different_local_ports_do_not_conflict() {
        let a = tunnel("a", ForwardType::Local, 5432, 5432);
        let b = tunnel("b", ForwardType::Local, 5433, 5432);
        assert_eq!(tunnel_conflict(&a, &b), None);
    }

    #[test]
    fn remote_forwards_bind_on_the_ssh_host_not_locally() {
        // -R listens on the ssh host, so a local port of the same number is free.
        let local = tunnel("local", ForwardType::Local, 8080, 80);
        let remote = tunnel("remote", ForwardType::Remote, 8080, 8080);
        assert_eq!(tunnel_conflict(&local, &remote), None);

        let same = tunnel("same", ForwardType::Remote, 9000, 8080);
        assert_eq!(
            tunnel_conflict(&remote, &same),
            Some("port 8080 on bastion".into())
        );

        let other_host = Tunnel {
            ssh_host: "other".into(),
            ..tunnel("elsewhere", ForwardType::Remote, 8080, 8080)
        };
        assert_eq!(tunnel_conflict(&remote, &other_host), None);
    }
}
