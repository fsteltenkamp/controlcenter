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
