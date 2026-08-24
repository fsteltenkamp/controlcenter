use crate::vpn::ProviderId;
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
    /// Empty string means ungrouped.
    #[serde(default)]
    pub group: String,
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
    /// Empty string means ungrouped.
    #[serde(default)]
    pub group: String,
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

/// A VPN requirement of "anything, just be connected".
pub const VPN_ANY: &str = "*";

/// What a connection means when it names a VPN.
///
/// Written as `provider:profile`, where either half may be `*`:
///
/// | written | means |
/// |---|---|
/// | `""` | nothing |
/// | `"*"` | any provider, connected |
/// | `"netbird:*"` | any netbird profile |
/// | `"wireguard:home"` | that profile |
/// | `"work"` | netbird's, from before there was more than one provider |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnRequirement {
    /// `None` = any provider will do.
    pub provider: Option<ProviderId>,
    /// `None` = any profile of that provider will do.
    pub profile: Option<String>,
}

impl VpnRequirement {
    /// How it is written in config files and carried in a plan step.
    pub fn canonical(&self) -> String {
        match (self.provider, &self.profile) {
            (None, _) => VPN_ANY.to_string(),
            (Some(p), None) => format!("{}:{}", p.slug(), VPN_ANY),
            (Some(p), Some(name)) => format!("{}:{}", p.slug(), name),
        }
    }

    /// How it reads in the UI.
    pub fn label(&self) -> String {
        match (self.provider, &self.profile) {
            (None, _) => "any VPN".to_string(),
            (Some(p), None) => format!("{} (any profile)", p.slug()),
            (Some(p), Some(name)) => format!("{}: {name}", p.slug()),
        }
    }
}

/// Read a `requires_vpn` value. `None` for "no VPN needed".
///
/// An unqualified name is netbird's, because that is what it meant when netbird
/// was the only provider and existing config files are full of them.
pub fn parse_vpn_requirement(req: &str) -> Option<VpnRequirement> {
    let req = req.trim();
    if req.is_empty() {
        return None;
    }
    if req == VPN_ANY {
        return Some(VpnRequirement {
            provider: None,
            profile: None,
        });
    }
    let (provider, profile) = match req.split_once(':') {
        Some((slug, rest)) => match ProviderId::from_slug(slug) {
            Some(p) => (p, rest.trim()),
            // Not a provider we know — treat the whole thing as a netbird
            // profile name rather than silently dropping the requirement.
            None => (ProviderId::Netbird, req),
        },
        None => (ProviderId::Netbird, req),
    };
    Some(VpnRequirement {
        provider: Some(provider),
        profile: (profile != VPN_ANY && !profile.is_empty()).then(|| profile.to_string()),
    })
}

/// The stored form of a requirement, with legacy spellings normalised.
pub fn canonical_vpn_requirement(req: &str) -> String {
    parse_vpn_requirement(req)
        .map(|r| r.canonical())
        .unwrap_or_default()
}

/// How a VPN requirement reads in the UI.
pub fn vpn_requirement_label(req: &str) -> String {
    parse_vpn_requirement(req)
        .map(|r| r.label())
        .unwrap_or_else(|| "\u{2014}".into())
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

// ---------------------------------------------------------------------------
// VPN profiles owned by controlcenter (`vpn.toml`)
// ---------------------------------------------------------------------------

/// A WireGuard peer. Unless `config_path` points at a config someone else
/// manages, these fields are the source of truth and the `.conf` handed to
/// `wg-quick` is generated from them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WireguardProfile {
    /// Also the interface name, so it has to be a valid one.
    pub name: String,
    /// An externally managed `.conf` to use as-is. Empty = generate one.
    #[serde(default)]
    pub config_path: String,
    /// CLEARTEXT, like the ssh password — vpn.toml is written 0600.
    #[serde(default)]
    pub private_key: String,
    /// This end's address inside the tunnel, e.g. "10.0.0.2/24".
    #[serde(default)]
    pub address: String,
    /// Needs resolvconf/openresolv on PATH; empty = leave DNS alone.
    #[serde(default)]
    pub dns: String,
    /// 0 = let the kernel pick.
    #[serde(default)]
    pub listen_port: u16,
    /// 0 = default.
    #[serde(default)]
    pub mtu: u16,
    #[serde(default)]
    pub peer_public_key: String,
    #[serde(default)]
    pub preshared_key: String,
    /// "host:port" of the peer.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    /// 0 = off. 25 is the usual value behind NAT.
    #[serde(default)]
    pub persistent_keepalive: u16,
}

pub fn default_allowed_ips() -> String {
    "0.0.0.0/0, ::/0".to_string()
}

/// An OpenVPN connection, backed by a `.ovpn` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenvpnProfile {
    /// Also the name of the directory the imported copy lives in.
    pub name: String,
    /// The `.ovpn` this profile came from.
    pub config_path: String,
    /// Copy the config and every certificate it names into controlcenter's own
    /// directory, so the profile keeps working once the download folder is gone.
    /// False runs `config_path` where it sits.
    #[serde(default = "yes")]
    pub import: bool,
    /// Empty = the config does not use user/password auth.
    #[serde(default)]
    pub username: String,
    /// CLEARTEXT. Fed to openvpn on stdin, never on the command line.
    #[serde(default)]
    pub password: String,
    /// Extra openvpn flags, whitespace separated.
    #[serde(default)]
    pub extra_args: String,
}

impl Default for OpenvpnProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            config_path: String::new(),
            import: true,
            username: String::new(),
            password: String::new(),
            extra_args: String::new(),
        }
    }
}

/// A named set of `tailscale up` flags. Tailscale has no profile concept of its
/// own, so a profile here is the state `up` is asked to put the node in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleProfile {
    pub name: String,
    /// Headscale or another coordination server. Empty = Tailscale's own.
    #[serde(default)]
    pub login_server: String,
    /// Exit node by IP or name. Empty = none.
    #[serde(default)]
    pub exit_node: String,
    #[serde(default)]
    pub exit_node_allow_lan: bool,
    #[serde(default = "yes")]
    pub accept_routes: bool,
    #[serde(default = "yes")]
    pub accept_dns: bool,
    #[serde(default)]
    pub ssh: bool,
    #[serde(default)]
    pub shields_up: bool,
    /// Empty = leave the machine name alone.
    #[serde(default)]
    pub hostname: String,
    /// Comma separated CIDRs to advertise as a subnet router.
    #[serde(default)]
    pub advertise_routes: String,
    #[serde(default)]
    pub advertise_exit_node: bool,
    #[serde(default)]
    pub extra_args: String,
}

fn yes() -> bool {
    true
}

impl Default for TailscaleProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            login_server: String::new(),
            exit_node: String::new(),
            exit_node_allow_lan: false,
            accept_routes: true,
            accept_dns: true,
            ssh: false,
            shields_up: false,
            hostname: String::new(),
            advertise_routes: String::new(),
            advertise_exit_node: false,
            extra_args: String::new(),
        }
    }
}

/// Everything in `vpn.toml`. NetBird is absent on purpose: its profiles live in
/// netbird itself and are only ever read.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnConfig {
    #[serde(default)]
    pub wireguard: Vec<WireguardProfile>,
    #[serde(default)]
    pub openvpn: Vec<OpenvpnProfile>,
    #[serde(default)]
    pub tailscale: Vec<TailscaleProfile>,
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
    fn an_unqualified_requirement_is_netbirds_the_way_it_always_was() {
        let r = parse_vpn_requirement("work").unwrap();
        assert_eq!(r.provider, Some(ProviderId::Netbird));
        assert_eq!(r.profile.as_deref(), Some("work"));
        assert_eq!(r.canonical(), "netbird:work");
    }

    #[test]
    fn a_bare_star_means_any_provider_at_all() {
        let r = parse_vpn_requirement("*").unwrap();
        assert_eq!(r.provider, None);
        assert_eq!(r.profile, None);
        assert_eq!(r.canonical(), "*");
        assert_eq!(r.label(), "any VPN");
    }

    #[test]
    fn a_provider_can_be_named_with_or_without_a_profile() {
        let any = parse_vpn_requirement("netbird:*").unwrap();
        assert_eq!(any.provider, Some(ProviderId::Netbird));
        assert_eq!(any.profile, None);
        assert_eq!(any.canonical(), "netbird:*");

        let one = parse_vpn_requirement("wireguard:home").unwrap();
        assert_eq!(one.provider, Some(ProviderId::Wireguard));
        assert_eq!(one.profile.as_deref(), Some("home"));
        assert_eq!(one.label(), "wireguard: home");
    }

    #[test]
    fn nothing_required_parses_to_nothing() {
        assert!(parse_vpn_requirement("").is_none());
        assert!(parse_vpn_requirement("   ").is_none());
        assert_eq!(canonical_vpn_requirement(""), "");
        assert_eq!(vpn_requirement_label(""), "\u{2014}");
    }

    #[test]
    fn an_unknown_prefix_is_a_profile_name_not_a_dropped_requirement() {
        // A netbird profile really can contain a colon.
        let r = parse_vpn_requirement("acme:prod").unwrap();
        assert_eq!(r.provider, Some(ProviderId::Netbird));
        assert_eq!(r.profile.as_deref(), Some("acme:prod"));
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
