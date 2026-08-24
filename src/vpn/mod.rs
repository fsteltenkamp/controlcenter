//! VPN providers.
//!
//! Every provider is a CLI shell-out that runs on a background thread and reports
//! back over one shared [`VpnMsg`] channel, the same pattern the NetBird
//! integration has always used. `mod.rs` holds the shapes they all share plus the
//! dispatch; the per-provider modules hold the argv and the parsing.

pub mod netbird;
pub mod openvpn;
pub mod privileged;
pub mod tailscale;
pub mod wireguard;

use crate::types::{VpnConfig, WireguardProfile};
use std::path::Path;
use std::sync::mpsc::Sender;

/// The VPN clients controlcenter knows about. The declaration order is also the
/// order VPN steps are run in when one plan needs more than one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderId {
    Netbird,
    Wireguard,
    Openvpn,
    Tailscale,
}

impl ProviderId {
    pub const ALL: [ProviderId; 4] = [
        Self::Netbird,
        Self::Wireguard,
        Self::Openvpn,
        Self::Tailscale,
    ];

    /// How the provider is written in `requires_vpn` and in config files.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Netbird => "netbird",
            Self::Wireguard => "wireguard",
            Self::Openvpn => "openvpn",
            Self::Tailscale => "tailscale",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.slug() == s)
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }

    /// Everything that has to be on PATH for the provider to be usable.
    pub fn binaries(self) -> &'static [&'static str] {
        match self {
            Self::Netbird => &["netbird"],
            Self::Wireguard => &["wg", "wg-quick"],
            Self::Openvpn => &["openvpn"],
            Self::Tailscale => &["tailscale"],
        }
    }

    /// Shown in the status pane when the client is not installed.
    pub fn install_hint(self) -> &'static str {
        match self {
            Self::Netbird => "install it from https://netbird.io",
            Self::Wireguard => "install the 'wireguard-tools' package (wg, wg-quick)",
            Self::Openvpn => "install the 'openvpn' package",
            Self::Tailscale => "install it from https://tailscale.com/download",
        }
    }

    /// Whether controlcenter owns this provider's profiles, i.e. whether they can
    /// be added, edited and deleted here. NetBird's live in netbird itself.
    pub fn manages_profiles(self) -> bool {
        !matches!(self, Self::Netbird)
    }

    /// Whether only one profile of this provider can be up at a time. NetBird
    /// selects one profile; tailscale puts the node in one state. WireGuard
    /// interfaces and OpenVPN sessions coexist, so they never conflict.
    pub fn exclusive(self) -> bool {
        matches!(self, Self::Netbird | Self::Tailscale)
    }

    /// Whether connecting needs root. Only used to warn up front; the escalation
    /// itself is decided per command in [`privileged`].
    pub fn needs_root(self) -> bool {
        matches!(self, Self::Wireguard | Self::Openvpn | Self::Tailscale)
    }
}

/// One profile as the VPN tab lists it, whether it came from the provider's CLI
/// or from `vpn.toml`.
#[derive(Debug, Clone, Default)]
pub struct VpnProfile {
    pub name: String,
    pub active: bool,
    /// Short summary shown next to the name — an endpoint, a remote, an exit node.
    pub detail: String,
}

/// A provider's current state. `fields` is an ordered, untyped key/value list so
/// the status pane can render whatever a provider happens to report.
#[derive(Debug, Clone, Default)]
pub struct VpnStatus {
    pub connected: bool,
    /// The profile that is up, when the provider can name one.
    pub active_profile: Option<String>,
    pub fields: Vec<(String, String)>,
    pub error: Option<String>,
}

impl VpnStatus {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// A status that could not be read at all.
    pub fn failed(error: String) -> Self {
        Self {
            error: Some(error),
            ..Default::default()
        }
    }
}

pub enum VpnMsg {
    Refreshed {
        provider: ProviderId,
        profiles: Result<Vec<VpnProfile>, String>,
        status: VpnStatus,
    },
    ActionDone {
        provider: ProviderId,
        desc: String,
        error: Option<String>,
    },
}

impl VpnMsg {
    pub fn provider(&self) -> ProviderId {
        match self {
            Self::Refreshed { provider, .. } | Self::ActionDone { provider, .. } => *provider,
        }
    }
}

/// Files controlcenter generates for a VPN hold private keys and certificates,
/// so they are only ever readable by their owner — the same rule ssh.toml and
/// vpn.toml follow.
#[cfg(unix)]
pub fn restrict_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("locking down {}: {e}", path.display()))
}

#[cfg(not(unix))]
pub fn restrict_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
pub fn restrict_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("locking down {}: {e}", path.display()))
}

#[cfg(not(unix))]
pub fn restrict_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub fn installed(p: ProviderId) -> bool {
    p.binaries()
        .iter()
        .all(|b| crate::tunnel::which_bin(b).is_some())
}

/// What the providers need from the app to act: the stored profiles, plus where
/// controlcenter keeps the files it generates and the pid files it reads back.
#[derive(Clone, Copy)]
pub struct VpnEnv<'a> {
    pub cfg: &'a VpnConfig,
    pub wireguard_dir: &'a Path,
}

/// Fetch profiles and status on a background thread; the result arrives as
/// [`VpnMsg::Refreshed`].
///
/// OpenVPN is absent on purpose: its connection *is* a child process the app
/// owns, so there is no daemon to poll and [`crate::app::App`] fills its state in
/// directly from the sessions it is holding.
pub fn refresh(p: ProviderId, tx: Sender<VpnMsg>, env: VpnEnv<'_>) {
    match p {
        ProviderId::Netbird => netbird::refresh(tx),
        ProviderId::Wireguard => wireguard::refresh(tx, env.cfg.wireguard.clone()),
        ProviderId::Tailscale => tailscale::refresh(tx, env.cfg.tailscale.clone()),
        ProviderId::Openvpn => {}
    }
}

/// Bring `profile` up. `None` means "just connect", for providers that already
/// know which profile they are on. OpenVPN is started by the app, not here.
pub fn connect(
    p: ProviderId,
    tx: Sender<VpnMsg>,
    env: VpnEnv<'_>,
    profile: Option<&str>,
) -> Result<(), String> {
    match p {
        ProviderId::Netbird => {
            netbird::connect(tx, profile);
            Ok(())
        }
        ProviderId::Wireguard => {
            let prof = find_wireguard(env.cfg, profile)?;
            wireguard::connect(tx, prof, env.wireguard_dir, env.cfg.wireguard.clone());
            Ok(())
        }
        ProviderId::Tailscale => {
            let name = profile.ok_or("pick a tailscale profile first")?;
            let prof = env
                .cfg
                .tailscale
                .iter()
                .find(|t| t.name == name)
                .ok_or_else(|| format!("tailscale profile '{name}' no longer exists"))?;
            tailscale::connect(tx, prof.clone(), env.cfg.tailscale.clone());
            Ok(())
        }
        ProviderId::Openvpn => Err("openvpn sessions are started by the app".into()),
    }
}

/// Take the provider down. `profile` matters only where more than one can be up.
pub fn disconnect(
    p: ProviderId,
    tx: Sender<VpnMsg>,
    env: VpnEnv<'_>,
    profile: Option<&str>,
) -> Result<(), String> {
    match p {
        ProviderId::Netbird => {
            netbird::disconnect(tx);
            Ok(())
        }
        ProviderId::Wireguard => {
            let prof = find_wireguard(env.cfg, profile)?;
            wireguard::disconnect(tx, prof, env.wireguard_dir, env.cfg.wireguard.clone());
            Ok(())
        }
        ProviderId::Tailscale => {
            tailscale::disconnect(tx, env.cfg.tailscale.clone());
            Ok(())
        }
        ProviderId::Openvpn => Err("openvpn sessions are stopped by the app".into()),
    }
}

fn find_wireguard(cfg: &VpnConfig, profile: Option<&str>) -> Result<WireguardProfile, String> {
    let name = profile.ok_or("pick a wireguard profile first")?;
    cfg.wireguard
        .iter()
        .find(|w| w.name == name)
        .cloned()
        .ok_or_else(|| format!("wireguard profile '{name}' no longer exists"))
}
