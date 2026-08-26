use crate::types::{RdpConnection, SshHost, Tunnel, VpnConfig};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub tunnels_file: PathBuf,
    pub config_file: PathBuf,
    pub rdp_file: PathBuf,
    pub ssh_file: PathBuf,
    pub vpn_file: PathBuf,
    /// WireGuard configs controlcenter generates and hands to `wg-quick`.
    pub wireguard_dir: PathBuf,
    /// One directory per imported OpenVPN profile: the `.ovpn` plus the
    /// certificates it ships with.
    pub openvpn_dir: PathBuf,
    /// Short-lived files, e.g. the pid openvpn writes so it can be signalled.
    pub run_dir: PathBuf,
    /// Reports exported from a log pane. Created the first time one is written.
    pub reports_dir: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "controlcenter", "controlcenter")
            .context("could not resolve platform config directories")?;
        let config_dir = dirs.config_dir().to_path_buf();
        let tunnels_file = config_dir.join("tunnels.toml");
        let config_file = config_dir.join("config.toml");
        let rdp_file = config_dir.join("rdp.toml");
        let ssh_file = config_dir.join("ssh.toml");
        let vpn_file = config_dir.join("vpn.toml");
        let wireguard_dir = config_dir.join("wireguard");
        let openvpn_dir = config_dir.join("openvpn");
        let reports_dir = config_dir.join("reports");
        let run_dir = dirs
            .runtime_dir()
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir)
            .join("controlcenter");
        Ok(Self {
            config_dir,
            tunnels_file,
            config_file,
            rdp_file,
            ssh_file,
            vpn_file,
            wireguard_dir,
            openvpn_dir,
            run_dir,
            reports_dir,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        // These hold private keys and client certificates, so they are 0700
        // even before a single file lands in them.
        for dir in [&self.wireguard_dir, &self.openvpn_dir] {
            fs::create_dir_all(dir)?;
            restrict_dir(dir)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TunnelsFile {
    #[serde(default)]
    tunnels: Vec<Tunnel>,
}

pub fn load_tunnels(path: &Path) -> Result<Vec<Tunnel>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file: TunnelsFile =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(file.tunnels)
}

pub fn save_tunnels(path: &Path, tunnels: &[Tunnel]) -> Result<()> {
    let file = TunnelsFile {
        tunnels: tunnels.to_vec(),
    };
    let raw = toml::to_string_pretty(&file)?;
    fs::write(path, raw).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RdpFile {
    #[serde(default)]
    connections: Vec<RdpConnection>,
}

pub fn load_rdp(path: &Path) -> Result<Vec<RdpConnection>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file: RdpFile =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(file.connections)
}

pub fn save_rdp(path: &Path, connections: &[RdpConnection]) -> Result<()> {
    let file = RdpFile {
        connections: connections.to_vec(),
    };
    let raw = toml::to_string_pretty(&file)?;
    fs::write(path, raw).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SshFile {
    #[serde(default)]
    hosts: Vec<SshHost>,
}

pub fn load_ssh(path: &Path) -> Result<Vec<SshHost>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file: SshFile =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(file.hosts)
}

/// SSH hosts may carry a cleartext password, so the file is written 0600.
pub fn save_ssh(path: &Path, hosts: &[SshHost]) -> Result<()> {
    let file = SshFile {
        hosts: hosts.to_vec(),
    };
    let raw = toml::to_string_pretty(&file)?;
    fs::write(path, raw).with_context(|| format!("writing {}", path.display()))?;
    restrict_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("locking down {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("locking down {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn load_vpn(path: &Path) -> Result<VpnConfig> {
    if !path.exists() {
        return Ok(VpnConfig::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: VpnConfig =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(cfg)
}

/// VPN profiles may carry a WireGuard private key or an OpenVPN password, so the
/// file is written 0600 just like ssh.toml.
pub fn save_vpn(path: &Path, cfg: &VpnConfig) -> Result<()> {
    let raw = toml::to_string_pretty(cfg)?;
    fs::write(path, raw).with_context(|| format!("writing {}", path.display()))?;
    restrict_permissions(path)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub vpn: VpnAppConfig,
}

/// How controlcenter handles the two things about a VPN that outlive it: the
/// root it needs to take one down, and the sessions still up when it quits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnAppConfig {
    /// Whether to take a sudo ticket on the terminal before the TUI starts:
    ///   ask     ask for a password if there is no valid ticket (default)
    ///   auto    use a ticket that is already there, never ask
    ///   never   leave sudo alone; every escalation goes through polkit
    ///
    /// With a ticket, stopping a VPN is a silent `sudo -n` instead of a polkit
    /// dialog per connection — which matters most for the dialog that gets
    /// dismissed and leaves a root openvpn running that nothing can reach.
    #[serde(default = "default_sudo")]
    pub sudo: String,
    /// What happens to OpenVPN sessions still up when you quit:
    ///   ask     ask, every time (default)
    ///   stop    take them down
    ///   keep    leave them running
    ///
    /// An OpenVPN session is a root process; once controlcenter is gone,
    /// nothing that is left knows how to reach it.
    #[serde(default = "default_on_exit")]
    pub on_exit: String,
}

impl Default for VpnAppConfig {
    fn default() -> Self {
        Self {
            sudo: default_sudo(),
            on_exit: default_on_exit(),
        }
    }
}

fn default_sudo() -> String {
    "ask".to_string()
}

fn default_on_exit() -> String {
    "ask".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    /// Where an interactive session opens:
    ///   auto     the first terminal emulator found on PATH ($TERMINAL first),
    ///            falling back to inline when there is none
    ///   inline   hand the current terminal to ssh until the session ends
    ///   <cmd>    a terminal command line of your own, e.g.
    ///            "kitty --title ssh" or "alacritty -e sh -c {cmd}";
    ///            without a {cmd} placeholder the command is appended
    #[serde(default = "default_ssh_terminal")]
    pub terminal: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            terminal: default_ssh_terminal(),
        }
    }
}

fn default_ssh_terminal() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    #[serde(default = "default_theme")]
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
        }
    }
}

fn default_theme() -> String {
    "dark".to_string()
}

pub fn load_app_config(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: AppConfig =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(cfg)
}

pub fn save_app_config(path: &Path, cfg: &AppConfig) -> Result<()> {
    let raw = toml::to_string_pretty(cfg)?;
    fs::write(path, raw).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
