use crate::types::{RdpConnection, SshHost, Tunnel};
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
        Ok(Self {
            config_dir,
            tunnels_file,
            config_file,
            rdp_file,
            ssh_file,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub ui: UiConfig,
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
