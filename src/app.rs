use crate::config::{self, AppConfig, Paths};
use crate::netbird::{self, NbMsg, NbStatus, Profile};
use crate::rdp::{self, ActiveRdp, RdpStatus};
use crate::ssh::{self, SessionOutcome};
use crate::theme::{self, Theme};
use crate::tunnel::{self, ActiveTunnel, Status};
use crate::types::{
    tunnel_conflict, vpn_requirement_label, ForwardType, RdpConnection, Requires, SshHost, Tunnel,
    VPN_ANY,
};
use crate::ui;
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

pub const THROUGHPUT_HISTORY: usize = 120;
const NETBIRD_REFRESH_SECS: u64 = 5;
/// How long a dependent connection waits for its tunnel to come up.
const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(30);
/// `netbird up` may sit through a browser login, so it gets much longer.
const VPN_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Vpn,
    Tunnels,
    Ssh,
    Rdp,
}

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Dashboard, Tab::Vpn, Tab::Tunnels, Tab::Ssh, Tab::Rdp];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Vpn => "VPN",
            Self::Tunnels => "Tunnels",
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// One visible row in the Tunnels tab: a group header or a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowItem {
    Group(String),
    Tunnel(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    None,
    Add,
    Edit(usize),
    DeleteConfirm(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Name,
    Group,
    SshHost,
    Forward,
    LocalPort,
    RemoteHost,
    RemotePort,
    ExtraArgs,
    AutoReconnect,
    RequiresVpn,
    DependsOn,
}

pub const FORM_FIELDS: &[FormField] = &[
    FormField::Name,
    FormField::Group,
    FormField::SshHost,
    FormField::Forward,
    FormField::LocalPort,
    FormField::RemoteHost,
    FormField::RemotePort,
    FormField::ExtraArgs,
    FormField::AutoReconnect,
    FormField::RequiresVpn,
    FormField::DependsOn,
];

impl FormField {
    pub fn label(self, forward: ForwardType) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Group => "Group (optional)",
            Self::SshHost => "SSH host (alias or user@host)",
            Self::Forward => "Forward type",
            Self::LocalPort => match forward {
                ForwardType::Remote => "Local destination port",
                ForwardType::Dynamic => "SOCKS listen port",
                ForwardType::Local => "Local listen port",
            },
            Self::RemoteHost => match forward {
                ForwardType::Remote => "Local destination host (empty = 127.0.0.1)",
                _ => "Remote destination host",
            },
            Self::RemotePort => match forward {
                ForwardType::Remote => "Listen port on SSH host",
                _ => "Remote destination port",
            },
            Self::ExtraArgs => "Extra ssh args (optional)",
            Self::AutoReconnect => "Auto-reconnect",
            Self::RequiresVpn => "Requires VPN",
            Self::DependsOn => "Requires tunnel",
        }
    }

    /// Whether the field applies to the given forward type.
    pub fn applies(self, forward: ForwardType) -> bool {
        match self {
            Self::RemoteHost | Self::RemotePort => forward != ForwardType::Dynamic,
            _ => true,
        }
    }

    /// Toggled with ◂ ▸ instead of typed into.
    pub fn is_picker(self) -> bool {
        matches!(
            self,
            Self::Forward | Self::AutoReconnect | Self::RequiresVpn | Self::DependsOn
        )
    }
}

#[derive(Debug, Clone)]
pub struct TunnelForm {
    pub field_idx: usize,
    pub name: String,
    pub group: String,
    pub ssh_host: String,
    pub forward: ForwardType,
    pub local_port: String,
    pub remote_host: String,
    pub remote_port: String,
    pub extra_args: String,
    pub auto_reconnect: bool,
    pub vpn: Picker,
    pub dep: Picker,
    pub error: Option<String>,
}

impl TunnelForm {
    pub fn empty(ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: String::new(),
            group: String::new(),
            ssh_host: String::new(),
            forward: ForwardType::Local,
            local_port: String::new(),
            remote_host: String::new(),
            remote_port: String::new(),
            extra_args: String::new(),
            auto_reconnect: false,
            vpn: Picker::vpn(ctx.profiles, ""),
            dep: Picker::tunnels(ctx.tunnels, "", None),
            error: None,
        }
    }

    pub fn from_tunnel(t: &Tunnel, ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: t.name.clone(),
            group: t.group.clone(),
            ssh_host: t.ssh_host.clone(),
            forward: t.forward,
            local_port: t.local_port.to_string(),
            remote_host: t.remote_host.clone(),
            remote_port: if t.remote_port == 0 {
                String::new()
            } else {
                t.remote_port.to_string()
            },
            extra_args: t.extra_args.clone(),
            auto_reconnect: t.auto_reconnect,
            vpn: Picker::vpn(ctx.profiles, &t.requires_vpn),
            // A tunnel cannot depend on itself.
            dep: Picker::tunnels(ctx.tunnels, &t.depends_on, Some(&t.name)),
            error: None,
        }
    }

    pub fn field(&self) -> FormField {
        FORM_FIELDS[self.field_idx]
    }

    pub fn next_field(&mut self) {
        loop {
            self.field_idx = (self.field_idx + 1) % FORM_FIELDS.len();
            if self.field().applies(self.forward) {
                break;
            }
        }
    }

    pub fn prev_field(&mut self) {
        loop {
            self.field_idx = (self.field_idx + FORM_FIELDS.len() - 1) % FORM_FIELDS.len();
            if self.field().applies(self.forward) {
                break;
            }
        }
    }

    pub fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.field() {
            FormField::Name => Some(&mut self.name),
            FormField::Group => Some(&mut self.group),
            FormField::SshHost => Some(&mut self.ssh_host),
            FormField::LocalPort => Some(&mut self.local_port),
            FormField::RemoteHost => Some(&mut self.remote_host),
            FormField::RemotePort => Some(&mut self.remote_port),
            FormField::ExtraArgs => Some(&mut self.extra_args),
            FormField::Forward
            | FormField::AutoReconnect
            | FormField::RequiresVpn
            | FormField::DependsOn => None,
        }
    }

    pub fn to_tunnel(&self) -> Result<Tunnel, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".into());
        }
        let ssh_host = self.ssh_host.trim().to_string();
        if ssh_host.is_empty() {
            return Err("ssh host is required".into());
        }
        let local_port: u16 = self
            .local_port
            .trim()
            .parse()
            .map_err(|_| "local port must be a number 1-65535".to_string())?;
        if local_port == 0 {
            return Err("local port must be a number 1-65535".into());
        }
        let remote_host = self.remote_host.trim().to_string();
        let mut remote_port: u16 = 0;
        if self.forward != ForwardType::Dynamic {
            remote_port = self
                .remote_port
                .trim()
                .parse()
                .map_err(|_| "remote port must be a number 1-65535".to_string())?;
            if remote_port == 0 {
                return Err("remote port must be a number 1-65535".into());
            }
            if self.forward == ForwardType::Local && remote_host.is_empty() {
                return Err("remote destination host is required for -L".into());
            }
        }
        Ok(Tunnel {
            name,
            group: self.group.trim().to_string(),
            ssh_host,
            forward: self.forward,
            local_port,
            remote_host,
            remote_port,
            extra_args: self.extra_args.trim().to_string(),
            auto_reconnect: self.auto_reconnect,
            requires_vpn: self.vpn.value(),
            depends_on: self.dep.value(),
        })
    }
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

/// What a [`Picker`] cycles through, which decides how empty and special
/// values are labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Tunnel,
    Vpn,
}

/// Cycling picker used by the forms to link a connection to what it needs:
/// "(none)" plus every configured tunnel, or "(none)", "(any profile)" and
/// every VPN profile.
#[derive(Debug, Clone)]
pub struct Picker {
    pub kind: PickerKind,
    pub options: Vec<String>,
    pub idx: usize,
}

impl Picker {
    /// `exclude` keeps a tunnel from being offered as its own dependency.
    pub fn tunnels(tunnels: &[Tunnel], current: &str, exclude: Option<&str>) -> Self {
        let mut options = vec![String::new()];
        options.extend(
            tunnels
                .iter()
                .map(|t| t.name.clone())
                .filter(|n| Some(n.as_str()) != exclude),
        );
        Self::build(PickerKind::Tunnel, options, current)
    }

    pub fn vpn(profiles: &[Profile], current: &str) -> Self {
        let mut options = vec![String::new(), VPN_ANY.to_string()];
        options.extend(profiles.iter().map(|p| p.name.clone()));
        Self::build(PickerKind::Vpn, options, current)
    }

    fn build(kind: PickerKind, mut options: Vec<String>, current: &str) -> Self {
        // Keep a dangling requirement visible instead of silently dropping it —
        // the tunnel may have been deleted, or the VPN may just be unreachable.
        if !current.is_empty() && !options.iter().any(|o| o == current) {
            options.push(current.to_string());
        }
        let idx = options.iter().position(|o| o == current).unwrap_or(0);
        Self { kind, options, idx }
    }

    pub fn value(&self) -> String {
        self.options.get(self.idx).cloned().unwrap_or_default()
    }

    pub fn label(&self) -> String {
        let v = self.value();
        match (self.kind, v.as_str()) {
            (_, "") => "(none)".into(),
            (PickerKind::Vpn, VPN_ANY) => "(any profile)".into(),
            _ => v,
        }
    }

    pub fn next(&mut self) {
        self.idx = (self.idx + 1) % self.options.len();
    }

    pub fn prev(&mut self) {
        self.idx = (self.idx + self.options.len() - 1) % self.options.len();
    }
}

/// The lists a form needs to build its pickers.
#[derive(Clone, Copy)]
pub struct FormContext<'a> {
    pub tunnels: &'a [Tunnel],
    pub profiles: &'a [Profile],
}

// ---------------------------------------------------------------------------
// RDP form / modal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpField {
    Name,
    Host,
    Port,
    Domain,
    Username,
    ExtraArgs,
    RequiresVpn,
    DependsOn,
}

pub const RDP_FIELDS: &[RdpField] = &[
    RdpField::Name,
    RdpField::Host,
    RdpField::Port,
    RdpField::Domain,
    RdpField::Username,
    RdpField::ExtraArgs,
    RdpField::RequiresVpn,
    RdpField::DependsOn,
];

impl RdpField {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Host => "Host / IP",
            Self::Port => "Port",
            Self::Domain => "Domain (optional)",
            Self::Username => "Username",
            Self::ExtraArgs => "Extra xfreerdp args (optional)",
            Self::RequiresVpn => "Requires VPN",
            Self::DependsOn => "Requires tunnel",
        }
    }

    /// Toggled with ◂ ▸ instead of typed into.
    pub fn is_picker(self) -> bool {
        matches!(self, Self::RequiresVpn | Self::DependsOn)
    }
}

#[derive(Debug, Clone)]
pub struct RdpForm {
    pub field_idx: usize,
    pub name: String,
    pub host: String,
    pub port: String,
    pub domain: String,
    pub username: String,
    pub extra_args: String,
    pub vpn: Picker,
    pub dep: Picker,
    pub error: Option<String>,
}

impl RdpForm {
    pub fn empty(ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: String::new(),
            host: String::new(),
            port: "3389".into(),
            domain: String::new(),
            username: String::new(),
            extra_args: String::new(),
            vpn: Picker::vpn(ctx.profiles, ""),
            dep: Picker::tunnels(ctx.tunnels, "", None),
            error: None,
        }
    }

    pub fn from_connection(c: &RdpConnection, ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: c.name.clone(),
            host: c.host.clone(),
            port: c.port.to_string(),
            domain: c.domain.clone(),
            username: c.username.clone(),
            extra_args: c.extra_args.clone(),
            vpn: Picker::vpn(ctx.profiles, &c.requires_vpn),
            dep: Picker::tunnels(ctx.tunnels, &c.depends_on, None),
            error: None,
        }
    }

    pub fn field(&self) -> RdpField {
        RDP_FIELDS[self.field_idx]
    }

    pub fn next_field(&mut self) {
        self.field_idx = (self.field_idx + 1) % RDP_FIELDS.len();
    }

    pub fn prev_field(&mut self) {
        self.field_idx = (self.field_idx + RDP_FIELDS.len() - 1) % RDP_FIELDS.len();
    }

    pub fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.field() {
            RdpField::Name => Some(&mut self.name),
            RdpField::Host => Some(&mut self.host),
            RdpField::Port => Some(&mut self.port),
            RdpField::Domain => Some(&mut self.domain),
            RdpField::Username => Some(&mut self.username),
            RdpField::ExtraArgs => Some(&mut self.extra_args),
            RdpField::RequiresVpn | RdpField::DependsOn => None,
        }
    }

    pub fn to_connection(&self) -> Result<RdpConnection, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".into());
        }
        let host = self.host.trim().to_string();
        if host.is_empty() {
            return Err("host is required".into());
        }
        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| "port must be a number 1-65535".to_string())?;
        if port == 0 {
            return Err("port must be a number 1-65535".into());
        }
        let username = self.username.trim().to_string();
        if username.is_empty() {
            return Err("username is required".into());
        }
        Ok(RdpConnection {
            name,
            host,
            port,
            domain: self.domain.trim().to_string(),
            username,
            extra_args: self.extra_args.trim().to_string(),
            depends_on: self.dep.value(),
            requires_vpn: self.vpn.value(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpMode {
    None,
    Add,
    Edit(usize),
    DeleteConfirm(usize),
    /// Masked password prompt before connecting to connection `idx`.
    Password { idx: usize, input: String },
    /// Full-screen log view of the selected session.
    Logs,
}

// ---------------------------------------------------------------------------
// SSH host form / modal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshField {
    Name,
    Host,
    Port,
    Username,
    KeyPath,
    Password,
    SkipHostKey,
    RequiresVpn,
    DependsOn,
    ExtraArgs,
}

pub const SSH_FIELDS: &[SshField] = &[
    SshField::Name,
    SshField::Host,
    SshField::Port,
    SshField::Username,
    SshField::KeyPath,
    SshField::Password,
    SshField::SkipHostKey,
    SshField::RequiresVpn,
    SshField::DependsOn,
    SshField::ExtraArgs,
];

impl SshField {
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Host => "Host / IP",
            Self::Port => "Port",
            Self::Username => "Username (optional)",
            Self::KeyPath => "Key file (optional, ~ ok)",
            Self::Password => "Password (optional, cleartext!)",
            Self::SkipHostKey => "Skip host key verification",
            Self::RequiresVpn => "Requires VPN",
            Self::DependsOn => "Requires tunnel",
            Self::ExtraArgs => "Extra ssh args (optional)",
        }
    }

    /// Toggled with ◂ ▸ instead of typed into.
    pub fn is_picker(self) -> bool {
        matches!(self, Self::SkipHostKey | Self::RequiresVpn | Self::DependsOn)
    }
}

#[derive(Debug, Clone)]
pub struct SshForm {
    pub field_idx: usize,
    pub name: String,
    pub host: String,
    pub port: String,
    pub username: String,
    pub key_path: String,
    pub password: String,
    pub skip_host_key_check: bool,
    pub vpn: Picker,
    pub dep: Picker,
    pub extra_args: String,
    pub error: Option<String>,
    /// Set once the user has acknowledged the cleartext-password warning for
    /// this edit, so saving again does not ask twice.
    pub password_ack: bool,
}

impl SshForm {
    pub fn empty(ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: String::new(),
            host: String::new(),
            port: "22".into(),
            username: String::new(),
            key_path: String::new(),
            password: String::new(),
            skip_host_key_check: false,
            vpn: Picker::vpn(ctx.profiles, ""),
            dep: Picker::tunnels(ctx.tunnels, "", None),
            extra_args: String::new(),
            error: None,
            password_ack: false,
        }
    }

    pub fn from_host(h: &SshHost, ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: h.name.clone(),
            host: h.host.clone(),
            port: h.port.to_string(),
            username: h.username.clone(),
            key_path: h.key_path.clone(),
            password: h.password.clone(),
            skip_host_key_check: h.skip_host_key_check,
            vpn: Picker::vpn(ctx.profiles, &h.requires_vpn),
            dep: Picker::tunnels(ctx.tunnels, &h.depends_on, None),
            extra_args: h.extra_args.clone(),
            error: None,
            // Already stored: the warning was accepted when it was first saved.
            password_ack: !h.password.is_empty(),
        }
    }

    pub fn field(&self) -> SshField {
        SSH_FIELDS[self.field_idx]
    }

    pub fn next_field(&mut self) {
        self.field_idx = (self.field_idx + 1) % SSH_FIELDS.len();
    }

    pub fn prev_field(&mut self) {
        self.field_idx = (self.field_idx + SSH_FIELDS.len() - 1) % SSH_FIELDS.len();
    }

    pub fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.field() {
            SshField::Name => Some(&mut self.name),
            SshField::Host => Some(&mut self.host),
            SshField::Port => Some(&mut self.port),
            SshField::Username => Some(&mut self.username),
            SshField::KeyPath => Some(&mut self.key_path),
            SshField::Password => Some(&mut self.password),
            SshField::ExtraArgs => Some(&mut self.extra_args),
            SshField::SkipHostKey | SshField::RequiresVpn | SshField::DependsOn => None,
        }
    }

    pub fn to_host(&self) -> Result<SshHost, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".into());
        }
        let host = self.host.trim().to_string();
        if host.is_empty() {
            return Err("host is required".into());
        }
        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| "port must be a number 1-65535".to_string())?;
        if port == 0 {
            return Err("port must be a number 1-65535".into());
        }
        Ok(SshHost {
            name,
            host,
            port,
            username: self.username.trim().to_string(),
            key_path: self.key_path.trim().to_string(),
            password: self.password.clone(),
            skip_host_key_check: self.skip_host_key_check,
            extra_args: self.extra_args.trim().to_string(),
            depends_on: self.dep.value(),
            requires_vpn: self.vpn.value(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshMode {
    None,
    Add,
    Edit(usize),
    DeleteConfirm(usize),
    /// Cleartext-password warning shown before the form is saved.
    PasswordWarning,
}

// ---------------------------------------------------------------------------
// Activation plans
// ---------------------------------------------------------------------------

/// Follow the tunnel chain from `start` and report the loop if it bites its
/// own tail.
pub fn tunnel_cycle(tunnels: &[Tunnel], start: &str) -> Option<String> {
    let mut seen = vec![start.to_string()];
    let mut current = start.to_string();
    loop {
        let next = tunnels
            .iter()
            .find(|t| t.name == current)
            .map(|t| t.depends_on.clone())
            .unwrap_or_default();
        if next.is_empty() {
            return None;
        }
        let looped = seen.contains(&next);
        seen.push(next.clone());
        if looped {
            return Some(seen.join(" → "));
        }
        current = next;
    }
}

/// One thing to bring up. A plan is an ordered list of these: the VPN first
/// (at most one), then tunnels from the bottom of the stack up, then the
/// connection the user actually asked for.
///
/// Steps carry names rather than indices so that editing a list while a plan
/// is running cannot redirect it at something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Vpn(String),
    Tunnel(String),
    Ssh(String),
    Rdp { name: String, password: String },
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Self::Vpn(p) => format!("vpn {}", vpn_requirement_label(p)),
            Self::Tunnel(n) => format!("tunnel '{n}'"),
            Self::Ssh(n) => format!("ssh '{n}'"),
            Self::Rdp { name, .. } => format!("rdp '{name}'"),
        }
    }

    /// Compact form for the dependency chain shown in the details panels.
    pub fn short(&self) -> String {
        match self {
            Self::Vpn(p) => format!("vpn {}", vpn_requirement_label(p)),
            Self::Tunnel(n) => format!("tun {n}"),
            Self::Ssh(n) => format!("ssh {n}"),
            Self::Rdp { name, .. } => format!("rdp {name}"),
        }
    }

    /// Steps that only fire and forget; everything else is waited on.
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Ssh(_) | Self::Rdp { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StepState {
    Ready,
    Waiting,
    Failed(String),
}

/// What happened when a plan tried to begin a step.
enum StartOutcome {
    /// Under way; the plan now waits for it.
    Started,
    /// Not yet possible for a reason that should pass on its own.
    Retry,
    Failed(String),
}

/// A read-only view of the configured connections, so a plan can be built and
/// tested without the rest of the application state.
#[derive(Clone, Copy)]
pub struct Catalog<'a> {
    pub tunnels: &'a [Tunnel],
    pub ssh_hosts: &'a [SshHost],
    pub rdp_conns: &'a [RdpConnection],
}

impl Catalog<'_> {
    /// What the named connection needs before it can start.
    fn requires_of(&self, step: &Step) -> Requires {
        match step {
            Step::Vpn(_) => Requires::default(),
            Step::Tunnel(n) => self
                .tunnels
                .iter()
                .find(|t| &t.name == n)
                .map(Tunnel::requires)
                .unwrap_or_default(),
            Step::Ssh(n) => self
                .ssh_hosts
                .iter()
                .find(|h| &h.name == n)
                .map(SshHost::requires)
                .unwrap_or_default(),
            Step::Rdp { name, .. } => self
                .rdp_conns
                .iter()
                .find(|c| &c.name == name)
                .map(RdpConnection::requires)
                .unwrap_or_default(),
        }
    }

    /// Fold a new VPN requirement into the one the plan already has. A specific
    /// profile beats "any profile"; two different profiles cannot both hold.
    fn merge_vpn(current: &mut Option<String>, want: &str) -> Result<(), String> {
        if want.is_empty() {
            return Ok(());
        }
        match current.as_deref() {
            None => *current = Some(want.to_string()),
            Some(have) if have == want => {}
            Some(VPN_ANY) => *current = Some(want.to_string()),
            Some(_) if want == VPN_ANY => {}
            Some(have) => {
                return Err(format!(
                    "needs VPN profile '{have}' and '{want}' at the same time"
                ))
            }
        }
        Ok(())
    }

    /// Append the tunnel and everything under it, deepest first.
    fn collect_tunnel(
        &self,
        name: &str,
        steps: &mut Vec<Step>,
        vpn: &mut Option<String>,
        chain: &mut Vec<String>,
    ) -> Result<(), String> {
        if steps.iter().any(|s| s == &Step::Tunnel(name.to_string())) {
            return Ok(());
        }
        if chain.iter().any(|n| n == name) {
            chain.push(name.to_string());
            return Err(format!("dependency cycle: {}", chain.join(" → ")));
        }
        let Some(t) = self.tunnels.iter().find(|t| t.name == name) else {
            return Err(format!("tunnel '{name}' no longer exists"));
        };
        let requires = t.requires();
        Self::merge_vpn(vpn, &requires.vpn)?;
        chain.push(name.to_string());
        if !requires.tunnel.is_empty() {
            self.collect_tunnel(&requires.tunnel, steps, vpn, chain)?;
        }
        chain.pop();
        steps.push(Step::Tunnel(name.to_string()));
        Ok(())
    }

    /// Resolve everything `targets` need into one ordered plan: the VPN first,
    /// then tunnels from the bottom of the stack up, then the targets.
    pub fn build_plan(&self, targets: Vec<Step>) -> Result<Vec<Step>, String> {
        let mut steps: Vec<Step> = Vec::new();
        let mut vpn: Option<String> = None;
        for target in targets {
            let requires = self.requires_of(&target);
            Self::merge_vpn(&mut vpn, &requires.vpn)?;
            if !requires.tunnel.is_empty() {
                let mut chain = match &target {
                    // A tunnel is part of its own chain, so a loop back to it
                    // is caught as a cycle.
                    Step::Tunnel(n) => vec![n.clone()],
                    _ => Vec::new(),
                };
                self.collect_tunnel(&requires.tunnel, &mut steps, &mut vpn, &mut chain)?;
            }
            if !steps.contains(&target) {
                steps.push(target);
            }
        }
        if let Some(profile) = vpn {
            steps.insert(0, Step::Vpn(profile));
        }
        Ok(steps)
    }
}

/// A plan being executed, one step at a time.
pub struct Activation {
    /// Remaining steps, front first. The front stays here until it starts, so
    /// a conflict prompt can hold the plan and retry the same step.
    pub steps: VecDeque<Step>,
    /// Step that was started and is now being waited on.
    pub waiting: Option<(Step, Instant)>,
    /// What the user asked for, for messages.
    pub target: String,
    pub total: usize,
    pub done: usize,
    /// Tunnels this plan started. A later step fighting one of these is a
    /// broken config, not something worth a prompt.
    started: Vec<String>,
}

impl Activation {
    /// "2/4 · tunnel 'bastion'" for the status bar.
    pub fn progress(&self) -> String {
        let current = self
            .waiting
            .as_ref()
            .map(|(s, _)| s.describe())
            .or_else(|| self.steps.front().map(Step::describe))
            .unwrap_or_else(|| "finishing".into());
        format!("{}/{} · {current}", self.done + 1, self.total)
    }
}

/// Something already running that stands in the way of a step, and what
/// accepting the prompt will do about it.
pub struct ConflictPrompt {
    /// The step being held up; retried once the conflict is resolved.
    pub step: Step,
    /// The contested resource, e.g. "local port 5432".
    pub resource: String,
    /// Active tunnels to disconnect on accept.
    pub stop_tunnels: Vec<String>,
    /// Running RDP sessions to disconnect on accept.
    pub stop_rdp: Vec<String>,
    /// Extra explanation, e.g. the profile switch being made.
    pub note: Option<String>,
}

impl ConflictPrompt {
    /// Everything that goes away if the user accepts.
    pub fn blocking(&self) -> Vec<String> {
        let mut all: Vec<String> = self.stop_tunnels.iter().map(|n| format!("tunnel '{n}'")).collect();
        all.extend(self.stop_rdp.iter().map(|n| format!("rdp '{n}'")));
        all
    }
}

// ---------------------------------------------------------------------------
// NetBird state
// ---------------------------------------------------------------------------

pub struct NetbirdView {
    pub installed: bool,
    pub profiles: Vec<Profile>,
    pub status: NbStatus,
    pub selected: usize,
    /// Description of the action currently running in the background.
    pub busy: Option<String>,
    pub error: Option<String>,
    last_refresh: Instant,
}

struct ReconnectState {
    next_at: Instant,
    attempts: u32,
}

pub struct App {
    pub tunnels: Vec<Tunnel>,
    pub active: HashMap<String, ActiveTunnel>,
    pub tab: Tab,
    pub rows: Vec<RowItem>,
    pub selected: usize,
    pub form: TunnelForm,
    pub form_mode: FormMode,
    pub show_help: bool,
    pub theme: Theme,
    pub status_msg: Option<(String, bool, Instant)>,
    pub paths: Paths,
    pub app_config: AppConfig,
    pub throughput_history: VecDeque<u64>,
    pub nb: NetbirdView,
    pub rdp_conns: Vec<RdpConnection>,
    pub rdp_active: HashMap<String, ActiveRdp>,
    pub rdp_selected: usize,
    pub rdp_form: RdpForm,
    pub rdp_mode: RdpMode,
    pub rdp_installed: bool,
    pub ssh_hosts: Vec<SshHost>,
    pub ssh_selected: usize,
    pub ssh_form: SshForm,
    pub ssh_mode: SshMode,
    /// Form state to come back to when the password warning is dismissed.
    ssh_return_mode: SshMode,
    pub sshpass_installed: bool,
    /// Outcome of the last finished interactive session, by host name.
    pub ssh_last: HashMap<String, SessionOutcome>,
    /// Plan currently being executed, if any.
    pub activation: Option<Activation>,
    /// Tunnel-binding conflict awaiting the user's decision.
    pub conflict: Option<ConflictPrompt>,
    /// Name of the host cleared to run; the main loop owns the terminal and
    /// hands it to ssh.
    ssh_launch: Option<String>,
    nb_tx: Sender<NbMsg>,
    nb_rx: Receiver<NbMsg>,
    reconnect: HashMap<String, ReconnectState>,
    last_tick: Instant,
    should_quit: bool,
}

impl App {
    pub fn new(
        tunnels: Vec<Tunnel>,
        rdp_conns: Vec<RdpConnection>,
        ssh_hosts: Vec<SshHost>,
        paths: Paths,
        app_config: AppConfig,
    ) -> Self {
        let theme = theme::by_name(&app_config.ui.theme);
        let (nb_tx, nb_rx) = channel();
        let nb_installed = netbird::installed();
        if nb_installed {
            netbird::refresh(nb_tx.clone());
        }
        let empty_ctx = FormContext {
            tunnels: &tunnels,
            profiles: &[],
        };
        let ssh_form = SshForm::empty(empty_ctx);
        let rdp_form = RdpForm::empty(empty_ctx);
        let tunnel_form = TunnelForm::empty(empty_ctx);
        let mut app = Self {
            tunnels,
            active: HashMap::new(),
            tab: Tab::Dashboard,
            rows: Vec::new(),
            selected: 0,
            form: tunnel_form,
            form_mode: FormMode::None,
            show_help: false,
            theme,
            status_msg: None,
            paths,
            app_config,
            throughput_history: VecDeque::with_capacity(THROUGHPUT_HISTORY),
            nb: NetbirdView {
                installed: nb_installed,
                profiles: Vec::new(),
                status: NbStatus::default(),
                selected: 0,
                busy: None,
                error: None,
                last_refresh: Instant::now(),
            },
            rdp_conns,
            rdp_active: HashMap::new(),
            rdp_selected: 0,
            rdp_form,
            rdp_mode: RdpMode::None,
            rdp_installed: rdp::installed(),
            ssh_hosts,
            ssh_selected: 0,
            ssh_form,
            ssh_mode: SshMode::None,
            ssh_return_mode: SshMode::None,
            sshpass_installed: ssh::sshpass_available(),
            ssh_last: HashMap::new(),
            activation: None,
            conflict: None,
            ssh_launch: None,
            nb_tx,
            nb_rx,
            reconnect: HashMap::new(),
            last_tick: Instant::now(),
            should_quit: false,
        };
        app.rebuild_rows();
        app
    }

    pub fn run(mut self, terminal: &mut Tui) -> Result<()> {
        let tick_rate = Duration::from_millis(1000);
        loop {
            terminal.draw(|f| ui::render(f, &self))?;

            let timeout = tick_rate
                .checked_sub(self.last_tick.elapsed())
                .unwrap_or(Duration::ZERO);
            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.on_key(key);
                    }
                }
            }
            if self.last_tick.elapsed() >= tick_rate {
                self.on_tick();
                self.last_tick = Instant::now();
            }
            // An interactive ssh session needs the terminal to itself.
            if let Some(name) = self.ssh_launch.take() {
                self.run_ssh_session(terminal, &name)?;
                self.last_tick = Instant::now();
            }
            if self.should_quit {
                break;
            }
        }
        for (_, mut t) in self.active.drain() {
            t.stop();
        }
        // RDP sessions are user-facing windows; leave them running on quit.
        Ok(())
    }

    /// Sorted names of active tunnels, as listed on the Dashboard.
    pub fn active_tunnel_names(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self.active.keys().collect();
        names.sort();
        names
    }

    /// Sorted names of RDP sessions (running or recently exited).
    pub fn rdp_session_names(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self.rdp_active.keys().collect();
        names.sort();
        names
    }

    /// Lists the forms use to populate their requirement pickers.
    fn form_ctx(&self) -> FormContext<'_> {
        FormContext {
            tunnels: &self.tunnels,
            profiles: &self.nb.profiles,
        }
    }

    pub fn rebuild_rows(&mut self) {
        self.rows.clear();
        // Ungrouped tunnels first, then groups in order of first appearance.
        for (i, t) in self.tunnels.iter().enumerate() {
            if t.group.is_empty() {
                self.rows.push(RowItem::Tunnel(i));
            }
        }
        let mut groups: Vec<String> = Vec::new();
        for t in &self.tunnels {
            if !t.group.is_empty() && !groups.contains(&t.group) {
                groups.push(t.group.clone());
            }
        }
        for g in groups {
            self.rows.push(RowItem::Group(g.clone()));
            for (i, t) in self.tunnels.iter().enumerate() {
                if t.group == g {
                    self.rows.push(RowItem::Tunnel(i));
                }
            }
        }
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
    }

    pub fn group_members(&self, group: &str) -> Vec<usize> {
        self.tunnels
            .iter()
            .enumerate()
            .filter(|(_, t)| t.group == group)
            .map(|(i, _)| i)
            .collect()
    }

    fn flash(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status_msg = Some((msg.into(), is_error, Instant::now()));
    }

    fn on_key(&mut self, key: KeyEvent) {
        if self.show_help {
            self.show_help = false;
            return;
        }
        // The conflict prompt is modal over everything: it holds a tunnel start.
        if self.conflict.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.resolve_conflict(true)
                }
                _ => self.resolve_conflict(false),
            }
            return;
        }
        match self.form_mode.clone() {
            FormMode::Add | FormMode::Edit(_) => {
                self.on_form_key(key);
                return;
            }
            FormMode::DeleteConfirm(idx) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        self.delete_tunnel(idx);
                        self.form_mode = FormMode::None;
                    }
                    _ => self.form_mode = FormMode::None,
                }
                return;
            }
            FormMode::None => {}
        }
        if self.rdp_mode != RdpMode::None {
            self.on_rdp_modal_key(key);
            return;
        }
        if self.ssh_mode != SshMode::None {
            self.on_ssh_modal_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('t') => {
                self.theme = theme::next(self.theme.name);
                self.app_config.ui.theme = self.theme.name.to_string();
                let _ = config::save_app_config(&self.paths.config_file, &self.app_config);
            }
            KeyCode::Char('1') => self.tab = Tab::Dashboard,
            KeyCode::Char('2') => self.tab = Tab::Vpn,
            KeyCode::Char('3') => self.tab = Tab::Tunnels,
            KeyCode::Char('4') => self.tab = Tab::Ssh,
            KeyCode::Char('5') => self.tab = Tab::Rdp,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            _ => match self.tab {
                Tab::Dashboard => {}
                Tab::Vpn => self.on_netbird_key(key),
                Tab::Tunnels => self.on_tunnels_key(key),
                Tab::Ssh => self.on_ssh_key(key),
                Tab::Rdp => self.on_rdp_key(key),
            },
        }
    }

    fn on_tunnels_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j')
                if !self.rows.is_empty() => {
                    self.selected = (self.selected + 1) % self.rows.len();
                }
            KeyCode::Up | KeyCode::Char('k')
                if !self.rows.is_empty() => {
                    self.selected = (self.selected + self.rows.len() - 1) % self.rows.len();
                }
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_selected(),
            KeyCode::Char('a') => {
                let form = TunnelForm::empty(self.form_ctx());
                self.form = form;
                // Pre-fill the group when a group row or grouped tunnel is selected.
                match self.rows.get(self.selected) {
                    Some(RowItem::Group(g)) => self.form.group = g.clone(),
                    Some(RowItem::Tunnel(i)) => {
                        self.form.group = self.tunnels[*i].group.clone()
                    }
                    None => {}
                }
                self.form_mode = FormMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(RowItem::Tunnel(i)) = self.rows.get(self.selected) {
                    let form = TunnelForm::from_tunnel(&self.tunnels[*i], self.form_ctx());
                    self.form = form;
                    self.form_mode = FormMode::Edit(*i);
                }
            }
            KeyCode::Char('d') => {
                if let Some(RowItem::Tunnel(i)) = self.rows.get(self.selected) {
                    self.form_mode = FormMode::DeleteConfirm(*i);
                }
            }
            KeyCode::Char('r') => {
                if let Some(RowItem::Tunnel(i)) = self.rows.get(self.selected).cloned() {
                    let name = self.tunnels[i].name.clone();
                    if self.active.contains_key(&name) {
                        self.stop_tunnel(&name);
                        self.start_tunnel(i);
                        self.flash(format!("restarted '{name}'"), false);
                    }
                }
            }
            KeyCode::Char('x') => self.stop_all(),
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // NetBird
    // -----------------------------------------------------------------------

    fn on_netbird_key(&mut self, key: KeyEvent) {
        if !self.nb.installed {
            return;
        }
        let count = self.nb.profiles.len();
        match key.code {
            KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                self.nb.selected = (self.nb.selected + 1) % count;
            }
            KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                self.nb.selected = (self.nb.selected + count - 1) % count;
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(p) = self.nb.profiles.get(self.nb.selected).cloned() {
                    self.netbird_action(
                        format!("switching to profile '{}'", p.name),
                        vec![
                            vec!["profile".into(), "select".into(), p.name.clone()],
                            vec!["up".into()],
                        ],
                    );
                }
            }
            KeyCode::Char('u') => {
                self.netbird_action("connecting".into(), vec![vec!["up".into()]]);
            }
            KeyCode::Char('d') => {
                self.netbird_action("disconnecting".into(), vec![vec!["down".into()]]);
            }
            KeyCode::Char('r') => {
                self.nb.error = None;
                netbird::refresh(self.nb_tx.clone());
                self.flash("refreshing netbird status", false);
            }
            _ => {}
        }
    }

    fn netbird_action(&mut self, desc: String, cmds: Vec<Vec<String>>) {
        if let Some(busy) = &self.nb.busy {
            self.flash(format!("netbird is busy ({busy})"), true);
            return;
        }
        self.nb.error = None;
        self.nb.busy = Some(desc.clone());
        self.flash(format!("netbird: {desc}…"), false);
        netbird::action(self.nb_tx.clone(), desc, cmds);
    }

    // -----------------------------------------------------------------------
    // RDP
    // -----------------------------------------------------------------------

    fn on_rdp_key(&mut self, key: KeyEvent) {
        let count = self.rdp_conns.len();
        match key.code {
            KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                self.rdp_selected = (self.rdp_selected + 1) % count;
            }
            KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                self.rdp_selected = (self.rdp_selected + count - 1) % count;
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let Some(conn) = self.rdp_conns.get(self.rdp_selected) else {
                    return;
                };
                let name = conn.name.clone();
                match self.rdp_active.get(&name).map(|a| a.status) {
                    Some(RdpStatus::Running) => {
                        if let Some(mut a) = self.rdp_active.remove(&name) {
                            a.stop();
                        }
                        self.flash(format!("disconnected '{name}'"), false);
                    }
                    Some(RdpStatus::Exited(_)) | None => {
                        if !self.rdp_installed {
                            self.flash("xfreerdp3 not found on PATH", true);
                            return;
                        }
                        self.rdp_mode = RdpMode::Password {
                            idx: self.rdp_selected,
                            input: String::new(),
                        };
                    }
                }
            }
            KeyCode::Char('a') => {
                let form = RdpForm::empty(self.form_ctx());
                self.rdp_form = form;
                self.rdp_mode = RdpMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(c) = self.rdp_conns.get(self.rdp_selected) {
                    let form = RdpForm::from_connection(c, self.form_ctx());
                    self.rdp_form = form;
                    self.rdp_mode = RdpMode::Edit(self.rdp_selected);
                }
            }
            KeyCode::Char('d') => {
                if self.rdp_selected < count {
                    self.rdp_mode = RdpMode::DeleteConfirm(self.rdp_selected);
                }
            }
            KeyCode::Char('l') => {
                if let Some(c) = self.rdp_conns.get(self.rdp_selected) {
                    if self.rdp_active.contains_key(&c.name) {
                        self.rdp_mode = RdpMode::Logs;
                    } else {
                        self.flash("no session (and no logs) for this connection", true);
                    }
                }
            }
            KeyCode::Char('c') => {
                // Clear a finished session entry (keeps running ones).
                if let Some(c) = self.rdp_conns.get(self.rdp_selected) {
                    let name = c.name.clone();
                    if matches!(
                        self.rdp_active.get(&name).map(|a| a.status),
                        Some(RdpStatus::Exited(_))
                    ) {
                        self.rdp_active.remove(&name);
                    }
                }
            }
            KeyCode::Char('x') => {
                let names: Vec<String> = self.rdp_active.keys().cloned().collect();
                for name in &names {
                    if let Some(mut a) = self.rdp_active.remove(name) {
                        a.stop();
                    }
                }
                if !names.is_empty() {
                    self.flash(format!("closed {} RDP session(s)", names.len()), false);
                }
            }
            _ => {}
        }
    }

    fn on_rdp_modal_key(&mut self, key: KeyEvent) {
        match self.rdp_mode.clone() {
            RdpMode::None => {}
            RdpMode::Add | RdpMode::Edit(_) => match key.code {
                KeyCode::Esc => self.rdp_mode = RdpMode::None,
                KeyCode::Enter => self.submit_rdp_form(),
                KeyCode::Tab | KeyCode::Down => self.rdp_form.next_field(),
                KeyCode::BackTab | KeyCode::Up => self.rdp_form.prev_field(),
                KeyCode::Left | KeyCode::Right if self.rdp_form.field().is_picker() => {
                    self.cycle_rdp_picker(key.code == KeyCode::Right);
                }
                KeyCode::Backspace => {
                    if let Some(text) = self.rdp_form.active_text_mut() {
                        text.pop();
                    }
                }
                KeyCode::Char(c) => match self.rdp_form.active_text_mut() {
                    Some(text) => text.push(c),
                    None => self.cycle_rdp_picker(true),
                },
                _ => {}
            },
            RdpMode::DeleteConfirm(idx) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        self.delete_rdp(idx);
                    }
                    _ => {}
                }
                self.rdp_mode = RdpMode::None;
            }
            RdpMode::Password { idx, mut input } => match key.code {
                KeyCode::Esc => self.rdp_mode = RdpMode::None,
                KeyCode::Enter => {
                    self.rdp_mode = RdpMode::None;
                    if let Some(c) = self.rdp_conns.get(idx) {
                        let step = Step::Rdp {
                            name: c.name.clone(),
                            password: input.clone(),
                        };
                        self.activate(vec![step]);
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.rdp_mode = RdpMode::Password { idx, input };
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    self.rdp_mode = RdpMode::Password { idx, input };
                }
                _ => {}
            },
            RdpMode::Logs => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('l') => {
                    self.rdp_mode = RdpMode::None;
                }
                _ => {}
            },
        }
    }

    fn cycle_rdp_picker(&mut self, forward: bool) {
        let picker = match self.rdp_form.field() {
            RdpField::RequiresVpn => &mut self.rdp_form.vpn,
            RdpField::DependsOn => &mut self.rdp_form.dep,
            _ => return,
        };
        if forward {
            picker.next()
        } else {
            picker.prev()
        }
    }

    fn spawn_rdp(&mut self, name: &str, password: &str) {
        let Some(conn) = self.rdp_conns.iter().find(|c| c.name == name).cloned() else {
            self.flash(format!("rdp connection '{name}' is gone"), true);
            return;
        };
        // Replace a finished session entry with the fresh one.
        if let Some(mut old) = self.rdp_active.remove(&conn.name) {
            old.stop();
        }
        match rdp::spawn(&conn, password) {
            Ok(active) => {
                self.rdp_active.insert(conn.name.clone(), active);
                self.flash(format!("connecting to '{}'", conn.name), false);
            }
            Err(e) => self.flash(format!("'{}': {e:#}", conn.name), true),
        }
    }

    fn submit_rdp_form(&mut self) {
        let conn = match self.rdp_form.to_connection() {
            Ok(c) => c,
            Err(e) => {
                self.rdp_form.error = Some(e);
                return;
            }
        };
        let editing = match &self.rdp_mode {
            RdpMode::Edit(i) => Some(*i),
            _ => None,
        };
        let duplicate = self
            .rdp_conns
            .iter()
            .enumerate()
            .any(|(i, c)| c.name == conn.name && Some(i) != editing);
        if duplicate {
            self.rdp_form.error =
                Some(format!("a connection named '{}' already exists", conn.name));
            return;
        }
        match editing {
            Some(i) => {
                let old_name = self.rdp_conns[i].name.clone();
                if let Some(mut a) = self.rdp_active.remove(&old_name) {
                    a.stop();
                    self.flash("session closed — press Enter to reconnect with new settings", false);
                }
                self.rdp_conns[i] = conn;
            }
            None => self.rdp_conns.push(conn),
        }
        self.rdp_mode = RdpMode::None;
        if self.rdp_selected >= self.rdp_conns.len() {
            self.rdp_selected = self.rdp_conns.len().saturating_sub(1);
        }
        if let Err(e) = config::save_rdp(&self.paths.rdp_file, &self.rdp_conns) {
            self.flash(format!("save failed: {e}"), true);
        }
    }

    fn delete_rdp(&mut self, idx: usize) {
        if idx >= self.rdp_conns.len() {
            return;
        }
        let name = self.rdp_conns[idx].name.clone();
        if let Some(mut a) = self.rdp_active.remove(&name) {
            a.stop();
        }
        self.rdp_conns.remove(idx);
        if self.rdp_selected >= self.rdp_conns.len() {
            self.rdp_selected = self.rdp_conns.len().saturating_sub(1);
        }
        if let Err(e) = config::save_rdp(&self.paths.rdp_file, &self.rdp_conns) {
            self.flash(format!("save failed: {e}"), true);
        } else {
            self.flash(format!("deleted '{name}'"), false);
        }
    }

    // -----------------------------------------------------------------------
    // SSH hosts
    // -----------------------------------------------------------------------

    fn on_ssh_key(&mut self, key: KeyEvent) {
        let count = self.ssh_hosts.len();
        match key.code {
            KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                self.ssh_selected = (self.ssh_selected + 1) % count;
            }
            KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                self.ssh_selected = (self.ssh_selected + count - 1) % count;
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(h) = self.ssh_hosts.get(self.ssh_selected) {
                    let step = Step::Ssh(h.name.clone());
                    self.activate(vec![step]);
                }
            }
            KeyCode::Char('a') => {
                let form = SshForm::empty(self.form_ctx());
                self.ssh_form = form;
                self.ssh_mode = SshMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(h) = self.ssh_hosts.get(self.ssh_selected) {
                    let form = SshForm::from_host(h, self.form_ctx());
                    self.ssh_form = form;
                    self.ssh_mode = SshMode::Edit(self.ssh_selected);
                }
            }
            KeyCode::Char('d') => {
                if self.ssh_selected < count {
                    self.ssh_mode = SshMode::DeleteConfirm(self.ssh_selected);
                }
            }
            KeyCode::Char('p') => self.clear_stored_password(),
            _ => {}
        }
    }

    fn on_ssh_modal_key(&mut self, key: KeyEvent) {
        match self.ssh_mode.clone() {
            SshMode::None => {}
            SshMode::Add | SshMode::Edit(_) => match key.code {
                KeyCode::Esc => self.ssh_mode = SshMode::None,
                KeyCode::Enter => self.submit_ssh_form(),
                KeyCode::Tab | KeyCode::Down => self.ssh_form.next_field(),
                KeyCode::BackTab | KeyCode::Up => self.ssh_form.prev_field(),
                KeyCode::Left | KeyCode::Right if self.ssh_form.field().is_picker() => {
                    self.cycle_ssh_picker(key.code == KeyCode::Right);
                }
                KeyCode::Backspace => {
                    if let Some(text) = self.ssh_form.active_text_mut() {
                        text.pop();
                    }
                }
                KeyCode::Char(c) => match self.ssh_form.active_text_mut() {
                    Some(text) => text.push(c),
                    None => self.cycle_ssh_picker(true),
                },
                _ => {}
            },
            SshMode::DeleteConfirm(idx) => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        self.delete_ssh(idx)
                    }
                    _ => {}
                }
                self.ssh_mode = SshMode::None;
            }
            SshMode::PasswordWarning => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.ssh_form.password_ack = true;
                    self.ssh_mode = self.ssh_return_mode.clone();
                    self.submit_ssh_form();
                }
                _ => {
                    // Back to the form so the password can be cleared.
                    self.ssh_mode = self.ssh_return_mode.clone();
                }
            },
        }
    }

    fn cycle_ssh_picker(&mut self, forward: bool) {
        match self.ssh_form.field() {
            SshField::SkipHostKey => {
                self.ssh_form.skip_host_key_check = !self.ssh_form.skip_host_key_check
            }
            SshField::RequiresVpn => {
                if forward {
                    self.ssh_form.vpn.next()
                } else {
                    self.ssh_form.vpn.prev()
                }
            }
            SshField::DependsOn => {
                if forward {
                    self.ssh_form.dep.next()
                } else {
                    self.ssh_form.dep.prev()
                }
            }
            _ => {}
        }
    }

    fn submit_ssh_form(&mut self) {
        let host = match self.ssh_form.to_host() {
            Ok(h) => h,
            Err(e) => {
                self.ssh_form.error = Some(e);
                return;
            }
        };
        let editing = match &self.ssh_mode {
            SshMode::Edit(i) => Some(*i),
            _ => None,
        };
        let duplicate = self
            .ssh_hosts
            .iter()
            .enumerate()
            .any(|(i, h)| h.name == host.name && Some(i) != editing);
        if duplicate {
            self.ssh_form.error = Some(format!("a host named '{}' already exists", host.name));
            return;
        }
        // Storing a password writes it to disk in the clear; make the user say so.
        if !host.password.is_empty() && !self.ssh_form.password_ack {
            self.ssh_return_mode = self.ssh_mode.clone();
            self.ssh_mode = SshMode::PasswordWarning;
            return;
        }
        match editing {
            Some(i) => self.ssh_hosts[i] = host,
            None => self.ssh_hosts.push(host),
        }
        self.ssh_mode = SshMode::None;
        if self.ssh_selected >= self.ssh_hosts.len() {
            self.ssh_selected = self.ssh_hosts.len().saturating_sub(1);
        }
        self.save_ssh_hosts();
    }

    fn delete_ssh(&mut self, idx: usize) {
        if idx >= self.ssh_hosts.len() {
            return;
        }
        let name = self.ssh_hosts[idx].name.clone();
        self.ssh_last.remove(&name);
        self.ssh_hosts.remove(idx);
        if self.ssh_selected >= self.ssh_hosts.len() {
            self.ssh_selected = self.ssh_hosts.len().saturating_sub(1);
        }
        self.save_ssh_hosts();
        self.flash(format!("deleted '{name}'"), false);
    }

    /// Drop a stored cleartext password without opening the form.
    fn clear_stored_password(&mut self) {
        let Some(h) = self.ssh_hosts.get_mut(self.ssh_selected) else {
            return;
        };
        if h.password.is_empty() {
            self.flash("no password stored for this host", false);
            return;
        }
        h.password.clear();
        let name = h.name.clone();
        self.save_ssh_hosts();
        self.flash(format!("cleared stored password for '{name}'"), false);
    }

    fn save_ssh_hosts(&mut self) {
        if let Err(e) = config::save_ssh(&self.paths.ssh_file, &self.ssh_hosts) {
            self.flash(format!("save failed: {e}"), true);
        }
    }

    /// Hand the terminal to ssh for the length of the session, then take it back.
    fn run_ssh_session(&mut self, terminal: &mut Tui, name: &str) -> Result<()> {
        let Some(host) = self.ssh_hosts.iter().find(|h| h.name == name).cloned() else {
            return Ok(());
        };
        if !host.password.is_empty() && !self.sshpass_installed {
            self.flash(
                format!("'{}' has a stored password but sshpass is not on PATH", host.name),
                true,
            );
            return Ok(());
        }

        crate::suspend_terminal(terminal)?;
        println!("── controlcenter: {} ──", ssh::command_preview(&host));
        let result = ssh::run_interactive(&host);
        crate::resume_terminal(terminal)?;

        match result {
            Ok(outcome) => {
                let msg = format!("'{}' session {}", host.name, outcome.label());
                self.ssh_last.insert(host.name.clone(), outcome);
                self.flash(msg, outcome.code != 0);
            }
            Err(e) => self.flash(format!("'{}': {e:#}", host.name), true),
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Dependency plans
    // -----------------------------------------------------------------------

    /// A read-only view of everything the plan builder needs.
    fn catalog(&self) -> Catalog<'_> {
        Catalog {
            tunnels: &self.tunnels,
            ssh_hosts: &self.ssh_hosts,
            rdp_conns: &self.rdp_conns,
        }
    }

    /// The chain a connection would run through, for the details panels.
    pub fn chain_of(&self, step: Step) -> Result<Vec<String>, String> {
        Ok(self
            .catalog()
            .build_plan(vec![step])?
            .iter()
            .map(Step::short)
            .collect())
    }

    /// Start a plan for the given targets, or report why it cannot be built.
    fn activate(&mut self, targets: Vec<Step>) {
        if let Some(act) = &self.activation {
            self.flash(
                format!("busy: {} ({})", act.target, act.progress()),
                true,
            );
            return;
        }
        let target = match targets.as_slice() {
            [one] => one.describe(),
            many => format!("{} connections", many.len()),
        };
        let steps = match self.catalog().build_plan(targets) {
            Ok(s) => s,
            Err(e) => {
                self.flash(format!("{target}: {e}"), true);
                return;
            }
        };
        self.activation = Some(Activation {
            total: steps.len(),
            steps: steps.into(),
            waiting: None,
            target,
            done: 0,
            started: Vec::new(),
        });
        self.advance_activation();
    }

    // -----------------------------------------------------------------------
    // Running a plan
    // -----------------------------------------------------------------------

    /// The active VPN profile as netbird reports it.
    pub fn active_vpn_profile(&self) -> Option<String> {
        self.nb
            .status
            .field("Profile")
            .map(str::to_string)
            .or_else(|| {
                self.nb
                    .profiles
                    .iter()
                    .find(|p| p.active)
                    .map(|p| p.name.clone())
            })
    }

    /// Whether the VPN already satisfies the requirement.
    pub fn vpn_satisfied(&self, want: &str) -> bool {
        if want.is_empty() {
            return true;
        }
        if !self.nb.status.connected {
            return false;
        }
        want == VPN_ANY || self.active_vpn_profile().as_deref() == Some(want)
    }

    fn step_state(&self, step: &Step) -> StepState {
        match step {
            Step::Vpn(profile) => {
                if self.vpn_satisfied(profile) {
                    StepState::Ready
                } else if !self.nb.installed {
                    StepState::Failed("netbird is not installed".into())
                } else if let Some(e) = &self.nb.error {
                    StepState::Failed(e.clone())
                } else {
                    StepState::Waiting
                }
            }
            Step::Tunnel(name) => match self.active.get(name) {
                Some(a) => match a.status {
                    Status::Up => StepState::Ready,
                    Status::Connecting => StepState::Waiting,
                    Status::Failed => StepState::Failed(
                        a.error.clone().unwrap_or_else(|| "tunnel failed".into()),
                    ),
                },
                None => StepState::Waiting,
            },
            // Terminal steps are never waited on.
            Step::Ssh(_) | Step::Rdp { .. } => StepState::Ready,
        }
    }

    /// How long a step may take before the plan gives up. `netbird up` can sit
    /// through a login, so it gets much longer than an ssh forward.
    fn step_timeout(step: &Step) -> Duration {
        match step {
            Step::Vpn(_) => VPN_TIMEOUT,
            _ => DEPENDENCY_TIMEOUT,
        }
    }

    /// Begin a step.
    fn start_step(&mut self, step: &Step) -> StartOutcome {
        match step {
            Step::Vpn(profile) => {
                if !self.nb.installed {
                    return StartOutcome::Failed("netbird is not installed".into());
                }
                if self.nb.busy.is_some() {
                    // Another netbird action is still running; try again next tick.
                    return StartOutcome::Retry;
                }
                self.nb.error = None;
                let cmds = if profile == VPN_ANY {
                    vec![vec!["up".to_string()]]
                } else {
                    vec![
                        vec!["profile".into(), "select".into(), profile.clone()],
                        vec!["up".into()],
                    ]
                };
                let desc = match profile.as_str() {
                    VPN_ANY => "connecting".to_string(),
                    p => format!("switching to profile '{p}'"),
                };
                self.nb.busy = Some(desc.clone());
                netbird::action(self.nb_tx.clone(), desc, cmds);
                StartOutcome::Started
            }
            Step::Tunnel(name) => {
                let Some(idx) = self.tunnels.iter().position(|t| t.name == *name) else {
                    return StartOutcome::Failed(format!("tunnel '{name}' no longer exists"));
                };
                // A dead tunnel is replaced rather than waited on.
                if matches!(
                    self.active.get(name).map(|a| a.status),
                    Some(Status::Failed)
                ) {
                    self.stop_tunnel(name);
                }
                self.start_tunnel(idx);
                if !self.active.contains_key(name) {
                    // start_tunnel already flashed the reason (usually a bind error).
                    return StartOutcome::Failed(format!("tunnel '{name}' could not be started"));
                }
                if let Some(act) = &mut self.activation {
                    act.started.push(name.clone());
                }
                StartOutcome::Started
            }
            Step::Ssh(name) => {
                if self.ssh_hosts.iter().any(|h| &h.name == name) {
                    self.ssh_launch = Some(name.clone());
                    StartOutcome::Started
                } else {
                    StartOutcome::Failed(format!("ssh host '{name}' is gone"))
                }
            }
            Step::Rdp { name, password } => {
                self.spawn_rdp(&name.clone(), &password.clone());
                StartOutcome::Started
            }
        }
    }

    /// Whatever is already running that this step cannot coexist with.
    fn step_conflict(&self, step: &Step) -> Option<ConflictPrompt> {
        match step {
            Step::Vpn(profile) if profile != VPN_ANY => {
                let current = self.active_vpn_profile()?;
                if &current == profile {
                    return None;
                }
                // Switching profiles cuts anything that asked for the old one.
                let stop_tunnels: Vec<String> = self
                    .tunnels
                    .iter()
                    .filter(|t| t.requires_vpn == current && self.active.contains_key(&t.name))
                    .map(|t| t.name.clone())
                    .collect();
                let stop_rdp: Vec<String> = self
                    .rdp_conns
                    .iter()
                    .filter(|c| c.requires_vpn == current && self.rdp_running(&c.name))
                    .map(|c| c.name.clone())
                    .collect();
                Some(ConflictPrompt {
                    step: step.clone(),
                    resource: "the active VPN profile".into(),
                    stop_tunnels,
                    stop_rdp,
                    note: Some(format!("netbird profile '{current}' → '{profile}'")),
                })
            }
            Step::Vpn(_) => None,
            Step::Tunnel(name) => {
                let idx = self.tunnels.iter().position(|t| &t.name == name)?;
                let (conflicting, binding) = self.conflicting_active(idx);
                if conflicting.is_empty() {
                    return None;
                }
                Some(ConflictPrompt {
                    step: step.clone(),
                    resource: binding,
                    stop_tunnels: conflicting,
                    stop_rdp: Vec::new(),
                    note: None,
                })
            }
            Step::Rdp { name, .. } => {
                let conn = self.rdp_conns.iter().find(|c| &c.name == name)?;
                let target = conn.target_summary();
                // A second session to the same machine normally throws the
                // first one off, so make that the user's choice.
                let stop_rdp: Vec<String> = self
                    .rdp_conns
                    .iter()
                    .filter(|c| {
                        &c.name != name && c.target_summary() == target && self.rdp_running(&c.name)
                    })
                    .map(|c| c.name.clone())
                    .collect();
                if stop_rdp.is_empty() {
                    return None;
                }
                Some(ConflictPrompt {
                    step: step.clone(),
                    resource: target,
                    stop_tunnels: Vec::new(),
                    stop_rdp,
                    note: None,
                })
            }
            Step::Ssh(_) => None,
        }
    }

    pub fn rdp_running(&self, name: &str) -> bool {
        matches!(
            self.rdp_active.get(name).map(|a| a.status),
            Some(RdpStatus::Running)
        )
    }

    /// Active tunnels that bind the same endpoint as tunnel `idx`.
    pub fn conflicting_active(&self, idx: usize) -> (Vec<String>, String) {
        let Some(t) = self.tunnels.get(idx) else {
            return (Vec::new(), String::new());
        };
        let mut names = Vec::new();
        let mut binding = String::new();
        for (i, other) in self.tunnels.iter().enumerate() {
            if i == idx || !self.active.contains_key(&other.name) {
                continue;
            }
            if let Some(b) = tunnel_conflict(t, other) {
                binding = b;
                names.push(other.name.clone());
            }
        }
        (names, binding)
    }

    /// Drive the plan as far as it will go without blocking.
    fn advance_activation(&mut self) {
        if self.conflict.is_some() {
            return;
        }
        let Some(mut act) = self.activation.take() else {
            return;
        };
        loop {
            // Waiting on a step that has already been started.
            if let Some((step, since)) = act.waiting.clone() {
                match self.step_state(&step) {
                    StepState::Ready => {
                        act.waiting = None;
                        act.done += 1;
                    }
                    StepState::Waiting if since.elapsed() < Self::step_timeout(&step) => {
                        self.activation = Some(act);
                        return;
                    }
                    StepState::Waiting => {
                        let msg = format!("{}: {} timed out", act.target, step.describe());
                        self.flash(msg, true);
                        return;
                    }
                    StepState::Failed(why) => {
                        let msg = format!("{}: {} failed — {why}", act.target, step.describe());
                        self.flash(msg, true);
                        return;
                    }
                }
                continue;
            }

            let Some(step) = act.steps.front().cloned() else {
                let msg = format!("{} started", act.target);
                self.flash(msg, false);
                return;
            };

            if !step.is_terminal() && self.step_state(&step) == StepState::Ready {
                act.steps.pop_front();
                act.done += 1;
                continue;
            }

            if let Some(prompt) = self.step_conflict(&step) {
                // Two steps of one plan fighting each other is a broken config;
                // say so and move on instead of asking to undo our own work.
                let self_inflicted = prompt
                    .stop_tunnels
                    .iter()
                    .all(|n| act.started.contains(n))
                    && prompt.stop_rdp.is_empty()
                    && !prompt.stop_tunnels.is_empty();
                if self_inflicted {
                    let msg = format!(
                        "skipped {}: {} already held by {}",
                        step.describe(),
                        prompt.resource,
                        prompt.stop_tunnels.join(", ")
                    );
                    self.flash(msg, true);
                    act.steps.pop_front();
                    act.done += 1;
                    continue;
                }
                self.activation = Some(act);
                self.conflict = Some(prompt);
                return;
            }

            self.activation = Some(act);
            let outcome = self.start_step(&step);
            act = self.activation.take().expect("start_step keeps the plan");
            match outcome {
                StartOutcome::Started => {
                    act.steps.pop_front();
                    if step.is_terminal() {
                        act.done += 1;
                    } else {
                        act.waiting = Some((step, Instant::now()));
                    }
                }
                StartOutcome::Retry => {
                    // Leave the step at the front for the next tick.
                    self.activation = Some(act);
                    return;
                }
                StartOutcome::Failed(why) => {
                    let msg = format!("{}: {why}", act.target);
                    self.flash(msg, true);
                    return;
                }
            }
        }
    }

    /// Accept or refuse the conflict prompt; accepting resumes the plan.
    fn resolve_conflict(&mut self, accept: bool) {
        let Some(c) = self.conflict.take() else {
            return;
        };
        if !accept {
            self.activation = None;
            let blocking = c.blocking();
            let detail = if blocking.is_empty() {
                String::new()
            } else {
                format!(" — {} stays", blocking.join(", "))
            };
            self.flash(format!("{} cancelled{detail}", c.step.describe()), true);
            return;
        }
        let mut evicted = c.blocking();
        for name in &c.stop_tunnels {
            self.stop_tunnel(name);
        }
        for name in &c.stop_rdp {
            if let Some(mut a) = self.rdp_active.remove(name) {
                a.stop();
            }
        }
        if let Some(note) = c.note {
            evicted.push(note);
        }
        if !evicted.is_empty() {
            self.flash(format!("for {}: {}", c.step.describe(), evicted.join(", ")), false);
        }
        self.advance_activation();
    }

    /// Everything that depends on a tunnel, for the Tunnels details panel.
    pub fn dependents_of(&self, tunnel_name: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .tunnels
            .iter()
            .filter(|t| t.depends_on == tunnel_name)
            .map(|t| format!("tun {}", t.name))
            .collect();
        names.extend(
            self.ssh_hosts
                .iter()
                .filter(|h| h.depends_on == tunnel_name)
                .map(|h| format!("ssh {}", h.name)),
        );
        names.extend(
            self.rdp_conns
                .iter()
                .filter(|c| c.depends_on == tunnel_name)
                .map(|c| format!("rdp {}", c.name)),
        );
        names
    }

    /// Everything that asks for a given VPN profile, for the VPN tab.
    pub fn vpn_dependents_of(&self, profile: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .tunnels
            .iter()
            .filter(|t| t.requires_vpn == profile)
            .map(|t| format!("tun {}", t.name))
            .collect();
        names.extend(
            self.ssh_hosts
                .iter()
                .filter(|h| h.requires_vpn == profile)
                .map(|h| format!("ssh {}", h.name)),
        );
        names.extend(
            self.rdp_conns
                .iter()
                .filter(|c| c.requires_vpn == profile)
                .map(|c| format!("rdp {}", c.name)),
        );
        names
    }

    /// Whether a dependency names a tunnel that still exists.
    pub fn dependency_missing(&self, dep: &str) -> bool {
        !dep.is_empty() && !self.tunnels.iter().any(|t| t.name == dep)
    }

    // -----------------------------------------------------------------------
    // Tunnel form / lifecycle (unchanged)
    // -----------------------------------------------------------------------

    fn on_form_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.form_mode = FormMode::None,
            KeyCode::Enter => self.submit_form(),
            KeyCode::Tab | KeyCode::Down => self.form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.form.prev_field(),
            KeyCode::Left => self.cycle_tunnel_picker(false),
            KeyCode::Right => self.cycle_tunnel_picker(true),
            KeyCode::Backspace => {
                if let Some(text) = self.form.active_text_mut() {
                    text.pop();
                }
            }
            KeyCode::Char(c) => match self.form.active_text_mut() {
                Some(text) => text.push(c),
                None => self.cycle_tunnel_picker(true),
            },
            _ => {}
        }
    }

    fn cycle_tunnel_picker(&mut self, forward: bool) {
        match self.form.field() {
            FormField::Forward => {
                self.form.forward = if forward {
                    self.form.forward.next()
                } else {
                    self.form.forward.prev()
                }
            }
            FormField::AutoReconnect => self.form.auto_reconnect = !self.form.auto_reconnect,
            FormField::RequiresVpn => {
                if forward {
                    self.form.vpn.next()
                } else {
                    self.form.vpn.prev()
                }
            }
            FormField::DependsOn => {
                if forward {
                    self.form.dep.next()
                } else {
                    self.form.dep.prev()
                }
            }
            _ => {}
        }
    }

    fn submit_form(&mut self) {
        let tunnel = match self.form.to_tunnel() {
            Ok(t) => t,
            Err(e) => {
                self.form.error = Some(e);
                return;
            }
        };
        let editing = match &self.form_mode {
            FormMode::Edit(i) => Some(*i),
            _ => None,
        };
        let duplicate = self
            .tunnels
            .iter()
            .enumerate()
            .any(|(i, t)| t.name == tunnel.name && Some(i) != editing);
        if duplicate {
            self.form.error = Some(format!("a tunnel named '{}' already exists", tunnel.name));
            return;
        }
        // Catch a → b → a before it is saved; the picker already rules out a → a.
        let mut candidate = self.tunnels.clone();
        match editing {
            Some(i) => candidate[i] = tunnel.clone(),
            None => candidate.push(tunnel.clone()),
        }
        if let Some(cycle) = tunnel_cycle(&candidate, &tunnel.name) {
            self.form.error = Some(format!("that makes a dependency cycle: {cycle}"));
            return;
        }
        match editing {
            Some(i) => {
                let old_name = self.tunnels[i].name.clone();
                // Editing an active tunnel: stop it; the user restarts with the new settings.
                if self.active.contains_key(&old_name) {
                    self.stop_tunnel(&old_name);
                    self.flash("tunnel stopped — press Enter to start with new settings", false);
                }
                let new_name = tunnel.name.clone();
                self.tunnels[i] = tunnel;
                if old_name != new_name {
                    self.rename_dependency(&old_name, &new_name);
                }
            }
            None => self.tunnels.push(tunnel),
        }
        self.form_mode = FormMode::None;
        self.rebuild_rows();
        if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
            self.flash(format!("save failed: {e}"), true);
        }
    }

    /// Keep dependencies pointing at a renamed tunnel.
    fn rename_dependency(&mut self, old: &str, new: &str) {
        let mut tunnels_touched = false;
        for t in self.tunnels.iter_mut().filter(|t| t.depends_on == old) {
            t.depends_on = new.to_string();
            tunnels_touched = true;
        }
        if tunnels_touched {
            if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
                self.flash(format!("save failed: {e}"), true);
            }
        }
        let mut ssh_touched = false;
        for h in self.ssh_hosts.iter_mut().filter(|h| h.depends_on == old) {
            h.depends_on = new.to_string();
            ssh_touched = true;
        }
        let mut rdp_touched = false;
        for c in self.rdp_conns.iter_mut().filter(|c| c.depends_on == old) {
            c.depends_on = new.to_string();
            rdp_touched = true;
        }
        if ssh_touched {
            self.save_ssh_hosts();
        }
        if rdp_touched {
            if let Err(e) = config::save_rdp(&self.paths.rdp_file, &self.rdp_conns) {
                self.flash(format!("save failed: {e}"), true);
            }
        }
    }

    fn delete_tunnel(&mut self, idx: usize) {
        if idx >= self.tunnels.len() {
            return;
        }
        let name = self.tunnels[idx].name.clone();
        if self.active.contains_key(&name) {
            self.stop_tunnel(&name);
        }
        let orphaned = self.dependents_of(&name);
        self.tunnels.remove(idx);
        self.rebuild_rows();
        if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
            self.flash(format!("save failed: {e}"), true);
        } else if orphaned.is_empty() {
            self.flash(format!("deleted '{name}'"), false);
        } else {
            self.flash(
                format!("deleted '{name}' — {} now depend(s) on a missing tunnel", orphaned.join(", ")),
                true,
            );
        }
    }

    fn toggle_selected(&mut self) {
        match self.rows.get(self.selected).cloned() {
            Some(RowItem::Tunnel(i)) => {
                let name = self.tunnels[i].name.clone();
                if self.active.contains_key(&name) {
                    self.stop_tunnel(&name);
                } else {
                    self.activate(vec![Step::Tunnel(name)]);
                }
            }
            Some(RowItem::Group(g)) => {
                let members = self.group_members(&g);
                let any_inactive = members
                    .iter()
                    .any(|i| !self.active.contains_key(&self.tunnels[*i].name));
                if any_inactive {
                    // One plan for the whole group: shared dependencies are
                    // brought up once, and members that fight each other are
                    // reported instead of prompting for every one of them.
                    let targets: Vec<Step> = members
                        .iter()
                        .map(|i| Step::Tunnel(self.tunnels[*i].name.clone()))
                        .collect();
                    self.activate(targets);
                } else {
                    for i in members {
                        let name = self.tunnels[i].name.clone();
                        self.stop_tunnel(&name);
                    }
                }
            }
            None => {}
        }
    }

    fn start_tunnel(&mut self, idx: usize) {
        let t = self.tunnels[idx].clone();
        match tunnel::spawn(&t) {
            Ok(active) => {
                self.reconnect.remove(&t.name);
                self.active.insert(t.name.clone(), active);
            }
            Err(e) => self.flash(format!("'{}': {e:#}", t.name), true),
        }
    }

    fn stop_tunnel(&mut self, name: &str) {
        self.reconnect.remove(name);
        if let Some(mut t) = self.active.remove(name) {
            t.stop();
        }
    }

    fn stop_all(&mut self) {
        let names: Vec<String> = self.active.keys().cloned().collect();
        for name in &names {
            self.stop_tunnel(name);
        }
        if !names.is_empty() {
            self.flash(format!("stopped {} tunnel(s)", names.len()), false);
        }
    }

    fn on_tick(&mut self) {
        let dt = self.last_tick.elapsed().as_secs_f64().max(0.5);
        let mut total_rate = 0u64;
        for active in self.active.values_mut() {
            active.poll();
            active.sample_rates(dt);
            total_rate += active.rate_tx + active.rate_rx;
        }
        if self.throughput_history.len() >= THROUGHPUT_HISTORY {
            self.throughput_history.pop_front();
        }
        self.throughput_history.push_back(total_rate);

        for session in self.rdp_active.values_mut() {
            session.poll();
        }

        self.drain_netbird();
        if self.nb.installed
            && self.nb.busy.is_none()
            && self.nb.last_refresh.elapsed() >= Duration::from_secs(NETBIRD_REFRESH_SECS)
        {
            self.nb.last_refresh = Instant::now();
            netbird::refresh(self.nb_tx.clone());
        }

        self.handle_reconnects();
        self.advance_activation();

        if let Some((_, _, at)) = &self.status_msg {
            if at.elapsed() > Duration::from_secs(6) {
                self.status_msg = None;
            }
        }
    }

    fn drain_netbird(&mut self) {
        while let Ok(msg) = self.nb_rx.try_recv() {
            match msg {
                NbMsg::Refreshed { profiles, status } => {
                    match profiles {
                        Ok(p) => {
                            self.nb.profiles = p;
                            if self.nb.selected >= self.nb.profiles.len() {
                                self.nb.selected =
                                    self.nb.profiles.len().saturating_sub(1);
                            }
                        }
                        Err(e) => self.nb.error = Some(e),
                    }
                    self.nb.status = status;
                    self.nb.last_refresh = Instant::now();
                }
                NbMsg::ActionDone { desc, error } => {
                    self.nb.busy = None;
                    match error {
                        Some(e) => {
                            self.nb.error = Some(e.clone());
                            self.flash(format!("netbird {desc} failed: {e}"), true);
                        }
                        None => self.flash(format!("netbird: {desc} done"), false),
                    }
                }
            }
        }
    }

    fn handle_reconnects(&mut self) {
        let now = Instant::now();
        let failed: Vec<String> = self
            .active
            .iter()
            .filter(|(_, a)| a.status == Status::Failed)
            .map(|(n, _)| n.clone())
            .collect();

        for name in failed {
            let Some(t) = self.tunnels.iter().find(|t| t.name == name).cloned() else {
                continue;
            };
            if !t.auto_reconnect {
                continue;
            }
            // Retrying is pointless while what it runs through is down.
            let requires = t.requires();
            if !self.vpn_satisfied(&requires.vpn) {
                continue;
            }
            if !requires.tunnel.is_empty()
                && !matches!(
                    self.active.get(&requires.tunnel).map(|a| a.status),
                    Some(Status::Up)
                )
            {
                continue;
            }
            let entry = self.reconnect.entry(name.clone()).or_insert(ReconnectState {
                next_at: now + Duration::from_secs(3),
                attempts: 0,
            });
            if now < entry.next_at {
                continue;
            }
            let attempts = entry.attempts + 1;
            let backoff = Duration::from_secs((3 * attempts.min(10)) as u64);
            match tunnel::spawn(&t) {
                Ok(mut fresh) => {
                    let prev = self.active.remove(&name);
                    if let Some(mut prev) = prev {
                        fresh.restarts = prev.restarts + 1;
                        prev.stop();
                    }
                    self.active.insert(name.clone(), fresh);
                    self.reconnect.remove(&name);
                    self.flash(format!("reconnecting '{name}'"), false);
                }
                Err(_) => {
                    self.reconnect.insert(
                        name,
                        ReconnectState {
                            next_at: now + backoff,
                            attempts,
                        },
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(name: &str, vpn: &str, dep: &str) -> Tunnel {
        Tunnel {
            name: name.into(),
            group: String::new(),
            ssh_host: "bastion".into(),
            forward: ForwardType::Local,
            local_port: 1234,
            remote_host: "db".into(),
            remote_port: 5432,
            extra_args: String::new(),
            auto_reconnect: false,
            requires_vpn: vpn.into(),
            depends_on: dep.into(),
        }
    }

    fn ssh_host(name: &str, vpn: &str, dep: &str) -> SshHost {
        SshHost {
            name: name.into(),
            host: "127.0.0.1".into(),
            port: 22,
            username: String::new(),
            key_path: String::new(),
            password: String::new(),
            skip_host_key_check: false,
            extra_args: String::new(),
            depends_on: dep.into(),
            requires_vpn: vpn.into(),
        }
    }

    fn catalog<'a>(tunnels: &'a [Tunnel], hosts: &'a [SshHost]) -> Catalog<'a> {
        Catalog {
            tunnels,
            ssh_hosts: hosts,
            rdp_conns: &[],
        }
    }

    fn names(steps: &[Step]) -> Vec<String> {
        steps.iter().map(Step::short).collect()
    }

    #[test]
    fn picker_starts_on_none_and_cycles_through_tunnels() {
        let ts = vec![tunnel("a", "", ""), tunnel("b", "", "")];
        let mut p = Picker::tunnels(&ts, "", None);
        assert_eq!(p.value(), "");
        assert_eq!(p.label(), "(none)");
        p.next();
        assert_eq!(p.value(), "a");
        p.next();
        assert_eq!(p.value(), "b");
        p.next();
        assert_eq!(p.value(), "");
        p.prev();
        assert_eq!(p.value(), "b");
    }

    #[test]
    fn a_tunnel_is_not_offered_as_its_own_dependency() {
        let ts = vec![tunnel("a", "", ""), tunnel("b", "", "")];
        let p = Picker::tunnels(&ts, "", Some("a"));
        assert_eq!(p.options, vec!["".to_string(), "b".to_string()]);
    }

    #[test]
    fn picker_keeps_a_dependency_whose_tunnel_is_gone() {
        // Deleting the tunnel must not silently unlink the connection.
        let ts = vec![tunnel("a", "", "")];
        let p = Picker::tunnels(&ts, "deleted", None);
        assert_eq!(p.value(), "deleted");
        assert_eq!(p.options.len(), 3);
    }

    #[test]
    fn vpn_picker_offers_none_any_and_every_profile() {
        let profiles = vec![
            Profile { name: "work".into(), active: true },
            Profile { name: "home".into(), active: false },
        ];
        let p = Picker::vpn(&profiles, VPN_ANY);
        assert_eq!(p.label(), "(any profile)");
        assert_eq!(p.options, vec!["", VPN_ANY, "work", "home"]);
    }

    #[test]
    fn stacked_tunnels_are_planned_bottom_up() {
        // app runs through mid, mid runs through base.
        let ts = vec![
            tunnel("base", "", ""),
            tunnel("mid", "", "base"),
            tunnel("app", "", "mid"),
        ];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap();
        assert_eq!(names(&plan), ["tun base", "tun mid", "tun app"]);
    }

    #[test]
    fn the_vpn_a_tunnel_deep_in_the_stack_needs_is_hoisted_to_the_front() {
        let ts = vec![tunnel("base", "work", ""), tunnel("app", "", "base")];
        let hosts = vec![ssh_host("login", "", "app")];
        let plan = catalog(&ts, &hosts)
            .build_plan(vec![Step::Ssh("login".into())])
            .unwrap();
        assert_eq!(names(&plan), ["vpn work", "tun base", "tun app", "ssh login"]);
    }

    #[test]
    fn a_named_profile_wins_over_any_profile() {
        let ts = vec![tunnel("base", VPN_ANY, ""), tunnel("app", "work", "base")];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap();
        assert_eq!(names(&plan)[0], "vpn work");
    }

    #[test]
    fn two_different_profiles_in_one_chain_are_rejected() {
        let ts = vec![tunnel("base", "home", ""), tunnel("app", "work", "base")];
        let err = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap_err();
        assert!(err.contains("'work'") && err.contains("'home'"), "{err}");
    }

    #[test]
    fn a_cycle_is_reported_instead_of_recursing_forever() {
        let ts = vec![tunnel("a", "", "b"), tunnel("b", "", "a")];
        let err = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("a".into())])
            .unwrap_err();
        assert!(err.starts_with("dependency cycle: a → b → a"), "{err}");
    }

    #[test]
    fn a_shared_dependency_is_started_once_for_a_whole_group() {
        let ts = vec![
            tunnel("base", "", ""),
            tunnel("one", "", "base"),
            tunnel("two", "", "base"),
        ];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("one".into()), Step::Tunnel("two".into())])
            .unwrap();
        assert_eq!(names(&plan), ["tun base", "tun one", "tun two"]);
    }

    #[test]
    fn a_missing_dependency_names_the_tunnel_that_is_gone() {
        let hosts = vec![ssh_host("login", "", "deleted")];
        let err = catalog(&[], &hosts)
            .build_plan(vec![Step::Ssh("login".into())])
            .unwrap_err();
        assert!(err.contains("'deleted'"), "{err}");
    }

    #[test]
    fn saving_a_tunnel_that_closes_a_loop_is_caught() {
        let ts = vec![tunnel("a", "", "b"), tunnel("b", "", "a")];
        assert!(tunnel_cycle(&ts, "a").is_some());
        let fine = vec![tunnel("a", "", ""), tunnel("b", "", "a")];
        assert!(tunnel_cycle(&fine, "b").is_none());
    }
}
