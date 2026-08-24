use crate::browser::FileBrowser;
use crate::config::{self, AppConfig, Paths};
use crate::rdp::{self, ActiveRdp, RdpStatus};
use crate::ssh::{self, SessionOutcome};
use crate::theme::{self, Theme};
use crate::tunnel::{self, ActiveTunnel, Status};
use crate::types::{
    canonical_vpn_requirement, parse_vpn_requirement, tunnel_conflict, vpn_requirement_label,
    ForwardType, OpenvpnProfile, RdpConnection, Requires, SshHost, TailscaleProfile, Tunnel,
    VpnConfig, WireguardProfile, VPN_ANY,
};
use crate::ui;
use crate::vpn::openvpn::{self, ActiveOvpn, OvpnStatus};
use crate::vpn::{self, wireguard, ProviderId, VpnEnv, VpnMsg, VpnProfile, VpnStatus};
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

pub const THROUGHPUT_HISTORY: usize = 120;
const VPN_REFRESH_SECS: u64 = 5;
/// How long a dependent connection waits for its tunnel to come up.
const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bringing a VPN up may sit through a browser login, so it gets much longer.
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

/// One visible row in a grouped list (tunnels, ssh hosts, rdp connections):
/// a group header, or an entry at the given index in the underlying list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowItem {
    Group(String),
    Item(usize),
}

/// Lay a list out for display: ungrouped entries first, then each group in
/// order of first appearance with its members underneath it.
pub fn build_rows<T>(items: &[T], group_of: impl Fn(&T) -> &str) -> Vec<RowItem> {
    let mut rows = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if group_of(item).is_empty() {
            rows.push(RowItem::Item(i));
        }
    }
    let mut groups: Vec<&str> = Vec::new();
    for item in items {
        let g = group_of(item);
        if !g.is_empty() && !groups.contains(&g) {
            groups.push(g);
        }
    }
    for g in groups {
        rows.push(RowItem::Group(g.to_string()));
        for (i, item) in items.iter().enumerate() {
            if group_of(item) == g {
                rows.push(RowItem::Item(i));
            }
        }
    }
    rows
}

/// Indices of the entries in `group`.
pub fn members_of<T>(items: &[T], group_of: impl Fn(&T) -> &str, group: &str) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| group_of(item) == group)
        .map(|(i, _)| i)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormMode {
    None,
    Add,
    Edit(usize),
    DeleteConfirm(usize),
    /// Full-screen view of the selected tunnel's ssh output.
    Logs,
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
            vpn: Picker::vpn(ctx.vpn, ""),
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
            vpn: Picker::vpn(ctx.vpn, &t.requires_vpn),
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

    /// "(none)", "(any VPN)", then each provider's "any profile" entry followed
    /// by its profiles.
    ///
    /// A provider that is not installed is still offered once it has profiles
    /// configured, so a dependency can be wired up before the client is there.
    pub fn vpn(view: &VpnView, current: &str) -> Self {
        let mut options = vec![String::new(), VPN_ANY.to_string()];
        for state in &view.providers {
            if !state.installed && state.profiles.is_empty() {
                continue;
            }
            options.push(format!("{}:{VPN_ANY}", state.id.slug()));
            options.extend(
                state
                    .profiles
                    .iter()
                    .map(|p| format!("{}:{}", state.id.slug(), p.name)),
            );
        }
        Self::build(PickerKind::Vpn, options, &canonical_vpn_requirement(current))
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
            (PickerKind::Vpn, _) => vpn_requirement_label(&v),
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
    pub vpn: &'a VpnView,
}

// ---------------------------------------------------------------------------
// RDP form / modal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpField {
    Name,
    Group,
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
    RdpField::Group,
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
            Self::Group => "Group (optional)",
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
    pub group: String,
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
            group: String::new(),
            host: String::new(),
            port: "3389".into(),
            domain: String::new(),
            username: String::new(),
            extra_args: String::new(),
            vpn: Picker::vpn(ctx.vpn, ""),
            dep: Picker::tunnels(ctx.tunnels, "", None),
            error: None,
        }
    }

    pub fn from_connection(c: &RdpConnection, ctx: FormContext) -> Self {
        Self {
            field_idx: 0,
            name: c.name.clone(),
            group: c.group.clone(),
            host: c.host.clone(),
            port: c.port.to_string(),
            domain: c.domain.clone(),
            username: c.username.clone(),
            extra_args: c.extra_args.clone(),
            vpn: Picker::vpn(ctx.vpn, &c.requires_vpn),
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
            RdpField::Group => Some(&mut self.group),
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
            group: self.group.trim().to_string(),
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
    /// Masked password prompt. A group start asks for each member in turn,
    /// so `pending` holds the connections still to be asked about (current
    /// one first) and `collected` the answers already given; the whole lot is
    /// started as one plan once the last one is answered.
    Password {
        pending: Vec<usize>,
        collected: Vec<Step>,
        input: String,
    },
    /// Full-screen log view of the selected session.
    Logs,
}

// ---------------------------------------------------------------------------
// SSH host form / modal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshField {
    Name,
    Group,
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
    SshField::Group,
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
            Self::Group => "Group (optional)",
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
    pub group: String,
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
            group: String::new(),
            host: String::new(),
            port: "22".into(),
            username: String::new(),
            key_path: String::new(),
            password: String::new(),
            skip_host_key_check: false,
            vpn: Picker::vpn(ctx.vpn, ""),
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
            group: h.group.clone(),
            host: h.host.clone(),
            port: h.port.to_string(),
            username: h.username.clone(),
            key_path: h.key_path.clone(),
            password: h.password.clone(),
            skip_host_key_check: h.skip_host_key_check,
            vpn: Picker::vpn(ctx.vpn, &h.requires_vpn),
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
            SshField::Group => Some(&mut self.group),
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
            group: self.group.trim().to_string(),
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

    /// Fold a new VPN requirement into the ones the plan already has.
    ///
    /// Requirements are held one per provider, so a chain may legitimately need
    /// wireguard *and* tailscale. Within a provider a named profile beats "any
    /// profile", and two different profiles of the same provider still cannot
    /// both hold. A bare "any VPN" is satisfied by anything already required.
    fn merge_vpn(current: &mut Vec<String>, want: &str) -> Result<(), String> {
        let Some(req) = parse_vpn_requirement(want) else {
            return Ok(());
        };
        let Some(provider) = req.provider else {
            if current.is_empty() {
                current.push(req.canonical());
            }
            return Ok(());
        };
        // Something specific supersedes a bare "any VPN".
        current.retain(|c| c != VPN_ANY);

        let existing = current.iter_mut().find(|c| {
            parse_vpn_requirement(c).and_then(|r| r.provider) == Some(provider)
        });
        let Some(slot) = existing else {
            current.push(req.canonical());
            return Ok(());
        };
        let have = parse_vpn_requirement(slot).unwrap_or(req.clone());
        match (&have.profile, &req.profile) {
            // "any profile of this provider" adds nothing to a named one.
            (_, None) => {}
            (None, Some(_)) => *slot = req.canonical(),
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => {
                return Err(format!(
                    "needs {} profile '{a}' and '{b}' at the same time",
                    provider.slug()
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
        vpn: &mut Vec<String>,
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
        let mut vpn: Vec<String> = Vec::new();
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
        // Every VPN the chain needs goes first, in a stable provider order.
        vpn.sort_by_key(|req| {
            parse_vpn_requirement(req)
                .and_then(|r| r.provider)
                .map(ProviderId::index)
                .unwrap_or(usize::MAX)
        });
        for (i, req) in vpn.into_iter().enumerate() {
            steps.insert(i, Step::Vpn(req));
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
// VPN state
// ---------------------------------------------------------------------------

/// One VPN client as the tab sees it.
pub struct ProviderState {
    pub id: ProviderId,
    pub installed: bool,
    pub profiles: Vec<VpnProfile>,
    pub status: VpnStatus,
    pub selected: usize,
    /// Description of the action currently running in the background.
    pub busy: Option<String>,
    pub error: Option<String>,
    last_refresh: Instant,
}

impl ProviderState {
    fn new(id: ProviderId) -> Self {
        Self {
            id,
            installed: vpn::installed(id),
            profiles: Vec::new(),
            status: VpnStatus::default(),
            selected: 0,
            busy: None,
            error: None,
            // Far enough in the past that the first tick refreshes.
            last_refresh: Instant::now() - Duration::from_secs(VPN_REFRESH_SECS * 2),
        }
    }

    pub fn selected_profile(&self) -> Option<&VpnProfile> {
        self.profiles.get(self.selected)
    }

    /// The profile that is up, as the provider reports it.
    pub fn active_profile(&self) -> Option<&str> {
        self.status
            .active_profile
            .as_deref()
            .or_else(|| self.profiles.iter().find(|p| p.active).map(|p| p.name.as_str()))
    }

    fn clamp_selection(&mut self) {
        if self.selected >= self.profiles.len() {
            self.selected = self.profiles.len().saturating_sub(1);
        }
    }
}

/// Which of the VPN tab's two lists has the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPane {
    Clients,
    Profiles,
}

pub struct VpnView {
    /// One per [`ProviderId`], in `ProviderId::ALL` order.
    pub providers: Vec<ProviderState>,
    pub client_idx: usize,
    pub focus: VpnPane,
}

impl VpnView {
    fn new() -> Self {
        Self {
            providers: ProviderId::ALL.into_iter().map(ProviderState::new).collect(),
            client_idx: 0,
            focus: VpnPane::Clients,
        }
    }

    pub fn get(&self, id: ProviderId) -> &ProviderState {
        &self.providers[id.index()]
    }

    fn get_mut(&mut self, id: ProviderId) -> &mut ProviderState {
        &mut self.providers[id.index()]
    }

    pub fn current(&self) -> &ProviderState {
        &self.providers[self.client_idx.min(self.providers.len() - 1)]
    }

    fn current_mut(&mut self) -> &mut ProviderState {
        let idx = self.client_idx.min(self.providers.len() - 1);
        &mut self.providers[idx]
    }

    pub fn current_id(&self) -> ProviderId {
        self.current().id
    }

    /// The clients that are connected, for the header and the dashboard.
    pub fn connected(&self) -> Vec<&ProviderState> {
        self.providers
            .iter()
            .filter(|p| p.status.connected)
            .collect()
    }

    pub fn any_installed(&self) -> bool {
        self.providers.iter().any(|p| p.installed)
    }

    pub fn any_busy(&self) -> bool {
        self.providers.iter().any(|p| p.busy.is_some())
    }
}

// ---------------------------------------------------------------------------
// VPN profile form
// ---------------------------------------------------------------------------

/// One line of a VPN profile form. The three providers whose profiles
/// controlcenter owns have very different fields but identical form behaviour,
/// so they share one table-driven form rather than three near-copies.
pub struct VpnFieldSpec {
    /// Key into the form's value maps, and the config field it maps to.
    pub id: &'static str,
    pub label: &'static str,
    /// Toggled with ◂ ▸ instead of typed into.
    pub flag: bool,
    /// Masked in the form and a reason to warn before saving.
    pub secret: bool,
}

const fn text(id: &'static str, label: &'static str) -> VpnFieldSpec {
    VpnFieldSpec { id, label, flag: false, secret: false }
}

const fn secret(id: &'static str, label: &'static str) -> VpnFieldSpec {
    VpnFieldSpec { id, label, flag: false, secret: true }
}

const fn flag(id: &'static str, label: &'static str) -> VpnFieldSpec {
    VpnFieldSpec { id, label, flag: true, secret: false }
}

pub const WIREGUARD_FIELDS: &[VpnFieldSpec] = &[
    text("name", "Name (also the interface)"),
    text("config_path", "Existing .conf (optional)"),
    secret("private_key", "Private key (g generates)"),
    text("address", "Address, e.g. 10.0.0.2/24"),
    text("dns", "DNS (optional, needs resolvconf)"),
    text("listen_port", "Listen port (0 = any)"),
    text("mtu", "MTU (0 = default)"),
    text("peer_public_key", "Peer public key"),
    secret("preshared_key", "Preshared key (optional)"),
    text("endpoint", "Endpoint host:port"),
    text("allowed_ips", "Allowed IPs"),
    text("persistent_keepalive", "Keepalive secs (0 = off)"),
];

pub const OPENVPN_FIELDS: &[VpnFieldSpec] = &[
    text("name", "Name"),
    text("config_path", "Config file (.ovpn, ~ ok)"),
    flag("import", "Import it and its certificates"),
    text("username", "Username (optional)"),
    secret("password", "Password (optional, cleartext!)"),
    text("extra_args", "Extra openvpn args (optional)"),
];

pub const TAILSCALE_FIELDS: &[VpnFieldSpec] = &[
    text("name", "Name"),
    text("login_server", "Login server (optional, Headscale)"),
    text("exit_node", "Exit node (optional)"),
    flag("exit_node_allow_lan", "Allow LAN access via exit node"),
    flag("accept_routes", "Accept subnet routes"),
    flag("accept_dns", "Accept MagicDNS"),
    flag("ssh", "Enable Tailscale SSH"),
    flag("shields_up", "Shields up (block incoming)"),
    text("hostname", "Hostname (optional)"),
    text("advertise_routes", "Advertise routes (optional)"),
    flag("advertise_exit_node", "Advertise as an exit node"),
    text("extra_args", "Extra tailscale args (optional)"),
];

pub fn vpn_fields(provider: ProviderId) -> &'static [VpnFieldSpec] {
    match provider {
        ProviderId::Wireguard => WIREGUARD_FIELDS,
        ProviderId::Openvpn => OPENVPN_FIELDS,
        ProviderId::Tailscale => TAILSCALE_FIELDS,
        // NetBird's profiles live in netbird; there is nothing to edit here.
        ProviderId::Netbird => &[],
    }
}

pub struct VpnForm {
    pub provider: ProviderId,
    pub field_idx: usize,
    text: HashMap<&'static str, String>,
    flags: HashMap<&'static str, bool>,
    pub error: Option<String>,
    /// Set once the cleartext-secret warning has been acknowledged for this edit.
    pub secret_ack: bool,
}

impl VpnForm {
    pub fn empty(provider: ProviderId) -> Self {
        let mut form = Self {
            provider,
            field_idx: 0,
            text: HashMap::new(),
            flags: HashMap::new(),
            error: None,
            secret_ack: false,
        };
        match provider {
            ProviderId::Wireguard => {
                form.set("allowed_ips", crate::types::default_allowed_ips());
                form.set("listen_port", "0");
                form.set("mtu", "0");
                form.set("persistent_keepalive", "25");
            }
            ProviderId::Openvpn => {
                // A downloaded profile almost always ships certificates next to
                // the .ovpn, so importing is the sensible default.
                form.flags.insert("import", true);
            }
            ProviderId::Tailscale => {
                let d = TailscaleProfile::default();
                form.flags.insert("accept_routes", d.accept_routes);
                form.flags.insert("accept_dns", d.accept_dns);
            }
            _ => {}
        }
        form
    }

    pub fn from_wireguard(w: &WireguardProfile) -> Self {
        let mut f = Self::empty(ProviderId::Wireguard);
        f.set("name", &w.name);
        f.set("config_path", &w.config_path);
        f.set("private_key", &w.private_key);
        f.set("address", &w.address);
        f.set("dns", &w.dns);
        f.set("listen_port", w.listen_port.to_string());
        f.set("mtu", w.mtu.to_string());
        f.set("peer_public_key", &w.peer_public_key);
        f.set("preshared_key", &w.preshared_key);
        f.set("endpoint", &w.endpoint);
        f.set("allowed_ips", &w.allowed_ips);
        f.set("persistent_keepalive", w.persistent_keepalive.to_string());
        f.secret_ack = !w.private_key.is_empty();
        f
    }

    pub fn from_openvpn(o: &OpenvpnProfile) -> Self {
        let mut f = Self::empty(ProviderId::Openvpn);
        f.set("name", &o.name);
        f.set("config_path", &o.config_path);
        f.set("username", &o.username);
        f.set("password", &o.password);
        f.set("extra_args", &o.extra_args);
        f.flags.insert("import", o.import);
        f.secret_ack = !o.password.is_empty();
        f
    }

    pub fn from_tailscale(t: &TailscaleProfile) -> Self {
        let mut f = Self::empty(ProviderId::Tailscale);
        f.set("name", &t.name);
        f.set("login_server", &t.login_server);
        f.set("exit_node", &t.exit_node);
        f.set("hostname", &t.hostname);
        f.set("advertise_routes", &t.advertise_routes);
        f.set("extra_args", &t.extra_args);
        f.flags.insert("exit_node_allow_lan", t.exit_node_allow_lan);
        f.flags.insert("accept_routes", t.accept_routes);
        f.flags.insert("accept_dns", t.accept_dns);
        f.flags.insert("ssh", t.ssh);
        f.flags.insert("shields_up", t.shields_up);
        f.flags.insert("advertise_exit_node", t.advertise_exit_node);
        f
    }

    fn set(&mut self, id: &'static str, value: impl Into<String>) {
        self.text.insert(id, value.into());
    }

    pub fn fields(&self) -> &'static [VpnFieldSpec] {
        vpn_fields(self.provider)
    }

    /// `None` only for a provider with nothing to edit, i.e. netbird — which
    /// never opens a form, but the arithmetic below must not assume that.
    pub fn field(&self) -> Option<&'static VpnFieldSpec> {
        self.fields().get(self.field_idx.min(self.fields().len().saturating_sub(1)))
    }

    pub fn next_field(&mut self) {
        let n = self.fields().len();
        if n > 0 {
            self.field_idx = (self.field_idx + 1) % n;
        }
    }

    pub fn prev_field(&mut self) {
        let n = self.fields().len();
        if n > 0 {
            self.field_idx = (self.field_idx + n - 1) % n;
        }
    }

    pub fn active_text_mut(&mut self) -> Option<&mut String> {
        let spec = self.field()?;
        if spec.flag {
            return None;
        }
        Some(self.text.entry(spec.id).or_default())
    }

    /// Flip the flag under the cursor. Text fields ignore ◂ ▸.
    pub fn toggle(&mut self) {
        let Some(spec) = self.field() else { return };
        if spec.flag {
            let e = self.flags.entry(spec.id).or_default();
            *e = !*e;
        }
    }

    pub fn str_value(&self, id: &str) -> &str {
        self.text.get(id).map(String::as_str).unwrap_or("")
    }

    pub fn bool_value(&self, id: &str) -> bool {
        self.flags.get(id).copied().unwrap_or(false)
    }

    /// What the form shows for a field: flags as yes/no, secrets as dots.
    pub fn display(&self, spec: &VpnFieldSpec) -> String {
        if spec.flag {
            return if self.bool_value(spec.id) { "yes".into() } else { "no".into() };
        }
        let v = self.str_value(spec.id);
        if spec.secret && !v.is_empty() {
            "•".repeat(v.chars().count().min(24))
        } else {
            v.to_string()
        }
    }

    /// Whether saving would write a secret to disk in the clear.
    pub fn stores_secret(&self) -> bool {
        self.fields()
            .iter()
            .any(|f| f.secret && !self.str_value(f.id).is_empty())
    }

    fn trimmed(&self, id: &str) -> String {
        self.str_value(id).trim().to_string()
    }

    fn number(&self, id: &str, label: &str) -> Result<u16, String> {
        let raw = self.trimmed(id);
        if raw.is_empty() {
            return Ok(0);
        }
        raw.parse()
            .map_err(|_| format!("{label} must be a number 0-65535"))
    }

    pub fn to_wireguard(&self) -> Result<WireguardProfile, String> {
        let p = WireguardProfile {
            name: self.trimmed("name"),
            config_path: expand_tilde(&self.trimmed("config_path")),
            private_key: self.trimmed("private_key"),
            address: self.trimmed("address"),
            dns: self.trimmed("dns"),
            listen_port: self.number("listen_port", "listen port")?,
            mtu: self.number("mtu", "MTU")?,
            peer_public_key: self.trimmed("peer_public_key"),
            preshared_key: self.trimmed("preshared_key"),
            endpoint: self.trimmed("endpoint"),
            allowed_ips: self.trimmed("allowed_ips"),
            persistent_keepalive: self.number("persistent_keepalive", "keepalive")?,
        };
        wireguard::validate(&p)?;
        Ok(p)
    }

    pub fn to_openvpn(&self) -> Result<OpenvpnProfile, String> {
        let name = self.trimmed("name");
        // The name becomes a directory under openvpn/, so it has to be one.
        if name.is_empty() {
            return Err("name is required".into());
        }
        if name.contains(['/', '\\']) || name.starts_with('.') {
            return Err("name cannot contain a path separator or start with '.'".into());
        }
        let config_path = expand_tilde(&self.trimmed("config_path"));
        if config_path.is_empty() {
            return Err("a .ovpn config file is required".into());
        }
        if !self.trimmed("password").is_empty() && self.trimmed("username").is_empty() {
            return Err("a password without a username will not be used".into());
        }
        Ok(OpenvpnProfile {
            name,
            config_path,
            import: self.bool_value("import"),
            username: self.trimmed("username"),
            password: self.str_value("password").to_string(),
            extra_args: self.trimmed("extra_args"),
        })
    }

    pub fn to_tailscale(&self) -> Result<TailscaleProfile, String> {
        let name = self.trimmed("name");
        if name.is_empty() {
            return Err("name is required".into());
        }
        Ok(TailscaleProfile {
            name,
            login_server: self.trimmed("login_server"),
            exit_node: self.trimmed("exit_node"),
            exit_node_allow_lan: self.bool_value("exit_node_allow_lan"),
            accept_routes: self.bool_value("accept_routes"),
            accept_dns: self.bool_value("accept_dns"),
            ssh: self.bool_value("ssh"),
            shields_up: self.bool_value("shields_up"),
            hostname: self.trimmed("hostname"),
            advertise_routes: self.trimmed("advertise_routes"),
            advertise_exit_node: self.bool_value("advertise_exit_node"),
            extra_args: self.trimmed("extra_args"),
        })
    }
}

/// `~/x` is what a person types; every other tool here takes a real path.
fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => std::path::Path::new(&home)
                .join(rest)
                .to_string_lossy()
                .into_owned(),
            None => path.to_string(),
        },
        None => path.to_string(),
    }
}

/// What the VPN tab has open on top of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnMode {
    None,
    /// Adding, or editing the profile at this index of its provider's list.
    Form {
        provider: ProviderId,
        edit: Option<usize>,
    },
    DeleteConfirm {
        provider: ProviderId,
        idx: usize,
    },
    /// Cleartext-secret warning shown before the form is saved.
    SecretWarning {
        provider: ProviderId,
        edit: Option<usize>,
    },
    /// Full-screen log of the selected OpenVPN session.
    Logs,
}

/// Whether a key closes a popup that only displays something — a log, the
/// help. `q` closes whatever is focused, `Esc` cancels, and `l` closes the log
/// it opened; nothing here types, so all three can mean "close".
fn closes_view(key: KeyEvent) -> bool {
    matches!(
        key.code,
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('l')
    )
}

/// What the panic button is about to take down, gathered while it asks.
pub struct PanicSummary {
    pub tunnels: usize,
    pub rdp: usize,
    pub ssh: usize,
    /// `provider:profile` for every VPN profile currently up.
    pub vpn: Vec<String>,
}

impl PanicSummary {
    pub fn is_empty(&self) -> bool {
        self.tunnels == 0 && self.rdp == 0 && self.ssh == 0 && self.vpn.is_empty()
    }

    /// One line per kind, leaving out the kinds that have nothing up.
    pub fn lines(&self) -> Vec<String> {
        let plural = |n: usize, one: &str| {
            if n == 1 {
                format!("1 {one}")
            } else {
                format!("{n} {one}s")
            }
        };
        let mut out = Vec::new();
        if self.tunnels > 0 {
            out.push(plural(self.tunnels, "tunnel"));
        }
        if self.rdp > 0 {
            out.push(plural(self.rdp, "RDP session"));
        }
        if self.ssh > 0 {
            out.push(plural(self.ssh, "SSH window"));
        }
        if !self.vpn.is_empty() {
            out.push(format!("VPN: {}", self.vpn.join(", ")));
        }
        out
    }
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
    /// The keybinding cheat sheet, opened with `k`.
    pub show_keys: bool,
    /// What `x` is about to tear down, while it asks whether to.
    pub panic: Option<PanicSummary>,
    pub theme: Theme,
    pub status_msg: Option<(String, bool, Instant)>,
    pub paths: Paths,
    pub app_config: AppConfig,
    pub throughput_history: VecDeque<u64>,
    pub vpn: VpnView,
    /// Profiles controlcenter owns, from `vpn.toml`.
    pub vpn_cfg: VpnConfig,
    pub vpn_form: VpnForm,
    pub vpn_mode: VpnMode,
    /// OpenVPN sessions, owned the same way RDP sessions are.
    pub ovpn_active: HashMap<String, ActiveOvpn>,
    pub rdp_conns: Vec<RdpConnection>,
    pub rdp_active: HashMap<String, ActiveRdp>,
    pub rdp_rows: Vec<RowItem>,
    /// Index into `rdp_rows`, not into `rdp_conns`.
    pub rdp_selected: usize,
    pub rdp_form: RdpForm,
    pub rdp_mode: RdpMode,
    pub rdp_installed: bool,
    pub ssh_hosts: Vec<SshHost>,
    pub ssh_rows: Vec<RowItem>,
    /// Index into `ssh_rows`, not into `ssh_hosts`.
    pub ssh_selected: usize,
    pub ssh_form: SshForm,
    pub ssh_mode: SshMode,
    /// Form state to come back to when the password warning is dismissed.
    ssh_return_mode: SshMode,
    pub sshpass_installed: bool,
    /// Outcome of the last finished interactive session, by host name.
    pub ssh_last: HashMap<String, SessionOutcome>,
    /// Sessions running in windows of their own, by host name. A host can have
    /// several — they are separate windows, nothing stops the user opening two.
    pub ssh_windows: HashMap<String, Vec<ssh::WindowSession>>,
    /// Where a session opens: its own window, or this terminal.
    pub ssh_launcher: ssh::Launch,
    /// The file picker, open over whichever form asked for it.
    pub browser: Option<FileBrowser>,
    /// Plan currently being executed, if any.
    pub activation: Option<Activation>,
    /// Tunnel-binding conflict awaiting the user's decision.
    pub conflict: Option<ConflictPrompt>,
    /// Name of the host cleared to run; the main loop owns the terminal and
    /// hands it to ssh.
    /// Sessions waiting for the main loop to open them. A queue, because a
    /// group start asks for several at once.
    ssh_launch: VecDeque<String>,
    vpn_tx: Sender<VpnMsg>,
    vpn_rx: Receiver<VpnMsg>,
    reconnect: HashMap<String, ReconnectState>,
    last_tick: Instant,
    should_quit: bool,
}

impl App {
    pub fn new(
        tunnels: Vec<Tunnel>,
        rdp_conns: Vec<RdpConnection>,
        ssh_hosts: Vec<SshHost>,
        vpn_cfg: VpnConfig,
        paths: Paths,
        app_config: AppConfig,
    ) -> Self {
        let theme = theme::by_name(&app_config.ui.theme);
        let app_config_terminal = app_config.ssh.terminal.clone();
        let (vpn_tx, vpn_rx) = channel();
        let vpn_view = VpnView::new();
        let empty_ctx = FormContext {
            tunnels: &tunnels,
            vpn: &vpn_view,
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
            show_keys: false,
            panic: None,
            theme,
            status_msg: None,
            paths,
            app_config,
            throughput_history: VecDeque::with_capacity(THROUGHPUT_HISTORY),
            vpn: vpn_view,
            vpn_cfg,
            vpn_form: VpnForm::empty(ProviderId::Wireguard),
            vpn_mode: VpnMode::None,
            ovpn_active: HashMap::new(),
            rdp_conns,
            rdp_active: HashMap::new(),
            rdp_rows: Vec::new(),
            rdp_selected: 0,
            rdp_form,
            rdp_mode: RdpMode::None,
            rdp_installed: rdp::installed(),
            ssh_hosts,
            ssh_rows: Vec::new(),
            ssh_selected: 0,
            ssh_form,
            ssh_mode: SshMode::None,
            ssh_return_mode: SshMode::None,
            sshpass_installed: ssh::sshpass_available(),
            ssh_last: HashMap::new(),
            ssh_windows: HashMap::new(),
            ssh_launcher: ssh::resolve_launch(&app_config_terminal),
            browser: None,
            activation: None,
            conflict: None,
            ssh_launch: VecDeque::new(),
            vpn_tx,
            vpn_rx,
            reconnect: HashMap::new(),
            last_tick: Instant::now(),
            should_quit: false,
        };
        app.rebuild_rows();
        app.rebuild_ssh_rows();
        app.rebuild_rdp_rows();
        for id in ProviderId::ALL {
            app.refresh_provider(id);
        }
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
            // A group start queues several; inline sessions then run one
            // after the other, windowed ones all open at once.
            while let Some(name) = self.ssh_launch.pop_front() {
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
            vpn: &self.vpn,
        }
    }

    pub fn rebuild_rows(&mut self) {
        self.rows = build_rows(&self.tunnels, |t| &t.group);
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
    }

    pub fn rebuild_ssh_rows(&mut self) {
        self.ssh_rows = build_rows(&self.ssh_hosts, |h| &h.group);
        if self.ssh_selected >= self.ssh_rows.len() {
            self.ssh_selected = self.ssh_rows.len().saturating_sub(1);
        }
    }

    pub fn rebuild_rdp_rows(&mut self) {
        self.rdp_rows = build_rows(&self.rdp_conns, |c| &c.group);
        if self.rdp_selected >= self.rdp_rows.len() {
            self.rdp_selected = self.rdp_rows.len().saturating_sub(1);
        }
    }

    pub fn group_members(&self, group: &str) -> Vec<usize> {
        members_of(&self.tunnels, |t| &t.group, group)
    }

    pub fn ssh_group_members(&self, group: &str) -> Vec<usize> {
        members_of(&self.ssh_hosts, |h| &h.group, group)
    }

    pub fn rdp_group_members(&self, group: &str) -> Vec<usize> {
        members_of(&self.rdp_conns, |c| &c.group, group)
    }

    /// The ssh host under the cursor, or `None` on a group header.
    pub fn selected_ssh_host(&self) -> Option<usize> {
        match self.ssh_rows.get(self.ssh_selected) {
            Some(RowItem::Item(i)) => Some(*i),
            _ => None,
        }
    }

    /// The rdp connection under the cursor, or `None` on a group header.
    pub fn selected_rdp_conn(&self) -> Option<usize> {
        match self.rdp_rows.get(self.rdp_selected) {
            Some(RowItem::Item(i)) => Some(*i),
            _ => None,
        }
    }

    fn flash(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status_msg = Some((msg.into(), is_error, Instant::now()));
    }

    fn on_key(&mut self, key: KeyEvent) {
        // The help and keybind overlays only display: any key closes them, and
        // the key for the other one swaps straight over to it.
        if self.show_help || self.show_keys {
            match key.code {
                KeyCode::Char('?') => {
                    self.show_help = true;
                    self.show_keys = false;
                }
                KeyCode::Char('k') => {
                    self.show_help = false;
                    self.show_keys = true;
                }
                _ => {
                    self.show_help = false;
                    self.show_keys = false;
                }
            }
            return;
        }
        // The panic prompt is modal over everything: it holds a global teardown.
        if self.panic.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.disconnect_everything()
                }
                _ => self.panic = None,
            }
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
        // The file picker sits on top of the form that opened it.
        if self.browser.is_some() {
            self.on_browser_key(key);
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
            FormMode::Logs => {
                if key.code == KeyCode::Char('c') {
                    self.clear_tunnel_log();
                } else if closes_view(key) {
                    self.form_mode = FormMode::None;
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
        if self.vpn_mode != VpnMode::None {
            self.on_vpn_modal_key(key);
            return;
        }

        // Nothing is open, so this is the base application: the keys that mean
        // the same thing everywhere are handled here, and only what is left
        // reaches the tab under the cursor.
        match key.code {
            // No popup left to close, so q closes the application itself.
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => {}
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('k') => self.show_keys = true,
            KeyCode::Char('t') => {
                self.theme = theme::next(self.theme.name);
                self.app_config.ui.theme = self.theme.name.to_string();
                let _ = config::save_app_config(&self.paths.config_file, &self.app_config);
            }
            // The panic button, and the one key that works the same on any tab
            // because what it acts on is everything rather than a selection.
            KeyCode::Char('x') => self.arm_panic(),
            KeyCode::Char('1') => self.tab = Tab::Dashboard,
            KeyCode::Char('2') => self.tab = Tab::Vpn,
            KeyCode::Char('3') => self.tab = Tab::Tunnels,
            KeyCode::Char('4') => self.tab = Tab::Ssh,
            KeyCode::Char('5') => self.tab = Tab::Rdp,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            _ => match self.tab {
                Tab::Dashboard => self.on_dashboard_key(key),
                Tab::Vpn => self.on_vpn_key(key),
                Tab::Tunnels => self.on_tunnels_key(key),
                Tab::Ssh => self.on_ssh_key(key),
                Tab::Rdp => self.on_rdp_key(key),
            },
        }
    }

    // -----------------------------------------------------------------------
    // The panic button
    // -----------------------------------------------------------------------

    /// Everything `x` would take down.
    fn panic_summary(&self) -> PanicSummary {
        let vpn: Vec<String> = self
            .vpn
            .providers
            .iter()
            .flat_map(|st| {
                st.profiles
                    .iter()
                    .filter(|p| p.active)
                    .map(|p| format!("{}:{}", st.id.slug(), p.name))
                    .collect::<Vec<_>>()
            })
            .collect();
        PanicSummary {
            tunnels: self.active.len(),
            rdp: self
                .rdp_active
                .values()
                .filter(|a| a.status == RdpStatus::Running)
                .count(),
            ssh: self.ssh_windows.values().map(Vec::len).sum(),
            vpn,
        }
    }

    /// `x` on any tab: work out what is up, then ask before pulling the plug.
    fn arm_panic(&mut self) {
        let summary = self.panic_summary();
        if summary.is_empty() {
            self.flash("nothing is connected", false);
            return;
        }
        self.panic = Some(summary);
    }

    /// Take down everything, in the order that leaves nothing reaching for a
    /// link that has already gone: the connections that ride on a VPN first,
    /// the VPNs last.
    fn disconnect_everything(&mut self) {
        let summary = match self.panic.take() {
            Some(s) => s,
            None => return,
        };
        // A plan half-way through would otherwise carry on bringing things back
        // up behind the teardown, and auto-reconnect would do the same.
        self.activation = None;
        self.conflict = None;
        self.reconnect.clear();

        for name in self.active.keys().cloned().collect::<Vec<_>>() {
            self.stop_tunnel(&name);
        }
        for name in self.rdp_active.keys().cloned().collect::<Vec<_>>() {
            if let Some(mut a) = self.rdp_active.remove(&name) {
                a.stop();
            }
        }
        for sessions in self.ssh_windows.values_mut() {
            for session in sessions.iter_mut() {
                session.kill();
            }
        }
        self.ssh_windows.clear();
        for id in ProviderId::ALL {
            self.vpn_disconnect_all(id);
        }
        self.flash(
            format!("disconnected everything: {}", summary.lines().join(", ")),
            false,
        );
    }

    /// Take down whatever of this client is up. WireGuard and OpenVPN can hold
    /// several profiles at once, so each one gets its own call.
    fn vpn_disconnect_all(&mut self, id: ProviderId) {
        if !self.vpn.get(id).installed {
            return;
        }
        let active: Vec<String> = self
            .vpn
            .get(id)
            .profiles
            .iter()
            .filter(|p| p.active)
            .map(|p| p.name.clone())
            .collect();
        if active.is_empty() {
            return;
        }
        if id == ProviderId::Openvpn {
            for name in active {
                self.stop_openvpn(&name);
            }
            return;
        }
        for name in active {
            self.vpn_start(id, "disconnecting".into(), Some(&name), false);
        }
    }

    // -----------------------------------------------------------------------
    // Dashboard
    // -----------------------------------------------------------------------

    /// The dashboard only watches. The keys that need something selected say
    /// where to go instead of doing nothing, so the map stays honest.
    fn on_dashboard_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') => {
                for id in ProviderId::ALL {
                    self.vpn.get_mut(id).error = None;
                    self.refresh_provider(id);
                }
                self.flash("refreshing every VPN client", false);
            }
            KeyCode::Char('c') => self.clear_finished_everywhere(),
            KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('a')
            | KeyCode::Char('e')
            | KeyCode::Char('d')
            | KeyCode::Char('p')
            | KeyCode::Char('l') => self.flash(
                "the dashboard only watches — act on the VPN, Tunnels, SSH or RDP tab",
                false,
            ),
            _ => {}
        }
    }

    /// `c` on the dashboard: drop every entry that has already finished, on
    /// every tab at once.
    fn clear_finished_everywhere(&mut self) {
        let mut cleared = 0usize;
        for name in self
            .active
            .iter()
            .filter(|(_, a)| a.status == Status::Failed)
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
        {
            self.stop_tunnel(&name);
            cleared += 1;
        }
        for name in self
            .rdp_active
            .iter()
            .filter(|(_, a)| matches!(a.status, RdpStatus::Exited(_)))
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
        {
            self.rdp_active.remove(&name);
            cleared += 1;
        }
        for name in self
            .ovpn_active
            .iter()
            .filter(|(_, a)| matches!(a.status, OvpnStatus::Exited(_)))
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
        {
            self.ovpn_active.remove(&name);
            cleared += 1;
        }
        cleared += self.ssh_last.len();
        self.ssh_last.clear();
        for id in ProviderId::ALL {
            self.vpn.get_mut(id).error = None;
        }
        if cleared == 0 {
            self.flash("nothing finished to clear", false);
        } else {
            self.flash(format!("cleared {cleared} finished entries"), false);
        }
    }

    fn on_tunnels_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down if !self.rows.is_empty() => {
                self.selected = (self.selected + 1) % self.rows.len();
            }
            KeyCode::Up if !self.rows.is_empty() => {
                self.selected = (self.selected + self.rows.len() - 1) % self.rows.len();
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_selected(),
            KeyCode::Char('a') => {
                let form = TunnelForm::empty(self.form_ctx());
                self.form = form;
                // Pre-fill the group when a group row or grouped tunnel is selected.
                match self.rows.get(self.selected) {
                    Some(RowItem::Group(g)) => self.form.group = g.clone(),
                    Some(RowItem::Item(i)) => {
                        self.form.group = self.tunnels[*i].group.clone()
                    }
                    None => {}
                }
                self.form_mode = FormMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(RowItem::Item(i)) = self.rows.get(self.selected) {
                    let form = TunnelForm::from_tunnel(&self.tunnels[*i], self.form_ctx());
                    self.form = form;
                    self.form_mode = FormMode::Edit(*i);
                }
            }
            KeyCode::Char('d') => {
                if let Some(RowItem::Item(i)) = self.rows.get(self.selected) {
                    self.form_mode = FormMode::DeleteConfirm(*i);
                }
            }
            KeyCode::Char('r') => self.restart_selected_tunnels(),
            KeyCode::Char('p') => self.flash(
                "tunnels authenticate with a key or an agent — no password is stored",
                false,
            ),
            KeyCode::Char('l') => match self.selected_active_tunnel() {
                Some(_) => self.form_mode = FormMode::Logs,
                None => self.flash("no ssh output — this tunnel is not running", true),
            },
            KeyCode::Char('c') => self.clear_finished_tunnels(),
            _ => {}
        }
    }

    /// The tunnel under the cursor, when there is a running ssh behind it to
    /// show output for.
    pub fn selected_active_tunnel(&self) -> Option<&str> {
        let Some(RowItem::Item(i)) = self.rows.get(self.selected) else {
            return None;
        };
        let name = self.tunnels.get(*i)?.name.as_str();
        self.active.contains_key(name).then_some(name)
    }

    /// `r` on the Tunnels tab: stop and start again what is under the cursor —
    /// every running member when it is a group header.
    fn restart_selected_tunnels(&mut self) {
        let targets: Vec<usize> = match self.rows.get(self.selected).cloned() {
            Some(RowItem::Item(i)) => vec![i],
            Some(RowItem::Group(g)) => self.group_members(&g),
            None => return,
        };
        let running: Vec<usize> = targets
            .into_iter()
            .filter(|i| self.active.contains_key(&self.tunnels[*i].name))
            .collect();
        if running.is_empty() {
            self.flash("nothing running to reconnect here", true);
            return;
        }
        for i in running.iter().copied() {
            let name = self.tunnels[i].name.clone();
            self.stop_tunnel(&name);
            self.start_tunnel(i);
        }
        self.flash(format!("restarted {} tunnel(s)", running.len()), false);
    }

    /// `c` on the Tunnels tab: drop the entries of tunnels that have failed, so
    /// what is left in the list is what is actually running.
    fn clear_finished_tunnels(&mut self) {
        let failed: Vec<String> = self
            .active
            .iter()
            .filter(|(_, a)| a.status == Status::Failed)
            .map(|(n, _)| n.clone())
            .collect();
        if failed.is_empty() {
            self.flash("no failed tunnels to clear", false);
            return;
        }
        for name in &failed {
            self.stop_tunnel(name);
        }
        self.flash(format!("cleared {} failed tunnel(s)", failed.len()), false);
    }

    /// `c` in the tunnel log view: throw away what ssh has said so far.
    fn clear_tunnel_log(&mut self) {
        let Some(name) = self.selected_active_tunnel().map(str::to_string) else {
            return;
        };
        if let Some(active) = self.active.get(&name) {
            active.stderr_log.lock().unwrap().clear();
        }
    }

    // -----------------------------------------------------------------------
    // VPN
    // -----------------------------------------------------------------------

    /// What the provider modules need from the app to act.
    fn vpn_env(&self) -> VpnEnv<'_> {
        VpnEnv {
            cfg: &self.vpn_cfg,
            wireguard_dir: &self.paths.wireguard_dir,
        }
    }

    /// How many profiles the provider under the cursor has.
    fn vpn_profile_count(&self) -> usize {
        self.vpn.current().profiles.len()
    }

    fn on_vpn_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Left => self.vpn.focus = VpnPane::Clients,
            KeyCode::Right => self.vpn.focus = VpnPane::Profiles,
            KeyCode::Down => match self.vpn.focus {
                VpnPane::Clients => {
                    let n = self.vpn.providers.len();
                    self.vpn.client_idx = (self.vpn.client_idx + 1) % n;
                }
                VpnPane::Profiles => {
                    let n = self.vpn_profile_count();
                    if n > 0 {
                        let st = self.vpn.current_mut();
                        st.selected = (st.selected + 1) % n;
                    }
                }
            },
            KeyCode::Up => match self.vpn.focus {
                VpnPane::Clients => {
                    let n = self.vpn.providers.len();
                    self.vpn.client_idx = (self.vpn.client_idx + n - 1) % n;
                }
                VpnPane::Profiles => {
                    let n = self.vpn_profile_count();
                    if n > 0 {
                        let st = self.vpn.current_mut();
                        st.selected = (st.selected + n - 1) % n;
                    }
                }
            },
            KeyCode::Enter | KeyCode::Char(' ') => self.vpn_toggle_selected(),
            KeyCode::Char('a') => self.open_vpn_form(None),
            KeyCode::Char('e') => {
                let idx = self.vpn.current().selected;
                if self.vpn_profile_count() > 0 {
                    self.open_vpn_form(Some(idx));
                }
            }
            KeyCode::Char('d') => {
                let provider = self.vpn.current_id();
                let idx = self.vpn.current().selected;
                if !provider.manages_profiles() {
                    self.flash("netbird profiles are managed by netbird itself", true);
                } else if self.vpn_profile_count() > 0 {
                    self.vpn_mode = VpnMode::DeleteConfirm { provider, idx };
                }
            }
            KeyCode::Char('r') => {
                let id = self.vpn.current_id();
                self.vpn.get_mut(id).error = None;
                self.refresh_provider(id);
                self.flash(format!("refreshing {}", id.slug()), false);
            }
            KeyCode::Char('p') => self.clear_vpn_password(),
            KeyCode::Char('l') => {
                let id = self.vpn.current_id();
                if id == ProviderId::Openvpn {
                    self.vpn_mode = VpnMode::Logs;
                } else {
                    self.flash(
                        format!(
                            "{} keeps no log here — only openvpn runs as a child process",
                            id.slug()
                        ),
                        true,
                    );
                }
            }
            KeyCode::Char('c') => self.clear_vpn_finished(),
            _ => {}
        }
    }

    /// `p` on the VPN tab: forget the password stored for the selected
    /// profile. Only OpenVPN keeps one — WireGuard's secret is a key, and
    /// neither NetBird nor Tailscale holds credentials here.
    fn clear_vpn_password(&mut self) {
        let id = self.vpn.current_id();
        if id != ProviderId::Openvpn {
            self.flash(format!("{} profiles store no password", id.slug()), false);
            return;
        }
        let Some(name) = self
            .vpn
            .current()
            .selected_profile()
            .map(|p| p.name.clone())
        else {
            return;
        };
        let Some(profile) = self.vpn_cfg.openvpn.iter_mut().find(|p| p.name == name) else {
            return;
        };
        if profile.password.is_empty() {
            self.flash(format!("no password stored for '{name}'"), false);
            return;
        }
        profile.password.clear();
        self.save_vpn_cfg();
        self.flash(format!("cleared stored password for '{name}'"), false);
    }

    /// `c` on the VPN tab: drop the client's last error and the entries of
    /// openvpn sessions that have already exited.
    fn clear_vpn_finished(&mut self) {
        let id = self.vpn.current_id();
        let mut cleared = self.vpn.get_mut(id).error.take().is_some();
        if id == ProviderId::Openvpn {
            let exited: Vec<String> = self
                .ovpn_active
                .iter()
                .filter(|(_, a)| matches!(a.status, OvpnStatus::Exited(_)))
                .map(|(n, _)| n.clone())
                .collect();
            for name in &exited {
                self.ovpn_active.remove(name);
            }
            cleared |= !exited.is_empty();
        }
        self.flash(
            if cleared {
                "cleared"
            } else {
                "nothing to clear"
            },
            false,
        );
    }

    /// `c` in the openvpn log view: throw away what the session has said so far.
    fn clear_vpn_log(&mut self) {
        if let Some((_, session)) = self.selected_ovpn() {
            session.log.lock().unwrap().clear();
        }
    }

    /// Fill a provider's profile list straight from `vpn.toml`.
    ///
    /// These profiles are controlcenter's own, so they are listed whether or not
    /// the client is installed — the config can be written before the package is.
    /// A live refresh then overwrites the list with the same names plus their
    /// real active state.
    fn seed_profiles(&mut self, id: ProviderId) {
        let seeded: Vec<VpnProfile> = match id {
            ProviderId::Wireguard => self
                .vpn_cfg
                .wireguard
                .iter()
                .map(|w| VpnProfile {
                    name: w.name.clone(),
                    active: false,
                    detail: w.summary(),
                })
                .collect(),
            ProviderId::Openvpn => {
                self.sync_openvpn();
                return;
            }
            ProviderId::Tailscale => self
                .vpn_cfg
                .tailscale
                .iter()
                .map(|t| VpnProfile {
                    name: t.name.clone(),
                    active: false,
                    detail: String::new(),
                })
                .collect(),
            ProviderId::Netbird => return,
        };
        // Carry the live state over: seeding runs on every poll, and dropping
        // the active flags until the background refresh lands would make the
        // profile list blink.
        let state = self.vpn.get_mut(id);
        state.profiles = seeded
            .into_iter()
            .map(|mut p| {
                if let Some(known) = state.profiles.iter().find(|k| k.name == p.name) {
                    p.active = known.active;
                }
                p
            })
            .collect();
        state.clamp_selection();
    }

    fn refresh_provider(&mut self, id: ProviderId) {
        self.seed_profiles(id);
        if !self.vpn.get(id).installed {
            return;
        }
        self.vpn.get_mut(id).last_refresh = Instant::now();
        if id == ProviderId::Openvpn {
            return;
        }
        let tx = self.vpn_tx.clone();
        vpn::refresh(id, tx, self.vpn_env());
    }

    /// Enter on a profile: bring it up, or take it down if it already is.
    fn vpn_toggle_selected(&mut self) {
        let state = self.vpn.current();
        let already_up = state.selected_profile().map(|p| p.active).unwrap_or(false);
        if already_up {
            self.vpn_disconnect_selected();
        } else {
            self.vpn_connect_selected();
        }
    }

    fn vpn_connect_selected(&mut self) {
        let id = self.vpn.current_id();
        if !self.vpn.get(id).installed {
            self.flash(format!("{} is not installed", id.slug()), true);
            return;
        }
        let profile = self
            .vpn
            .get(id)
            .selected_profile()
            .map(|p| p.name.clone());
        if id == ProviderId::Openvpn {
            match profile {
                Some(name) => self.start_openvpn(&name),
                None => self.flash("no openvpn profile selected", true),
            }
            return;
        }
        let desc = match &profile {
            Some(p) => format!("bringing up '{p}'"),
            None => "connecting".to_string(),
        };
        self.vpn_start(id, desc, profile.as_deref(), true);
    }

    fn vpn_disconnect_selected(&mut self) {
        let id = self.vpn.current_id();
        if !self.vpn.get(id).installed {
            return;
        }
        let profile = self
            .vpn
            .get(id)
            .selected_profile()
            .map(|p| p.name.clone());
        if id == ProviderId::Openvpn {
            match profile {
                Some(name) => self.stop_openvpn(&name),
                None => self.flash("no openvpn profile selected", true),
            }
            return;
        }
        self.vpn_start(id, "disconnecting".into(), profile.as_deref(), false);
    }

    /// Kick off a connect or disconnect and mark the provider busy. One action
    /// per provider at a time, so a slow login cannot be stacked on itself.
    fn vpn_start(&mut self, id: ProviderId, desc: String, profile: Option<&str>, up: bool) {
        if let Some(busy) = &self.vpn.get(id).busy {
            self.flash(format!("{} is busy ({busy})", id.slug()), true);
            return;
        }
        let profile = profile.map(str::to_string);
        let tx = self.vpn_tx.clone();
        let result = {
            let env = self.vpn_env();
            if up {
                vpn::connect(id, tx, env, profile.as_deref())
            } else {
                vpn::disconnect(id, tx, env, profile.as_deref())
            }
        };
        match result {
            Ok(()) => {
                let state = self.vpn.get_mut(id);
                state.error = None;
                state.busy = Some(desc.clone());
                self.flash(format!("{}: {desc}…", id.slug()), false);
            }
            Err(e) => {
                self.vpn.get_mut(id).error = Some(e.clone());
                self.flash(format!("{}: {e}", id.slug()), true);
            }
        }
    }

    // ----- OpenVPN sessions, owned here like RDP sessions -------------------

    fn start_openvpn(&mut self, name: &str) {
        if self
            .ovpn_active
            .get(name)
            .is_some_and(|s| !matches!(s.status, OvpnStatus::Exited(_)))
        {
            self.flash(format!("openvpn '{name}' is already up"), true);
            return;
        }
        let Some(profile) = self
            .vpn_cfg
            .openvpn
            .iter()
            .find(|o| o.name == name)
            .cloned()
        else {
            self.flash(format!("openvpn profile '{name}' no longer exists"), true);
            return;
        };
        match crate::vpn::openvpn::spawn(&profile, &self.paths.openvpn_dir, &self.paths.run_dir) {
            Ok(session) => {
                self.ovpn_active.insert(name.to_string(), session);
                self.flash(format!("openvpn: connecting '{name}'…"), false);
            }
            Err(e) => {
                self.vpn.get_mut(ProviderId::Openvpn).error = Some(e.clone());
                self.flash(format!("openvpn '{name}': {e}"), true);
            }
        }
        self.sync_openvpn();
    }

    fn stop_openvpn(&mut self, name: &str) {
        let Some(mut session) = self.ovpn_active.remove(name) else {
            self.flash(format!("openvpn '{name}' is not running"), true);
            return;
        };
        match session.stop() {
            Some(e) => self.flash(format!("openvpn '{name}': {e}"), true),
            None => self.flash(format!("openvpn: '{name}' stopped"), false),
        }
        self.sync_openvpn();
    }

    /// OpenVPN has no daemon to poll: its state is the sessions being held, so
    /// its [`ProviderState`] is filled in from them rather than over the channel.
    fn sync_openvpn(&mut self) {
        let sessions = &self.ovpn_active;
        let profiles: Vec<VpnProfile> = self
            .vpn_cfg
            .openvpn
            .iter()
            .map(|o| VpnProfile {
                active: sessions.get(&o.name).is_some_and(ActiveOvpn::is_up),
                name: o.name.clone(),
                detail: sessions
                    .get(&o.name)
                    .map(|s| s.status.label())
                    .unwrap_or_else(|| o.summary(&self.paths.openvpn_dir)),
            })
            .collect();

        let live = self
            .vpn_cfg
            .openvpn
            .iter()
            .find(|o| sessions.get(&o.name).is_some_and(ActiveOvpn::is_up));

        let mut status = VpnStatus::default();
        if let Some(o) = live {
            let session = &sessions[&o.name];
            status.connected = true;
            status.active_profile = Some(o.name.clone());
            status.fields.push(("Profile".into(), o.name.clone()));
            status.fields.push(("Config".into(), o.config_path.clone()));
            status.fields.push((
                "Up for".into(),
                ui::fmt_duration(session.started_at.elapsed()),
            ));
            if let Some(line) = session.last_line() {
                status.fields.push(("Last".into(), ui::truncate_pub(&line, 60)));
            }
        } else if let Some((name, session)) = sessions.iter().find(|(_, s)| {
            matches!(s.status, OvpnStatus::Connecting)
        }) {
            status.fields.push(("Profile".into(), name.clone()));
            status.fields.push(("State".into(), session.status.label()));
            if let Some(line) = session.last_line() {
                status.fields.push(("Last".into(), ui::truncate_pub(&line, 60)));
            }
        }

        // A session that openvpn itself said will not work says why.
        let fault = sessions.values().find_map(ActiveOvpn::fault);

        let state = self.vpn.get_mut(ProviderId::Openvpn);
        state.profiles = profiles;
        state.clamp_selection();
        // Keep an error from a failed spawn visible until something else happens.
        let error = fault.or_else(|| state.error.take());
        state.status = status;
        state.error = error;
        state.last_refresh = Instant::now();
    }

    /// The files that came with the selected OpenVPN profile, so the panel can
    /// show what the profile actually consists of rather than just a path.
    pub fn openvpn_import_listing(&self) -> Option<(String, Vec<String>)> {
        let selected = self.vpn.get(ProviderId::Openvpn).selected_profile()?;
        let profile = self
            .vpn_cfg
            .openvpn
            .iter()
            .find(|o| o.name == selected.name)?;
        if !profile.import {
            return None;
        }
        let mut names: Vec<String> = std::fs::read_dir(profile.dir(&self.paths.openvpn_dir))
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        Some((profile.name.clone(), names))
    }

    /// The session shown in the log view.
    pub fn selected_ovpn(&self) -> Option<(&String, &ActiveOvpn)> {
        let name = self.vpn.get(ProviderId::Openvpn).selected_profile()?;
        self.ovpn_active.get_key_value(&name.name)
    }

    // ----- profile forms ----------------------------------------------------

    fn open_vpn_form(&mut self, edit: Option<usize>) {
        let provider = self.vpn.current_id();
        if !provider.manages_profiles() {
            self.flash("netbird profiles are managed by netbird itself", true);
            return;
        }
        self.vpn_form = match (provider, edit) {
            (ProviderId::Wireguard, Some(i)) => match self.vpn_cfg.wireguard.get(i) {
                Some(w) => VpnForm::from_wireguard(w),
                None => return,
            },
            (ProviderId::Openvpn, Some(i)) => match self.vpn_cfg.openvpn.get(i) {
                Some(o) => VpnForm::from_openvpn(o),
                None => return,
            },
            (ProviderId::Tailscale, Some(i)) => match self.vpn_cfg.tailscale.get(i) {
                Some(t) => VpnForm::from_tailscale(t),
                None => return,
            },
            (p, None) => VpnForm::empty(p),
            _ => return,
        };
        self.vpn_mode = VpnMode::Form { provider, edit };
    }

    fn on_vpn_modal_key(&mut self, key: KeyEvent) {
        match self.vpn_mode.clone() {
            VpnMode::None => {}
            VpnMode::Logs => {
                if key.code == KeyCode::Char('c') {
                    self.clear_vpn_log();
                } else if closes_view(key) {
                    self.vpn_mode = VpnMode::None;
                }
            }
            VpnMode::DeleteConfirm { provider, idx } => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        self.delete_vpn_profile(provider, idx)
                    }
                    _ => {}
                }
                self.vpn_mode = VpnMode::None;
            }
            VpnMode::SecretWarning { provider, edit } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.vpn_form.secret_ack = true;
                    self.vpn_mode = VpnMode::Form { provider, edit };
                    self.submit_vpn_form();
                }
                _ => self.vpn_mode = VpnMode::Form { provider, edit },
            },
            VpnMode::Form { .. } => match key.code {
                KeyCode::Esc => self.vpn_mode = VpnMode::None,
                KeyCode::Enter => self.submit_vpn_form(),
                KeyCode::Tab | KeyCode::Down => self.vpn_form.next_field(),
                KeyCode::BackTab | KeyCode::Up => self.vpn_form.prev_field(),
                KeyCode::Left | KeyCode::Right => self.vpn_form.toggle(),
                KeyCode::Backspace => {
                    if let Some(t) = self.vpn_form.active_text_mut() {
                        t.pop();
                    }
                }
                KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_path_browser()
                }
                KeyCode::Char(c) => self.on_vpn_form_char(c),
                _ => {}
            },
        }
    }

    fn on_vpn_form_char(&mut self, c: char) {
        // `g` on the private-key field generates a keypair instead of typing a g.
        if self.vpn_form.provider == ProviderId::Wireguard
            && self.vpn_form.field().is_some_and(|f| f.id == "private_key")
            && c == 'g'
        {
            match wireguard::generate_keypair() {
                Ok((private, public)) => {
                    self.vpn_form.set("private_key", private);
                    self.vpn_form.secret_ack = false;
                    self.flash(format!("generated a key — its public half is {public}"), false);
                }
                Err(e) => self.vpn_form.error = Some(e),
            }
            return;
        }
        if let Some(t) = self.vpn_form.active_text_mut() {
            t.push(c);
        }
    }

    fn submit_vpn_form(&mut self) {
        let VpnMode::Form { provider, edit } = self.vpn_mode.clone() else {
            return;
        };
        // Saving a key or a password in the clear is asked about once per edit.
        if self.vpn_form.stores_secret() && !self.vpn_form.secret_ack {
            self.vpn_mode = VpnMode::SecretWarning { provider, edit };
            return;
        }
        let result = match provider {
            ProviderId::Wireguard => self
                .vpn_form
                .to_wireguard()
                .and_then(|w| self.store_wireguard(w, edit)),
            ProviderId::Openvpn => self
                .vpn_form
                .to_openvpn()
                .and_then(|o| self.store_openvpn(o, edit)),
            ProviderId::Tailscale => self
                .vpn_form
                .to_tailscale()
                .and_then(|t| self.store_tailscale(t, edit)),
            ProviderId::Netbird => Err("netbird profiles are managed by netbird".into()),
        };
        match result {
            Ok(name) => {
                self.vpn_mode = VpnMode::None;
                self.save_vpn_cfg();
                self.refresh_provider(provider);
                self.flash(format!("{}: saved '{name}'", provider.slug()), false);
            }
            Err(e) => self.vpn_form.error = Some(e),
        }
    }

    /// A profile name is its identity everywhere else — in `requires_vpn`, and
    /// for WireGuard in the interface it creates — so it has to stay unique.
    fn name_taken(existing: &[String], name: &str, edit: Option<usize>) -> bool {
        existing
            .iter()
            .enumerate()
            .any(|(i, n)| n == name && Some(i) != edit)
    }

    fn store_wireguard(&mut self, w: WireguardProfile, edit: Option<usize>) -> Result<String, String> {
        let names: Vec<String> = self.vpn_cfg.wireguard.iter().map(|p| p.name.clone()).collect();
        if Self::name_taken(&names, &w.name, edit) {
            return Err(format!("a wireguard profile named '{}' already exists", w.name));
        }
        let name = w.name.clone();
        match edit {
            Some(i) => {
                let old = self.vpn_cfg.wireguard[i].clone();
                // A rename leaves a stale config behind under the old name.
                if old.name != w.name {
                    wireguard::remove_conf(&old, &self.paths.wireguard_dir);
                    self.rename_vpn_requirement(ProviderId::Wireguard, &old.name, &w.name);
                }
                self.vpn_cfg.wireguard[i] = w.clone();
            }
            None => self.vpn_cfg.wireguard.push(w.clone()),
        }
        if !w.external() {
            wireguard::write_conf(&w, &self.paths.wireguard_dir)?;
        }
        Ok(name)
    }

    fn store_openvpn(&mut self, o: OpenvpnProfile, edit: Option<usize>) -> Result<String, String> {
        let names: Vec<String> = self.vpn_cfg.openvpn.iter().map(|p| p.name.clone()).collect();
        if Self::name_taken(&names, &o.name, edit) {
            return Err(format!("an openvpn profile named '{}' already exists", o.name));
        }
        let name = o.name.clone();
        if let Some(i) = edit {
            let old = self.vpn_cfg.openvpn[i].clone();
            if old.name != o.name {
                self.rename_vpn_requirement(ProviderId::Openvpn, &old.name, &o.name);
                if let Some(session) = self.ovpn_active.remove(&old.name) {
                    self.ovpn_active.insert(o.name.clone(), session);
                }
            }
            // A rename or a switch to running the file in place leaves the old
            // import behind; drop it rather than orphaning certificates.
            if old.name != o.name || (old.import && !o.import) {
                openvpn::remove_import(&old, &self.paths.openvpn_dir);
            }
        }
        let note = self.import_openvpn(&o)?;
        match edit {
            Some(i) => self.vpn_cfg.openvpn[i] = o,
            None => self.vpn_cfg.openvpn.push(o),
        }
        if let Some(note) = note {
            self.flash(note, false);
        }
        Ok(name)
    }

    /// Copy a profile's `.ovpn` and every certificate it names into
    /// controlcenter's own directory. Returns what to tell the user about it.
    ///
    /// A source that has since been moved or deleted is not an error as long as
    /// the profile was imported once already — that is the whole point of having
    /// imported it.
    fn import_openvpn(&mut self, o: &OpenvpnProfile) -> Result<Option<String>, String> {
        if !o.import {
            return match std::path::Path::new(&o.config_path).is_file() {
                true => Ok(None),
                false => Err(format!("{} does not exist", o.config_path)),
            };
        }
        let source = std::path::Path::new(&o.config_path);
        let dir = o.dir(&self.paths.openvpn_dir);
        if !source.is_file() {
            return if o.runtime_config(&self.paths.openvpn_dir).is_file() {
                Ok(Some(format!(
                    "'{}' kept its imported copy — {} is gone",
                    o.name, o.config_path
                )))
            } else {
                Err(format!("{} does not exist", o.config_path))
            };
        }
        let plan = openvpn::import_into(source, &dir, OpenvpnProfile::CONFIG_NAME)?;
        let missing = plan.missing();
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|f| f.original.as_str()).collect();
            return Err(format!(
                "the config needs {} which {} not next to it",
                names.join(", "),
                if names.len() == 1 { "is" } else { "are" }
            ));
        }
        Ok(Some(match plan.found() {
            0 => format!("imported '{}' (everything is inline)", o.name),
            n => format!("imported '{}' with {n} file(s)", o.name),
        }))
    }

    fn store_tailscale(&mut self, t: TailscaleProfile, edit: Option<usize>) -> Result<String, String> {
        let names: Vec<String> = self.vpn_cfg.tailscale.iter().map(|p| p.name.clone()).collect();
        if Self::name_taken(&names, &t.name, edit) {
            return Err(format!("a tailscale profile named '{}' already exists", t.name));
        }
        let name = t.name.clone();
        match edit {
            Some(i) => {
                let old = self.vpn_cfg.tailscale[i].name.clone();
                if old != t.name {
                    self.rename_vpn_requirement(ProviderId::Tailscale, &old, &t.name);
                }
                self.vpn_cfg.tailscale[i] = t;
            }
            None => self.vpn_cfg.tailscale.push(t),
        }
        Ok(name)
    }

    /// Follow a renamed profile through everything that requires it, the way
    /// renaming a tunnel already updates what depends on it.
    fn rename_vpn_requirement(&mut self, provider: ProviderId, from: &str, to: &str) {
        let old = format!("{}:{from}", provider.slug());
        let new = format!("{}:{to}", provider.slug());
        let mut touched = false;
        for t in &mut self.tunnels {
            if canonical_vpn_requirement(&t.requires_vpn) == old {
                t.requires_vpn = new.clone();
                touched = true;
            }
        }
        for h in &mut self.ssh_hosts {
            if canonical_vpn_requirement(&h.requires_vpn) == old {
                h.requires_vpn = new.clone();
                touched = true;
            }
        }
        for c in &mut self.rdp_conns {
            if canonical_vpn_requirement(&c.requires_vpn) == old {
                c.requires_vpn = new.clone();
                touched = true;
            }
        }
        if touched {
            self.save_tunnels();
            self.save_ssh_hosts();
            self.save_rdp_conns();
        }
    }

    fn delete_vpn_profile(&mut self, provider: ProviderId, idx: usize) {
        let name = match provider {
            ProviderId::Wireguard => {
                if idx >= self.vpn_cfg.wireguard.len() {
                    return;
                }
                let w = self.vpn_cfg.wireguard.remove(idx);
                wireguard::remove_conf(&w, &self.paths.wireguard_dir);
                w.name
            }
            ProviderId::Openvpn => {
                if idx >= self.vpn_cfg.openvpn.len() {
                    return;
                }
                let o = self.vpn_cfg.openvpn.remove(idx);
                if let Some(mut session) = self.ovpn_active.remove(&o.name) {
                    session.stop();
                }
                openvpn::remove_import(&o, &self.paths.openvpn_dir);
                o.name
            }
            ProviderId::Tailscale => {
                if idx >= self.vpn_cfg.tailscale.len() {
                    return;
                }
                self.vpn_cfg.tailscale.remove(idx).name
            }
            ProviderId::Netbird => return,
        };
        self.save_vpn_cfg();
        self.refresh_provider(provider);
        // A dangling requirement is left visible and marked missing, the same
        // way a deleted tunnel is.
        self.flash(format!("{}: deleted '{name}'", provider.slug()), false);
    }

    fn save_vpn_cfg(&mut self) {
        if let Err(e) = config::save_vpn(&self.paths.vpn_file, &self.vpn_cfg) {
            self.flash(format!("could not save vpn.toml: {e}"), true);
        }
    }

    // -----------------------------------------------------------------------
    // RDP
    // -----------------------------------------------------------------------

    fn on_rdp_key(&mut self, key: KeyEvent) {
        let count = self.rdp_rows.len();
        match key.code {
            KeyCode::Down if count > 0 => {
                self.rdp_selected = (self.rdp_selected + 1) % count;
            }
            KeyCode::Up if count > 0 => {
                self.rdp_selected = (self.rdp_selected + count - 1) % count;
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_selected_rdp(),
            KeyCode::Char('a') => {
                let mut form = RdpForm::empty(self.form_ctx());
                // Pre-fill the group when a group row or grouped connection is selected.
                match self.rdp_rows.get(self.rdp_selected) {
                    Some(RowItem::Group(g)) => form.group = g.clone(),
                    Some(RowItem::Item(i)) => form.group = self.rdp_conns[*i].group.clone(),
                    None => {}
                }
                self.rdp_form = form;
                self.rdp_mode = RdpMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(i) = self.selected_rdp_conn() {
                    let form = RdpForm::from_connection(&self.rdp_conns[i], self.form_ctx());
                    self.rdp_form = form;
                    self.rdp_mode = RdpMode::Edit(i);
                }
            }
            KeyCode::Char('d') => {
                if let Some(i) = self.selected_rdp_conn() {
                    self.rdp_mode = RdpMode::DeleteConfirm(i);
                }
            }
            KeyCode::Char('r') => self.reconnect_selected_rdp(),
            KeyCode::Char('p') => self.flash(
                "the RDP password is asked for on connect and never stored",
                false,
            ),
            KeyCode::Char('l') => {
                if let Some(i) = self.selected_rdp_conn() {
                    if self.rdp_active.contains_key(&self.rdp_conns[i].name) {
                        self.rdp_mode = RdpMode::Logs;
                    } else {
                        self.flash("no session (and no logs) for this connection", true);
                    }
                }
            }
            KeyCode::Char('c') => {
                // Clear a finished session entry (keeps running ones).
                if let Some(i) = self.selected_rdp_conn() {
                    let name = self.rdp_conns[i].name.clone();
                    if matches!(
                        self.rdp_active.get(&name).map(|a| a.status),
                        Some(RdpStatus::Exited(_))
                    ) {
                        self.rdp_active.remove(&name);
                    }
                }
            }
            _ => {}
        }
    }

    /// `r` on the RDP tab: drop the running session and connect again — which
    /// asks for the password a second time, because xfreerdp is handed it on
    /// stdin at start and nothing keeps a copy.
    fn reconnect_selected_rdp(&mut self) {
        let targets: Vec<usize> = match self.rdp_rows.get(self.rdp_selected).cloned() {
            Some(RowItem::Item(i)) => vec![i],
            Some(RowItem::Group(g)) => self.rdp_group_members(&g),
            None => return,
        };
        let running: Vec<usize> = targets
            .into_iter()
            .filter(|i| self.rdp_running(&self.rdp_conns[*i].name))
            .collect();
        if running.is_empty() {
            self.flash("nothing running to reconnect here", true);
            return;
        }
        for i in running.iter().copied() {
            let name = self.rdp_conns[i].name.clone();
            if let Some(mut a) = self.rdp_active.remove(&name) {
                a.stop();
            }
        }
        self.rdp_mode = RdpMode::Password {
            pending: running,
            collected: Vec::new(),
            input: String::new(),
        };
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
            RdpMode::Password {
                mut pending,
                mut collected,
                mut input,
            } => match key.code {
                // Esc drops the whole group, not just the one being asked about.
                KeyCode::Esc => self.rdp_mode = RdpMode::None,
                KeyCode::Enter => {
                    if pending.is_empty() {
                        self.rdp_mode = RdpMode::None;
                        return;
                    }
                    let idx = pending.remove(0);
                    if let Some(c) = self.rdp_conns.get(idx) {
                        collected.push(Step::Rdp {
                            name: c.name.clone(),
                            password: input.clone(),
                        });
                    }
                    if pending.is_empty() {
                        self.rdp_mode = RdpMode::None;
                        if !collected.is_empty() {
                            self.activate(collected);
                        }
                    } else {
                        // On to the next member of the group.
                        self.rdp_mode = RdpMode::Password {
                            pending,
                            collected,
                            input: String::new(),
                        };
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                    self.rdp_mode = RdpMode::Password {
                        pending,
                        collected,
                        input,
                    };
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    self.rdp_mode = RdpMode::Password {
                        pending,
                        collected,
                        input,
                    };
                }
                _ => {}
            },
            RdpMode::Logs => {
                if key.code == KeyCode::Char('c') {
                    self.clear_rdp_log();
                } else if closes_view(key) {
                    self.rdp_mode = RdpMode::None;
                }
            }
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

    /// Enter on the RDP tab: connect or disconnect the selected connection,
    /// or the whole group under a group header.
    fn toggle_selected_rdp(&mut self) {
        let targets: Vec<usize> = match self.rdp_rows.get(self.rdp_selected).cloned() {
            Some(RowItem::Item(i)) => vec![i],
            Some(RowItem::Group(g)) => self.rdp_group_members(&g),
            None => return,
        };
        if targets.is_empty() {
            return;
        }
        // Anything already up is stopped; otherwise everything idle is started.
        let running: Vec<usize> = targets
            .iter()
            .copied()
            .filter(|i| self.rdp_running(&self.rdp_conns[*i].name))
            .collect();
        if !running.is_empty() && running.len() == targets.len() {
            for i in running {
                let name = self.rdp_conns[i].name.clone();
                if let Some(mut a) = self.rdp_active.remove(&name) {
                    a.stop();
                }
                self.flash(format!("disconnected '{name}'"), false);
            }
            return;
        }
        if !self.rdp_installed {
            self.flash("xfreerdp3 not found on PATH", true);
            return;
        }
        // Members that are already up stay up; the rest are asked for a
        // password in turn and then started together.
        let pending: Vec<usize> = targets
            .into_iter()
            .filter(|i| !self.rdp_running(&self.rdp_conns[*i].name))
            .collect();
        if pending.is_empty() {
            return;
        }
        self.rdp_mode = RdpMode::Password {
            pending,
            collected: Vec::new(),
            input: String::new(),
        };
    }

    /// `c` in the RDP log view: throw away what the session has said so far.
    fn clear_rdp_log(&mut self) {
        let Some(i) = self.selected_rdp_conn() else {
            return;
        };
        let name = self.rdp_conns[i].name.clone();
        if let Some(active) = self.rdp_active.get(&name) {
            active.log.lock().unwrap().clear();
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
        let idx = editing.unwrap_or(self.rdp_conns.len() - 1);
        self.rdp_mode = RdpMode::None;
        self.rebuild_rdp_rows();
        // Grouping it moved its row; follow it.
        if let Some(row) = self.rdp_rows.iter().position(|r| r == &RowItem::Item(idx)) {
            self.rdp_selected = row;
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
        self.rebuild_rdp_rows();
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
        let count = self.ssh_rows.len();
        match key.code {
            KeyCode::Down if count > 0 => {
                self.ssh_selected = (self.ssh_selected + 1) % count;
            }
            KeyCode::Up if count > 0 => {
                self.ssh_selected = (self.ssh_selected + count - 1) % count;
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.open_selected_ssh(),
            KeyCode::Char('a') => {
                let mut form = SshForm::empty(self.form_ctx());
                // Pre-fill the group when a group row or grouped host is selected.
                match self.ssh_rows.get(self.ssh_selected) {
                    Some(RowItem::Group(g)) => form.group = g.clone(),
                    Some(RowItem::Item(i)) => form.group = self.ssh_hosts[*i].group.clone(),
                    None => {}
                }
                self.ssh_form = form;
                self.ssh_mode = SshMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(i) = self.selected_ssh_host() {
                    let form = SshForm::from_host(&self.ssh_hosts[i], self.form_ctx());
                    self.ssh_form = form;
                    self.ssh_mode = SshMode::Edit(i);
                }
            }
            KeyCode::Char('d') => {
                if let Some(i) = self.selected_ssh_host() {
                    self.ssh_mode = SshMode::DeleteConfirm(i);
                }
            }
            // A session is a window of its own, so reconnecting is opening
            // another one — the same thing Enter does.
            KeyCode::Char('r') => self.open_selected_ssh(),
            KeyCode::Char('p') => self.clear_stored_password(),
            KeyCode::Char('l') => self.show_ssh_outcome(),
            KeyCode::Char('c') => self.clear_finished_ssh(),
            _ => {}
        }
    }

    /// `l` on the SSH tab. The session runs in a terminal window of its own, so
    /// its output is there rather than here; what controlcenter knows is how
    /// the last one ended.
    fn show_ssh_outcome(&mut self) {
        let Some(i) = self.selected_ssh_host() else {
            return;
        };
        let name = self.ssh_hosts[i].name.clone();
        match self.ssh_last.get(&name) {
            Some(outcome) => {
                let label = outcome.label();
                self.flash(
                    format!("'{name}': {label} — a session's output stays in its own window"),
                    false,
                )
            }
            None => self.flash(
                "sessions run in a terminal window of their own — no log is kept here",
                false,
            ),
        }
    }

    /// `c` on the SSH tab: forget how the selected host's last session ended.
    fn clear_finished_ssh(&mut self) {
        let Some(i) = self.selected_ssh_host() else {
            return;
        };
        let name = self.ssh_hosts[i].name.clone();
        if self.ssh_last.remove(&name).is_some() {
            self.flash(format!("cleared the last session of '{name}'"), false);
        } else {
            self.flash("nothing finished to clear", false);
        }
    }

    /// Enter on the SSH tab: open a session for the selected host, or one for
    /// every member of the group under a group header. A group goes into a
    /// single plan, so a VPN or tunnel they share is brought up once.
    fn open_selected_ssh(&mut self) {
        let steps: Vec<Step> = match self.ssh_rows.get(self.ssh_selected).cloned() {
            Some(RowItem::Item(i)) => vec![Step::Ssh(self.ssh_hosts[i].name.clone())],
            Some(RowItem::Group(g)) => self
                .ssh_group_members(&g)
                .into_iter()
                .map(|i| Step::Ssh(self.ssh_hosts[i].name.clone()))
                .collect(),
            None => return,
        };
        if !steps.is_empty() {
            self.activate(steps);
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
                KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_path_browser()
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
        let idx = match editing {
            Some(i) => {
                self.ssh_hosts[i] = host;
                i
            }
            None => {
                self.ssh_hosts.push(host);
                self.ssh_hosts.len() - 1
            }
        };
        self.ssh_mode = SshMode::None;
        self.rebuild_ssh_rows();
        // Grouping it moved its row; follow it rather than leave the cursor
        // sitting on whatever took its place.
        if let Some(row) = self.ssh_rows.iter().position(|r| r == &RowItem::Item(idx)) {
            self.ssh_selected = row;
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
        self.rebuild_ssh_rows();
        self.save_ssh_hosts();
        self.flash(format!("deleted '{name}'"), false);
    }

    /// Drop a stored cleartext password without opening the form.
    fn clear_stored_password(&mut self) {
        let Some(idx) = self.selected_ssh_host() else {
            return;
        };
        let Some(h) = self.ssh_hosts.get_mut(idx) else {
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

    fn save_tunnels(&mut self) {
        if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
            self.flash(format!("save failed: {e}"), true);
        }
    }

    fn save_rdp_conns(&mut self) {
        if let Err(e) = config::save_rdp(&self.paths.rdp_file, &self.rdp_conns) {
            self.flash(format!("save failed: {e}"), true);
        }
    }

    /// Open a session: in a window of its own, so the TUI stays usable, or —
    /// when there is no terminal emulator to open one with — by handing this
    /// terminal to ssh until the session ends.
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

        match self.ssh_launcher.clone() {
            ssh::Launch::Window(term) => {
                match ssh::spawn_windowed(&host, &term) {
                    Ok(session) => {
                        self.ssh_windows
                            .entry(host.name.clone())
                            .or_default()
                            .push(session);
                        self.ssh_last.remove(&host.name);
                        let msg = format!("'{}' opened in a new {} window", host.name, term.name());
                        self.flash(msg, false);
                    }
                    Err(e) => self.flash(format!("'{}': {e:#}", host.name), true),
                }
                return Ok(());
            }
            ssh::Launch::Inline => {}
        }

        crate::suspend_terminal(terminal)?;
        println!("── controlcenter: {} ──", ssh::command_preview(&host));
        let result = ssh::run_interactive(&host);
        crate::resume_terminal(terminal)?;

        match result {
            Ok(outcome) => {
                let msg = format!("'{}' session {}", host.name, outcome.label());
                self.ssh_last.insert(host.name.clone(), outcome);
                self.flash(msg, outcome.failed());
            }
            Err(e) => self.flash(format!("'{}': {e:#}", host.name), true),
        }
        Ok(())
    }

    /// How many windows are currently open for a host.
    pub fn ssh_windows_open(&self, name: &str) -> usize {
        self.ssh_windows.get(name).map(Vec::len).unwrap_or(0)
    }

    /// Reap the windows that were closed since the last tick.
    fn poll_ssh_windows(&mut self) {
        let mut finished: Vec<(String, SessionOutcome)> = Vec::new();
        for (name, sessions) in self.ssh_windows.iter_mut() {
            sessions.retain_mut(|s| match s.poll() {
                Some(outcome) => {
                    finished.push((name.clone(), outcome));
                    false
                }
                None => true,
            });
        }
        self.ssh_windows.retain(|_, v| !v.is_empty());
        for (name, outcome) in finished {
            self.ssh_last.insert(name, outcome);
        }
    }

    // -----------------------------------------------------------------------
    // File picker
    // -----------------------------------------------------------------------

    /// Ctrl+O over a path field opens the picker on the value it already holds.
    fn open_path_browser(&mut self) {
        match self.active_path_value() {
            Some(current) => self.browser = Some(FileBrowser::open(&current)),
            None => self.flash("Ctrl+O picks a file — only on the path fields", false),
        }
    }

    /// The value of the path field under the cursor, if the field takes a path.
    fn active_path_value(&self) -> Option<String> {
        if matches!(self.ssh_mode, SshMode::Add | SshMode::Edit(_)) {
            return (self.ssh_form.field() == SshField::KeyPath)
                .then(|| self.ssh_form.key_path.clone());
        }
        if matches!(self.vpn_mode, VpnMode::Form { .. }) {
            let spec = self.vpn_form.field()?;
            return (spec.id == "config_path")
                .then(|| self.vpn_form.str_value("config_path").to_string());
        }
        None
    }

    fn on_browser_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.browser = None;
            return;
        }
        let picked = {
            let Some(b) = self.browser.as_mut() else {
                return;
            };
            match key.code {
                KeyCode::Down | KeyCode::Tab => {
                    b.down();
                    None
                }
                KeyCode::Up | KeyCode::BackTab => {
                    b.up();
                    None
                }
                // Left and right walk the tree; there is no cursor to move.
                KeyCode::Right => {
                    b.descend();
                    None
                }
                KeyCode::Left => {
                    b.ascend();
                    None
                }
                KeyCode::Backspace => {
                    b.backspace();
                    None
                }
                KeyCode::Enter => b.accept(),
                // Ctrl+O opened this; don't type an o with it.
                KeyCode::Char(_) if key.modifiers.contains(KeyModifiers::CONTROL) => None,
                KeyCode::Char(c) => {
                    b.push(c);
                    None
                }
                _ => None,
            }
        };
        if let Some(path) = picked {
            self.browser = None;
            if let Some(text) = self.active_form_text_mut() {
                *text = path;
            }
        }
    }

    /// The text field of whichever form the picker was opened from.
    fn active_form_text_mut(&mut self) -> Option<&mut String> {
        if matches!(self.ssh_mode, SshMode::Add | SshMode::Edit(_)) {
            return self.ssh_form.active_text_mut();
        }
        if matches!(self.vpn_mode, VpnMode::Form { .. }) {
            return self.vpn_form.active_text_mut();
        }
        None
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

    /// The profile a provider currently has up.
    pub fn active_vpn_profile(&self, provider: ProviderId) -> Option<String> {
        self.vpn.get(provider).active_profile().map(str::to_string)
    }

    /// Whether a VPN already satisfies the requirement.
    pub fn vpn_satisfied(&self, want: &str) -> bool {
        let Some(req) = parse_vpn_requirement(want) else {
            return true;
        };
        let Some(provider) = req.provider else {
            // Any VPN at all will do.
            return self.vpn.providers.iter().any(|p| p.status.connected);
        };
        let state = self.vpn.get(provider);
        if !state.status.connected {
            return false;
        }
        match &req.profile {
            None => true,
            Some(name) => {
                // WireGuard and OpenVPN can hold several at once, so the profile
                // list is the truth there, not a single "active" field.
                state.profiles.iter().any(|p| p.active && &p.name == name)
                    || state.active_profile() == Some(name.as_str())
            }
        }
    }

    /// Which provider a bare `*` requirement should bring up. NetBird first,
    /// because that is what `*` meant when it was the only provider; otherwise
    /// the only unambiguous choice there is.
    fn provider_for_any_vpn(&self) -> Result<(ProviderId, Option<String>), String> {
        if self.vpn.get(ProviderId::Netbird).installed {
            return Ok((ProviderId::Netbird, None));
        }
        let candidates: Vec<&ProviderState> = self
            .vpn
            .providers
            .iter()
            .filter(|p| p.installed && p.profiles.len() == 1)
            .collect();
        match candidates.as_slice() {
            [only] => Ok((only.id, Some(only.profiles[0].name.clone()))),
            [] => Err("no VPN client is installed".into()),
            _ => Err("several VPNs could satisfy '*' — name one, e.g. wireguard:home".into()),
        }
    }

    fn step_state(&self, step: &Step) -> StepState {
        match step {
            Step::Vpn(req) => {
                if self.vpn_satisfied(req) {
                    return StepState::Ready;
                }
                match parse_vpn_requirement(req).and_then(|r| r.provider) {
                    Some(id) => {
                        let state = self.vpn.get(id);
                        if !state.installed {
                            StepState::Failed(format!("{} is not installed", id.slug()))
                        } else if let Some(e) = &state.error {
                            StepState::Failed(e.clone())
                        } else {
                            StepState::Waiting
                        }
                    }
                    None if !self.vpn.any_installed() => {
                        StepState::Failed("no VPN client is installed".into())
                    }
                    None => StepState::Waiting,
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
            Step::Vpn(req) => {
                let parsed = parse_vpn_requirement(req);
                let Some(parsed) = parsed else {
                    return StartOutcome::Failed("empty VPN requirement".into());
                };
                let (id, profile) = match parsed.provider {
                    Some(id) => (id, parsed.profile.clone()),
                    // "any VPN": choose one rather than guess between several.
                    None => match self.provider_for_any_vpn() {
                        Ok(choice) => choice,
                        Err(e) => return StartOutcome::Failed(e),
                    },
                };
                if !self.vpn.get(id).installed {
                    return StartOutcome::Failed(format!("{} is not installed", id.slug()));
                }
                if id == ProviderId::Openvpn {
                    let Some(name) = profile else {
                        return StartOutcome::Failed(
                            "openvpn needs a named profile, e.g. openvpn:work".into(),
                        );
                    };
                    self.start_openvpn(&name);
                    return match self.ovpn_active.contains_key(&name) {
                        true => StartOutcome::Started,
                        false => StartOutcome::Failed(format!("openvpn '{name}' would not start")),
                    };
                }
                if self.vpn.get(id).busy.is_some() {
                    // Another action on this provider is still running.
                    return StartOutcome::Retry;
                }
                // wg-quick and tailscale need to be told which profile; netbird
                // can just be brought up on whatever it already has selected.
                let profile = match (profile, id) {
                    (Some(p), _) => Some(p),
                    (None, ProviderId::Netbird) => None,
                    (None, _) => match self.vpn.get(id).profiles.as_slice() {
                        [only] => Some(only.name.clone()),
                        _ => {
                            return StartOutcome::Failed(format!(
                                "{} needs a named profile, e.g. {}:<name>",
                                id.slug(),
                                id.slug()
                            ))
                        }
                    },
                };
                let desc = match &profile {
                    Some(p) => format!("bringing up '{p}'"),
                    None => "connecting".to_string(),
                };
                let tx = self.vpn_tx.clone();
                let result = {
                    let env = self.vpn_env();
                    vpn::connect(id, tx, env, profile.as_deref())
                };
                match result {
                    Ok(()) => {
                        let state = self.vpn.get_mut(id);
                        state.error = None;
                        state.busy = Some(desc);
                        StartOutcome::Started
                    }
                    Err(e) => StartOutcome::Failed(e),
                }
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
                    self.ssh_launch.push_back(name.clone());
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
            Step::Vpn(req) => {
                // Only providers that can hold one profile at a time conflict.
                // WireGuard interfaces and OpenVPN sessions coexist happily.
                let parsed = parse_vpn_requirement(req)?;
                let id = parsed.provider.filter(|p| p.exclusive())?;
                let wanted = parsed.profile?;
                let current = self.active_vpn_profile(id)?;
                if current == wanted {
                    return None;
                }
                // Switching profiles cuts anything that asked for the old one.
                let old = format!("{}:{current}", id.slug());
                let requires_old =
                    |req: &str| canonical_vpn_requirement(req) == old;
                let stop_tunnels: Vec<String> = self
                    .tunnels
                    .iter()
                    .filter(|t| requires_old(&t.requires_vpn) && self.active.contains_key(&t.name))
                    .map(|t| t.name.clone())
                    .collect();
                let stop_rdp: Vec<String> = self
                    .rdp_conns
                    .iter()
                    .filter(|c| requires_old(&c.requires_vpn) && self.rdp_running(&c.name))
                    .map(|c| c.name.clone())
                    .collect();
                Some(ConflictPrompt {
                    step: step.clone(),
                    resource: format!("the active {} profile", id.slug()),
                    stop_tunnels,
                    stop_rdp,
                    note: Some(format!(
                        "{} profile '{current}' → '{wanted}'",
                        id.slug()
                    )),
                })
            }
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

    /// Everything that asks for exactly this VPN requirement, for the VPN tab.
    /// `want` is compared in canonical form, so a legacy bare profile name and
    /// `netbird:<name>` count as the same requirement.
    pub fn vpn_dependents_of(&self, want: &str) -> Vec<String> {
        let want = canonical_vpn_requirement(want);
        let matches = |req: &str| canonical_vpn_requirement(req) == want;
        let mut names: Vec<String> = self
            .tunnels
            .iter()
            .filter(|t| matches(&t.requires_vpn))
            .map(|t| format!("tun {}", t.name))
            .collect();
        names.extend(
            self.ssh_hosts
                .iter()
                .filter(|h| matches(&h.requires_vpn))
                .map(|h| format!("ssh {}", h.name)),
        );
        names.extend(
            self.rdp_conns
                .iter()
                .filter(|c| matches(&c.requires_vpn))
                .map(|c| format!("rdp {}", c.name)),
        );
        names
    }

    /// Everything that asks for any profile of `provider`, or for any VPN at all.
    pub fn vpn_dependents_of_provider(&self, provider: ProviderId) -> Vec<String> {
        let wants = |req: &str| {
            parse_vpn_requirement(req)
                .map(|r| r.provider.is_none() || r.provider == Some(provider))
                .unwrap_or(false)
        };
        let mut names: Vec<String> = self
            .tunnels
            .iter()
            .filter(|t| wants(&t.requires_vpn))
            .map(|t| format!("tun {}", t.name))
            .collect();
        names.extend(
            self.ssh_hosts
                .iter()
                .filter(|h| wants(&h.requires_vpn))
                .map(|h| format!("ssh {}", h.name)),
        );
        names.extend(
            self.rdp_conns
                .iter()
                .filter(|c| wants(&c.requires_vpn))
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
            Some(RowItem::Item(i)) => {
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
        self.poll_ssh_windows();
        for session in self.ovpn_active.values_mut() {
            session.poll();
        }
        self.sync_openvpn();

        self.drain_vpn();
        // Poll each installed provider on its own clock, and never while one of
        // its own actions is still in flight.
        let due: Vec<ProviderId> = self
            .vpn
            .providers
            .iter()
            .filter(|p| {
                p.installed
                    && p.id != ProviderId::Openvpn
                    && p.busy.is_none()
                    && p.last_refresh.elapsed() >= Duration::from_secs(VPN_REFRESH_SECS)
            })
            .map(|p| p.id)
            .collect();
        for id in due {
            self.refresh_provider(id);
        }

        self.handle_reconnects();
        self.advance_activation();

        if let Some((_, _, at)) = &self.status_msg {
            if at.elapsed() > Duration::from_secs(6) {
                self.status_msg = None;
            }
        }
    }

    fn drain_vpn(&mut self) {
        while let Ok(msg) = self.vpn_rx.try_recv() {
            let id = msg.provider();
            match msg {
                VpnMsg::Refreshed {
                    profiles, status, ..
                } => {
                    let state = self.vpn.get_mut(id);
                    match profiles {
                        Ok(p) => {
                            state.profiles = p;
                            state.clamp_selection();
                            state.error = None;
                        }
                        Err(e) => state.error = Some(e),
                    }
                    state.status = status;
                    state.last_refresh = Instant::now();
                }
                VpnMsg::ActionDone { desc, error, .. } => {
                    self.vpn.get_mut(id).busy = None;
                    match error {
                        Some(e) => {
                            self.vpn.get_mut(id).error = Some(e.clone());
                            self.flash(format!("{} {desc} failed: {e}", id.slug()), true);
                        }
                        None => self.flash(format!("{}: {desc} done", id.slug()), false),
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
            group: String::new(),
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

    /// A view with one provider marked installed and given some profiles, so
    /// the picker and the plan can be exercised without any VPN client present.
    fn view_with(entries: &[(ProviderId, &[&str])]) -> VpnView {
        let mut view = VpnView::new();
        for state in &mut view.providers {
            state.installed = false;
            state.profiles.clear();
        }
        for (id, names) in entries {
            let state = &mut view.providers[id.index()];
            state.installed = true;
            state.profiles = names
                .iter()
                .map(|n| VpnProfile {
                    name: (*n).to_string(),
                    active: false,
                    detail: String::new(),
                })
                .collect();
        }
        view
    }

    #[test]
    fn vpn_picker_offers_none_any_vpn_and_every_provider_profile() {
        let view = view_with(&[
            (ProviderId::Netbird, &["work", "home"]),
            (ProviderId::Wireguard, &["office"]),
        ]);
        let p = Picker::vpn(&view, VPN_ANY);
        assert_eq!(p.label(), "any VPN");
        assert_eq!(
            p.options,
            vec![
                "",
                "*",
                "netbird:*",
                "netbird:work",
                "netbird:home",
                "wireguard:*",
                "wireguard:office",
            ]
        );
    }

    #[test]
    fn the_picker_shows_a_legacy_bare_name_as_the_netbird_profile_it_means() {
        let view = view_with(&[(ProviderId::Netbird, &["work"])]);
        let p = Picker::vpn(&view, "work");
        assert_eq!(p.value(), "netbird:work");
        assert_eq!(p.label(), "netbird: work");
    }

    #[test]
    fn a_configured_profile_is_offered_even_before_its_client_is_installed() {
        let mut view = view_with(&[(ProviderId::Wireguard, &["home"])]);
        view.providers[ProviderId::Wireguard.index()].installed = false;
        let p = Picker::vpn(&view, "");
        assert!(p.options.contains(&"wireguard:home".to_string()));
    }

    #[test]
    fn a_client_with_neither_an_install_nor_profiles_is_left_out() {
        let view = view_with(&[]);
        assert_eq!(Picker::vpn(&view, "").options, vec!["", "*"]);
    }

    #[test]
    fn the_picker_keeps_a_requirement_whose_profile_is_gone() {
        let view = view_with(&[(ProviderId::Wireguard, &["office"])]);
        let p = Picker::vpn(&view, "wireguard:deleted");
        assert_eq!(p.value(), "wireguard:deleted");
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
        assert_eq!(
            names(&plan),
            ["vpn netbird: work", "tun base", "tun app", "ssh login"]
        );
    }

    #[test]
    fn a_legacy_bare_profile_name_still_means_netbird() {
        let ts = vec![tunnel("a", "work", "")];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("a".into())])
            .unwrap();
        assert_eq!(plan[0], Step::Vpn("netbird:work".into()));
    }

    #[test]
    fn a_named_profile_wins_over_any_profile_of_the_same_provider() {
        let ts = vec![
            tunnel("base", "netbird:*", ""),
            tunnel("app", "netbird:work", "base"),
        ];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap();
        assert_eq!(plan[0], Step::Vpn("netbird:work".into()));
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn a_named_provider_supersedes_a_bare_any_vpn() {
        let ts = vec![
            tunnel("base", VPN_ANY, ""),
            tunnel("app", "wireguard:home", "base"),
        ];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap();
        assert_eq!(plan[0], Step::Vpn("wireguard:home".into()));
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn two_providers_in_one_chain_both_get_a_step_in_provider_order() {
        // The tailscale requirement is declared first but netbird sorts ahead.
        let ts = vec![
            tunnel("base", "tailscale:work", ""),
            tunnel("app", "netbird:tn", "base"),
        ];
        let plan = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap();
        assert_eq!(
            plan[..2],
            [
                Step::Vpn("netbird:tn".into()),
                Step::Vpn("tailscale:work".into())
            ]
        );
        assert_eq!(names(&plan)[2..], ["tun base", "tun app"]);
    }

    #[test]
    fn two_different_profiles_of_the_same_provider_are_still_rejected() {
        let ts = vec![
            tunnel("base", "wireguard:home", ""),
            tunnel("app", "wireguard:office", "base"),
        ];
        let err = catalog(&ts, &[])
            .build_plan(vec![Step::Tunnel("app".into())])
            .unwrap_err();
        assert!(
            err.contains("wireguard") && err.contains("'home'") && err.contains("'office'"),
            "{err}"
        );
    }

    #[test]
    fn two_different_netbird_profiles_are_rejected_however_they_are_spelled() {
        // One legacy bare name, one namespaced — the same contradiction.
        let ts = vec![tunnel("base", "home", ""), tunnel("app", "netbird:work", "base")];
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
    fn a_shared_dependency_is_started_once_for_a_whole_ssh_group() {
        // Opening a group of logins that all sit behind the same tunnel and
        // VPN brings each of those up once, then hands out the sessions.
        let ts = vec![tunnel("base", "work", "")];
        let hosts = vec![
            ssh_host("app-1", "", "base"),
            ssh_host("app-2", "", "base"),
        ];
        let plan = catalog(&ts, &hosts)
            .build_plan(vec![Step::Ssh("app-1".into()), Step::Ssh("app-2".into())])
            .unwrap();
        assert_eq!(
            names(&plan),
            ["vpn netbird: work", "tun base", "ssh app-1", "ssh app-2"]
        );
    }

    #[test]
    fn every_member_of_an_rdp_group_keeps_its_own_password() {
        let conns = vec![
            Step::Rdp {
                name: "one".into(),
                password: "a".into(),
            },
            Step::Rdp {
                name: "two".into(),
                password: "b".into(),
            },
        ];
        let plan = catalog(&[], &[]).build_plan(conns.clone()).unwrap();
        assert_eq!(plan, conns);
    }

    fn grouped(name: &str, group: &str) -> SshHost {
        SshHost {
            group: group.into(),
            ..ssh_host(name, "", "")
        }
    }

    #[test]
    fn rows_put_ungrouped_entries_first_then_each_group_with_its_members() {
        let hosts = vec![
            grouped("a", "prod"),
            grouped("loose", ""),
            grouped("b", "prod"),
            grouped("c", "dev"),
        ];
        let rows = build_rows(&hosts, |h| &h.group);
        assert_eq!(
            rows,
            vec![
                RowItem::Item(1),
                RowItem::Group("prod".into()),
                RowItem::Item(0),
                RowItem::Item(2),
                RowItem::Group("dev".into()),
                RowItem::Item(3),
            ]
        );
        assert_eq!(members_of(&hosts, |h| &h.group, "prod"), vec![0, 2]);
    }

    #[test]
    fn a_list_without_groups_has_a_row_per_entry() {
        let hosts = vec![ssh_host("a", "", ""), ssh_host("b", "", "")];
        let rows = build_rows(&hosts, |h| &h.group);
        assert_eq!(rows, vec![RowItem::Item(0), RowItem::Item(1)]);
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
