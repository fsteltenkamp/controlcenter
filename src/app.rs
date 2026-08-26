use crate::browser::FileBrowser;
use crate::config::{self, AppConfig, Paths};
use crate::logs::{Entry, Journal, LogTarget, Ring};
use crate::rdp::{self, ActiveRdp, RdpStatus};
use crate::report;
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
use crate::vpn::scan::{self, Foreign, LinkKind, Scan};
use crate::vpn::{self, privileged, wireguard, ProviderId, VpnEnv, VpnMsg, VpnProfile, VpnStatus};
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

pub const THROUGHPUT_HISTORY: usize = 120;
const VPN_REFRESH_SECS: u64 = 5;
/// How often the machine is swept for VPN connections controlcenter is not
/// holding. The same clock as a status poll: an orphan is only interesting
/// while the user is looking at a connection that will not stay up.
const SCAN_SECS: u64 = 5;
/// How often the sudo ticket is refreshed, when there is one. Comfortably
/// inside sudo's default five-minute timeout.
const TICKET_REFRESH: Duration = Duration::from_secs(120);
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

    /// The log this step's news belongs in. A VPN requirement that names no
    /// provider is nobody's in particular, so it goes to the program's.
    pub fn log_target(&self) -> LogTarget {
        match self {
            Self::Vpn(req) => match parse_vpn_requirement(req).and_then(|r| {
                r.provider.map(|p| (p, r.profile.unwrap_or_default()))
            }) {
                Some((provider, profile)) => LogTarget::Vpn(provider, profile),
                None => LogTarget::Program,
            },
            Self::Tunnel(n) => LogTarget::Tunnel(n.clone()),
            Self::Ssh(n) => LogTarget::Ssh(n.clone()),
            Self::Rdp { name, .. } => LogTarget::Rdp(name.clone()),
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
    /// The running tunnels and RDP sessions that ride on exactly this VPN
    /// requirement — what taking it down would cut. `tunnel_up` and `rdp_up`
    /// answer for the two lists separately, because a tunnel and an RDP
    /// connection may share a name.
    fn riders_of(
        &self,
        req: &str,
        tunnel_up: &dyn Fn(&str) -> bool,
        rdp_up: &dyn Fn(&str) -> bool,
    ) -> (Vec<String>, Vec<String>) {
        let want = canonical_vpn_requirement(req);
        let matches = |r: &str| canonical_vpn_requirement(r) == want;
        let tunnels = self
            .tunnels
            .iter()
            .filter(|t| matches(&t.requires_vpn) && tunnel_up(&t.name))
            .map(|t| t.name.clone())
            .collect();
        let rdp = self
            .rdp_conns
            .iter()
            .filter(|c| matches(&c.requires_vpn) && rdp_up(&c.name))
            .map(|c| c.name.clone())
            .collect();
        (tunnels, rdp)
    }

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
    /// The step whose conflict the user has already accepted. What stood in
    /// the way is gone, but the resource it held can take a moment to come
    /// free — a VPN profile only switches once the client says so — and
    /// without this the same step would be asked about again on every tick.
    approved: Option<Step>,
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

    /// The profile that is up, as the provider reports it. A connection
    /// controlcenter is not holding never speaks for the client: it is
    /// reported so it can be dealt with, not counted as this client being up.
    pub fn active_profile(&self) -> Option<&str> {
        self.status.active_profile.as_deref().or_else(|| {
            self.profiles
                .iter()
                .find(|p| p.active && p.is_stored())
                .map(|p| p.name.as_str())
        })
    }

    /// The rows that are stored profiles, i.e. the ones `a`, `e`, `d` and `p`
    /// mean anything on.
    pub fn stored(&self) -> impl Iterator<Item = &VpnProfile> {
        self.profiles.iter().filter(|p| p.is_stored())
    }

    /// The connections found on the machine that this client is not holding.
    pub fn foreign(&self) -> impl Iterator<Item = &VpnProfile> {
        self.profiles.iter().filter(|p| !p.is_stored())
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
}

/// The log pane, which is the same popup on every tab: it shows what
/// controlcenter did about one connection merged with what the process it
/// started printed, and it is the only place a report is exported from.
///
/// There is one of these rather than one per tab, because a log is a log — see
/// [`LogTarget`] for what a pane can be about.
pub struct LogPane {
    pub target: LogTarget,
    /// How many lines back from the newest the view is scrolled. 0 follows the
    /// tail, which is what a log that is still being written wants.
    pub scroll: usize,
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

/// What quitting would leave behind, while it asks what to do about it.
///
/// Only OpenVPN sessions: a tunnel is an ssh child that goes when the terminal
/// does, an RDP or SSH session is a window the user can see, but an OpenVPN
/// session is a *root* process started through pkexec, and once controlcenter
/// is gone nothing is left that knows how to reach it. Left running it keeps
/// holding the server's slot, and the next attempt at the same profile is
/// thrown off it every couple of minutes by the one still there.
pub struct QuitPrompt {
    /// `profile — state`, one line each.
    pub sessions: Vec<String>,
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
    /// What quitting would leave running as root, while it asks whether to.
    pub quit_prompt: Option<QuitPrompt>,
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
    /// What the last sweep of the machine found: every VPN process and tunnel
    /// device, whoever started it. Subtracting the sessions above is what
    /// [`App::foreign_for`] does.
    pub scan: Scan,
    scan_at: Instant,
    /// A sweep is on a thread and has not reported back yet.
    scan_pending: bool,
    /// Processes that have already been sent a `SIGTERM` from here, so a second
    /// attempt on one that ignored it can escalate.
    termed: std::collections::HashSet<u32>,
    ticket_at: Instant,
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
    /// The log pane, whichever tab opened it.
    pub log_pane: Option<LogPane>,
    /// Everything controlcenter has done this run, for the log panes and the
    /// reports they export.
    pub journal: Journal,
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
            quit_prompt: None,
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
            scan: Scan::default(),
            // Far enough in the past that the first tick sweeps.
            scan_at: Instant::now() - Duration::from_secs(SCAN_SECS * 2),
            scan_pending: false,
            termed: std::collections::HashSet::new(),
            ticket_at: Instant::now(),
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
            log_pane: None,
            journal: Journal::default(),
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

    // -----------------------------------------------------------------------
    // Log panes
    //
    // One pane, opened from every tab with `l` and exported with `s`. What it
    // shows is what controlcenter did about a connection merged with what the
    // process it started printed — the two halves of any answer to "why did
    // that not come up".
    // -----------------------------------------------------------------------

    /// Record something in the log of the connection it is about, without
    /// saying it in the status bar. The mechanics go here — a command line, an
    /// exit code — while what the user has to read now goes through
    /// [`Self::report`].
    fn note(&mut self, target: LogTarget, msg: impl Into<String>) {
        self.journal.note(target, msg);
    }

    /// Say it in the status bar *and* keep it in the log of what it is about,
    /// so it outlives the few seconds a flash lasts.
    fn report(&mut self, target: LogTarget, msg: impl Into<String>, is_error: bool) {
        let msg = msg.into();
        if is_error {
            self.journal.fail(target, msg.clone());
        } else {
            self.journal.note(target, msg.clone());
        }
        self.flash(msg, is_error);
    }

    /// The line buffers a pane on `target` shows. An SSH host has none: its
    /// session runs in a terminal window of its own, and its output stays
    /// there — what controlcenter knows about it is in the journal instead.
    fn rings_for(&self, target: &LogTarget) -> Vec<&Ring> {
        let mut rings: Vec<&Ring> = Vec::new();
        for (name, a) in &self.active {
            if target.covers(&LogTarget::Tunnel(name.clone())) {
                rings.push(&a.stderr_log);
            }
        }
        for (name, a) in &self.rdp_active {
            if target.covers(&LogTarget::Rdp(name.clone())) {
                rings.push(&a.log);
            }
        }
        for (name, a) in &self.ovpn_active {
            if target.covers(&LogTarget::Vpn(ProviderId::Openvpn, name.clone())) {
                rings.push(&a.log);
            }
        }
        rings
    }

    /// What a pane shows, oldest first.
    pub fn log_lines(&self, target: &LogTarget) -> Vec<Entry> {
        let mut lines = self.journal.entries_for(target);
        for ring in self.rings_for(target) {
            lines.extend(ring.all());
        }
        lines.sort_by_key(|e| e.at);
        lines
    }

    /// What `l` and `s` act on with a tab in front: the connection under the
    /// cursor, or the whole program on the Dashboard, which watches everything
    /// and owns nothing.
    fn selection_target(&self) -> Result<LogTarget, String> {
        let entry = |what: &str| Err(format!("a group has no log of its own — pick {what}"));
        match self.tab {
            Tab::Dashboard => Ok(LogTarget::Program),
            Tab::Vpn => {
                let id = self.vpn.current_id();
                Ok(match self.vpn.current().selected_profile() {
                    Some(p) => LogTarget::Vpn(id, p.name.clone()),
                    None => LogTarget::vpn(id),
                })
            }
            Tab::Tunnels => match self.rows.get(self.selected) {
                Some(RowItem::Item(i)) => Ok(LogTarget::Tunnel(self.tunnels[*i].name.clone())),
                Some(RowItem::Group(_)) => entry("a tunnel"),
                None => Err("no tunnel is configured yet".into()),
            },
            Tab::Ssh => match self.selected_ssh_host() {
                Some(i) => Ok(LogTarget::Ssh(self.ssh_hosts[i].name.clone())),
                None if self.ssh_rows.is_empty() => Err("no ssh host is configured yet".into()),
                None => entry("a host"),
            },
            Tab::Rdp => match self.selected_rdp_conn() {
                Some(i) => Ok(LogTarget::Rdp(self.rdp_conns[i].name.clone())),
                None if self.rdp_rows.is_empty() => {
                    Err("no rdp connection is configured yet".into())
                }
                None => entry("a connection"),
            },
        }
    }

    /// `l` on any tab.
    fn open_log(&mut self) {
        match self.selection_target() {
            Ok(target) => {
                self.log_pane = Some(LogPane {
                    target,
                    scroll: 0,
                })
            }
            Err(why) => self.flash(why, true),
        }
    }

    /// The pane is modal and means the same thing wherever it was opened, so
    /// its keys are handled here rather than by the tab underneath it.
    fn on_log_key(&mut self, key: KeyEvent) {
        let Some(pane) = &self.log_pane else {
            return;
        };
        let last = self.log_lines(&pane.target).len().saturating_sub(1);
        let scroll_by = |app: &mut Self, delta: isize| {
            if let Some(p) = &mut app.log_pane {
                p.scroll = p.scroll.saturating_add_signed(delta).min(last);
            }
        };
        match key.code {
            KeyCode::Char('c') => self.clear_log(),
            KeyCode::Char('s') => self.export_log(),
            KeyCode::Up => scroll_by(self, 1),
            KeyCode::Down => scroll_by(self, -1),
            KeyCode::PageUp => scroll_by(self, 10),
            KeyCode::PageDown => scroll_by(self, -10),
            _ if closes_view(key) => self.log_pane = None,
            _ => {}
        }
    }

    /// `c` in the pane: throw away what is in it, on both sides of the merge.
    fn clear_log(&mut self) {
        let Some(target) = self.log_pane.as_ref().map(|p| p.target.clone()) else {
            return;
        };
        for ring in self.rings_for(&target) {
            ring.clear();
        }
        self.journal.clear_for(&target);
        if let Some(pane) = &mut self.log_pane {
            pane.scroll = 0;
        }
    }

    /// `s`: write the report out and say where it went. It is deliberately far
    /// more than the pane shows — the whole configuration, every command line
    /// and everything controlcenter did — because the file is read somewhere
    /// else, by someone or something without the program in front of them.
    fn export_log(&mut self) {
        let target = match self.log_pane.as_ref().map(|p| p.target.clone()) {
            Some(t) => t,
            None => match self.selection_target() {
                Ok(t) => t,
                Err(why) => {
                    self.flash(why, true);
                    return;
                }
            },
        };
        // Every file of one export shares a name, so the report can link to
        // the logs written beside it.
        let stem = report::file_stem(&target, std::time::SystemTime::now());
        let written = report::build(self, &target, &stem);
        match report::write(&self.paths.reports_dir, &stem, &written) {
            Ok(path) => self.report(
                target,
                format!("report written to {}", path.display()),
                false,
            ),
            Err(e) => self.report(target, format!("report failed: {e}"), true),
        }
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
        // The quit prompt is modal over everything: nothing else can matter
        // while the question is whether the program is still going to be here.
        if self.quit_prompt.is_some() {
            match key.code {
                KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Enter => {
                    self.quit_prompt = None;
                    self.stop_all_openvpn();
                    self.should_quit = true;
                }
                KeyCode::Char('k') | KeyCode::Char('K') => {
                    self.quit_prompt = None;
                    self.leave_openvpn_running();
                    self.should_quit = true;
                }
                _ => self.quit_prompt = None,
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
        // The log pane is one popup for the whole program, so it is handled
        // before anything that belongs to a single tab.
        if self.log_pane.is_some() {
            self.on_log_key(key);
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
        if self.vpn_mode != VpnMode::None {
            self.on_vpn_modal_key(key);
            return;
        }

        // Nothing is open, so this is the base application: the keys that mean
        // the same thing everywhere are handled here, and only what is left
        // reaches the tab under the cursor.
        match key.code {
            // No popup left to close, so q closes the application itself —
            // once it has settled what happens to anything running as root.
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Esc => {}
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('k') => self.show_keys = true,
            // Exporting is the same act everywhere: write down what happened
            // to whatever is selected, in full.
            KeyCode::Char('s') => self.export_log(),
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
                    .map(|p| {
                        let name = format!("{}:{}", st.id.slug(), p.name);
                        if p.is_stored() {
                            name
                        } else {
                            format!("{name} (not started here)")
                        }
                    })
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
        self.note(
            LogTarget::Program,
            format!("panic: taking down {}", summary.lines().join(", ")),
        );

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
        self.report(
            LogTarget::Program,
            format!("disconnected everything: {}", summary.lines().join(", ")),
            false,
        );
    }

    /// Take down whatever of this client is up. WireGuard and OpenVPN can hold
    /// several profiles at once, so each one gets its own call.
    ///
    /// Connections controlcenter is not holding go too. The panic button means
    /// "nothing is left up", and an orphan is exactly the thing most likely to
    /// still be there afterwards holding the link open.
    fn vpn_disconnect_all(&mut self, id: ProviderId) {
        let foreign: Vec<Foreign> = self
            .vpn
            .get(id)
            .foreign()
            .filter_map(|p| p.foreign.clone())
            .collect();
        for target in foreign {
            self.spawn_foreign_stop(id, target);
        }
        if !self.vpn.get(id).installed {
            return;
        }
        let active: Vec<String> = self
            .vpn
            .get(id)
            .stored()
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
                self.refresh_scan();
                self.flash("refreshing every VPN client", false);
            }
            KeyCode::Char('c') => self.clear_finished_everywhere(),
            // The dashboard watches everything, so its log is everything.
            KeyCode::Char('l') => self.open_log(),
            KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('a')
            | KeyCode::Char('e')
            | KeyCode::Char('d')
            | KeyCode::Char('p') => self.flash(
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
            KeyCode::Char('l') => self.open_log(),
            KeyCode::Char('c') => self.clear_finished_tunnels(),
            _ => {}
        }
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
                if self.selected_foreign().is_some() {
                    self.foreign_row_note("edit");
                } else if self.vpn_profile_count() > 0 {
                    self.open_vpn_form(Some(idx));
                }
            }
            KeyCode::Char('d') => {
                let provider = self.vpn.current_id();
                let idx = self.vpn.current().selected;
                if self.selected_foreign().is_some() {
                    self.foreign_row_note("delete");
                } else if !provider.manages_profiles() {
                    self.flash("netbird profiles are managed by netbird itself", true);
                } else if self.vpn_profile_count() > 0 {
                    self.vpn_mode = VpnMode::DeleteConfirm { provider, idx };
                }
            }
            KeyCode::Char('r') => {
                let id = self.vpn.current_id();
                self.vpn.get_mut(id).error = None;
                self.refresh_provider(id);
                self.refresh_scan();
                self.flash(format!("refreshing {}", id.slug()), false);
            }
            KeyCode::Char('p') => self.clear_vpn_password(),
            KeyCode::Char('l') => self.open_log(),
            KeyCode::Char('c') => self.clear_vpn_finished(),
            _ => {}
        }
    }

    /// `p` on the VPN tab: forget the password stored for the selected
    /// profile. Only OpenVPN keeps one — WireGuard's secret is a key, and
    /// neither NetBird nor Tailscale holds credentials here.
    fn clear_vpn_password(&mut self) {
        let id = self.vpn.current_id();
        if self.selected_foreign().is_some() {
            self.foreign_row_note("forget a password for");
            return;
        }
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
                    foreign: None,
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
                    foreign: None,
                })
                .collect(),
            ProviderId::Netbird => {
                self.merge_foreign(id);
                return;
            }
        };
        // Carry the live state over: seeding runs on every poll, and dropping
        // the active flags until the background refresh lands would make the
        // profile list blink.
        let state = self.vpn.get_mut(id);
        state.profiles = seeded
            .into_iter()
            .map(|mut p| {
                if let Some(known) = state.profiles.iter().find(|k| k.name == p.name && k.is_stored()) {
                    p.active = known.active;
                }
                p
            })
            .collect();
        state.clamp_selection();
        self.merge_foreign(id);
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
    ///
    /// On a connection controlcenter is not holding there is only one thing it
    /// can mean. Bringing one "up" is not ours to do — it is already up, and it
    /// belongs to something else.
    fn vpn_toggle_selected(&mut self) {
        if let Some(target) = self.selected_foreign() {
            let id = self.vpn.current_id();
            self.stop_foreign(id, target);
            return;
        }
        let state = self.vpn.current();
        let already_up = state.selected_profile().map(|p| p.active).unwrap_or(false);
        if already_up {
            self.vpn_disconnect_selected();
        } else {
            self.vpn_connect_selected();
        }
    }

    /// Why a profile key does nothing on a row that is not a stored profile.
    /// Every key means the same thing on every tab, so the ones that cannot
    /// apply here say why rather than going quiet.
    fn foreign_row_note(&mut self, what: &str) {
        let name = self
            .vpn
            .current()
            .selected_profile()
            .map(|p| p.name.clone())
            .unwrap_or_default();
        self.flash(
            format!("'{name}' was not started here — there is no profile to {what}; Enter stops it"),
            false,
        );
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
        // Switching an exclusive client's profile here cuts whatever rides on
        // the one going down, exactly as it does inside a dependency plan, so
        // it asks with the same prompt rather than pulling the rug silently.
        let step = Step::Vpn(match &profile {
            Some(p) => format!("{}:{p}", id.slug()),
            None => id.slug().to_string(),
        });
        if let Some(prompt) = self.step_conflict(&step) {
            self.conflict = Some(prompt);
            return;
        }
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
        let target = LogTarget::Vpn(id, profile.clone().unwrap_or_default());
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
            Ok(ran) => {
                let state = self.vpn.get_mut(id);
                state.error = None;
                state.busy = Some(desc.clone());
                for cmd in ran {
                    self.note(target.clone(), format!("ran: {cmd}"));
                }
                self.flash(format!("{}: {desc}…", id.slug()), false);
            }
            Err(e) => {
                self.vpn.get_mut(id).error = Some(e.clone());
                self.report(target, format!("{}: {e}", id.slug()), true);
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
        let target = LogTarget::Vpn(ProviderId::Openvpn, name.to_string());
        match crate::vpn::openvpn::spawn(&profile, &self.paths.openvpn_dir, &self.paths.run_dir) {
            Ok(session) => {
                let cmd = report::command_line(&session.argv);
                self.ovpn_active.insert(name.to_string(), session);
                self.note(target, format!("starting as root: {cmd}"));
                self.flash(format!("openvpn: connecting '{name}'…"), false);
            }
            Err(e) => {
                self.vpn.get_mut(ProviderId::Openvpn).error = Some(e.clone());
                self.report(target, format!("openvpn '{name}': {e}"), true);
            }
        }
        self.sync_openvpn();
    }

    fn stop_openvpn(&mut self, name: &str) {
        let Some(mut session) = self.ovpn_active.remove(name) else {
            self.flash(format!("openvpn '{name}' is not running"), true);
            return;
        };
        let target = LogTarget::Vpn(ProviderId::Openvpn, name.to_string());
        match session.stop() {
            Some(e) => self.report(target, format!("openvpn '{name}': {e}"), true),
            None => self.report(target, format!("openvpn: '{name}' stopped"), false),
        }
        self.sync_openvpn();
    }

    /// `q` with nothing left to close.
    ///
    /// Quitting is not free: an OpenVPN session runs as root, and controlcenter
    /// is the only thing holding the pid that can stop it. Leaving one behind
    /// is what puts an orphan on the machine, so the sessions still up get a
    /// say in whether the program is allowed to walk away from them.
    fn request_quit(&mut self) {
        let mut live: Vec<String> = self
            .ovpn_active
            .iter()
            .filter(|(_, s)| !matches!(s.status, OvpnStatus::Exited(_)))
            .map(|(n, s)| format!("{n} — {}", s.status.label()))
            .collect();
        if live.is_empty() {
            self.should_quit = true;
            return;
        }
        live.sort();
        match self.app_config.vpn.on_exit.trim().to_ascii_lowercase().as_str() {
            "stop" => {
                self.stop_all_openvpn();
                self.should_quit = true;
            }
            "keep" => {
                self.leave_openvpn_running();
                self.should_quit = true;
            }
            _ => self.quit_prompt = Some(QuitPrompt { sessions: live }),
        }
    }

    /// Take down every OpenVPN session controlcenter is holding.
    fn stop_all_openvpn(&mut self) {
        let names: Vec<String> = self.ovpn_active.keys().cloned().collect();
        for name in names {
            self.stop_openvpn(&name);
        }
    }

    /// Quit with the sessions left up, and write down that this is what
    /// happened — the next run will find them as orphans, and the log is where
    /// it says where they came from.
    fn leave_openvpn_running(&mut self) {
        let names: Vec<String> = self
            .ovpn_active
            .iter()
            .filter(|(_, s)| !matches!(s.status, OvpnStatus::Exited(_)))
            .map(|(n, _)| n.clone())
            .collect();
        for name in &names {
            let pid = self.ovpn_active[name].root_pid();
            self.note(
                LogTarget::Vpn(ProviderId::Openvpn, name.clone()),
                match pid {
                    Some(pid) => format!(
                        "left running as root on exit (pid {pid}); stop it with `sudo kill {pid}`"
                    ),
                    None => "left running as root on exit".to_string(),
                },
            );
        }
        self.note(
            LogTarget::Program,
            format!("quit with {} openvpn session(s) left running", names.len()),
        );
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
                foreign: None,
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
        self.merge_foreign(ProviderId::Openvpn);
    }

    /// The files that came with the selected OpenVPN profile, so the panel can
    /// show what the profile actually consists of rather than just a path.
    pub fn openvpn_import_listing(&self) -> Option<(String, Vec<String>)> {
        let selected = self.vpn.get(ProviderId::Openvpn).selected_profile()?;
        if !selected.is_stored() {
            return None;
        }
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

    // -----------------------------------------------------------------------
    // Connections controlcenter is not holding
    //
    // A session can outlive the program that started it — a crash, a kill, an
    // exit while openvpn was up — and an orphan holding the server's slot is
    // exactly what a profile that connects and drops every few minutes looks
    // like from the inside. So the tab shows what is on the machine, not only
    // what is in `ovpn_active`: [`crate::vpn::scan`] sweeps it, and everything
    // below is that sweep minus what this process owns.
    // -----------------------------------------------------------------------

    /// Sweep the machine on a background thread. One at a time: a sweep reads
    /// `/proc` and runs `ip` four times, and stacking those achieves nothing.
    fn refresh_scan(&mut self) {
        // A sweep that never reported back must not stop every later one. It
        // cannot fail — `scan` returns its errors rather than panicking — but a
        // flag that can only be cleared by a message is a flag worth a deadline.
        if self.scan_pending && self.scan_at.elapsed() < Duration::from_secs(SCAN_SECS * 6) {
            return;
        }
        self.scan_pending = true;
        self.scan_at = Instant::now();
        scan::spawn(self.vpn_tx.clone());
    }

    /// Ask for a sweep on the next tick rather than in the middle of whatever
    /// is happening now — used after an action that should change the picture.
    fn scan_soon(&mut self) {
        self.scan_at = Instant::now() - Duration::from_secs(SCAN_SECS);
    }

    /// The client a tunnel device belongs to, where that can be told.
    ///
    /// A device is not labelled with its owner, so the only honest way to
    /// attribute one is by what the clients themselves say: NetBird reports the
    /// address it was given, Tailscale reports its own, and a WireGuard profile
    /// names the interface it creates. A device that matches none of those is
    /// left unattributed rather than guessed at.
    pub fn claimant(&self, link: &scan::Link) -> Option<ProviderId> {
        if self
            .vpn_cfg
            .wireguard
            .iter()
            .any(|w| w.interface() == link.name)
        {
            return Some(ProviderId::Wireguard);
        }
        // A session controlcenter is holding says in its own log which device
        // it got, and an openvpn that was told which one to use says so on its
        // command line. Those are the only direct links between the two halves
        // of the sweep there are.
        if self
            .ovpn_active
            .values()
            .any(|s| s.device().as_deref() == Some(link.name.as_str()))
        {
            return Some(ProviderId::Openvpn);
        }
        if self
            .scan
            .processes_of(ProviderId::Openvpn)
            .any(|p| p.dev() == Some(link.name.as_str()))
        {
            return Some(ProviderId::Openvpn);
        }
        // Otherwise the only evidence is what the clients report about
        // themselves: NetBird and Tailscale each name the address they were
        // given. Only the fields that are *about* an address are compared —
        // a client's last log line can easily quote the same address a leaked
        // device is still holding, and matching that would hide exactly the
        // device this is here to find.
        let bare = |a: &str| a.split('/').next().unwrap_or(a).to_string();
        let addrs: Vec<String> = link.addrs.iter().map(|a| bare(a)).collect();
        // "NetBird IP", "Tailscale IP", "Address", "Interface" — and not a
        // key that merely happens to contain those two letters.
        let addressy = |k: &str| {
            let k = k.to_ascii_lowercase();
            k == "ip" || k.ends_with(" ip") || k.contains("address") || k.contains("interface")
        };
        self.vpn
            .providers
            .iter()
            .find(|state| {
                state.status.connected
                    && state.status.fields.iter().any(|(k, v)| {
                        addressy(k)
                            && (v == &link.name || addrs.iter().any(|a| v.contains(a.as_str())))
                    })
            })
            .map(|state| state.id)
    }

    /// Every tunnel device the sweep found, with whatever client accounts for
    /// it. The status pane shows these as evidence: a device nothing accounts
    /// for is a tunnel that is up and that nothing here can name.
    pub fn tunnel_devices(&self) -> Vec<(scan::Link, Option<ProviderId>)> {
        self.scan
            .tunnels()
            .map(|l| (l.clone(), self.claimant(l)))
            .collect()
    }

    /// The connections this client has on the machine that controlcenter is not
    /// holding a session for.
    ///
    /// OpenVPN is the one that leaks, because its connection is a root process
    /// that outlives us; a process is ours if we are holding a session that is
    /// writing its pid file, which keeps a session that has not written the
    /// file yet from being reported as its own orphan.
    fn foreign_for(&self, id: ProviderId) -> Vec<Foreign> {
        let mut out = Vec::new();
        match id {
            ProviderId::Openvpn => {
                let live: Vec<&ActiveOvpn> = self
                    .ovpn_active
                    .values()
                    .filter(|s| !matches!(s.status, OvpnStatus::Exited(_)))
                    .collect();
                for p in self.scan.processes_of(ProviderId::Openvpn) {
                    let held = live.iter().any(|s| {
                        s.root_pid() == Some(p.pid)
                            || p.pid_file()
                                .is_some_and(|f| std::path::Path::new(f) == s.pid_file())
                    });
                    if !held {
                        out.push(Foreign::Process(p.clone()));
                    }
                }
                // What the process scan cannot see: the devices of sessions
                // that are already gone. See [`scan::leaked_ovpn_devices`].
                let ours: Vec<String> = live.iter().filter_map(|s| s.device()).collect();
                let unaccounted = !out.is_empty();
                out.extend(
                    scan::leaked_ovpn_devices(&self.scan, &ours, unaccounted)
                        .into_iter()
                        .map(Foreign::Interface),
                );
            }
            ProviderId::Wireguard => {
                for link in self.scan.tunnels() {
                    if link.kind == LinkKind::Wireguard && self.claimant(link).is_none() {
                        out.push(Foreign::Interface(link.clone()));
                    }
                }
            }
            // NetBird and Tailscale are daemons: their own status already
            // reports the machine rather than this process, so there is nothing
            // here they could be holding without knowing it.
            ProviderId::Netbird | ProviderId::Tailscale => {}
        }
        out
    }

    /// Put the foreign rows at the end of a client's profile list. Called
    /// wherever that list is rebuilt, and idempotent, so the two can happen in
    /// either order.
    fn merge_foreign(&mut self, id: ProviderId) {
        let run_dir = self.paths.run_dir.clone();
        let rows: Vec<VpnProfile> = self
            .foreign_for(id)
            .into_iter()
            .map(|f| VpnProfile {
                name: f.name(),
                // It is up: that is the entire point of reporting it.
                active: true,
                detail: f.detail(&run_dir),
                foreign: Some(f),
            })
            .collect();
        let state = self.vpn.get_mut(id);
        state.profiles.retain(|p| p.is_stored());
        state.profiles.extend(rows);
        state.clamp_selection();
    }

    /// How many connections controlcenter is not holding, across every client.
    pub fn foreign_count(&self) -> usize {
        self.vpn
            .providers
            .iter()
            .map(|state| state.foreign().count())
            .sum()
    }

    /// The row under the cursor, when it is a connection controlcenter is not
    /// holding.
    fn selected_foreign(&self) -> Option<Foreign> {
        self.vpn.current().selected_profile()?.foreign.clone()
    }

    /// Take down something controlcenter did not start.
    ///
    /// Runs on a thread like every other VPN action, and reports back through
    /// the same channel. A second attempt on the same process sends `SIGKILL`:
    /// the first one has already been ignored, and an openvpn that will not
    /// leave keeps the server's slot for as long as it stays.
    fn stop_foreign(&mut self, id: ProviderId, target: Foreign) {
        if let Some(busy) = &self.vpn.get(id).busy {
            self.flash(format!("{} is busy ({busy})", id.slug()), true);
            return;
        }
        self.spawn_foreign_stop(id, target);
    }

    /// The same without the busy guard, for the panic button: "take everything
    /// down" cannot stop at the first client that is already doing something.
    fn spawn_foreign_stop(&mut self, id: ProviderId, target: Foreign) {
        // A process that has already been asked once and is still here gets
        // the signal it cannot ignore.
        let force = match &target {
            Foreign::Process(p) => {
                let again = self.termed.contains(&p.pid);
                self.termed.insert(p.pid);
                again
            }
            Foreign::Interface(_) => false,
        };
        let argv = target.stop_argv(force);
        let name = target.name();
        let desc = if force {
            format!("killing '{name}' — it ignored SIGTERM")
        } else {
            format!("stopping '{name}', which was not started here")
        };
        let log_target = LogTarget::Vpn(id, name);
        self.note(
            log_target,
            format!("as root: {}", report::command_line(&argv)),
        );
        self.vpn.get_mut(id).busy = Some(desc.clone());
        self.flash(format!("{}: {desc}…", id.slug()), false);
        let tx = self.vpn_tx.clone();
        std::thread::spawn(move || {
            let error = privileged::run(&argv).err();
            let _ = tx.send(VpnMsg::ActionDone {
                provider: id,
                desc,
                error,
            });
        });
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
            KeyCode::Char('l') => self.open_log(),
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
    fn spawn_rdp(&mut self, name: &str, password: &str) {
        let Some(conn) = self.rdp_conns.iter().find(|c| c.name == name).cloned() else {
            self.flash(format!("rdp connection '{name}' is gone"), true);
            return;
        };
        // Replace a finished session entry with the fresh one.
        if let Some(mut old) = self.rdp_active.remove(&conn.name) {
            old.stop();
        }
        let target = LogTarget::Rdp(conn.name.clone());
        match rdp::spawn(&conn, password) {
            Ok(active) => {
                let cmd = report::command_line(&active.argv);
                self.rdp_active.insert(conn.name.clone(), active);
                self.note(target, format!("starting: {cmd}"));
                self.flash(format!("connecting to '{}'", conn.name), false);
            }
            Err(e) => self.report(target, format!("'{}': {e:#}", conn.name), true),
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
            KeyCode::Char('l') => self.open_log(),
            KeyCode::Char('c') => self.clear_finished_ssh(),
            _ => {}
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
        let target = LogTarget::Ssh(host.name.clone());
        if !host.password.is_empty() && !self.sshpass_installed {
            self.report(
                target,
                format!("'{}' has a stored password but sshpass is not on PATH", host.name),
                true,
            );
            return Ok(());
        }
        // The session's own output goes to its window or to this terminal, so
        // the command line is the one thing about it worth keeping here.
        self.note(
            target.clone(),
            format!("opening in {}: {}", self.ssh_launcher.label(), ssh::command_preview(&host)),
        );

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
                        self.report(target, msg, false);
                    }
                    Err(e) => self.report(target, format!("'{}': {e:#}", host.name), true),
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
                let msg = format!(
                    "'{}' session {} after {}",
                    host.name,
                    outcome.label(),
                    ui::fmt_duration(outcome.duration)
                );
                self.ssh_last.insert(host.name.clone(), outcome);
                self.report(target, msg, outcome.failed());
            }
            Err(e) => self.report(target, format!("'{}': {e:#}", host.name), true),
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
            self.journal.note(
                LogTarget::Ssh(name.clone()),
                format!(
                    "session {} after {}",
                    outcome.label(),
                    ui::fmt_duration(outcome.duration)
                ),
            );
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
        Ok(self.plan_for(step)?.iter().map(Step::short).collect())
    }

    /// The steps a connection would be brought up through, itself last. What
    /// the details panels show as a chain, and what a report scopes itself to.
    pub fn plan_for(&self, step: Step) -> Result<Vec<Step>, String> {
        self.catalog().build_plan(vec![step])
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
                self.report(LogTarget::Program, format!("{target}: {e}"), true);
                return;
            }
        };
        self.note(
            LogTarget::Program,
            format!(
                "activating {target}: {}",
                steps.iter().map(Step::short).collect::<Vec<_>>().join(" → ")
            ),
        );
        self.activation = Some(Activation {
            total: steps.len(),
            steps: steps.into(),
            waiting: None,
            target,
            done: 0,
            started: Vec::new(),
            approved: None,
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
                state
                    .stored()
                    .any(|p| p.active && &p.name == name)
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
                let target = LogTarget::Vpn(id, profile.unwrap_or_default());
                match result {
                    Ok(ran) => {
                        let state = self.vpn.get_mut(id);
                        state.error = None;
                        state.busy = Some(desc);
                        for cmd in ran {
                            self.note(target.clone(), format!("ran: {cmd}"));
                        }
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
                let (stop_tunnels, stop_rdp) = self.catalog().riders_of(
                    &old,
                    &|name| self.active.contains_key(name),
                    &|name| self.rdp_running(name),
                );
                // Nothing rides on the profile going down, so the switch is
                // simply what was asked for: do it rather than ask again.
                if stop_tunnels.is_empty() && stop_rdp.is_empty() {
                    return None;
                }
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
        /// News about one step of a plan. A plan for a single connection is
        /// named after that connection, so saying both would say it twice.
        fn plan_msg(act: &Activation, step: &Step, what: &str) -> String {
            if act.target == step.describe() {
                format!("{} {what}", step.describe())
            } else {
                format!("{}: {} {what}", act.target, step.describe())
            }
        }

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
                        let msg = plan_msg(&act, &step, "timed out");
                        self.report(step.log_target(), msg, true);
                        return;
                    }
                    StepState::Failed(why) => {
                        let msg = plan_msg(&act, &step, &format!("failed — {why}"));
                        self.report(step.log_target(), msg, true);
                        return;
                    }
                }
                continue;
            }

            let Some(step) = act.steps.front().cloned() else {
                let msg = format!("{} started", act.target);
                self.report(LogTarget::Program, msg, false);
                return;
            };

            if !step.is_terminal() && self.step_state(&step) == StepState::Ready {
                act.steps.pop_front();
                act.approved = None;
                act.done += 1;
                continue;
            }

            // A conflict the user has already accepted is not asked about
            // again: what blocked the step is gone, even if the resource it
            // held has not come free yet.
            let approved = act.approved.as_ref() == Some(&step);
            if let Some(prompt) = self.step_conflict(&step).filter(|_| !approved) {
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
                    self.report(step.log_target(), msg, true);
                    act.steps.pop_front();
                    act.approved = None;
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
                    act.approved = None;
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
                    self.report(step.log_target(), msg, true);
                    return;
                }
            }
        }
    }

    /// Accept or refuse the conflict prompt. Accepting clears what is in the
    /// way and then goes on with the step itself: a plan carries on where a
    /// plan raised it, and the step is started on its own where a tab did.
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
            self.report(
                c.step.log_target(),
                format!("{} cancelled{detail}", c.step.describe()),
                true,
            );
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
        if let Some(note) = &c.note {
            evicted.push(note.clone());
        }
        if !evicted.is_empty() {
            let msg = format!("for {}: {}", c.step.describe(), evicted.join(", "));
            self.report(c.step.log_target(), msg, false);
        }
        let Some(act) = self.activation.as_mut() else {
            // Raised straight from a tab, so there is no plan to resume.
            match self.start_step(&c.step) {
                StartOutcome::Started => {}
                StartOutcome::Retry => {
                    let msg = format!("{} is not ready yet — try again", c.step.describe());
                    self.report(c.step.log_target(), msg, true);
                }
                StartOutcome::Failed(why) => {
                    let msg = format!("{}: {why}", c.step.describe());
                    self.report(c.step.log_target(), msg, true)
                }
            }
            return;
        };
        act.approved = Some(c.step);
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
        let target = LogTarget::Tunnel(t.name.clone());
        match tunnel::spawn(&t) {
            Ok(active) => {
                let cmd = report::command_line(&active.argv);
                self.reconnect.remove(&t.name);
                self.active.insert(t.name.clone(), active);
                self.note(target, format!("starting: {cmd}"));
            }
            Err(e) => self.report(target, format!("'{}': {e:#}", t.name), true),
        }
    }

    fn stop_tunnel(&mut self, name: &str) {
        self.reconnect.remove(name);
        if let Some(mut t) = self.active.remove(name) {
            t.stop();
            self.note(LogTarget::Tunnel(name.to_string()), "stopped");
        }
    }

    fn on_tick(&mut self) {
        let dt = self.last_tick.elapsed().as_secs_f64().max(0.5);
        let mut total_rate = 0u64;
        // Polling needs the sessions mutably and recording needs the journal,
        // so what changed is collected first and written down afterwards.
        let mut changed: Vec<(LogTarget, String, bool)> = Vec::new();
        for (name, active) in self.active.iter_mut() {
            let before = active.status;
            active.poll();
            active.sample_rates(dt);
            total_rate += active.rate_tx + active.rate_rx;
            if active.status != before {
                let detail = match &active.error {
                    Some(e) => format!("{} — {e}", active.status.label()),
                    None => active.status.label().to_string(),
                };
                changed.push((
                    LogTarget::Tunnel(name.clone()),
                    detail,
                    active.status == Status::Failed,
                ));
            }
        }
        if self.throughput_history.len() >= THROUGHPUT_HISTORY {
            self.throughput_history.pop_front();
        }
        self.throughput_history.push_back(total_rate);

        for (name, session) in self.rdp_active.iter_mut() {
            let before = session.status;
            session.poll();
            if session.status != before {
                changed.push((
                    LogTarget::Rdp(name.clone()),
                    session.status.label(),
                    matches!(session.status, RdpStatus::Exited(c) if c != 0),
                ));
            }
        }
        self.poll_ssh_windows();
        for (name, session) in self.ovpn_active.iter_mut() {
            let before = session.status;
            session.poll();
            if session.status != before {
                let detail = match session.fault() {
                    Some(f) => format!("{} — {f}", session.status.label()),
                    None => session.status.label(),
                };
                changed.push((
                    LogTarget::Vpn(ProviderId::Openvpn, name.clone()),
                    detail,
                    matches!(session.status, OvpnStatus::Exited(c) if c != 0),
                ));
            }
        }
        for (target, detail, failed) in changed {
            if failed {
                self.journal.fail(target, detail);
            } else {
                self.journal.note(target, detail);
            }
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
        // The sweep is nobody's client, so it runs on a clock of its own.
        if self.scan_at.elapsed() >= Duration::from_secs(SCAN_SECS) {
            self.refresh_scan();
        }
        if self.ticket_at.elapsed() >= TICKET_REFRESH {
            self.ticket_at = Instant::now();
            privileged::keep_warm();
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
            match msg {
                // What is on the machine belongs to no one client, so it is
                // merged into every one of them.
                VpnMsg::Scanned(found) => {
                    self.scan_pending = false;
                    if let Some(e) = &found.error {
                        self.note(LogTarget::Program, format!("scanning for VPN connections: {e}"));
                    }
                    self.scan = found;
                    for id in ProviderId::ALL {
                        self.merge_foreign(id);
                    }
                    // A process that has gone can never need a SIGKILL, and its
                    // pid will eventually belong to something else.
                    let live: Vec<u32> =
                        self.scan.processes.iter().map(|p| p.pid).collect();
                    self.termed.retain(|pid| live.contains(pid));
                }
                VpnMsg::Refreshed {
                    provider: id,
                    profiles,
                    status,
                } => {
                    let mut listing_failed = None;
                    let state = self.vpn.get_mut(id);
                    match profiles {
                        Ok(p) => {
                            state.profiles = p;
                            state.clamp_selection();
                            state.error = None;
                        }
                        Err(e) => {
                            state.error = Some(e.clone());
                            listing_failed = Some(e);
                        }
                    }
                    state.status = status;
                    state.last_refresh = Instant::now();
                    self.merge_foreign(id);
                    // A poll that failed is worth keeping: it is usually the
                    // reason a step later times out waiting for this client.
                    if let Some(e) = listing_failed {
                        self.journal.fail(LogTarget::vpn(id), format!("status: {e}"));
                    }
                }
                VpnMsg::ActionDone {
                    provider: id,
                    desc,
                    error,
                } => {
                    self.vpn.get_mut(id).busy = None;
                    // Whatever it was, the machine is not what it was.
                    self.scan_soon();
                    match error {
                        Some(e) => {
                            self.vpn.get_mut(id).error = Some(e.clone());
                            self.report(
                                LogTarget::vpn(id),
                                format!("{} {desc} failed: {e}", id.slug()),
                                true,
                            );
                        }
                        None => self.report(
                            LogTarget::vpn(id),
                            format!("{}: {desc} done", id.slug()),
                            false,
                        ),
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
                    self.report(
                        LogTarget::Tunnel(name.clone()),
                        format!("reconnecting '{name}' (attempt {attempts})"),
                        false,
                    );
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

    fn rdp_conn(name: &str, vpn: &str) -> RdpConnection {
        RdpConnection {
            name: name.into(),
            group: String::new(),
            host: "10.0.0.1".into(),
            port: 3389,
            domain: String::new(),
            username: "user".into(),
            extra_args: String::new(),
            depends_on: String::new(),
            requires_vpn: vpn.into(),
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
                    foreign: None,
                })
                .collect();
        }
        view
    }

    #[test]
    fn a_connection_controlcenter_is_not_holding_never_speaks_for_the_client() {
        let mut view = view_with(&[(ProviderId::Openvpn, &["work"])]);
        let state = &mut view.providers[ProviderId::Openvpn.index()];
        state.profiles.push(VpnProfile {
            name: "orphan".into(),
            // It is up — that is why it is listed at all.
            active: true,
            detail: "pid 4242 · root · not started here".into(),
            foreign: Some(scan::Foreign::Process(scan::Process {
                pid: 4242,
                provider: ProviderId::Openvpn,
                argv: vec!["/usr/bin/openvpn".into(), "--config".into(), "/etc/x.ovpn".into()],
                uid: 0,
                age_secs: Some(60),
            })),
        });
        // The client is not "on" the orphan's profile: nothing here brought it
        // up, so nothing here may report it as the profile that is active.
        assert_eq!(state.active_profile(), None);
        assert_eq!(state.stored().count(), 1);
        assert_eq!(state.foreign().count(), 1);
        assert_eq!(state.foreign().next().unwrap().name, "orphan");

        // And once one of ours really is up, that is the one that answers.
        state.profiles[0].active = true;
        assert_eq!(state.active_profile(), Some("work"));
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
    fn only_what_is_up_and_asks_for_the_profile_counts_as_a_rider() {
        let ts = vec![
            tunnel("up-on-home", "netbird:home", ""),
            tunnel("down-on-home", "netbird:home", ""),
            tunnel("on-work", "netbird:work", ""),
        ];
        let conns = vec![rdp_conn("desk", "netbird:home"), rdp_conn("other", "")];
        let cat = Catalog {
            tunnels: &ts,
            ssh_hosts: &[],
            rdp_conns: &conns,
        };
        let (tunnels, rdp) =
            cat.riders_of("netbird:home", &|n| n == "up-on-home", &|n| n == "desk");
        assert_eq!(tunnels, ["up-on-home"]);
        assert_eq!(rdp, ["desk"]);
    }

    #[test]
    fn a_legacy_bare_profile_name_rides_on_the_same_netbird_profile() {
        // "home" is how a requirement was written before there was more than
        // one client, so it must count against netbird:home.
        let ts = vec![tunnel("legacy", "home", "")];
        let cat = catalog(&ts, &[]);
        let (tunnels, _) = cat.riders_of("netbird:home", &|_| true, &|_| true);
        assert_eq!(tunnels, ["legacy"]);
    }

    #[test]
    fn nothing_rides_on_a_profile_no_one_asks_for() {
        // The switch then goes through without a prompt.
        let ts = vec![tunnel("a", "netbird:work", "")];
        let cat = catalog(&ts, &[]);
        let (tunnels, rdp) = cat.riders_of("netbird:home", &|_| true, &|_| true);
        assert!(tunnels.is_empty() && rdp.is_empty());
    }

    #[test]
    fn saving_a_tunnel_that_closes_a_loop_is_caught() {
        let ts = vec![tunnel("a", "", "b"), tunnel("b", "", "a")];
        assert!(tunnel_cycle(&ts, "a").is_some());
        let fine = vec![tunnel("a", "", ""), tunnel("b", "", "a")];
        assert!(tunnel_cycle(&fine, "b").is_none());
    }
}
