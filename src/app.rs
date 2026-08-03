use crate::config::{self, AppConfig, Paths};
use crate::netbird::{self, NbMsg, NbStatus, Profile};
use crate::rdp::{self, ActiveRdp, RdpStatus};
use crate::theme::{self, Theme};
use crate::tunnel::{self, ActiveTunnel, Status};
use crate::types::{ForwardType, RdpConnection, Tunnel};
use crate::ui;
use crate::Tui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

pub const THROUGHPUT_HISTORY: usize = 120;
const NETBIRD_REFRESH_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Vpn,
    Tunnels,
    Rdp,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Dashboard, Tab::Vpn, Tab::Tunnels, Tab::Rdp];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Vpn => "VPN",
            Self::Tunnels => "Tunnels",
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
        }
    }

    /// Whether the field applies to the given forward type.
    pub fn applies(self, forward: ForwardType) -> bool {
        match self {
            Self::RemoteHost | Self::RemotePort => forward != ForwardType::Dynamic,
            _ => true,
        }
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
    pub error: Option<String>,
}

impl TunnelForm {
    pub fn empty() -> Self {
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
            error: None,
        }
    }

    pub fn from_tunnel(t: &Tunnel) -> Self {
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
            FormField::Forward | FormField::AutoReconnect => None,
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
        })
    }
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
}

pub const RDP_FIELDS: &[RdpField] = &[
    RdpField::Name,
    RdpField::Host,
    RdpField::Port,
    RdpField::Domain,
    RdpField::Username,
    RdpField::ExtraArgs,
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
        }
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
    pub error: Option<String>,
}

impl RdpForm {
    pub fn empty() -> Self {
        Self {
            field_idx: 0,
            name: String::new(),
            host: String::new(),
            port: "3389".into(),
            domain: String::new(),
            username: String::new(),
            extra_args: String::new(),
            error: None,
        }
    }

    pub fn from_connection(c: &RdpConnection) -> Self {
        Self {
            field_idx: 0,
            name: c.name.clone(),
            host: c.host.clone(),
            port: c.port.to_string(),
            domain: c.domain.clone(),
            username: c.username.clone(),
            extra_args: c.extra_args.clone(),
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

    pub fn active_text_mut(&mut self) -> &mut String {
        match self.field() {
            RdpField::Name => &mut self.name,
            RdpField::Host => &mut self.host,
            RdpField::Port => &mut self.port,
            RdpField::Domain => &mut self.domain,
            RdpField::Username => &mut self.username,
            RdpField::ExtraArgs => &mut self.extra_args,
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
        paths: Paths,
        app_config: AppConfig,
    ) -> Self {
        let theme = theme::by_name(&app_config.ui.theme);
        let (nb_tx, nb_rx) = channel();
        let nb_installed = netbird::installed();
        if nb_installed {
            netbird::refresh(nb_tx.clone());
        }
        let mut app = Self {
            tunnels,
            active: HashMap::new(),
            tab: Tab::Dashboard,
            rows: Vec::new(),
            selected: 0,
            form: TunnelForm::empty(),
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
            rdp_form: RdpForm::empty(),
            rdp_mode: RdpMode::None,
            rdp_installed: rdp::installed(),
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
            KeyCode::Char('4') => self.tab = Tab::Rdp,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            _ => match self.tab {
                Tab::Dashboard => {}
                Tab::Vpn => self.on_netbird_key(key),
                Tab::Tunnels => self.on_tunnels_key(key),
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
                self.form = TunnelForm::empty();
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
                    self.form = TunnelForm::from_tunnel(&self.tunnels[*i]);
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
                self.rdp_form = RdpForm::empty();
                self.rdp_mode = RdpMode::Add;
            }
            KeyCode::Char('e') => {
                if let Some(c) = self.rdp_conns.get(self.rdp_selected) {
                    self.rdp_form = RdpForm::from_connection(c);
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
                KeyCode::Backspace => {
                    self.rdp_form.active_text_mut().pop();
                }
                KeyCode::Char(c) => self.rdp_form.active_text_mut().push(c),
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
                    self.connect_rdp(idx, &input);
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

    fn connect_rdp(&mut self, idx: usize, password: &str) {
        let Some(conn) = self.rdp_conns.get(idx).cloned() else {
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
    // Tunnel form / lifecycle (unchanged)
    // -----------------------------------------------------------------------

    fn on_form_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.form_mode = FormMode::None,
            KeyCode::Enter => self.submit_form(),
            KeyCode::Tab | KeyCode::Down => self.form.next_field(),
            KeyCode::BackTab | KeyCode::Up => self.form.prev_field(),
            KeyCode::Left => match self.form.field() {
                FormField::Forward => self.form.forward = self.form.forward.prev(),
                FormField::AutoReconnect => {
                    self.form.auto_reconnect = !self.form.auto_reconnect
                }
                _ => {}
            },
            KeyCode::Right => match self.form.field() {
                FormField::Forward => self.form.forward = self.form.forward.next(),
                FormField::AutoReconnect => {
                    self.form.auto_reconnect = !self.form.auto_reconnect
                }
                _ => {}
            },
            KeyCode::Backspace => {
                if let Some(text) = self.form.active_text_mut() {
                    text.pop();
                }
            }
            KeyCode::Char(c) => match self.form.field() {
                FormField::Forward => self.form.forward = self.form.forward.next(),
                FormField::AutoReconnect => {
                    self.form.auto_reconnect = !self.form.auto_reconnect
                }
                _ => {
                    if let Some(text) = self.form.active_text_mut() {
                        text.push(c);
                    }
                }
            },
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
        match editing {
            Some(i) => {
                let old_name = self.tunnels[i].name.clone();
                // Editing an active tunnel: stop it; the user restarts with the new settings.
                if self.active.contains_key(&old_name) {
                    self.stop_tunnel(&old_name);
                    self.flash("tunnel stopped — press Enter to start with new settings", false);
                }
                self.tunnels[i] = tunnel;
            }
            None => self.tunnels.push(tunnel),
        }
        self.form_mode = FormMode::None;
        self.rebuild_rows();
        if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
            self.flash(format!("save failed: {e}"), true);
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
        self.tunnels.remove(idx);
        self.rebuild_rows();
        if let Err(e) = config::save_tunnels(&self.paths.tunnels_file, &self.tunnels) {
            self.flash(format!("save failed: {e}"), true);
        } else {
            self.flash(format!("deleted '{name}'"), false);
        }
    }

    fn toggle_selected(&mut self) {
        match self.rows.get(self.selected).cloned() {
            Some(RowItem::Tunnel(i)) => {
                let name = self.tunnels[i].name.clone();
                if self.active.contains_key(&name) {
                    self.stop_tunnel(&name);
                } else {
                    self.start_tunnel(i);
                }
            }
            Some(RowItem::Group(g)) => {
                let members = self.group_members(&g);
                let any_inactive = members
                    .iter()
                    .any(|i| !self.active.contains_key(&self.tunnels[*i].name));
                if any_inactive {
                    for i in members {
                        if !self.active.contains_key(&self.tunnels[i].name) {
                            self.start_tunnel(i);
                        }
                    }
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
