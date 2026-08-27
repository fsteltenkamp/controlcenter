use crate::app::{
    App, FormField, FormMode, LogPane, RdpField, RdpMode, RowItem, SshField, SshMode, Step, Tab,
    VpnMode, VpnPane, FORM_FIELDS, RDP_FIELDS, SSH_FIELDS,
};
use crate::browser::FileBrowser;
use crate::logs;
use crate::rdp::RdpStatus;
use crate::ssh;
use crate::theme::{self, Theme};
use crate::tunnel::Status;
use crate::types::{vpn_requirement_label, ForwardType, Tunnel};
use crate::vpn::ProviderId;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Tabs, Wrap,
};
use ratatui::Frame;

thread_local! {
    static CURRENT_THEME: std::cell::Cell<Theme> = const { std::cell::Cell::new(theme::DARK) };
}

fn set_theme(t: Theme) {
    CURRENT_THEME.with(|c| c.set(t));
}
fn theme_now() -> Theme {
    CURRENT_THEME.with(|c| c.get())
}

#[allow(non_snake_case)]
fn ACCENT() -> Color {
    theme_now().accent
}
#[allow(non_snake_case)]
fn DIM() -> Color {
    theme_now().dim
}
#[allow(non_snake_case)]
fn BORDER() -> Color {
    theme_now().border
}
#[allow(non_snake_case)]
fn TEXT() -> Color {
    theme_now().text
}
#[allow(non_snake_case)]
fn DANGER() -> Color {
    theme_now().danger
}
#[allow(non_snake_case)]
fn WARN() -> Color {
    theme_now().warn
}
#[allow(non_snake_case)]
fn OK() -> Color {
    theme_now().ok
}
#[allow(non_snake_case)]
fn SELECTION_BG() -> Color {
    theme_now().selection_bg
}

pub fn render(f: &mut Frame, app: &App) {
    set_theme(app.theme);
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(f, app, chunks[0]);
    match app.tab {
        Tab::Dashboard => render_dashboard(f, app, chunks[1]),
        Tab::Vpn => render_vpn(f, app, chunks[1]),
        Tab::Tunnels => render_tunnels(f, app, chunks[1]),
        Tab::Ssh => render_ssh(f, app, chunks[1]),
        Tab::Rdp => render_rdp(f, app, chunks[1]),
    }
    render_status(f, app, chunks[2]);

    match &app.form_mode {
        FormMode::None => {}
        FormMode::Add | FormMode::Edit(_) => render_form_overlay(f, app, area),
        FormMode::DeleteConfirm(i) => render_delete_confirm(f, app, area, *i),
    }

    match &app.rdp_mode {
        RdpMode::None => {}
        RdpMode::Add | RdpMode::Edit(_) => render_rdp_form_overlay(f, app, area),
        RdpMode::DeleteConfirm(i) => render_rdp_delete_confirm(f, app, area, *i),
        RdpMode::Password {
            pending,
            collected,
            input,
        } => render_rdp_password_overlay(f, app, area, pending, collected.len(), input),
    }

    match &app.ssh_mode {
        SshMode::None => {}
        SshMode::Add | SshMode::Edit(_) => render_ssh_form_overlay(f, app, area),
        SshMode::DeleteConfirm(i) => render_ssh_delete_confirm(f, app, area, *i),
        SshMode::PasswordWarning => render_password_warning(f, app, area),
    }

    match &app.vpn_mode {
        VpnMode::None => {}
        VpnMode::Form { edit, .. } => render_vpn_form_overlay(f, app, area, edit.is_some()),
        VpnMode::DeleteConfirm { provider, idx } => {
            render_vpn_delete_confirm(f, app, area, *provider, *idx)
        }
        VpnMode::SecretWarning { .. } => render_vpn_secret_warning(f, app, area),
    }

    // One log pane for the whole program, over whichever tab opened it.
    if let Some(pane) = &app.log_pane {
        render_log_overlay(f, app, pane, area);
    }

    // The file picker covers the form that opened it.
    if let Some(browser) = &app.browser {
        render_browser_overlay(f, browser, area);
    }

    // A conflict prompt holds a tunnel start hostage; it wins over everything.
    if app.conflict.is_some() {
        render_conflict_prompt(f, app, area);
    }

    // The panic button asks over the top of anything else on screen.
    if app.panic.is_some() {
        render_panic_prompt(f, app, area);
    }

    // And quitting asks over the top of that: it is the one question whose
    // answer decides whether any of the rest is still here afterwards.
    if app.quit_prompt.is_some() {
        render_quit_prompt(f, app, area);
    }

    if app.show_help {
        render_help_overlay(f, area);
    }
    if app.show_keys {
        render_keys_overlay(f, area);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let titles = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!("[{}] ", i + 1), Style::default().fg(DIM())),
                Span::styled(t.label(), Style::default().fg(TEXT())),
            ])
        })
        .collect::<Vec<_>>();

    let up = app
        .active
        .values()
        .filter(|a| a.status == Status::Up)
        .count();
    let rdp_running = app
        .rdp_active
        .values()
        .filter(|a| a.status == RdpStatus::Running)
        .count();
    // Name what is actually up rather than a single up/down, now that more than
    // one VPN can be connected at a time.
    let connected = app.vpn.connected();
    let vpn = if !app.vpn.any_installed() {
        "-".to_string()
    } else if connected.is_empty() {
        if app.vpn.any_busy() { "…".to_string() } else { "down".to_string() }
    } else {
        let mut names: Vec<&str> = connected.iter().map(|p| p.id.slug()).collect();
        names.sort_unstable();
        names.join("+")
    };
    let title_right =
        format!(" ssh {}/{} up · vpn {} · rdp {} ", up, app.active.len(), vpn, rdp_running);

    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .style(Style::default().fg(TEXT()))
        .highlight_style(
            Style::default()
                .fg(ACCENT())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled("│", Style::default().fg(BORDER())))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Line::from(vec![
                    Span::styled(" controlcenter ", Style::default().fg(ACCENT()).bold()),
                    Span::styled("· control center ", Style::default().fg(DIM())),
                ]))
                .title_bottom(
                    Line::from(Span::styled(title_right, Style::default().fg(DIM())))
                        .right_aligned(),
                ),
        );

    f.render_widget(tabs, area);
}

fn status_dot(app: &App, t: &Tunnel) -> Span<'static> {
    match app.active.get(&t.name) {
        Some(a) => match a.status {
            Status::Up => Span::styled("●", Style::default().fg(OK())),
            Status::Connecting => Span::styled("◐", Style::default().fg(WARN())),
            Status::Failed => Span::styled("✖", Style::default().fg(DANGER())),
        },
        None => Span::styled("○", Style::default().fg(DIM())),
    }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

fn summary_block<'a>(title: &'a str, lines: Vec<Line<'a>>) -> Paragraph<'a> {
    Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(format!(" {title} "), Style::default().fg(TEXT()))),
    )
}

fn kv<'a>(k: &str, v: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {k:<11}"), Style::default().fg(DIM())),
        v,
    ])
}

fn render_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(rows[0]);

    // --- SSH tunnels summary ---
    let up = app
        .active
        .values()
        .filter(|a| a.status == Status::Up)
        .count();
    let connecting = app
        .active
        .values()
        .filter(|a| a.status == Status::Connecting)
        .count();
    let failed = app
        .active
        .values()
        .filter(|a| a.status == Status::Failed)
        .count();
    let (mut tx, mut rx) = (0u64, 0u64);
    for a in app.active.values() {
        tx += a.counters.tx.load(std::sync::atomic::Ordering::Relaxed);
        rx += a.counters.rx.load(std::sync::atomic::Ordering::Relaxed);
    }
    let ok_span = |n: usize, color: Color| {
        Span::styled(n.to_string(), Style::default().fg(color).bold())
    };
    let mut ssh_lines = vec![
        kv("configured", Span::styled(app.tunnels.len().to_string(), Style::default().fg(TEXT()))),
        kv("up", ok_span(up, if up > 0 { OK() } else { DIM() })),
        kv("connecting", ok_span(connecting, if connecting > 0 { WARN() } else { DIM() })),
        kv("failed", ok_span(failed, if failed > 0 { DANGER() } else { DIM() })),
        kv(
            "traffic",
            Span::styled(
                format!("↑ {}  ↓ {}", human_bytes(tx), human_bytes(rx)),
                Style::default().fg(TEXT()),
            ),
        ),
    ];
    let chained = app
        .tunnels
        .iter()
        .filter(|t| !t.requires_vpn.is_empty() || !t.depends_on.is_empty())
        .count();
    if chained > 0 {
        ssh_lines.push(kv(
            "chained",
            Span::styled(chained.to_string(), Style::default().fg(TEXT())),
        ));
    }
    if app.active.is_empty() {
        ssh_lines.push(Line::from(""));
        ssh_lines.push(Line::from(Span::styled(
            " no active tunnels",
            Style::default().fg(DIM()),
        )));
    }
    f.render_widget(summary_block("ssh tunnels [3]", ssh_lines), cols[1]);

    // --- VPN summary: one line per client ---
    let mut nb_lines: Vec<Line> = Vec::new();
    if !app.vpn.any_installed() {
        nb_lines.push(Line::from(""));
        nb_lines.push(Line::from(Span::styled(
            " no VPN client found on PATH",
            Style::default().fg(DIM()),
        )));
    } else {
        for state in &app.vpn.providers {
            let (mark, style) = if !state.installed {
                ("·", Style::default().fg(DIM()))
            } else if state.busy.is_some() {
                ("◌", Style::default().fg(WARN()))
            } else if state.status.connected {
                ("●", Style::default().fg(OK()))
            } else {
                ("○", Style::default().fg(DIM()))
            };
            let detail = if !state.installed {
                "not installed".to_string()
            } else if let Some(busy) = &state.busy {
                format!("{busy}…")
            } else if state.status.connected {
                state.active_profile().unwrap_or("connected").to_string()
            } else {
                "down".to_string()
            };
            nb_lines.push(Line::from(vec![
                Span::styled(format!(" {mark} "), style),
                Span::styled(format!("{:<11}", state.id.slug()), Style::default().fg(TEXT())),
                Span::styled(
                    truncate(&detail, 18),
                    Style::default().fg(if state.status.connected { ACCENT() } else { DIM() }),
                ),
            ]));
        }
        // The one detail worth the space: where the connected client puts you.
        if let Some(primary) = app.vpn.connected().first() {
            for key in ["NetBird IP", "Tailscale IP", "Address"] {
                if let Some(v) = primary.status.field(key) {
                    nb_lines.push(kv("ip", Span::styled(v.to_string(), Style::default().fg(TEXT()))));
                    break;
                }
            }
        }
        let strays = app.foreign_count();
        if strays > 0 {
            nb_lines.push(Line::from(Span::styled(
                format!(" ◆ {strays} not started here"),
                Style::default().fg(WARN()),
            )));
        }
        if let Some(err) = app.vpn.providers.iter().find_map(|p| p.error.as_ref()) {
            nb_lines.push(Line::from(Span::styled(
                format!(" {}", truncate(err, 40)),
                Style::default().fg(DANGER()),
            )));
        }
    }
    f.render_widget(summary_block("vpn [2]", nb_lines), cols[0]);

    // --- RDP summary ---
    let rdp_running = app
        .rdp_active
        .values()
        .filter(|a| a.status == RdpStatus::Running)
        .count();
    let mut rdp_lines = vec![
        kv(
            "configured",
            Span::styled(app.rdp_conns.len().to_string(), Style::default().fg(TEXT())),
        ),
        kv(
            "running",
            ok_span(rdp_running, if rdp_running > 0 { OK() } else { DIM() }),
        ),
    ];
    if !app.rdp_installed {
        rdp_lines.push(Line::from(Span::styled(
            " xfreerdp3 not found on PATH",
            Style::default().fg(DIM()),
        )));
    }
    for name in app.rdp_session_names().iter().take(4) {
        let a = &app.rdp_active[*name];
        let (dot, style) = match a.status {
            RdpStatus::Running => ("●", Style::default().fg(OK())),
            RdpStatus::Exited(0) => ("○", Style::default().fg(DIM())),
            RdpStatus::Exited(_) => ("✖", Style::default().fg(DANGER())),
        };
        rdp_lines.push(Line::from(vec![
            Span::styled(format!(" {dot} "), style),
            Span::styled(truncate(name, 16), Style::default().fg(TEXT())),
            Span::styled(
                format!("  {}", fmt_duration(a.started_at.elapsed())),
                Style::default().fg(DIM()),
            ),
        ]));
    }
    f.render_widget(summary_block("rdp [5]", rdp_lines), cols[3]);

    // --- SSH hosts summary ---
    let with_password = app
        .ssh_hosts
        .iter()
        .filter(|h| !h.password.is_empty())
        .count();
    let mut ssh_host_lines = vec![kv(
        "configured",
        Span::styled(app.ssh_hosts.len().to_string(), Style::default().fg(TEXT())),
    )];
    let open_windows: usize = app
        .ssh_hosts
        .iter()
        .map(|h| app.ssh_windows_open(&h.name))
        .sum();
    if open_windows > 0 {
        ssh_host_lines.push(kv(
            "sessions",
            Span::styled(
                format!("{open_windows} window(s) open"),
                Style::default().fg(OK()),
            ),
        ));
    }
    if with_password > 0 {
        ssh_host_lines.push(kv(
            "cleartext",
            Span::styled(
                format!("{with_password} password(s)"),
                Style::default().fg(WARN()),
            ),
        ));
    }
    if let Some(act) = &app.activation {
        ssh_host_lines.push(kv(
            "starting",
            Span::styled(truncate(&act.progress(), 16), Style::default().fg(WARN())),
        ));
    }
    ssh_host_lines.push(Line::from(""));
    ssh_host_lines.push(Line::from(Span::styled(
        " sessions run in this terminal",
        Style::default().fg(DIM()),
    )));
    f.render_widget(summary_block("ssh hosts [4]", ssh_host_lines), cols[2]);

    // --- Active tunnels + RDP sessions table ---
    render_active_table(f, app, rows[1]);

    // --- Throughput sparkline ---
    let current = app.throughput_history.back().copied().unwrap_or(0);
    let data: Vec<u64> = app.throughput_history.iter().copied().collect();
    let spark = Sparkline::default()
        .data(data)
        .style(Style::default().fg(ACCENT()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Line::from(vec![
                    Span::styled(" tunnel throughput ", Style::default().fg(TEXT())),
                    Span::styled(
                        format!("(all tunnels, {} now) ", human_rate(current)),
                        Style::default().fg(DIM()),
                    ),
                ])),
        );
    f.render_widget(spark, rows[2]);
}

fn render_active_table(f: &mut Frame, app: &App, area: Rect) {
    let names = app.active_tunnel_names();
    let rdp_names = app.rdp_session_names();

    let header = Line::from(Span::styled(
        format!(
            " {:<18} {:<5} {:<11} {:>8} {:>13} {:>10} {:>10} {:>9} {:>9}",
            "name", "type", "status", "uptime", "conns", "↑/s", "↓/s", "↑ total", "↓ total"
        ),
        Style::default().fg(DIM()).bold(),
    ));

    let mut items: Vec<ListItem> = vec![ListItem::new(header)];
    for name in &names {
        let a = &app.active[*name];
        let status_style = match a.status {
            Status::Up => Style::default().fg(OK()),
            Status::Connecting => Style::default().fg(WARN()),
            Status::Failed => Style::default().fg(DANGER()),
        };
        let c = &a.counters;
        let (active_c, total_c, tx, rx) = (
            c.active_conns.load(std::sync::atomic::Ordering::Relaxed),
            c.total_conns.load(std::sync::atomic::Ordering::Relaxed),
            c.tx.load(std::sync::atomic::Ordering::Relaxed),
            c.rx.load(std::sync::atomic::Ordering::Relaxed),
        );
        let is_remote = app
            .tunnels
            .iter()
            .find(|t| &t.name == *name)
            .map(|t| t.forward == ForwardType::Remote)
            .unwrap_or(false);
        let (conns, up_s, down_s, up_t, down_t) = if is_remote {
            ("-".to_string(), "-".into(), "-".into(), "-".into(), "-".into())
        } else {
            (
                format!("{active_c} / {total_c}"),
                human_rate(a.rate_tx),
                human_rate(a.rate_rx),
                human_bytes(tx),
                human_bytes(rx),
            )
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!(" {:<18} ", truncate(name, 18)),
                Style::default().fg(TEXT()),
            ),
            Span::styled("ssh   ", Style::default().fg(DIM())),
            Span::styled(format!("{:<11} ", a.status.label()), status_style),
            Span::styled(
                format!(
                    "{:>8} {:>13} {:>10} {:>10} {:>9} {:>9}",
                    fmt_duration(a.started_at.elapsed()),
                    conns,
                    up_s,
                    down_s,
                    up_t,
                    down_t
                ),
                Style::default().fg(TEXT()),
            ),
        ])));
    }
    for name in &rdp_names {
        let a = &app.rdp_active[*name];
        let status_style = match a.status {
            RdpStatus::Running => Style::default().fg(OK()),
            RdpStatus::Exited(0) => Style::default().fg(DIM()),
            RdpStatus::Exited(_) => Style::default().fg(DANGER()),
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!(" {:<18} ", truncate(name, 18)),
                Style::default().fg(TEXT()),
            ),
            Span::styled("rdp   ", Style::default().fg(DIM())),
            Span::styled(format!("{:<11} ", a.status.label()), status_style),
            Span::styled(
                format!(
                    "{:>8} {:>13} {:>10} {:>10} {:>9} {:>9}",
                    fmt_duration(a.started_at.elapsed()),
                    "-",
                    "-",
                    "-",
                    "-",
                    "-"
                ),
                Style::default().fg(TEXT()),
            ),
        ])));
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" active ", Style::default().fg(TEXT()))),
    );
    f.render_widget(list, area);

    if names.is_empty() && rdp_names.is_empty() {
        let hint = Paragraph::new(Line::from(Span::styled(
            "  nothing active — start a tunnel [3] or an RDP session [5]",
            Style::default().fg(DIM()),
        )));
        let inner = Rect {
            x: area.x + 1,
            y: area.y + 2,
            width: area.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(hint, inner);
    }
}

// ---------------------------------------------------------------------------
// Tunnels tab (unchanged behavior)
// ---------------------------------------------------------------------------

/// Compact "needs …" tail for a tunnel row; the details panel spells out which
/// profile and which tunnel.
fn needs_span(app: &App, t: &Tunnel) -> Span<'static> {
    let mut parts: Vec<&str> = Vec::new();
    if !t.requires_vpn.is_empty() {
        parts.push("vpn");
    }
    if !t.depends_on.is_empty() {
        parts.push("tun");
    }
    if parts.is_empty() {
        return Span::raw("");
    }
    let ready = app.vpn_satisfied(&t.requires_vpn)
        && (t.depends_on.is_empty()
            || matches!(
                app.active.get(&t.depends_on).map(|a| a.status),
                Some(Status::Up)
            ));
    let color = if app.dependency_missing(&t.depends_on) {
        DANGER()
    } else if ready {
        OK()
    } else {
        DIM()
    };
    Span::styled(format!("needs {}", parts.join("+")), Style::default().fg(color))
}

/// The head of a group's details panel: its name, how many members it has and
/// how many of them are up. `state` names what "up" means for that tab.
fn group_details(name: &str, members: usize, up: usize, state: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled("group     ", Style::default().fg(DIM())),
            Span::styled(name.to_string(), Style::default().fg(ACCENT()).bold()),
        ]),
        Line::from(vec![
            Span::styled("members   ", Style::default().fg(DIM())),
            Span::styled(members.to_string(), Style::default().fg(TEXT())),
        ]),
        Line::from(vec![
            Span::styled(format!("{state:<10}"), Style::default().fg(DIM())),
            Span::styled(up.to_string(), Style::default().fg(TEXT())),
        ]),
        Line::from(""),
    ]
}

/// A group row: "▸ name  (2/3 active)".
fn group_header(name: &str, summary: &str) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled("▸ ", Style::default().fg(ACCENT())),
        Span::styled(name.to_string(), Style::default().fg(ACCENT()).bold()),
        Span::styled(format!("  {summary}"), Style::default().fg(DIM())),
    ]))
}

fn render_tunnels(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|row| match row {
            RowItem::Group(g) => {
                let members = app.group_members(g);
                let up = members
                    .iter()
                    .filter(|i| app.active.contains_key(&app.tunnels[**i].name))
                    .count();
                group_header(g, &format!("({up}/{} active)", members.len()))
            }
            RowItem::Item(i) => {
                let t = &app.tunnels[*i];
                let indent = if t.group.is_empty() { " " } else { "   " };
                ListItem::new(Line::from(vec![
                    Span::raw(indent.to_string()),
                    status_dot(app, t),
                    Span::styled(
                        format!(" {:<16}", truncate(&t.name, 16)),
                        Style::default().fg(TEXT()),
                    ),
                    Span::styled(
                        format!("{:<22}", truncate(&t.forward_summary(), 22)),
                        Style::default().fg(DIM()),
                    ),
                    Span::styled(
                        format!("via {:<12}", truncate(&t.ssh_host, 12)),
                        Style::default().fg(DIM()),
                    ),
                    needs_span(app, t),
                ]))
            }
        })
        .collect();

    let empty = items.is_empty();
    let list = List::new(items)
        .highlight_style(Style::default().bg(SELECTION_BG()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Span::styled(" tunnels ", Style::default().fg(TEXT()))),
        );

    let mut state = ListState::default();
    if !empty {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    if empty {
        let hint = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no tunnels configured yet",
                Style::default().fg(DIM()),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  press ", Style::default().fg(DIM())),
                Span::styled("a", Style::default().fg(ACCENT()).bold()),
                Span::styled(" to add your first tunnel", Style::default().fg(DIM())),
            ]),
        ]);
        let inner = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + 1,
            width: chunks[0].width.saturating_sub(2),
            height: chunks[0].height.saturating_sub(2),
        };
        f.render_widget(hint, inner);
    }

    render_details(f, app, chunks[1]);
}

fn render_details(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    match app.rows.get(app.selected) {
        Some(RowItem::Group(g)) => {
            let members = app.group_members(g);
            let up = members
                .iter()
                .filter(|i| app.active.contains_key(&app.tunnels[**i].name))
                .count();
            lines.extend(group_details(g, members.len(), up, "active"));
            lines.push(Line::from(Span::styled(
                "Enter starts every inactive member,",
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                "or stops all when everything is up.",
                Style::default().fg(DIM()),
            )));
        }
        Some(RowItem::Item(i)) => {
            let t = &app.tunnels[*i];
            let field = |k: &str, v: String| {
                Line::from(vec![
                    Span::styled(format!("{k:<11}"), Style::default().fg(DIM())),
                    Span::styled(v, Style::default().fg(TEXT())),
                ])
            };
            lines.push(field("name", t.name.clone()));
            if !t.group.is_empty() {
                lines.push(field("group", t.group.clone()));
            }
            lines.push(field("ssh host", t.ssh_host.clone()));
            lines.push(field("type", t.forward.label().to_string()));
            lines.push(field("forward", t.forward_summary()));
            if !t.extra_args.is_empty() {
                lines.push(field("extra args", t.extra_args.clone()));
            }
            lines.push(field(
                "reconnect",
                if t.auto_reconnect { "auto" } else { "manual" }.to_string(),
            ));
            lines.push(Line::from(vec![
                Span::styled("needs vpn  ", Style::default().fg(DIM())),
                vpn_span(app, &t.requires_vpn),
            ]));
            lines.push(Line::from(vec![
                Span::styled("needs tun  ", Style::default().fg(DIM())),
                dependency_span(app, &t.depends_on),
            ]));
            lines.extend(chain_lines(app, Step::Tunnel(t.name.clone())));
            let dependents = app.dependents_of(&t.name);
            if !dependents.is_empty() {
                lines.push(field("needed by", dependents.join(", ")));
            }

            if let Some(a) = app.active.get(&t.name) {
                lines.push(Line::from(""));
                let status_style = match a.status {
                    Status::Up => Style::default().fg(OK()).bold(),
                    Status::Connecting => Style::default().fg(WARN()).bold(),
                    Status::Failed => Style::default().fg(DANGER()).bold(),
                };
                lines.push(Line::from(vec![
                    Span::styled("status     ", Style::default().fg(DIM())),
                    Span::styled(a.status.label(), status_style),
                ]));
                lines.push(field("uptime", fmt_duration(a.started_at.elapsed())));
                if t.forward != ForwardType::Remote {
                    let c = &a.counters;
                    lines.push(field(
                        "conns",
                        format!(
                            "{} active / {} total",
                            c.active_conns.load(std::sync::atomic::Ordering::Relaxed),
                            c.total_conns.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    ));
                    lines.push(field(
                        "traffic",
                        format!(
                            "↑ {}  ↓ {}",
                            human_bytes(c.tx.load(std::sync::atomic::Ordering::Relaxed)),
                            human_bytes(c.rx.load(std::sync::atomic::Ordering::Relaxed))
                        ),
                    ));
                }
                if a.restarts > 0 {
                    lines.push(field("restarts", a.restarts.to_string()));
                }
                if let Some(err) = &a.error {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        err.clone(),
                        Style::default().fg(DANGER()),
                    )));
                }
                let recent = a.recent_stderr(5);
                if !recent.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "ssh output:",
                        Style::default().fg(DIM()),
                    )));
                    for l in recent {
                        lines.push(Line::from(Span::styled(l.text, Style::default().fg(DIM()))));
                    }
                }
            } else {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("press ", Style::default().fg(DIM())),
                    Span::styled("Enter", Style::default().fg(ACCENT()).bold()),
                    Span::styled(" to start this tunnel", Style::default().fg(DIM())),
                ]));
            }
        }
        None => {
            lines.push(Line::from(Span::styled(
                "nothing selected",
                Style::default().fg(DIM()),
            )));
        }
    }

    let details = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" details ", Style::default().fg(TEXT()))),
    );
    f.render_widget(details, area);
}

// ---------------------------------------------------------------------------
// VPN tab
// ---------------------------------------------------------------------------

/// Clients on the left, that client's profiles in the middle, its status on the
/// right. A client that is not installed stays in the list, greyed out, so the
/// status pane can say where to get it.
fn render_vpn(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            // Wide enough for "· wireguard  n/i" without truncating.
            Constraint::Length(22),
            Constraint::Percentage(38),
            Constraint::Percentage(62),
        ])
        .split(area);

    render_vpn_clients(f, app, chunks[0]);
    render_vpn_profiles(f, app, chunks[1]);
    render_vpn_status(f, app, chunks[2]);
}

/// The border of the pane that has the keyboard is drawn in the accent colour.
fn pane_border(focused: bool) -> Style {
    Style::default().fg(if focused { ACCENT() } else { BORDER() })
}

fn render_vpn_clients(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .vpn
        .providers
        .iter()
        .map(|state| {
            let (dot, dot_style) = if !state.installed {
                ("·", Style::default().fg(DIM()))
            } else if state.busy.is_some() {
                ("◌", Style::default().fg(WARN()))
            } else if state.status.connected {
                ("●", Style::default().fg(OK()))
            } else {
                ("○", Style::default().fg(DIM()))
            };
            let name_style = match (state.installed, state.status.connected) {
                (false, _) => Style::default().fg(DIM()),
                (true, true) => Style::default().fg(TEXT()).bold(),
                (true, false) => Style::default().fg(TEXT()),
            };
            let mut spans = vec![
                Span::raw(" "),
                Span::styled(format!("{dot} "), dot_style),
                Span::styled(state.id.slug(), name_style),
            ];
            if !state.installed {
                spans.push(Span::styled("  n/i", Style::default().fg(DIM())));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(Style::default().bg(SELECTION_BG()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border(app.vpn.focus == VpnPane::Clients))
                .title(Span::styled(" clients ", Style::default().fg(TEXT()))),
        );
    let mut state = ListState::default();
    state.select(Some(app.vpn.client_idx));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_vpn_profiles(f: &mut Frame, app: &App, area: Rect) {
    let provider = app.vpn.current();
    let title = format!(" {} profiles ", provider.id.slug());
    let focused = app.vpn.focus == VpnPane::Profiles;

    let items: Vec<ListItem> = provider
        .profiles
        .iter()
        .map(|p| {
            // A row controlcenter is not holding is up, but it is not one of
            // ours: a different mark, so the list never reads as if the program
            // started something it cannot account for.
            let dot = if !p.is_stored() {
                Span::styled("◆ ", Style::default().fg(WARN()))
            } else if p.active {
                Span::styled("● ", Style::default().fg(OK()))
            } else {
                Span::styled("○ ", Style::default().fg(DIM()))
            };
            let name_style = if !p.is_stored() {
                Style::default().fg(WARN())
            } else if p.active {
                Style::default().fg(TEXT()).bold()
            } else {
                Style::default().fg(TEXT())
            };
            let mut spans = vec![Span::raw(" "), dot, Span::styled(p.name.clone(), name_style)];
            let needed_by = if p.is_stored() {
                app.vpn_dependents_of(&format!("{}:{}", provider.id.slug(), p.name))
                    .len()
            } else {
                0
            };
            if needed_by > 0 {
                spans.push(Span::styled(
                    format!("  {needed_by} dep(s)"),
                    Style::default().fg(DIM()),
                ));
            }
            if !p.detail.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", truncate(&p.detail, if p.is_stored() { 24 } else { 40 })),
                    Style::default().fg(DIM()),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let empty = items.is_empty();
    let list = List::new(items)
        .highlight_style(Style::default().bg(SELECTION_BG()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border(focused))
                .title(Span::styled(title, Style::default().fg(TEXT()))),
        );
    let mut state = ListState::default();
    if !empty {
        state.select(Some(provider.selected));
    }
    f.render_stateful_widget(list, area, &mut state);

    if empty {
        let hint = if !provider.installed {
            format!("  {} is not installed", provider.id.slug())
        } else if provider.id.manages_profiles() {
            "  no profiles yet — press a to add one".to_string()
        } else {
            "  no profiles found".to_string()
        };
        let inner = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(hint, Style::default().fg(DIM())))),
            inner,
        );
    }
}

fn render_vpn_status(f: &mut Frame, app: &App, area: Rect) {
    let provider = app.vpn.current();
    let mut lines: Vec<Line> = Vec::new();

    if !provider.installed {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {} was not found on PATH", provider.id.slug()),
            Style::default().fg(WARN()),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", provider.id.install_hint()),
            Style::default().fg(DIM()),
        )));
        let waiting = app.vpn_dependents_of_provider(provider.id);
        if !waiting.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  {} connection(s) ask for it:", waiting.len()),
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                format!("   {}", waiting.join(", ")),
                Style::default().fg(TEXT()),
            )));
        }
        f.render_widget(vpn_status_block(lines), area);
        return;
    }

    let st = &provider.status;
    let state_span = if st.connected {
        Span::styled("connected", Style::default().fg(OK()).bold())
    } else {
        Span::styled("disconnected", Style::default().fg(DANGER()).bold())
    };
    lines.push(kv("state", state_span));
    if let Some(busy) = &provider.busy {
        lines.push(kv(
            "action",
            Span::styled(format!("{busy}…"), Style::default().fg(WARN()).bold()),
        ));
    }
    if provider.id.needs_root() && !crate::vpn::privileged::available() {
        lines.push(kv(
            "root",
            Span::styled(
                "no pkexec or sudo found",
                Style::default().fg(DANGER()),
            ),
        ));
    }
    lines.push(Line::from(""));
    for (k, v) in &st.fields {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<20}", k.to_lowercase()),
                Style::default().fg(DIM()),
            ),
            Span::styled(v.clone(), Style::default().fg(TEXT())),
        ]));
    }
    if let Some(err) = st.error.as_ref().or(provider.error.as_ref()) {
        lines.push(Line::from(""));
        for line in err.lines() {
            lines.push(Line::from(Span::styled(
                format!(" {line}"),
                Style::default().fg(DANGER()),
            )));
        }
    }

    // OpenVPN profiles are a directory, not a single setting: show what is in it.
    if provider.id == ProviderId::Openvpn {
        if let Some((name, files)) = app.openvpn_import_listing() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(" '{name}' imported into controlcenter:"),
                Style::default().fg(DIM()),
            )));
            if files.is_empty() {
                lines.push(Line::from(Span::styled(
                    "   nothing yet — save the profile to import it",
                    Style::default().fg(WARN()),
                )));
            } else {
                for f in files {
                    lines.push(Line::from(Span::styled(
                        format!("   {f}"),
                        Style::default().fg(TEXT()),
                    )));
                }
            }
        }
    }

    // What is on the machine that this client is not holding, and every tunnel
    // device found — the two halves of "is something else already up".
    let not_ours: Vec<&crate::vpn::VpnProfile> = provider.foreign().collect();
    if !not_ours.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {} connection(s) controlcenter is not holding:", not_ours.len()),
            Style::default().fg(WARN()),
        )));
        for p in &not_ours {
            lines.push(Line::from(vec![
                Span::styled("   ◆ ", Style::default().fg(WARN())),
                Span::styled(p.name.clone(), Style::default().fg(TEXT())),
                Span::styled(format!("  {}", p.detail), Style::default().fg(DIM())),
            ]));
        }
        lines.push(Line::from(Span::styled(
            "   Enter stops one; press it again to kill what ignored SIGTERM.",
            Style::default().fg(DIM()),
        )));
    }

    let devices = app.tunnel_devices();
    if !devices.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " tunnel devices on this machine:",
            Style::default().fg(DIM()),
        )));
        for (link, owner) in &devices {
            let owner = match owner {
                Some(id) => format!("{}", id.slug()),
                None => "unaccounted for".to_string(),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("   {:<10}", link.name), Style::default().fg(TEXT())),
                Span::styled(
                    format!("{:<16}", link.detail()),
                    Style::default().fg(DIM()),
                ),
                Span::styled(
                    owner.clone(),
                    Style::default().fg(if owner == "unaccounted for" {
                        WARN()
                    } else {
                        DIM()
                    }),
                ),
            ]));
        }
    }

    if let Some(p) = provider.selected_profile().filter(|p| p.is_stored()) {
        let want = format!("{}:{}", provider.id.slug(), p.name);
        let dependents = app.vpn_dependents_of(&want);
        let any = app.vpn_dependents_of(crate::types::VPN_ANY);
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" requires '{want}':"),
            Style::default().fg(DIM()),
        )));
        if dependents.is_empty() {
            lines.push(Line::from(Span::styled(
                "   nothing",
                Style::default().fg(DIM()),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!("   {}", dependents.join(", ")),
                Style::default().fg(TEXT()),
            )));
        }
        if !any.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("   plus {} needing any VPN", any.len()),
                Style::default().fg(DIM()),
            )));
        }
    }

    lines.push(Line::from(""));
    for hint in vpn_hints(provider.id) {
        lines.push(Line::from(Span::styled(hint, Style::default().fg(DIM()))));
    }

    f.render_widget(vpn_status_block(lines), area);
}

fn vpn_status_block(lines: Vec<Line>) -> Paragraph {
    Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" status ", Style::default().fg(TEXT()))),
    )
}

/// What is worth knowing about this particular client, in the space there is.
fn vpn_hints(id: ProviderId) -> Vec<&'static str> {
    match id {
        ProviderId::Netbird => vec![
            " Enter switches to the selected profile and connects.",
            " Anything that requires the profile being left is disconnected.",
            " Profiles are netbird's own; add them with the netbird CLI.",
        ],
        ProviderId::Wireguard => vec![
            " Enter runs wg-quick up on the selected profile; Enter again takes it down.",
            " ◆ marks an interface no stored profile accounts for; Enter runs wg-quick down.",
            " Several interfaces can be up at once, so profiles never conflict.",
            " Connecting asks for root through polkit.",
        ],
        ProviderId::Openvpn => vec![
            " Enter starts the session; l shows its log.",
            " ◆ marks something controlcenter is not holding: an openvpn process",
            " that outlived an earlier run, or a tun device its session left behind",
            " still holding the address. Enter takes one away; that is all it does.",
            " Saving a profile copies the .ovpn and every certificate it names",
            " into controlcenter, so it survives the download folder being cleaned up.",
            " Disconnecting asks for root a second time: the process runs as root",
            " and has to be signalled by the pid openvpn wrote.",
        ],
        ProviderId::Tailscale => vec![
            " Enter runs tailscale up --reset with the profile's flags,",
            " so a profile always means exactly the state it describes.",
            " Connecting asks for root through polkit.",
        ],
    }
}

/// The add/edit form. All three editable providers share it, driven by their
/// field table, because they differ only in which lines they show.
fn render_vpn_form_overlay(f: &mut Frame, app: &App, area: Rect, edit: bool) {
    let form = &app.vpn_form;
    let fields = form.fields();
    // fields + a blank line + the hint, and one more for wireguard's key hint.
    let height = fields.len() as u16 + if form.provider == ProviderId::Wireguard { 5 } else { 4 };
    let rect = centered_rect(84, height.min(area.height), area);
    f.render_widget(Clear, rect);

    let title = format!(
        " {} {} profile ",
        if edit { "edit" } else { "add" },
        form.provider.slug()
    );
    let value_width = value_width(rect, 33);

    let mut lines: Vec<Line> = Vec::new();
    for (i, spec) in fields.iter().enumerate() {
        let is_active = i == form.field_idx;
        let label_style = if is_active {
            Style::default().fg(ACCENT()).bold()
        } else {
            Style::default().fg(DIM())
        };
        let raw = form.display(spec);
        let value = if spec.flag {
            format!("◂ {raw} ▸")
        } else {
            scrolled(&raw, value_width)
        };
        let value_style = if spec.secret && !raw.is_empty() {
            Style::default().fg(WARN())
        } else {
            Style::default().fg(TEXT())
        };
        let cursor = if is_active && !spec.flag { "▏" } else { "" };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<32}", spec.label), label_style),
            Span::styled(value, value_style),
            Span::styled(cursor, Style::default().fg(ACCENT())),
        ]));
    }
    lines.push(Line::from(""));
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(DANGER()),
        )));
    } else if form.field().is_some_and(|f| f.id == "config_path") {
        lines.push(Line::from(Span::styled(
            " Ctrl+O file picker · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            " tab/↓ next · ↑ prev · ◂▸ toggle · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
        if form.provider == ProviderId::Wireguard {
            lines.push(Line::from(Span::styled(
                " g on the private key field generates a fresh keypair",
                Style::default().fg(DIM()),
            )));
        }
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(title, Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

fn render_vpn_delete_confirm(f: &mut Frame, app: &App, area: Rect, provider: ProviderId, idx: usize) {
    let name = match provider {
        ProviderId::Wireguard => app.vpn_cfg.wireguard.get(idx).map(|p| p.name.clone()),
        ProviderId::Openvpn => app.vpn_cfg.openvpn.get(idx).map(|p| p.name.clone()),
        ProviderId::Tailscale => app.vpn_cfg.tailscale.get(idx).map(|p| p.name.clone()),
        ProviderId::Netbird => None,
    }
    .unwrap_or_else(|| "?".into());
    render_confirm_box(
        f,
        area,
        &format!(" delete {} profile '{name}'?", provider.slug()),
    );
}

/// The same acknowledgement the SSH tab asks for before storing a password:
/// vpn.toml is 0600, but it is still cleartext on disk.
fn render_vpn_secret_warning(f: &mut Frame, app: &App, area: Rect) {
    let path = app.paths.vpn_file.display().to_string();
    let what = match app.vpn_form.provider {
        ProviderId::Wireguard => "The private key is saved in cleartext.",
        _ => "The password is saved in cleartext.",
    };
    let rect = centered_rect(68, 10, area);
    f.render_widget(Clear, rect);
    let para = Paragraph::new(vec![
        Line::from(Span::styled(
            format!(" {what}"),
            Style::default().fg(WARN()).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(" It goes into {path}, which is written mode 0600."),
            Style::default().fg(TEXT()),
        )),
        Line::from(Span::styled(
            " Anything that can read your files can read it.",
            Style::default().fg(TEXT()),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " y / Enter to save anyway · any other key to go back",
            Style::default().fg(DIM()),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(WARN()))
            .title(Span::styled(
                " store a secret? ",
                Style::default().fg(WARN()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

// ---------------------------------------------------------------------------
// RDP tab
// ---------------------------------------------------------------------------

fn rdp_status_dot(app: &App, name: &str) -> Span<'static> {
    match app.rdp_active.get(name).map(|a| a.status) {
        Some(RdpStatus::Running) => Span::styled("●", Style::default().fg(OK())),
        Some(RdpStatus::Exited(0)) => Span::styled("○", Style::default().fg(DIM())),
        Some(RdpStatus::Exited(_)) => Span::styled("✖", Style::default().fg(DANGER())),
        None => Span::styled("○", Style::default().fg(DIM())),
    }
}

fn render_rdp(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let items: Vec<ListItem> = app
        .rdp_rows
        .iter()
        .map(|row| match row {
            RowItem::Group(g) => {
                let members = app.rdp_group_members(g);
                let up = members
                    .iter()
                    .filter(|i| app.rdp_running(&app.rdp_conns[**i].name))
                    .count();
                group_header(g, &format!("({up}/{} connected)", members.len()))
            }
            RowItem::Item(i) => {
                let c = &app.rdp_conns[*i];
                let indent = if c.group.is_empty() { " " } else { "   " };
                ListItem::new(Line::from(vec![
                    Span::raw(indent.to_string()),
                    rdp_status_dot(app, &c.name),
                    Span::styled(
                        format!(" {:<16}", truncate(&c.name, 16)),
                        Style::default().fg(TEXT()),
                    ),
                    Span::styled(
                        format!("{:<20}", truncate(&c.target_summary(), 20)),
                        Style::default().fg(DIM()),
                    ),
                    Span::styled(
                        format!("{:<15}", format!("as {}", truncate(&c.login_summary(), 12))),
                        Style::default().fg(DIM()),
                    ),
                    Span::styled("via ", Style::default().fg(DIM())),
                ]
                .into_iter()
                .chain(requires_spans(app, &c.requires_vpn, &c.depends_on))
                .collect::<Vec<_>>()))
            }
        })
        .collect();

    let empty = items.is_empty();
    let list = List::new(items)
        .highlight_style(Style::default().bg(SELECTION_BG()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Span::styled(" rdp connections ", Style::default().fg(TEXT()))),
        );
    let mut state = ListState::default();
    if !empty {
        state.select(Some(app.rdp_selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    if empty {
        let hint = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no RDP connections configured yet",
                Style::default().fg(DIM()),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  press ", Style::default().fg(DIM())),
                Span::styled("a", Style::default().fg(ACCENT()).bold()),
                Span::styled(" to add your first connection", Style::default().fg(DIM())),
            ]),
        ]);
        let inner = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + 1,
            width: chunks[0].width.saturating_sub(2),
            height: chunks[0].height.saturating_sub(2),
        };
        f.render_widget(hint, inner);
    }

    // Details panel
    let mut lines: Vec<Line> = Vec::new();
    match app.rdp_rows.get(app.rdp_selected) {
        Some(RowItem::Group(g)) => {
            let members = app.rdp_group_members(g);
            let up = members
                .iter()
                .filter(|i| app.rdp_running(&app.rdp_conns[**i].name))
                .count();
            lines.extend(group_details(g, members.len(), up, "connected"));
            lines.push(Line::from(Span::styled(
                "Enter connects every idle member —",
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                "each is asked for its password in turn —",
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                "or disconnects all when everything is up.",
                Style::default().fg(DIM()),
            )));
        }
        Some(RowItem::Item(idx)) => {
            let c = &app.rdp_conns[*idx];
            let field = |k: &str, v: String| {
                Line::from(vec![
                    Span::styled(format!("{k:<11}"), Style::default().fg(DIM())),
                    Span::styled(v, Style::default().fg(TEXT())),
                ])
            };
            lines.push(field("name", c.name.clone()));
            lines.push(field("host", c.target_summary()));
            if !c.domain.is_empty() {
                lines.push(field("domain", c.domain.clone()));
            }
            lines.push(field("username", c.username.clone()));
            lines.push(Line::from(vec![
                Span::styled("needs vpn  ", Style::default().fg(DIM())),
                vpn_span(app, &c.requires_vpn),
            ]));
            lines.push(Line::from(vec![
                Span::styled("needs tun  ", Style::default().fg(DIM())),
                dependency_span(app, &c.depends_on),
            ]));
            lines.extend(chain_lines(
                app,
                Step::Rdp {
                    name: c.name.clone(),
                    password: String::new(),
                },
            ));
            if !c.extra_args.is_empty() {
                lines.push(field("extra args", c.extra_args.clone()));
            }

            match app.rdp_active.get(&c.name) {
                Some(a) => {
                    lines.push(Line::from(""));
                    let status_style = match a.status {
                        RdpStatus::Running => Style::default().fg(OK()).bold(),
                        RdpStatus::Exited(0) => Style::default().fg(DIM()).bold(),
                        RdpStatus::Exited(_) => Style::default().fg(DANGER()).bold(),
                    };
                    lines.push(Line::from(vec![
                        Span::styled("status     ", Style::default().fg(DIM())),
                        Span::styled(a.status.label(), status_style),
                    ]));
                    lines.push(field("uptime", fmt_duration(a.started_at.elapsed())));
                    let recent = a.recent_log(6);
                    if !recent.is_empty() {
                        lines.push(Line::from(""));
                        lines.push(Line::from(vec![
                            Span::styled("log (", Style::default().fg(DIM())),
                            Span::styled("l", Style::default().fg(ACCENT()).bold()),
                            Span::styled(" for full view):", Style::default().fg(DIM())),
                        ]));
                        for l in recent {
                            lines.push(Line::from(Span::styled(
                                truncate(&l.text, 60),
                                Style::default().fg(DIM()),
                            )));
                        }
                    }
                }
                None => {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("press ", Style::default().fg(DIM())),
                        Span::styled("Enter", Style::default().fg(ACCENT()).bold()),
                        Span::styled(" to connect (password prompt)", Style::default().fg(DIM())),
                    ]));
                }
            }
        }
        None => {
            lines.push(Line::from(Span::styled(
                "nothing selected",
                Style::default().fg(DIM()),
            )));
        }
    }

    let details = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" details ", Style::default().fg(TEXT()))),
    );
    f.render_widget(details, chunks[1]);
}

// ---------------------------------------------------------------------------
// SSH tab
// ---------------------------------------------------------------------------

/// Dependency shown next to a connection: dim when idle, green when the tunnel
/// it needs is up, red when the tunnel no longer exists.
fn dependency_span(app: &App, dep: &str) -> Span<'static> {
    if dep.is_empty() {
        return Span::styled("—", Style::default().fg(DIM()));
    }
    if app.dependency_missing(dep) {
        return Span::styled(format!("{dep} (missing)"), Style::default().fg(DANGER()));
    }
    let color = match app.active.get(dep).map(|a| a.status) {
        Some(Status::Up) => OK(),
        Some(Status::Connecting) => WARN(),
        Some(Status::Failed) => DANGER(),
        None => DIM(),
    };
    Span::styled(dep.to_string(), Style::default().fg(color))
}

/// The full path a connection runs through, e.g. "vpn work → tun base → ssh app".
/// Renders the reason instead when the chain cannot be resolved.
fn chain_lines(app: &App, step: Step) -> Vec<Line<'static>> {
    match app.chain_of(step) {
        Ok(parts) if parts.len() > 1 => vec![
            Line::from(Span::styled("chain", Style::default().fg(DIM()))),
            Line::from(Span::styled(
                format!("  {}", parts.join(" → ")),
                Style::default().fg(TEXT()),
            )),
        ],
        Ok(_) => Vec::new(),
        Err(e) => vec![Line::from(Span::styled(
            format!("chain      {e}"),
            Style::default().fg(DANGER()),
        ))],
    }
}

/// "vpn work" / "any profile" with a colour for whether it currently holds.
fn vpn_span(app: &App, req: &str) -> Span<'static> {
    if req.is_empty() {
        return Span::styled("—", Style::default().fg(DIM()));
    }
    let color = if app.vpn_satisfied(req) { OK() } else { DIM() };
    Span::styled(vpn_requirement_label(req), Style::default().fg(color))
}

/// Same, shortened for a list row where it sits next to a tunnel name.
fn vpn_span_short(app: &App, req: &str) -> Span<'static> {
    let color = if app.vpn_satisfied(req) { OK() } else { DIM() };
    let label = if req == crate::types::VPN_ANY {
        "vpn any".to_string()
    } else {
        format!("vpn {req}")
    };
    Span::styled(label, Style::default().fg(color))
}

/// "vpn work + base" for a connection row, each half coloured by whether it
/// currently holds.
fn requires_spans(app: &App, vpn: &str, tunnel: &str) -> Vec<Span<'static>> {
    if vpn.is_empty() && tunnel.is_empty() {
        return vec![Span::styled("—", Style::default().fg(DIM()))];
    }
    let mut spans = Vec::new();
    if !vpn.is_empty() {
        spans.push(vpn_span_short(app, vpn));
    }
    if !tunnel.is_empty() {
        if !spans.is_empty() {
            spans.push(Span::styled(" + ", Style::default().fg(DIM())));
        }
        spans.push(dependency_span(app, tunnel));
    }
    spans
}

fn render_ssh(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let items: Vec<ListItem> = app
        .ssh_rows
        .iter()
        .map(|row| match row {
            RowItem::Group(g) => {
                let members = app.ssh_group_members(g);
                let open = members
                    .iter()
                    .filter(|i| app.ssh_windows_open(&app.ssh_hosts[**i].name) > 0)
                    .count();
                group_header(g, &format!("({open}/{} open)", members.len()))
            }
            RowItem::Item(i) => {
                let h = &app.ssh_hosts[*i];
                let indent = if h.group.is_empty() { "" } else { "  " };
                let lock = if h.password.is_empty() {
                    Span::raw(" ")
                } else {
                    Span::styled("!", Style::default().fg(WARN()).bold())
                };
                let open = if app.ssh_windows_open(&h.name) > 0 {
                    Span::styled("●", Style::default().fg(OK()))
                } else {
                    Span::raw(" ")
                };
                ListItem::new(Line::from(vec![
                    Span::raw(indent.to_string()),
                    open,
                    lock,
                    Span::styled(
                        format!(" {:<16}", truncate(&h.name, 16)),
                        Style::default().fg(TEXT()),
                    ),
                    Span::styled(
                        format!("{:<24}", truncate(&h.target_summary(), 24)),
                        Style::default().fg(DIM()),
                    ),
                    Span::styled("via ", Style::default().fg(DIM())),
                ]
                .into_iter()
                .chain(requires_spans(app, &h.requires_vpn, &h.depends_on))
                .collect::<Vec<_>>()))
            }
        })
        .collect();

    let empty = items.is_empty();
    let list = List::new(items)
        .highlight_style(Style::default().bg(SELECTION_BG()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Span::styled(" ssh hosts ", Style::default().fg(TEXT()))),
        );
    let mut state = ListState::default();
    if !empty {
        state.select(Some(app.ssh_selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    if empty {
        let hint = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no SSH hosts configured yet",
                Style::default().fg(DIM()),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  press ", Style::default().fg(DIM())),
                Span::styled("a", Style::default().fg(ACCENT()).bold()),
                Span::styled(" to add your first host", Style::default().fg(DIM())),
            ]),
        ]);
        let inner = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + 1,
            width: chunks[0].width.saturating_sub(2),
            height: chunks[0].height.saturating_sub(2),
        };
        f.render_widget(hint, inner);
    }

    // Details panel
    let mut lines: Vec<Line> = Vec::new();
    match app.ssh_rows.get(app.ssh_selected) {
        Some(RowItem::Group(g)) => {
            let members = app.ssh_group_members(g);
            let open = members
                .iter()
                .filter(|i| app.ssh_windows_open(&app.ssh_hosts[**i].name) > 0)
                .count();
            lines.extend(group_details(g, members.len(), open, "open"));
            lines.push(Line::from(Span::styled(
                "Enter opens a session for every member,",
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                "bringing a shared VPN or tunnel up once.",
                Style::default().fg(DIM()),
            )));
        }
        Some(RowItem::Item(idx)) => {
            let h = &app.ssh_hosts[*idx];
            let field = |k: &str, v: String| {
                Line::from(vec![
                    Span::styled(format!("{k:<11}"), Style::default().fg(DIM())),
                    Span::styled(v, Style::default().fg(TEXT())),
                ])
            };
            lines.push(field("name", h.name.clone()));
            lines.push(field("target", h.target_summary()));
            lines.push(field("auth", h.auth_summary()));
            if h.skip_host_key_check {
                lines.push(Line::from(vec![
                    Span::styled("host key   ", Style::default().fg(DIM())),
                    Span::styled("verification skipped", Style::default().fg(WARN())),
                ]));
            }
            lines.push(Line::from(vec![
                Span::styled("needs vpn  ", Style::default().fg(DIM())),
                vpn_span(app, &h.requires_vpn),
            ]));
            lines.push(Line::from(vec![
                Span::styled("needs tun  ", Style::default().fg(DIM())),
                dependency_span(app, &h.depends_on),
            ]));
            lines.extend(chain_lines(app, Step::Ssh(h.name.clone())));
            if !h.extra_args.is_empty() {
                lines.push(field("extra args", h.extra_args.clone()));
            }

            if !h.password.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "password stored in cleartext in ssh.toml",
                    Style::default().fg(WARN()),
                )));
                lines.push(Line::from(vec![
                    Span::styled("press ", Style::default().fg(DIM())),
                    Span::styled("p", Style::default().fg(ACCENT()).bold()),
                    Span::styled(" to remove it", Style::default().fg(DIM())),
                ]));
                if !app.sshpass_installed {
                    lines.push(Line::from(Span::styled(
                        "sshpass is not on PATH — it cannot be used",
                        Style::default().fg(DANGER()),
                    )));
                }
            }

            let open = app.ssh_windows_open(&h.name);
            if open > 0 {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("session    ", Style::default().fg(DIM())),
                    Span::styled(
                        format!("{open} window{} open", if open == 1 { "" } else { "s" }),
                        Style::default().fg(OK()),
                    ),
                ]));
            }

            if let Some(last) = app.ssh_last.get(&h.name) {
                lines.push(Line::from(""));
                let style = if last.failed() {
                    Style::default().fg(DANGER())
                } else {
                    Style::default().fg(DIM())
                };
                lines.push(Line::from(vec![
                    Span::styled("last run   ", Style::default().fg(DIM())),
                    Span::styled(last.label(), style),
                ]));
                lines.push(field("lasted", fmt_duration(last.duration)));
                lines.push(field("ended", format!("{} ago", fmt_duration(last.finished_at.elapsed()))));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                truncate(&ssh::command_preview(h), 60),
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("press ", Style::default().fg(DIM())),
                Span::styled("Enter", Style::default().fg(ACCENT()).bold()),
                Span::styled(
                    format!(" to open a session in {}", app.ssh_launcher.label()),
                    Style::default().fg(DIM()),
                ),
            ]));
        }
        None => {
            lines.push(Line::from(Span::styled(
                "nothing selected",
                Style::default().fg(DIM()),
            )));
        }
    }

    let details = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" details ", Style::default().fg(TEXT()))),
    );
    f.render_widget(details, chunks[1]);
}

// ---------------------------------------------------------------------------
// Status bar / overlays
// ---------------------------------------------------------------------------

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    // A running plan owns the status bar: it is the only thing that keeps
    // moving on its own, and its steps are what the user is waiting for.
    let line = if let Some(act) = &app.activation {
        Line::from(vec![
            Span::styled(" ⟳ ", Style::default().fg(WARN()).bold()),
            Span::styled(
                format!("starting {} ", act.target),
                Style::default().fg(TEXT()),
            ),
            Span::styled(act.progress(), Style::default().fg(ACCENT())),
        ])
    } else if let Some((msg, is_error, _)) = &app.status_msg {
        let color = if *is_error { DANGER() } else { OK() };
        Line::from(Span::styled(format!(" {msg}"), Style::default().fg(color)))
    } else {
        // The same keys in the same order everywhere; only what each one acts
        // on differs, so only the words after the key change.
        let hints: &[(&str, &str)] = match app.tab {
            Tab::Dashboard => &[
                ("1-5/tab", "tab"),
                ("r", "reload"),
                ("l", "log"),
                ("s", "report"),
                ("c", "clear"),
                ("x", "panic"),
                ("t", "theme"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Vpn => &[
                ("↵", "connect/disconnect"),
                ("a/e/d", "profile"),
                ("ctrl↑↓", "move"),
                ("r", "refresh"),
                ("p", "password"),
                ("l", "log"),
                ("s", "report"),
                ("x", "panic"),
                ("?", "help"),
                ("k", "keys"),
            ],
            Tab::Tunnels => &[
                ("↵", "start/stop"),
                ("a/e/d", "tunnel"),
                ("ctrl↑↓", "move"),
                ("r", "restart"),
                ("l", "log"),
                ("s", "report"),
                ("c", "clear"),
                ("x", "panic"),
                ("?", "help"),
                ("k", "keys"),
            ],
            Tab::Ssh => &[
                ("↵", "open session"),
                ("a/e/d", "host"),
                ("ctrl↑↓", "move"),
                ("r", "new session"),
                ("p", "password"),
                ("l", "log"),
                ("s", "report"),
                ("c", "clear"),
                ("x", "panic"),
                ("?", "help"),
            ],
            Tab::Rdp => &[
                ("↵", "connect/disconnect"),
                ("a/e/d", "connection"),
                ("ctrl↑↓", "move"),
                ("r", "reconnect"),
                ("l", "log"),
                ("s", "report"),
                ("c", "clear"),
                ("x", "panic"),
                ("?", "help"),
                ("k", "keys"),
            ],
        };
        let mut spans = Vec::new();
        for (key, desc) in hints {
            spans.push(Span::styled(
                format!(" {key} "),
                Style::default().fg(ACCENT()),
            ));
            spans.push(Span::styled(
                format!("{desc} "),
                Style::default().fg(DIM()),
            ));
        }
        Line::from(spans)
    };
    f.render_widget(Paragraph::new(line), area);
}

fn render_form_overlay(f: &mut Frame, app: &App, area: Rect) {
    let form = &app.form;
    let visible: Vec<FormField> = FORM_FIELDS
        .iter()
        .copied()
        .filter(|fld| fld.applies(form.forward))
        .collect();
    let height = (visible.len() + 5) as u16;
    let rect = centered_rect(70, height, area);
    f.render_widget(Clear, rect);

    let title = match app.form_mode {
        FormMode::Edit(_) => " edit tunnel ",
        _ => " add tunnel ",
    };
    let value_width = value_width(rect, 33);

    let mut lines: Vec<Line> = Vec::new();
    for fld in &visible {
        let is_active = *fld == form.field();
        let label_style = if is_active {
            Style::default().fg(ACCENT()).bold()
        } else {
            Style::default().fg(DIM())
        };
        let value: String = match fld {
            FormField::Name => form.name.clone(),
            FormField::Group => form.group.clone(),
            FormField::SshHost => form.ssh_host.clone(),
            FormField::Forward => format!("◂ {} ▸", form.forward.label()),
            FormField::LocalPort => form.local_port.clone(),
            FormField::RemoteHost => form.remote_host.clone(),
            FormField::RemotePort => form.remote_port.clone(),
            FormField::ExtraArgs => form.extra_args.clone(),
            FormField::AutoReconnect => {
                format!("◂ {} ▸", if form.auto_reconnect { "yes" } else { "no" })
            }
            FormField::RequiresVpn => format!("◂ {} ▸", form.vpn.label()),
            FormField::DependsOn => format!("◂ {} ▸", form.dep.label()),
        };
        let cursor = if is_active && !fld.is_picker() { "▏" } else { "" };
        let value = if fld.is_picker() { value } else { scrolled(&value, value_width) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<32}", fld.label(form.forward)), label_style),
            Span::styled(value, Style::default().fg(TEXT())),
            Span::styled(cursor, Style::default().fg(ACCENT())),
        ]));
    }
    lines.push(Line::from(""));
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(DANGER()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            " tab/↓ next · ↑ prev · ◂▸ toggle · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(title, Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

fn render_delete_confirm(f: &mut Frame, app: &App, area: Rect, idx: usize) {
    let name = app
        .tunnels
        .get(idx)
        .map(|t| t.name.as_str())
        .unwrap_or("?");
    render_confirm_box(f, area, &format!(" delete tunnel '{name}'?"));
}

fn render_rdp_delete_confirm(f: &mut Frame, app: &App, area: Rect, idx: usize) {
    let name = app
        .rdp_conns
        .get(idx)
        .map(|c| c.name.as_str())
        .unwrap_or("?");
    render_confirm_box(f, area, &format!(" delete RDP connection '{name}'?"));
}

fn render_confirm_box(f: &mut Frame, area: Rect, question: &str) {
    let rect = centered_rect(50, 5, area);
    f.render_widget(Clear, rect);
    let para = Paragraph::new(vec![
        Line::from(Span::styled(
            question.to_string(),
            Style::default().fg(TEXT()),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" y", Style::default().fg(DANGER()).bold()),
            Span::styled(" delete · ", Style::default().fg(DIM())),
            Span::styled("any other key", Style::default().fg(ACCENT())),
            Span::styled(" cancel", Style::default().fg(DIM())),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DANGER()))
            .title(Span::styled(
                " confirm ",
                Style::default().fg(DANGER()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

fn render_rdp_form_overlay(f: &mut Frame, app: &App, area: Rect) {
    let form = &app.rdp_form;
    let height = (RDP_FIELDS.len() + 5) as u16;
    let rect = centered_rect(64, height, area);
    f.render_widget(Clear, rect);

    let title = match app.rdp_mode {
        RdpMode::Edit(_) => " edit rdp connection ",
        _ => " add rdp connection ",
    };
    let value_width = value_width(rect, 31);

    let mut lines: Vec<Line> = Vec::new();
    for fld in RDP_FIELDS {
        let is_active = *fld == form.field();
        let label_style = if is_active {
            Style::default().fg(ACCENT()).bold()
        } else {
            Style::default().fg(DIM())
        };
        let value: String = match fld {
            RdpField::Name => form.name.clone(),
            RdpField::Group => form.group.clone(),
            RdpField::Host => form.host.clone(),
            RdpField::Port => form.port.clone(),
            RdpField::Domain => form.domain.clone(),
            RdpField::Username => form.username.clone(),
            RdpField::ExtraArgs => form.extra_args.clone(),
            RdpField::RequiresVpn => format!("◂ {} ▸", form.vpn.label()),
            RdpField::DependsOn => format!("◂ {} ▸", form.dep.label()),
        };
        let cursor = if is_active && !fld.is_picker() { "▏" } else { "" };
        let value = if fld.is_picker() { value } else { scrolled(&value, value_width) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<30}", fld.label()), label_style),
            Span::styled(value, Style::default().fg(TEXT())),
            Span::styled(cursor, Style::default().fg(ACCENT())),
        ]));
    }
    lines.push(Line::from(""));
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(DANGER()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            " tab/↓ next · ↑ prev · ◂▸ toggle · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(title, Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

/// `pending` holds the connections still to be asked about, current one first;
/// `done` how many of a group have already been answered.
fn render_rdp_password_overlay(
    f: &mut Frame,
    app: &App,
    area: Rect,
    pending: &[usize],
    done: usize,
    input: &str,
) {
    let (name, login) = pending
        .first()
        .and_then(|i| app.rdp_conns.get(*i))
        .map(|c| (c.name.clone(), format!("{} @ {}", c.login_summary(), c.target_summary())))
        .unwrap_or_else(|| ("?".into(), String::new()));
    let total = done + pending.len();
    // Only a group start asks more than once, and then it says where it is.
    let counter = if total > 1 {
        format!("  ({} of {total})", done + 1)
    } else {
        String::new()
    };
    let rect = centered_rect(56, 7, area);
    f.render_widget(Clear, rect);
    let masked: String = "•".repeat(input.chars().count());
    let para = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" connect to ", Style::default().fg(DIM())),
            Span::styled(name, Style::default().fg(ACCENT()).bold()),
            Span::styled(counter, Style::default().fg(DIM())),
        ]),
        Line::from(Span::styled(format!(" {login}"), Style::default().fg(DIM()))),
        Line::from(""),
        Line::from(vec![
            Span::styled(" password  ", Style::default().fg(DIM())),
            Span::styled(masked, Style::default().fg(TEXT())),
            Span::styled("▏", Style::default().fg(ACCENT())),
        ]),
        Line::from(Span::styled(
            " Enter connect · Esc cancel (password is not stored)",
            Style::default().fg(DIM()),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(
                " rdp password ",
                Style::default().fg(ACCENT()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

/// The one log pane. Every tab opens this, and only what it is about changes:
/// what controlcenter did merged with what the process it started printed,
/// newest last.
///
/// Entries are of uneven height once they wrap, so the visible ones are walked
/// backwards from the newest until the box is full. That keeps `scroll` a count
/// of entries — what the arrow keys move — rather than of drawn rows, which
/// depend on how wide the terminal happens to be.
fn render_log_overlay(f: &mut Frame, app: &App, pane: &LogPane, area: Rect) {
    let rect = centered_rect(
        area.width.saturating_sub(8).max(40),
        area.height.saturating_sub(4).max(10),
        area,
    );
    f.render_widget(Clear, rect);

    let entries = app.log_lines(&pane.target);
    let inner = rect.width.saturating_sub(2) as usize;
    // Two borders and the footer.
    let rows = rect.height.saturating_sub(3) as usize;
    let newest = entries.len().saturating_sub(pane.scroll);

    let mut lines: Vec<Line> = Vec::new();
    for entry in entries[..newest].iter().rev() {
        let block = log_entry_lines(entry, inner);
        if !lines.is_empty() && lines.len() + block.len() > rows {
            break;
        }
        for line in block.into_iter().rev() {
            lines.insert(0, line);
        }
        if lines.len() >= rows {
            break;
        }
    }
    lines.truncate(rows);
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " nothing logged yet — a quiet connection says nothing",
            Style::default().fg(DIM()),
        )));
    }
    while lines.len() < rows {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        " s report · c clear · ↑↓ scroll · Esc/q/l close",
        Style::default().fg(DIM()),
    )));

    let title = match pane.scroll {
        0 => format!(" log · {} ", pane.target.title()),
        n => format!(" log · {} · {n} back ", pane.target.title()),
    };
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(title, Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

/// One entry as it is drawn: a time, who said it, and the text under a hanging
/// indent so a wrapped line still lines up under its own column.
fn log_entry_lines(entry: &logs::Entry, width: usize) -> Vec<Line<'static>> {
    let prefix = format!(" {} {:<11} ", logs::clock(entry.at), entry.source);
    let indent = prefix.chars().count();
    let color = if entry.error {
        DANGER()
    } else if entry.source == logs::SELF {
        TEXT()
    } else {
        DIM()
    };
    wrap_text(&entry.text, width.saturating_sub(indent).max(8))
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let head = if i == 0 {
                prefix.clone()
            } else {
                " ".repeat(indent)
            };
            Line::from(vec![
                Span::styled(head, Style::default().fg(DIM())),
                Span::styled(chunk, Style::default().fg(color)),
            ])
        })
        .collect()
}

/// Break a line to fit the pane. Log output is long — a command line, a stack
/// of ssh options — and the interesting half is usually the end of it, so it
/// wraps rather than being cut off at the border.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        // A word wider than the pane — a long path — is cut, because there is
        // nowhere to break it.
        if word.chars().count() > width {
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
            }
            let mut rest = word;
            while rest.chars().count() > width {
                let cut = rest
                    .char_indices()
                    .nth(width)
                    .map(|(i, _)| i)
                    .unwrap_or(rest.len());
                out.push(rest[..cut].to_string());
                rest = &rest[cut..];
            }
            line = rest.to_string();
            continue;
        }
        let joined = if line.is_empty() {
            word.chars().count()
        } else {
            line.chars().count() + 1 + word.chars().count()
        };
        if joined > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || out.is_empty() {
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::wrap_text;

    #[test]
    fn a_line_breaks_between_words_and_never_loses_one() {
        let text = "ssh -N -o BatchMode=yes bastion";
        let lines = wrap_text(text, 16);
        assert!(lines.len() > 1, "{lines:?}");
        assert!(lines.iter().all(|l| l.chars().count() <= 16), "{lines:?}");
        assert_eq!(lines.join(" "), text);
    }

    #[test]
    fn a_word_wider_than_the_pane_is_cut_rather_than_left_to_overflow() {
        // A long path has nowhere to break.
        let lines = wrap_text("/very/long/path/to/a/config.ovpn", 10);
        assert!(lines.iter().all(|l| l.chars().count() <= 10), "{lines:?}");
        assert_eq!(lines.concat(), "/very/long/path/to/a/config.ovpn");
    }

    #[test]
    fn an_empty_line_still_draws_as_one_row() {
        assert_eq!(wrap_text("", 20), vec![String::new()]);
    }
}

/// The panic button's confirmation: what is up, and that it all goes.
fn render_panic_prompt(f: &mut Frame, app: &App, area: Rect) {
    let Some(p) = &app.panic else {
        return;
    };
    let items = p.lines();
    let rect = centered_rect(60, (items.len() + 7) as u16, area);
    f.render_widget(Clear, rect);

    let mut lines = vec![Line::from(Span::styled(
        " Disconnect everything?",
        Style::default().fg(TEXT()).bold(),
    ))];
    for item in &items {
        lines.push(Line::from(Span::styled(
            format!("   {item}"),
            Style::default().fg(WARN()),
        )));
    }
    lines.push(Line::from(""));
    if !p.vpn.is_empty() {
        lines.push(Line::from(Span::styled(
            " Taking a VPN down asks for root.",
            Style::default().fg(DIM()),
        )));
    }
    lines.push(Line::from(Span::styled(
        " Auto-reconnect stops too; nothing comes back on its own.",
        Style::default().fg(DIM()),
    )));
    lines.push(Line::from(vec![
        Span::styled(" y/enter ", Style::default().fg(DANGER()).bold()),
        Span::styled("disconnect  ", Style::default().fg(DIM())),
        Span::styled("any key ", Style::default().fg(ACCENT()).bold()),
        Span::styled("leave it", Style::default().fg(DIM())),
    ]));

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DANGER()))
            .title(Span::styled(" panic ", Style::default().fg(DANGER()).bold())),
    );
    f.render_widget(para, rect);
}

/// What quitting would leave running as root, and the two ways out of it.
fn render_quit_prompt(f: &mut Frame, app: &App, area: Rect) {
    let Some(q) = &app.quit_prompt else {
        return;
    };
    let rect = centered_rect(72, (q.sessions.len() + 9) as u16, area);
    f.render_widget(Clear, rect);

    let mut lines = vec![Line::from(Span::styled(
        format!(
            " {} openvpn session(s) are still up:",
            q.sessions.len()
        ),
        Style::default().fg(TEXT()).bold(),
    ))];
    for item in &q.sessions {
        lines.push(Line::from(Span::styled(
            format!("   {item}"),
            Style::default().fg(WARN()),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " They run as root. Once controlcenter is gone nothing is left that",
        Style::default().fg(DIM()),
    )));
    lines.push(Line::from(Span::styled(
        " knows how to reach them, and the next connection to the same profile",
        Style::default().fg(DIM()),
    )));
    lines.push(Line::from(Span::styled(
        " will be fighting the one still there for the server's slot.",
        Style::default().fg(DIM()),
    )));
    lines.push(Line::from(vec![
        Span::styled(" s/enter ", Style::default().fg(OK()).bold()),
        Span::styled("stop and quit  ", Style::default().fg(DIM())),
        Span::styled("k ", Style::default().fg(WARN()).bold()),
        Span::styled("keep and quit  ", Style::default().fg(DIM())),
        Span::styled("any key ", Style::default().fg(ACCENT()).bold()),
        Span::styled("stay", Style::default().fg(DIM())),
    ]));

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(WARN()))
            .title(Span::styled(" quit ", Style::default().fg(WARN()).bold())),
    );
    f.render_widget(para, rect);
}

fn render_ssh_form_overlay(f: &mut Frame, app: &App, area: Rect) {
    let form = &app.ssh_form;
    let height = (SSH_FIELDS.len() + 5) as u16;
    // Wide enough that a key path is readable without scrolling it.
    let rect = centered_rect(80, height, area);
    f.render_widget(Clear, rect);

    let title = match app.ssh_mode {
        SshMode::Edit(_) => " edit ssh host ",
        _ => " add ssh host ",
    };
    let value_width = value_width(rect, 33);

    let mut lines: Vec<Line> = Vec::new();
    for fld in SSH_FIELDS {
        let is_active = *fld == form.field();
        let label_style = if is_active {
            Style::default().fg(ACCENT()).bold()
        } else {
            Style::default().fg(DIM())
        };
        let (value, value_style) = match fld {
            SshField::Name => (form.name.clone(), Style::default().fg(TEXT())),
            SshField::Group => (form.group.clone(), Style::default().fg(TEXT())),
            SshField::Host => (form.host.clone(), Style::default().fg(TEXT())),
            SshField::Port => (form.port.clone(), Style::default().fg(TEXT())),
            SshField::Username => (form.username.clone(), Style::default().fg(TEXT())),
            SshField::KeyPath => (form.key_path.clone(), Style::default().fg(TEXT())),
            // Typed in the clear so the user can see what they are storing.
            SshField::Password => (
                form.password.clone(),
                Style::default().fg(if form.password.is_empty() {
                    TEXT()
                } else {
                    WARN()
                }),
            ),
            SshField::SkipHostKey => (
                format!(
                    "◂ {} ▸",
                    if form.skip_host_key_check { "yes" } else { "no" }
                ),
                Style::default().fg(if form.skip_host_key_check {
                    WARN()
                } else {
                    TEXT()
                }),
            ),
            SshField::RequiresVpn => (
                format!("◂ {} ▸", form.vpn.label()),
                Style::default().fg(TEXT()),
            ),
            SshField::DependsOn => (
                format!("◂ {} ▸", form.dep.label()),
                Style::default().fg(TEXT()),
            ),
            SshField::ExtraArgs => (form.extra_args.clone(), Style::default().fg(TEXT())),
        };
        let cursor = if is_active && !fld.is_picker() { "▏" } else { "" };
        let value = if fld.is_picker() { value } else { scrolled(&value, value_width) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<32}", fld.label()), label_style),
            Span::styled(value, value_style),
            Span::styled(cursor, Style::default().fg(ACCENT())),
        ]));
    }
    lines.push(Line::from(""));
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(DANGER()),
        )));
    } else if form.field() == SshField::KeyPath {
        lines.push(Line::from(Span::styled(
            " Ctrl+O file picker · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            " tab/↓ next · ↑ prev · ◂▸ toggle · Enter save · Esc cancel",
            Style::default().fg(DIM()),
        )));
    }

    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(title, Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

fn render_ssh_delete_confirm(f: &mut Frame, app: &App, area: Rect, idx: usize) {
    let name = app
        .ssh_hosts
        .get(idx)
        .map(|h| h.name.as_str())
        .unwrap_or("?");
    render_confirm_box(f, area, &format!(" delete SSH host '{name}'?"));
}

fn render_password_warning(f: &mut Frame, app: &App, area: Rect) {
    let path = app.paths.ssh_file.display().to_string();
    let rect = centered_rect(68, 10, area);
    f.render_widget(Clear, rect);
    let para = Paragraph::new(vec![
        Line::from(Span::styled(
            " The password is saved in cleartext.",
            Style::default().fg(WARN()).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!(" It is written to {path}"),
            Style::default().fg(TEXT()),
        )),
        Line::from(Span::styled(
            " (file mode 0600) and passed to ssh through sshpass.",
            Style::default().fg(TEXT()),
        )),
        Line::from(Span::styled(
            " Anyone who can read your home directory can read it,",
            Style::default().fg(DIM()),
        )),
        Line::from(Span::styled(
            " and backups will carry it along. A key is safer.",
            Style::default().fg(DIM()),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" y", Style::default().fg(WARN()).bold()),
            Span::styled(" save it anyway · ", Style::default().fg(DIM())),
            Span::styled("any other key", Style::default().fg(ACCENT())),
            Span::styled(" back to the form", Style::default().fg(DIM())),
        ]),
    ])
    .wrap(Wrap { trim: false })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(WARN()))
            .title(Span::styled(
                " cleartext password ",
                Style::default().fg(WARN()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

fn render_conflict_prompt(f: &mut Frame, app: &App, area: Rect) {
    let Some(c) = &app.conflict else {
        return;
    };
    let blocking = c.blocking();
    let height = (9 + blocking.len().min(4) + usize::from(c.note.is_some())) as u16;
    let rect = centered_rect(72, height, area);
    f.render_widget(Clear, rect);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" starting  ", Style::default().fg(DIM())),
            Span::styled(c.step.describe(), Style::default().fg(ACCENT()).bold()),
        ]),
        Line::from(vec![
            Span::styled(" needs     ", Style::default().fg(DIM())),
            Span::styled(c.resource.clone(), Style::default().fg(WARN()).bold()),
        ]),
    ];
    if let Some(note) = &c.note {
        lines.push(Line::from(vec![
            Span::styled(" change    ", Style::default().fg(DIM())),
            Span::styled(note.clone(), Style::default().fg(TEXT())),
        ]));
    }
    lines.push(Line::from(""));
    // A prompt is only raised when something is in the way, so this list is
    // never empty.
    lines.push(Line::from(Span::styled(
        " These are disconnected first:",
        Style::default().fg(DIM()),
    )));
    for b in blocking.iter().take(4) {
        lines.push(Line::from(Span::styled(
            format!("   {b}"),
            Style::default().fg(TEXT()),
        )));
    }
    // Only worth saying when there is more to the plan than this one step.
    if let Some(act) = app.activation.as_ref().filter(|a| a.total > 1) {
        lines.push(Line::from(Span::styled(
            format!(" Part of starting {} ({}).", act.target, act.progress()),
            Style::default().fg(DIM()),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" y/Enter", Style::default().fg(WARN()).bold()),
        Span::styled(" go ahead · ", Style::default().fg(DIM())),
        Span::styled("any other key", Style::default().fg(ACCENT())),
        Span::styled(" cancel", Style::default().fg(DIM())),
    ]));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(WARN()))
            .title(Span::styled(
                " conflict ",
                Style::default().fg(WARN()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let entry = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<12}"), Style::default().fg(ACCENT())),
            Span::styled(d.to_string(), Style::default().fg(TEXT())),
        ])
    };
    let text = |d: &str| Line::from(Span::styled(format!("   {d}"), Style::default().fg(TEXT())));
    let section = |t: &str| {
        Line::from(Span::styled(
            format!(" {t}"),
            Style::default().fg(DIM()).bold(),
        ))
    };
    let lines = vec![
        Line::from(Span::styled(
            " SSH tunnels, SSH logins, VPN clients and RDP sessions in one place.",
            Style::default().fg(TEXT()),
        )),
        Line::from(""),
        section("tabs"),
        entry("  dashboard", "everything that is up, and what it is moving"),
        entry("  vpn", "netbird, wireguard, openvpn and tailscale side by side"),
        entry("  tunnels", "ssh forwards — local (-L), remote (-R), dynamic (-D)"),
        entry("  ssh", "interactive logins, each in a terminal window of its own"),
        entry("  rdp", "xfreerdp3 sessions, running in the background"),
        Line::from(""),
        section("groups"),
        text("entries sharing a group name stack under one header, and the"),
        text("header acts on every member as one plan — so a VPN or tunnel"),
        text("several of them share is brought up once, not once each"),
        Line::from(""),
        section("dependencies"),
        text("a tunnel, ssh host or rdp connection can require a VPN profile"),
        text("and a tunnel, and tunnels stack on other tunnels. Connecting"),
        text("brings the whole chain up in order: VPNs first, then the"),
        text("tunnels bottom-up, then the session itself"),
        Line::from(""),
        section("conflicts"),
        text("a step that cannot coexist with what is already running asks"),
        text("first — y evicts what is in the way, anything else cancels"),
        Line::from(""),
        section("connections that are not ours"),
        text("the VPN tab lists what is on the machine, not only what this"),
        text("program started: a ◆ row is an openvpn process or an interface"),
        text("controlcenter is not holding — an orphan of an earlier run, or"),
        text("someone else's. Enter stops one; x takes them down with the rest"),
        Line::from(""),
        section("logs and reports"),
        text("l opens the log of whatever is selected: what controlcenter did"),
        text("about it, merged with what the process it started printed."),
        text("s writes a report — that log plus every connection, command"),
        text("line and VPN state — to a file you can hand to someone else"),
        Line::from(""),
        section("config"),
        text("TOML under ~/.config/controlcenter, editable by hand"),
        text("(controlcenter --config-paths says exactly where)"),
        Line::from(""),
        Line::from(vec![
            Span::styled(" k ", Style::default().fg(ACCENT()).bold()),
            Span::styled("for the keys · any key closes", Style::default().fg(DIM())),
        ]),
    ];
    let rect = centered_rect(72, (lines.len() + 2) as u16, area);
    f.render_widget(Clear, rect);
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" help ", Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

/// The keybinding cheat sheet. Every key means the same thing on every tab, so
/// the sheet is one list plus a grid of what each one acts on where.
fn render_keys_overlay(f: &mut Frame, area: Rect) {
    let entry = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<14}"), Style::default().fg(ACCENT())),
            Span::styled(d.to_string(), Style::default().fg(TEXT())),
        ])
    };
    let section = |t: &str| {
        Line::from(Span::styled(
            format!(" {t}"),
            Style::default().fg(DIM()).bold(),
        ))
    };
    // key, vpn, tunnels, ssh, rdp
    let row = |k: &str, a: &str, b: &str, c: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<8}"), Style::default().fg(ACCENT())),
            Span::styled(
                format!("{a:<15}{b:<15}{c:<15}{d}"),
                Style::default().fg(TEXT()),
            ),
        ])
    };
    let lines = vec![
        section("acting on what is selected"),
        entry("enter space", "connect · disconnect if it is already up"),
        entry("", "on a ◆ VPN row: stop a connection controlcenter is"),
        entry("", "not holding — again to kill one that ignored SIGTERM"),
        entry("a", "add"),
        entry("e", "edit"),
        entry("d", "delete"),
        entry("r", "reconnect · reload"),
        entry("p", "remove the stored password"),
        entry("l", "log"),
        entry("s", "save a report to a file — everything, not just this log"),
        entry("c", "clear — the log, or entries that have finished"),
        entry("ctrl+↑ ↓", "move it up or down — an entry inside its group, a"),
        entry("", "group past the next one; the new order is saved"),
        Line::from(""),
        section("everywhere"),
        Line::from(vec![
            Span::styled(
                format!(" {:<14}", "x"),
                Style::default().fg(DANGER()).bold(),
            ),
            Span::styled(
                "disconnect EVERYTHING — the panic button",
                Style::default().fg(TEXT()),
            ),
        ]),
        entry("t", "cycle the colour theme"),
        entry("?", "help · k these keys"),
        entry("q", "close what is focused, and the application once"),
        entry("", "nothing is left to close — asks first if an openvpn"),
        entry("", "session would be left running as root"),
        Line::from(""),
        section("moving about"),
        entry("1-5 tab", "switch tab (shift+tab goes back)"),
        entry("↑ ↓", "move the selection · scroll a log"),
        entry("pgup pgdn", "move the selection by ten · scroll a log by a screen"),
        entry("← →", "switch pane · change the field under the cursor"),
        entry("esc", "cancel a form, close a popup"),
        entry("y", "confirm in a prompt"),
        entry("ctrl+o", "open the file picker on a path field"),
        Line::from(""),
        section("what each one acts on"),
        row("", "VPN", "TUNNELS", "SSH", "RDP"),
        row("enter", "connect · stop ◆", "start/stop", "open session", "connect"),
        row("a e d", "profile", "tunnel", "host", "connection"),
        row("r", "refresh", "restart", "new session", "reconnect"),
        row("p", "openvpn pw", "—", "stored pw", "never stored"),
        row("l", "profile log", "ssh output", "what it did", "xfreerdp log"),
        row("c", "errors", "failed", "last session", "finished"),
        row("ctrl+↑↓", "move profile", "move tunnel", "move host", "move connection"),
        Line::from(""),
        Line::from(vec![
            Span::styled(" ? ", Style::default().fg(ACCENT()).bold()),
            Span::styled("for help · any key closes", Style::default().fg(DIM())),
        ]),
    ];
    let rect = centered_rect(76, (lines.len() + 2) as u16, area);
    f.render_widget(Clear, rect);
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" keys ", Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
}

/// How much room a form leaves for a value: the box minus its borders, the
/// label column and the cursor.
fn value_width(rect: Rect, label_width: u16) -> usize {
    rect.width.saturating_sub(2 + label_width + 1) as usize
}

/// Form text is appended at the end, so that is where the cursor is: when a
/// value outgrows its field, show the tail instead of letting it disappear
/// under the border.
fn scrolled(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    let keep = width.saturating_sub(1);
    let tail: String = value.chars().skip(len - keep).collect();
    format!("…{tail}")
}

/// The file picker: the path being typed, and the directory it points at.
fn render_browser_overlay(f: &mut Frame, browser: &FileBrowser, area: Rect) {
    let width = 76.min(area.width);
    let height = area.height.saturating_sub(4).clamp(8, 26);
    let rect = centered_rect(width, height, area);
    f.render_widget(Clear, rect);

    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT()))
            .title(Span::styled(
                " pick a file ",
                Style::default().fg(ACCENT()).bold(),
            )),
        rect,
    );
    let inner = Rect {
        x: rect.x + 1,
        y: rect.y + 1,
        width: rect.width.saturating_sub(2),
        height: rect.height.saturating_sub(2),
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    let path_width = inner.width.saturating_sub(7) as usize;
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" path ", Style::default().fg(DIM())),
            Span::styled(
                scrolled(&browser.input, path_width),
                Style::default().fg(TEXT()),
            ),
            Span::styled("▏", Style::default().fg(ACCENT())),
        ])),
        chunks[0],
    );

    let subtitle = match &browser.error {
        Some(e) => Span::styled(format!(" {}", truncate(e, inner.width as usize - 1)), Style::default().fg(DANGER())),
        None if browser.entries.is_empty() => {
            Span::styled(" nothing here matches", Style::default().fg(DIM()))
        }
        None => Span::styled(
            format!(" {} entries", browser.entries.len()),
            Style::default().fg(DIM()),
        ),
    };
    f.render_widget(Paragraph::new(Line::from(subtitle)), chunks[1]);

    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .map(|e| {
            let (mark, name, style) = if e.is_dir {
                ("▸ ", format!("{}/", e.name), Style::default().fg(ACCENT()))
            } else {
                ("  ", e.name.clone(), Style::default().fg(TEXT()))
            };
            ListItem::new(Line::from(vec![
                Span::styled(mark, Style::default().fg(DIM())),
                Span::styled(name, style),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    if !browser.entries.is_empty() {
        state.select(Some(browser.selected));
    }
    f.render_stateful_widget(
        List::new(items).highlight_style(Style::default().bg(SELECTION_BG())),
        chunks[2],
        &mut state,
    );

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " ↑↓ select · → / Enter open folder · Enter pick file · ← up · Esc cancel",
            Style::default().fg(DIM()),
        ))),
        chunks[3],
    );
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

pub fn truncate_pub(s: &str, max: usize) -> String {
    truncate(s, max)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

pub fn human_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut val = b as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{b} B")
    } else {
        format!("{val:.1} {}", UNITS[unit])
    }
}

pub fn human_rate(b: u64) -> String {
    format!("{}/s", human_bytes(b))
}

pub fn fmt_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}
