use crate::app::{
    App, FormField, FormMode, RdpField, RdpMode, RowItem, Tab, FORM_FIELDS, RDP_FIELDS,
};
use crate::rdp::RdpStatus;
use crate::theme::{self, Theme};
use crate::tunnel::Status;
use crate::types::{ForwardType, Tunnel};
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
        RdpMode::Password { idx, input } => {
            render_rdp_password_overlay(f, app, area, *idx, input)
        }
        RdpMode::Logs => render_rdp_logs_overlay(f, app, area),
    }

    if app.show_help {
        render_help_overlay(f, area);
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
    let nb = if !app.nb.installed {
        "-".to_string()
    } else if app.nb.busy.is_some() {
        "…".to_string()
    } else if app.nb.status.connected {
        "up".to_string()
    } else {
        "down".to_string()
    };
    let title_right =
        format!(" ssh {}/{} up · vpn {} · rdp {} ", up, app.active.len(), nb, rdp_running);

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
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
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
    if app.active.is_empty() {
        ssh_lines.push(Line::from(""));
        ssh_lines.push(Line::from(Span::styled(
            " no active tunnels",
            Style::default().fg(DIM()),
        )));
    }
    f.render_widget(summary_block("ssh tunnels [3]", ssh_lines), cols[1]);

    // --- NetBird summary ---
    let mut nb_lines: Vec<Line> = Vec::new();
    if !app.nb.installed {
        nb_lines.push(Line::from(""));
        nb_lines.push(Line::from(Span::styled(
            " netbird not found on PATH",
            Style::default().fg(DIM()),
        )));
    } else {
        let st = &app.nb.status;
        let state = if st.connected {
            Span::styled("connected", Style::default().fg(OK()).bold())
        } else {
            Span::styled("disconnected", Style::default().fg(DANGER()).bold())
        };
        nb_lines.push(kv("state", state));
        let profile = st
            .field("Profile")
            .map(str::to_string)
            .or_else(|| {
                app.nb
                    .profiles
                    .iter()
                    .find(|p| p.active)
                    .map(|p| p.name.clone())
            })
            .unwrap_or_else(|| "-".into());
        nb_lines.push(kv("profile", Span::styled(profile, Style::default().fg(ACCENT()))));
        for key in ["NetBird IP", "FQDN", "Peers count"] {
            if let Some(v) = st.field(key) {
                let label = match key {
                    "NetBird IP" => "ip",
                    "FQDN" => "fqdn",
                    _ => "peers",
                };
                nb_lines.push(kv(label, Span::styled(v.to_string(), Style::default().fg(TEXT()))));
            }
        }
        if let Some(busy) = &app.nb.busy {
            nb_lines.push(kv("busy", Span::styled(format!("{busy}…"), Style::default().fg(WARN()))));
        }
        if let Some(err) = &app.nb.error {
            nb_lines.push(Line::from(Span::styled(
                format!(" {}", truncate(err, 40)),
                Style::default().fg(DANGER()),
            )));
        }
    }
    f.render_widget(summary_block("vpn · netbird [2]", nb_lines), cols[0]);

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
    f.render_widget(summary_block("rdp [4]", rdp_lines), cols[2]);

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
            "  nothing active — start a tunnel [3] or an RDP session [4]",
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
                ListItem::new(Line::from(vec![
                    Span::styled("▸ ", Style::default().fg(ACCENT())),
                    Span::styled(g.clone(), Style::default().fg(ACCENT()).bold()),
                    Span::styled(
                        format!("  ({up}/{} active)", members.len()),
                        Style::default().fg(DIM()),
                    ),
                ]))
            }
            RowItem::Tunnel(i) => {
                let t = &app.tunnels[*i];
                let indent = if t.group.is_empty() { " " } else { "   " };
                ListItem::new(Line::from(vec![
                    Span::raw(indent.to_string()),
                    status_dot(app, t),
                    Span::styled(
                        format!(" {:<18}", truncate(&t.name, 18)),
                        Style::default().fg(TEXT()),
                    ),
                    Span::styled(
                        format!("{:<26}", truncate(&t.forward_summary(), 26)),
                        Style::default().fg(DIM()),
                    ),
                    Span::styled(
                        format!("via {}", t.ssh_host),
                        Style::default().fg(DIM()),
                    ),
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
            lines.push(Line::from(vec![
                Span::styled("group     ", Style::default().fg(DIM())),
                Span::styled(g.clone(), Style::default().fg(ACCENT()).bold()),
            ]));
            lines.push(Line::from(vec![
                Span::styled("members   ", Style::default().fg(DIM())),
                Span::styled(format!("{}", members.len()), Style::default().fg(TEXT())),
            ]));
            lines.push(Line::from(vec![
                Span::styled("active    ", Style::default().fg(DIM())),
                Span::styled(format!("{up}"), Style::default().fg(TEXT())),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Enter starts every inactive member,",
                Style::default().fg(DIM()),
            )));
            lines.push(Line::from(Span::styled(
                "or stops all when everything is up.",
                Style::default().fg(DIM()),
            )));
        }
        Some(RowItem::Tunnel(i)) => {
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
                        lines.push(Line::from(Span::styled(l, Style::default().fg(DIM()))));
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
// VPN tab (currently backed by netbird; more providers may follow)
// ---------------------------------------------------------------------------

fn render_vpn(f: &mut Frame, app: &App, area: Rect) {
    if !app.nb.installed {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  netbird was not found on PATH",
                Style::default().fg(WARN()),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  install it from https://netbird.io to manage profiles here",
                Style::default().fg(DIM()),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER()))
                .title(Span::styled(" vpn ", Style::default().fg(TEXT()))),
        );
        f.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Profiles list
    let items: Vec<ListItem> = app
        .nb
        .profiles
        .iter()
        .map(|p| {
            let dot = if p.active {
                Span::styled("● ", Style::default().fg(OK()))
            } else {
                Span::styled("○ ", Style::default().fg(DIM()))
            };
            let name_style = if p.active {
                Style::default().fg(TEXT()).bold()
            } else {
                Style::default().fg(TEXT())
            };
            let mut spans = vec![Span::raw(" "), dot, Span::styled(p.name.clone(), name_style)];
            if p.active {
                spans.push(Span::styled("  (active)", Style::default().fg(DIM())));
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
                .border_style(Style::default().fg(BORDER()))
                .title(Span::styled(" netbird profiles ", Style::default().fg(TEXT()))),
        );
    let mut state = ListState::default();
    if !empty {
        state.select(Some(app.nb.selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    if empty {
        let hint = Paragraph::new(Line::from(Span::styled(
            "  no profiles found",
            Style::default().fg(DIM()),
        )));
        let inner = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + 1,
            width: chunks[0].width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(hint, inner);
    }

    // Status panel
    let mut lines: Vec<Line> = Vec::new();
    let st = &app.nb.status;
    let state_span = if st.connected {
        Span::styled("connected", Style::default().fg(OK()).bold())
    } else {
        Span::styled("disconnected", Style::default().fg(DANGER()).bold())
    };
    lines.push(kv("state", state_span));
    if let Some(busy) = &app.nb.busy {
        lines.push(kv(
            "action",
            Span::styled(format!("{busy}…"), Style::default().fg(WARN()).bold()),
        ));
    }
    lines.push(Line::from(""));
    for (k, v) in &st.fields {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<20}", k.to_lowercase()), Style::default().fg(DIM())),
            Span::styled(v.clone(), Style::default().fg(TEXT())),
        ]));
    }
    if let Some(err) = st.error.as_ref().or(app.nb.error.as_ref()) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {err}"),
            Style::default().fg(DANGER()),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Enter switches to the selected profile and connects.",
        Style::default().fg(DIM()),
    )));

    let status = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" status ", Style::default().fg(TEXT()))),
    );
    f.render_widget(status, chunks[1]);
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
        .rdp_conns
        .iter()
        .map(|c| {
            ListItem::new(Line::from(vec![
                Span::raw(" "),
                rdp_status_dot(app, &c.name),
                Span::styled(
                    format!(" {:<18}", truncate(&c.name, 18)),
                    Style::default().fg(TEXT()),
                ),
                Span::styled(
                    format!("{:<22}", truncate(&c.target_summary(), 22)),
                    Style::default().fg(DIM()),
                ),
                Span::styled(
                    format!("as {}", c.login_summary()),
                    Style::default().fg(DIM()),
                ),
            ]))
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
    match app.rdp_conns.get(app.rdp_selected) {
        Some(c) => {
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
                                truncate(&l, 60),
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
// Status bar / overlays
// ---------------------------------------------------------------------------

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let line = if let Some((msg, is_error, _)) = &app.status_msg {
        let color = if *is_error { DANGER() } else { OK() };
        Line::from(Span::styled(format!(" {msg}"), Style::default().fg(color)))
    } else {
        let hints: &[(&str, &str)] = match app.tab {
            Tab::Dashboard => &[
                ("1-4/tab", "switch tab"),
                ("t", "theme"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Tunnels => &[
                ("↵/space", "start/stop"),
                ("a", "add"),
                ("e", "edit"),
                ("d", "delete"),
                ("r", "restart"),
                ("x", "stop all"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Vpn => &[
                ("j/k", "select"),
                ("↵", "switch profile + connect"),
                ("u", "up"),
                ("d", "down"),
                ("r", "refresh"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Tab::Rdp => &[
                ("↵", "connect/disconnect"),
                ("a", "add"),
                ("e", "edit"),
                ("d", "delete"),
                ("l", "logs"),
                ("c", "clear finished"),
                ("x", "close all"),
                ("?", "help"),
                ("q", "quit"),
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
    let rect = centered_rect(64, height, area);
    f.render_widget(Clear, rect);

    let title = match app.form_mode {
        FormMode::Edit(_) => " edit tunnel ",
        _ => " add tunnel ",
    };

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
        };
        let cursor = if is_active
            && !matches!(fld, FormField::Forward | FormField::AutoReconnect)
        {
            "▏"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<24}", fld.label(form.forward)), label_style),
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
            RdpField::Host => form.host.clone(),
            RdpField::Port => form.port.clone(),
            RdpField::Domain => form.domain.clone(),
            RdpField::Username => form.username.clone(),
            RdpField::ExtraArgs => form.extra_args.clone(),
        };
        let cursor = if is_active { "▏" } else { "" };
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
            " tab/↓ next · ↑ prev · Enter save · Esc cancel",
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

fn render_rdp_password_overlay(f: &mut Frame, app: &App, area: Rect, idx: usize, input: &str) {
    let (name, login) = app
        .rdp_conns
        .get(idx)
        .map(|c| (c.name.clone(), format!("{} @ {}", c.login_summary(), c.target_summary())))
        .unwrap_or_else(|| ("?".into(), String::new()));
    let rect = centered_rect(56, 7, area);
    f.render_widget(Clear, rect);
    let masked: String = "•".repeat(input.chars().count());
    let para = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" connect to ", Style::default().fg(DIM())),
            Span::styled(name, Style::default().fg(ACCENT()).bold()),
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

fn render_rdp_logs_overlay(f: &mut Frame, app: &App, area: Rect) {
    let rect = centered_rect(area.width.saturating_sub(8).max(40), area.height.saturating_sub(4).max(10), area);
    f.render_widget(Clear, rect);

    let mut lines: Vec<Line> = Vec::new();
    let name = app
        .rdp_conns
        .get(app.rdp_selected)
        .map(|c| c.name.clone())
        .unwrap_or_default();
    match app.rdp_active.get(&name) {
        Some(a) => {
            let n = rect.height.saturating_sub(3) as usize;
            for l in a.recent_log(n) {
                lines.push(Line::from(Span::styled(l, Style::default().fg(TEXT()))));
            }
            if lines.is_empty() {
                lines.push(Line::from(Span::styled(
                    " no output yet",
                    Style::default().fg(DIM()),
                )));
            }
        }
        None => lines.push(Line::from(Span::styled(
            " no session",
            Style::default().fg(DIM()),
        ))),
    }
    lines.push(Line::from(Span::styled(
        " Esc/q/l close",
        Style::default().fg(DIM()),
    )));

    let para = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(
                format!(" xfreerdp log · {name} "),
                Style::default().fg(ACCENT()).bold(),
            )),
    );
    f.render_widget(para, rect);
}

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let rect = centered_rect(66, 26, area);
    f.render_widget(Clear, rect);
    let entry = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!(" {k:<12}"), Style::default().fg(ACCENT())),
            Span::styled(d.to_string(), Style::default().fg(TEXT())),
        ])
    };
    let section = |t: &str| {
        Line::from(Span::styled(
            format!(" {t}"),
            Style::default().fg(DIM()).bold(),
        ))
    };
    let lines = vec![
        entry("1-4 / tab", "switch tab (dashboard, vpn, tunnels, rdp)"),
        entry("j k ↑ ↓", "move selection"),
        entry("t", "cycle color theme"),
        entry("q", "quit (stops tunnels; RDP windows stay open)"),
        Line::from(""),
        section("tunnels"),
        entry("enter/space", "start/stop tunnel or whole group"),
        entry("a / e / d", "add / edit / delete"),
        entry("r", "restart selected active tunnel"),
        entry("x", "stop all tunnels"),
        Line::from(""),
        section("vpn (netbird)"),
        entry("enter", "select profile and connect (netbird up)"),
        entry("u / d", "netbird up / netbird down"),
        entry("r", "refresh status"),
        Line::from(""),
        section("rdp"),
        entry("enter", "connect (asks password) / disconnect"),
        entry("a / e / d", "add / edit / delete connection"),
        entry("l", "view session log"),
        entry("c", "clear finished session"),
        entry("x", "close all sessions"),
        Line::from(""),
        Line::from(Span::styled(
            " press any key to close",
            Style::default().fg(DIM()),
        )),
    ];
    let para = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER()))
            .title(Span::styled(" help ", Style::default().fg(ACCENT()).bold())),
    );
    f.render_widget(para, rect);
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

fn fmt_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}
