//! The report a log pane exports.
//!
//! The point of the file is that it can be read away from the program — mailed
//! to someone, or handed to an AI — and still explain what happened. So it
//! carries more than the pane it was exported from: the connection's whole
//! configuration, the command line it runs, and every link of the chain it
//! needs, because a chain fails at one link and is read at another.
//!
//! It carries no more than that. What the subject does not depend on cannot
//! explain what it did, and listing it only buries what can. The Dashboard's
//! report is the exception: its subject *is* everything.
//!
//! Nothing in it is a secret. Passwords never reach a command line to begin
//! with (they go through the environment or a child's stdin), stored ones are
//! reported as present rather than printed, and every line still goes through
//! [`redact`] on the way out in case a password was typed into an extra-args
//! field, where controlcenter would otherwise pass it on verbatim.

use crate::app::{App, Step};
use crate::logs::{self, Entry, LogTarget};
use crate::ssh;
use crate::tunnel::{self, Status};
use crate::types::{vpn_requirement_label, RdpConnection, SshHost, Tunnel};
use crate::ui::fmt_duration;
use crate::vpn::{openvpn, ProviderId};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// What a redacted value is replaced with. Spelled out rather than starred, so
/// that whoever reads the report knows something was removed on purpose.
pub const REDACTED: &str = "<redacted>";

/// Extension of the file the chain's logs are written to, beside the report.
const CHAIN_LOG_SUFFIX: &str = "-chain.log";

/// Words that make whatever follows them a secret.
const SENSITIVE: [&str; 7] = [
    "password", "passwd", "secret", "token", "privatekey", "presharedkey", "apikey",
];

/// Mask anything on a command line that looks like a secret.
///
/// controlcenter never puts a password on a command line itself, but
/// `extra_args` is free text: `/p:hunter2` for xfreerdp or `--password x` for
/// another tool would be passed straight through, and would otherwise be
/// copied into the report as typed.
pub fn redact(line: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut mask_next = false;
    for word in line.split_whitespace() {
        if mask_next {
            // `PrivateKey = value`: the separator is not the secret, whatever
            // comes after it is.
            if word == "=" || word == ":" {
                out.push(word.to_string());
                continue;
            }
            out.push(REDACTED.to_string());
            mask_next = false;
            continue;
        }
        // A word carrying its own value is settled here — `--password=value`,
        // `/p:value`, `PrivateKey = value` — and only a bare flag can mean that
        // the *next* word is the secret.
        match split_assignment(word) {
            Some((key, sep)) => {
                if is_sensitive(key) {
                    out.push(format!("{key}{sep}{REDACTED}"));
                } else {
                    out.push(word.to_string());
                }
            }
            None if is_sensitive(word) => {
                out.push(word.to_string());
                mask_next = true;
            }
            None => out.push(word.to_string()),
        }
    }
    out.join(" ")
}

/// The key and separator of a `key=value` or `key:value` word, if it has one.
fn split_assignment(word: &str) -> Option<(&str, char)> {
    let at = word.find(['=', ':'])?;
    Some((&word[..at], word[at..].chars().next()?))
}

/// Whether a key names a secret. `key` keeps whatever it was written with —
/// `--`, `-` or `/` — because that is part of the answer.
///
/// The word has to be at the *end* of the key, because that is where a flag
/// that takes a secret puts it: `--password`, `--auth-token`, `PrivateKey`.
/// Matching anywhere would also hit `NumberOfPasswordPrompts=1`, an option
/// controlcenter passes itself, and blanking that would make its own reports
/// harder to read for nothing.
fn is_sensitive(key: &str) -> bool {
    let slashed = key.starts_with('/');
    let flat: String = key
        .trim_start_matches(['-', '/'])
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    // One letter is too little to guess from, so the prefix decides: `/p` is
    // xfreerdp's password, `-p` is ssh's port.
    if flat == "p" {
        return slashed;
    }
    SENSITIVE.iter().any(|s| flat.ends_with(s))
}

/// How a stored secret is reported: that it is there, and nothing else.
pub fn secret_note(value: &str) -> String {
    if value.is_empty() {
        "not set".to_string()
    } else {
        format!("set ({} characters, not shown)", value.chars().count())
    }
}

/// A command line as the report prints it: one string, secrets masked.
pub fn command_line(argv: &[String]) -> String {
    redact(&argv.join(" "))
}

// ---------------------------------------------------------------------------
// Writing the file
// ---------------------------------------------------------------------------

/// An export: the report, and the files it links to.
///
/// The report itself carries the focused pane's log in full, because that is
/// the one being asked about. The chain's logs are full too, and long, so they
/// go in a file of their own rather than pushing the report's own findings off
/// the first screen.
pub struct Report {
    pub body: String,
    /// `(file name, contents)`, written beside the report.
    pub attachments: Vec<(String, String)>,
}

/// `controlcenter-tunnel-db-20260826-140311` — what every file of one export
/// is named after.
pub fn file_stem(target: &LogTarget, now: SystemTime) -> String {
    format!("controlcenter-{}-{}", target.slug(), logs::file_stamp(now))
}

/// Write a report and its attachments into `dir`, creating it if this is the
/// first one, and answer with the path of the report itself.
///
/// These name hosts, users and paths, so they are written like everything else
/// here that could: a 0700 directory and 0600 files.
pub fn write(dir: &Path, stem: &str, report: &Report) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    crate::vpn::restrict_dir(dir)?;
    // Attachments first: the report links to them, so it should not exist
    // pointing at a file that failed to be written.
    for (name, body) in &report.attachments {
        let path = dir.join(name);
        std::fs::write(&path, body).map_err(|e| format!("writing {}: {e}", path.display()))?;
        crate::vpn::restrict_file(&path)?;
    }
    let path = dir.join(format!("{stem}.md"));
    std::fs::write(&path, &report.body)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    crate::vpn::restrict_file(&path)?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Building the report
// ---------------------------------------------------------------------------

pub fn build(app: &App, target: &LogTarget, stem: &str) -> Report {
    let everything = *target == LogTarget::Program;
    let chain = chain_targets(app, target);
    let mut out = String::new();
    header(&mut out, app, target);
    subject(&mut out, app, target);
    if everything {
        vpn_clients(&mut out, app);
        tunnels(&mut out, app);
        ssh_hosts(&mut out, app);
        rdp_connections(&mut out, app);
    } else {
        what_comes_first(&mut out, app, &chain);
    }
    environment(&mut out, app, target, &chain);
    what_it_did(&mut out, app, target, &chain);
    let attachments = log_output(&mut out, app, target, &chain, stem);
    Report {
        body: out,
        attachments,
    }
}

/// Everything that has to be up before the subject, in the order a plan would
/// bring it up — the only other connections a report is about.
///
/// Empty for a VPN profile, which waits for nothing, and for the whole
/// program, which lists every connection anyway. A chain that does not
/// resolve — a tunnel pointing at one that has been deleted — is left empty
/// too; the subject's own `chain` line already says so.
fn chain_targets(app: &App, target: &LogTarget) -> Vec<LogTarget> {
    let step = match target {
        LogTarget::Program | LogTarget::Vpn(..) => return Vec::new(),
        LogTarget::Tunnel(name) => Step::Tunnel(name.clone()),
        LogTarget::Ssh(name) => Step::Ssh(name.clone()),
        LogTarget::Rdp(name) => Step::Rdp {
            name: name.clone(),
            password: String::new(),
        },
    };
    app.plan_for(step)
        .unwrap_or_default()
        .iter()
        .map(Step::log_target)
        .filter(|t| t != target)
        .collect()
}

/// One connection as the report describes it, whichever kind it is.
fn target_block(out: &mut String, app: &App, target: &LogTarget) {
    match target {
        LogTarget::Program => {}
        LogTarget::Tunnel(name) => match app.tunnels.iter().find(|t| &t.name == name) {
            Some(t) => tunnel_block(out, app, t),
            None => field(out, "gone", "no tunnel by this name is configured"),
        },
        LogTarget::Ssh(name) => match app.ssh_hosts.iter().find(|h| &h.name == name) {
            Some(h) => ssh_block(out, app, h),
            None => field(out, "gone", "no ssh host by this name is configured"),
        },
        LogTarget::Rdp(name) => match app.rdp_conns.iter().find(|c| &c.name == name) {
            Some(c) => rdp_block(out, app, c),
            None => field(out, "gone", "no rdp connection by this name is configured"),
        },
        LogTarget::Vpn(provider, profile) => vpn_profile_block(out, app, *provider, profile),
    }
}

/// The chain, link by link — each one described as fully as the subject is,
/// because any of them is where it actually went wrong.
fn what_comes_first(out: &mut String, app: &App, chain: &[LogTarget]) {
    if chain.is_empty() {
        return;
    }
    section(out, "what has to be up first");
    for link in chain {
        let _ = writeln!(out, "### {}", link.title());
        target_block(out, app, link);
        let _ = writeln!(out);
    }
}

fn section(out: &mut String, title: &str) {
    let _ = write!(out, "\n## {title}\n\n");
}

/// One `label   value` line. A VPN client names its own status fields, so the
/// label column widens rather than letting a long one run into its value.
fn field(out: &mut String, label: &str, value: impl AsRef<str>) {
    let value = value.as_ref();
    let value = if value.is_empty() { "—" } else { value };
    let width = 16.max(label.chars().count() + 2);
    let _ = writeln!(out, "{label:<width$}{value}");
}

fn header(out: &mut String, app: &App, target: &LogTarget) {
    let _ = writeln!(out, "# controlcenter report");
    let _ = writeln!(out);
    field(out, "generated", logs::stamp(SystemTime::now()));
    field(out, "version", env!("CARGO_PKG_VERSION"));
    field(out, "subject", target.title());
    field(out, "platform", std::env::consts::OS);
    field(out, "config dir", app.paths.config_dir.display().to_string());
    let _ = writeln!(
        out,
        "\nEvery command line below is what controlcenter runs. Passwords are never \
         passed as arguments — they go through the environment or the child's stdin — \
         and anything secret-looking in a user-supplied argument is shown as {REDACTED}."
    );
}

/// What the pane was open on, in full: its configuration, the command line it
/// runs, what it needs first, and what it is doing now.
fn subject(out: &mut String, app: &App, target: &LogTarget) {
    section(out, &format!("subject: {}", target.title()));
    match target {
        LogTarget::Program => {
            let _ = writeln!(
                out,
                "The whole program: every connection and everything it has done this run."
            );
        }
        LogTarget::Tunnel(name) => match app.tunnels.iter().find(|t| &t.name == name) {
            Some(t) => {
                tunnel_block(out, app, t);
                chain(out, app, Step::Tunnel(name.clone()));
            }
            None => {
                let _ = writeln!(out, "no tunnel named '{name}' is configured any more");
            }
        },
        LogTarget::Ssh(name) => match app.ssh_hosts.iter().find(|h| &h.name == name) {
            Some(h) => {
                ssh_block(out, app, h);
                chain(out, app, Step::Ssh(name.clone()));
            }
            None => {
                let _ = writeln!(out, "no ssh host named '{name}' is configured any more");
            }
        },
        LogTarget::Rdp(name) => match app.rdp_conns.iter().find(|c| &c.name == name) {
            Some(c) => {
                rdp_block(out, app, c);
                chain(
                    out,
                    app,
                    Step::Rdp {
                        name: name.clone(),
                        password: String::new(),
                    },
                );
            }
            None => {
                let _ = writeln!(out, "no rdp connection named '{name}' is configured any more");
            }
        },
        LogTarget::Vpn(provider, profile) => {
            vpn_profile_block(out, app, *provider, profile);
        }
    }
}

fn chain(out: &mut String, app: &App, step: Step) {
    match app.chain_of(step) {
        Ok(parts) if parts.len() > 1 => field(out, "chain", parts.join(" → ")),
        Ok(_) => field(out, "chain", "nothing has to come up first"),
        Err(e) => field(out, "chain", format!("BROKEN: {e}")),
    }
}

fn requirements(out: &mut String, app: &App, vpn: &str, dep: &str) {
    let satisfied = |ok: bool| if ok { "satisfied" } else { "NOT satisfied" };
    if vpn.is_empty() {
        field(out, "needs vpn", "none");
    } else {
        field(
            out,
            "needs vpn",
            format!(
                "{} — {}",
                vpn_requirement_label(vpn),
                satisfied(app.vpn_satisfied(vpn))
            ),
        );
    }
    if dep.is_empty() {
        field(out, "needs tunnel", "none");
    } else {
        let up = matches!(app.active.get(dep).map(|a| a.status), Some(Status::Up));
        field(out, "needs tunnel", format!("'{dep}' — {}", satisfied(up)));
    }
}

fn tunnel_block(out: &mut String, app: &App, t: &Tunnel) {
    field(out, "name", &t.name);
    field(out, "group", if t.group.is_empty() { "—" } else { &t.group });
    field(out, "ssh host", &t.ssh_host);
    field(out, "forward", t.forward.label());
    field(out, "forwards", t.forward_summary());
    field(out, "extra args", redact(&t.extra_args));
    field(out, "auto reconnect", if t.auto_reconnect { "on" } else { "off" });
    requirements(out, app, &t.requires_vpn, &t.depends_on);

    match app.active.get(&t.name) {
        Some(a) => {
            field(out, "state", a.status.label());
            if let Some(e) = &a.error {
                field(out, "last error", redact(e));
            }
            field(out, "started", format!("{} ago", fmt_duration(a.started_at.elapsed())));
            field(out, "restarts", a.restarts.to_string());
            field(out, "command", command_line(&a.argv));
            let c = &a.counters;
            use std::sync::atomic::Ordering::Relaxed;
            field(
                out,
                "traffic",
                format!(
                    "{} sent, {} received, {} connections ({} open)",
                    c.tx.load(Relaxed),
                    c.rx.load(Relaxed),
                    c.total_conns.load(Relaxed),
                    c.active_conns.load(Relaxed)
                ),
            );
        }
        None => {
            field(out, "state", "not running");
            field(
                out,
                "command",
                format!(
                    "{} (the internal port is picked when it starts)",
                    command_line(&tunnel::build_args(t, None))
                ),
            );
        }
    }
}

fn ssh_block(out: &mut String, app: &App, h: &SshHost) {
    field(out, "name", &h.name);
    field(out, "group", if h.group.is_empty() { "—" } else { &h.group });
    field(out, "target", h.target_summary());
    field(out, "auth", h.auth_summary());
    field(out, "password", secret_note(&h.password));
    field(
        out,
        "host key check",
        if h.skip_host_key_check { "skipped" } else { "normal" },
    );
    field(out, "extra args", redact(&h.extra_args));
    requirements(out, app, &h.requires_vpn, &h.depends_on);
    field(out, "opens in", app.ssh_launcher.label());
    field(
        out,
        "command",
        redact(&ssh::command_preview(h, &app.ssh_password_helper)),
    );
    field(out, "windows open", app.ssh_windows_open(&h.name).to_string());
    match app.ssh_last.get(&h.name) {
        Some(o) => field(
            out,
            "last session",
            format!("{} after {}", o.label(), fmt_duration(o.duration)),
        ),
        None => field(out, "last session", "none this run"),
    }
}

fn rdp_block(out: &mut String, app: &App, c: &RdpConnection) {
    field(out, "name", &c.name);
    field(out, "group", if c.group.is_empty() { "—" } else { &c.group });
    field(out, "client", app.rdp_client.program());
    field(out, "target", c.target_summary());
    field(out, "login", c.login_summary());
    field(out, "password", "asked for on connect, never stored");
    field(out, "extra args", redact(&c.extra_args));
    requirements(out, app, &c.requires_vpn, &c.depends_on);
    match app.rdp_active.get(&c.name) {
        Some(a) => {
            field(out, "state", a.status.label());
            field(out, "started", format!("{} ago", fmt_duration(a.started_at.elapsed())));
            field(out, "command", command_line(&a.argv));
        }
        None => {
            field(out, "state", "no session");
            field(
                out,
                "command",
                command_line(&crate::rdp::build_args(c, app.rdp_client, None)),
            );
        }
    }
}

fn vpn_profile_block(out: &mut String, app: &App, provider: ProviderId, profile: &str) {
    let state = app.vpn.get(provider);
    field(out, "client", provider.slug());
    field(
        out,
        "installed",
        if state.installed {
            "yes"
        } else {
            "no — the tab greys it out"
        },
    );
    field(out, "needs root", if provider.needs_root() { "yes" } else { "no" });
    if profile.is_empty() {
        return;
    }
    field(out, "profile", profile);
    match provider {
        ProviderId::Wireguard => {
            if let Some(w) = app.vpn_cfg.wireguard.iter().find(|w| w.name == profile) {
                field(out, "interface", w.interface());
                field(
                    out,
                    "config",
                    if w.external() {
                        format!("{} (managed elsewhere)", w.config_path)
                    } else {
                        format!(
                            "generated at {}",
                            crate::vpn::wireguard::conf_path(w, &app.paths.wireguard_dir).display()
                        )
                    },
                );
                field(out, "address", &w.address);
                field(out, "dns", &w.dns);
                field(out, "endpoint", &w.endpoint);
                field(out, "allowed ips", &w.allowed_ips);
                field(out, "private key", secret_note(&w.private_key));
                field(out, "preshared key", secret_note(&w.preshared_key));
                field(out, "peer key", &w.peer_public_key);
            }
        }
        ProviderId::Openvpn => {
            if let Some(o) = app.vpn_cfg.openvpn.iter().find(|o| o.name == profile) {
                let config = o.runtime_config(&app.paths.openvpn_dir);
                field(out, "config", config.display().to_string());
                field(out, "imported", if o.import { "yes" } else { "run in place" });
                field(out, "username", if o.username.is_empty() { "—" } else { &o.username });
                field(out, "password", secret_note(&o.password));
                field(out, "extra args", redact(&o.extra_args));
                let pid = openvpn::pid_file_for(&o.name, &app.paths.run_dir);
                match app.ovpn_active.get(profile) {
                    Some(a) => {
                        field(out, "state", a.status.label());
                        field(
                            out,
                            "started",
                            format!("{} ago", fmt_duration(a.started_at.elapsed())),
                        );
                        field(out, "command", command_line(&a.argv));
                        if let Some(f) = a.fault() {
                            field(out, "fault", f);
                        }
                    }
                    None => {
                        field(out, "state", "no session");
                        field(
                            out,
                            "command",
                            command_line(&openvpn::build_args(o, &config, &pid)),
                        );
                    }
                }
                // Another openvpn on the same config is the one thing that
                // explains a tunnel which connects and is thrown off every
                // few minutes: the server hands the slot to whichever client
                // asked last, and the two take it from each other in turn.
                // It belongs to this profile's story wherever it came from.
                let held = app.ovpn_active.get(profile).and_then(|a| a.root_pid());
                let others: Vec<&crate::vpn::scan::Process> = app
                    .scan
                    .processes_of(ProviderId::Openvpn)
                    .filter(|p| p.config().is_some_and(|c| Path::new(c) == config))
                    .filter(|p| Some(p.pid) != held)
                    .collect();
                if others.is_empty() {
                    field(out, "others on this config", "none");
                }
                for p in others {
                    field(
                        out,
                        &format!("also running (pid {})", p.pid),
                        format!(
                            "{}{}{}",
                            if p.root() { "as root" } else { "not root" },
                            match p.age_secs {
                                Some(secs) => format!(
                                    ", for {}",
                                    fmt_duration(std::time::Duration::from_secs(secs))
                                ),
                                None => String::new(),
                            },
                            if p.ours(&app.paths.run_dir) {
                                " — started by a controlcenter that is no longer here"
                            } else {
                                " — not started by controlcenter"
                            },
                        ),
                    );
                    field(out, "  its command", redact(&command_line(&p.argv)));
                }
            }
        }
        ProviderId::Tailscale => {
            if let Some(t) = app.vpn_cfg.tailscale.iter().find(|t| t.name == profile) {
                let mut argv = vec!["tailscale".to_string()];
                argv.extend(crate::vpn::tailscale::up_args(t));
                field(out, "command", command_line(&argv));
            }
        }
        ProviderId::Netbird => {
            field(out, "profiles", "netbird's own — controlcenter only reads them");
        }
    }
}

/// What the subject and its chain need from the machine — a missing binary is
/// one of the two or three things that explain a connection never starting.
/// Clients nothing here uses are left out with everything else about them.
fn environment(out: &mut String, app: &App, target: &LogTarget, chain: &[LogTarget]) {
    section(out, "environment");
    let bin = |name: &str| match crate::platform::which_bin(name) {
        Some(p) => p.display().to_string(),
        None => "not on PATH".to_string(),
    };

    let mut wanted: Vec<&str> = Vec::new();
    let mut needs_root = false;
    let mut opens_a_session = false;
    for t in std::iter::once(target).chain(chain) {
        match t {
            LogTarget::Program => {
                wanted.push("ssh");
                if app.ssh_password_helper == crate::ssh::PasswordHelper::Sshpass {
                    wanted.push("sshpass");
                }
                wanted.push(app.rdp_client.program());
                for p in ProviderId::ALL {
                    wanted.extend(p.binaries());
                }
                needs_root = true;
                opens_a_session = true;
            }
            LogTarget::Tunnel(_) => wanted.push("ssh"),
            LogTarget::Ssh(_) => {
                wanted.push("ssh");
                if app.ssh_password_helper == crate::ssh::PasswordHelper::Sshpass {
                    wanted.push("sshpass");
                }
                opens_a_session = true;
            }
            LogTarget::Rdp(_) => wanted.push(app.rdp_client.program()),
            LogTarget::Vpn(p, _) => {
                wanted.extend(p.binaries());
                needs_root |= p.needs_root();
            }
        }
    }
    // Two links of a chain usually want ssh; the reader needs it once.
    let mut listed: Vec<&str> = Vec::new();
    for name in wanted {
        if !listed.contains(&name) {
            listed.push(name);
            field(out, name, bin(name));
        }
    }
    if needs_root {
        // Which escalation was available, and which was used, decides whether a
        // stop could have been dismissed — so it belongs next to the commands
        // that were run.
        #[cfg(not(windows))]
        {
            field(
                out,
                "root",
                if crate::vpn::privileged::available() {
                    format!("{} / {}", bin("pkexec"), bin("sudo"))
                } else {
                    "neither pkexec nor sudo is on PATH".to_string()
                },
            );
            field(
                out,
                "sudo ticket",
                if crate::vpn::privileged::has_ticket() {
                    "held — root commands run as `sudo -n`, without a dialog"
                } else {
                    "none — root commands go through pkexec"
                },
            );
        }
        #[cfg(windows)]
        field(
            out,
            "administrator",
            if crate::vpn::privileged::has_ticket() {
                "yes — VPN commands run directly".to_string()
            } else if crate::vpn::privileged::available() {
                format!("no — VPN commands go through {}", bin("sudo"))
            } else {
                "no, and there is no sudo — VPN commands cannot run at all".to_string()
            },
        );
    }
    if opens_a_session {
        field(out, "ssh sessions", app.ssh_launcher.label());
        // Which helper carries a stored password decides what a failed login
        // means: a wrong password, or one that never reached ssh at all.
        field(out, "ssh passwords", app.ssh_password_helper.label());
    }
    // A plan still running is why something is half up, whatever it is about.
    match &app.activation {
        Some(a) => field(out, "activating", format!("{} · {}", a.target, a.progress())),
        None => field(out, "activating", "nothing in flight"),
    }
    // Every tunnel on the machine, whoever made it. A device nobody accounts
    // for is the shape a leaked session takes once its log is gone, so it is
    // reported wherever the subject is about a VPN at all.
    let about_a_vpn = std::iter::once(target)
        .chain(chain)
        .any(|t| matches!(t, LogTarget::Program | LogTarget::Vpn(..)));
    if about_a_vpn {
        let devices = app.tunnel_devices();
        if devices.is_empty() {
            field(out, "tunnel devices", "none");
        }
        for (link, owner) in devices {
            field(
                out,
                &format!("device {}", link.name),
                format!(
                    "{} — {}",
                    link.detail(),
                    match owner {
                        Some(id) => id.slug().to_string(),
                        None => "unaccounted for".to_string(),
                    }
                ),
            );
        }
    }
}

fn vpn_clients(out: &mut String, app: &App) {
    section(out, "vpn clients");
    for state in &app.vpn.providers {
        let _ = writeln!(out, "### {}", state.id.slug());
        field(
            out,
            "installed",
            if state.installed { "yes" } else { "no" },
        );
        field(
            out,
            "connected",
            if state.status.connected { "yes" } else { "no" },
        );
        if let Some(p) = state.active_profile() {
            field(out, "active", p);
        }
        if let Some(b) = &state.busy {
            field(out, "busy", b);
        }
        if let Some(e) = &state.error {
            field(out, "error", redact(e));
        }
        for (k, v) in &state.status.fields {
            field(out, &k.to_lowercase(), redact(v));
        }
        if state.profiles.is_empty() {
            field(out, "profiles", "none");
        } else {
            for p in &state.profiles {
                let _ = writeln!(
                    out,
                    "  {} {}{}",
                    match (p.is_stored(), p.active) {
                        // Up, but not controlcenter's: it explains the client's
                        // state without being any of its profiles.
                        (false, _) => "[!]   ",
                        (true, true) => "[up]  ",
                        (true, false) => "[down]",
                    },
                    p.name,
                    if p.detail.is_empty() {
                        String::new()
                    } else {
                        format!(" — {}", p.detail)
                    }
                );
            }
        }
        let _ = writeln!(out);
    }
}

fn tunnels(out: &mut String, app: &App) {
    section(out, "tunnels");
    if app.tunnels.is_empty() {
        let _ = writeln!(out, "none configured");
        return;
    }
    for t in &app.tunnels {
        let _ = writeln!(out, "### {}", t.name);
        tunnel_block(out, app, t);
        let _ = writeln!(out);
    }
}

fn ssh_hosts(out: &mut String, app: &App) {
    section(out, "ssh hosts");
    if app.ssh_hosts.is_empty() {
        let _ = writeln!(out, "none configured");
        return;
    }
    for h in &app.ssh_hosts {
        let _ = writeln!(out, "### {}", h.name);
        ssh_block(out, app, h);
        let _ = writeln!(out);
    }
}

fn rdp_connections(out: &mut String, app: &App) {
    section(out, "rdp connections");
    if app.rdp_conns.is_empty() {
        let _ = writeln!(out, "none configured");
        return;
    }
    for c in &app.rdp_conns {
        let _ = writeln!(out, "### {}", c.name);
        rdp_block(out, app, c);
        let _ = writeln!(out);
    }
}

/// The journal, in order: what controlcenter did about the subject, about each
/// link of its chain, and the plans and teardowns that drove them.
fn what_it_did(out: &mut String, app: &App, target: &LogTarget, chain: &[LogTarget]) {
    section(out, "what controlcenter did");
    let mut wrote_any = false;
    let mut body = String::new();
    for (about, e) in app.journal.all() {
        // A plan or a panic is recorded against the program itself and is what
        // set every one of these in motion, so it belongs in any report.
        let mine = *about == LogTarget::Program
            || target.covers(about)
            || chain.iter().any(|link| link.covers(about));
        if !mine {
            continue;
        }
        wrote_any = true;
        let _ = writeln!(
            body,
            "{}  {:<24}{}{}",
            logs::stamp(e.at),
            about.title(),
            if e.error { "ERROR: " } else { "" },
            redact(&e.text)
        );
    }
    if !wrote_any {
        let _ = writeln!(out, "nothing yet this run");
        return;
    }
    let _ = writeln!(out, "```\n{body}```");
}

/// The focused pane's log, in full, and then the chain's — as a file beside
/// the report, since between them the links can run to thousands of lines.
fn log_output(
    out: &mut String,
    app: &App,
    target: &LogTarget,
    chain: &[LogTarget],
    stem: &str,
) -> Vec<(String, String)> {
    section(out, &format!("log · {}", target.title()));
    write_lines(out, &app.log_lines(target));

    let mut chain_log = String::new();
    for link in chain {
        let lines = app.log_lines(link);
        if lines.is_empty() {
            continue;
        }
        let _ = writeln!(chain_log, "──── {} ────\n", link.title());
        for line in &lines {
            let _ = writeln!(chain_log, "{}", plain_line(line));
        }
        let _ = writeln!(chain_log);
    }
    if chain_log.is_empty() {
        return Vec::new();
    }

    let name = format!("{stem}{CHAIN_LOG_SUFFIX}");
    section(out, "logs of the chain");
    let _ = writeln!(
        out,
        "Everything the links above logged, in full, is in [{name}]({name}) beside this \
         file — one section per link, oldest line first."
    );
    let header = format!(
        "controlcenter — every log {} depends on\ngenerated {}\n\n",
        target.title(),
        logs::stamp(SystemTime::now())
    );
    vec![(name, header + &chain_log)]
}

fn write_lines(out: &mut String, lines: &[Entry]) {
    if lines.is_empty() {
        let _ = writeln!(out, "nothing logged");
        return;
    }
    let _ = writeln!(out, "```");
    for e in lines {
        let _ = writeln!(out, "{}", plain_line(e));
    }
    let _ = writeln!(out, "```");
}

/// One log line as both the report and the files beside it write it: when, who
/// said it, and what — with anything secret-looking taken out.
fn plain_line(e: &Entry) -> String {
    format!("{}  {:<14}{}", logs::stamp(e.at), e.source, redact(&e.text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn a_password_typed_into_extra_args_never_reaches_the_report() {
        // The forms take free text; xfreerdp really does take /p:.
        assert_eq!(
            redact("xfreerdp3 /v:host:3389 /p:hunter2 /f"),
            format!("xfreerdp3 /v:host:3389 /p:{REDACTED} /f")
        );
        assert_eq!(
            redact("openvpn --config x.ovpn --password hunter2"),
            format!("openvpn --config x.ovpn --password {REDACTED}")
        );
        assert_eq!(
            redact("tool --auth-token=abc123"),
            format!("tool --auth-token={REDACTED}")
        );
        assert_eq!(
            redact("PrivateKey = wOEI9rqqbDwn"),
            format!("PrivateKey = {REDACTED}")
        );
    }

    #[test]
    fn a_single_letter_flag_is_read_by_the_prefix_it_came_with() {
        // xfreerdp: /p: is the password.
        assert_eq!(
            redact("xfreerdp3 /v:host /p:hunter2"),
            format!("xfreerdp3 /v:host /p:{REDACTED}")
        );
        // ssh: -p is the port, and a stacked tunnel is full of them.
        assert_eq!(
            redact("ssh -N -p 12222 127.0.0.1"),
            "ssh -N -p 12222 127.0.0.1"
        );
    }

    #[test]
    fn the_ssh_options_controlcenter_passes_itself_stay_readable() {
        // Set for every host with a stored password, and not a secret.
        assert_eq!(
            redact("ssh -o NumberOfPasswordPrompts=1 host"),
            "ssh -o NumberOfPasswordPrompts=1 host"
        );
        // openvpn is told where to read the credentials, not what they are.
        assert_eq!(
            redact("openvpn --auth-user-pass /dev/stdin"),
            "openvpn --auth-user-pass /dev/stdin"
        );
    }

    #[test]
    fn an_ordinary_command_line_is_left_exactly_as_it_is() {
        let line = "ssh -N -o BatchMode=yes -L 127.0.0.1:5432:db.internal:5432 bastion";
        assert_eq!(redact(line), line);
        // -p is a port on ssh, but a password on xfreerdp: the flag that takes
        // a value is masked either way, and a port number is not a secret worth
        // keeping. Being wrong in this direction is the safe one.
        assert_eq!(redact("ssh -i ~/.ssh/id_ed25519 host"), "ssh -i ~/.ssh/id_ed25519 host");
    }

    #[test]
    fn a_stored_secret_is_reported_as_present_and_nothing_more() {
        assert_eq!(secret_note(""), "not set");
        let note = secret_note("hunter2");
        assert!(note.contains('7'), "{note}");
        assert!(!note.contains("hunter"), "{note}");
    }

    #[test]
    fn every_file_of_one_export_is_named_after_the_same_stem() {
        let at = UNIX_EPOCH + Duration::from_secs(1_787_752_991);
        let stem = file_stem(&LogTarget::Tunnel("db prod".into()), at);
        assert_eq!(stem, "controlcenter-tunnel-db-prod-20260826-140311");
        assert_eq!(
            format!("{stem}{CHAIN_LOG_SUFFIX}"),
            "controlcenter-tunnel-db-prod-20260826-140311-chain.log"
        );
    }
}
