mod app;
mod browser;
mod chooser;
mod config;
mod logs;
mod platform;
mod rdp;
mod report;
mod ssh;
mod theme;
mod tunnel;
mod types;
mod ui;
mod vpn;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;

#[derive(Parser)]
#[command(
    name = "controlcenter",
    version,
    about = "TUI for configuring, activating, and monitoring SSH tunnels"
)]
struct Cli {
    /// Print the resolved config paths and exit
    #[arg(long)]
    config_paths: bool,
    /// Print every VPN connection on this machine and exit
    #[arg(long)]
    vpn_scan: bool,
    /// Whether to take a sudo ticket before starting: ask, auto or never.
    /// Overrides `vpn.sudo` in config.toml for this run.
    #[arg(long, value_name = "ask|auto|never")]
    sudo: Option<String>,
}

fn main() -> Result<()> {
    if let Some(code) = askpass() {
        return Ok(code);
    }
    let cli = Cli::parse();

    let paths = config::Paths::new()?;
    if cli.config_paths {
        println!("config dir : {}", paths.config_dir.display());
        println!("tunnels    : {}", paths.tunnels_file.display());
        println!("config     : {}", paths.config_file.display());
        println!("rdp        : {}", paths.rdp_file.display());
        println!("ssh        : {}", paths.ssh_file.display());
        println!("vpn        : {}", paths.vpn_file.display());
        println!("wireguard  : {}", paths.wireguard_dir.display());
        println!("openvpn    : {}", paths.openvpn_dir.display());
        println!("runtime    : {}", paths.run_dir.display());
        println!("reports    : {}", paths.reports_dir.display());
        return Ok(());
    }

    if cli.vpn_scan {
        print_vpn_scan();
        return Ok(());
    }

    if tunnel::which_ssh().is_none() {
        eprintln!("controlcenter: `ssh` was not found on PATH.");
        if cfg!(windows) {
            eprintln!(
                "Install it with: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
            );
        }
        std::process::exit(2);
    }

    paths.ensure_dirs().context("creating config dir")?;
    let tunnels = config::load_tunnels(&paths.tunnels_file)?;
    let rdp_conns = config::load_rdp(&paths.rdp_file)?;
    let ssh_hosts = config::load_ssh(&paths.ssh_file)?;
    let vpn_cfg = config::load_vpn(&paths.vpn_file)?;
    let app_config = config::load_app_config(&paths.config_file)?;

    escalation_warm_up(&cli, &app_config);

    let mut terminal = init_terminal()?;
    let res = app::App::new(tunnels, rdp_conns, ssh_hosts, vpn_cfg, paths, app_config)
        .run(&mut terminal);
    restore_terminal(&mut terminal)?;
    res
}

/// Answer ssh's password prompt, when ssh is the one that started us.
///
/// ssh runs the program named by `SSH_ASKPASS` when it wants a password, hands
/// it the prompt as an argument and reads one line back. Where `sshpass` is not
/// installed — every Windows machine, since sshpass is built on pseudo-terminals
/// and cannot exist there — that program is controlcenter itself, re-run with
/// [`ssh::ASKPASS_ENV`] set. The password comes through the environment, the
/// same way sshpass takes it, and never touches a command line.
///
/// This runs before the arguments are parsed, because the argument ssh passes
/// is a prompt for a human and not a flag.
fn askpass() -> Option<()> {
    if std::env::var_os(ssh::ASKPASS_ENV).is_none() {
        return None;
    }
    if let Ok(password) = std::env::var(ssh::PASSWORD_ENV) {
        println!("{password}");
    }
    Some(())
}

/// `--vpn-scan`: what is on this machine, before the TUI is involved at all.
///
/// The same sweep the VPN tab runs, printed once. It is the fastest way to
/// answer "is something already holding this tunnel" from a shell, and it needs
/// no root — see [`vpn::scan`].
fn print_vpn_scan() {
    let scan = vpn::scan::scan();
    if let Some(e) = &scan.error {
        eprintln!("controlcenter: {e}");
    }
    println!("processes");
    if scan.processes.is_empty() {
        println!("  none");
    }
    for p in &scan.processes {
        println!(
            "  {:<8} pid {:<8} {}{}",
            p.provider.slug(),
            p.pid,
            if p.root() { "root " } else { "" },
            p.label()
        );
        println!("           {}", report::redact(&report::command_line(&p.argv)));
    }
    println!("\ntunnel devices");
    let devices: Vec<_> = scan.tunnels().collect();
    if devices.is_empty() {
        println!("  none");
    }
    for link in devices {
        println!("  {:<10} {}", link.name, link.detail());
    }
}

/// Settle the question of root *before* the TUI takes the screen.
///
/// Taking a VPN down needs root, and the escalation that is always available
/// once the alternate screen is up — a polkit dialog — is also the one that can
/// be dismissed, or that never appears at all on a bare tty. A dismissed prompt
/// there leaves a root openvpn running that nothing left on the machine knows
/// how to reach. So this is the one moment where a password prompt can simply
/// be typed at, and controlcenter uses it: with a sudo ticket in hand, stopping
/// a connection later is silent and cannot fail for want of an agent.
///
/// Nothing is asked for when no client that needs root is installed, and
/// nothing here handles a password: `sudo` prompts, on the user's own terminal.
fn escalation_warm_up(cli: &Cli, app_config: &config::AppConfig) {
    let mode = vpn::privileged::Warmup::from_str(
        cli.sudo.as_deref().unwrap_or(&app_config.vpn.sudo),
    );
    let wanted = vpn::ProviderId::ALL
        .into_iter()
        .any(|p| p.needs_root() && vpn::installed(p));
    if !wanted || mode == vpn::privileged::Warmup::Never {
        return;
    }
    if vpn::privileged::will_ask(mode) {
        println!(
            "controlcenter: taking a sudo ticket so VPN sessions can be stopped without a \
             dialog (set vpn.sudo = \"never\" in config.toml to skip this)."
        );
    }
    if let Some(line) = vpn::privileged::warm_up(mode).line() {
        println!("{line}");
    }
}

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

fn init_terminal() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Hand the terminal back to a child process (interactive ssh).
pub fn suspend_terminal(terminal: &mut Tui) -> Result<()> {
    restore_terminal(terminal)
}

/// Take the terminal back after the child exited.
pub fn resume_terminal(terminal: &mut Tui) -> Result<()> {
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen, Clear(ClearType::All))?;
    terminal.hide_cursor()?;
    // The alternate screen we came back to is blank, but ratatui still diffs
    // against the frame drawn before the session; drop it so the next draw
    // repaints every cell. (Terminal::clear would do this too, but it asks the
    // terminal for the cursor position first and that can hang.)
    terminal.swap_buffers();
    Ok(())
}
