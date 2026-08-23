mod app;
mod config;
mod netbird;
mod rdp;
mod ssh;
mod theme;
mod tunnel;
mod types;
mod ui;

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let paths = config::Paths::new()?;
    if cli.config_paths {
        println!("config dir : {}", paths.config_dir.display());
        println!("tunnels    : {}", paths.tunnels_file.display());
        println!("config     : {}", paths.config_file.display());
        println!("rdp        : {}", paths.rdp_file.display());
        println!("ssh        : {}", paths.ssh_file.display());
        return Ok(());
    }

    if tunnel::which_ssh().is_none() {
        eprintln!("controlcenter: `ssh` was not found on PATH.");
        std::process::exit(2);
    }

    paths.ensure_dirs().context("creating config dir")?;
    let tunnels = config::load_tunnels(&paths.tunnels_file)?;
    let rdp_conns = config::load_rdp(&paths.rdp_file)?;
    let ssh_hosts = config::load_ssh(&paths.ssh_file)?;
    let app_config = config::load_app_config(&paths.config_file)?;

    let mut terminal = init_terminal()?;
    let res = app::App::new(tunnels, rdp_conns, ssh_hosts, paths, app_config).run(&mut terminal);
    restore_terminal(&mut terminal)?;
    res
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
