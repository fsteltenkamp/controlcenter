//! Every VPN connection on this machine, whoever started it.
//!
//! controlcenter owns the sessions it starts, but a session can outlive it — a
//! crash, a `kill -9`, an exit while openvpn was up — and carry on as a root
//! process nothing here holds any more. The next connection to the same server
//! then fights the orphan for the slot, which reads as a tunnel that comes up
//! and drops every three minutes rather than as the leak it is. So the tab has
//! to show what is on the machine, not only what controlcenter is holding.
//!
//! This module deliberately knows nothing about what the app owns: it reports
//! what it finds and [`crate::app::App`] subtracts its own sessions. Two
//! sources, because neither one is enough on its own:
//!
//! - **processes**, from `/proc`. An OpenVPN connection *is* a process, so this
//!   is the source that can name one (by the `--config` it was started with)
//!   and the only one that can stop it (by pid). It is also the only source
//!   that sees a client which is failing to connect: a session stuck retrying
//!   holds no interface yet still holds the server's slot.
//! - **interfaces**, from `ip`. A tunnel actually carrying traffic has a device
//!   whoever created it, so this is the catch-all — a device nothing else
//!   accounts for is evidence, and is reported rather than dropped. It cannot
//!   replace the process scan: a device says a tunnel exists, never whose it is
//!   or how to take it down.
//!
//! Nothing here escalates, and nothing here is allowed to: reading another
//! user's `/proc/<pid>/cmdline` and listing links are both unprivileged on an
//! ordinary Linux, which is what lets the scan run on the same five-second
//! clock as the rest of the status polling.

use super::{ProviderId, VpnMsg};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;

/// The client binaries a running process can belong to. Only OpenVPN appears
/// here for now: NetBird and Tailscale are daemons that are up whether or not
/// anything is connected, so their own status is the honest source for them,
/// and WireGuard has no process at all — its connection is the interface.
fn provider_of_binary(name: &str) -> Option<ProviderId> {
    match name {
        "openvpn" => Some(ProviderId::Openvpn),
        _ => None,
    }
}

/// One VPN client process found on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub provider: ProviderId,
    /// The command line as the kernel has it. Never shown without going
    /// through [`crate::report::redact`] first — this is someone else's argv.
    pub argv: Vec<String>,
    pub uid: u32,
    /// How long it has been running, when `/proc` could say.
    pub age_secs: Option<u64>,
}

impl Process {
    pub fn root(&self) -> bool {
        self.uid == 0
    }

    /// The value openvpn was given for `--<flag>`.
    fn flag(&self, flag: &str) -> Option<&str> {
        let want = format!("--{flag}");
        let mut it = self.argv.iter();
        while let Some(arg) = it.next() {
            if *arg == want {
                return it.next().map(String::as_str);
            }
        }
        None
    }

    pub fn config(&self) -> Option<&str> {
        self.flag("config")
    }

    /// The pid file it was told to write. A session controlcenter started
    /// names one inside the run directory, which is how its orphans are
    /// recognised as having been ours.
    pub fn pid_file(&self) -> Option<&str> {
        self.flag("writepid")
    }

    /// The interface it was told to use, when the config named one on the
    /// command line. openvpn usually gets `dev tun` from the config instead, so
    /// this is a bonus rather than something to rely on.
    pub fn dev(&self) -> Option<&str> {
        self.flag("dev")
    }

    /// What the row is called. Every profile controlcenter imports has its
    /// config at `<profile name>/config.ovpn`, so an orphan of ours gets its
    /// profile name back rather than being listed as "config".
    pub fn label(&self) -> String {
        let Some(config) = self.config() else {
            return format!("pid {}", self.pid);
        };
        let path = Path::new(config);
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
        match stem.as_deref() {
            Some("config") | None => path
                .parent()
                .and_then(Path::file_name)
                .map(|s| s.to_string_lossy().into_owned())
                .or(stem)
                .unwrap_or_else(|| format!("pid {}", self.pid)),
            Some(_) => stem.unwrap(),
        }
    }

    /// Was this started by a controlcenter whose run directory is `run_dir`?
    /// True for our own live sessions and for the orphans of a previous run,
    /// which is exactly the distinction worth drawing in the list.
    pub fn ours(&self, run_dir: &Path) -> bool {
        self.pid_file()
            .is_some_and(|p| Path::new(p).starts_with(run_dir))
    }

    /// How to stop it. The one place this command line is built, so what a
    /// report shows is what was actually run.
    pub fn stop_argv(&self, force: bool) -> Vec<String> {
        vec![
            "kill".to_string(),
            if force { "-KILL" } else { "-TERM" }.to_string(),
            self.pid.to_string(),
        ]
    }
}

/// The kinds of link that mean a tunnel. `ovpn` is what an OpenVPN using the
/// kernel's data channel offload registers; without DCO it is an ordinary
/// `tun`, which is the same kind a virtual machine's tap device has — see
/// [`Link::is_tunnel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Wireguard,
    Ovpn,
    Tun,
}

impl LinkKind {
    /// What `ip link show type <kind>` is asked for.
    pub fn query(self) -> &'static str {
        match self {
            Self::Wireguard => "wireguard",
            Self::Ovpn => "ovpn",
            Self::Tun => "tun",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Wireguard => "wireguard",
            Self::Ovpn => "openvpn (dco)",
            Self::Tun => "tun",
        }
    }
}

/// One network interface that carries, or could carry, a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub kind: LinkKind,
    /// Enslaved to a bridge, i.e. a virtual machine's tap rather than a tunnel.
    pub bridged: bool,
    /// Whether anything is actually on the other end. A device left behind by a
    /// client that has gone reads `NO-CARRIER`/`state DOWN` while keeping its
    /// address — which is exactly what makes the next connection collide with
    /// it, so it is worth saying out loud.
    pub carrier: bool,
    pub addrs: Vec<String>,
}

impl Link {
    /// Whether this device is worth reporting as a tunnel.
    ///
    /// A `wireguard` or `ovpn` device is one by definition. A `tun` device is
    /// not: libvirt and qemu create them too. Those are either enslaved to a
    /// bridge or have no address of their own, and a tunnel that is up always
    /// has an address — so that is the line drawn here rather than a guess at
    /// the name.
    pub fn is_tunnel(&self) -> bool {
        match self.kind {
            LinkKind::Wireguard | LinkKind::Ovpn => true,
            LinkKind::Tun => !self.bridged && !self.addrs.is_empty(),
        }
    }

    pub fn detail(&self) -> String {
        let mut s = self.kind.label().to_string();
        if !self.carrier {
            s.push_str(" · no carrier");
        }
        if !self.addrs.is_empty() {
            s.push_str(" · ");
            s.push_str(&self.addrs.join(", "));
        }
        s
    }

    /// How to take the device away.
    ///
    /// A WireGuard interface goes back to `wg-quick`, which is what brought it
    /// up wherever it came from — and which says so plainly when there is no
    /// config to go with it, a better answer than pulling a link out from under
    /// whatever owns it. An `ovpn` device has no such owner by the time it is
    /// offered here (see `App::foreign_for`), so it is deleted outright.
    pub fn remove_argv(&self) -> Vec<String> {
        match self.kind {
            LinkKind::Wireguard => {
                vec!["wg-quick".to_string(), "down".to_string(), self.name.clone()]
            }
            LinkKind::Ovpn | LinkKind::Tun => vec![
                "ip".to_string(),
                "link".to_string(),
                "delete".to_string(),
                self.name.clone(),
            ],
        }
    }
}

/// What the machine looks like right now.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub processes: Vec<Process>,
    pub links: Vec<Link>,
    /// Why the picture is incomplete, when something could not be read.
    pub error: Option<String>,
}

impl Scan {
    /// The tunnel devices, in the order `ip` listed them.
    pub fn tunnels(&self) -> impl Iterator<Item = &Link> {
        self.links.iter().filter(|l| l.is_tunnel())
    }

    pub fn processes_of(&self, provider: ProviderId) -> impl Iterator<Item = &Process> {
        self.processes.iter().filter(move |p| p.provider == provider)
    }
}

/// The OpenVPN devices left behind on the machine.
///
/// A killed openvpn does not take its device with it: an `ovpn` link outlives
/// the process, keeps the address it was given, and is what the next connection
/// to the same profile collides with — openvpn logs `File exists` and takes the
/// next number instead. There is no process left to find one by, so here the
/// device *is* the connection.
///
/// `ours` are the devices live sessions have said they are on. `unaccounted` is
/// whether any openvpn process was found that nothing is holding: while one of
/// those is running, a device it has not named is not evidence of a leak — it
/// is very likely the one that process is using, and there is no way to tell
/// from the outside which is which. Nothing is offered in that case, because
/// the process is the thing to deal with first and taking it down releases its
/// device anyway.
pub fn leaked_ovpn_devices(scan: &Scan, ours: &[String], unaccounted: bool) -> Vec<Link> {
    if unaccounted {
        return Vec::new();
    }
    scan.tunnels()
        .filter(|l| l.kind == LinkKind::Ovpn)
        .filter(|l| !ours.iter().any(|o| o == &l.name))
        .cloned()
        .collect()
}

/// A connection on the machine that controlcenter is not holding a session for.
/// The profile list shows one row per [`Foreign`], underneath the profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Foreign {
    /// A client process: an orphan of a previous run, or someone else's.
    Process(Process),
    /// An interface no stored profile accounts for.
    Interface(Link),
}

impl Foreign {
    /// What the row is called.
    pub fn name(&self) -> String {
        match self {
            Self::Process(p) => p.label(),
            Self::Interface(l) => l.name.clone(),
        }
    }

    /// Shown next to the name, and in the status pane.
    pub fn detail(&self, run_dir: &Path) -> String {
        match self {
            Self::Process(p) => {
                let mut s = format!("pid {}", p.pid);
                if p.root() {
                    s.push_str(" · root");
                }
                if let Some(age) = p.age_secs {
                    s.push_str(&format!(
                        " · {}",
                        crate::ui::fmt_duration(std::time::Duration::from_secs(age))
                    ));
                }
                s.push_str(if p.ours(run_dir) {
                    " · left behind by controlcenter"
                } else {
                    " · not started here"
                });
                s
            }
            Self::Interface(l) => match l.kind {
                // An ovpn device is only ever offered once nothing is left that
                // could own it, so there is no doubt about what it is.
                LinkKind::Ovpn => format!("{} · left behind, nothing owns it", l.detail()),
                _ => format!("{} · not controlcenter's", l.detail()),
            },
        }
    }

    /// How to take it down.
    pub fn stop_argv(&self, force: bool) -> Vec<String> {
        match self {
            Self::Process(p) => p.stop_argv(force),
            Self::Interface(l) => l.remove_argv(),
        }
    }
}

// ---------------------------------------------------------------------------
// /proc
// ---------------------------------------------------------------------------

/// argv as `/proc/<pid>/cmdline` holds it: NUL-separated, usually NUL-terminated.
fn split_cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// The client a command line belongs to, by the binary it is running.
///
/// Only argv[0] is looked at, so `pkexec /usr/bin/openvpn …` — the wrapper
/// controlcenter's own sessions are started through — is not counted a second
/// time alongside the openvpn it exec'd.
fn provider_of(argv: &[String]) -> Option<ProviderId> {
    let program = argv.first()?;
    let base = Path::new(program).file_name()?.to_str()?;
    provider_of_binary(base)
}

/// The real uid from `/proc/<pid>/status`.
fn uid_in_status(raw: &str) -> Option<u32> {
    raw.lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Seconds since boot at which the process started, from field 22 of
/// `/proc/<pid>/stat`.
///
/// The fields are counted from the *end* of the command name rather than by
/// splitting the whole line: field 2 is the executable name in parentheses and
/// may itself contain spaces and brackets.
fn starttime_in_stat(raw: &str, ticks_per_sec: u64) -> Option<u64> {
    // Everything after the comm field is fields 3 onwards, so field 22 is the
    // twentieth of them.
    let after_comm = raw.rsplit_once(')')?.1;
    let jiffies: u64 = after_comm.split_whitespace().nth(19)?.parse().ok()?;
    Some(jiffies / ticks_per_sec.max(1))
}

/// Seconds since boot, from `/proc/uptime`.
fn uptime_secs() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = raw.split_whitespace().next()?.parse().ok()?;
    Some(secs as u64)
}

/// The kernel's tick rate. `USER_HZ` is 100 on every Linux port that matters
/// and there is no way to ask for it without libc, so it is assumed — this
/// only ever moves the "running for" column, never a decision.
const USER_HZ: u64 = 100;

fn read_processes() -> Vec<Process> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    let uptime = uptime_secs();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        // A process that exits between the readdir and the read is normal, so
        // every one of these is a `continue` rather than an error.
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let argv = split_cmdline(&raw);
        let Some(provider) = provider_of(&argv) else {
            continue;
        };
        let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| uid_in_status(&s))
            .unwrap_or(u32::MAX);
        let age_secs = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| starttime_in_stat(&s, USER_HZ))
            .zip(uptime)
            .map(|(started, up)| up.saturating_sub(started));
        found.push(Process {
            pid,
            provider,
            argv,
            uid,
            age_secs,
        });
    }
    found.sort_by_key(|p| p.pid);
    found
}

// ---------------------------------------------------------------------------
// ip
// ---------------------------------------------------------------------------

fn ip(args: &[&str]) -> Result<String, String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("running ip: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Interface names and their bridge, from `ip -o link show type <kind>`.
///
/// Asking the kernel to filter by kind is why nothing here has to parse the
/// device-type section of `ip -d`, which differs from device to device. A
/// `master` in the flags means the device is enslaved to a bridge.
fn parse_links(raw: &str, kind: LinkKind) -> Vec<Link> {
    raw.lines()
        .filter_map(|line| {
            let after_index = line.split_once(':')?.1;
            // `ip` writes "wg0@if7" for stacked links; the device is the left half.
            let name = after_index.split(':').next()?.split('@').next()?.trim();
            if name.is_empty() {
                return None;
            }
            let flags = line
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map(|(f, _)| f)
                .unwrap_or("");
            let mut tokens = line.split_whitespace();
            let state = tokens
                .by_ref()
                .position(|t| t == "state")
                .and(tokens.next())
                .unwrap_or("UNKNOWN");
            Some(Link {
                name: name.to_string(),
                kind,
                bridged: line.split_whitespace().any(|t| t == "master"),
                // A tun device reads UNKNOWN while it is perfectly alive, so
                // only an explicit DOWN, or no carrier, counts as dead.
                carrier: !flags.split(',').any(|f| f == "NO-CARRIER") && state != "DOWN",
                addrs: Vec::new(),
            })
        })
        .collect()
}

/// Addresses per interface, from `ip -o addr show`.
fn parse_addrs(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let _index = it.next()?;
            let iface = it.next()?.trim_end_matches(':');
            let family = it.next()?;
            if family != "inet" && family != "inet6" {
                return None;
            }
            Some((iface.to_string(), it.next()?.to_string()))
        })
        .collect()
}

fn read_links() -> (Vec<Link>, Option<String>) {
    let mut links: Vec<Link> = Vec::new();
    let mut error = None;
    for kind in [LinkKind::Wireguard, LinkKind::Ovpn, LinkKind::Tun] {
        match ip(&["-o", "link", "show", "type", kind.query()]) {
            Ok(out) => links.extend(parse_links(&out, kind)),
            // A kind the running kernel has no module for is not an error:
            // `ovpn` only exists where openvpn's data channel offload does.
            Err(e) if kind == LinkKind::Ovpn => {
                let _ = e;
            }
            Err(e) => error = Some(format!("listing {} interfaces: {e}", kind.query())),
        }
    }
    if let Ok(out) = ip(&["-o", "addr", "show"]) {
        for (iface, addr) in parse_addrs(&out) {
            if let Some(link) = links.iter_mut().find(|l| l.name == iface) {
                link.addrs.push(addr);
            }
        }
    }
    (links, error)
}

/// Read the machine. Runs on a thread; takes a few milliseconds of `/proc` and
/// four `ip` calls.
pub fn scan() -> Scan {
    let (links, error) = read_links();
    Scan {
        processes: read_processes(),
        links,
        error,
    }
}

/// Scan on a background thread and send the result back, like every other
/// status poll.
pub fn spawn(tx: Sender<VpnMsg>) {
    thread::spawn(move || {
        let _ = tx.send(VpnMsg::Scanned(scan()));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ovpn(pid: u32, args: &[&str]) -> Process {
        Process {
            pid,
            provider: ProviderId::Openvpn,
            argv: args.iter().map(|s| s.to_string()).collect(),
            uid: 0,
            age_secs: Some(3600),
        }
    }

    #[test]
    fn a_command_line_is_read_back_out_of_the_nul_separated_form() {
        let raw = b"/usr/bin/openvpn\0--config\0/etc/x.ovpn\0";
        assert_eq!(
            split_cmdline(raw),
            ["/usr/bin/openvpn", "--config", "/etc/x.ovpn"]
        );
        // A kernel thread has an empty cmdline, and is nobody's client.
        assert!(split_cmdline(b"").is_empty());
    }

    #[test]
    fn only_the_binary_being_run_decides_which_client_a_process_is() {
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            provider_of(&argv("/usr/bin/openvpn --config x.ovpn")),
            Some(ProviderId::Openvpn)
        );
        // The pkexec controlcenter starts its own sessions through would
        // otherwise be counted a second time next to the openvpn it exec'd.
        assert_eq!(provider_of(&argv("/usr/bin/pkexec /usr/bin/openvpn")), None);
        assert_eq!(provider_of(&argv("/usr/bin/sudo /usr/bin/openvpn")), None);
        assert_eq!(provider_of(&argv("/usr/bin/ssh -N -L 1:2:3")), None);
        assert!(provider_of(&[]).is_none());
    }

    #[test]
    fn an_orphan_is_named_after_the_profile_it_was_started_from() {
        // Every imported profile's config has the same name, so the directory
        // is what says which profile an orphan of ours belonged to.
        let p = ovpn(
            42,
            &[
                "/usr/bin/openvpn",
                "--config",
                "/home/me/.config/controlcenter/openvpn/MuP - RZ Mgmt/config.ovpn",
            ],
        );
        assert_eq!(p.label(), "MuP - RZ Mgmt");
        // Anything else is named after the config file itself.
        let other = ovpn(43, &["/usr/bin/openvpn", "--config", "/etc/openvpn/work.ovpn"]);
        assert_eq!(other.label(), "work");
        // And a process with no --config at all still has to be addressable.
        assert_eq!(ovpn(44, &["/usr/bin/openvpn"]).label(), "pid 44");
    }

    #[test]
    fn a_session_left_behind_by_controlcenter_is_told_apart_by_its_pid_file() {
        let run = Path::new("/run/user/1000/controlcenter");
        let ours = ovpn(
            1,
            &[
                "/usr/bin/openvpn",
                "--config",
                "/etc/x.ovpn",
                "--writepid",
                "/run/user/1000/controlcenter/openvpn-work.pid",
            ],
        );
        assert!(ours.ours(run));
        let theirs = ovpn(
            2,
            &[
                "/usr/bin/openvpn",
                "--config",
                "/etc/x.ovpn",
                "--writepid",
                "/run/openvpn/work.pid",
            ],
        );
        assert!(!theirs.ours(run));
        // A systemd unit's openvpn writes no pid file at all.
        assert!(!ovpn(3, &["/usr/bin/openvpn", "--config", "/etc/x.ovpn"]).ours(run));
    }

    #[test]
    fn the_command_that_stops_a_process_is_built_in_one_place() {
        assert_eq!(ovpn(77, &["openvpn"]).stop_argv(false), ["kill", "-TERM", "77"]);
        assert_eq!(ovpn(77, &["openvpn"]).stop_argv(true), ["kill", "-KILL", "77"]);
    }

    #[test]
    fn interfaces_come_out_of_the_o_form_with_their_bridge() {
        let raw = "\
7: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none
9: wt0@if3: <POINTOPOINT,NOARP,UP> mtu 1280 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
";
        let links = parse_links(raw, LinkKind::Wireguard);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].name, "wg0");
        // A stacked link is named by its left half.
        assert_eq!(links[1].name, "wt0");
        assert!(!links[1].bridged);
    }

    #[test]
    fn a_virtual_machines_tap_is_not_a_tunnel() {
        let raw = "\
5: vnet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master virbr0 state UNKNOWN mode DEFAULT group default qlen 1000\\    link/ether fe:54:00:11:22:33
6: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
";
        let mut links = parse_links(raw, LinkKind::Tun);
        assert!(links[0].bridged);
        assert!(!links[0].is_tunnel());
        // An unbridged tun still has to carry an address to count: qemu makes
        // bare ones too, and a tunnel that is up always has one.
        assert!(!links[1].is_tunnel());
        links[1].addrs.push("192.168.233.5/24".into());
        assert!(links[1].is_tunnel());
    }

    #[test]
    fn an_openvpn_device_is_only_called_leaked_when_nothing_could_still_own_it() {
        let dev = |name: &str| Link {
            name: name.into(),
            kind: LinkKind::Ovpn,
            bridged: false,
            carrier: false,
            addrs: vec!["192.168.233.5/24".into()],
        };
        let scan = Scan {
            processes: Vec::new(),
            links: vec![dev("tun0"), dev("tun1"), dev("tun2")],
            error: None,
        };
        // The one a live session is on is not leaked; the other two are.
        let ours = vec!["tun2".to_string()];
        let names: Vec<String> = leaked_ovpn_devices(&scan, &ours, false)
            .iter()
            .map(|l| l.name.clone())
            .collect();
        assert_eq!(names, ["tun0", "tun1"]);

        // With an openvpn running that nothing here is holding, none of them
        // can be told apart from the one it is using.
        assert!(leaked_ovpn_devices(&scan, &ours, true).is_empty());
    }

    #[test]
    fn a_wireguard_interface_counts_whether_or_not_it_has_an_address() {
        let link = Link {
            name: "wt0".into(),
            kind: LinkKind::Wireguard,
            bridged: false,
            carrier: true,
            addrs: Vec::new(),
        };
        assert!(link.is_tunnel());
    }

    #[test]
    fn a_device_a_dead_client_left_behind_is_seen_for_what_it_is() {
        // What an openvpn that was killed leaves on the machine: the device is
        // still there, still holding the address the next connection wants, and
        // carrying nothing. The process scan cannot see this at all — there is
        // no process left — which is why the sweep reads interfaces too.
        let raw = "\
22: tun0: <NO-CARRIER,POINTOPOINT,NOARP,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000\\    link/none
24: tun2: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
";
        let mut links = parse_links(raw, LinkKind::Ovpn);
        assert!(!links[0].carrier);
        // A live tun reads UNKNOWN rather than UP, and is not dead.
        assert!(links[1].carrier);

        links[0].addrs.push("192.168.233.5/24".into());
        assert!(links[0].is_tunnel());
        assert!(links[0].detail().contains("no carrier"));
        assert!(links[0].detail().contains("192.168.233.5/24"));
        // An ovpn device has no client left to hand it back to.
        assert_eq!(links[0].remove_argv(), ["ip", "link", "delete", "tun0"]);
    }

    #[test]
    fn addresses_are_matched_up_with_the_interface_that_holds_them() {
        let raw = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
6: tun2    inet 192.168.233.5/24 scope global tun2\\       valid_lft forever preferred_lft forever
6: tun2    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever
2: enp42s0    link/ether aa:bb:cc:dd:ee:ff
";
        let addrs = parse_addrs(raw);
        assert_eq!(
            addrs,
            [
                ("lo".to_string(), "127.0.0.1/8".to_string()),
                ("tun2".to_string(), "192.168.233.5/24".to_string()),
                ("tun2".to_string(), "fe80::1/64".to_string()),
            ]
        );
    }

    #[test]
    fn a_processs_age_is_read_past_a_command_name_that_contains_spaces() {
        // Field 2 is "(comm)" and may hold anything, so the fields after it are
        // counted from the closing parenthesis rather than from the start.
        let stat = "1234 (open vpn) S 1 1234 1234 0 -1 4194560 1000 0 0 0 10 20 0 0 20 0 1 0 \
                    360000 12345 678 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0";
        assert_eq!(starttime_in_stat(stat, 100), Some(3600));
    }

    #[test]
    fn the_uid_that_owns_a_process_is_the_first_of_the_four() {
        let status = "Name:\topenvpn\nState:\tS (sleeping)\nPPid:\t1\nUid:\t0\t0\t0\t0\n";
        assert_eq!(uid_in_status(status), Some(0));
        assert_eq!(uid_in_status("Name:\tx\n"), None);
    }

    #[test]
    fn a_foreign_row_says_which_kind_of_leftover_it_is() {
        let run = Path::new("/run/user/1000/controlcenter");
        let ours = Foreign::Process(ovpn(
            9,
            &[
                "/usr/bin/openvpn",
                "--config",
                "/etc/x.ovpn",
                "--writepid",
                "/run/user/1000/controlcenter/openvpn-work.pid",
            ],
        ));
        assert!(ours.detail(run).contains("left behind by controlcenter"));
        assert!(ours.detail(run).contains("pid 9"));

        let theirs = Foreign::Interface(Link {
            name: "wt0".into(),
            kind: LinkKind::Wireguard,
            bridged: false,
            carrier: true,
            addrs: vec!["100.72.0.5/16".into()],
        });
        assert_eq!(theirs.name(), "wt0");
        assert!(theirs.detail(run).contains("not controlcenter's"));
        assert_eq!(theirs.stop_argv(false), ["wg-quick", "down", "wt0"]);
    }
}
