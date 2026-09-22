# ControlCenter

TUI control center: SSH tunnels, SSH logins, VPN clients and RDP sessions in one place.
Built with [ratatui](https://ratatui.rs).

Configure tunnels, hosts, VPN profiles and RDP connections once, then bring them up and
down from one screen. A connection declares what it needs — a VPN profile, a tunnel, or a
tunnel stacked on another tunnel — and activating it brings that whole chain up first.

```sh
cargo build --release
./target/release/controlcenter
```

## Tabs

| | | |
| --- | --- | --- |
| 1 | **Dashboard** | everything that is up: VPN state, tunnel counts and traffic, running RDP sessions, and the aggregate throughput sparkline |
| 2 | **VPN** | NetBird, WireGuard, OpenVPN, Tailscale and Pangolin side by side — clients on the left, their profiles in the middle, status on the right, and anything already up that controlcenter did not start |
| 3 | **Tunnels** | SSH forwards: local (`-L`), remote (`-R`) and dynamic/SOCKS (`-D`), with live ↑/↓ throughput and optional auto-reconnect |
| 4 | **SSH** | interactive logins, each in a terminal window of its own so the TUI keeps running |
| 5 | **RDP** | remote desktop sessions — `mstsc` on Windows, `xfreerdp3` elsewhere — running in the background with a log view |

Entries on any of these tabs can share a **group** name to stack under one header and be
acted on together, and can **require** a VPN profile or a tunnel — see
[docs/connections.md](docs/connections.md).

## Keys

Every key means the same thing on every tab. Only what it acts on changes.

| Key | Action |
| --- | --- |
| `Enter` / `Space` | connect — or disconnect what is already up |
| `a` | add |
| `e` | edit |
| `d` | delete |
| `r` | reconnect / reload |
| `p` | remove the stored password |
| `l` | log |
| `s` | save a report to a file |
| `c` | clear — the log, or the entries that have finished |
| `Ctrl+↑` `Ctrl+↓` | move what is selected up or down in the list — the new order is written to the config |
| `x` | **disconnect everything** — the panic button, from any tab |
| `t` | cycle the colour theme |
| `?` | help — `k` for the keys |
| `q` | close what is focused; quits the application once nothing is left to close — asking first if that would leave an OpenVPN session running as root |

Moving about:

| Key | Action |
| --- | --- |
| `1`–`5` | jump to a tab |
| `Tab` / `Shift+Tab` | next / previous tab |
| `↑` `↓` | move the selection · scroll a log |
| `PgUp` `PgDn` | move the selection ten rows · scroll a log by a screen |
| `←` `→` | switch pane (VPN) · change the field under the cursor (forms) |
| `Esc` | cancel a form, close a popup |
| `y` | confirm in a prompt |
| `Ctrl+O` | open the file picker on a path field |

There is no vim navigation: `h` `j` `k` `l` are action keys here, so the arrows do the
moving.

### What each key acts on

| | VPN | Tunnels | SSH | RDP |
| --- | --- | --- | --- | --- |
| `Enter` | connect the profile, or stop a `◆` | start the tunnel | open a session | connect |
| `a` `e` `d` | profile | tunnel | host | connection |
| `r` | refresh this client now | restart it | open another session | reconnect |
| `p` | forget an OpenVPN password | — keys only | forget the stored password | — never stored |
| `l` | the profile's log | the tunnel's log | the host's log | the connection's log |
| `s` | a report about it | a report about it | a report about it | a report about it |
| `c` | the client's error, exited sessions | failed tunnels | the last session's outcome | finished sessions |
| `Ctrl+↑` `Ctrl+↓` | the profile, in `vpn.toml` | the tunnel or its group | the host or its group | the connection or its group |

An entry moves inside its own group and a group header moves the whole group, so the
list keeps the shape it is drawn in; `Ctrl+↑` `Ctrl+↓` on a group's first or last entry
says so rather than moving it into the neighbouring group.

NetBird profiles and Pangolin accounts belong to those clients, so `a` `e` `d` `Ctrl+↑`
`Ctrl+↓` say so instead of editing them. A NetBird **user-device** profile is logged in
through a browser rather than with a setup key: connecting one shows the URL and code
netbird is waiting for — `o` opens the browser, `c` gives up, `Esc` hides the popup while
the login carries on — and says so plainly when the login is what is missing. The SSO
session expires, so it asks again; see [docs/vpn.md](docs/vpn.md).
Reconnecting an RDP session asks for the password again, because nothing keeps a copy.

### Connections that are not ours

The VPN tab lists what is up on the **machine**, not only what this program started. A
session can outlive controlcenter — a crash, a `kill -9`, an exit while it was connected —
and what is left is a root process, or the tun device it abandoned still holding the
address, that nothing here is holding any more. The next connection to the same server
then fights it for the slot and drops every few minutes.

Those show up as `◆` rows under the client they belong to, saying what they are and how
long they have been there. `Enter` takes one away — again to kill a process that ignored
`SIGTERM` — and `x` takes them down with everything else. `controlcenter --vpn-scan`
prints the same sweep from a shell. See [docs/vpn.md](docs/vpn.md).

On a **group header** every one of these acts on all the members at once, as a single
plan. On the **Dashboard** `r` refreshes every VPN client, `c` clears every finished entry
everywhere, and `l` and `s` act on the whole program rather than on one connection; the
keys that need something selected say which tab owns it.

### Logs and reports

`l` opens the same log pane on every tab: what controlcenter did about the thing under the
cursor — the plan, the command line, the exit code — merged with what the process it
started printed, each line stamped with the time.

`s` writes a **report** to `~/.config/controlcenter/reports/` and says where it went. The
report is more than the pane: the connection in full, every link of the chain it needs, the
command line each one runs, everything controlcenter did about them, and the pane's whole
log — and nothing it does not depend on. The chain's own logs go in a `.log` file beside
it. On the Dashboard it covers the whole program instead. It is meant to be read away from
here: sent to someone, or handed to an AI, to work out what went wrong. Passwords never
appear; see [docs/logs.md](docs/logs.md).

### The panic button

`x` works from any tab. It lists what is up and asks, then takes down every tunnel, RDP
session, SSH window and VPN profile — including the ones controlcenter did not start —
abandons any activation in flight and stops auto-reconnect, so nothing comes back on its
own. Taking a VPN down needs root: silent with a sudo ticket or an elevated controlcenter,
otherwise a polkit prompt for each one.

### Popups

`q` closes whatever is focused — a log, the help, a prompt — and only quits the
application when nothing is left to close. `Esc` does the same and also cancels a form.
In a form or a password prompt `q` is just a letter; use `Esc` there.

## Requirements

`ssh` on PATH is the only hard requirement. On Windows that is the OpenSSH client, which
ships with Windows 10 and 11 but is not always turned on:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

Tunnels run ssh with `BatchMode=yes` (no interactive prompts), so use key- or agent-based
authentication for the hosts you tunnel through; SSH-tab sessions are interactive and may
prompt normally.

Optional, each detected on startup and only greying out its own feature when missing:

| | Linux | Windows |
| --- | --- | --- |
| RDP tab | `xfreerdp3` (freerdp3) | `mstsc`, which is part of Windows |
| SSH passwords | `sshpass` | nothing to install — see below |
| VPN tab | `netbird`, `wireguard-tools` (`wg`, `wg-quick`), `openvpn`, `tailscale`, `pangolin` | the NetBird, WireGuard, OpenVPN, Tailscale and Pangolin installers; controlcenter looks under Program Files as well as on PATH |

A stored SSH password is never an argument. Where `sshpass` is installed it is used;
where it is not — every Windows machine — controlcenter answers ssh's own prompt instead,
through `SSH_ASKPASS`. Either way the password travels in the environment.

### Root, and administrator

WireGuard and OpenVPN need to change the network, and so do Tailscale on Linux and
Pangolin. Pangolin is the one that escalates itself — its own CLI re-runs under `sudo` —
so all it needs from controlcenter is that the ticket below is already there.

On Linux controlcenter never handles a password itself: it runs `pkexec`
so your polkit agent puts the prompt in front of you, and falls back to `sudo -n` when
there is no agent to answer — a bare tty, or an ssh session. If neither works it says so
instead of hanging. Status polling never escalates.

A polkit dialog is the wrong thing to stand between you and a connection you are trying
to take *down*: dismiss it, or have no agent to show it, and a root openvpn is left
running that nothing on the machine can reach. So before the TUI starts — while the
terminal is still yours — controlcenter runs `sudo -v` once, and every stop after that is
silent. Set `vpn.sudo = "never"` in `config.toml`, or pass `--sudo never`, to skip it.

On Windows there is nothing to take in advance: UAC decides when a process starts and
cannot raise one afterwards. **Start controlcenter as administrator** if you want to use
WireGuard or OpenVPN — right-click it and choose *Run as administrator*, or start it from
an elevated terminal. Started normally it still runs everything else, and says on the VPN
tab that it cannot start or stop those two. NetBird and Tailscale on Windows take their
commands from the signed-in user and need nothing; Pangolin asks for elevation itself.

## Configuration

Everything is edited in the TUI and stored as TOML — under `~/.config/controlcenter/` on
Linux and `%APPDATA%\controlcenter\controlcenter\config\` on Windows — so you can also
edit it by hand. `controlcenter --config-paths` prints exactly where each file lives.

## More

- [docs/connections.md](docs/connections.md) — groups, dependencies, conflicts, and how
  SSH sessions and passwords work
- [docs/vpn.md](docs/vpn.md) — how each of the four VPN clients is driven, and what
  importing an OpenVPN profile does
- [docs/logs.md](docs/logs.md) — the log pane, and what an exported report contains
- [docs/configuration.md](docs/configuration.md) — every config file, field by field
- [AGENTS.md](AGENTS.md) — instructions for AI agents working on this repository
