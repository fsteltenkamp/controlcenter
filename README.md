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
| 2 | **VPN** | NetBird, WireGuard, OpenVPN and Tailscale side by side — clients on the left, their profiles in the middle, status on the right |
| 3 | **Tunnels** | SSH forwards: local (`-L`), remote (`-R`) and dynamic/SOCKS (`-D`), with live ↑/↓ throughput and optional auto-reconnect |
| 4 | **SSH** | interactive logins, each in a terminal window of its own so the TUI keeps running |
| 5 | **RDP** | `xfreerdp3` sessions, running in the background with a log view |

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
| `c` | clear — the log, or the entries that have finished |
| `x` | **disconnect everything** — the panic button, from any tab |
| `t` | cycle the colour theme |
| `?` | help — `k` for the keys |
| `q` | close what is focused; quits the application once nothing is left to close |

Moving about:

| Key | Action |
| --- | --- |
| `1`–`5` | jump to a tab |
| `Tab` / `Shift+Tab` | next / previous tab |
| `↑` `↓` | move the selection |
| `←` `→` | switch pane (VPN) · change the field under the cursor (forms) |
| `Esc` | cancel a form, close a popup |
| `y` | confirm in a prompt |
| `Ctrl+O` | open the file picker on a path field |

There is no vim navigation: `h` `j` `k` `l` are action keys here, so the arrows do the
moving.

### What each key acts on

| | VPN | Tunnels | SSH | RDP |
| --- | --- | --- | --- | --- |
| `Enter` | connect the profile | start the tunnel | open a session | connect |
| `a` `e` `d` | profile | tunnel | host | connection |
| `r` | refresh this client now | restart it | open another session | reconnect |
| `p` | forget an OpenVPN password | — keys only | forget the stored password | — never stored |
| `l` | the OpenVPN session log | what ssh has printed | — it is in the window | the xfreerdp log |
| `c` | the client's error, exited sessions | failed tunnels | the last session's outcome | finished sessions |

NetBird profiles are netbird's own, so `a` `e` `d` say so instead of editing them.
Reconnecting an RDP session asks for the password again, because nothing keeps a copy.

On a **group header** every one of these acts on all the members at once, as a single
plan. On the **Dashboard** `r` refreshes every VPN client and `c` clears every finished
entry everywhere; the keys that need something selected say which tab owns it.

### The panic button

`x` works from any tab. It lists what is up and asks, then takes down every tunnel, RDP
session, SSH window and VPN profile, abandons any activation in flight and stops
auto-reconnect — nothing comes back on its own. Taking a VPN down needs root, so expect a
polkit prompt for each one.

### Popups

`q` closes whatever is focused — a log, the help, a prompt — and only quits the
application when nothing is left to close. `Esc` does the same and also cancels a form.
In a form or a password prompt `q` is just a letter; use `Esc` there.

## Requirements

`ssh` on PATH is the only hard requirement. Tunnels run ssh with `BatchMode=yes` (no
interactive prompts), so use key- or agent-based authentication for the hosts you tunnel
through; SSH-tab sessions are interactive and may prompt normally.

Optional, each detected on startup and only greying out its own feature when missing:

- `xfreerdp3` (freerdp3) — the RDP tab
- `sshpass` — SSH hosts with a stored password
- `netbird`, `wireguard-tools` (`wg`, `wg-quick`), `openvpn`, `tailscale` — the VPN tab

WireGuard, OpenVPN and Tailscale need root to change the network. controlcenter never
handles a password itself: it runs `pkexec` so your polkit agent puts the prompt in front
of you, and falls back to `sudo -n` when there is no agent to answer — a bare tty, or an
ssh session. If neither works it says so instead of hanging. Status polling never
escalates.

## Configuration

Everything is edited in the TUI and stored as TOML under `~/.config/controlcenter/`, so
you can also edit it by hand. `controlcenter --config-paths` prints exactly where each
file lives.

## More

- [docs/connections.md](docs/connections.md) — groups, dependencies, conflicts, and how
  SSH sessions and passwords work
- [docs/vpn.md](docs/vpn.md) — how each of the four VPN clients is driven, and what
  importing an OpenVPN profile does
- [docs/configuration.md](docs/configuration.md) — every config file, field by field
- [AGENTS.md](AGENTS.md) — instructions for AI agents working on this repository
