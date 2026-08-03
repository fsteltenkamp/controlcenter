# ControlCenter

TUI control center: SSH tunnels, NetBird profiles, and RDP sessions in one place.

Built with [ratatui](https://ratatui.rs). Configure tunnels and RDP connections once,
then start/stop them individually or as whole groups, switch NetBird profiles, and watch
everything on the dashboard.

## Tabs

1. **Dashboard** — live status of everything: VPN state (profile, IP, FQDN, peers),
   tunnel counts and traffic, running RDP sessions, a combined table of active tunnels
   and RDP sessions, and the aggregate throughput sparkline
2. **VPN** — currently NetBird: list profiles, switch profile (select + `netbird up`),
   connect/disconnect; more VPN technologies may be added later
3. **Tunnels** — configure and toggle SSH forwards
4. **RDP** — manage `xfreerdp3` connections; sessions run in the background with a log view

## Features

- **Local (-L), remote (-R), and dynamic/SOCKS (-D) forwards**
- **Groups** — organize tunnels into named groups and start/stop a whole group with one key
- **Monitoring** — per-tunnel status (connecting/up/failed), uptime, active/total
  connections, live ↑/↓ throughput and totals
- **Auto-reconnect** (optional, per tunnel) with backoff
- **VPN (NetBird)** — profile list/switch and up/down run in the background; the UI never blocks
- **RDP** — password is prompted per connect (masked) and passed to xfreerdp via stdin
  (`/from-stdin`), never stored and never on the command line; sessions keep running when
  you quit the TUI
- **Themes** — dark, dracula, nord, gruvbox (`t` to cycle)

Throughput is measured by relaying `-L`/`-D` forwards through controlcenter itself: ssh binds
an internal loopback port and controlcenter listens on your configured port, counting bytes in
both directions. Remote (`-R`) forwards have no local socket, so they show status only.

## Install / Run

```sh
cargo build --release
./target/release/controlcenter
```

Requires `ssh` on PATH. ssh is run with `BatchMode=yes` (no interactive prompts), so use
key- or agent-based authentication for the hosts you tunnel through.
Optional: `netbird` for the VPN tab, `xfreerdp3` (freerdp3) for the RDP tab.

## Keys

| Key | Action |
| --- | --- |
| `1`-`4` / `Tab` | switch tab (Dashboard, VPN, Tunnels, RDP) |
| `j` `k` / arrows | move selection |
| `t` | cycle color theme |
| `?` | help |
| `q` | quit (stops tunnels; RDP windows stay open) |

**Tunnels**

| Key | Action |
| --- | --- |
| `Enter` / `Space` | start/stop the selected tunnel — or every tunnel in the selected group |
| `a` / `e` / `d` | add / edit / delete (group pre-filled from selection on add) |
| `r` | restart the selected active tunnel |
| `x` | stop all tunnels |

**VPN (NetBird)**

| Key | Action |
| --- | --- |
| `Enter` | switch to the selected profile and connect (`profile select` + `up`) |
| `u` / `d` | `netbird up` / `netbird down` |
| `r` | refresh status now (auto-refreshes every 5s) |

**RDP**

| Key | Action |
| --- | --- |
| `Enter` | connect (masked password prompt) / disconnect running session |
| `a` / `e` / `d` | add / edit / delete connection |
| `l` | view the session's xfreerdp log |
| `c` | clear a finished session entry |
| `x` | close all sessions |

## Configuration

Everything is edited in the TUI and stored as TOML under `~/.config/controlcenter/`
(see `controlcenter --config-paths`), so you can also edit it by hand:

```toml
# tunnels.toml
[[tunnels]]
name = "prod-db"
group = "prod"
ssh_host = "bastion.example.com"   # anything ssh accepts: alias, user@host
forward = "local"                  # local | remote | dynamic
local_port = 5432                  # listen port (-L/-D) or local dest port (-R)
remote_host = "db.internal"        # destination host (-L) / local dest host (-R)
remote_port = 5432                 # destination port (-L) / listen port on ssh host (-R)
extra_args = "-J jumphost"         # optional, passed to ssh verbatim
auto_reconnect = true
```

```toml
# rdp.toml
[[connections]]
name = "office-dc"
host = "192.168.1.10"
port = 3389
domain = "CORP"                    # optional
username = "admin"
extra_args = "/f"                  # optional, passed to xfreerdp3 verbatim
```

RDP sessions launch as `xfreerdp3 /v:host:port /u:user [/d:domain] /dynamic-resolution
/cert:ignore /from-stdin`, matching the classic rdp-wrap script.

The color theme is persisted in `~/.config/controlcenter/config.toml`.
