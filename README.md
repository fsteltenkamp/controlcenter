# ControlCenter

TUI control center: SSH tunnels, SSH logins, NetBird profiles, and RDP sessions in one place.

Built with [ratatui](https://ratatui.rs). Configure tunnels, hosts, and RDP connections once,
then start/stop them individually or as whole groups, switch NetBird profiles, and watch
everything on the dashboard. Connections declare what they need — a VPN profile, a tunnel,
or a tunnel stacked on another tunnel — and activating one brings that whole chain up first.

## Tabs

1. **Dashboard** — live status of everything: VPN state (profile, IP, FQDN, peers),
   tunnel counts and traffic, running RDP sessions, a combined table of active tunnels
   and RDP sessions, and the aggregate throughput sparkline
2. **VPN** — currently NetBird: list profiles, switch profile (select + `netbird up`),
   connect/disconnect; more VPN technologies may be added later
3. **Tunnels** — configure and toggle SSH forwards
4. **SSH** — interactive logins; the TUI steps aside and hands the terminal to `ssh`
5. **RDP** — manage `xfreerdp3` connections; sessions run in the background with a log view

## Features

- **Local (-L), remote (-R), and dynamic/SOCKS (-D) forwards**
- **Groups** — organize tunnels into named groups and start/stop a whole group with one key
- **Monitoring** — per-tunnel status (connecting/up/failed), uptime, active/total
  connections, live ↑/↓ throughput and totals
- **Auto-reconnect** (optional, per tunnel) with backoff
- **Dependencies** — every connection (tunnel, SSH host, RDP) can require a VPN profile
  and a tunnel, and tunnels stack on other tunnels; activating one brings the whole chain
  up in order and only then opens the session
- **Conflict handling** — the same prompt everywhere: another tunnel on the port, another
  VPN profile active, another RDP session on the same host — confirm and it is evicted
- **SSH logins** — key file, port, username, optional cleartext password (via `sshpass`),
  and a per-host "skip host key verification" switch for tunnelled localhost targets
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

Requires `ssh` on PATH. Tunnels run ssh with `BatchMode=yes` (no interactive prompts), so use
key- or agent-based authentication for the hosts you tunnel through. SSH tab sessions are
interactive and may prompt normally.
Optional: `netbird` for the VPN tab, `xfreerdp3` (freerdp3) for the RDP tab,
`sshpass` for SSH hosts with a stored password.

## Keys

| Key | Action |
| --- | --- |
| `1`-`5` / `Tab` | switch tab (Dashboard, VPN, Tunnels, SSH, RDP) |
| `j` `k` / arrows | move selection |
| `t` | cycle color theme |
| `?` | help |
| `q` | quit (stops tunnels; RDP windows stay open) |

**Tunnels**

| Key | Action |
| --- | --- |
| `Enter` / `Space` | start/stop the selected tunnel (with its chain) — or the whole group |
| `a` / `e` / `d` | add / edit / delete (group pre-filled from selection on add) |
| `r` | restart the selected active tunnel |
| `x` | stop all tunnels |
| `y` | in a conflict prompt: evict what is in the way and continue |

**VPN (NetBird)**

| Key | Action |
| --- | --- |
| `Enter` | switch to the selected profile and connect (`profile select` + `up`) |
| | the panel lists what requires the selected profile |
| `u` / `d` | `netbird up` / `netbird down` |
| `r` | refresh status now (auto-refreshes every 5s) |

**SSH**

| Key | Action |
| --- | --- |
| `Enter` | open a session in this terminal (starts the required tunnel first) |
| `a` / `e` / `d` | add / edit / delete host |
| `p` | drop the stored cleartext password for the selected host |

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
requires_vpn = "work"              # optional: profile name, or "*" for any
depends_on = ""                    # optional: another tunnel to stack on

# Stacking: this one runs through prod-db's local end.
[[tunnels]]
name = "prod-app"
ssh_host = "127.0.0.1"
extra_args = "-p 5432"             # the port prod-db listens on
forward = "local"
local_port = 8080
remote_host = "app.internal"
remote_port = 80
depends_on = "prod-db"
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
requires_vpn = "*"                 # optional: profile name, or "*" for any
depends_on = "prod-db"             # optional, tunnel to bring up first
```

```toml
# ssh.toml — written 0600 because it may hold a password
[[hosts]]
name = "prod-app"
host = "127.0.0.1"                 # e.g. the local end of a tunnel
port = 2222
username = "deploy"                # optional, empty = let ssh decide
key_path = "~/.ssh/id_ed25519"     # optional, passed as -i
password = ""                      # optional, CLEARTEXT — see below
skip_host_key_check = true         # StrictHostKeyChecking=no + no known_hosts
extra_args = "-A"                  # optional, passed to ssh verbatim
requires_vpn = "work"              # optional: profile name, or "*" for any
depends_on = "prod-db"             # optional, tunnel to bring up first
```

RDP sessions launch as `xfreerdp3 /v:host:port /u:user [/d:domain] /dynamic-resolution
/cert:ignore /from-stdin`, matching the classic rdp-wrap script.

The color theme is persisted in `~/.config/controlcenter/config.toml`.

## Dependencies between connections

Tunnels, SSH hosts and RDP connections each take two optional requirements, picked with
◂ ▸ in their form:

- **`requires_vpn`** — a NetBird profile that must be active, or *any profile* (`*`) to
  just require the VPN to be connected.
- **`depends_on`** — a tunnel that must be up. Tunnels can name another tunnel here, which
  is how you stack them: point the upper tunnel's ssh host at `127.0.0.1` with `-p <lower
  tunnel's local port>` (or a `-J` jump host) and it runs through the one below.

Pressing Enter builds a plan out of that chain and runs it in order: the VPN first, then
the tunnels bottom-up, then the connection itself. Each step is waited for before the next
one starts (30s for a tunnel, 2 min for the VPN, since `netbird up` may sit through a
login), and the status bar shows how far along it is. A step that fails or times out stops
the plan and says why.

A VPN requirement found anywhere in the chain is hoisted to the front, so a tunnel three
levels down asking for a profile still gets it first. Two different profiles in one chain
is a contradiction and is refused before anything starts, as is a dependency cycle.

Starting a whole group builds one plan for all of its members, so a tunnel that several of
them share is started once.

### Conflicts

A step that cannot coexist with something already running prompts before touching it, and
accepting evicts what is in the way:

| Step | Conflicts with | Accepting |
| --- | --- | --- |
| tunnel | another tunnel on the same binding — the same local port for `-L`/`-D`, the same port on the same ssh host for `-R` | disconnects it |
| VPN profile | a different profile being active | switches, disconnecting whatever required the old one |
| RDP | another running session to the same host:port | disconnects it |

Declining cancels the plan and leaves everything as it was. Two members of one group
fighting over a port is a broken config rather than a question, so the later one is skipped
with a message instead of a prompt.

Renaming a tunnel updates everything that depends on it; deleting one leaves the dependency
visible and marked *missing* rather than silently unlinking it. Auto-reconnect holds off
while a tunnel's VPN or parent tunnel is down instead of retrying into a dead chain.

## SSH sessions and passwords

SSH sessions are interactive and run in the foreground: controlcenter leaves the alternate
screen, hands the terminal to `ssh`, and comes back when the session ends. While a session
is open the TUI is not drawing, so tunnel status and auto-reconnect pause until you exit
(traffic through existing tunnels keeps flowing).

Storing a password is optional and asks for confirmation first, because it is written to
`ssh.toml` in the clear (the file is mode 0600). It is handed to ssh through
`sshpass -e`, i.e. via the environment, so it never shows up in the process list. `p` on the
SSH tab removes a stored password. A key file or an agent is the better option.
