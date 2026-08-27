# Groups, dependencies and conflicts

Back to the [README](../README.md).

## Groups

Give entries in `tunnels.toml`, `ssh.toml` or `rdp.toml` the same `group` name and they
stack under one header in their tab, showing how many members are up. Every key that acts
on a selection acts on all the members when the cursor is on the header, and builds **one
plan** for the lot — a VPN or tunnel several of them share is brought up once, not once
per member.

| Tab | `Enter` on a group header |
| --- | --- |
| Tunnels | starts every inactive member; stops them all when everything is up |
| SSH | opens a session per member (windowed: all at once; inline: one after the other) |
| RDP | asks each idle member for its password in turn, then connects them together |

VPN profiles have no groups: one profile per client is active anyway.

## Order

`Ctrl+↑` and `Ctrl+↓` move what is under the cursor, and the new order is written straight
to the config file — the order of a list *is* the order of its file. (`PgUp` and `PgDn`
stay navigation: they move the selection ten rows.)

- on an entry, it moves within its own group. Ungrouped entries are a block of their own
  at the top of the tab and move within that
- on a group header, the whole group moves past the next one, members and all
- at the top or bottom of a group, nothing happens and the status bar says so. Moving an
  entry between groups is a change of `group`, so it is done in the form with `e`

On the VPN tab the same keys move the selected profile in `vpn.toml`. NetBird's profiles
are netbird's own and a `◆` row is not a stored profile at all, so neither one moves; the
client list on the left is fixed, because that order is the order a plan brings clients up
in.

## Dependencies

Tunnels, SSH hosts and RDP connections each take two optional requirements, picked with
`←` `→` in their form:

- **`requires_vpn`** — a VPN that must be up first, written as `provider:profile`
- **`depends_on`** — a tunnel that must be up. Tunnels can name another tunnel here, which
  is how you stack them: point the upper tunnel's ssh host at `127.0.0.1` with
  `-p <lower tunnel's local port>` (or a `-J` jump host) and it runs through the one below

`Enter` builds a plan out of that chain and runs it in order: the VPNs first, then the
tunnels bottom-up, then the connection itself. Each step is waited for before the next one
starts — 30s for a tunnel, 2 minutes for a VPN, since bringing one up may sit through a
login — and the status bar shows how far along it is. A step that fails or times out stops
the plan and says why.

Every VPN requirement found anywhere in the chain is hoisted to the front, so a tunnel
three levels down asking for a profile still gets it first. A dependency cycle is refused
before anything starts.

Renaming a tunnel updates everything that depends on it; deleting one leaves the
dependency visible and marked *missing* rather than silently unlinking it. Auto-reconnect
holds off while a tunnel's VPN or parent tunnel is down instead of retrying into a dead
chain.

### Requiring a VPN

`requires_vpn` is written as `provider:profile`, where either half may be `*`:

| written | means |
| --- | --- |
| `""` | nothing |
| `"*"` | any VPN, as long as one is connected |
| `"netbird:*"` | any NetBird profile |
| `"wireguard:home"` | that profile of that client |
| `"work"` | NetBird's `work` — how it was written before there was more than one client |

Unqualified names still mean NetBird, so config files written before the other clients
existed keep working untouched; the form rewrites them to the namespaced form when you
next save the entry.

A plan holds **one requirement per client**, so a chain may legitimately need WireGuard
*and* Tailscale and both get a step, run in a fixed order (netbird, wireguard, openvpn,
tailscale). Within one client a named profile beats `*`, and two different profiles of the
*same* client is a contradiction, refused before anything starts. Renaming a profile
follows it through everything that requires it.

## Conflicts

A step that cannot coexist with something already running prompts before touching it, and
accepting (`y` or Enter) evicts what is in the way and then goes on with the step. The
prompt is the same wherever the step came from — a tunnel, an SSH or RDP connection
pulling a VPN up behind it, or a profile switched by hand on the VPN tab:

| Step | Conflicts with | Accepting |
| --- | --- | --- |
| tunnel | another tunnel on the same binding — the same local port for `-L`/`-D`, the same port on the same ssh host for `-R` | disconnects it |
| VPN profile | a different profile of the *same* client being active | switches, disconnecting whatever required the old one |
| RDP | another running session to the same host:port | disconnects it |

Only NetBird and Tailscale can hold one profile at a time, so only they conflict.
WireGuard interfaces and OpenVPN sessions coexist, and several can be up at once.

A prompt only appears when something running would actually be cut. Switching to another
profile of the same client while nothing is riding on the old one is simply what you asked
for, so it happens without a question.

Declining cancels the plan and leaves everything as it was. Two members of one group
fighting over a port is a broken config rather than a question, so the later one is
skipped with a message instead of a prompt.

## SSH sessions

A session opens in a terminal window of its own, so the TUI keeps running: tunnel status,
auto-reconnect and the VPN polls carry on, and you can open a second session while the
first one is up. A host with windows open is marked `●` in the list, and the window is
tracked until it closes. `r` opens another one; the panic button (`x`) closes them all.

Which terminal is used is `ssh.terminal` in `config.toml`:

- `auto` (the default) takes `$TERMINAL` if it is installed, else the first of
  `xdg-terminal-exec`, ghostty, kitty, alacritty, foot, wezterm, konsole, gnome-terminal,
  xfce4-terminal, terminator, tilix, urxvt, st, xterm that is on PATH
- `inline` hands *this* terminal to ssh until the session ends — which is also what
  happens automatically when no terminal emulator can be found, over a plain TTY, say.
  While an inline session is open the TUI is not drawing, so status and auto-reconnect
  pause until you exit; traffic through existing tunnels keeps flowing
- anything else is a command line of your own, e.g. `kitty --title ssh` or
  `alacritty -e sh -c {cmd}`. A `{cmd}` placeholder is replaced by the shell command;
  without one, `sh -c <command>` is appended

The window runs ssh through `sh`, and on a non-zero exit it waits for Enter before closing
so the error stays readable. Its output belongs to that window, so `l` on the SSH tab shows
what controlcenter knows instead: the command line it ran, where the session opened, and
how it ended — see [logs.md](logs.md).

## Passwords

Storing an SSH password is optional and asks for confirmation first, because it is written
to `ssh.toml` in the clear (the file is mode 0600). It is handed to ssh through
`sshpass -e`, i.e. via the environment, so it never shows up in the process list. `p` on
the SSH tab removes a stored password. A key file or an agent is the better option.

RDP passwords are never stored: `Enter` asks for one (masked) and passes it to xfreerdp on
stdin (`/from-stdin`), never on the command line. That is why `r` — reconnect — asks again.

OpenVPN credentials can be stored in `vpn.toml` (0600) and are written to the child's
stdin; `p` on the VPN tab forgets the selected profile's password.

## Throughput

Throughput is measured by relaying `-L`/`-D` forwards through controlcenter itself: ssh
binds an internal loopback port and controlcenter listens on your configured port,
counting bytes in both directions. Remote (`-R`) forwards have no local socket, so they
show status only.
