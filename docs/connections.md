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
and Pangolin's accounts belong to those clients, and a `◆` row is not a stored profile at
all, so none of those move; the
client list on the left is fixed, because that order is the order a plan brings clients up
in.

## Dependencies

Tunnels, SSH hosts and RDP connections each take two optional requirements, picked with
`←` `→` in their form — or with `Ctrl+O`, which opens the whole list as a popup where
groups are folders and typing searches every one of them at once:

- **`requires_vpn`** — a VPN that must be up first, written as `provider:profile`
- **`depends_on`** — a tunnel that must be up. Tunnels can name another tunnel here, which
  is how you stack them: point the upper tunnel's ssh host at `127.0.0.1` with
  `-p <lower tunnel's local port>` (or a `-J` jump host) and it runs through the one below

A tunnel has a third link: the host it goes **through**, which can be an entry on the SSH
tab rather than something `~/.ssh/config` has to know about.

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

### Tunnels through a configured host

A tunnel's **SSH host** field takes two kinds of value:

- a destination ssh works out for itself — an `ssh_config` alias, `user@host`, an
  `ssh://` URI. This is what it has always taken
- the name of an entry on the **SSH tab**, stored as `ssh:<name>`. Press `Ctrl+O` on the
  field to pick one

Pick an entry and the tunnel runs with everything that entry says: its host and port, its
username, its key (`-i`, with `IdentitiesOnly`), its `skip_host_key_check`, its extra args
and — where one is stored — its password. Nothing about the connection has to be repeated
in `extra_args`, and nothing has to exist in `~/.ssh/config`. The tunnel's own extra args
are still passed, after the host's.

The entry's **own** requirements become the tunnel's: if the host needs a VPN or sits
behind another tunnel, that is now part of this tunnel's chain and is brought up first. A
host that needs a tunnel which rides that same host is a cycle, and is refused when you
save it rather than when you try to start it.

```
tunnels.toml                 ssh.toml
name      = "prod-cache"     name       = "bast"
ssh_host  = "ssh:bast"       host       = "bastion.corp"
forward   = "local"          port       = 2222
local_port = 6379            username   = "fl"
remote_host = "cache.int"    key_path   = "~/.ssh/id_b"
remote_port = 6379           extra_args = "-A"
extra_args = "-o TCPKeepAlive=yes"

what runs:
ssh -N -o BatchMode=yes … -L 127.0.0.1:<port>:cache.int:6379 \
    -p 2222 -i ~/.ssh/id_b -o IdentitiesOnly=yes -A \
    -o TCPKeepAlive=yes fl@bastion.corp
```

Tunnels normally run with `BatchMode=yes`, which switches off every prompt — including the
password one. A tunnel riding a host that has a **stored password** therefore runs with
`BatchMode=no` and `NumberOfPasswordPrompts=1` instead, and the password reaches ssh the
same way an interactive session's does: through `sshpass -e`, or through `SSH_ASKPASS`
where sshpass is not installed. It is never an argument. One wrong attempt and ssh gives
up rather than sitting on a prompt nobody can answer.

The SSH tab shows which tunnels run through a host, and deleting a host says which tunnels
it has just left pointing at nothing. Renaming one follows through to them.

### Requiring a VPN

`requires_vpn` is written as `provider:profile`, where either half may be `*`:

| written | means |
| --- | --- |
| `""` | nothing |
| `"*"` | any VPN, as long as one is connected |
| `"netbird:*"` | any NetBird profile |
| `"wireguard:home"` | that profile of that client |
| `"pangolin:you@example.net"` | that pangolin account |
| `"work"` | NetBird's `work` — how it was written before there was more than one client |

Unqualified names still mean NetBird, so config files written before the other clients
existed keep working untouched; the form rewrites them to the namespaced form when you
next save the entry.

A plan holds **one requirement per client**, so a chain may legitimately need WireGuard
*and* Tailscale and both get a step, run in a fixed order (netbird, wireguard, openvpn,
tailscale, pangolin). Within one client a named profile beats `*`, and two different profiles of the
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

Only NetBird, Tailscale and Pangolin can hold one profile at a time, so only they
conflict. WireGuard interfaces and OpenVPN sessions coexist, and several can be up at
once.

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
  xfce4-terminal, terminator, tilix, urxvt, st, xterm that is on PATH. On Windows it is
  `cmd.exe`, given a console of its own — which *is* a new window there, and needs
  nothing installed
- `inline` hands *this* terminal to ssh until the session ends — which is also what
  happens automatically when no terminal emulator can be found, over a plain TTY, say.
  While an inline session is open the TUI is not drawing, so status and auto-reconnect
  pause until you exit; traffic through existing tunnels keeps flowing
- anything else is a command line of your own, e.g. `kitty --title ssh` or
  `alacritty -e sh -c {cmd}`, and on Windows `wt.exe cmd /C {cmd}` for Windows Terminal.
  A `{cmd}` placeholder is replaced by the shell command; without one, `sh -c <command>`
  is appended (on Windows the command line itself is)

The window runs ssh through `sh` — through `cmd` on Windows — and on a non-zero exit it
waits before closing so the error stays readable. Its output belongs to that window, so
`l` on the SSH tab shows what controlcenter knows instead: the command line it ran, where
the session opened, and how it ended — see [logs.md](logs.md).

## Transferring files

`f` on an SSH host opens a two-pane browser — this machine on the left, the host on the
right — over a single `sftp` session to that host. It is opened through the same plan a
session is: whatever the host requires is brought up first, and a transfer to a host
behind a VPN and a tunnel works for the same reason a login to it does.

The keys are the file picker's keys:

| | |
| --- | --- |
| `Tab` | the other pane |
| `↑` `↓` `PgUp` `PgDn` | select |
| typing | filter the listing, or type a path outright |
| `→` | open the folder under the cursor |
| `←` | up one level |
| `Enter` | a folder: walk into it. Anything else: **copy it to the other pane's directory** |
| `Esc` | close the browser — `q` is a letter here, because the panes take text |

The pane with the focus is where a copy comes *from*, and the other pane's directory is
where it lands, so the direction is always visible and there is no separate upload and
download to confuse. A file that is already there at the far end is asked about before it
is overwritten. One copy runs at a time; closing the browser during one cuts it off, and
says so in the log.

The session is `sftp` run with exactly what the host entry says — port, user, key,
password, `skip_host_key_check`, extra args — which is what a login to the same host runs
with. Nothing needs to be in `~/.ssh/config`, and there is no `scp` command line to get
right.

Two things follow from there being no terminal to ask at:

- a host with **no stored password** runs with `BatchMode=yes`, so a key, an agent or a
  stored password is what makes a transfer work. Anything that would have been a prompt —
  a password, an unknown host key — becomes an error in the log rather than a session
  that hangs
- a session that never answers is given up on after twenty seconds

A download shows how far it has got, because the file is on this machine and growing. An
upload shows its size and how long it has been running: `sftp` on a pipe does not report
the far end's progress, and a number that was made up here would be worth less than the
clock. Every command and every outcome goes into the host's log (`l`) and its report
(`s`) — see [logs.md](logs.md).

A symlink is listed with `→`. `Enter` copies what it points at; `→` tries to walk into it,
and says so if it is not a directory.

## Passwords

Storing an SSH password is optional and asks for confirmation first, because it is written
to `ssh.toml` in the clear (the file is mode 0600, or on Windows an ACL that leaves you as
its only reader). `p` on the SSH tab removes a stored password. A key file or an agent is
the better option.

It never shows up in the process list, whichever route it takes:

- where `sshpass` is installed, it is handed to ssh through `sshpass -e`, i.e. via the
  environment
- where it is not — every Windows machine, since sshpass is built on pseudo-terminals and
  cannot exist there — controlcenter answers ssh's own prompt instead. ssh runs the
  program named by `SSH_ASKPASS` when it wants a password, and the program named is
  controlcenter, re-run as a helper; it reads the password out of the same environment
  variable and prints it. If ssh asks anyway, type it: nothing is broken, the helper just
  did not get a turn

RDP passwords are never stored. `Enter` asks for one (masked) and never puts it on a
command line. With freerdp it goes in on stdin (`/from-stdin`); with mstsc, which reads
neither stdin nor a password argument, it is sealed with DPAPI to your Windows account —
the same thing Remote Desktop does with a saved connection — and written into the `.rdp`
file, which is deleted once mstsc has read it. Either way `r` — reconnect — asks again,
because nothing keeps a copy.

OpenVPN credentials can be stored in `vpn.toml` (0600) and are written to the child's
stdin, or on Windows to a file that is deleted once openvpn has read it — see
[vpn.md](vpn.md#openvpn). `p` on the VPN tab forgets the selected profile's password.

## Throughput

Throughput is measured by relaying `-L`/`-D` forwards through controlcenter itself: ssh
binds an internal loopback port and controlcenter listens on your configured port,
counting bytes in both directions. Remote (`-R`) forwards have no local socket, so they
show status only.

## Ports below 1024

That relay is also what decides where the permission for a privileged port has to go. The
socket on your configured port is opened by controlcenter, in its own process; ssh only
ever listens on the loopback port behind it. So a tunnel on 80 or 443 needs one capability
on the controlcenter binary, and nothing at all on ssh:

```sh
sudo setcap cap_net_bind_service=+ep /path/to/controlcenter
getcap /path/to/controlcenter          # says whether it is still there
```

`cap_net_bind_service` grants low ports and nothing else, and a file capability is not
inherited, so ssh and every other process controlcenter starts stay exactly as
unprivileged as they were. Running the whole TUI under `sudo` would do the opposite —
every ssh, every RDP client and every config file it writes would be root's — so that is
not the answer here.

The capability lives on the file itself, so a rebuild, an upgrade or a reinstall replaces
the file and drops it, and it has to be granted again.

Without it the tunnel does not start. Controlcenter says so in a popup that carries the
exact command for the binary you are running, and puts the same lines in that tunnel's
log, so a report exported afterwards still explains the failure. Nothing retries — a
refused port is not a race, and waiting will not change the answer.

If you would rather not single out one binary,
`sysctl net.ipv4.ip_unprivileged_port_start=80` lowers the reserved range for everything
on the machine: one file in `/etc/sysctl.d/`, nothing to re-apply after an upgrade, at the
cost of letting any program you run bind those ports.

A remote (`-R`) forward binds on the server instead, so a low port there is sshd's
business — `GatewayPorts`, and what the remote user is allowed — and not something setcap
here can help with.

On Windows no port is reserved by number. A bind refused there means the port falls inside
a range something else has already excluded: Hyper-V, WSL and WinNAT reserve blocks at
boot, and a reserved port is refused even when nothing is listening on it.

```powershell
netsh int ipv4 show excludedportrange protocol=tcp
```
