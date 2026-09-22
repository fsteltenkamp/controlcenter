# Configuration files

Back to the [README](../README.md).

Everything is edited in the TUI and stored as TOML, so you can also edit it by hand.
`controlcenter --config-paths` prints exactly where each file lives:

| | |
| --- | --- |
| Linux | `~/.config/controlcenter/` |
| Windows | `%APPDATA%\controlcenter\controlcenter\config\` |

| file | holds | mode |
| --- | --- | --- |
| `config.toml` | the settings that are not connections | 0644 |
| `tunnels.toml` | SSH forwards | 0644 |
| `ssh.toml` | SSH hosts — may hold a password | 0600 |
| `rdp.toml` | RDP connections | 0644 |
| `vpn.toml` | WireGuard, OpenVPN and Tailscale profiles — may hold a key or a password | 0600 |
| `wireguard/` | generated `.conf` files handed to the WireGuard client | 0700 |
| `openvpn/<name>/` | imported `.ovpn` files and their certificates | 0700 |
| `reports/` | reports exported from a log pane with `s` | 0700, files 0600 |

The modes are the Linux ones. Windows has no file modes, so the same rule is written as an
ACL instead: `icacls <path> /inheritance:r /grant:r <you>:F` drops everything the parent
directory granted — including the machine's administrators — and leaves your account as
the only entry. A file that would be 0600 on Linux is yours alone on Windows too.

NetBird and Pangolin are absent from `vpn.toml` on purpose: netbird's profiles live in
netbird and pangolin's accounts live in pangolin, and both are only read. `reports/` is written to rather than read, and appears the first time you export
one — see [logs.md](logs.md).

## config.toml

```toml
[ui]
theme = "dark"                     # dark, dracula, nord, gruvbox — `t` cycles them

[ssh]
terminal = "auto"                  # auto | inline | a terminal command line

[rdp]
client = "auto"                    # auto | freerdp | mstsc

[vpn]
sudo = "ask"                       # ask | auto | never
on_exit = "ask"                    # ask | stop | keep
```

`ssh.terminal` is explained in [connections.md](connections.md#ssh-sessions).

`rdp.client` picks which client opens a session:

| | |
| --- | --- |
| `auto` | the one this system ships — `mstsc` on Windows, `xfreerdp3` everywhere else (the default) |
| `freerdp` | `xfreerdp3`, configured on its command line |
| `mstsc` | Windows' own Remote Desktop Connection, configured through a `.rdp` file controlcenter writes |

`vpn.sudo` decides whether controlcenter takes a sudo ticket on your terminal before the
TUI starts, so that taking a VPN down later needs no polkit dialog:

| | |
| --- | --- |
| `ask` | ask for a password when there is no valid ticket (the default) |
| `auto` | use a ticket that is already there, never ask |
| `never` | leave sudo alone; every escalation goes through polkit |

Nothing is asked for when no client that needs root is installed. `--sudo <mode>`
overrides it for one run. See [vpn.md](vpn.md#root).

On Windows there is no ticket to take and the setting does nothing: a process is elevated
or it is not, decided before it started. Start controlcenter as administrator to use
WireGuard or OpenVPN there.

`vpn.on_exit` decides what happens to OpenVPN sessions still up when you quit — `ask`
(the default), `stop`, or `keep`. They run as root, so once controlcenter is gone nothing
that is left knows how to reach them; `keep` is how orphans are made on purpose.

## tunnels.toml

```toml
[[tunnels]]
name = "prod-db"
group = "prod"                     # optional, empty = ungrouped
ssh_host = "bastion.example.com"   # a destination ssh resolves, or "ssh:<name>"
forward = "local"                  # local | remote | dynamic
local_port = 5432                  # listen port (-L/-D) or local dest port (-R)
remote_host = "db.internal"        # destination host (-L) / local dest host (-R)
remote_port = 5432                 # destination port (-L) / listen port on ssh host (-R)
extra_args = "-J jumphost"         # optional, passed to ssh verbatim
auto_reconnect = true
requires_vpn = "netbird:work"      # optional, see connections.md
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

# Or point the whole thing at a host on the SSH tab, which is where its port,
# user, key, password and extra args then come from — see connections.md.
[[tunnels]]
name = "prod-cache"
ssh_host = "ssh:prod-bastion"      # the `name` of an entry in ssh.toml
forward = "local"
local_port = 6379
remote_host = "cache.internal"
remote_port = 6379
```

`ssh_host` is either a destination ssh works out for itself — an `ssh_config` alias,
`user@host`, an `ssh://` URI — or `ssh:<name>`, naming an entry in `ssh.toml`. Only the
`ssh:` prefix makes it a reference; `ssh://` is a destination like any other.

## ssh.toml

Written 0600 because it may hold a password.

```toml
[[hosts]]
name = "prod-app"
group = "prod"                     # optional, empty = ungrouped
host = "127.0.0.1"                 # e.g. the local end of a tunnel
port = 2222
username = "deploy"                # optional, empty = let ssh decide
key_path = "~/.ssh/id_ed25519"     # optional, passed as -i
password = ""                      # optional, CLEARTEXT — see connections.md
skip_host_key_check = true         # StrictHostKeyChecking=no + no known_hosts
extra_args = "-A"                  # optional, passed to ssh verbatim
requires_vpn = "wireguard:home"    # optional, see connections.md
depends_on = "prod-db"             # optional, tunnel to bring up first
```

`skip_host_key_check` is there for tunnelled localhost targets, where the key changes with
whatever is on the far end of the tunnel.

An entry here is not only an interactive login: a tunnel can name it as its `ssh_host`,
and then runs with everything set here — see
[connections.md](connections.md#tunnels-through-a-configured-host). Renaming the entry
follows through to the tunnels that ride it.

## rdp.toml

```toml
[[connections]]
name = "office-dc"
group = "office"                   # optional, empty = ungrouped
host = "192.168.1.10"
port = 3389
domain = "CORP"                    # optional
username = "admin"
extra_args = "/f"                  # optional, passed to the client — see below
requires_vpn = "*"                 # optional, see connections.md
depends_on = "prod-db"             # optional, tunnel to bring up first
```

With **freerdp**, sessions launch as `xfreerdp3 /v:host:port /u:user [/d:domain]
/dynamic-resolution /cert:ignore /from-stdin`, matching the classic rdp-wrap script, and
`extra_args` is appended to that command line verbatim.

With **mstsc** there is no command line to append to: mstsc takes its settings in a `.rdp`
file, so controlcenter writes one — host, port, user and domain, a window rather than the
whole screen, and the certificate check relaxed the same way `/cert:ignore` relaxes it —
into the runtime directory, hands mstsc the path, and deletes the file again once mstsc
has read it. `extra_args` is read as a comma-separated list there, and each entry is
either kind of thing:

```toml
extra_args = "/f, redirectclipboard:i:0, audiomode:i:2"
```

Anything shaped like a `.rdp` setting — `key:s:value`, `key:i:0`, `key:b:…` — goes into
the file, replacing the generated line with the same key rather than fighting it.
Everything else is passed to `mstsc` as a switch. A field written the freerdp way, with no
commas at all, is still read as a run of switches.

Sessions keep running when you quit the TUI, whichever client opened them.

## vpn.toml

Written 0600 because it may hold a key or a password. See [vpn.md](vpn.md) for what each
client does with these.

```toml
[[wireguard]]
name = "home"                      # also the interface name, so it must be a valid one
config_path = ""                   # set this to use a .conf someone else maintains
private_key = "…"                  # CLEARTEXT — `g` in the form generates a keypair
address = "10.0.0.2/24"
dns = ""                           # on Linux, needs resolvconf or resolvectl on PATH
listen_port = 0                    # 0 = let the kernel pick
mtu = 0                            # 0 = default
peer_public_key = "…"
preshared_key = ""
endpoint = "vpn.example.com:51820"
allowed_ips = "0.0.0.0/0, ::/0"
persistent_keepalive = 25          # 0 = off

[[openvpn]]
name = "work"                      # also the directory the import lives in
config_path = "/home/you/Downloads/work.ovpn"   # where it came from
import = true                      # copy it and its certificates in — see vpn.md
username = "you"                   # optional
password = ""                      # optional, CLEARTEXT
extra_args = ""

[[tailscale]]
name = "default"
login_server = ""                  # Headscale or another coordination server
exit_node = ""
exit_node_allow_lan = false
accept_routes = true
accept_dns = true
ssh = false
shields_up = false
hostname = ""
advertise_routes = ""              # comma separated CIDRs
advertise_exit_node = false
extra_args = ""
```
