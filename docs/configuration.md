# Configuration files

Back to the [README](../README.md).

Everything is edited in the TUI and stored as TOML under `~/.config/controlcenter/`, so
you can also edit it by hand. `controlcenter --config-paths` prints exactly where each
file lives.

| file | holds | mode |
| --- | --- | --- |
| `config.toml` | the settings that are not connections | 0644 |
| `tunnels.toml` | SSH forwards | 0644 |
| `ssh.toml` | SSH hosts — may hold a password | 0600 |
| `rdp.toml` | RDP connections | 0644 |
| `vpn.toml` | WireGuard, OpenVPN and Tailscale profiles — may hold a key or a password | 0600 |
| `wireguard/` | generated `.conf` files handed to `wg-quick` | 0700 |
| `openvpn/<name>/` | imported `.ovpn` files and their certificates | 0700 |
| `reports/` | reports exported from a log pane with `s` | 0700, files 0600 |

NetBird is absent from `vpn.toml` on purpose: its profiles live in netbird and are only
read. `reports/` is written to rather than read, and appears the first time you export
one — see [logs.md](logs.md).

## config.toml

```toml
[ui]
theme = "dark"                     # dark, dracula, nord, gruvbox — `t` cycles them

[ssh]
terminal = "auto"                  # auto | inline | a terminal command line

[vpn]
sudo = "ask"                       # ask | auto | never
on_exit = "ask"                    # ask | stop | keep
```

`ssh.terminal` is explained in [connections.md](connections.md#ssh-sessions).

`vpn.sudo` decides whether controlcenter takes a sudo ticket on your terminal before the
TUI starts, so that taking a VPN down later needs no polkit dialog:

| | |
| --- | --- |
| `ask` | ask for a password when there is no valid ticket (the default) |
| `auto` | use a ticket that is already there, never ask |
| `never` | leave sudo alone; every escalation goes through polkit |

Nothing is asked for when no client that needs root is installed. `--sudo <mode>`
overrides it for one run. See [vpn.md](vpn.md#root).

`vpn.on_exit` decides what happens to OpenVPN sessions still up when you quit — `ask`
(the default), `stop`, or `keep`. They run as root, so once controlcenter is gone nothing
that is left knows how to reach them; `keep` is how orphans are made on purpose.

## tunnels.toml

```toml
[[tunnels]]
name = "prod-db"
group = "prod"                     # optional, empty = ungrouped
ssh_host = "bastion.example.com"   # anything ssh accepts: alias, user@host
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
```

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

## rdp.toml

```toml
[[connections]]
name = "office-dc"
group = "office"                   # optional, empty = ungrouped
host = "192.168.1.10"
port = 3389
domain = "CORP"                    # optional
username = "admin"
extra_args = "/f"                  # optional, passed to xfreerdp3 verbatim
requires_vpn = "*"                 # optional, see connections.md
depends_on = "prod-db"             # optional, tunnel to bring up first
```

Sessions launch as `xfreerdp3 /v:host:port /u:user [/d:domain] /dynamic-resolution
/cert:ignore /from-stdin`, matching the classic rdp-wrap script, and keep running when you
quit the TUI.

## vpn.toml

Written 0600 because it may hold a key or a password. See [vpn.md](vpn.md) for what each
client does with these.

```toml
[[wireguard]]
name = "home"                      # also the interface name, so it must be a valid one
config_path = ""                   # set this to use a .conf someone else maintains
private_key = "…"                  # CLEARTEXT — `g` in the form generates a keypair
address = "10.0.0.2/24"
dns = ""                           # needs resolvconf or resolvectl on PATH
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
