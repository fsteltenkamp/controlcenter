# VPN clients

Back to the [README](../README.md).

Four clients share one tab. A client that is not on PATH stays listed, greyed out, with
the install hint and what is already waiting on it. Every connect, disconnect and status
poll runs in the background; the UI never blocks.

| | NetBird | WireGuard | OpenVPN | Tailscale |
| --- | --- | --- | --- | --- |
| needs | `netbird` | `wg`, `wg-quick` | `openvpn` | `tailscale` |
| profiles come from | `netbird profile list` | `vpn.toml` | `vpn.toml` | `vpn.toml` |
| status poll | `netbird status` | `ip link show type wireguard` | the child process | `tailscale status --json` |
| poll needs root | no | no | no | no |
| connect | `profile select` + `up` | `wg-quick up <conf>` | `openvpn --config …` | `tailscale up --reset …` |

The status panel lists what requires the selected profile, and for a client that is not
installed, what is already waiting on it.

## NetBird

Profiles are netbird's own, so they are listed and switched but never edited here — `a`,
`e` and `d` say so instead. Only one profile is active at a time, so switching prompts as
a conflict.

## WireGuard

Polled with `ip`, not `wg show`, because `ip` needs no privileges: an interface named
after one of your profiles existing is exactly what "that profile is up" means. Interfaces
that are not controlcenter's — NetBird runs one of its own — are reported but never
counted as connected. Live handshake and transfer counters would need root, so the panel
shows the byte counters `ip -s link` gives up for free instead.

Unless `config_path` points at a config someone else maintains, a WireGuard profile *is*
the source of truth: the `.conf` handed to `wg-quick` is generated from the profile's
fields into `~/.config/controlcenter/wireguard/<name>.conf` (0600, in a 0700 directory)
and regenerated on every save. Nothing is ever written into root-owned `/etc/wireguard`,
because `wg-quick` accepts a path.

`g` on the private key field in the form generates a keypair.

Several interfaces can be up at once, so WireGuard profiles never conflict with each
other.

## OpenVPN

A child process with a tailed log rather than a daemon to poll, the same shape as an RDP
session; `l` opens the log and `c` clears it. Credentials are written to the child's
**stdin** (`--auth-user-pass /dev/stdin`), so they never appear in the process list or on
disk.

Because the process runs as root, controlcenter cannot signal it directly — `kill` would
only reach `pkexec` — so openvpn is started with `--writepid` and stopped by an escalated
`kill`. **Disconnecting therefore asks for root a second time.**

### Importing a profile

A downloaded OpenVPN profile is rarely one file. It is usually a `.ovpn` next to the
certificates it references — `ca.crt`, `client.crt`, `client.key`, `ta.key` — and pointing
controlcenter at the download folder means the profile breaks the moment that folder is
tidied away.

So when you add a profile, controlcenter reads the `.ovpn`, finds every directive that
names a file (`ca`, `cert`, `key`, `extra-certs`, `dh`, `pkcs12`, `secret`, `tls-auth`,
`tls-crypt`, `tls-crypt-v2`, `crl-verify`, `askpass`, `auth-user-pass`,
`http-proxy-user-pass`), and copies all of them into
`~/.config/controlcenter/openvpn/<name>/` alongside a copy of the config rewritten to
point at the local names. The originals can then be deleted.

- Files already inlined in `<ca>…</ca>` blocks are left exactly as they are — they are
  already self-contained
- Trailing arguments survive the rewrite, so `tls-auth ta.key 1` keeps its direction
- Absolute and nested paths are flattened into the profile directory; two different files
  with the same basename are disambiguated rather than overwriting each other
- A file the config names but that is not there is reported **when you save**, not when
  you connect: *"the config needs client.crt, client.key which are not next to it"*
- openvpn resolves relative paths against the working directory rather than the config's
  own directory, so the session is started with `--cd` pointing at the profile directory

The status panel lists what a profile actually contains. Re-saving a profile re-imports
it; if the original is gone by then, the imported copy is kept rather than the save
failing. Set `import = false` (the *Import it and its certificates* toggle in the form) to
run a `.ovpn` where it sits instead — for a config someone else keeps up to date.

## Tailscale

Tailscale has no profile concept of its own; a profile here is a named set of
`tailscale up` flags. `up` is always run with `--reset`, so a profile means exactly the
state it describes rather than merging into whatever was set before.

Which profile is "active" is worked out by comparing `tailscale debug prefs` against your
stored profiles, since tailscale cannot report a name. If the daemon socket is root-only
the panel says to run `sudo tailscale set --operator=$USER` rather than escalating the
poll.

Only one profile is active at a time, so switching prompts as a conflict.

## Root

WireGuard, OpenVPN and Tailscale need root to change the network. controlcenter never
handles a password: it runs `pkexec`, so your polkit agent puts the prompt in front of
you, and falls back to `sudo -n` when there is no agent to answer — a bare tty, or an ssh
session. If neither works it says so instead of hanging. Status polling never escalates.
