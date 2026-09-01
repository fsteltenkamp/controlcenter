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
| also swept | — | strays | orphans and leftover devices | — |
| poll needs root | no | no | no | no |
| connect | `profile select` + `up` | `wg-quick up <conf>` | `openvpn --config …` | `tailscale up --reset …` |

### On Windows

The clients are the same clients and the tab is the same tab; four things underneath it
are not, and each is spelled out where it matters below.

| | Windows |
| --- | --- |
| WireGuard needs | `wireguard.exe` and `wg.exe`, from the WireGuard for Windows installer |
| WireGuard is driven with | `wireguard /installtunnelservice <conf>` and `/uninstalltunnelservice <name>` |
| WireGuard is polled with | the `WireGuardTunnel$<name>` services, which is what installing one registers |
| OpenVPN credentials go through | a file in the runtime directory, locked to you and deleted once openvpn has read it |
| the sweep reads | `Win32_Process` and `Get-NetAdapter` rather than `/proc` and `ip` |
| root is | being started as administrator — see [Root](#root) |

controlcenter looks under `Program Files` as well as on `PATH`, so a client installed the
normal way is found without anything being added to `PATH`.

The status panel lists what requires the selected profile, and for a client that is not
installed, what is already waiting on it. It also lists every connection found on the
machine that controlcenter is *not* holding — see
[what is not ours](#connections-controlcenter-is-not-holding).

## NetBird

Profiles are netbird's own, so they are listed and switched but never edited here — `a`,
`e` and `d` say so instead. Only one profile is active at a time, so switching prompts as
a conflict when something is riding on the profile going down.

## WireGuard

Polled with `ip`, not `wg show`, because `ip` needs no privileges: an interface named
after one of your profiles existing is exactly what "that profile is up" means. Interfaces
that are not controlcenter's — NetBird runs one of its own — are reported but never
counted as connected; one that no client accounts for at all is listed as **◆** and can
be handed back to `wg-quick down`. Live handshake and transfer counters would need root,
so the panel shows the byte counters `ip -s link` gives up for free instead.

On Windows there is no `wg-quick`: the same generated `.conf` is handed to
`wireguard.exe /installtunnelservice`, which registers a service that owns the tunnel, and
`/uninstalltunnelservice <name>` takes it away again. The state is read from those
services rather than from adapters, so a tunnel counts as up the moment it is installed
and running, whether or not its adapter has appeared yet. Addresses and byte counters come
from `Get-NetIPAddress` and `Get-NetAdapterStatistics`. Installing a tunnel is the one
part that needs administrator; reading the state is not.

Unless `config_path` points at a config someone else maintains, a WireGuard profile *is*
the source of truth: the `.conf` handed to the client is generated from the profile's
fields into `wireguard/<name>.conf` in the config directory (0600, in a 0700 directory —
on Windows, an ACL that leaves you as the only entry) and regenerated on every save.
Nothing is ever written into root-owned `/etc/wireguard`, because both clients accept a
path.

`g` on the private key field in the form generates a keypair.

Several interfaces can be up at once, so WireGuard profiles never conflict with each
other.

## OpenVPN

A child process with a tailed log rather than a daemon to poll, the same shape as an RDP
session; `l` opens the log ([logs.md](logs.md)) and `c` clears it. The other three clients
have no session log of their own, so their pane shows what controlcenter ran and what came
back. Credentials are written to the child's
**stdin** (`--auth-user-pass /dev/stdin`), so they never appear in the process list or on
disk.

Windows has no `/dev/stdin` for a program to open, and openvpn there reads a console
rather than a handed-down pipe. So on Windows the credentials go into a two-line file in
the runtime directory instead — written with an ACL that leaves you as its only reader,
in a directory with the same, and deleted twenty seconds after openvpn started, by which
time it has read the file and kept what it found in memory. They are still never an
argument, which is the part that matters: an argument is readable by every process on the
machine for as long as the session lasts.

Because the process runs as root, controlcenter cannot signal it directly — `kill` would
only reach `pkexec` — so openvpn is started with `--writepid` and stopped by an escalated
`kill`. **Disconnecting therefore asks for root a second time**, unless a sudo ticket was
taken at startup, in which case it is silent — see [Root](#root). An elevated
controlcenter on Windows owns the process outright and asks nothing.

Stopping does not stop at asking. The pid file is not the only place the process is looked
for: the process list is swept as well, so a session cancelled before openvpn got round to
writing the file, or one that left a stale file behind, is still found. A polite stop that
is not obeyed within a second and a half is followed by a forceful one — `SIGTERM` then
`SIGKILL`, and `taskkill /PID … /T` then the same with `/F` on Windows, where a console
program with no window has nothing to ask politely and the forceful form is the one that
does the work. An openvpn left running is not a cosmetic failure — it keeps holding the
server's slot, and the next connection to the same profile is thrown off it every couple
of minutes by the one still there.

Quitting with sessions up asks what to do about them, because walking away has the same
effect: **s** stops them, **k** leaves them running and writes down where they came from.
`vpn.on_exit` in [configuration.md](configuration.md#configtoml) makes that answer
permanent.

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

Only one profile is active at a time, so switching prompts as a conflict when something is
riding on the profile going down.

## Connections controlcenter is not holding

A session can outlive the program that started it — a crash, a `kill -9`, an exit while
openvpn was up. What is left is a *root* process nothing here holds any more, and the next
connection to the same server fights it for the slot. From the inside that looks like a
tunnel which connects and drops every three minutes, not like a leak.

So the VPN tab shows what is on the machine, not only what controlcenter started. Every
five seconds it sweeps, and anything found that no session accounts for is listed at the
bottom of that client's profile list, marked **◆**. `Enter` takes one away; press it again
on a process that ignored `SIGTERM` and it is killed outright. `x` takes them down with
everything else, and `a`, `e`, `d` and `p` say why they do not apply. `controlcenter
--vpn-scan` prints the same sweep from a shell and exits.

Two sources, because neither one is enough:

**Processes**, from `/proc` — from `Win32_Process` on Windows, which is the same list by
another name. An OpenVPN connection *is* a process, so this is what can
name one — by the `--config` it was started with, which for a profile controlcenter
imported gives the profile's own name back — and the only thing that can stop it, by pid.
It is also the only source that sees a client which is *failing* to connect: a session
stuck retrying holds no interface and still holds the server's slot. A process whose
`--writepid` points into controlcenter's run directory was started by a controlcenter that
is no longer here, and the row says so.

Windows withholds one thing from an unelevated reader: the command line of a process
belonging to somebody else, or running elevated while controlcenter is not. Such a process
is still listed and can still be stopped — that an openvpn is holding the server's slot is
the half that matters — it just shows as its pid rather than by profile. Starting
controlcenter as administrator gives it a name.

**Interfaces**, from `ip` — from `Get-NetAdapter` on Windows. A tunnel actually carrying
traffic has a device whoever made it. This is the catch-all, and for OpenVPN it is more than that: a killed openvpn does
**not** take its device with it. The `ovpn` link outlives the process, keeps the address
it was given, and is what the next connection collides with — openvpn logs `sitnl_send:
rtnl: generic error (-17): File exists` and takes the next `tun` number instead. By then
there is no process left to find it by, so the device is the only evidence there is.

None of that applies on Windows, where an adapter is installed by the client's driver and
is simply always there, connected or not: its being present says nothing about a leak. So
only a WireGuard tunnel service is ever offered for removal there, and it goes back to
`wireguard.exe`. The adapters are still listed, so what is up is visible.

A device is only offered for removal once nothing is left that could still own it: while
an OpenVPN process is running unaccounted for, a device it has not named is not a leak,
and there is no way to tell from the outside which of them it is using. Take the process
down first; its device goes with it, and anything still standing afterwards is listed.

A device is matched to its owner by what the clients say about themselves — the interface
a WireGuard profile creates, the device a live session named in its own log, the address
NetBird or Tailscale reports. One that matches none of them is listed as *unaccounted
for* rather than guessed at. NetBird and Tailscale are daemons whose status already
reports the machine rather than this process, so nothing of theirs can be orphaned here.

Nothing in the sweep escalates: reading `/proc/<pid>/cmdline` and listing links are both
unprivileged, and so are the two PowerShell queries that replace them. Only taking
something down needs root.

## Root

WireGuard and OpenVPN need root to change the network, and so does Tailscale on Linux.

### Linux

controlcenter never handles a password: it runs `pkexec`, so your polkit agent puts the prompt in front of
you, and falls back to `sudo -n` when there is no agent to answer — a bare tty, or an ssh
session. If neither works it says so instead of hanging. Status polling never escalates,
and neither does the sweep.

That order is right for bringing something *up*, and wrong for taking it down. A dialog
per connection means the panic button asks four times, and a dialog that is dismissed — or
that never appears because nothing is there to show it — leaves a root openvpn running
that nothing on the machine knows how to reach. So before the TUI takes the screen, while
the terminal is still yours and a prompt is just a prompt, controlcenter runs `sudo -v`
once:

```
controlcenter: taking a sudo ticket so VPN sessions can be stopped without a dialog
               (set vpn.sudo = "never" in config.toml to skip this).
[sudo] password for you:
```

With that ticket in hand `sudo -n` goes first and every stop is silent. It is refreshed
every two minutes for as long as the program runs, and pkexec is still there if it lapses.
Nothing is asked for when no client that needs root is installed, and declining costs only
the dialogs. `vpn.sudo` and `--sudo` choose between `ask`, `auto` (use a ticket that is
already there, never prompt) and `never` — see
[configuration.md](configuration.md#configtoml).

### Windows

None of that applies, because none of it can. UAC decides whether a process is elevated
when it starts and cannot raise one afterwards, so there is no ticket to take and no agent
to ask — the question is settled before controlcenter exists.

**Start controlcenter as administrator** to use WireGuard or OpenVPN: right-click it and
choose *Run as administrator*, or start it from an elevated terminal. It then runs those
commands itself, with no dialog, and owns the OpenVPN process outright — which is exactly
the property the sudo ticket buys on Linux, and for the same reason: a stop that can be
dismissed is a VPN left running that nothing can reach.

Started normally, controlcenter says so on the VPN tab and in an exported report, and
everything else — tunnels, SSH, RDP, NetBird, Tailscale — works as usual. If the `sudo`
that ships with current Windows is installed and its **inline** mode is turned on, VPN
commands are routed through it instead, which asks for consent every time.

`vpn.sudo` and `--sudo` do nothing here beyond `never`, which skips the check.
