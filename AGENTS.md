# Instructions for AI agents

This file is for AI agents working on this repository. The [README](README.md) and
[docs/](docs/) are for humans using the program — keep it that way: do not put agent
instructions there, and do not put usage documentation here.

## Build and test

```sh
cargo build            # must stay warning-free
cargo test             # 227 tests, all pure unit tests — no network, no root
cargo build --release
```

Both systems are built and tested in CI (`.github/workflows/ci.yml`): Linux and Windows.
A change to a `#[cfg(windows)]` path is not verified by a green build here, so check it
before pushing:

```sh
./build.sh              # dist/controlcenter and dist/controlcenter.exe
./build.sh test         # the Windows unit tests, run here under wine
```

`build.sh` cross-compiles in a container — the toolchain is not on this machine and on
Arch the package that would provide it replaces the `rust` package — with the source
mounted read-only and the object tree in a volume, so nothing is installed, nothing
root-owned lands in the working tree, and a second run takes seconds. The `.exe` is the
gnu target; releases ship the msvc one from a real Windows runner.

`./build.sh test` is worth the wait rather than a formality: it is what caught the
accepted socket in `tunnel.rs` inheriting the listener's non-blocking mode, which made
every tunnel on Windows relay nothing at all and which no amount of reading had found.
Two of the tests are Unix-only and do not run there. What wine cannot answer for is
anything that reaches a real Windows service — DPAPI, `icacls`, `taskkill`, PowerShell —
so those still need the CI job or a real machine.

## Layout

| file | holds |
| --- | --- |
| `src/main.rs` | CLI, terminal setup/teardown, handing the terminal to an inline ssh session, and the `SSH_ASKPASS` mode |
| `src/platform.rs` | what differs between the systems and belongs to no one client: finding a binary, the null device, locking a file to its owner, looking up and stopping a process, whether we are elevated, and the Windows command-line and CSV parsers |
| `src/app.rs` | all state and all key handling; the only place that decides what a key does |
| `src/ui.rs` | all drawing; reads `App`, never mutates it |
| `src/types.rs` | the config types, requirement parsing, conflict rules |
| `src/config.rs` | paths, load/save, file modes |
| `src/logs.rs` | the line ring every child process fills, the journal of what the program did, and `LogTarget` — which connection a pane, an entry or a report is about |
| `src/report.rs` | the report `s` exports, and the redaction every line goes through |
| `src/tunnel.rs` | spawning ssh, the counting relay, per-tunnel status |
| `src/ssh.rs` | interactive sessions: terminal detection, windowed and inline |
| `src/sftp.rs` | the one `sftp` process a transfer browser talks to, the listing it parses, and the remote pane's state |
| `src/rdp.rs` | RDP sessions: xfreerdp3, and mstsc through a generated `.rdp` |
| `src/browser.rs` | the file picker |
| `src/chooser.rs` | the list picker — groups as folders, entries as files |
| `src/theme.rs` | the four colour themes |
| `src/vpn/` | one module per client behind a shared interface in `mod.rs`, plus `privileged.rs` for pkexec/sudo/elevation and `scan.rs` for what is on the machine |

## Conventions that matter here

**One keymap.** Every key means the same thing on every tab; only what it acts on
changes. The table in the README is the contract. When adding a key:

- put it in `App::on_key` if it means the same thing regardless of what is selected
  (`t`, `x`, `?`, `k`, `q`, tab switching), otherwise in the tab's `on_*_key`
- give it a meaning on *every* tab. Where a tab genuinely cannot do it, `flash` a line
  saying why rather than leaving the key dead — `p` on the Tunnels tab is the model
- update the README table, `render_keys_overlay`, and the tab's footer hints in
  `render_status` in the same change
- navigation is arrow keys only. `h` `j` `k` `l` are action keys; do not reintroduce vim
  bindings

`Ctrl+O` is the one picker key, in forms. It opens whatever picker the field under the
cursor has — `browser::FileBrowser` on a path, `chooser::Chooser` on a field whose value
comes from a list — and flashes a line on a field that has neither, rather than doing
nothing. A new form field with a list behind it is added to `App::active_chooser_field`
and its two companions, not given a key of its own. A `Chooser` never stores anything
itself: it hands back a value, and a `Picker` or a text field takes it, so what is saved
does not depend on which way the field was set.

**A list's order is its file's order.** `build_rows` lays a list out as the ungrouped
entries, then each group in order of first appearance, so `reorder` only makes moves that
survive being drawn again: an entry moves among its own group's members, a group header
moves the whole block. Anything that reorders saves the file in the same breath, or the
order is gone at the next start. The VPN tab has no groups and no vec of its own — its
rows are seeded from `vpn.toml` on every poll, so `move_named` moves the profile in the
config and the list follows.

**What is on the machine is not what we started.** `vpn/scan.rs` sweeps `/proc` and `ip`
for VPN processes and tunnel devices; `App::foreign_for` subtracts the sessions this
process is holding, and what is left is listed as a `◆` row that can only be stopped. Keep
that split: the scan never knows what the app owns, and the app never re-implements the
scan. Both halves are needed and neither is optional — a process names a connection and
can stop it but vanishes on a kill, while a device outlives the process that made it and
is the only evidence a leaked openvpn leaves behind. A device is only ever offered for
removal when nothing is left that could still own it (`scan::leaked_ovpn_devices`); a live
session's device comes from its own log, so never make that a guess.

**Nothing that only looks escalates.** The sweep, like every status poll, is unprivileged
by construction: `/proc/<pid>/cmdline` and `ip link` need no root, and if a future source
would, it does not belong in `scan.rs`.

**A stop has to actually stop.** An openvpn left running keeps the server's slot and the
next connection to the same profile is thrown off it every few minutes, so stopping is
belt and braces: every holder found (pid file *and* `/proc`), `SIGTERM`, then `SIGKILL`
for whatever ignored it. The same reasoning is why quitting asks about sessions still up
and why `privileged` prefers a startup sudo ticket over a polkit dialog that can be
dismissed. Do not make any of those quieter.

**Popups close with `q` and `Esc`.** `q` only quits the application when nothing is
focused. A popup that takes text (a form, a password prompt) is the exception: there `q`
is a letter and only `Esc` closes.

**One platform difference, in one place.** `platform.rs` holds what is true of the
operating system and of no particular client; a client module holds what is true of its
client on each system. Two rules keep the `#[cfg]`s from spreading:

- a client module never asks which system it is on in order to find a binary, write a
  private file, stop a process or check for root — it asks `platform`
- a Windows code path that *parses* anything is written as a `#[cfg(any(windows, test))]`
  function with its tests beside it, so the parsing is exercised on Linux too. That is
  most of what the Windows halves are, and it is the only way any of it is checked before
  it reaches a Windows machine. See `scan::parse_windows_processes`,
  `wireguard::parse_services`, `platform::split_command_line`

Where the two systems genuinely do different things — `wg-quick` against
`wireguard.exe /installtunnelservice`, a pipe against a file only its owner can read —
say so in the comment and say why, the same as any other decision.

**Comments explain why, not what.** The existing comments are the house style: they
justify a decision that would otherwise look arbitrary — why WireGuard is polled with `ip`
rather than `wg show`, why openvpn is stopped through a pid file. Do not add comments that
restate the code.

**A transfer is a session, not a command per file.** `sftp.rs` holds one `sftp` process
per open transfer browser and talks to it on its stdin, because listing a directory and
copying out of it are the same conversation: one authentication, no handshake between
keystrokes, and a password asked for once or never. `ControlMaster` would have done the
same on Unix and nothing at all on Windows. Three things about sftp's own interface carry
the whole protocol, and none of them is incidental:

- reading commands from a pipe it echoes each one back prefixed with `sftp> `, so what
  comes home is recognisable as ours
- a command prefixed with `-` does not end the session when it fails, which is what keeps
  a typo'd path from costing the connection — every command we send has it
- `pwd`'s reply cannot be produced by a listing, so every command is followed by one and
  its reply is where that command's output ends

Two things were established against a real server rather than reasoned about, and a change
here should be too: the progress meter is *on* by default on a pipe, so it is turned off
with the `progress` command, which toggles — what it prints is checked rather than
assumed; and `ls` echoes each entry the way it was asked for, so listing by absolute path
gives absolute paths back and the pane reads the last segment. Errors arrive on stderr,
out of step with the stdout being parsed, so a thread collects them and they are read once
the marker says the command is done — and `Connected to` and `Warning:` are not errors, or
every empty directory would report one.

**A transfer belongs to the host, not to itself.** It gets no `LogTarget` of its own: it
writes to `LogTarget::Ssh(name)`, so `l` on the host shows it and a report on the host
covers it without a new section. Its ring lives in `App::sftp_logs`, keyed by host rather
than held by the session, so closing the browser does not take the record of what it did
with it. `Step::Transfer` requires exactly what `Step::Ssh` requires, which is why a host
behind a VPN and a tunnel can be browsed at all.

**A configured SSH host becomes a command line in one place.** A tunnel's `ssh_host` is
either a destination ssh resolves or `ssh:<name>`, an entry from `ssh.toml`
(`types::parse_ssh_target`). Where it is an entry, everything that entry says about
reaching the host comes from `ssh::connection_args` — the same function an interactive
session uses — so a field added to `SshHost` reaches tunnels and sessions together or
neither. `ssh::transfer_args` is that function again for `sftp` — the same options with the port
flag swapped, by position and never by search, because `extra_args` is free text and may
hold a `-p` of its own. What the entry needs for itself is folded into the tunnel's plan by
`Catalog::requires_of`, which returns one `Requires` per source rather than merging them:
a tunnel and the host it rides can each name a tunnel, and both have to be up.

**A client is driven through its CLI, unless its CLI cannot be driven.** Every
provider shells out; `vpn/pangolin.rs` is the one that also talks to its client's
control socket, because two of the pangolin CLI's subcommands are unusable from a
full-screen program — `down` opens `/dev/tty` to draw a progress view and exits
non-zero on a no-op, and `status --json` shares its stdout with the CLI's update
banner. Reaching past a CLI needs that kind of reason written down beside it, and
it stays inside the same two rules as everything else: the client's own published
interface, and no escalation for anything that only looks.

**The UI thread never blocks.** Every connect, disconnect and status poll runs on a thread
and reports back through `vpn_tx`/`vpn_rx`. A new long-running operation follows the same
shape.

**One log pane.** There is one pane (`App::log_pane`), one renderer
(`ui::render_log_overlay`) and one source for it: `App::log_lines`, which merges the
journal entries for a `LogTarget` with the output rings of whatever processes that target
covers. A new kind of connection gets a `LogTarget` variant and a case in `rings_for`, and
nothing else — never a second log popup.

**A report covers the subject and its chain, and stops there.** `report::build` scopes
itself with `chain_targets`, i.e. the plan the subject would be brought up through. A
connection that cannot explain the subject's behaviour does not belong in its report;
`LogTarget::Program` is the one subject that means everything. Add a section and it has to
answer to the same rule. Logs are never truncated to make a report shorter: the pane's own
goes in whole, and the chain's go in whole in a `Report::attachment` written beside it.

**Everything the program does is written down.** A child process's output goes through a
`logs::Ring`; anything controlcenter decides or runs goes through `App::note` (quiet) or
`App::report` (also flashes), against the `LogTarget` it is about. When you add an
operation, record the command line it ran and the outcome it got, or the report exported
next to it will be missing the step that explains the failure. Command lines come from a
`build_args`-style function that spawning and reporting both call, so what a report shows
is what actually ran.

**Secrets never reach a command line.** Passwords go through the environment (`sshpass -e`,
`SSH_ASKPASS`) or a child's stdin (`xfreerdp /from-stdin`,
`openvpn --auth-user-pass /dev/stdin`). Files that can hold one are written 0600, in 0700
directories — exported reports included; on Windows the same rule is an ACL with the owner
as its only entry, which is what `platform::restrict_file` writes. Do not add an argv path.
Anything that leaves the program goes through `report::redact` first, because `extra_args`
is free text and a user can type a password into it.

Two clients cannot take a password any other way, and both are handled without weakening
that rule rather than around it: mstsc reads a `.rdp` file, so the password goes in sealed
with DPAPI to the current account, and openvpn on Windows reads a file, so one is written
into the run directory and deleted once it has been read. Anything new that needs a file
does the same: owner-only, in the run directory, swept.

**Privilege escalation goes through `vpn/privileged.rs`.** `pkexec` first, `sudo -n` as
the fallback, and a clear message when neither can work — unless `warm_up` took a sudo
ticket before the TUI started, in which case sudo goes first because it cannot be
dismissed. That warm-up is the only place sudo is ever allowed to prompt, and it runs in
`main` before the alternate screen, on the user's own terminal. Nothing else shells out to
sudo, and status polling never escalates at all.

The one exception is a client that escalates *itself*: `pangolin up` re-executes under
sudo, so controlcenter runs it unprivileged and `ProviderId::needs_root` returning true is
what takes the startup ticket that sudo then finds. Wrapping it in `privileged::run` as
well would be two escalations racing for one command. Do not add a second such client
without the same reasoning written down beside it.

Windows is a second implementation behind the same interface, in the same file. There is
nothing to warm up: UAC settles the question before the process starts and cannot raise
one afterwards. An elevated controlcenter runs the command itself; an unelevated one has
`sudo --inline` where that exists and otherwise says so. Do not add a `runas` — a child in
a window we cannot read and cannot signal is exactly the leaked VPN this file exists to
prevent, and `privileged::command`, which streams openvpn's log, refuses rather than
starting one. `ProviderId::needs_root` is what decides whether an action goes through this
file at all, and it is platform-aware: Tailscale on Windows needs nothing.

**A low port is a capability on the binary, never root.** The relay in `tunnel.rs` binds
the tunnel's local port in this process, so a tunnel on 80 or 443 is answered by
`setcap cap_net_bind_service=+ep` on the controlcenter binary — not by running the TUI
under sudo, and not by touching ssh, which only ever binds a loopback port behind the
relay. A bind that comes back `EACCES` is therefore a different failure from `EADDRINUSE`:
one can be evicted and retried, the other never can, so `tunnel::bind_error` gives the
refusal its own type and `App::start_tunnel` raises the popup that carries the exact
command. What the popup says is `platform::port_refused_advice`, because what is reserved
and why is the operating system's business — Windows reserves nothing by rank, and its
refusals are excluded ranges instead. Never retry a refused port and never make the
advice a guess at the binary's path: it comes from `current_exe`.

**Config is edited in the TUI and is hand-editable.** Adding a field means adding it to
the type in `types.rs`, the form in `app.rs`, the panel in `ui.rs`, and
`docs/configuration.md`. Old files must keep loading — see how unqualified `requires_vpn`
values are still read as NetBird.

## Documentation

- `README.md` — what the program is, the tabs, the full keymap, requirements. Keep it
  short; it is the page a human reads first
- `docs/connections.md` — groups, dependencies, conflicts, SSH sessions and passwords
- `docs/logs.md` — the log pane, and what an exported report contains
- `docs/vpn.md` — how each VPN client is driven
- `docs/configuration.md` — every config file, field by field
- this file — anything an agent needs and a user does not

A behaviour change that a user would notice belongs in one of the first five. A convention
that only matters while editing the code belongs here.
