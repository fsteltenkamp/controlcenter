# Instructions for AI agents

This file is for AI agents working on this repository. The [README](README.md) and
[docs/](docs/) are for humans using the program — keep it that way: do not put agent
instructions there, and do not put usage documentation here.

## Build and test

```sh
cargo build            # must stay warning-free
cargo test             # 169 tests, all pure unit tests — no network, no root
cargo build --release
```

Both systems are built and tested in CI (`.github/workflows/ci.yml`): Linux and Windows.
A change to a `#[cfg(windows)]` path is not verified by a green build here — push it and
read the Windows job.

There is no test harness for the TUI itself. Anything drawn is verified by reading it;
anything parsed, planned or rendered to a config file has unit tests next to it and should
keep having them.

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
| `src/rdp.rs` | RDP sessions: xfreerdp3, and mstsc through a generated `.rdp` |
| `src/browser.rs` | the file picker |
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

Windows is a second implementation behind the same interface, in the same file. There is
nothing to warm up: UAC settles the question before the process starts and cannot raise
one afterwards. An elevated controlcenter runs the command itself; an unelevated one has
`sudo --inline` where that exists and otherwise says so. Do not add a `runas` — a child in
a window we cannot read and cannot signal is exactly the leaked VPN this file exists to
prevent, and `privileged::command`, which streams openvpn's log, refuses rather than
starting one. `ProviderId::needs_root` is what decides whether an action goes through this
file at all, and it is platform-aware: Tailscale on Windows needs nothing.

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
