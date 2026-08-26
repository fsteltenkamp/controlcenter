# Instructions for AI agents

This file is for AI agents working on this repository. The [README](README.md) and
[docs/](docs/) are for humans using the program — keep it that way: do not put agent
instructions there, and do not put usage documentation here.

## Build and test

```sh
cargo build            # must stay warning-free
cargo test             # 133 tests, all pure unit tests — no network, no root
cargo build --release
```

There is no test harness for the TUI itself. Anything drawn is verified by reading it;
anything parsed, planned or rendered to a config file has unit tests next to it and should
keep having them.

## Layout

| file | holds |
| --- | --- |
| `src/main.rs` | CLI, terminal setup/teardown, and handing the terminal to an inline ssh session |
| `src/app.rs` | all state and all key handling; the only place that decides what a key does |
| `src/ui.rs` | all drawing; reads `App`, never mutates it |
| `src/types.rs` | the config types, requirement parsing, conflict rules |
| `src/config.rs` | paths, load/save, file modes |
| `src/logs.rs` | the line ring every child process fills, the journal of what the program did, and `LogTarget` — which connection a pane, an entry or a report is about |
| `src/report.rs` | the report `s` exports, and the redaction every line goes through |
| `src/tunnel.rs` | spawning ssh, the counting relay, per-tunnel status |
| `src/ssh.rs` | interactive sessions: terminal detection, windowed and inline |
| `src/rdp.rs` | xfreerdp3 sessions |
| `src/browser.rs` | the file picker |
| `src/theme.rs` | the four colour themes |
| `src/vpn/` | one module per client behind a shared interface in `mod.rs`, plus `privileged.rs` for pkexec/sudo and `scan.rs` for what is on the machine |

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

**Secrets never reach a command line.** Passwords go through the environment (`sshpass -e`)
or a child's stdin (`xfreerdp /from-stdin`, `openvpn --auth-user-pass /dev/stdin`). Files
that can hold one are written 0600, in 0700 directories — exported reports included. Do
not add an argv path. Anything that leaves the program goes through `report::redact`
first, because `extra_args` is free text and a user can type a password into it.

**Privilege escalation goes through `vpn/privileged.rs`.** `pkexec` first, `sudo -n` as
the fallback, and a clear message when neither can work — unless `warm_up` took a sudo
ticket before the TUI started, in which case sudo goes first because it cannot be
dismissed. That warm-up is the only place sudo is ever allowed to prompt, and it runs in
`main` before the alternate screen, on the user's own terminal. Nothing else shells out to
sudo, and status polling never escalates at all.

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
