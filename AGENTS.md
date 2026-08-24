# Instructions for AI agents

This file is for AI agents working on this repository. The [README](README.md) and
[docs/](docs/) are for humans using the program — keep it that way: do not put agent
instructions there, and do not put usage documentation here.

## Build and test

```sh
cargo build            # must stay warning-free
cargo test             # 96 tests, all pure unit tests — no network, no root
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
| `src/tunnel.rs` | spawning ssh, the counting relay, per-tunnel status |
| `src/ssh.rs` | interactive sessions: terminal detection, windowed and inline |
| `src/rdp.rs` | xfreerdp3 sessions |
| `src/browser.rs` | the file picker |
| `src/theme.rs` | the four colour themes |
| `src/vpn/` | one module per client behind a shared interface in `mod.rs`, plus `privileged.rs` for pkexec/sudo |

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

**Secrets never reach a command line.** Passwords go through the environment (`sshpass -e`)
or a child's stdin (`xfreerdp /from-stdin`, `openvpn --auth-user-pass /dev/stdin`). Files
that can hold one are written 0600, in 0700 directories. Do not add an argv path.

**Privilege escalation goes through `vpn/privileged.rs`.** `pkexec` first, `sudo -n` as
the fallback, and a clear message when neither can work. Nothing else shells out to sudo,
and status polling never escalates at all.

**Config is edited in the TUI and is hand-editable.** Adding a field means adding it to
the type in `types.rs`, the form in `app.rs`, the panel in `ui.rs`, and
`docs/configuration.md`. Old files must keep loading — see how unqualified `requires_vpn`
values are still read as NetBird.

## Documentation

- `README.md` — what the program is, the tabs, the full keymap, requirements. Keep it
  short; it is the page a human reads first
- `docs/connections.md` — groups, dependencies, conflicts, SSH sessions and passwords
- `docs/vpn.md` — how each VPN client is driven
- `docs/configuration.md` — every config file, field by field
- this file — anything an agent needs and a user does not

A behaviour change that a user would notice belongs in one of the first four. A convention
that only matters while editing the code belongs here.
