# Logs and reports

Back to the [README](../README.md).

Every tab has the same log pane, opened with `l` on whatever is selected, and every log
pane exports the same report with `s`. What changes between them is only what they are
about.

## The log pane

A pane merges two things, in the order they happened:

- **what controlcenter did** — the plan it built, the command line it ran, the exit code
  it saw, the reason it gave up
- **what the process printed** — ssh's stderr for a tunnel, the RDP client's output for an
  RDP session, openvpn's log for a VPN session, and what the VPN client itself said while
  it was being driven: the browser login NetBird asks for is printed there and nowhere else

Each line is stamped with the time and marked with who said it, so a refused key and the
command that asked for it read as one story. Lines controlcenter wrote itself are bright;
a process's own output is dim; anything that failed is red.

| tab | `l` opens |
| --- | --- |
| Dashboard | everything, in one list — the whole run |
| VPN | the selected profile: its session log, what the client printed, and what was run to bring it up |
| Tunnels | the selected tunnel: its ssh output and its starts, restarts and failures |
| SSH | the selected host: the command line, where the session opened, how it ended |
| RDP | the selected connection: the client's log |

An SSH session is the one thing with no output here — it runs in a terminal window of its
own, and that is where what it prints stays.

In the pane, `↑` `↓` scroll a line at a time and `PgUp` `PgDn` a screen; the title says how
far back you are. `c` clears it, `q`, `Esc` and `l` all close it.

A process keeps its last 2000 lines and controlcenter its last 2000 actions, so a
connection that has been up for a week does not grow without bound. Both are forgotten
when the program exits — export before you quit.

## Exporting a report

`s` writes a report and says where it went. It works from inside a log pane and from the
tab itself, on whatever is selected — on the Dashboard, on the whole program.

The file is more than the pane it came from, because it is read somewhere else by someone
without the program in front of them. A report on one connection contains:

- when it was written, which version wrote it, and what it is about
- **the subject in full**: its configuration, the command line it runs, what it needs
  first and whether that is satisfied, the chain it would bring up, and what it is doing
  now
- **every link of that chain**, described just as fully — the VPN profile it needs, the
  tunnel it stacks on, the tunnel *that* stacks on
- the binaries those need and whether they were found, and how root would be asked for
- for anything about a VPN: every tunnel device on the machine and which client accounts
  for it, and for an OpenVPN profile, any *other* openvpn found running the same config —
  a second one holding the same server slot is the whole explanation for a tunnel that
  connects and drops every few minutes, and nothing in the profile's own log says so
- what controlcenter did about any of them this run, timestamped
- **the pane's own log, in full** — every line of it, not a tail

The chain is the point: a chain fails at one link and is usually read at another. Nothing
else is in there — a tunnel's report says nothing about the tunnels, hosts, connections or
VPN clients it does not depend on, because they cannot explain what it did.

The **Dashboard's** report is the exception, since its subject is the whole program: every
VPN client, every tunnel, SSH host and RDP connection, everything the program did, and
every log line, in one file. That is the one to send when you do not yet know which
connection is at fault.

The links keep logs of their own too, and between them they run long, so they are written
beside the report rather than inside it — in full, one section per link — and the report
links to the file:

```
<config dir>/reports/
    controlcenter-tunnel-prod-db-20260826-140311.md          the report
    controlcenter-tunnel-prod-db-20260826-140311-chain.log   every log it depends on
```

Every file of one export shares that name, so an export is a set you can send together —
though the report alone is enough when the answer is in the pane you were looking at, and
there is no `.log` at all when the chain had nothing to say.

Reports land in `<config dir>/reports/`. The directory is `0700` and every file
`0600`, because they name your hosts, your usernames and your paths. Nothing deletes them
for you.

## What a report will not contain

No password ever reaches a command line in the first place: they go through the
environment (`sshpass -e`, `SSH_ASKPASS`), a child's stdin (`xfreerdp /from-stdin`,
`openvpn --auth-user-pass /dev/stdin`), or a file only its owner can read that is deleted
as soon as it has been read. A stored one is reported as present and how long it
is, never as itself:

```
password        set (12 characters, not shown)
```

The `extra_args` fields are free text, though, and controlcenter passes them on as typed.
So every line of a report — every command line, every log line — is filtered on the way
out, and anything that looks like a secret is replaced:

```
extra args      /p:<redacted> /f
```

The rule is that a key *ending* in `password`, `passwd`, `secret`, `token`, `privatekey`,
`presharedkey` or `apikey` hides whatever it is set to, whether written as
`--password value`, `--password=value` or `PrivateKey = value`. xfreerdp's `/p:` counts
too — but ssh's `-p` is a port, so it is left alone.

It is a filter, not a guarantee: read a report before you send it anywhere.
