# Docker

The Docker tab (`6`) manages containers and compose stacks — on this machine, and on any
host from the SSH tab that is marked as running docker. It is laid out like the VPN tab:

- **stacks**, left — each engine, with its compose projects under it, and the containers
  that belong to no project together as `(no stack)`
- **containers**, middle — the selected stack's, one per line with its state and image
- **details**, right — whatever is under the cursor: an engine's reachability, a stack's
  directory and compose files, a container's status, ports and latest log lines

The stack list is a tree, and every engine starts folded so a host with dozens of stacks
does not push the others off the screen; its mark still says whether anything on it needs
a look. `→` opens an engine, and on an open one steps onto its first stack; `←` folds it
again, from the engine or from any of its stacks. `→` on a stack crosses into its
containers, and `←` from there comes back.

The keys act on the container under the cursor while the middle list has them, and on the
stack or engine while the left one does.

## Stacks are what docker says they are

Nothing here is configured. A stack is a compose project as docker labels it, so one
started from any directory — by hand, by a script, by an editor's dev container — is
listed as soon as it exists, and one taken down disappears. Stacks are listed by name.

Every compose command is run by project name, `docker compose -p <project> …`, without the
compose file. That is what lets a stack be stopped and started even when its file has
moved or was a temporary one. It also means `r` restarts the containers that exist rather
than re-reading the file: after changing a compose file, run `docker compose up -d` in its
directory as usual.

## What each key does

| key | on a stack | on a container | on an engine |
| --- | --- | --- | --- |
| `Enter` | `compose stop` if anything in it runs, `compose start` otherwise | `stop`, `start`, or `unpause` | list it again — on a remote engine, first bring up what its host needs |
| `r` | `compose restart` | `restart` | list it again |
| `d` | `compose down` — containers and networks go, volumes stay; asked first | `rm`, for a stopped container; asked first | — |
| `l` | a tile per container, side by side | that container's log | what controlcenter did there |
| `s` | a report | a report | a report |
| `c` | clear the error and the finished actions under the cursor | | |

## States

Each container is marked by what it needs from you:

| mark | means |
| --- | --- |
| `●` green | running, or running and **healthy** |
| `◐` amber | a health check still **starting**, or **paused** |
| `✖` red | **crashed** — exited with a code other than 0, 130 or 143 — **unhealthy**, **restarting** in a loop, or **dead** |
| `○` grey | **stopped** cleanly, or created and never started |

Exit codes 130 and 143 are SIGINT and SIGTERM, which is what `docker stop` sends, so a
container you stopped is not a crash. 137 is: a stop that had to fall back to SIGKILL and
the OOM killer look the same from outside, and the second is worth a look.

A stack is marked by its worst container, so one crashed service shows on the stack
before you open it.

## Logs

`l` on a **container** follows `docker logs` for that one container. `l` on a **stack**
splits the pane into a tile per container, side by side — wrapping into a grid when there
are more than fit across — each titled with the container's state and following its own
log. It is the view for seeing at once that something in a stack is off, without one
chatty service burying the rest.

In the tiles, `←` `→` choose a container and `↑` `↓` `PgUp` `PgDn` scroll only that one,
so the others keep following live. `Enter` opens the chosen container's log on its own,
full width, and `Esc` goes back to the tiles as they were; `l` closes the pane from
either. What controlcenter did to the stack — a stop, a restart, a `compose down` — runs
along the bottom, under the tiles.

Each line is stamped with when the container printed it, not when it arrived.

An exported report (`s`) on a stack carries every container's log, merged in time order
and tagged with the service, since a file has no tiles.

A log is followed while its pane is open. Close it and open it again, and it picks up
where it left off rather than starting over. The terminal colour codes containers print
for their own console are removed.

A report also carries the compose directory and files, every container's state, and the
command lines that list and follow it.

## Remote engines

Set **Docker on this host** on a host on the SSH tab, and it is listed as an engine of its
own. Its containers are managed by running the `docker` CLI on the host over ssh — with
the host's port, user, key, stored password, options, VPN and tunnel, exactly as a login to
it. Nothing has to be in `~/.ssh/config`, and docker needs to be installed only there.

A remote engine is listed only while what it needs is up. Until then it says what is
missing; `Enter` on it brings that chain up the way connecting a session would, and then
lists it. Like file transfers it runs in batch mode unless the host has a stored password,
because the full-screen program has no terminal to put a prompt on.

The remote side is assumed to be a Unix host with a POSIX shell, and the remote user has
to be allowed to talk to docker — usually by being in the `docker` group. controlcenter
never escalates for docker, here or there; a refusal is reported with that hint.

Engines are listed every few seconds while the tab, or a docker log pane, is in front, and
not otherwise. `x` takes down connections, not containers: it leaves docker alone.
