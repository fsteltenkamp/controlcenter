# Scripts

Back to the [README](../README.md).

`!` runs a script on whatever is selected — an SSH host on the SSH tab, a container on
the Docker tab — and shows what it printed in the log pane. On a container it can open an
interactive shell instead.

## Running one

`!` opens the run form. The first time it goes straight to the library; after that it
opens as you last left it for that host or container, so running the same thing again is
`!` and `Enter`.

| field | |
| --- | --- |
| **run** | `script` or `shell` — a container only; `←` `→` switch |
| **script** | picked from the library. Typing here searches all of it; `Ctrl+O` opens it where the current script is |
| **arguments** | split the way a shell splits words: blanks separate them, `'…'`, `"…"` and `\` keep one together. Nothing is expanded — `$HOME` arrives as `$HOME`. If the script says what its arguments are, that is shown underneath |
| **shell** | the command a shell runs — empty is `bash` where the image has it, `sh` where it does not |
| **user** | a container only: a name or uid, optionally with `:group` or `:gid` — what `docker exec -u` takes. Empty is the image's own user, not root |

Below the fields the form shows where the script came from (a repository script with the
commit it is at), the **exact command line** that will run, and the script itself. `Enter`
runs it; `Esc` closes the form.

The log pane opens on the run as it starts and fills as the script prints. Its stderr is
red. The line at the top says whether it is still running and how it ended; `Enter` in the
pane stops a script that is. The run is also in the log of the host or container it ran
on, and `s` exports a report on it like on anything else: the run, the host or container,
and the chain in front of it.

A script on an SSH host is brought up the way a login is: if the host needs a VPN or a
tunnel, those come up first. A container has to be running — `docker exec` cannot reach
one that is not.

## How it runs

Nothing is copied to the host. The script is fed to its interpreter on **stdin**:

```
ssh … host '/bin/sh -s -- arg1 arg2'                  # an SSH host
docker exec -i -u 1000 web-1 /bin/sh -s -- arg1        # a container
```

The interpreter comes from the script's `#!` line — `sh`, `bash` and other shells read the
script with `-s` and take the arguments after `--`; anything else, such as
`#!/usr/bin/env python3`, is handed `-` and reads it the same way. A script without `#!`
runs in `sh`. So there is no temporary file to clean up on the far side, and the host or
image only needs the interpreter.

The other side of that is that the script's stdin *is* the script. Anything in it that
reads from the terminal gets end-of-file: `read` with no input redirected, or `sudo`
asking for a password. Use `sudo -n`, which fails rather than asks, or run the script as
a user that does not need it.

Over SSH it uses everything the host says about reaching it — port, key, password, extra
options — and with no stored password it runs with `BatchMode=yes`, so a host that would
ask for one fails with that reason instead of waiting on a prompt nobody can see.

## The library

The picker has a folder per shelf:

| | |
| --- | --- |
| `built-in` | scripts that ship with controlcenter |
| `local` | your own, in `scripts/` in the config directory (`--config-paths` prints it) — subdirectories become folders |
| *a repository's name* | a git repository from `config.toml` |

A file counts as a script if it starts with `#!` or ends in `.sh`, `.bash`, `.py`, `.pl`
or `.rb`. Hidden files and directories are skipped, which keeps a clone's `.git` out of
the list.

### Built in

All POSIX `sh`, and careful about what they assume, so the same script works on a server
and in a busybox container:

| | |
| --- | --- |
| `overview.sh` | who and what this is — system, kernel, uptime, load, memory, disks |
| `disk-usage.sh` | filesystems by use, inodes, and the biggest directories under a path |
| `memory.sh` | memory and swap, and the processes using the most |
| `listening-ports.sh` | open ports, and — as root — what holds them |
| `failed-units.sh` | failed systemd units and their last lines |
| `journal-errors.sh` | errors logged since boot |
| `pending-updates.sh` | updates waiting, from apt, dnf, yum, pacman, apk or zypper — nothing is refreshed or installed |
| `cert-expiry.sh` | when the TLS certificates on some `host:port` pairs run out |
| `docker-summary.sh` | containers, images and docker's disk use |

### Saying what a script is for

Comments at the top of a script, after the `#!`, can carry two keys:

```sh
#!/bin/sh
# description: rotate the app's logs and say how much was freed
# args: [days to keep, default 7]
```

The description is shown beside the name in the picker, and is searched too; `args` is
shown under the arguments field.

### Repositories

```toml
[scripts]
repos = [
  { name = "ops", url = "git@github.com:me/ops-scripts.git" },
  { name = "pinned", url = "https://example.com/tools.git", ref = "v1.4" },
]
```

Each repository is cloned into the cache directory and kept there. It is fetched when `!`
is pressed and the last fetch was more than five minutes ago, in the background: the picker
lists what is already there, and picks up what arrives. A fetch that fails says why in the
form, and the full git output is in the Dashboard's log.

git runs as you, with your credentials — an ssh key in the agent, or a credential helper
for https — but it is never allowed to ask: a repository that needs a password typed in
fails rather than waits. A token written into an https URL works, and is left out of
everything controlcenter writes down.

The clone is a cache that belongs to controlcenter: each fetch checks out exactly what the
repository says and throws away anything else in that directory. Keep your edits in the
repository, or in `scripts/`.

**Running a script from a repository runs whatever was last pushed to it.** The form
shows the commit and the script before anything runs, and `ref` can pin a repository to a
tag or a commit when that is not good enough.

## Shells in a container

With **run** set to `shell`, `Enter` opens an interactive shell in the container, as the
user in the **user** field. It opens where an SSH session would — a terminal window of its
own, or this terminal when `ssh.terminal` is `inline` or there is no emulator — and the
log of the container records when it opened and how it ended. On a remote engine it is
`ssh -t` to the host and `docker exec -it` there.
