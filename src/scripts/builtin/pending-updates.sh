#!/bin/sh
# description: package updates waiting to be installed, from the last refresh
#
# Nothing is refreshed and nothing is installed — both need root, and this
# only looks. The list is as fresh as the package manager's last metadata.

have() { command -v "$1" >/dev/null 2>&1; }

if have apt; then
    apt list --upgradable 2>/dev/null | tail -n +2
    [ -f /var/run/reboot-required ] && echo "a reboot is required"
elif have dnf || have yum; then
    # check-update exits 100 when there is something to update: that is the
    # answer, not a failure.
    if have dnf; then dnf -q --cacheonly check-update; else yum -q --cacheonly check-update; fi
    s=$?
    [ $s -eq 100 ] && exit 0
    exit $s
elif have checkupdates; then
    # pacman-contrib's: a scratch copy of the database, so no root needed.
    checkupdates
elif have pacman; then
    pacman -Qu
elif have apk; then
    apk version -l '<' 2>/dev/null
elif have zypper; then
    zypper --no-refresh -q list-updates
else
    echo "no package manager this script knows" >&2
    exit 1
fi
