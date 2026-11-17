#!/bin/sh
# description: who and what this is — system, uptime, load, memory, disks
#
# Safe anywhere: every tool is checked for before it is used, so the same
# script says something useful on a server and in a busybox container.

have() { command -v "$1" >/dev/null 2>&1; }
# Filesystems on a device, and whatever is mounted on / — which in a
# container is an overlay, and the only one that matters there.
real_df() { df -P "$@" | awk 'NR == 1 || $1 ~ /^\// || $6 == "/"'; }

echo "host      $(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)"
echo "user      $(id 2>/dev/null)"
if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "system    ${PRETTY_NAME:-$NAME}"
fi
echo "kernel    $(uname -srm)"
if [ -r /proc/uptime ]; then
    up=$(cut -d. -f1 /proc/uptime)
    echo "uptime    $((up / 86400))d $((up % 86400 / 3600))h $((up % 3600 / 60))m"
fi
[ -r /proc/loadavg ] && echo "load      $(cut -d' ' -f1-3 /proc/loadavg)"
have nproc && echo "cpus      $(nproc)"
if [ -f /.dockerenv ] || grep -qs 'docker\|containerd\|kubepods' /proc/1/cgroup; then
    echo "container yes"
fi

echo
echo "── memory"
if have free; then
    free -h 2>/dev/null || free
else
    grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
fi

echo
echo "── disks"
real_df -h
