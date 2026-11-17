#!/bin/sh
# description: errors the system has logged since it booted
# args: [how many lines, default 50]

count=${1:-50}

if command -v journalctl >/dev/null 2>&1; then
    # Reading the whole journal needs the adm or systemd-journal group.
    journalctl -b -p err -n "$count" --no-pager
elif [ -r /var/log/syslog ]; then
    grep -iE 'error|fail|crit|panic' /var/log/syslog | tail -n "$count"
elif [ -r /var/log/messages ]; then
    grep -iE 'error|fail|crit|panic' /var/log/messages | tail -n "$count"
else
    echo "no journal, and no syslog file this user can read" >&2
    exit 1
fi
