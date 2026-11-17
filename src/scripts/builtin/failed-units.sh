#!/bin/sh
# description: systemd units that have failed, and the last lines of each

if ! command -v systemctl >/dev/null 2>&1; then
    echo "no systemd here (systemctl was not found)"
    exit 0
fi

failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{ print $1 }')
if [ -z "$failed" ]; then
    echo "no failed units"
    exit 0
fi
systemctl list-units --state=failed --no-pager
for unit in $failed; do
    echo
    echo "── $unit"
    journalctl -u "$unit" -n 10 --no-pager 2>/dev/null ||
        systemctl status "$unit" --no-pager -n 10
done
exit 1
