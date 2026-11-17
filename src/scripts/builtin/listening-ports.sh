#!/bin/sh
# description: which ports are open, and — as root — what holds them
#
# Without root the process column is only filled in for your own processes.

if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null || ss -tuln
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null || netstat -tuln
else
    # Neither tool: decode the kernel's own tables. Ports are hex, state 0A
    # is LISTEN for TCP; UDP has no listening state, so every bound socket.
    for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
        [ -r "$f" ] || continue
        proto=${f##*/}
        awk -v proto="$proto" 'NR > 1 && (proto ~ /udp/ || $4 == "0A") {
            split($2, a, ":"); printf "%-5s %s\n", proto, a[2] }' "$f"
    done | while read -r proto hex; do
        echo "$proto $((0x$hex))"
    done | sort -u -k2n
fi
