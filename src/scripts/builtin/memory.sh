#!/bin/sh
# description: memory and swap, and the processes using the most
# args: [how many, default 10]

count=${1:-10}

if command -v free >/dev/null 2>&1; then
    free -h 2>/dev/null || free
else
    grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo
fi

echo
echo "── top $count by resident memory"
if ps -eo rss,pid,user,comm --sort=-rss >/dev/null 2>&1; then
    ps -eo rss,pid,user,comm --sort=-rss | head -n "$((count + 1))" |
        awk 'NR == 1 { printf "%9s %7s %-12s %s\n", "RSS", "PID", "USER", "COMMAND"; next }
             { printf "%8.1fM %7s %-12s %s\n", $1 / 1024, $2, $3, $4 }'
else
    # busybox ps has no --sort: read the same numbers out of /proc.
    for p in /proc/[0-9]*; do
        rss=$(awk '/^VmRSS:/ { print $2 }' "$p/status" 2>/dev/null)
        [ -n "$rss" ] && echo "$rss ${p#/proc/} $(cat "$p/comm" 2>/dev/null)"
    done | sort -rn | head -n "$count" |
        awk '{ printf "%8.1fM %7s %s\n", $1 / 1024, $2, $3 }'
fi
