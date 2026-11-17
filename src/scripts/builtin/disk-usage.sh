#!/bin/sh
# description: filesystems by use, and the biggest directories under a path
# args: [path, default /] [how many, default 15]

dir=${1:-/}
count=${2:-15}

# Filesystems on a device, and whatever is mounted on / — which in a
# container is an overlay, and the only one that matters there.
real_df() { df -P "$@" | awk 'NR == 1 || $1 ~ /^\// || $6 == "/"'; }

echo "── filesystems"
real_df -h

echo
echo "── inodes"
real_df -i 2>/dev/null || echo "df cannot report inodes here"

echo
echo "── largest directories under $dir (this filesystem only)"
if [ ! -d "$dir" ]; then
    echo "$dir is not a directory" >&2
    exit 1
fi
# -x stays on one filesystem, so / does not wander into /proc or a mount.
# Directories this user cannot read are skipped rather than reported.
du -x -k -d 1 "$dir" 2>/dev/null | sort -rn | head -n "$((count + 1))" |
    awk '{ s = $1; u = "K"; if (s >= 1024) { s /= 1024; u = "M" } if (s >= 1024) { s /= 1024; u = "G" }
           $1 = ""; printf "%8.1f%s %s\n", s, u, substr($0, 2) }'
