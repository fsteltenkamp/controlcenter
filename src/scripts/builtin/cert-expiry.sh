#!/bin/sh
# description: when the TLS certificates on some host:port pairs run out
# args: host[:port] … (default: localhost:443)
#
# Checked from where the script runs, so on an SSH host this sees what the
# host sees — including names only its own resolver knows.

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl was not found" >&2
    exit 1
fi
[ $# -eq 0 ] && set -- localhost:443

status=0
for target in "$@"; do
    case $target in
        *:*) host=${target%:*} port=${target##*:} ;;
        *) host=$target port=443 ;;
    esac
    end=$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null |
        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "$end" ]; then
        echo "$host:$port  no certificate (nothing listening, or not TLS)"
        status=1
        continue
    fi
    if echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null |
        openssl x509 -noout -checkend $((14 * 86400)) >/dev/null 2>&1; then
        echo "$host:$port  ok — until $end"
    else
        echo "$host:$port  EXPIRES WITHIN 14 DAYS — $end"
        status=1
    fi
done
exit $status
