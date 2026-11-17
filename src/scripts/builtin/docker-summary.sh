#!/bin/sh
# description: containers, images and the disk docker is using

if ! command -v docker >/dev/null 2>&1; then
    echo "docker was not found" >&2
    exit 1
fi
docker ps --all --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' || exit 1
echo
docker system df
echo
echo "── dangling images"
docker images --filter dangling=true --quiet | wc -l
