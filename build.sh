#!/usr/bin/env bash
#
# Build controlcenter for this machine and for Windows, into dist/.
#
# The Linux half is an ordinary release build. The Windows half runs in a
# container: cross-compiling needs a rust toolchain with the Windows target and
# a mingw linker, and on Arch the package that provides those (rustup) replaces
# the rust package — so the toolchain lives in an image instead of on the
# machine. Nothing is installed and nothing in the repository is written to.
#
#   ./build.sh              both
#   ./build.sh linux        just this machine
#   ./build.sh windows      just the .exe
#   ./build.sh test         the Windows unit tests, run here under wine
#
# The .exe is the *gnu* target. Releases ship the msvc one, built on a real
# Windows runner by .github/workflows/release.yml — this is for debugging a
# Windows code path here, not for handing to anyone.

set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
dist="$root/dist"

# Rebuilt into a volume rather than into the container, so a second run only
# compiles what changed instead of the whole dependency tree again.
image="${CONTROLCENTER_WINBUILD_IMAGE:-controlcenter-winbuild}"
volume="controlcenter-winbuild-target"
registry="controlcenter-winbuild-cargo"
target="x86_64-pc-windows-gnu"

what="${1:-both}"
case "$what" in
    both | linux | windows | test) ;;
    *)
        echo "usage: $0 [both|linux|windows|test]" >&2
        exit 2
        ;;
esac

say() { printf '\n\033[1m── %s\033[0m\n' "$*"; }

mkdir -p "$dist"

# ---------------------------------------------------------------------------
# This machine
# ---------------------------------------------------------------------------

if [ "$what" = both ] || [ "$what" = linux ]; then
    say "linux · cargo build --release"
    cargo build --release --locked --manifest-path "$root/Cargo.toml"
    cp "$root/target/release/controlcenter" "$dist/controlcenter"
fi

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

if [ "$what" != linux ]; then
    if ! docker info >/dev/null 2>&1; then
        echo "build.sh: docker is not running, so the Windows build cannot be made." >&2
        echo "          \`./build.sh linux\` builds the rest." >&2
        exit 1
    fi

    # Built once and kept. `docker build` reuses its own layers, so a second
    # run of this is a no-op that prints a line.
    say "windows · toolchain image ($image)"
    docker build -q -t "$image" - >/dev/null <<'DOCKERFILE'
FROM rust:latest
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-pc-windows-gnu
DOCKERFILE

    # The source is read-only and the build writes only to the volumes, so the
    # container cannot leave a root-owned file behind in the working tree; the
    # artifacts it does hand back are given the caller's ownership.
    in_container() {
        docker run --rm \
            -v "$root":/src:ro \
            -v "$volume":/target \
            -v "$registry":/usr/local/cargo/registry \
            -v "$dist":/out \
            -e CARGO_TARGET_DIR=/target \
            -e RUSTFLAGS="-D warnings" \
            -e OWNER="$(id -u):$(id -g)" \
            -e TARGET="$target" \
            -w /src \
            "$image" bash -euc "$1"
    }

    if [ "$what" = test ]; then
        say "windows · cargo test --no-run --target $target"
        in_container '
            cargo test --no-run --locked --target "$TARGET" 2>&1 | tee /tmp/t
            exe=$(grep -oE "/target/[^ )]*deps/controlcenter-[0-9a-f]+\.exe" /tmp/t | head -1)
            cp "$exe" /out/tests.exe
            chown "$OWNER" /out/tests.exe
        '
        say "windows · running the tests here"
        if command -v wine >/dev/null 2>&1; then
            # wine runs the Windows code paths against Windows semantics, which
            # is what catches a socket or a path that only misbehaves there. It
            # is not Windows: what it cannot answer for is anything that talks
            # to a real service — DPAPI, icacls, taskkill, PowerShell.
            WINEDEBUG=-all wine "$dist/tests.exe" 2>&1 | grep -vE '^[0-9a-f]{4}:'
        else
            echo "wine is not installed; the test binary is at $dist/tests.exe"
        fi
    else
        say "windows · cargo build --release --target $target"
        in_container '
            cargo build --release --locked --target "$TARGET"
            cp "/target/$TARGET/release/controlcenter.exe" /out/
            chown "$OWNER" /out/controlcenter.exe
        '
    fi
fi

say "dist"
ls -lh "$dist"
