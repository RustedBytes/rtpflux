#!/usr/bin/env bash
# Cross-repository test: ferrosip's sip-ua + rtpflux-client-async + rtpflux.
#
# sip-ua is a git dependency pinned by `rev` in Cargo.toml (and
# Cargo.lock). ferrosip is a private repository, fetched over SSH, or from
# FERROSIP_REPO (a mirror or a local clone holding that commit). Without
# access the test is skipped, unless REQUIRE_FERROSIP=1.
set -euo pipefail
cd "$(dirname "$0")"
upstream=ssh://git@github.com/RustedBytes/ferrosip.git
repo=${FERROSIP_REPO:-$upstream}
if ! git ls-remote -q "$repo" >/dev/null 2>&1; then
    if [ -n "${REQUIRE_FERROSIP:-}" ]; then
        echo "FAIL: cannot fetch ferrosip from $repo" >&2
        exit 1
    fi
    echo "SKIP: cannot fetch ferrosip (set FERROSIP_REPO, or REQUIRE_FERROSIP=1 to fail)"
    exit 0
fi
if [ "$repo" != "$upstream" ]; then
    export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.$repo.insteadOf" GIT_CONFIG_VALUE_0="$upstream"
fi
cargo test --locked "$@"
