#!/usr/bin/env bash
# Benchmark rtpflux at HEAD against a pinned baseline commit, on this
# machine, with the same configuration, alternating the two (A B A B …) so
# that drift (heat, other load) falls on both alike.
#
# Measured, for each:
#   - ordinary relaying (rtpflux-bench over ng): plain RTP, and SRTP on
#     both sides; delivery, one-way latency p50/p99/p99.9, relay CPU;
#   - native control (native-bench): create+destroy pairs per second, each
#     operation's p50/p95/p99, endpoint.destroyed event throughput, RSS
#     before and after (a leak shows as growth);
#   - recovery: KEEP endpoints, then a graceful stop (SIGINT) and SIGKILL
#     each, and the time until the restarted relay lists them all.
# HEAD only (the baseline has no ledger): durable keyed operations
# ([sessions] ledger, synced before each reply).
#
# Not measured here: transcoding (rtpflux-bench has no transcoding load)
# and XDP (needs root and namespaces: bench/fastpath.sh).
#
# Environment:
#   BASELINE=cac9411            the commit to compare with
#   CALLS=500,1000              rtpflux-bench steps (concurrent calls)
#   WARMUP=2 DURATION=10        seconds
#   ROUNDS=2                    A/B alternations
#   OPS=2000                    native create+destroy pairs
#   KEEP=500                    endpoints for the recovery measurement
#   WORKERS=2                   relay worker threads
#   RELAY_CPUS=0,1,8,9 CLIENT_CPUS=2,3,10,11 NATIVE_CPUS=4,12
set -euo pipefail
cd "$(dirname "$0")/.."
. bench/lib.sh
require_user
require_commands cargo git taskset

BASELINE=${BASELINE:-cac9411}
CALLS=${CALLS:-500,1000}
WARMUP=${WARMUP:-2}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-2}
OPS=${OPS:-2000}
KEEP=${KEEP:-500}
WORKERS=${WORKERS:-2}
RELAY_CPUS=${RELAY_CPUS:-0,1,8,9}
CLIENT_CPUS=${CLIENT_CPUS:-2,3,10,11}
NATIVE_CPUS=${NATIVE_CPUS:-4,12}

TMP=$(mktemp -d)
RELAY_PID=""
cleanup() {
    [ -n "$RELAY_PID" ] && kill -9 "$RELAY_PID" 2>/dev/null || true
    git worktree remove --force "$TMP/base" >/dev/null 2>&1 || true
    rm -rf "$TMP"
    finish_output
}
trap cleanup EXIT

# Both binaries: HEAD here, the baseline from a worktree.
cargo build --release -q -p rtpflux -p rtpflux-bench
cp target/release/rtpflux "$TMP/rtpflux-head"
git worktree add -q --detach "$TMP/base" "$BASELINE"
(cd "$TMP/base" && CARGO_TARGET_DIR="$TMP/base-target" cargo build --release -q -p rtpflux)
cp "$TMP/base-target/release/rtpflux" "$TMP/rtpflux-base"
HEAD_REV=$(git rev-parse --short HEAD)
BASE_REV=$(git -C "$TMP/base" rev-parse --short HEAD)

OUT="bench/results/baseline-$(date +%Y%m%d-%H%M%S).txt"
output_to "$OUT"
host_line
echo "# baseline $BASE_REV against HEAD $HEAD_REV; relay workers $WORKERS on CPUs $RELAY_CPUS,"
echo "# load on $CLIENT_CPUS, native-bench on $NATIVE_CPUS; loopback; $ROUNDS rounds, alternating"

# config DIR [EXTRA]: a relay's configuration in DIR.
config() {
    mkdir -p "$1"
    cat >"$1/rtpflux.toml" <<EOF
[control]
listen = ["127.0.0.1:2223"]
native_socket = "$1/api.sock"
[[interface]]
name = "lo"
address = "127.0.0.1"
[ports]
min = 10000
max = 30999
[sessions]
max = 5000
timeout = 600
silent_timeout = 3600
state_file = "$1/state.json"
${2:-}
[runtime]
workers = $WORKERS
[log]
level = "error"
EOF
}

# start BIN DIR: run a relay, wait for it.
start() {
    taskset -c "$RELAY_CPUS" "$1" -c "$2/rtpflux.toml" &
    RELAY_PID=$!
    wait_ng 127.0.0.1 2223 "" "$RELAY_PID"
}

# stop SIGNAL
stop() {
    kill "-$1" "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
    RELAY_PID=""
}

native() {
    taskset -c "$NATIVE_CPUS" target/release/native-bench "$@"
}

# one NAME BIN: every measurement of one binary.
one() {
    local name=$1 bin=$2 dir="$TMP/run-$1-$RANDOM"
    config "$dir"
    start "$bin" "$dir"
    for srtp in none both; do
        echo "## $name relaying, srtp = $srtp"
        taskset -c "$CLIENT_CPUS" target/release/rtpflux-bench --name "$name-srtp-$srtp" \
            --ng 127.0.0.1:2223 --pid "$RELAY_PID" --calls "$CALLS" --warmup "$WARMUP" \
            --duration "$DURATION" --threads 4 --srtp "$srtp"
    done
    echo "## $name native control"
    native --name "$name" --socket "$dir/api.sock" --pid "$RELAY_PID" --ops "$OPS"
    echo "## $name recovery"
    for signal in INT KILL; do
        native --name "$name" --socket "$dir/api.sock" --keep "$KEEP" >/dev/null
        # Let the periodic state write catch up (what SIGKILL leaves).
        sleep 2
        stop "$signal"
        # Timed from the relay's launch until it lists them all.
        taskset -c "$RELAY_CPUS" "$bin" -c "$dir/rtpflux.toml" &
        RELAY_PID=$!
        native --name "$name-after-SIG$signal" --socket "$dir/api.sock" --expect "$KEEP"
        # Clean the endpoints up for the next measurement.
        stop INT
        rm -f "$dir/state.json"
        start "$bin" "$dir"
    done
    stop INT
    rm -rf "$dir"
}

for round in $(seq 1 "$ROUNDS"); do
    echo
    echo "# round $round"
    one "base-$BASE_REV" "$TMP/rtpflux-base"
    one "head-$HEAD_REV" "$TMP/rtpflux-head"
done

# Durable operations, HEAD only.
echo
echo "# durable keyed operations (HEAD only: [sessions] ledger)"
dir="$TMP/durable"
config "$dir" "ledger = \"$dir/ledger.jsonl\""
start "$TMP/rtpflux-head" "$dir"
native --name "head-$HEAD_REV-durable" --socket "$dir/api.sock" --pid "$RELAY_PID" --ops "$OPS" --keyed
stop INT
echo "saved to $OUT"
