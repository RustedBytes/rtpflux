#!/usr/bin/env bash
# Benchmark rtpflux against rtpengine (userspace forwarding, loopback).
#
# Both relays get the same port range (outside the ephemeral range used by
# the load generator), the same number of worker threads, and the same ng
# flags. rtpengine runs from a container image, rootless, host network,
# with its kernel module disabled (--table=-1).
#
# Environment:
#   CALLS=250,500,1000,2000,4000   steps (concurrent calls; 100 pps each)
#   WARMUP=2 DURATION=10           seconds
#   WORKERS=4                      relay worker threads (both relays)
#   CLIENT_THREADS=4               load generator threads
#   REPEAT=3                       windows per step (median reported)
#   RELAY_CPUS=0,1,4,5             CPUs for the relay (both relays)
#   CLIENT_CPUS=2,3,6,7            CPUs for the load generator
#   RTPENGINE_IMAGE=localhost/speech-engine-rtpengine-audit:latest
#   RECEIVE=io_uring,recvmmsg      rtpflux's runtime.receive, one run each
#
# The default CPU sets give the relay and the load generator two physical
# cores each (CPUs N and N+4 are hyper-thread siblings on the reference
# machine; check `lscpu -e` on yours).
set -euo pipefail
cd "$(dirname "$0")/.."
. bench/lib.sh

CALLS=${CALLS:-250,500,1000,2000,4000}
WARMUP=${WARMUP:-2}
DURATION=${DURATION:-10}
WORKERS=${WORKERS:-4}
CLIENT_THREADS=${CLIENT_THREADS:-4}
REPEAT=${REPEAT:-3}
SRTP=${SRTP:-none}   # none | a (SRTP on side A, plain on B) | both
RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
CLIENT_CPUS=${CLIENT_CPUS:-2,3,6,7}
IMAGE=${RTPENGINE_IMAGE:-localhost/speech-engine-rtpengine-audit:latest}
RECEIVE=${RECEIVE:-io_uring,recvmmsg}
PORT_MIN=10000
PORT_MAX=30999
CONTAINER=rtpflux-bench-rtpengine

case $SRTP in none | a | both) ;; *) echo "SRTP must be none, a or both" >&2; exit 1 ;; esac
require_commands cargo dd git podman taskset timeout

cargo build --release -q -p rtpflux -p rtpflux-bench
OUT="bench/results/$(date +%Y%m%d-%H%M%S)$( [ "$SRTP" = none ] || echo "-srtp-$SRTP").txt"
TMP=$(mktemp -d)
RTPFLUX_PID=""
cleanup() {
    if [ -n "$RTPFLUX_PID" ]; then
        kill -INT "$RTPFLUX_PID" 2>/dev/null || true
    fi
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$TMP"
    finish_output
}
trap cleanup EXIT

bench() {
    taskset -c "$CLIENT_CPUS" target/release/rtpflux-bench --name "$1" --ng "$2" --pid "$3" \
        --calls "$CALLS" --warmup "$WARMUP" --duration "$DURATION" --threads "$CLIENT_THREADS" \
        --repeat "$REPEAT" --srtp "$SRTP"
}

output_to "$OUT"
host_line
echo "# relay workers: $WORKERS on CPUs $RELAY_CPUS, client on CPUs $CLIENT_CPUS, ports $PORT_MIN-$PORT_MAX, loopback"
echo

for receive in ${RECEIVE//,/ }; do
    cat >"$TMP/rtpflux.toml" <<EOF
[control]
listen = ["127.0.0.1:2223"]
[[interface]]
name = "lo"
address = "127.0.0.1"
[ports]
min = $PORT_MIN
max = $PORT_MAX
[sessions]
max = 5000
timeout = 600
silent_timeout = 3600
[runtime]
workers = $WORKERS
receive = "$receive"
[log]
level = "error"
EOF
    taskset -c "$RELAY_CPUS" target/release/rtpflux -c "$TMP/rtpflux.toml" &
    RTPFLUX_PID=$!
    wait_ng 127.0.0.1 2223 "" "$RTPFLUX_PID"
    echo "# rtpflux $(git rev-parse --short HEAD), receive = $receive"
    bench "rtpflux-$receive" 127.0.0.1:2223 "$RTPFLUX_PID"
    kill -INT "$RTPFLUX_PID"
    wait "$RTPFLUX_PID" || true
    RTPFLUX_PID=""
    echo
done

podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman run -d --rm --name "$CONTAINER" --network host --entrypoint rtpengine "$IMAGE" \
    --foreground --log-stderr --log-level=3 --table=-1 \
    --interface=127.0.0.1 --listen-ng=127.0.0.1:2224 \
    --port-min=$PORT_MIN --port-max=$PORT_MAX --num-threads="$WORKERS" \
    --delete-delay=0 --timeout=600 --endpoint-learning=off >/dev/null
wait_ng 127.0.0.1 2224
PID=$(podman inspect -f '{{.State.Pid}}' "$CONTAINER")
taskset -a -cp "$RELAY_CPUS" "$PID" >/dev/null
echo "# rtpengine $(podman run --rm --entrypoint rtpengine "$IMAGE" --version 2>&1 | head -1)"
bench rtpengine 127.0.0.1:2224 "$PID"
echo "saved to $OUT"
