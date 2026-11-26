#!/usr/bin/env bash
# rtpflux alone with plain RTP, SRTP on one side (the relay decrypts or
# encrypts each packet) and SRTP on both sides (it decrypts and re-encrypts
# each packet), on loopback, pinned like bench/compare.sh.
#
#   CALLS=250,500,1000,2000 REPEAT=3 RELAY_CPUS=0,1,4,5 CLIENT_CPUS=2,3,6,7
#
# bench/compare.sh with SRTP=a compares SRTP on one side with rtpengine.
set -euo pipefail
cd "$(dirname "$0")/.."
. bench/lib.sh

CALLS=${CALLS:-250,500,1000,2000}
REPEAT=${REPEAT:-3}
RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
CLIENT_CPUS=${CLIENT_CPUS:-2,3,6,7}
WORKERS=4
require_commands cargo dd git taskset timeout

cargo build --release -q -p rtpflux -p rtpflux-bench
OUT="bench/results/$(date +%Y%m%d-%H%M%S)-srtp-modes.txt"
TMP=$(mktemp -d)
PID=""
cleanup() {
    [ -n "$PID" ] && kill -INT "$PID" 2>/dev/null || true
    rm -rf "$TMP"
    finish_output
}
trap cleanup EXIT

cat >"$TMP/rtpflux.toml" <<EOT
[control]
listen = ["127.0.0.1:2223"]
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
[runtime]
workers = $WORKERS
[log]
level = "error"
EOT
taskset -c "$RELAY_CPUS" target/release/rtpflux -c "$TMP/rtpflux.toml" &
PID=$!
wait_ng 127.0.0.1 2223 "" "$PID"

output_to "$OUT"
host_line
echo "# relay workers: $WORKERS on CPUs $RELAY_CPUS, client on CPUs $CLIENT_CPUS, ports 10000-30999, loopback"
echo "# rtpflux $(git rev-parse --short HEAD)"
for mode in none a both; do
    taskset -c "$CLIENT_CPUS" target/release/rtpflux-bench --name rtpflux --ng 127.0.0.1:2223 --pid "$PID" \
        --calls "$CALLS" --warmup 2 --duration 10 --threads 4 --repeat "$REPEAT" --srtp "$mode"
    echo
done
kill -INT "$PID"
wait "$PID" || true
PID=""
echo "saved to $OUT"
