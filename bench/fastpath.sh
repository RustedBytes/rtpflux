#!/usr/bin/env bash
# Fast-path benchmark: rtpflux (XDP) against rtpengine (xt_RTPENGINE kernel
# forwarding), with each relay's userspace mode as a reference, all in the
# same topology:
#
#   relay netns rfx-relay: rfx0 10.77.0.1/24  <— veth —>  peer netns rfx-peer: rfx1 10.77.0.2, .3
#
# The relays run in rfx-relay pinned to RELAY_CPUS; the load generator runs
# in rfx-relay (ng over loopback) with its endpoints in rfx-peer, pinned to
# CLIENT_CPUS. Forwarding done in the kernel shows up as softirq / host CPU
# rather than relay process CPU, so both are reported.
#
# Builds as the invoking user, then uses sudo for: the namespaces, loading
# the kernel module (bench/rtpengine-kmod.sh builds it), copying the
# rtpengine image into root's podman storage, and running the relays and
# the generator. Everything is removed on exit (the module is unloaded if
# this script loaded it).
#
#   CALLS=1000,2000,4000 WARMUP=4 DURATION=10 REPEAT=3 WORKERS=4
#   RELAY_CPUS=0,1,4,5 CLIENT_CPUS=2,3,6,7 CLIENT_THREADS=4
#   XDP_MODE=generic|native   RTPENGINE_IMAGE=...
#
# Each configuration gets a freshly built topology, checked with ping
# before the relay starts, so one run cannot leave the next with a broken
# device (a native XDP attach on veth once did).
set -euo pipefail
cd "$(dirname "$0")/.."
. bench/lib.sh
require_user

CALLS=${CALLS:-1000,2000,4000}
WARMUP=${WARMUP:-4}
DURATION=${DURATION:-10}
REPEAT=${REPEAT:-3}
WORKERS=${WORKERS:-4}
RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
CLIENT_CPUS=${CLIENT_CPUS:-2,3,6,7}
CLIENT_THREADS=${CLIENT_THREADS:-4}
XDP_MODE=${XDP_MODE:-generic}
IMAGE=${RTPENGINE_IMAGE:-localhost/speech-engine-rtpengine-audit:latest}
PORT_MIN=10000
PORT_MAX=30999
RELAY_NS=rfx-relay
PEER_NS=rfx-peer
CONTAINER=rtpflux-fastpath-rtpengine

case $XDP_MODE in generic | native) ;; *) echo "XDP_MODE must be generic or native" >&2; exit 1 ;; esac
require_commands cargo dd git podman sudo ip ethtool taskset ping timeout

# ---- build (as the user) ----
cargo build --release -q -p rtpflux -p rtpflux-bench
(cd crates/rtpflux-xdp-ebpf && cargo build --release -q)
OBJECT="$PWD/crates/rtpflux-xdp-ebpf/target/bpfel-unknown-none/release/rtpflux-xdp"
[ -f bench/kmod/xt_RTPENGINE.ko ] || ./bench/rtpengine-kmod.sh

OUT="bench/results/fastpath-$(date +%Y%m%d-%H%M%S).txt"
TMP=$(mktemp -d)
LOADED_MODULE=0
RELAY_PID=""

cleanup() {
    if [ -n "$RELAY_PID" ]; then
        sudo kill -INT "$RELAY_PID" 2>/dev/null || true
    fi
    sudo podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    del_netns "$RELAY_NS" "$PEER_NS"
    if [ "$LOADED_MODULE" = 1 ]; then
        sleep 1
        sudo rmmod xt_RTPENGINE 2>/dev/null || echo "note: xt_RTPENGINE still in use; rmmod it later" >&2
    fi
    stop_sudo_keepalive
    rm -rf "$TMP"
    finish_output
}
trap cleanup EXIT

# ---- root setup ----
# A full run takes longer than sudo's default credential timeout.
sudo_keepalive
if ! lsmod | grep -q '^xt_RTPENGINE'; then
    sudo insmod bench/kmod/xt_RTPENGINE.ko
    LOADED_MODULE=1
fi
if ! sudo podman image exists "$IMAGE"; then
    echo "copying $IMAGE into root's podman storage"
    podman save "$IMAGE" | sudo podman load >/dev/null
fi

# A fresh topology per configuration.
topology() {
    if [ "$XDP_MODE" = native ]; then
        veth_topology "$RELAY_NS" "$PEER_NS" "$OBJECT"
    else
        veth_topology "$RELAY_NS" "$PEER_NS"
    fi
}

bench() { # name ng-port pid
    sudo ip netns exec "$RELAY_NS" taskset -c "$CLIENT_CPUS" target/release/rtpflux-bench \
        --name "$1" --ng "127.0.0.1:$2" --pid "$3" \
        --peer-netns "/var/run/netns/$PEER_NS" --a-addr 10.77.0.2 --b-addr 10.77.0.3 \
        --calls "$CALLS" --warmup "$WARMUP" --duration "$DURATION" --repeat "$REPEAT" \
        --threads "$CLIENT_THREADS"
}

rtpflux_run() { # name xdp(true|false)
    topology
    cat >"$TMP/rtpflux.toml" <<EOF
[control]
listen = ["127.0.0.1:2223"]
[[interface]]
name = "veth"
address = "10.77.0.1"
[ports]
min = $PORT_MIN
max = $PORT_MAX
[sessions]
max = 5000
timeout = 600
silent_timeout = 3600
[runtime]
workers = $WORKERS
[xdp]
enabled = $2
devices = ["rfx0"]
mode = "$XDP_MODE"
object = "$OBJECT"
[log]
level = "warn"
EOF
    rm -f "$TMP/pid"
    sudo ip netns exec "$RELAY_NS" sh -c "echo \$\$ > '$TMP/pid'; exec taskset -c '$RELAY_CPUS' target/release/rtpflux -c '$TMP/rtpflux.toml'" &
    local launcher=$!
    # The pid file appears as soon as the shell starts.
    while [ ! -s "$TMP/pid" ]; do
        kill -0 "$launcher" 2>/dev/null || { echo "rtpflux did not start" >&2; exit 1; }
        sleep 0.1
    done
    RELAY_PID=$(cat "$TMP/pid")
    wait_ng 127.0.0.1 2223 "$RELAY_NS" "$RELAY_PID"
    bench "$1" 2223 "$RELAY_PID"
    sudo kill -INT "$RELAY_PID"
    wait "$launcher" || true
    RELAY_PID=""
    echo
}

rtpengine_run() { # name table
    topology
    sudo podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    sudo podman run -d --rm --name "$CONTAINER" --privileged --userns=host \
        --network "ns:/var/run/netns/$RELAY_NS" --entrypoint rtpengine "$IMAGE" \
        --foreground --log-stderr --log-level=3 --table="$2" \
        --interface=10.77.0.1 --listen-ng=127.0.0.1:2224 \
        --port-min=$PORT_MIN --port-max=$PORT_MAX --num-threads="$WORKERS" \
        --delete-delay=0 --timeout=600 --endpoint-learning=off >/dev/null
    wait_ng 127.0.0.1 2224 "$RELAY_NS"
    local pid
    pid=$(sudo podman inspect -f '{{.State.Pid}}' "$CONTAINER")
    sudo taskset -a -cp "$RELAY_CPUS" "$pid" >/dev/null
    local sampler=""
    if [ "$2" != "-1" ]; then
        # Sample the kernel table during the first measurement window.
        # shellcheck disable=SC2024 # $TMP is ours: only the read needs root
        (sleep $((WARMUP + 5)); sudo grep -c '^local' "/proc/rtpengine/$2/list" >"$TMP/kstreams" 2>/dev/null || true) &
        sampler=$!
    fi
    bench "$1" 2224 "$pid"
    if [ -n "$sampler" ]; then
        wait "$sampler"
        echo "# streams in kernel table $2 during the first step: $(cat "$TMP/kstreams" 2>/dev/null || echo unknown)"
    fi
    sudo podman rm -f "$CONTAINER" >/dev/null
    echo
}

output_to "$OUT"
host_line
echo "# veth between netns $RELAY_NS and $PEER_NS; relay on CPUs $RELAY_CPUS, client on CPUs $CLIENT_CPUS; XDP mode $XDP_MODE"
echo "# rtpflux $(git rev-parse --short HEAD); rtpengine $(podman run --rm --entrypoint rtpengine "$IMAGE" --version 2>&1 | head -1)"
echo
rtpengine_run "rtpengine userspace" -1
rtpengine_run "rtpengine kernel (xt_RTPENGINE)" 0
rtpflux_run "rtpflux userspace" false
rtpflux_run "rtpflux XDP ($XDP_MODE)" true
echo "saved to $OUT"
