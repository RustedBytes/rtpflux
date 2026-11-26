#!/usr/bin/env bash
# Why does rtpengine not use its kernel module in bench/fastpath.sh?
# Starts rtpengine with --table=0 --no-fallback and verbose logging in the
# fast-path topology, relays 20 calls, and prints what the kernel side
# shows. Needs sudo; cleans up afterwards (does not unload the module).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
. bench/lib.sh
require_user
require_commands cargo dd podman sudo ip ethtool nft ping timeout

IMAGE=${RTPENGINE_IMAGE:-localhost/speech-engine-rtpengine-audit:latest}
RELAY_NS=rfx-relay
PEER_NS=rfx-peer
C=rtpflux-kernel-check

cargo build --release -q -p rtpflux-bench || exit 1
cleanup() {
    sudo podman rm -f "$C" "$C-hostnet" >/dev/null 2>&1
    del_netns "$RELAY_NS" "$PEER_NS"
}
trap cleanup EXIT
cleanup

sudo -v
[ -f bench/kmod/xt_RTPENGINE.ko ] || ./bench/rtpengine-kmod.sh
lsmod | grep -q '^xt_RTPENGINE' || sudo insmod bench/kmod/xt_RTPENGINE.ko
echo "== module"
lsmod | grep -E '^xt_RTPENGINE' || echo "not loaded"
echo "== /proc/rtpengine on the host"
sudo ls -la /proc/rtpengine 2>&1 | head
sudo cat /proc/rtpengine/version 2>&1

veth_topology "$RELAY_NS" "$PEER_NS" || exit 1

sudo podman run -d --name "$C" --privileged --userns=host \
    --network "ns:/var/run/netns/$RELAY_NS" --entrypoint rtpengine "$IMAGE" \
    --foreground --log-stderr --log-level=6 --table=0 --no-fallback \
    --interface=10.77.0.1 --listen-ng=127.0.0.1:2224 \
    --port-min=10000 --port-max=30999 --num-threads=2 \
    --delete-delay=0 --timeout=600 --endpoint-learning=off >/dev/null
# It may refuse to start (the point of this script): wait briefly only.
for _ in $(seq 1 10); do
    [ "$(sudo podman inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || break
    sudo ip netns exec "$RELAY_NS" bash -c "$(declare -f ng_ping); ng_ping 127.0.0.1 2224" && break
    sleep 0.5
done
echo "== container state"
sudo podman ps -a --filter "name=$C" --format '{{.Names}} {{.Status}}'
echo "== /proc/rtpengine inside the container"
sudo podman exec "$C" ls -la /proc/rtpengine 2>&1 | head
echo "== nftables in the relay namespace"
sudo ip netns exec "$RELAY_NS" nft list ruleset 2>&1 | head -40
PID=$(sudo podman inspect -f '{{.State.Pid}}' "$C" 2>/dev/null)

if [ -n "$PID" ] && [ "$PID" != 0 ]; then
    (sleep 6
     echo "== kernel table 0 during the run (first lines)"
     sudo head -20 /proc/rtpengine/0/list 2>&1
     echo "== kernel table 0 lines: $(sudo cat /proc/rtpengine/0/list 2>/dev/null | wc -l)") &
    sudo ip netns exec "$RELAY_NS" target/release/rtpflux-bench --name check --ng 127.0.0.1:2224 \
        --pid "$PID" --peer-netns "/var/run/netns/$PEER_NS" --a-addr 10.77.0.2 --b-addr 10.77.0.3 \
        --calls 20 --warmup 3 --duration 5 --threads 1
    wait
fi
echo "== rtpengine log: kernel, nftables, errors (full log if it exited)"
if [ "$(sudo podman inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ]; then
    sudo podman logs "$C" 2>&1 | grep -iE "kernel|table|nft|iptables|fallback|err|warn|crit|push" | grep -v "DEBUG" | head -40
else
    sudo podman logs "$C" 2>&1 | tail -40
fi

# If rtpengine refused to start, probe why nftables is denied.
if [ "$(sudo podman inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" != true ]; then
    RUN=(sudo podman run --rm --privileged --userns=host --entrypoint sh)
    echo "== probe: capabilities, user namespace, LSM inside the container (relay netns)"
    # shellcheck disable=SC2016 # expanded by the container's shell
    "${RUN[@]}" --network "ns:/var/run/netns/$RELAY_NS" "$IMAGE" -c \
        'grep -E "^Cap(Eff|Bnd)|^NoNewPrivs|^Seccomp:" /proc/self/status; echo "uid_map: $(cat /proc/self/uid_map)"; echo "apparmor: $(cat /proc/self/attr/current 2>/dev/null)"' 2>&1
    echo "== probe: nft inside the container (relay netns)"
    "${RUN[@]}" --network "ns:/var/run/netns/$RELAY_NS" "$IMAGE" -c \
        'command -v nft >/dev/null && nft list tables 2>&1 || echo "no nft in the image"' 2>&1
    echo "== probe: nft on the host in the relay netns (as root)"
    sudo ip netns exec "$RELAY_NS" nft list tables 2>&1 && echo "host nft ok"
    echo "== probe: rtpengine kernel mode on the host network instead of the netns"
    sudo podman run -d --name "$C-hostnet" --privileged --userns=host --network host \
        --entrypoint rtpengine "$IMAGE" --foreground --log-stderr --log-level=6 --table=0 \
        --no-fallback --interface=127.0.0.1 --listen-ng=127.0.0.1:2299 --port-min=31000 \
        --port-max=31099 --num-threads=1 >/dev/null
    sleep 2
    sudo podman ps -a --filter "name=$C-hostnet" --format '{{.Names}} {{.Status}}'
    sudo podman logs "$C-hostnet" 2>&1 | grep -iE "nft|kernel|fatal|crit|err" | head -8
    sudo nft list ruleset 2>/dev/null | grep -iE "rtpengine" | head -5
    # Stop gracefully: rtpengine removes its nftables rules on SIGTERM.
    sudo podman stop -t 10 "$C-hostnet" >/dev/null 2>&1
    sudo podman rm -f "$C-hostnet" >/dev/null 2>&1
    if sudo nft list ruleset 2>/dev/null | grep -qi rtpengine; then
        echo "note: rtpengine left nftables rules on the host; remove with: sudo nft list ruleset | grep -n rtpengine"
    fi
    echo "== podman security"
    sudo podman info --format '{{.Host.Security}}' 2>&1
fi
