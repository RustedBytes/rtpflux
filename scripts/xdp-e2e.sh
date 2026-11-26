#!/usr/bin/env bash
# End-to-end test of the XDP fast path in network namespaces.
#
#   relay netns: rfx0 10.77.0.1 fd77::1  <— veth —>  peer netns: rfx1 10.77.0.2-3 fd77::2-3
#                rfx2 10.78.0.1 fd78::1  <— veth —>              rfx3 10.78.0.2    fd78::2
#
# Same-device calls are relayed with XDP_TX, calls across rfx0 and rfx2 with
# XDP_REDIRECT, over IPv4 and IPv6.
#
# XDP_MODE=native tests the driver (native) attach; the default is generic.
#
# Builds as the invoking user, then uses sudo only to create the namespaces
# and run the test binary. Everything it creates is removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" = 0 ]; then
    echo "run this as your user, not with sudo: it builds with cargo and calls sudo itself where needed" >&2
    exit 1
fi
for cmd in cargo python3 sudo ip ethtool; do
    command -v "$cmd" >/dev/null || { echo "missing command: $cmd" >&2; exit 1; }
done
case ${XDP_MODE:-generic} in generic | native) ;; *) echo "XDP_MODE must be generic or native" >&2; exit 1 ;; esac

(cd crates/rtpflux-xdp-ebpf && cargo build --release)
OBJECT="$PWD/crates/rtpflux-xdp-ebpf/target/bpfel-unknown-none/release/rtpflux-xdp"
# Build the test with its diagnostics shown, then ask cargo (now a no-op
# build) for its path: the artifact whose target is `xdp_e2e` (the crate's
# other executables, such as the daemon, are listed too).
cargo test -p rtpflux --test xdp_e2e --no-run
TEST_BIN=$(cargo test -p rtpflux --test xdp_e2e --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "xdp_e2e" and m.get("executable"):
        print(m["executable"])')
[ -x "$TEST_BIN" ] || { echo "test binary not found" >&2; exit 1; }

cleanup() {
    sudo ip netns del rtpflux-relay 2>/dev/null || true
    sudo ip netns del rtpflux-peer 2>/dev/null || true
}
trap cleanup EXIT
cleanup

sudo ip netns add rtpflux-relay
sudo ip netns add rtpflux-peer
for pair in "rfx0 rfx1" "rfx2 rfx3"; do
    read -r relay_dev peer_dev <<<"$pair"
    sudo ip link add "$relay_dev" type veth peer name "$peer_dev"
    sudo ip link set "$relay_dev" netns rtpflux-relay
    sudo ip link set "$peer_dev" netns rtpflux-peer
done
sudo ip -n rtpflux-relay addr add 10.77.0.1/24 dev rfx0
sudo ip -n rtpflux-relay addr add fd77::1/64 dev rfx0 nodad
sudo ip -n rtpflux-relay addr add 10.78.0.1/24 dev rfx2
sudo ip -n rtpflux-relay addr add fd78::1/64 dev rfx2 nodad
sudo ip -n rtpflux-peer addr add 10.77.0.2/24 dev rfx1
sudo ip -n rtpflux-peer addr add 10.77.0.3/24 dev rfx1
sudo ip -n rtpflux-peer addr add fd77::2/64 dev rfx1 nodad
sudo ip -n rtpflux-peer addr add fd77::3/64 dev rfx1 nodad
sudo ip -n rtpflux-peer addr add 10.78.0.2/24 dev rfx3
sudo ip -n rtpflux-peer addr add fd78::2/64 dev rfx3 nodad
for ns in rtpflux-relay rtpflux-peer; do sudo ip -n "$ns" link set lo up; done
for dev in rfx0 rfx2; do sudo ip -n rtpflux-relay link set "$dev" up; done
for dev in rfx1 rfx3; do sudo ip -n rtpflux-peer link set "$dev" up; done
# Locally generated packets can cross a veth with a partial UDP checksum
# (checksum offload); have the stack compute it so the relayed packets are
# checked for real.
for dev in rfx0 rfx2; do sudo ip netns exec rtpflux-relay ethtool -K "$dev" tx off >/dev/null; done
for dev in rfx1 rfx3; do sudo ip netns exec rtpflux-peer ethtool -K "$dev" tx off >/dev/null; done
# Native XDP_TX on rfx0 (and XDP_REDIRECT into rfx2) hands frames to the
# peer ends, which accept them only with NAPI enabled: attach the same
# program there (its maps are empty, so it passes everything). A real NIC
# needs nothing of the kind.
if [ "${XDP_MODE:-generic}" = native ]; then
    for dev in rfx1 rfx3; do
        sudo ip -n rtpflux-peer link set dev "$dev" xdpdrv obj "$OBJECT" sec xdp
    done
fi

sudo ip netns exec rtpflux-relay env \
    RTPFLUX_E2E_PEER_NS=/var/run/netns/rtpflux-peer \
    RTPFLUX_XDP_OBJECT="$OBJECT" \
    RTPFLUX_XDP_MODE="${XDP_MODE:-generic}" \
    RUST_LOG="${RUST_LOG:-info}" \
    "$TEST_BIN" --ignored --nocapture --test-threads=1
