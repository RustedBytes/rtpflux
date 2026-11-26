# shellcheck shell=bash
# Helpers shared by the benchmark scripts (sourced, not run).

# Refuse to run as root: the scripts build with cargo as the user and call
# sudo themselves where needed.
require_user() {
    if [ "$(id -u)" = 0 ]; then
        echo "run this as your user, not with sudo: it builds with cargo and calls sudo itself where needed" >&2
        exit 1
    fi
}

# Exit with a message unless every named command is installed.
require_commands() {
    local cmd missing=()
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "missing commands: ${missing[*]}" >&2
        exit 1
    fi
}

# The first line of every result file: date, host, CPU and kernel.
host_line() {
    echo "# $(date -Is) on $(hostname): $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), $(nproc) CPUs, kernel $(uname -r)"
}

# Send stdout to the terminal and to FILE. Unlike `{ ...; } | tee FILE`,
# the script keeps running in this shell, so variables it sets (such as a
# relay's pid) are seen by its EXIT trap. Call finish_output at the end so
# the last lines reach FILE before the script exits.
TEE_PID=""
output_to() {
    mkdir -p "$(dirname "$1")"
    exec 3>&1
    exec > >(tee "$1")
    TEE_PID=$!
}
finish_output() {
    [ -n "$TEE_PID" ] || return 0
    exec 1>&3 3>&-
    wait "$TEE_PID" 2>/dev/null || true
    TEE_PID=""
}

# ng_ping HOST PORT: one ng ping; succeeds when the relay answers pong.
ng_ping() {
    local reply=""
    exec 4<>"/dev/udp/$1/$2" || return 1
    printf 'rfxping d7:command4:pinge' >&4
    # One read of the whole datagram (bash's read takes a byte at a time,
    # and each read of a UDP socket consumes a datagram).
    reply=$(timeout 0.3 dd bs=512 count=1 status=none <&4 2>/dev/null) || true
    exec 4>&-
    [[ $reply == "rfxping d6:result4:ponge" ]]
}

# wait_ng HOST PORT [NETNS] [PID]: wait up to 30 s for a relay to answer an
# ng ping (inside network namespace NETNS when given, via sudo), failing
# early when process PID (when given) exits.
wait_ng() {
    local host=$1 port=$2 netns=${3:-} pid=${4:-}
    local as_root=() deadline=$((SECONDS + 30))
    [ -n "$netns" ] && as_root=(sudo)
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -n "$netns" ]; then
            sudo ip netns exec "$netns" bash -c "$(declare -f ng_ping); ng_ping $host $port" && return 0
        else
            ng_ping "$host" "$port" && return 0
        fi
        if [ -n "$pid" ] && ! "${as_root[@]}" kill -0 "$pid" 2>/dev/null; then
            echo "the relay (pid $pid) exited before answering on $host:$port" >&2
            return 1
        fi
        sleep 0.2
    done
    echo "no ng answer on $host:$port after 30 s" >&2
    return 1
}

# Keep sudo's credentials fresh for a run longer than its timeout; the
# loop ends with the script.
SUDO_KEEPALIVE_PID=""
sudo_keepalive() {
    sudo -v
    (while kill -0 "$$" 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 50; done) &
    SUDO_KEEPALIVE_PID=$!
}
stop_sudo_keepalive() {
    [ -n "$SUDO_KEEPALIVE_PID" ] && kill "$SUDO_KEEPALIVE_PID" 2>/dev/null
    SUDO_KEEPALIVE_PID=""
}

# veth_topology RELAY_NS PEER_NS [XDP_OBJECT]: a fresh pair of namespaces
# joined by a veth, rfx0 10.77.0.1/24 in RELAY_NS and rfx1 10.77.0.2, .3 in
# PEER_NS, checked with ping. With XDP_OBJECT, attach it natively to rfx1:
# native XDP_TX on rfx0 hands frames to rfx1, which accepts them only with
# NAPI enabled (its maps are empty, so it passes everything). A real NIC
# needs nothing of the kind.
veth_topology() {
    local relay=$1 peer=$2 object=${3:-} ns addr
    sudo ip netns del "$relay" 2>/dev/null || true
    sudo ip netns del "$peer" 2>/dev/null || true
    sudo ip netns add "$relay"
    sudo ip netns add "$peer"
    sudo ip link add rfx0 type veth peer name rfx1
    sudo ip link set rfx0 netns "$relay"
    sudo ip link set rfx1 netns "$peer"
    sudo ip -n "$relay" addr add 10.77.0.1/24 dev rfx0
    sudo ip -n "$peer" addr add 10.77.0.2/24 dev rfx1
    sudo ip -n "$peer" addr add 10.77.0.3/24 dev rfx1
    for ns in "$relay" "$peer"; do sudo ip -n "$ns" link set lo up; done
    sudo ip -n "$relay" link set rfx0 up
    sudo ip -n "$peer" link set rfx1 up
    # Full UDP checksums on the wire (no partial offload across the veth).
    sudo ip netns exec "$relay" ethtool -K rfx0 tx off >/dev/null
    sudo ip netns exec "$peer" ethtool -K rfx1 tx off >/dev/null
    if [ -n "$object" ]; then
        sudo ip -n "$peer" link set dev rfx1 xdpdrv obj "$object" sec xdp
    fi
    for addr in 10.77.0.2 10.77.0.3; do
        if ! sudo ip netns exec "$relay" ping -c 1 -W 1 "$addr" >/dev/null; then
            echo "topology check failed: $addr unreachable" >&2
            return 1
        fi
    done
}

# Delete the namespaces made by veth_topology.
del_netns() {
    local ns
    for ns in "$@"; do sudo ip netns del "$ns" 2>/dev/null || true; done
}
