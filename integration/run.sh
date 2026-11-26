#!/usr/bin/env bash
# Integration bench: real calls through Kamailio's and OpenSIPS's rtpengine
# modules and rtpflux (see compose.yaml). Builds the images, places a call
# to a SIPp callee, one to FreeSWITCH, a G.722 one, one through OpenSIPS,
# one through ferrosip (when it can be fetched) and a ZRTP call between two
# linphones, and checks for all but the last that:
#   1. the call completes (SIPp's exit status);
#   2. the called party got rtpflux's address in the SDP, not the caller's;
#   3. the audio went through rtpflux both ways (the echo doubles it);
#   4. rtpflux answered every ng command (no ng errors);
#   5. the call was deleted in rtpflux at BYE;
# and for the ZRTP call that both phones are secure with the same short
# authentication string and that rtpflux relayed their ZRTP packets.
# Needs Docker with Compose. Leaves nothing running; logs are in out/.
#
#   integration/run.sh            build, run, check, tear down
#   KEEP=1 integration/run.sh     leave the bench running afterwards
#   RUST_LOG=debug integration/run.sh   rtpflux's log level (default info;
#                                 its log is in out/compose.log)
set -euo pipefail
cd "$(dirname "$0")"

# Compose v2 (docker compose) or v1 (docker-compose).
if docker compose version >/dev/null 2>&1; then
    compose() { docker compose -p rtpflux-integration "$@"; }
else
    compose() { docker-compose -p rtpflux-integration "$@"; }
fi
fail() { echo "FAIL: $*" >&2; exit 1; }

rm -rf out && mkdir -p out && chmod 777 out

# ferrosip (a private repository): at the commit in ferrosip.ref, from
# ferrosip-src (CI checks it out there), or cloned over SSH. Without access
# its call is skipped, unless REQUIRE_FERROSIP=1.
ferrosip_ref=$(cat ferrosip.ref)
ferrosip=
if [ -d ferrosip-src/.git ] || git clone -q "${FERROSIP_REPO:-git@github.com:RustedBytes/ferrosip.git}" ferrosip-src 2>/dev/null; then
    if [ "$(git -C ferrosip-src rev-parse HEAD 2>/dev/null)" != "$ferrosip_ref" ]; then
        git -C ferrosip-src fetch -q origin "$ferrosip_ref" 2>/dev/null || true
        git -C ferrosip-src checkout -q --detach "$ferrosip_ref" || fail "ferrosip: commit $ferrosip_ref not found"
    fi
    ferrosip=1
    echo "ferrosip at ${ferrosip_ref:0:7}"
elif [ -n "${REQUIRE_FERROSIP:-}" ]; then
    fail "ferrosip: cannot fetch the repository"
else
    echo "SKIP ferrosip: cannot fetch the repository (set FERROSIP_REPO, or REQUIRE_FERROSIP=1 to fail)"
fi
profiles=()
[ -n "$ferrosip" ] && profiles=(--profile ferrosip)
cleanup() {
    compose logs --no-color >out/compose.log 2>&1 || true
    if [ -z "${KEEP:-}" ]; then compose --profile call --profile ferrosip down -v --remove-orphans >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

compose "${profiles[@]}" build
compose "${profiles[@]}" up -d rtpflux kamailio kamailio-fs kamailio-g722 kamailio-zrtp opensips freeswitch zrtp-b uas ${ferrosip:+ferrosip}

metric() {
    # The value of a metric (summed over its labels), from inside the
    # bench network.
    compose exec -T uas bash -c "exec 3<>/dev/tcp/172.30.89.10/9101 && printf 'GET /metrics HTTP/1.0\r\n\r\n' >&3 && cat <&3" \
        | awk -v m="$1" '$1 == m || index($1, m "{") == 1 { s += $2 } END { print s + 0 }'
}

# Kamailio pings rtpflux at start; wait until both answer.
for _ in $(seq 1 60); do
    if [ "$(metric rtpflux_workers)" != 0 ]; then break; fi
    sleep 1
done
[ "$(metric rtpflux_workers)" != 0 ] || fail "rtpflux is not up"

# SIPp's g711a.pcap holds 236 RTP packets (7 s); the callee echoes each,
# so rtpflux forwards 472. One direction alone would be 236 (a callee that
# got the caller's own address would send its echo around rtpflux).
expected=472

# call NAME PROXY VIA CALLEE: one call through VIA (a proxy at PROXY) to
# CALLEE, checked. A SIPp callee also logged the offer it got.
call() {
    local name=$1 proxy=$2 via=$3 callee=$4
    local before after forwarded errors calls answer_sdp offer_sdp
    before=$(metric rtpflux_packets_forwarded_total)
    errors=$(metric rtpflux_ng_errors_total)
    echo "== $name: uac -> $via $proxy -> $callee, media through rtpflux"
    PROXY=$proxy CALL=$name compose --profile call run --rm uac >/dev/null \
        || fail "$name: the call did not complete (see out/uac-$name-errors.log)"
    sleep 2
    after=$(metric rtpflux_packets_forwarded_total)
    forwarded=$((after - before))

    answer_sdp=$(grep -A40 'SIP/2.0 200 OK' "out/uac-$name-messages.log" | grep '^c=IN' | head -1 || true)
    echo "caller saw: ${answer_sdp:-nothing}"
    grep -q '^c=IN IP4 172.30.89.10' <<<"$answer_sdp" || fail "$name: the caller's SDP does not point at rtpflux"
    if [ "$callee" = sipp ]; then
        # The INVITE of this call (its Call-ID ends with the name).
        offer_sdp=$(awk -v id="@172.30.89.13-$name" '/^INVITE sip:/ { inv = 1; mine = 0 }
            inv && index($0, "Call-ID:") == 1 && index($0, id) { mine = 1 }
            inv && mine && /^c=IN/ { print; exit }' out/uas-messages.log)
        echo "callee saw: ${offer_sdp:-nothing}"
        grep -q '^c=IN IP4 172.30.89.10' <<<"$offer_sdp" || fail "$name: the callee's SDP does not point at rtpflux"
    fi

    echo "packets forwarded by rtpflux: $forwarded of $expected"
    [ "$forwarded" -ge $((expected * 95 / 100)) ] || fail "$name: too few packets forwarded (expected the audio both ways)"

    [ "$(metric rtpflux_ng_errors_total)" = "$errors" ] || fail "$name: rtpflux answered ng commands with errors"
    calls=$(metric rtpflux_calls)
    [ "$calls" = 0 ] || fail "$name: the call is still in rtpflux after BYE ($calls)"
}

call sipp 172.30.89.11 kamailio sipp

# FreeSWITCH takes a few seconds to start its SIP profile.
for _ in $(seq 1 60); do
    if compose exec -T freeswitch fs_cli -x "sofia status" 2>/dev/null | grep -q "rtpflux.*RUNNING"; then break; fi
    sleep 1
done
compose exec -T freeswitch fs_cli -x "sofia status" 2>/dev/null | grep -q "rtpflux.*RUNNING" \
    || fail "FreeSWITCH's rtpflux profile did not start"
call freeswitch 172.30.89.15 kamailio freeswitch
# Transcoding: the caller's PCMA becomes G.722 for FreeSWITCH (offered
# nothing else) and its G.722 echo PCMA again. The call only connects if
# FreeSWITCH takes rtpflux's G.722 offer; the echo only comes back if each
# side decodes the other's G.722.
call g722 172.30.89.18 kamailio freeswitch-g722
grep -A30 'SIP/2.0 200 OK' out/uac-g722-messages.log | grep -q '^m=audio [0-9]* RTP/AVP 8 ' \
    || fail "g722: the caller was not answered with its own PCMA"
echo "caller answered with PCMA; FreeSWITCH was offered G.722 only"

# OpenSIPS: its rtpengine module drives rtpflux as Kamailio's does; the
# same call and checks as through Kamailio.
call opensips 172.30.89.19 opensips sipp

# ferrosip: its media module drives rtpflux as Kamailio's rtpengine module
# does; the same call and checks as through Kamailio.
if [ -n "$ferrosip" ]; then
    call ferrosip 172.30.89.17 ferrosip sipp
fi

# ZRTP end to end: two linphones (ZRTP mandatory) through Kamailio and
# rtpflux. Both must reach the secure state with the same short
# authentication string, which they could not if the relay had touched
# the key agreement; rtpflux must have relayed the ZRTP packets.
echo "== zrtp: linphone -> kamailio 172.30.89.16 -> linphone, ZRTP through rtpflux"
zrtp_before=$(metric rtpflux_zrtp_forwarded_total)
for _ in $(seq 1 30); do
    grep -q "LinphoneGlobalOn" out/zrtp-b.log 2>/dev/null && break
    sleep 1
done
compose --profile call run --rm zrtp-a >/dev/null
sleep 2
sas() { grep -o "SAS is [a-z0-9]*" "out/$1.log" | tail -1 | cut -d' ' -f3; }
for side in zrtp-a zrtp-b; do
    grep -q "Entering state secure" "out/$side.log" || fail "zrtp: $side did not reach the ZRTP secure state (see out/$side.log)"
done
sas_a=$(sas zrtp-a)
sas_b=$(sas zrtp-b)
echo "short authentication strings: $sas_a / $sas_b"
if [ -z "$sas_a" ] || [ "$sas_a" != "$sas_b" ]; then
    fail "zrtp: the two sides' SAS differ"
fi
zrtp=$(( $(metric rtpflux_zrtp_forwarded_total) - zrtp_before ))
echo "ZRTP packets forwarded by rtpflux: $zrtp"
[ "$zrtp" -gt 0 ] || fail "zrtp: rtpflux relayed no ZRTP packets"
[ "$(metric rtpflux_calls)" = 0 ] || fail "zrtp: the call is still in rtpflux after BYE"

echo "PASS"
