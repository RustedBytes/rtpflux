#!/usr/bin/env bash
# Run every scenario in order, then print a summary and every finding.
# Needs a release build first:
#   cargo build --release -p rtpflux -p rtpflux-bench
# Options are passed to every scenario:
#   --quick    shorter runs: the load test (08), no 30 s consent loss (18),
#              fewer packets in the long calls (22)
#   --browser  also drive headless Firefox through the relay (03, 11)
#   --docker   also run the real SIP stacks in Docker (23)
# Exits non-zero when a check failed (findings alone do not fail).
set -u
cd "$(dirname "$0")" || exit 1
command -v python3 >/dev/null || { echo "missing command: python3" >&2; exit 1; }
log=$(mktemp)
trap 'rm -f "$log"' EXIT
status=0
summary=()
findings=()
for dir in [0-9][0-9]-*/; do
    dir=${dir%/}
    # Shown as it runs, and kept for the summary.
    python3 "$dir/run.py" "$@" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    summary+=("$(grep -E '^--- ' "$log" | tail -1)")
    while IFS= read -r line; do
        [ -n "$line" ] && findings+=("[$dir] ${line#  NOTE  }")
    done < <(grep -E '^  NOTE  ' "$log")
    [ "$rc" -ne 0 ] && status=1
done
echo
echo "=== summary ==="
printf '%s\n' "${summary[@]}"
echo
echo "=== findings (${#findings[@]}) ==="
if [ "${#findings[@]}" -gt 0 ]; then
    printf -- '- %s\n' "${findings[@]}"
fi
exit $status
