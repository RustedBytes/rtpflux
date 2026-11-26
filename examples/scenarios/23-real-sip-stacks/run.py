#!/usr/bin/env python3
"""Real SIP stacks instead of this harness: the repository's integration
bench (integration/run.sh, Docker Compose) places calls through
Kamailio's rtpengine module and rtpflux: to a SIPp callee, to
FreeSWITCH, a G.722 call, ferrosip when its repository is reachable, and
a ZRTP call between two linphones. Opt in with --docker: it builds
images (minutes the first time)."""

import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import ROOT, main  # noqa: E402

BENCH = os.path.join(ROOT, "integration", "run.sh")


def scenario(r):
    if "--docker" not in sys.argv:
        r.skip("real SIP stacks (Kamailio, SIPp, FreeSWITCH, linphone): run with --docker")
        return
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        r.skip("Docker is not available")
        return
    res = subprocess.run(["bash", BENCH], capture_output=True, text=True, timeout=3600)
    out = res.stdout + res.stderr
    with open(os.path.join(ROOT, "integration", "out", "scenario-23.log"), "w") as f:
        f.write(out)
    calls = re.findall(r"^== (.+)$", out, re.M)
    for c in calls:
        print(f"        call: {c}")
    # The bench prints PASS last on stdout (Compose's progress goes to stderr).
    r.check(res.returncode == 0 and res.stdout.rstrip().endswith("PASS"),
            f"integration/run.sh: {len(calls)} real calls through Kamailio and rtpflux pass",
            "\n".join(ln for ln in out.splitlines() if ln.startswith(("FAIL", "SKIP")))[-500:] or out[-500:])
    for ln in out.splitlines():
        if ln.startswith("SKIP"):
            r.skip(ln[5:].strip())
    sas = re.search(r"short authentication strings: (\S+) / (\S+)", out)
    if sas:
        r.check(sas.group(1) == sas.group(2), f"ZRTP between two linphones through rtpflux: SAS {sas.group(1)} on both")
    zrtp = re.search(r"ZRTP packets forwarded by rtpflux: (\d+)", out)
    if zrtp:
        r.check(int(zrtp.group(1)) > 0, f"rtpflux relayed {zrtp.group(1)} ZRTP packets of that call")
    print("        full log: integration/out/scenario-23.log (and the bench's own logs in integration/out/)")


if __name__ == "__main__":
    main(scenario)
