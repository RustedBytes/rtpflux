#!/usr/bin/env python3
"""A real WebRTC endpoint through rtpflux: headless Firefox <-> plain RTP.

Starts the daemon, serves a page in which Firefox (fake microphone) makes a
WebRTC offer (ICE, DTLS-SRTP, rtcp-mux, BUNDLE), sends it through `ng`
`offer` towards a plain RTP/AVP "phone" played by this script, answers with
the phone's SDP through `ng` `answer`, and checks:

* Firefox's ICE and DTLS complete against the relay (a full ICE agent, the
  controlled one; with --lite an ICE-lite one; DTLS server), and the relay's
  SDP says which (`a=ice-options` with ice2, or `a=ice-lite`);
* the phone receives Firefox's audio as plain RTP (decrypted by the relay);
* Firefox receives the phone's RTP (encrypted by the relay) and reports it
  in getStats().

With --video Firefox also sends a fake camera: two media sections, which
it offers in a BUNDLE group. The relay accepts the group towards the
browser (one ICE/DTLS transport for both sections, media sorted by payload
type) and offers the phone separate ports; the check then requires exactly
one connected transport and audio and video both ways.

--max-bundle asks the browser for `bundlePolicy: 'max-bundle'` (every
section but the first `bundle-only`); --chrome PATH runs Chrome or
Chromium instead of Firefox.

--no-sandbox (with --chrome) starts Chrome without its sandbox, as
Playwright does, where the sandbox cannot start.

--lite makes the relay an ICE-lite agent towards the browser (`ICE-lite:
backward`) instead of a full one.

--subscribe checks a WebRTC subscriber instead: two plain "phones" played
by this script make a call through the relay (PCMU), and the browser
subscribes to one of them (`subscribe request` with UDP/TLS/RTP/SAVPF,
its answer through `subscribe answer`); the check requires the browser's
ICE and DTLS to complete against the relay (ICE-lite, DTLS server or
client as the browser answers) and its audio to arrive.

Usage: scripts/webrtc-firefox.py [--video] [--max-bundle] [--lite | --subscribe] [--chrome PATH [--no-sandbox]]   (builds nothing: run `cargo
build --release -p rtpflux` first). Needs firefox. Exits non-zero on failure.
"""

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = os.environ.get("RTPFLUX_BIN", os.path.join(ROOT, "target", "release", "rtpflux"))
NG = ("127.0.0.1", 22299)


def lan_address():
    """The address of the default route's interface (where Firefox gathers
    its host candidates); a real relay is reached on such an address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    finally:
        s.close()
TIMEOUT = 40
VIDEO = "--video" in sys.argv[1:]
MAX_BUNDLE = "--max-bundle" in sys.argv[1:]
LITE = "--lite" in sys.argv[1:]
SUBSCRIBE = "--subscribe" in sys.argv[1:]
# --chrome PATH: run Chrome/Chromium (headless) instead of Firefox.
_args = sys.argv[1:]
CHROME = None
if "--chrome" in _args:
    _at = _args.index("--chrome")
    if _at + 1 >= len(_args) or _args[_at + 1].startswith("--"):
        sys.exit("--chrome needs the browser's path")
    CHROME = _args.pop(_at + 1)
# --no-sandbox: start Chrome without its sandbox, as Playwright does by
# default; needed where unprivileged user namespaces are restricted
# (Ubuntu 23.10+ AppArmor). Only for this local test page.
NO_SANDBOX = "--no-sandbox" in _args
# A misspelt flag must not run another test (and pass): refuse it.
_unknown = sorted(set(_args) - {"--video", "--max-bundle", "--lite", "--subscribe", "--chrome", "--no-sandbox"})
if _unknown:
    sys.exit(f"unknown argument {_unknown[0]!r}; usage: see the top of {sys.argv[0]}")
if LITE and SUBSCRIBE:
    sys.exit("--lite and --subscribe are separate checks: run them one at a time")


# ---------------------------------------------------------------- bencode

def benc(v):
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(benc(x) for x in v) + b"e"
    if isinstance(v, dict):
        items = sorted((k.encode() if isinstance(k, str) else k, x) for k, x in v.items())
        return b"d" + b"".join(benc(k) + benc(x) for k, x in items) + b"e"
    raise TypeError(v)


def bdec(b, i=0):
    c = b[i:i + 1]
    if c == b"i":
        j = b.index(b"e", i)
        return int(b[i + 1:j]), j + 1
    if c == b"l":
        i, out = i + 1, []
        while b[i:i + 1] != b"e":
            x, i = bdec(b, i)
            out.append(x)
        return out, i + 1
    if c == b"d":
        i, out = i + 1, {}
        while b[i:i + 1] != b"e":
            k, i = bdec(b, i)
            x, i = bdec(b, i)
            out[k] = x
        return out, i + 1
    j = b.index(b":", i)
    n = int(b[i:j])
    return b[j + 1:j + 1 + n], j + 1 + n


_cookie = [0]
_cookie_lock = threading.Lock()


def ng_reply(cmd, timeout=3.0):
    """Send one ng command; its reply dictionary."""
    with _cookie_lock:
        _cookie[0] += 1
        cookie = b"c%d" % _cookie[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(cookie + b" " + benc(cmd), NG)
        while True:
            data, _ = s.recvfrom(65535)
            if data.partition(b" ")[0] == cookie:
                return bdec(data, len(cookie) + 1)[0]


def ng(cmd):
    reply = ng_reply(cmd)
    if reply.get(b"result") != b"ok":
        raise RuntimeError("ng %s: %r" % (cmd["command"], reply))
    return reply.get(b"sdp", b"").decode()


def wait_for_daemon(daemon, log):
    """Until the daemon answers a ping; exits with its log if it stops or
    stays silent."""
    deadline = time.time() + 5
    while time.time() < deadline:
        if daemon.poll() is not None:
            break
        try:
            if ng_reply({"command": "ping"}, timeout=0.3).get(b"result") == b"pong":
                return
        except OSError:  # not listening yet (a timeout is an OSError too)
            time.sleep(0.05)
    with open(log) as f:
        tail = f.read()[-2000:]
    sys.exit("rtpflux did not start (%s):\n%s" % (
        "exited %d" % daemon.returncode if daemon.poll() is not None else "no answer to ping", tail))


# ---------------------------------------------------------------- the phone

class Phone:
    """A plain RTP endpoint: counts what arrives, sends its own audio."""

    def __init__(self, kind="audio"):
        self.kind = kind
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((lan_address(), 0))
        self.sock.settimeout(0.02)
        self.port = self.sock.getsockname()[1]
        self.received = 0
        self.bad = 0
        self.relay = None
        self.pt = 0
        self.stop = False
        # PCMU silence (--subscribe) instead of an Opus frame.
        self.pcmu = False

    def run(self):
        seq, ts = 1000, 0
        next_send = time.time()
        while not self.stop:
            try:
                data, src = self.sock.recvfrom(4096)
                if len(data) >= 12 and data[0] >> 6 == 2:
                    self.received += 1
                    if self.relay is None:
                        self.relay = src
                else:
                    self.bad += 1
            except socket.timeout:
                pass
            if self.relay is not None and time.time() >= next_send:
                next_send += 0.02
                # 20 ms of "audio": a valid Opus TOC (silence) frame; for
                # video, a minimal VP8 payload descriptor and key frame tag.
                ssrc = b"\x12\x34\x56\x78" if self.kind == "audio" else b"\x87\x65\x43\x21"
                hdr = bytes([0x80, self.pt, seq >> 8 & 255, seq & 255]) + ts.to_bytes(4, "big") + ssrc
                body = b"\xf8\xff\xfe" if self.kind == "audio" else b"\x10\x00\x00\x9d\x01\x2a"
                if self.pcmu:
                    body = b"\xff" * 160
                self.sock.sendto(hdr + body, self.relay)
                step = 160 if self.pcmu else (960 if self.kind == "audio" else 3000)
                seq, ts = (seq + 1) & 0xFFFF, (ts + step) & 0xFFFFFFFF


PAGE = """<!doctype html><meta charset=utf-8><title>rtpflux webrtc</title><script>
async function main() {
  const report = (o) => fetch('/report', {method: 'POST', body: JSON.stringify(o)});
  try {
    const pc = new RTCPeerConnection({bundlePolicy: MAX_BUNDLE ? 'max-bundle' : 'balanced'});
    const stream = await navigator.mediaDevices.getUserMedia({audio: true, video: VIDEO});
    stream.getTracks().forEach(t => pc.addTrack(t, stream));
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise(r => { if (pc.iceGatheringState === 'complete') r();
      pc.onicegatheringstatechange = () => pc.iceGatheringState === 'complete' && r();
      setTimeout(r, 2000); });
    const answer = await (await fetch('/offer', {method: 'POST', body: pc.localDescription.sdp})).text();
    await pc.setRemoteDescription({type: 'answer', sdp: answer});
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const s = {conn: pc.connectionState, ice: pc.iceConnectionState, sent: {}, received: {}, dtls: []};
      (await pc.getStats()).forEach(x => {
        if (x.type === 'outbound-rtp') s.sent[x.kind] = x.packetsSent;
        if (x.type === 'inbound-rtp') s.received[x.kind] = x.packetsReceived;
        if (x.type === 'transport') s.dtls.push(x.dtlsState);
      });
      await report(s);
    }
  } catch (e) { await report({error: String(e)}); }
}
main();
</script>"""

# --subscribe: the browser answers the relay's subscription offer.
PAGE_SUBSCRIBE = """<!doctype html><meta charset=utf-8><title>rtpflux subscriber</title><script>
async function main() {
  const report = (o) => fetch('/report', {method: 'POST', body: JSON.stringify(o)});
  try {
    const pc = new RTCPeerConnection();
    const offer = await (await fetch('/subscribe', {method: 'POST', body: ''})).text();
    await pc.setRemoteDescription({type: 'offer', sdp: offer});
    await pc.setLocalDescription(await pc.createAnswer());
    await new Promise(r => { if (pc.iceGatheringState === 'complete') r();
      pc.onicegatheringstatechange = () => pc.iceGatheringState === 'complete' && r();
      setTimeout(r, 2000); });
    await fetch('/answer', {method: 'POST', body: pc.localDescription.sdp});
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const s = {conn: pc.connectionState, ice: pc.iceConnectionState, sent: {}, received: {}, dtls: []};
      (await pc.getStats()).forEach(x => {
        if (x.type === 'inbound-rtp') s.received[x.kind] = x.packetsReceived;
        if (x.type === 'transport') s.dtls.push(x.dtlsState);
      });
      await report(s);
    }
  } catch (e) { await report({error: String(e)}); }
}
main();
</script>"""


def plain_call(phones):
    """A plain PCMU call between phones A and B through the relay; each
    phone then sends to the relay's port facing it."""
    lan = lan_address()
    sdp = lambda port: ("v=0\r\no=phone 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
                        "m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n" % (lan, lan, port))
    to_b = ng({"command": "offer", "call-id": "sub-1", "from-tag": "a", "sdp": sdp(phones["a"].port),
               "flags": ["trust-address"]})
    to_a = ng({"command": "answer", "call-id": "sub-1", "from-tag": "a", "to-tag": "b",
               "sdp": sdp(phones["b"].port), "flags": ["trust-address"]})
    port = lambda s: int(s.split("\r\nm=audio ")[1].split()[0])
    phones["a"].relay = (lan, port(to_a))
    phones["b"].relay = (lan, port(to_b))



def main():
    if not os.path.exists(DAEMON):
        sys.exit("build the daemon first: cargo build --release -p rtpflux")
    if CHROME is None and not shutil.which("firefox"):
        sys.exit("firefox not found")
    tmp = tempfile.mkdtemp()
    conf = os.path.join(tmp, "rtpflux.toml")
    with open(conf, "w") as f:
        f.write('[control]\nlisten = ["%s:%d"]\n[[interface]]\nname = "lan"\naddress = "%s"\n'
                "[ports]\nmin = 41000\nmax = 41099\n[sessions]\nmax = 10\n[runtime]\nworkers = 1\n"
                '[log]\nlevel = "debug"\n' % (NG[0], NG[1], lan_address()))
    log = os.path.join(tmp, "daemon.log")
    daemon = subprocess.Popen([DAEMON, "-c", conf], stderr=open(log, "w"))
    ff = http_srv = profile = None
    phones = {}
    try:
        wait_for_daemon(daemon, log)
        if SUBSCRIBE:
            phones = {"a": Phone("audio"), "b": Phone("audio")}
            for ph in phones.values():
                ph.pcmu = True
            plain_call(phones)
        else:
            phones = {"audio": Phone("audio")}
            if VIDEO:
                phones["video"] = Phone("video")
        for ph in phones.values():
            threading.Thread(target=ph.run, daemon=True).start()
        reports, errors = [], []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, body, ctype="text/plain"):
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(body.encode())

            def do_GET(self):
                if SUBSCRIBE:
                    self.reply(PAGE_SUBSCRIBE, "text/html")
                    return
                page = PAGE.replace("MAX_BUNDLE", "true" if MAX_BUNDLE else "false")
                self.reply(page.replace("VIDEO", "true" if VIDEO else "false"), "text/html")

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"])).decode()
                if self.path in ("/subscribe", "/answer"):
                    try:
                        if self.path == "/subscribe":
                            offer = ng({"command": "subscribe request", "call-id": "sub-1", "from-tag": "a",
                                        "to-tag": "browser", "transport-protocol": "UDP/TLS/RTP/SAVPF"})
                            with open(os.path.join(tmp, "sdp.txt"), "w") as f:
                                f.write("--- subscription offer\n%s\n" % offer)
                            self.reply(offer)
                        else:
                            with open(os.path.join(tmp, "sdp.txt"), "a") as f:
                                f.write("--- browser answer\n%s\n" % body)
                            ng({"command": "subscribe answer", "call-id": "sub-1", "to-tag": "browser", "sdp": body})
                            self.reply("ok")
                    except Exception as e:  # report and fail the run
                        errors.append(str(e))
                        self.reply("")
                    return
                if self.path == "/offer":
                    try:
                        offer = {"command": "offer", "call-id": "ff-1", "from-tag": "browser", "sdp": body,
                                 "transport-protocol": "RTP/AVP", "replace": ["origin"]}
                        if LITE:
                            offer["ICE-lite"] = "backward"
                        to_phone = ng(offer)
                        lan = lan_address()
                        answer = "v=0\r\no=phone 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n" % (lan, lan)
                        sections = to_phone.split("\r\nm=")[1:]
                        for sec in sections:
                            lines = ("m=" + sec).split("\r\n")
                            kind, relay_port = lines[0][2:].split()[0], int(lines[0].split()[1])
                            codec = "opus/48000" if kind == "audio" else "VP8/90000"
                            pt = next(ln.split()[0].split(":")[1] for ln in lines
                                      if ln.startswith("a=rtpmap:") and codec in ln)
                            mid = next((ln for ln in lines if ln.startswith("a=mid:")), None)
                            ph = phones[kind]
                            ph.pt = int(pt)
                            ph.relay = (lan, relay_port)
                            rtpmap = "opus/48000/2" if kind == "audio" else "VP8/90000"
                            answer += ("m=%s %d RTP/AVP %s\r\na=rtpmap:%s %s\r\n%sa=rtcp-mux\r\na=sendrecv\r\n"
                                       % (kind, ph.port, pt, pt, rtpmap, (mid + "\r\n") if mid else ""))
                        to_browser = ng({"command": "answer", "call-id": "ff-1", "from-tag": "browser",
                                         "to-tag": "phone", "sdp": answer})
                        with open(os.path.join(tmp, "sdp.txt"), "w") as f:
                            f.write("--- browser offer\n%s\n--- to phone\n%s\n--- phone answer\n%s\n--- to browser\n%s\n"
                                    % (body, to_phone, answer, to_browser))
                        self.reply(to_browser)
                    except Exception as e:  # report and fail the run
                        errors.append(str(e))
                        self.reply("")
                else:
                    reports.append(json.loads(body))
                    self.reply("ok")

        http_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:%d/" % http_srv.server_address[1]
        if CHROME:
            profile = os.path.join(tmp, "chrome-profile")
            ff = subprocess.Popen(
                [CHROME, "--headless=new", "--no-first-run", "--no-default-browser-check",
                 "--user-data-dir=" + profile, "--use-fake-device-for-media-stream",
                 "--use-fake-ui-for-media-stream", "--remote-debugging-port=0"]
                + (["--no-sandbox"] if NO_SANDBOX else []) + [url],
                stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, "browser.log"), "w"))
        else:
            profile = os.path.expanduser("~/snap/firefox/common/rtpflux-webrtc-profile")
            if not os.path.isdir(os.path.expanduser("~/snap/firefox")):
                profile = os.path.join(tmp, "profile")
            shutil.rmtree(profile, ignore_errors=True)
            os.makedirs(profile)
            with open(os.path.join(profile, "user.js"), "w") as f:
                for k, v in {
                    "media.navigator.streams.fake": True,
                    "media.navigator.permission.disabled": True,
                    "media.peerconnection.ice.loopback": True,
                    "media.peerconnection.ice.obfuscate_host_addresses": False,
                    "browser.shell.checkDefaultBrowser": False,
                    "browser.aboutwelcome.enabled": False,
                    "datareporting.policy.dataSubmissionEnabled": False,
                    "toolkit.telemetry.reportingpolicy.firstRun": False,
                    "browser.startup.homepage_override.mstone": "ignore",
                }.items():
                    f.write("user_pref(%s, %s);\n" % (json.dumps(k), json.dumps(v)))
            ff = subprocess.Popen(["firefox", "--headless", "--no-remote", "--profile", profile, url],
                                  stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, "browser.log"), "w"))
        deadline = time.time() + TIMEOUT
        while time.time() < deadline and len(reports) < 12 and not errors:
            if reports and "error" in reports[-1]:
                break
            time.sleep(0.5)
    finally:
        # Whatever failed: nothing is left running (a daemon left on the ng
        # port would make the next run fail).
        for ph in phones.values():
            ph.stop = True
        for proc in (ff, daemon):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        if http_srv is not None:
            http_srv.shutdown()
    last = reports[-1] if reports else {}
    print("browser:", last)
    for kind, ph in phones.items():
        print("phone %s: %d RTP packets received from the relay, %d not RTP" % (kind, ph.received, ph.bad))
    print("logs and SDP in", tmp)
    if SUBSCRIBE:
        # The subscriber receives A's audio; the call goes on meanwhile.
        ok = (not errors and last.get("conn") == "connected"
              and last.get("ice") in ("connected", "completed")
              and len(last.get("dtls", [])) == 1 and all(d == "connected" for d in last["dtls"])
              and last.get("received", {}).get("audio", 0) > 30
              and all(ph.received > 30 and ph.bad == 0 for ph in phones.values()))
    else:
        # The relay's answer to the browser: the ICE mode asked for.
        to_browser = open(os.path.join(tmp, "sdp.txt")).read().split("--- to browser")[-1]
        mode_ok = ("a=ice-lite" in to_browser) if LITE else ("ice2" in to_browser and "a=ice-lite" not in to_browser)
        if not mode_ok:
            errors.append("the relay's SDP to the browser is not %s ICE" % ("lite" if LITE else "full"))
        ok = (not errors and last.get("conn") == "connected"
              and last.get("ice") in ("connected", "completed")
              and len(last.get("dtls", [])) == 1 and all(d == "connected" for d in last["dtls"])
              and all(last.get("sent", {}).get(k, 0) > 30 and last.get("received", {}).get(k, 0) > 30 for k in phones)
              and all(ph.received > 30 and ph.bad == 0 for ph in phones.values()))
    for e in errors:
        print("error:", e)
    print("PASS" if ok else "FAIL")
    if profile is not None:
        shutil.rmtree(profile, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
