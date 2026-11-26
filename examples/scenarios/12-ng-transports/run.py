#!/usr/bin/env python3
"""The ng protocol over streams, as proxies use it besides UDP: TCP
(messages back to back), HTTP (`POST /ng`, `/ng-plain` with bencode or
JSON) and WebSocket (`ng.rtpengine.com`, `ng-plain.rtpengine.com`, what
Kamailio's `rtpengine_sock "ws://..."` speaks). Includes the RFC 6455
frame errors that must fail the connection, and many clients at once."""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from harness import Relay, Sdp, base_config, benc, main, sdp  # noqa: E402

NG = 20312
HTTP = NG + 100
PORTS = (29800, 29999)


# ------------------------------------------------------------- WebSocket

class Ws:
    """A minimal WebSocket client (RFC 6455): enough to send well-formed
    and deliberately malformed frames."""

    def __init__(self, port, protocol, path="/"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                        f"Sec-WebSocket-Protocol: {protocol}\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.s.recv(1)
            if not chunk:
                break
            head += chunk
        self.head = head.decode(errors="replace")
        want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.ok = " 101 " in self.head.split("\r\n")[0] and want in self.head

    def frame(self, payload: bytes, opcode=2, fin=True, mask=True, rsv=0, long_len=False):
        b0 = (0x80 if fin else 0) | (rsv << 4) | opcode
        n = len(payload)
        if long_len:  # a length not in its shortest form
            hdr = struct.pack("!BBQ", b0, (0x80 if mask else 0) | 127, n)
        elif n < 126:
            hdr = struct.pack("!BB", b0, (0x80 if mask else 0) | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", b0, (0x80 if mask else 0) | 126, n)
        else:
            hdr = struct.pack("!BBQ", b0, (0x80 if mask else 0) | 127, n)
        if mask:
            k = os.urandom(4)
            payload = bytes(c ^ k[i % 4] for i, c in enumerate(payload))
            hdr += k
        self.s.sendall(hdr + payload)

    def recv(self, timeout=3.0):
        """(opcode, payload) of the next frame, or None when closed."""
        self.s.settimeout(timeout)

        def read(n):
            buf = b""
            while len(buf) < n:
                c = self.s.recv(n - len(buf))
                if not c:
                    raise EOFError
                buf += c
            return buf
        try:
            b0, b1 = read(2)
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack("!H", read(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", read(8))[0]
            return b0 & 0x0F, read(n)
        except (EOFError, socket.timeout, ConnectionResetError):
            return None

    def close_code(self):
        """The status code of the server's close frame, if it sends one."""
        while True:
            f = self.recv(2.0)
            if f is None:
                return None
            if f[0] == 8:
                return struct.unpack("!H", f[1][:2])[0] if len(f[1]) >= 2 else 1005


def http_post(path, body: bytes, ctype):
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP}{path}", data=body, method="POST",
                                 headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, "", e.read()


def scenario(r):
    cfg = base_config(NG, ports=PORTS).replace(
        f'listen = ["127.0.0.1:{NG}"]',
        f'listen = ["127.0.0.1:{NG}"]\nlisten_tcp = ["127.0.0.1:{NG}"]\nlisten_http = ["127.0.0.1:{HTTP}"]')
    with Relay(cfg, NG, "transports") as relay:
        offer_sdp = sdp("127.0.0.1", 5000)

        # ---------------------------------------------------------- TCP
        t = socket.create_connection(("127.0.0.1", NG), timeout=3)
        # 200 requests back to back in one write; then read every reply
        msgs = b"".join(f"t{i} ".encode() + benc({"command": "ping"}) for i in range(200))
        t0 = time.time()
        t.sendall(msgs)
        buf = b""
        while buf.count(b"pong") < 200:
            c = t.recv(65536)
            if not c:
                break
            buf += c
        dt = time.time() - t0
        cookies = [part.split(b" ")[0] for part in buf.split(b"d6:result4:ponge") if part]
        r.check(cookies == [f"t{i}".encode() for i in range(200)],
                f"TCP: 200 pipelined pings answered in order ({dt * 1000:.0f} ms)", repr(buf[:80]))
        # A request split across writes, byte by byte.
        req = b"split " + benc({"command": "offer", "call-id": "tcp-1", "from-tag": "a", "sdp": offer_sdp})
        for i in range(0, len(req), 7):
            t.sendall(req[i:i + 7])
            time.sleep(0.001)
        reply = t.recv(65536)
        r.check(reply.startswith(b"split ") and b"2:ok" in reply, "TCP: a request arriving in pieces is handled")
        # The same cookie on TCP again: a retransmission.
        t.sendall(req)
        r.check(t.recv(65536) == reply, "TCP: a retransmitted request gets the cached reply")
        t.close()
        # Many connections at once
        results = []

        def client(i):
            try:
                c = socket.create_connection(("127.0.0.1", NG), timeout=5)
                c.sendall(f"m{i} ".encode() + benc({"command": "ping"}))
                results.append(c.recv(100).startswith(f"m{i} ".encode()))
                c.close()
            except OSError:
                results.append(False)
        th = [threading.Thread(target=client, args=(i,)) for i in range(100)]
        [x.start() for x in th]
        [x.join() for x in th]
        r.check(results.count(True) == 100, f"TCP: 100 concurrent connections all answered ({results.count(True)})")
        # Hostile streams close their own connection only
        for what, data in [("no space in 256 bytes", b"x" * 300),
                           ("an empty cookie", b" " + benc({"command": "ping"})),
                           ("a leading zero", b"c d7:commandi01ee"),
                           ("a repeated key", b"c d7:command4:ping7:command4:pinge"),
                           ("nesting of 40", b"c " + b"l" * 40 + b"e" * 40),
                           ("over 65535 bytes", b"c d3:sdp70000:" + b"x" * 70000 + b"e")]:
            c = socket.create_connection(("127.0.0.1", NG), timeout=3)
            try:
                c.sendall(data)
                c.settimeout(2)
                closed = c.recv(100) == b""
            except (ConnectionResetError, BrokenPipeError, socket.timeout):
                closed = True
            r.check(closed, f"TCP: {what} closes that connection")
            c.close()
        r.check(relay.ng("ping")["result"] == "pong", "the relay is still up")

        # ---------------------------------------------------------- HTTP
        code, ctype, body = http_post("/ng", b"h1 " + benc({"command": "ping"}), "application/x-rtpengine-ng")
        r.check(code == 200 and body == b"h1 d6:result4:ponge", "HTTP POST /ng: cookie and bencode", repr(body))
        code, ctype, body = http_post("/ng-plain", benc({"command": "ping"}), "application/x-rtpengine-ng")
        r.check(code == 200 and body == b"d6:result4:ponge", "HTTP POST /ng-plain with bencode", repr(body))
        code, ctype, body = http_post("/ng-plain", json.dumps({"command": "offer", "call-id": "http-1", "from-tag": "a",
                                                               "sdp": offer_sdp, "flags": ["trust-address"]}).encode(),
                                      "application/json")
        rep = json.loads(body or b"{}")
        r.check(code == 200 and "json" in ctype and rep.get("result") == "ok" and Sdp(rep["sdp"]).media,
                "HTTP POST /ng-plain with JSON: a JSON reply with the SDP")
        rep = json.loads(http_post("/ng-plain", b'{"command":"query","call-id":"http-1"}', "application/json")[2])
        r.check(rep.get("result") == "ok" and "tags" in rep, "HTTP: query in JSON (nested dictionaries)")
        code, _, body = http_post("/ng-plain", b'{"command":', "application/json")
        r.check(code >= 400 or b"error" in body, f"HTTP: broken JSON is refused ({code})")
        code, _, _ = http_post("/nothing", b"x", "text/plain")
        r.check(code == 404, f"HTTP: an unknown path is 404 ({code})")
        with urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/ping", timeout=3) as resp:
            r.check(resp.read().strip() == b"pong", "HTTP GET /ping")

        # ---------------------------------------------------------- WebSocket
        ws = Ws(HTTP, "ng.rtpengine.com")
        r.check(ws.ok, "WebSocket handshake with subprotocol ng.rtpengine.com", ws.head.split("\r\n")[0])
        r.check("Sec-WebSocket-Protocol: ng.rtpengine.com" in ws.head, "the server confirms the subprotocol")
        ws.frame(b"w1 " + benc({"command": "ping"}))
        f = ws.recv()
        r.check(f is not None and f[0] == 2 and f[1] == b"w1 d6:result4:ponge",
                "ng.rtpengine.com: a binary reply with the cookie", repr(f))
        ws.frame(b"w2 " + benc({"command": "offer", "call-id": "ws-1", "from-tag": "a", "sdp": offer_sdp}))
        f = ws.recv()
        r.check(f is not None and b"m=audio" in f[1], "an offer over WebSocket")
        # A message in fragments (continuation frames)
        msg = b"w3 " + benc({"command": "ping"})
        ws.frame(msg[:5], fin=False)
        ws.frame(msg[5:10], opcode=0, fin=False)
        ws.frame(msg[10:], opcode=0, fin=True)
        f = ws.recv()
        r.check(f is not None and f[1].startswith(b"w3 "), "a fragmented message is reassembled")
        # A ping between fragments is answered
        ws.frame(b"hi", opcode=9)
        f = ws.recv()
        r.check(f is not None and f[0] == 10 and f[1] == b"hi", "a WebSocket ping gets a pong")
        ws.s.close()

        ws = Ws(HTTP, "ng-plain.rtpengine.com")
        ws.frame(b'{"command":"ping"}', opcode=1)
        f = ws.recv()
        r.check(f is not None and json.loads(f[1]) == {"result": "pong"}, "ng-plain.rtpengine.com with JSON")
        ws.frame(benc({"command": "ping"}))
        f = ws.recv()
        r.check(f is not None and f[1] == b"d6:result4:ponge", "ng-plain.rtpengine.com with bencode")
        ws.s.close()

        # RFC 6455 violations fail the connection with 1002
        cases = [
            ("an unmasked frame", dict(payload=b"x d7:command4:pinge", mask=False)),
            ("a reserved bit", dict(payload=b"x d7:command4:pinge", rsv=4)),
            ("a reserved opcode", dict(payload=b"x", opcode=3)),
            ("a fragmented control frame", dict(payload=b"x", opcode=9, fin=False)),
            ("a length not in its shortest form", dict(payload=b"x d7:command4:pinge", long_len=True)),
            ("a continuation without a message", dict(payload=b"x", opcode=0)),
        ]
        for what, kw in cases:
            ws = Ws(HTTP, "ng.rtpengine.com")
            ws.frame(**kw)
            code = ws.close_code()
            r.check(code == 1002, f"WebSocket: {what} fails the connection with 1002", str(code))
            ws.s.close()
        ws = Ws(HTTP, "ng.rtpengine.com")
        ws.frame(b"a" * 70000)
        code = ws.close_code()
        r.check(code in (1009, 1002), f"WebSocket: a message over 65535 bytes is refused ({code})")
        ws = Ws(HTTP, "chat.example")
        r.check(not ws.ok or "ng" not in ws.head, f"an unknown subprotocol is not accepted: {ws.head.splitlines()[0]}")

        # all transports see the same calls
        calls = relay.ok("list")["calls"]
        r.check({"tcp-1", "http-1", "ws-1"} <= set(calls), f"calls made over TCP, HTTP and WebSocket are one table: {calls}")
        r.check(relay.ng("ping")["result"] == "pong", "the relay is still up after every hostile stream")


if __name__ == "__main__":
    main(scenario)
