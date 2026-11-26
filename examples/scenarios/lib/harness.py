"""A small harness for the rtpflux scenarios.

It plays both the SIP proxy (it sends `ng` commands, as Kamailio's or
OpenSIPS's rtpengine module would) and the phones (real RTP/SRTP over UDP
on loopback), so a scenario needs nothing but Python 3 and, for SRTP,
the `cryptography` package.

Everything here is test tooling: simple and explicit rather than fast.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DAEMON = os.environ.get("RTPFLUX_BIN", os.path.join(ROOT, "target", "release", "rtpflux"))


# ------------------------------------------------------------------ bencode

def benc(v) -> bytes:
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, (bytes, bytearray)):
        return b"%d:%s" % (len(v), bytes(v))
    if isinstance(v, (list, tuple)):
        return b"l" + b"".join(benc(x) for x in v) + b"e"
    if isinstance(v, dict):
        items = sorted((k.encode() if isinstance(k, str) else k, x) for k, x in v.items())
        return b"d" + b"".join(benc(k) + benc(x) for k, x in items) + b"e"
    raise TypeError(type(v))


def bdec(b: bytes, i: int = 0):
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
            out[k if isinstance(k, str) else k.decode(errors="replace")] = x
        return out, i + 1
    j = b.index(b":", i)
    n = int(b[i:j])
    raw = b[j + 1:j + 1 + n]
    try:
        return raw.decode(), j + 1 + n
    except UnicodeDecodeError:
        return raw, j + 1 + n


# ------------------------------------------------------------------ results

class Report:
    """PASS / FAIL checks, plus FINDINGs: behaviour worth a human look
    (edge cases, surprises) that is not a plain failure."""

    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed: list[str] = []
        self.findings: list[str] = []
        self.skipped: list[str] = []
        print(f"\n=== {name} ===", flush=True)

    def check(self, ok: bool, what: str, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"  PASS  {what}", flush=True)
        else:
            self.failed.append(f"{what}{': ' + detail if detail else ''}")
            print(f"  FAIL  {what}{': ' + detail if detail else ''}", flush=True)
        return ok

    def finding(self, what: str):
        self.findings.append(what)
        print(f"  NOTE  {what}", flush=True)

    def skip(self, what: str):
        self.skipped.append(what)
        print(f"  SKIP  {what}", flush=True)

    def done(self) -> int:
        print(
            f"--- {self.name}: {self.passed} passed, {len(self.failed)} failed, "
            f"{len(self.findings)} findings, {len(self.skipped)} skipped",
            flush=True,
        )
        return 1 if self.failed else 0


# ------------------------------------------------------------------ the relay

class NgError(Exception):
    def __init__(self, reply):
        super().__init__(reply.get("error-reason", reply))
        self.reply = reply


class Relay:
    """An rtpflux daemon with a generated configuration, on loopback."""

    def __init__(self, config: str, ng_port: int, name: str = "relay", workdir: str | None = None):
        self.dir = workdir or tempfile.mkdtemp(prefix=f"rtpflux-{name}-")
        self.config_path = os.path.join(self.dir, "rtpflux.toml")
        with open(self.config_path, "w") as f:
            f.write(config)
        self.ng_addr = ("127.0.0.1", ng_port)
        self.log_path = os.path.join(self.dir, "rtpflux.log")
        self.proc: subprocess.Popen | None = None
        self.cookie = random.randrange(1 << 30)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))

    def check_config(self) -> subprocess.CompletedProcess:
        return subprocess.run([DAEMON, "--check", "-c", self.config_path], capture_output=True, text=True)

    def start(self, wait: float = 5.0, env: dict | None = None):
        # Another daemon on the ng port would answer our pings: refuse.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(self.ng_addr)
        except OSError as e:
            raise RuntimeError(f"ng port {self.ng_addr} is taken (a stale rtpflux?)") from e
        finally:
            probe.close()
        try:
            return self._start(wait, env)
        except BaseException:
            self.stop()
            raise

    def _start(self, wait: float, env: dict | None):
        log = open(self.log_path, "a")
        e = dict(os.environ)
        e.setdefault("RUST_LOG", "info")
        e.update(env or {})
        self.proc = subprocess.Popen([DAEMON, "-c", self.config_path], stdout=log, stderr=log, env=e)
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"rtpflux exited ({self.proc.returncode}):\n{self.log()}")
            try:
                if self.ng("ping", timeout=0.3).get("result") == "pong":
                    # Listeners after the ng one may still fail: give
                    # them a moment and make sure the daemon stayed up.
                    time.sleep(0.15)
                    if self.proc.poll() is not None:
                        raise RuntimeError(f"rtpflux exited ({self.proc.returncode}):\n{self.log()}")
                    return self
            except (TimeoutError, OSError):
                pass
            time.sleep(0.05)
        raise RuntimeError(f"rtpflux did not answer ping:\n{self.log()}")

    def stop(self, sig=signal.SIGTERM, timeout: float = 10.0) -> int | None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        return self.proc.returncode if self.proc else None

    def log(self) -> str:
        try:
            with open(self.log_path) as f:
                return f.read()
        except OSError:
            return ""

    def cleanup(self):
        self.stop()
        if os.environ.get("KEEP") != "1":
            shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.cleanup()

    # ---- ng

    def ng_raw(self, payload: bytes, timeout: float = 3.0) -> bytes:
        self.sock.settimeout(timeout)
        self.sock.sendto(payload, self.ng_addr)
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout as e:
            raise TimeoutError("no ng reply") from e
        return data

    def ng(self, command: str, timeout: float = 3.0, cookie: str | None = None, **opts) -> dict:
        """Send one command; options use `_` for `-` and ` ` is spelled
        out by the caller where needed (pass a dict via **{...})."""
        if cookie is None:
            self.cookie += 1
            cookie = f"c{self.cookie}"
        msg = {"command": command}
        for k, v in opts.items():
            msg[k.replace("_", "-")] = v
        want = cookie.encode()
        data = self.ng_raw(want + b" " + benc(msg), timeout)
        # A reply that came after an earlier command timed out is still
        # queued: skip anything that is not this command's reply.
        deadline = time.time() + timeout
        while data.partition(b" ")[0] != want:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(f"no ng reply with cookie {cookie} (others: {data[:40]!r})")
            self.sock.settimeout(left)
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout as e:
                raise TimeoutError("no ng reply") from e
        reply, _ = bdec(data, len(want) + 1)
        return reply

    def ok(self, command: str, **opts) -> dict:
        r = self.ng(command, **opts)
        if r.get("result") not in ("ok", "pong"):
            raise NgError(r)
        return r


# ------------------------------------------------------------------ SDP

def sdp(addr: str, port: int, pts=(0,), proto="RTP/AVP", media="audio", extra=(), session_extra=(),
        sections=None, origin_addr=None) -> str:
    """A minimal offer/answer. `sections` (list of dicts with the same
    keys) builds several m= lines."""
    fam = "IP6" if ":" in addr else "IP4"
    o = origin_addr or addr
    lines = [
        "v=0",
        f"o=- {random.randrange(1 << 31)} 1 IN {'IP6' if ':' in o else 'IP4'} {o}",
        "s=-",
        f"c=IN {fam} {addr}",
        "t=0 0",
        *session_extra,
    ]
    if sections is None:
        sections = [dict(port=port, pts=pts, proto=proto, media=media, extra=extra)]
    for s in sections:
        pts_ = s.get("pts", (0,))
        lines.append(f"m={s.get('media', 'audio')} {s['port']} {s.get('proto', 'RTP/AVP')} {' '.join(str(p) for p in pts_)}")
        for p in pts_:
            name = RTPMAP.get(p)
            if name:
                lines.append(f"a=rtpmap:{p} {name}")
        lines.extend(s.get("extra", ()))
    return "\r\n".join(lines) + "\r\n"


RTPMAP = {0: "PCMU/8000", 8: "PCMA/8000", 9: "G722/8000", 18: "G729/8000", 101: "telephone-event/8000",
          111: "opus/48000/2", 13: "CN/8000"}


class Media:
    def __init__(self, line: str):
        f = line[2:].split()
        self.kind, self.port, self.proto = f[0], int(f[1].split("/")[0]), f[2]
        self.fmts = f[3:]
        self.attrs: list[str] = []
        self.conn: str | None = None

    def attr(self, name: str) -> list[str]:
        out = []
        for a in self.attrs:
            if a == name:
                out.append("")
            elif a.startswith(name + ":"):
                out.append(a[len(name) + 1:])
        return out

    def has(self, name: str) -> bool:
        return bool(self.attr(name))

    def __repr__(self):
        return f"<m={self.kind} {self.port} {self.proto} {self.fmts}>"


class Sdp:
    def __init__(self, text: str):
        self.text = text
        self.lines = [x for x in text.replace("\r\n", "\n").split("\n") if x]
        self.session_attrs: list[str] = []
        self.conn: str | None = None
        self.origin: str | None = None
        self.media: list[Media] = []
        for ln in self.lines:
            if ln.startswith("m="):
                self.media.append(Media(ln))
            elif ln.startswith("c="):
                addr = ln.split()[-1].split("/")[0]
                if self.media:
                    self.media[-1].conn = addr
                else:
                    self.conn = addr
            elif ln.startswith("o="):
                self.origin = ln.split()[-1]
            elif ln.startswith("a="):
                (self.media[-1].attrs if self.media else self.session_attrs).append(ln[2:])

    def addr(self, i: int = 0) -> str:
        return self.media[i].conn or self.conn

    def dest(self, i: int = 0) -> tuple[str, int]:
        return (self.addr(i), self.media[i].port)

    def session_attr(self, name: str) -> list[str]:
        return [a[len(name) + 1:] for a in self.session_attrs if a.startswith(name + ":")] + \
            ["" for a in self.session_attrs if a == name]


# ------------------------------------------------------------------ RTP

def rtp(pt: int, seq: int, ts: int, ssrc: int, payload: bytes, marker: bool = False, csrcs=()) -> bytes:
    b0 = 0x80 | len(csrcs)
    b1 = (0x80 if marker else 0) | pt
    head = struct.pack("!BBHII", b0, b1, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    return head + b"".join(struct.pack("!I", c) for c in csrcs) + payload


def parse_rtp(data: bytes):
    if len(data) < 12 or data[0] >> 6 != 2:
        return None
    cc = data[0] & 0x0F
    seq, ts, ssrc = struct.unpack("!HII", data[2:12])
    off = 12 + 4 * cc
    if data[0] & 0x10 and len(data) >= off + 4:
        ext_len = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4 + 4 * ext_len
    end = len(data)
    if data[0] & 0x20 and end > off:
        end -= data[-1]
    return dict(pt=data[1] & 0x7F, marker=bool(data[1] & 0x80), seq=seq, ts=ts, ssrc=ssrc,
                payload=data[off:end], cc=cc)


def rtcp_sr(ssrc: int) -> bytes:
    """A minimal RTCP sender report with no report blocks."""
    now = time.time() + 2208988800
    ntp_hi, ntp_lo = int(now), int((now % 1) * (1 << 32))
    return struct.pack("!BBHIIIIII", 0x80, 200, 6, ssrc, ntp_hi, ntp_lo, 0, 0, 0)


class Endpoint:
    """One side's media socket (a phone, a browser, a trunk)."""

    # Endpoint ports come from 10000-19999; the scenarios' relays use
    # 21000-29399. Both stay out of the kernel's ephemeral range
    # (32768-60999): any process's socket sitting on a media port would
    # take a pair away from the relay.
    _next_port = 10000 + (os.getpid() % 50) * 100

    def __init__(self, addr: str = "127.0.0.1", port: int = 0):
        fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_DGRAM)
        if port:
            self.sock.bind((addr, port))
        else:
            for _ in range(10000):
                p = Endpoint._next_port
                Endpoint._next_port = 10000 + (p - 10000 + 2) % 10000  # even ports, like phones
                try:
                    self.sock.bind((addr, p))
                    break
                except OSError:
                    continue
            else:
                raise OSError("no free endpoint port in 10000-19999")
        self.addr, self.port = self.sock.getsockname()[:2]
        self.seq = random.randrange(1 << 16)
        self.ts = random.randrange(1 << 32)
        self.ssrc = random.randrange(1, 1 << 32)

    def send(self, data: bytes, dst):
        self.sock.sendto(data, dst)

    def send_rtp(self, dst, pt=0, payload=b"\xff" * 160, n=1, interval=0.0, marker=False, ts_step=160):
        for _ in range(n):
            self.sock.sendto(rtp(pt, self.seq, self.ts, self.ssrc, payload, marker), dst)
            self.seq = (self.seq + 1) & 0xFFFF
            self.ts = (self.ts + ts_step) & 0xFFFFFFFF
            marker = False
            if interval:
                time.sleep(interval)

    def recv_all(self, timeout: float = 0.5, until: int | None = None):
        """Every datagram within `timeout` (or until `until` arrived)."""
        out = []
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0 or (until is not None and len(out) >= until):
                break
            self.sock.settimeout(left)
            try:
                out.append(self.sock.recvfrom(65535))
            except (socket.timeout, BlockingIOError):
                break
            except ConnectionRefusedError:
                continue
        return out

    def drain(self):
        self.sock.setblocking(False)
        try:
            while True:
                self.sock.recvfrom(65535)
        except (BlockingIOError, ConnectionRefusedError):
            pass
        finally:
            self.sock.setblocking(True)

    def close(self):
        self.sock.close()


def exchange(a: Endpoint, a_dst, b: Endpoint, b_dst, n: int = 10, pt=0, payload=b"\xff" * 160, interval=0.02):
    """a and b send `n` packets each to the relay; returns what each
    received (lists of (data, src))."""
    for _ in range(n):
        a.send_rtp(a_dst, pt=pt, payload=payload)
        b.send_rtp(b_dst, pt=pt, payload=payload)
        if interval:
            time.sleep(interval)
    return b.recv_all(0.5), a.recv_all(0.5)


# ------------------------------------------------------------------ SRTP (RFC 3711)

class Srtp:
    """AES_CM_128_HMAC_SHA1_80 / _32 for one direction (one SSRC at a
    time is enough here; the rollover counter is tracked per SSRC)."""

    def __init__(self, master_key: bytes, master_salt: bytes, tag_len: int = 10):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: F401
        self.tag_len = tag_len
        kl = len(master_key)  # 16 (AES-128) or 32 (AES-256, RFC 6188)
        self.k_e = self._kdf(master_key, master_salt, 0, kl)
        self.k_a = self._kdf(master_key, master_salt, 1, 20)
        self.k_s = self._kdf(master_key, master_salt, 2, 14)
        self.rk_e = self._kdf(master_key, master_salt, 3, kl)
        self.rk_a = self._kdf(master_key, master_salt, 4, 20)
        self.rk_s = self._kdf(master_key, master_salt, 5, 14)
        self.roc: dict[int, int] = {}
        self.last_seq: dict[int, int] = {}
        self.srtcp_index = 0

    @staticmethod
    def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return enc.update(data) + enc.finalize()

    @classmethod
    def _kdf(cls, key: bytes, salt: bytes, label: int, n: int) -> bytes:
        x = bytearray(salt.ljust(14, b"\0"))
        x[7] ^= label
        return cls._ctr(key, bytes(x) + b"\0\0", b"\0" * n)

    def _iv(self, salt: bytes, ssrc: int, index: int) -> bytes:
        iv = int.from_bytes(salt, "big") << 16
        iv ^= ssrc << 64
        iv ^= index << 16
        return iv.to_bytes(16, "big")

    def protect(self, packet: bytes) -> bytes:
        p = parse_rtp(packet)
        ssrc, seq = p["ssrc"], p["seq"]
        roc = self.roc.get(ssrc, 0)
        last = self.last_seq.get(ssrc)
        if last is not None and seq < last and last - seq > 0x8000:
            roc += 1
        self.roc[ssrc], self.last_seq[ssrc] = roc, seq
        hdr_len = len(packet) - len(p["payload"])
        index = (roc << 16) | seq
        body = self._ctr(self.k_e, self._iv(self.k_s, ssrc, index), packet[hdr_len:])
        out = packet[:hdr_len] + body
        tag = hmac.new(self.k_a, out + roc.to_bytes(4, "big"), hashlib.sha1).digest()[: self.tag_len]
        return out + tag

    def unprotect(self, packet: bytes) -> bytes | None:
        if len(packet) < 12 + self.tag_len:
            return None
        body, tag = packet[: -self.tag_len], packet[-self.tag_len:]
        p = parse_rtp(body)
        if p is None:
            return None
        ssrc, seq = p["ssrc"], p["seq"]
        roc = self.roc.get(ssrc, 0)
        last = self.last_seq.get(ssrc)
        if last is not None and seq < last and last - seq > 0x8000:
            roc += 1
        want = hmac.new(self.k_a, body + roc.to_bytes(4, "big"), hashlib.sha1).digest()[: self.tag_len]
        if not hmac.compare_digest(want, tag):
            return None
        self.roc[ssrc], self.last_seq[ssrc] = roc, seq
        hdr_len = len(body) - len(p["payload"])
        index = (roc << 16) | seq
        return body[:hdr_len] + self._ctr(self.k_e, self._iv(self.k_s, ssrc, index), body[hdr_len:])

    def protect_rtcp(self, packet: bytes) -> bytes:
        ssrc = struct.unpack("!I", packet[4:8])[0]
        self.srtcp_index += 1
        idx = self.srtcp_index
        body = packet[:8] + self._ctr(self.rk_e, self._iv(self.rk_s, ssrc, idx), packet[8:])
        e_idx = (0x80000000 | idx).to_bytes(4, "big")
        tag = hmac.new(self.rk_a, body + e_idx, hashlib.sha1).digest()[:10]
        return body + e_idx + tag


SUITES = {  # name: (master key length, auth tag length)
    "AES_CM_128_HMAC_SHA1_80": (16, 10),
    "AES_CM_128_HMAC_SHA1_32": (16, 4),
    "AES_256_CM_HMAC_SHA1_80": (32, 10),
    "AES_256_CM_HMAC_SHA1_32": (32, 4),
}


def crypto_line(tag: int = 1, suite: str = "AES_CM_128_HMAC_SHA1_80", key: bytes | None = None, params: str = ""):
    """An `a=crypto` attribute, and an Srtp context for its key."""
    kl, tl = SUITES[suite]
    key = key or os.urandom(kl + 14)
    line = f"a=crypto:{tag} {suite} inline:{base64.b64encode(key).decode()}{params}"
    return line, Srtp(key[:kl], key[kl:kl + 14], tl)


def parse_crypto(value: str):
    """(tag, suite, Srtp) of an `a=crypto` value."""
    tag, suite, params = value.split()[:3]
    kl, tl = SUITES[suite]
    material = base64.b64decode(params.split("inline:")[1].split("|")[0])
    return int(tag), suite, Srtp(material[:kl], material[kl:kl + 14], tl)


# ------------------------------------------------------------------ STUN / ICE

MAGIC = 0x2112A442


def _crc32(b: bytes) -> int:
    return (zlib.crc32(b) ^ 0x5354554E) & 0xFFFFFFFF


def stun_message(mtype: int, txid: bytes, attrs: list[tuple[int, bytes]], key: bytes | None,
                 fingerprint: bool = True) -> bytes:
    def enc(t, v):
        return struct.pack("!HH", t, len(v)) + v + b"\0" * (-len(v) % 4)

    body = b"".join(enc(t, v) for t, v in attrs)
    if key is not None:
        head = struct.pack("!HHI", mtype, len(body) + 24, MAGIC) + txid
        mac = hmac.new(key, head + body, hashlib.sha1).digest()
        body += enc(0x0008, mac)
    if fingerprint:
        head = struct.pack("!HHI", mtype, len(body) + 8, MAGIC) + txid
        body += enc(0x8028, struct.pack("!I", _crc32(head + body)))
    return struct.pack("!HHI", mtype, len(body), MAGIC) + txid + body


def stun_parse(data: bytes):
    if len(data) < 20 or data[0] >> 6 != 0 or struct.unpack("!I", data[4:8])[0] != MAGIC:
        return None
    mtype, length = struct.unpack("!HH", data[:4])
    attrs, i = {}, 20
    while i + 4 <= 20 + length:
        t, n = struct.unpack("!HH", data[i:i + 4])
        attrs.setdefault(t, data[i + 4:i + 4 + n])
        i += 4 + n + (-n % 4)
    return dict(type=mtype, txid=data[8:20], attrs=attrs)


def xor_address(v: bytes):
    fam, xport = struct.unpack("!xBH", v[:4])
    port = xport ^ (MAGIC >> 16)
    if fam == 1:
        ip = struct.unpack("!I", v[4:8])[0] ^ MAGIC
        return socket.inet_ntoa(struct.pack("!I", ip)), port
    return None, port


def binding_request(username: str, key: str, priority: int = 0x6E0001FF, controlling: bool = True,
                    use_candidate: bool = False, tie: int = 1) -> tuple[bytes, bytes]:
    txid = os.urandom(12)
    attrs = [(0x0006, username.encode()), (0x0024, struct.pack("!I", priority)),
             (0x802A if controlling else 0x8029, struct.pack("!Q", tie))]
    if use_candidate:
        attrs.append((0x0025, b""))
    return stun_message(0x0001, txid, attrs, key.encode()), txid


def binding_success(txid: bytes, src, key: str) -> bytes:
    ip, port = src
    xip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ MAGIC
    v = struct.pack("!xBHI", 1, port ^ (MAGIC >> 16), xip)
    return stun_message(0x0101, txid, [(0x0020, v)], key.encode())


# ------------------------------------------------------------------ G.711

# Python 3.13 removed `audioop`; these are its G.711 conversions (the Sun
# g711.c it was built on), checked equal to it for every input, so the
# scenarios need no C extension on any Python.

def _segment(value: int, ends: tuple[int, ...]) -> int:
    for i, end in enumerate(ends):
        if value <= end:
            return i
    return len(ends)


_U_ENDS = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)
_A_ENDS = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)


def _lin2ulaw(sample: int) -> int:
    v = sample >> 2  # 14 bits
    if v < 0:
        v, mask = -v, 0x7F
    else:
        mask = 0xFF
    v = min(v, 8159) + 33
    seg = _segment(v, _U_ENDS)
    if seg >= 8:
        return 0x7F ^ mask
    return ((seg << 4) | ((v >> (seg + 1)) & 0xF)) ^ mask


def _lin2alaw(sample: int) -> int:
    v = sample >> 3  # 13 bits
    if v >= 0:
        mask = 0xD5
    else:
        mask, v = 0x55, -v - 1
    seg = _segment(v, _A_ENDS)
    if seg >= 8:
        return 0x7F ^ mask
    aval = seg << 4
    aval |= ((v >> 1) if seg < 2 else (v >> seg)) & 0xF
    return aval ^ mask


def _ulaw2lin(code: int) -> int:
    u = ~code & 0xFF
    t = (((u & 0xF) << 3) + 0x84) << ((u & 0x70) >> 4)
    return (0x84 - t) if u & 0x80 else (t - 0x84)


def _alaw2lin(code: int) -> int:
    a = code ^ 0x55
    t = (a & 0xF) << 4
    seg = (a & 0x70) >> 4
    t = t + 8 if seg == 0 else (t + 0x108) << max(seg - 1, 0)
    return t if a & 0x80 else -t


# Tables: a 16-bit sample (as unsigned, little-endian bytes) to its code,
# and a code to its sample's two little-endian bytes.
_ENC_U = bytes(_lin2ulaw(i - 65536 if i >= 32768 else i) for i in range(65536))
_ENC_A = bytes(_lin2alaw(i - 65536 if i >= 32768 else i) for i in range(65536))
_DEC_U = [struct.pack("<h", _ulaw2lin(c)) for c in range(256)]
_DEC_A = [struct.pack("<h", _alaw2lin(c)) for c in range(256)]


def _samples(pcm: bytes):
    return struct.unpack(f"<{len(pcm) // 2}H", pcm[: len(pcm) // 2 * 2])


def tone(freq: float = 1000.0, ms: int = 20, rate: int = 8000, amp: float = 8000.0, phase: int = 0) -> bytes:
    import math
    n = rate * ms // 1000
    return b"".join(struct.pack("<h", int(amp * math.sin(2 * math.pi * freq * (phase + i) / rate))) for i in range(n))


def pcm_to_ulaw(pcm: bytes) -> bytes:
    """16-bit little-endian linear PCM to G.711 u-law."""
    return bytes(_ENC_U[s] for s in _samples(pcm))


def pcm_to_alaw(pcm: bytes) -> bytes:
    """16-bit little-endian linear PCM to G.711 A-law."""
    return bytes(_ENC_A[s] for s in _samples(pcm))


def ulaw_to_pcm(b: bytes) -> bytes:
    return b"".join(_DEC_U[c] for c in b)


def alaw_to_pcm(b: bytes) -> bytes:
    return b"".join(_DEC_A[c] for c in b)


def rms(pcm: bytes) -> int:
    """The root mean square of 16-bit little-endian PCM (as audioop.rms)."""
    n = len(pcm) // 2
    if not n:
        return 0
    import math
    return int(math.sqrt(sum(v * v for v in struct.unpack(f"<{n}h", pcm[: n * 2])) / n))


def write_wav(path: str, pcm: bytes, rate: int = 8000):
    import wave
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)


# ------------------------------------------------------------------ misc

def http_get(url: str, auth: tuple[str, str] | None = None, timeout: float = 3.0):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def base_config(ng_port: int, ports=(40000, 40999), interfaces=(("default", "127.0.0.1", None),), extra: str = "",
                sessions: str = "", runtime: str = "workers = 2", max_sessions: int | None = None) -> str:
    ifaces = []
    for name, addr, adv in interfaces:
        ifaces.append(f'[[interface]]\nname = "{name}"\naddress = "{addr}"\n' + (f'advertise = "{adv}"\n' if adv else ""))
    max_sessions = max_sessions or max(1, (ports[1] - ports[0] + 1) // 4)
    return (
        f'[control]\nlisten = ["127.0.0.1:{ng_port}"]\n\n' + "\n".join(ifaces) +
        f"\n[ports]\nmin = {ports[0]}\nmax = {ports[1]}\n\n"
        f"[sessions]\nmax = {max_sessions}\n{sessions}\n"
        f"[runtime]\n{runtime}\n\n[log]\nlevel = \"info\"\n\n{extra}"
    )


def main(fn):
    """Run a scenario function `fn(report)`, exit with its status."""
    report = Report(os.path.basename(os.path.dirname(os.path.abspath(sys.modules["__main__"].__file__))))
    try:
        fn(report)
    except Exception as e:  # a crash is a failure, with its trace
        import traceback
        traceback.print_exc()
        report.check(False, "scenario ran to the end", repr(e))
    sys.exit(report.done())
