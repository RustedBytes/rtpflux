"""Unit tests for the scenario harness's own code (run on every supported
Python: `python3 -m unittest discover -s examples/scenarios/lib`).

The G.711 conversions replace `audioop`, which Python 3.13 removed. Each
is checked over its whole input against the SHA-256 of what `audioop`
returned for the same input (taken on Python 3.12), so they stay exactly
equal on Pythons that no longer have it."""

import hashlib
import math
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

ALL_SAMPLES = struct.pack("<65536h", *range(-32768, 32768))
ALL_CODES = bytes(range(256))

# audioop.lin2ulaw(ALL_SAMPLES, 2) and so on, on CPython 3.12.
AUDIOOP_SHA256 = {
    "lin2ulaw": "81d633c9e6972a18c74a58720b96cb8ca0bdd096d4060b646dd708c3b846019a",
    "lin2alaw": "38488f6fd710f4686360edc4d38639f96c491595ef93f8eb8d62d5e07ca6ce7b",
    "ulaw2lin": "3dab54339e520bb2c924826e3b72a917a2b612e9fd12fc867500f1d983a75827",
    "alaw2lin": "e04788d110e58ff8c70c93b8480190d973e3b67876b6119abbaec766cc75c174",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class G711(unittest.TestCase):
    def test_equal_to_audioop_for_every_input(self):
        self.assertEqual(sha(harness.pcm_to_ulaw(ALL_SAMPLES)), AUDIOOP_SHA256["lin2ulaw"])
        self.assertEqual(sha(harness.pcm_to_alaw(ALL_SAMPLES)), AUDIOOP_SHA256["lin2alaw"])
        self.assertEqual(sha(harness.ulaw_to_pcm(ALL_CODES)), AUDIOOP_SHA256["ulaw2lin"])
        self.assertEqual(sha(harness.alaw_to_pcm(ALL_CODES)), AUDIOOP_SHA256["alaw2lin"])

    def test_silence_codes(self):
        zero = struct.pack("<h", 0)
        self.assertEqual(harness.pcm_to_ulaw(zero), b"\xff")
        self.assertEqual(harness.pcm_to_alaw(zero), b"\xd5")

    def test_round_trip_is_stable(self):
        # Decoding then encoding a code gives the code back (u-law's two
        # zeros, 0x7f and 0xff, both decode to 0, which encodes as 0xff).
        for code in range(256):
            u = harness.pcm_to_ulaw(harness.ulaw_to_pcm(bytes([code])))
            self.assertEqual(u, b"\xff" if code == 0x7F else bytes([code]))
            self.assertEqual(harness.pcm_to_alaw(harness.alaw_to_pcm(bytes([code]))), bytes([code]))

    def test_odd_trailing_byte_is_ignored(self):
        self.assertEqual(harness.pcm_to_ulaw(b"\x00\x00\x01"), b"\xff")

    def test_rms(self):
        self.assertEqual(harness.rms(b""), 0)
        self.assertEqual(harness.rms(struct.pack("<2h", 3, -4)), int(math.sqrt(12.5)))
        self.assertEqual(harness.rms(struct.pack("<h", -32768) * 10), 32768)
        level = harness.rms(harness.tone(1000, amp=8000))
        self.assertAlmostEqual(level, 8000 / math.sqrt(2), delta=60)


class Bencode(unittest.TestCase):
    def test_round_trip(self):
        v = {"command": "offer", "flags": ["trust-address", "SDES-off"], "n": -12, "d": {"a": [1, {"b": "c"}]}}
        out, end = harness.bdec(harness.benc(v))
        self.assertEqual(out, v)

    def test_keys_are_sorted(self):
        self.assertEqual(harness.benc({"b": 1, "a": 2}), b"d1:ai2e1:bi1ee")


class NgReplies(unittest.TestCase):
    def test_a_late_reply_to_an_earlier_command_is_skipped(self):
        """A reply that arrives after its command timed out must not be
        taken for the next command's reply."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        relay = harness.Relay("", port, "unit")
        try:
            def answer():
                data, src = server.recvfrom(65535)
                cookie = data.partition(b" ")[0]
                server.sendto(b"stale d6:result4:ponge", src)  # an old command's reply
                server.sendto(cookie + b" d6:result4:ponge", src)

            t = threading.Thread(target=answer)
            t.start()
            self.assertEqual(relay.ng("ping", timeout=2.0), {"result": "pong"})
            t.join()
        finally:
            server.close()
            relay.sock.close()
            relay.cleanup()


if __name__ == "__main__":
    unittest.main()
