"""A tiny Redis stand-in for the scenarios (RESP2: PING, AUTH, SELECT,
SET, GET, QUIT), used when `redis-server` is not installed. It can be
taken down and brought back, and it records what was written, so a
scenario can watch the relay's writes."""

from __future__ import annotations

import socket
import threading
import time


class FakeRedis:
    def __init__(self, port: int, password: str | None = None):
        self.port = port
        self.password = password
        self.data: dict[tuple[int, bytes], bytes] = {}
        self.sets = 0
        self.auth_failures = 0
        self.lock = threading.Lock()
        self.down = False
        self.srv = None
        self.thread = None
        self.conns: list[socket.socket] = []

    def start(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", self.port))
        self.srv.listen(16)
        self.down = False
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        """Go down: close the listener and every connection."""
        self.down = True
        try:
            self.srv.close()
        except OSError:
            pass
        for c in self.conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass
        self.conns.clear()

    def get(self, key: str, db: int = 0) -> bytes | None:
        with self.lock:
            return self.data.get((db, key.encode()))

    def _accept(self):
        while not self.down:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c: socket.socket):
        f = c.makefile("rb")
        authed = self.password is None
        db = 0
        try:
            while not self.down:
                line = f.readline()
                if not line:
                    return
                if not line.startswith(b"*"):
                    c.sendall(b"-ERR protocol\r\n")
                    return
                args = []
                for _ in range(int(line[1:])):
                    n = int(f.readline()[1:])
                    args.append(f.read(n + 2)[:-2])
                cmd = args[0].upper()
                if cmd == b"PING":
                    out = b"+PONG\r\n"
                elif cmd == b"QUIT":
                    c.sendall(b"+OK\r\n")
                    return
                elif cmd == b"AUTH":
                    ok = self.password is not None and args[-1].decode() == self.password
                    authed = authed or ok
                    if not ok:
                        self.auth_failures += 1
                    out = b"+OK\r\n" if ok else b"-WRONGPASS invalid username-password pair\r\n"
                elif not authed:
                    out = b"-NOAUTH Authentication required.\r\n"
                elif cmd == b"SELECT":
                    db = int(args[1])
                    out = b"+OK\r\n"
                elif cmd == b"SET":
                    with self.lock:
                        self.data[(db, args[1])] = args[2]
                        self.sets += 1
                    out = b"+OK\r\n"
                elif cmd == b"GET":
                    with self.lock:
                        v = self.data.get((db, args[1]))
                    out = b"$-1\r\n" if v is None else b"$%d\r\n%s\r\n" % (len(v), v)
                else:
                    out = b"-ERR unknown command\r\n"
                c.sendall(out)
        except (OSError, ValueError):
            return
        finally:
            try:
                c.close()
            except OSError:
                pass


def wait_for(cond, secs: float = 5.0, step: float = 0.05) -> bool:
    deadline = time.time() + secs
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False
