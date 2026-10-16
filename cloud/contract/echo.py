#!/usr/bin/env python3
"""The contract suite's echo service for real nodes (Env.RealRecipes): cloudtest.EchoHandler's
behaviour in the Python standard library, served by the svc-echo machine template on one port.

- a WebSocket upgrade on any path: an echo of every frame (the first offered subprotocol chosen);
- /redirect: 302 to /target with a cookie; /cookies: two Set-Cookie; /spoof: 404 with a forged
  Cloud-Transport-Error; /stream?n=: Server-Sent Events every 10 ms; /status/<code>;
  /slow?ms=; /drop: part of a body, then the connection drops;
- anything else: JSON {method, path, query, host, headers, body_bytes, body_sha256} with the
  path and query exactly as received.
"""

import base64
import hashlib
import json
import socket
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def canonical(name):
    return "-".join(p[:1].upper() + p[1:].lower() for p in name.split("-"))


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "svc-echo"
    sys_version = ""

    def log_message(self, *args):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, socket.timeout):
            self.close_connection = True

    def _body(self):
        h = hashlib.sha256()
        n = 0
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                left = size
                while left:
                    b = self.rfile.read(min(left, 65536))
                    if not b:
                        raise ConnectionError("short chunk")
                    h.update(b)
                    n += len(b)
                    left -= len(b)
                self.rfile.readline()
        else:
            left = int(self.headers.get("Content-Length") or 0)
            while left:
                b = self.rfile.read(min(left, 65536))
                if not b:
                    raise ConnectionError("short body")
                h.update(b)
                n += len(b)
                left -= len(b)
        return n, h.hexdigest()

    def _send(self, code, headers=(), body=b""):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        raw_path, _, raw_query = self.path.partition("?")
        query = parse_qs(raw_query)
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._websocket()
        if raw_path == "/redirect":
            return self._send(302, [("Set-Cookie", "r=1; Path=/"), ("Location", "/target")])
        if raw_path == "/drop":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"partial")
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        if raw_path == "/spoof":
            return self._send(404, [("Cloud-Transport-Error", "service_absent")])
        if raw_path == "/cookies":
            return self._send(200, [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/; HttpOnly")])
        if raw_path == "/stream":
            n = int((query.get("n") or ["3"])[0]) or 3
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(n):
                ev = ("id: %d\ndata: event %d\n\n" % (i, i)).encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(ev), ev))
                self.wfile.flush()
                time.sleep(0.01)
            self.wfile.write(b"0\r\n\r\n")
            return
        if raw_path == "/bytes":  # n bytes (downloads; not in cloudtest)
            n = int((query.get("n") or ["0"])[0])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(n))
            self.end_headers()
            chunk = b"\0" * 65536
            while n > 0:
                self.wfile.write(chunk[:min(n, 65536)])
                n -= 65536
            return
        if raw_path.startswith("/status/"):
            try:
                code = int(raw_path[len("/status/"):])
            except ValueError:
                code = 400
            if code < 200 or code > 599:
                code = 400
            return self._send(code)
        if raw_path == "/slow":
            time.sleep(int((query.get("ms") or ["0"])[0]) / 1000)
        n, digest = self._body()
        headers = {}
        for k, v in self.headers.items():
            headers.setdefault(canonical(k), []).append(v)
        out = {"method": self.command, "path": raw_path, "query": raw_query, "host": self.headers.get("Host", ""),
               "headers": headers, "body_bytes": n, "body_sha256": digest}
        self._send(200, [("Content-Type", "application/json")], (json.dumps(out) + "\n").encode())

    def _websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        proto = self.headers.get("Sec-WebSocket-Protocol")
        if proto:
            self.send_header("Sec-WebSocket-Protocol", proto.split(",")[0].strip())
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        r, w = self.rfile, self.wfile
        while True:
            head = r.read(2)
            if len(head) < 2:
                return
            fin_op, ln = head[0], head[1]
            masked, n = ln & 0x80, ln & 0x7F
            if n == 126:
                n = struct.unpack(">H", r.read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", r.read(8))[0]
            mask = r.read(4) if masked else b"\0\0\0\0"
            data = bytearray(r.read(n))
            for i in range(len(data)):
                data[i] ^= mask[i % 4]
            op = fin_op & 0x0F
            if op == 0x8:
                self._frame(w, 0x88, bytes(data))
                return
            if op == 0x9:
                self._frame(w, 0x8A, bytes(data))
            elif op != 0xA:
                self._frame(w, fin_op, bytes(data))

    @staticmethod
    def _frame(w, fin_op, payload):
        n = len(payload)
        if n < 126:
            head = struct.pack(">BB", fin_op, n)
        elif n <= 0xFFFF:
            head = struct.pack(">BBH", fin_op, 126, n)
        else:
            head = struct.pack(">BBQ", fin_op, 127, n)
        w.write(head + payload)
        w.flush()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 8080), Echo).serve_forever()
