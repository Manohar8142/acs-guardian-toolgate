# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""The two v0.1.0 transports (Spec §3): HTTP POST and stdio with Content-Length framing."""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import BinaryIO

from acs_guardian_toolgate.guardian import Guardian


def make_http_server(guardian: Guardian, host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    cfg = guardian.config
    path = cfg.path

    class Handler(BaseHTTPRequestHandler):
        server_version = "acs-guardian-toolgate"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # request lines stay off stderr; decisions go to the audit log
            return

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            if self.path.split("?", 1)[0] not in (path, "/"):
                return self._send(404, b'{"error":"not found"}')
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0:
                return self._send(411, b'{"error":"Content-Length required"}')
            if length > cfg.max_body_bytes:
                # Bounded processing: answer with a JSON-RPC error body; do not read it.
                self.close_connection = True
                return self._send(413, guardian._dump(guardian._error(None, -32600, "request body exceeds max_body_bytes")))
            body = self.rfile.read(length)
            out = guardian.handle_bytes(body, transport="http")
            self._send(200, out or b"")

        def do_GET(self):  # noqa: N802
            if self.path == "/healthz":
                return self._send(200, b'{"status":"ok"}')
            self._send(405, b'{"error":"POST JSON-RPC to ' + path.encode() + b'"}')

    server = ThreadingHTTPServer((host or cfg.host, cfg.port if port is None else port), Handler)
    server.daemon_threads = True
    return server


def serve_http_background(guardian: Guardian, host: str = "127.0.0.1", port: int = 0):
    """Start on a thread; returns (server, url). Used by tests and the conformance driver."""
    server = make_http_server(guardian, host, port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    h, p = server.server_address[:2]
    return server, f"http://{h}:{p}{guardian.config.path}"


# ---------------------------------------------------------------- stdio
def read_frame(stream: BinaryIO, max_bytes: int) -> bytes | None:
    """Read one ``Content-Length: N\\r\\n\\r\\n<body>`` frame. None at EOF."""
    length = None
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            if length is None:
                continue
            break
        name, _, value = line.decode("ascii", "replace").partition(":")
        if name.strip().lower() == "content-length":
            length = int(value.strip())
    if length > max_bytes:
        stream.read(length)
        return b"\x00oversize"
    return stream.read(length)


def write_frame(stream: BinaryIO, body: bytes) -> None:
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    stream.flush()


def serve_stdio(guardian: Guardian, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    while True:
        body = read_frame(stdin, guardian.config.max_body_bytes)
        if body is None:
            return
        if body == b"\x00oversize":
            out = guardian._dump(guardian._error(None, -32600, "request body exceeds max_body_bytes"))
        else:
            out = guardian.handle_bytes(body, transport="stdio")
        if out:
            write_frame(stdout, out)
