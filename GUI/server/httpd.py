"""Localhost HTTP + Server-Sent-Events bridge to the Engine.

  GET  /            -> the single-page frontend (GUI/web/index.html)
  GET  /events      -> SSE stream of state / console / trace / prompt events
  POST /cmd         -> {"name": ..., "args": {...}} dispatched to the engine

SSE (one-way server->client) plus POST commands is enough for a debugger UI and
needs only the standard library — no websocket dependency.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


class _Handler(BaseHTTPRequestHandler):
    engine = None  # set on the server

    def log_message(self, *a):  # silence default request logging
        pass

    def _send(self, code, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._serve_file("index.html", "text/html; charset=utf-8")
        if path == "/events":
            return self._serve_events()
        if path.startswith("/") and ".." not in path:
            fn = path.lstrip("/")
            full = os.path.join(WEB_DIR, fn)
            if os.path.isfile(full):
                ctype = ("text/css" if fn.endswith(".css")
                         else "application/javascript" if fn.endswith(".js")
                         else "text/plain")
                return self._serve_file(fn, ctype)
        self._send(404, b'{"error":"not found"}')

    def _serve_file(self, name, ctype):
        try:
            with open(os.path.join(WEB_DIR, name), "rb") as f:
                self._send(200, f.read(), ctype)
        except OSError:
            self._send(404, b'{"error":"missing"}')

    def _serve_events(self):
        q = self.engine.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                try:
                    obj = q.get(timeout=15)
                    payload = "data: {}\n\n".format(json.dumps(obj))
                except queue.Empty:
                    payload = ": ping\n\n"  # keep the connection alive
                self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.engine.unsubscribe(q)

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/cmd":
            return self._send(404, b'{"error":"not found"}')
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            msg = json.loads(body.decode("utf-8"))
            name = msg.get("name", "")
            args = msg.get("args", {}) or {}
        except Exception as e:
            return self._send(400, json.dumps({"ok": False, "error": str(e)}).encode())
        result = self.engine.command(name, args)
        self._send(200, json.dumps(result).encode("utf-8"))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Clients drop connections constantly here — SSE unsubscribe, a page
        # reload, a closed Safari tab — which surfaces as a reset/broken pipe
        # while reading the request. That's normal for this UI, not a bug worth
        # dumping a traceback to the log for; let everything else through.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


def serve(engine, host="127.0.0.1", port=0):
    """Start the server in a background thread; return (httpd, port)."""
    handler = type("Handler", (_Handler,), {"engine": engine})
    httpd = _Server((host, port), handler)
    actual_port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, name="httpd", daemon=True).start()
    return httpd, actual_port
