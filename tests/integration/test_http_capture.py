"""Capture synthetic POSTs to loopback without changing what the server receives."""

import base64
import contextlib
import http.server
import json
from pathlib import Path
import queue
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import urlsplit

from .support import AgentProcess, FIXTURE_DIR


FIXTURE = FIXTURE_DIR / "http_fixture"
FORM = b"tag=one&tag=two&message=hello+world%26test&padding=" + b"x" * 2048
JSON_BODY = (b'{"kind":"upload","message":"synthetic local request","padding":"'
             + b"y" * 2048 + b'"}')


@contextlib.contextmanager
def local_server(certificate=None, private_key=None):
    received = queue.Queue()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.connection.settimeout(15)
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received.put({"path": self.path, "headers": dict(self.headers), "body": body})
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if certificate is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "{}://127.0.0.1:{}".format("https" if certificate else "http",
                                          server.server_port), received
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


class HTTPCaptureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="md-http-", dir="/private/tmp")
        self.addCleanup(self.scratch.cleanup)
        self.env = {"MACDBG_STATE_DIR": self.scratch.name, "PYTHONDONTWRITEBYTECODE": "1"}

    def capture(self, mode, expected_body, tls=False):
        certificate = private_key = None
        if tls:
            certificate = Path(self.scratch.name) / "local-test.crt"
            private_key = Path(self.scratch.name) / "local-test.key"
            subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-sha256", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                            "-keyout", str(private_key), "-out", str(certificate)],
                           check=True, capture_output=True, timeout=15)
        with local_server(certificate, private_key) as (base_url, received):
            url = base_url + "/" + mode
            with AgentProcess(FIXTURE, mode, extra_args=[url], env=self.env) as agent:
                enabled = agent.cmd("tracer_enable")
                self.assertTrue(enabled["ok"], enabled)
                result = agent.cmd("continue", {"timeout": 60}, timeout=65)
                self.assertEqual(result.get("event"), "exited", result)
                self.assertEqual(result["exit"]["code"], 0, result)
                self.assertIn("HTTP-FIXTURE:ok", result["console"])
                rows = agent.cmd("trace_hits")["hits"]
            actual = received.get(timeout=5)
            self.assertEqual(actual["path"], "/" + mode)
            self.assertEqual(actual["body"], expected_body)
            headers = {name.lower(): value for name, value in actual["headers"].items()}
            self.assertEqual(headers["x-macdbg-fixture"], "synthetic-local-only")
            self.assertEqual(headers["content-type"], "application/json" if mode == "upload-json"
                             else "application/x-www-form-urlencoded")
            if mode != "raw-http":
                self.assertEqual(headers["authorization"], "Bearer test-token")
            self.assertTrue(received.empty(), "capture unexpectedly duplicated the request")
            return url, rows

    def requests(self, rows, url, source="foundation"):
        target = urlsplit(url).path if source == "http1" else url
        requests = [request for row in rows for request in row.get("http_requests", [])
                    if request.get("url") == target and request.get("source") == source]
        summary = [{"call": row.get("call", "")[:140],
                    "error": row.get("capture_error"),
                    "requests": [{"source": request.get("source"),
                                  "url": request.get("url"),
                                  "status": request.get("body", {}).get("status"),
                                  "bytes": request.get("body", {}).get("captured_bytes"),
                                  "warnings": request.get("warnings")}
                                 for request in row.get("http_requests", [])]}
                   for row in rows if row.get("http_requests") or row.get("capture_error")]
        self.assertTrue(requests, {"expected_url": target, "source": source,
                                   "row_count": len(rows), "captures": summary})
        return requests

    def assert_body(self, request, expected):
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["complete"], request)
        self.assertTrue(request["source"], request)
        headers = {item["name"].lower(): item["value"] for item in request["headers"]}
        self.assertEqual(headers["x-macdbg-fixture"], "synthetic-local-only")
        body = request["body"]
        self.assertEqual(body["encoding"], "base64")
        self.assertEqual(base64.b64decode(body["data"]), expected)
        self.assertEqual(body["captured_bytes"], len(expected))
        self.assertEqual(body["total_bytes"], len(expected))
        self.assertFalse(body["truncated"], body)
        self.assertEqual(body["text"], expected.decode("utf-8"))
        return body

    def test_urlsession_request_retains_headers_and_full_form_body(self):
        url, rows = self.capture("data-form", FORM)
        request = next(request for request in self.requests(rows, url)
                       if request["body"].get("captured_bytes") == len(FORM))
        body = self.assert_body(request, FORM)
        headers = {item["name"].lower(): item["value"] for item in request["headers"]}
        self.assertEqual(headers["authorization"], "Bearer test-token")
        self.assertIn({"name": "tag", "value": "one"}, body["fields"])
        self.assertIn({"name": "tag", "value": "two"}, body["fields"])
        self.assertIn({"name": "message", "value": "hello world&test"}, body["fields"])

    def test_urlsession_upload_captures_fromdata_instead_of_httpbody(self):
        url, rows = self.capture("upload-json", JSON_BODY)
        request = next(request for request in self.requests(rows, url)
                       if request["body"].get("captured_bytes") == len(JSON_BODY))
        body = self.assert_body(request, JSON_BODY)
        self.assertEqual(body["json"], json.loads(JSON_BODY))

    def test_https_urlsession_captures_plaintext_request_before_tls(self):
        url, rows = self.capture("data-https", FORM, tls=True)
        self.assertTrue(url.startswith("https://"))
        request = next(request for request in self.requests(rows, url)
                       if request["body"].get("captured_bytes") == len(FORM))
        body = self.assert_body(request, FORM)
        headers = {item["name"].lower(): item["value"] for item in request["headers"]}
        self.assertEqual(headers["authorization"], "Bearer test-token")
        self.assertIn({"name": "message", "value": "hello world&test"}, body["fields"])

    def test_stream_body_is_reported_unavailable_without_consuming_stream(self):
        url, rows = self.capture("stream-form", FORM)
        candidates = self.requests(rows, url)
        self.assertTrue(any(request["body"].get("status") in ("unavailable", "stream_unavailable")
                            and request["body"].get("captured_bytes", 0) == 0
                            for request in candidates), candidates)

    def test_socket_send_and_write_reassemble_split_headers_and_body(self):
        url, rows = self.capture("raw-http", FORM)
        request = next(request for request in self.requests(rows, url, "http1")
                       if request.get("complete"))
        body = self.assert_body(request, FORM)
        self.assertIn({"name": "tag", "value": "two"}, body["fields"])
        writes = [row for row in rows if row.get("payload")
                  and row.get("capture_stream") == request["stream"]
                  and not row.get("assembly_skipped")]
        self.assertEqual({row["capture_source"] for row in writes}, {"send", "write"})
        wire = b"".join(base64.b64decode(row["payload"]["data"]) for row in writes)
        self.assertEqual(wire.split(b"\r\n\r\n", 1)[1], FORM)
        for nested in (row for row in rows if row.get("assembly_skipped")):
            self.assertIn(nested["payload"]["data"],
                          [row["payload"]["data"] for row in writes])


if __name__ == "__main__":
    unittest.main()
