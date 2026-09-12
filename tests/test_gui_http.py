import http.client
import json
import queue
import unittest
import threading
from unittest.mock import Mock

from GUI.server.httpd import serve


class Engine:
    def __init__(self):
        self.commands = []

    def command(self, name, args):
        self.commands.append((name, args))
        return {"ok": True}

    def subscribe(self):
        q = queue.Queue()
        q.put({"t": "state", "process_state": "none"})
        return q

    def unsubscribe(self, q):
        pass


class GuiHttpTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        self.server, self.port = serve(self.engine)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method="POST", path="/cmd", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        self.addCleanup(connection.close)
        connection.request(method, path, body=body or '{"name":"refresh"}', headers=headers or {})
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def auth(self, **extras):
        return {"Content-Type": "application/json", "X-Macdbg-Token": self.server.token, **extras}

    def test_missing_or_incorrect_credential_never_dispatches(self):
        for headers in ({}, self.auth(**{"X-Macdbg-Token": "incorrect"})):
            self.assertEqual(self.request(headers=headers)[0], 403)
        self.assertEqual(self.engine.commands, [])

    def test_foreign_origin_or_host_is_rejected_even_with_token(self):
        for headers in ({"Origin": "http://untrusted.invalid"}, {"Host": "untrusted.invalid"}, {"Origin": "null"}):
            self.assertEqual(self.request(headers=self.auth(**headers))[0], 403)
        self.assertEqual(self.engine.commands, [])

    def test_native_and_same_origin_clients_can_dispatch(self):
        for extras in ({}, {"Origin": "http://127.0.0.1:{}".format(self.port)}):
            self.assertEqual(self.request(headers=self.auth(**extras)), (200, {"ok": True}))
        self.assertEqual(self.engine.commands, [("refresh", {}), ("refresh", {})])

    def test_wrong_type_and_malformed_arguments_do_not_dispatch(self):
        self.assertEqual(self.request(headers=self.auth(**{"Content-Type": "text/plain"}))[0], 415)
        self.assertEqual(self.request(body='{"name":[],"args":[]}', headers=self.auth())[0], 400)
        self.assertEqual(self.request(headers=self.auth(**{"Content-Length": "1048577"}))[0], 413)
        self.assertEqual(self.engine.commands, [])

    def test_event_stream_and_health_require_session_credential(self):
        for path in ("/events", "/health"):
            self.assertEqual(self.request("GET", path)[0], 403)
        self.assertEqual(self.request("GET", "/health", headers=self.auth())[0], 200)

    def test_tokens_are_unique_per_server(self):
        second, _ = serve(Engine())
        try:
            self.assertNotEqual(self.server.token, second.token)
        finally:
            second.shutdown()
            second.server_close()


class EngineQueueTests(unittest.TestCase):
    def test_timeout_cancels_queued_mutation_before_it_can_run_later(self):
        from GUI.server.engine import Engine
        engine = Engine.__new__(Engine)
        pending = []
        engine.submit = lambda fn: pending.append(fn)
        mutation = Mock()
        with self.assertRaisesRegex(TimeoutError, "cancelled before execution"):
            engine._run_sync(mutation, timeout=0.01)
        pending[0]()
        mutation.assert_not_called()

    def test_slow_subscriber_disconnects_instead_of_growing_forever(self):
        from GUI.server.engine import Engine
        engine = Engine.__new__(Engine)
        q = queue.Queue(maxsize=2)
        engine._subs, engine._subs_lock = {q}, threading.Lock()
        for n in range(100):
            engine._emit({"t": "trace", "n": n})
        self.assertEqual(q.get_nowait(), {"t": "resync"})
        self.assertTrue(q.empty())
        self.assertEqual(engine._subs, set())
