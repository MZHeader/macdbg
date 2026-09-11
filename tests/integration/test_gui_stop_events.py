import queue
import time
import unittest
import tempfile
from pathlib import Path

from GUI.server.engine import Engine

from .support import FIXTURE, FRIDA_FIXTURE, FIXTURE_DIR, fixture_text_digest


class GuiStopEventIntegrationTests(unittest.TestCase):
    def test_osa_prompt_blocks_until_decision_and_does_not_execute_script(self):
        with tempfile.TemporaryDirectory(prefix='macdbg-gui-osa-', dir='/private/tmp') as directory:
            marker = Path(directory) / 'executed'
            engine = Engine(str(FIXTURE_DIR / 'script_exec_fixture'), ['execute', str(marker), 'block'])
            engine.dbg.exec_interactive = True
            engine.start()
            events = engine.subscribe()
            try:
                self.collect_until(events, lambda e: e.get('t') == 'console' and e.get('text', '').startswith('launched '))
                engine.command('defense', {'key': 'exec_sandbox'})
                self.collect_until(events, lambda e: 'exec sandbox armed' in e.get('text', ''))
                engine.command('cont', {})
                result = self.collect_until(events, lambda e: e.get('t') == 'prompt')
                self.assertEqual(result[-1]['name'], 'OSAExecute')
                self.assertIn('executed', result[-1]['script_content']['text'])
                self.assertIn('captured_payload', result[-1]['metadata'])
                token = result[-1]['token']
                engine.command('decide_exec', {'decision': 'allow', 'token': 'stale'})
                stale = self.collect_until(events, lambda e: e.get('t') == 'prompt' and e.get('dump_error'))
                self.assertEqual(stale[-1]['token'], token)
                self.assertFalse(marker.exists())
                reconnected = engine.subscribe()
                replay = self.collect_until(reconnected, lambda e: e.get('t') == 'prompt')
                self.assertEqual(replay[-1]['name'], 'OSAExecute')
                engine.unsubscribe(reconnected)
                engine.command('decide_exec', {'decision': 'dump', 'token': token})
                dumped = self.collect_until(events, lambda e: e.get('t') == 'prompt' and e.get('dump_result'))
                self.assertIn('Readable content:', dumped[-1]['dump_result'])
                self.assertIn('executed', Path(dumped[-1]['content_path']).read_text())
                self.assertEqual(Path(dumped[-1]['dump_path']).read_bytes(),
                                 Path(str(marker) + '.source.txt').read_bytes())
                self.assertFalse(marker.exists())
                engine.command('decide_exec', {'decision': 'block', 'token': token})
                result = self.collect_until(events, lambda e: e.get('text', '').startswith('process exited with code'))
                self.assertIn('code 0', result[-1]['text'])
                self.assertFalse(marker.exists())
            finally:
                engine.shutdown()

    def collect_until(self, events, predicate, timeout=25):
        collected = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = events.get(timeout=min(0.5, deadline - time.monotonic()))
            except queue.Empty:
                continue
            collected.append(event)
            if predicate(event):
                return collected
        self.fail("timed out waiting for GUI event; received {!r}".format(collected[-10:]))

    @staticmethod
    def drain(events, duration=0.75):
        collected = []
        deadline = time.monotonic() + duration
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                collected.append(events.get(timeout=remaining))
            except queue.Empty:
                break
        return collected

    def test_compiled_fixture_does_not_surface_internal_return_stops(self):
        engine = Engine(
            program=str(FIXTURE),
            program_args=["combined", fixture_text_digest(), str(FRIDA_FIXTURE.resolve())],
        )
        engine.start()
        events = engine.subscribe()
        try:
            launched = self.collect_until(
                events,
                lambda event: (event.get("t") == "console"
                               and event.get("text", "").startswith("launched ")),
            )
            self.assertTrue(launched)

            engine.command("defense", {"key": "analysis_cloak"})
            enabled = self.collect_until(
                events,
                lambda event: (event.get("t") == "console"
                               and "analysis cloak enabled" in event.get("text", "")),
            )
            self.assertTrue(enabled)

            engine.command("cont", {})
            completed = self.collect_until(
                events,
                lambda event: (event.get("t") == "console"
                               and event.get("text", "").startswith(
                                   "process exited with code")),
            )
            completed.extend(self.drain(events))
            console = [event.get("text", "") for event in completed
                       if event.get("t") == "console"]
            self.assertIn(
                "PAYLOAD:macdbg analysis cloak recovered this payload",
                "\n".join(console),
            )
            self.assertFalse(
                any(line.startswith("[stop]") for text in console
                    for line in text.splitlines()),
                console,
            )
        finally:
            engine.shutdown()


if __name__ == "__main__":
    unittest.main()
