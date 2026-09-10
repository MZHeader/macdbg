import queue
import time
import unittest

from GUI.server.engine import Engine

from .support import FIXTURE, FRIDA_FIXTURE, fixture_text_digest


class GuiStopEventIntegrationTests(unittest.TestCase):
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
