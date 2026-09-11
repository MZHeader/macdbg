"""End-to-end tests exclusively using locally built, benign timing fixtures."""
import json
import os
import re
import subprocess
import tempfile
import time
import unittest

from .support import AgentProcess, FIXTURE_DIR, run_core_probe


FIXTURES = [FIXTURE_DIR / "timing_fixture", FIXTURE_DIR / "timing_fixture_optimized"]


def symbol(fixture, name):
    output = subprocess.check_output(["nm", str(fixture)], text=True)
    return next(int(row.split()[0], 16) for row in output.splitlines()
                if row.split()[-1] == "_" + name)


def add_rule(agent, fixture, style="penalty"):
    name = {"penalty": "timing_decision", "mask": "timing_mask_decision",
            "branch": "timing_branch_decision"}[style]
    args = {"name": "elapsed-result", "addr": hex(symbol(fixture, name))}
    if style == "branch":
        args["redirect"] = hex(symbol(fixture, "timing_branch_clean"))
    else:
        args.update(register="w8", value=0)
        if style == "mask":
            args["mask"] = "0xffff"
    result = agent.cmd("timing_rule_add", args)
    if not result["ok"]:
        raise AssertionError(result)
    return args


class TimingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="macdbg-timing-", dir="/private/tmp")
        self.env = {"MACDBG_STATE_DIR": self.scratch.name, "PYTHONDONTWRITEBYTECODE": "1"}

    def tearDown(self):
        self.scratch.cleanup()

    def agent(self, fixture=FIXTURES[0], source="dynamic", style="penalty", delay="40000",
              aggregate="min", threads=False):
        return AgentProcess(fixture, source, [delay, style, aggregate] + (["threads"] if threads else []), env=self.env)

    def assert_clean(self, result):
        self.assertTrue(result["ok"], result)
        self.assertEqual(result.get("event"), "exited", result)
        self.assertEqual(result["exit"]["code"], 0, result)
        self.assertIn("PAYLOAD:local timing fixture recovered", result["console"])
        self.assertNotIn("TIMING:detected", result["console"])
        # The defense changes the decision; the real delayed clock stays real.
        measured = re.findall(r"\bns=(\d+)", result["console"])
        self.assertTrue(measured, result)
        self.assertTrue(all(int(ns) > 20000000 for ns in measured), measured)

    def test_native_baseline_and_forced_delay(self):
        for fixture in FIXTURES:
            for delay, code in [("0", 0), ("40000", 1)]:
                with self.subTest(fixture=fixture.name, delay=delay):
                    result = subprocess.run([str(fixture), "mach", delay], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)

    def test_toggle_controls_penalty_and_restart_rearms(self):
        with self.agent() as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            add_rule(agent, FIXTURES[0])
            disabled = agent.continue_to_exit()
            self.assertEqual(disabled["exit"]["code"], 1, disabled)
            self.assertTrue(agent.cmd("restart")["ok"])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assert_clean(agent.continue_to_exit())
            status = agent.cmd("timing_rules")
            self.assertTrue(status["safe"], status)
            self.assertEqual(status["hits"], {"elapsed-result": 1})
            self.assertTrue(agent.cmd("restart")["ok"])
            self.assert_clean(agent.continue_to_exit())
            self.assertTrue(agent.cmd("defense_disable", {"name": "anti_timing"})["ok"])
            self.assertTrue(agent.cmd("restart")["ok"])
            self.assertEqual(agent.continue_to_exit()["exit"]["code"], 1)

    def test_clock_sources_and_optimized_build(self):
        for fixture in FIXTURES:
            for source in ("mach", "dynamic", "continuous", "monotonic", "wall", "counter"):
                with self.subTest(fixture=fixture.name, source=source), self.agent(fixture, source) as agent:
                    # Each session saves rules, so explicitly remove previously configured ones.
                    for rule in agent.cmd("timing_rules")["rules"]:
                        self.assertTrue(agent.cmd("timing_rule_remove", {"name": rule["name"]})["ok"])
                    add_rule(agent, fixture)
                    self.assertTrue(agent.enable_cloak()["ok"])
                    self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
                    self.assert_clean(agent.continue_to_exit())

    def test_mask_and_redirect_with_maximum_aggregation(self):
        for style in ("mask", "branch"):
            with self.subTest(style=style), self.agent(style=style, aggregate="max") as agent:
                for rule in agent.cmd("timing_rules")["rules"]:
                    agent.cmd("timing_rule_remove", {"name": rule["name"]})
                add_rule(agent, FIXTURES[0], style)
                self.assertTrue(agent.enable_cloak()["ok"])
                self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
                self.assert_clean(agent.continue_to_exit())

    def test_rule_is_saved_but_new_session_starts_disabled(self):
        with self.agent() as agent:
            rule = add_rule(agent, FIXTURES[0])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assertTrue(agent.cmd("save")["ok"])
        with self.agent() as agent:
            status = agent.cmd("timing_rules")
            self.assertFalse(status["enabled"])
            self.assertEqual(status["rules"][0]["name"], rule["name"])
            self.assertFalse(agent.cmd("breakpoint_list")["breakpoints"])

    def test_shared_user_breakpoint_and_instruction_step(self):
        with self.agent() as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            args = add_rule(agent, FIXTURES[0])
            self.assertTrue(agent.cmd("breakpoint_toggle", {"addr": args["addr"]})["ok"])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            stopped = agent.continue_to_exit()
            self.assertEqual(stopped.get("event"), "stop", stopped)
            self.assertEqual(stopped["stop"]["pc"], int(args["addr"], 16))
            self.assertEqual(agent.cmd("timing_rules")["hits"], {"elapsed-result": 1})
            stepped = agent.cmd("step_in", {"timeout": 10})
            self.assertEqual(stepped.get("event"), "stop", stepped)
            self.assertEqual(stepped["stop"]["pc"], int(args["addr"], 16) + 4)
            self.assertEqual(agent.cmd("timing_rules")["hits"], {"elapsed-result": 1})
            self.assert_clean(agent.continue_to_exit())

    def test_step_landing_on_rule_applies_once(self):
        with self.agent() as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            args = add_rule(agent, FIXTURES[0])
            address = int(args["addr"], 16)
            agent.cmd("breakpoint_toggle", {"addr": address - 4})
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assertEqual(agent.continue_to_exit()["event"], "stop")
            landed = agent.cmd("step_in", {"timeout": 10})
            self.assertEqual(landed.get("event"), "stop", landed)
            self.assertEqual(landed["stop"]["pc"], address)
            self.assertEqual(agent.cmd("timing_rules")["hits"], {"elapsed-result": 1})
            self.assert_clean(agent.continue_to_exit())

    def test_two_threads_use_their_own_registers(self):
        with self.agent(threads=True) as agent:
            add_rule(agent, FIXTURES[0])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assert_clean(agent.continue_to_exit())
            self.assertEqual(agent.cmd("timing_rules")["hits"], {"elapsed-result": 2})

    def test_deleted_hook_blocks_resume_until_disabled(self):
        with self.agent() as agent:
            self.assertFalse(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            add_rule(agent, FIXTURES[0])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assertFalse(agent.cmd("timing_rule_remove", {"name": "elapsed-result"})["ok"])
            bp = agent.cmd("breakpoint_list", {"hide_internal": False})["breakpoints"][0]
            self.assertFalse(agent.cmd("breakpoint_delete", {"bp_id": bp["id"]})["ok"])
            agent.cmd("raw", {"command": "breakpoint delete {}".format(bp["id"])})
            self.assertFalse(agent.continue_to_exit()["ok"])
            self.assertFalse(agent.cmd("timing_rules")["safe"])
            self.assertTrue(agent.cmd("defense_disable", {"name": "anti_timing"})["ok"])

    def test_modified_auto_continue_filter_blocks_resume(self):
        with self.agent() as agent:
            add_rule(agent, FIXTURES[0])
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            bp = agent.cmd("breakpoint_list", {"hide_internal": False})["breakpoints"][0]
            result = agent.cmd("raw", {"command":
                "script lldb.debugger.GetSelectedTarget().FindBreakpointByID({}).SetAutoContinue(True)".format(bp["id"])})
            self.assertTrue(result["ok"], result)
            result = agent.continue_to_exit()
            self.assertFalse(result["ok"], result)
            self.assertIn("filters were modified", result["error"])
            self.assertEqual(agent.cmd("status")["process_state"], "stopped")

    def test_real_debugger_pauses_across_all_measurements(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), self.agent(delay="0") as agent:
                self.assertTrue(agent.enable_cloak()["ok"])
                if enabled:
                    add_rule(agent, FIXTURES[0])
                    self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
                agent.cmd("breakpoint_toggle", {"addr": symbol(FIXTURES[0], "timing_pause")})
                for _ in range(3):
                    result = agent.continue_to_exit()
                    self.assertEqual(result.get("event"), "stop", result)
                    time.sleep(0.05)
                result = agent.continue_to_exit()
                if enabled:
                    self.assert_clean(result)
                else:
                    self.assertEqual(result["exit"]["code"], 1, result)

    def test_step_out_preserves_bounded_plan(self):
        with self.agent() as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            add_rule(agent, FIXTURES[0])
            agent.cmd("breakpoint_toggle", {"addr": symbol(FIXTURES[0], "timing_result")})
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_timing"})["ok"])
            self.assertEqual(agent.continue_to_exit()["event"], "stop")
            result = agent.cmd("step_out", {"timeout": 10})
            self.assertEqual(result.get("event"), "stop", result)
            self.assertEqual(agent.cmd("timing_rules")["hits"], {"elapsed-result": 1})
            self.assert_clean(agent.continue_to_exit())

    def test_stale_instruction_guard_blocks_activation_and_resume(self):
        result = run_core_probe('''
            import json, os
            os.environ["MACDBG_STATE_DIR"] = STATE_PATH
            from macdbg.agent.session import AgentSession
            from tests.integration.test_timing_rules import FIXTURES, symbol
            session = AgentSession(str(FIXTURES[0]), ["mach", "40000"])
            try:
                assert session.start()["ok"]
                timing = session.dbg.timing
                address = symbol(FIXTURES[0], "timing_decision")
                timing.add({"name": "elapsed", "addr": address, "register": "w8", "value": 0})
                expected = timing.rules[0]["expected"]
                timing.rules[0]["expected"] = "00000000"
                rejected_enable = timing.enable()
                timing.rules[0]["expected"] = expected
                assert timing.enable()[0]
                timing.rules[0]["expected"] = "00000000"
                rejected_resume = session.dispatch("continue", {"timeout": 5})
                print(json.dumps({"enable": rejected_enable, "resume": rejected_resume,
                                  "original": expected,
                                  "actual": session.dbg.read_memory(address, 4).hex()}))
            finally:
                session.shutdown(save=False)
        '''.replace("STATE_PATH", repr(self.scratch.name)))
        self.assertFalse(result["enable"][0], result)
        self.assertFalse(result["resume"]["ok"], result)
        self.assertIn("instruction changed", result["resume"]["error"])
        self.assertEqual(result["original"], result["actual"])

    def test_gui_configure_toggle_and_execution(self):
        # A separate interpreter keeps LLDB isolated from unit-test doubles.
        result = run_core_probe('''
            import json, os, queue, time
            os.environ["MACDBG_STATE_DIR"] = STATE_PATH
            from GUI.server.engine import Engine
            from tests.integration.test_timing_rules import FIXTURES, symbol
            engine = Engine(str(FIXTURES[0]), ["dynamic", "40000"])
            events = engine.subscribe()
            engine.start()
            seen = []
            def wait_for(predicate):
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        event = events.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    seen.append(event)
                    if predicate(event):
                        return event
                raise AssertionError(seen[-10:])
            def text_contains(text):
                return lambda event: event.get("t") == "console" and text in event.get("text", "")
            try:
                wait_for(text_contains("launched "))
                engine.command("timing_rule_add", {
                    "name": "elapsed-result", "addr": hex(symbol(FIXTURES[0], "timing_decision")),
                    "register": "w8", "value": 0})
                wait_for(text_contains("configured elapsed-result"))
                engine.command("defense", {"key": "analysis_cloak"})
                wait_for(text_contains("analysis cloak enabled"))
                engine.command("defense", {"key": "anti_timing"})
                wait_for(text_contains("timing rules enabled"))
                engine.command("cont", {})
                wait_for(text_contains("process exited with code 0"))
                time.sleep(0.1)
                while not events.empty(): seen.append(events.get_nowait())
                status = engine._run_sync(engine._defense_states)
                print(json.dumps({"events": seen, "status": status}))
            finally:
                engine.shutdown()
        '''.replace("STATE_PATH", repr(self.scratch.name)), timeout=45)
        self.assertTrue(result["status"]["anti_timing_safe"], result)
        self.assertEqual(result["status"]["timing_hits"], {"elapsed-result": 1})
        console = "\n".join(event.get("text", "") for event in result["events"] if event.get("t") == "console")
        self.assertIn("PAYLOAD:local timing fixture recovered", console)
        self.assertNotIn("[engine]", console)
        self.assertNotIn("[stop]", console)

    def test_switching_target_clears_rules_and_hooks(self):
        result = run_core_probe('''
            import json, os
            os.environ["MACDBG_STATE_DIR"] = STATE_PATH
            from macdbg.agent.session import AgentSession
            from tests.integration.test_timing_rules import FIXTURES, symbol
            session = AgentSession(str(FIXTURES[0]), ["mach", "40000"])
            try:
                assert session.start()["ok"]
                timing = session.dbg.timing
                timing.add({"name": "elapsed", "addr": symbol(FIXTURES[0], "timing_decision"),
                            "register": "w8", "value": 0})
                assert timing.enable()[0]
                outcome = session.dispatch("continue", {"timeout": 10})
                assert outcome["exit"]["code"] == 0, outcome
                assert timing.hits == {"elapsed": 1}, timing.hits
                session.dbg.create_target(str(FIXTURES[1]))
                session.dbg.launch(["mach", "40000"])
                print(json.dumps(timing.status()))
            finally:
                session.shutdown(save=False)
        '''.replace("STATE_PATH", repr(self.scratch.name)))
        self.assertFalse(result["enabled"])
        self.assertEqual(result["armed"], 0)
        self.assertEqual(result["rules"], [])
        self.assertEqual(result["hits"], {})


if __name__ == "__main__":
    unittest.main()
