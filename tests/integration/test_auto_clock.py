"""Automatic timing compensation against benign, locally compiled fixtures."""
import re
import tempfile
import time
import unittest

from .support import AgentProcess, run_core_probe
from .test_timing_rules import FIXTURES, symbol


class AutomaticClockTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="macdbg-clock-", dir="/private/tmp")
        self.env = {"MACDBG_STATE_DIR": self.scratch.name, "PYTHONDONTWRITEBYTECODE": "1"}

    def tearDown(self):
        self.scratch.cleanup()

    def agent(self, fixture=FIXTURES[0], source="dynamic", delay="0", style="penalty", aggregate="min"):
        return AgentProcess(fixture, source, [delay, style, aggregate], env=self.env)

    def enable(self, agent):
        self.assertTrue(agent.enable_cloak()["ok"])
        enabled = agent.cmd("defense_enable", {"name": "auto_clock"})
        self.assertTrue(enabled["ok"], enabled)
        status = agent.cmd("clock_status")
        self.assertTrue(status["safe"], status)
        self.assertEqual(len(status["apis"]), 5)
        self.assertTrue(status["scan_complete"], status)
        self.assertEqual(status["counter_sites"], status["counter_armed"], status)
        self.assertFalse(agent.cmd("timing_rules")["rules"])

    def pause_three_times(self, agent, fixture):
        # This is a test-induced pause, not a rule identifying a timing decision.
        breakpoint = agent.cmd("breakpoint_toggle", {"addr": symbol(fixture, "timing_pause")})
        self.assertTrue(breakpoint["ok"], breakpoint)
        for _ in range(3):
            stopped = agent.continue_to_exit()
            self.assertEqual(stopped.get("event"), "stop", stopped)
            time.sleep(0.08)
        return agent.continue_to_exit()

    def assert_clean(self, result):
        self.assertTrue(result["ok"], result)
        self.assertEqual(result.get("event"), "exited", result)
        self.assertEqual(result["exit"]["code"], 0, result)
        self.assertIn("PAYLOAD:local timing fixture recovered", result["console"])

    def test_dynamic_clock_without_rules(self):
        with self.agent() as agent:
            self.enable(agent)
            result = self.pause_three_times(agent, FIXTURES[0])
            self.assert_clean(result)
            status = agent.cmd("clock_status")
            self.assertEqual(status["hits"]["mach_absolute_time"], 6)
            self.assertGreater(status["paused_ns"], 240000000)

    def test_real_program_sleep_is_not_removed(self):
        with self.agent(delay="40000") as agent:
            self.enable(agent)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 1, result)
            ns = int(re.search(r"ns=(\d+)", result["console"])[1])
            self.assertGreaterEqual(ns, 30000000)

    def test_all_clock_sources_and_builds(self):
        for fixture in FIXTURES:
            for source in ("mach", "continuous", "monotonic", "wall", "counter", "physical"):
                with self.subTest(fixture=fixture.name, source=source), self.agent(fixture, source) as agent:
                    self.enable(agent)
                    self.assert_clean(self.pause_three_times(agent, fixture))

    def test_disabled_control_detects_debugger_delay(self):
        with self.agent() as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            result = self.pause_three_times(agent, FIXTURES[0])
            self.assertEqual(result["exit"]["code"], 1, result)

    def test_maximum_aggregation_and_branch_are_also_automatic(self):
        with self.agent(style="branch", aggregate="max") as agent:
            self.enable(agent)
            self.assert_clean(self.pause_three_times(agent, FIXTURES[0]))

    def test_restart_rearms_and_late_enable_is_rejected(self):
        with self.agent() as agent:
            self.enable(agent)
            self.assert_clean(agent.continue_to_exit())
            self.assertTrue(agent.cmd("restart")["ok"])
            self.assert_clean(self.pause_three_times(agent, FIXTURES[0]))
            self.assertTrue(agent.cmd("restart")["ok"])
            self.assertTrue(agent.cmd("defense_disable", {"name": "auto_clock"})["ok"])
            stopped = agent.continue_to_exit()
            self.assertEqual(stopped.get("event"), "stop", stopped)
            enabled = agent.cmd("defense_enable", {"name": "auto_clock"})
            self.assertFalse(enabled["ok"], enabled)

    def test_clock_contracts_preserve_waits_errors_and_monotonicity(self):
        with self.agent(source="contracts") as agent:
            self.enable(agent)
            agent.cmd("breakpoint_toggle", {"addr": symbol(FIXTURES[0], "timing_pause")})
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            time.sleep(0.12)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("CONTRACTS:clean", result["console"])
            status = agent.cmd("clock_status")
            self.assertEqual(status["hits"]["mach_wait_until"], 1)
            self.assertGreaterEqual(status["passthrough"], 2)

    def test_step_out_runs_through_clock_hook_without_losing_plan(self):
        with self.agent() as agent:
            self.enable(agent)
            agent.cmd("breakpoint_toggle", {"addr": symbol(FIXTURES[0], "now")})
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            time.sleep(0.08)
            result = agent.cmd("step_out", {"timeout": 10})
            self.assertEqual(result.get("event"), "stop", result)
            self.assertEqual(agent.cmd("clock_status")["hits"].get("mach_absolute_time"), 1)
            agent.clear_user_breakpoints()
            self.assert_clean(agent.continue_to_exit())

    def test_instruction_steps_across_clock_call_preserve_caller_stop(self):
        for command in ("step_over", "step_in"):
            with self.subTest(command=command), self.agent(source="probe") as agent:
                self.enable(agent)
                at = symbol(FIXTURES[0], "timing_clock_call")
                returned = symbol(FIXTURES[0], "timing_clock_return")
                bp = agent.cmd("breakpoint_toggle", {"addr": at})
                self.assertTrue(bp["ok"], bp)
                agent.cmd("raw", {"command": "breakpoint modify --ignore-count 1 {}".format(bp["bp_id"])})
                self.assertEqual(agent.continue_to_exit().get("event"), "stop")
                time.sleep(0.08)
                for _ in range(16):
                    result = agent.cmd(command, {"timeout": 10})
                    self.assertEqual(result.get("event"), "stop", result)
                    if result["stop"]["pc"] == returned:
                        break
                    if command == "step_over":
                        self.fail("step-over did not return to caller: {!r}".format(result))
                self.assertEqual(result["stop"]["pc"], returned, result)
                self.assertEqual(agent.cmd("clock_status")["hits"].get("mach_absolute_time"), 2)
                agent.clear_user_breakpoints()
                self.assert_clean(agent.continue_to_exit())

    def test_shared_clock_entry_preserves_user_stop(self):
        with self.agent() as agent:
            self.enable(agent)
            address = agent.cmd('clock_status')['entry_points']['mach_absolute_time']
            raw = agent.cmd("raw", {"command": "breakpoint set -a {:#x}".format(address)})
            self.assertTrue(raw["ok"], raw)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "stop", result)
            status = agent.cmd("clock_status")
            self.assertEqual(status["hits"].get("mach_absolute_time"), 1)
            agent.clear_user_breakpoints()
            self.assert_clean(agent.continue_to_exit())

    def test_deleted_api_hook_blocks_resume(self):
        with self.agent() as agent:
            self.enable(agent)
            rows = agent.cmd("breakpoint_list", {"hide_internal": False})["breakpoints"]
            address = agent.cmd('clock_status')['entry_points']['mach_absolute_time']
            clock = next(row for row in rows if row['addr'] == address)
            self.assertFalse(agent.cmd("breakpoint_delete", {"bp_id": clock["id"]})["ok"])
            agent.cmd("raw", {"command": "breakpoint delete {}".format(clock["id"])})
            result = agent.continue_to_exit()
            self.assertFalse(result["ok"], result)
            self.assertIn("clock breakpoint", result["error"])
            self.assertEqual(agent.cmd("status")["process_state"], "stopped")

    def test_disabled_forwarder_keeps_cached_function_pointer_callable(self):
        with self.agent() as agent:
            self.enable(agent)
            address = agent.cmd('clock_status')['entry_points']['mach_absolute_time']
            before = agent.cmd('read_memory', {'addr': address, 'size': 16})['hex']
            agent.cmd('breakpoint_toggle', {'addr': symbol(FIXTURES[0], 'timing_pause')})
            self.assertEqual(agent.continue_to_exit()['event'], 'stop')
            self.assertTrue(agent.cmd('defense_disable', {'name': 'auto_clock'})['ok'])
            self.assertEqual(agent.cmd('read_memory', {'addr': address, 'size': 16})['hex'], before)
            agent.clear_user_breakpoints()
            result = agent.continue_to_exit()
            self.assertEqual(result['event'], 'exited', result)
            self.assertIn(result['exit']['code'], (0, 1), result)
            self.assertIn('ns=', result['console'])

    def test_bindings_are_guarded_and_forwarders_are_not_writable(self):
        result = run_core_probe('''
            import json, lldb
            from macdbg.agent.session import AgentSession
            from tests.integration.test_timing_rules import FIXTURES
            s = AgentSession(str(FIXTURES[0]), ['dynamic', '0'])
            try:
                assert s.start()['ok']
                assert s.dbg.enable_auto_clock()[0]
                c = s.dbg.auto_clock
                region = lldb.SBMemoryRegionInfo()
                address = c.bindings.proxies['mach_absolute_time']
                assert s.dbg.process.GetMemoryRegionInfo(address, region).Success()
                writable, executable = region.IsWritable(), region.IsExecutable()
                original_addresses = set(c.bindings.originals.values())
                hook_addresses = {entry[0] for entry in c._hooks.values()}
                slot = c.bindings.slots[0][0]
                assert s.dbg.write_memory(slot, bytes(8), track=False)[0]
                valid, message = c.validate()
                print(json.dumps({'writable': writable, 'executable': executable,
                                  'system_hooked': bool(original_addresses & hook_addresses),
                                  'valid': valid, 'error': message}))
            finally:
                s.shutdown(save=False)
        ''')
        self.assertFalse(result['writable'], result)
        self.assertTrue(result['executable'], result)
        self.assertFalse(result['system_hooked'], result)
        self.assertFalse(result['valid'], result)
        self.assertIn('binding was modified', result['error'])

    def test_counter_slot_exhaustion_reports_partial_coverage(self):
        result = run_core_probe('''
            import json, os
            os.environ["MACDBG_STATE_DIR"] = STATE_PATH
            from macdbg.agent.session import AgentSession
            from macdbg.core.breakpoints import hardware_breakpoint_capacity
            from tests.integration.test_timing_rules import FIXTURES, symbol
            session = AgentSession(str(FIXTURES[0]), ["mach", "0"])
            try:
                assert session.start()["ok"]
                d = session.dbg
                at = symbol(FIXTURES[0], "main")
                for i in range(hardware_breakpoint_capacity()):
                    d.create_hardware_breakpoint_by_address(at + i * 4)
                enabled = d.auto_clock.enable()
                print(json.dumps({"enabled": enabled, "status": d.auto_clock.status()}))
            finally:
                session.shutdown(save=False)
        '''.replace("STATE_PATH", repr(self.scratch.name)))
        self.assertTrue(result["enabled"][0], result)
        status = result["status"]
        self.assertTrue(status["safe"], result)
        self.assertGreater(status["counter_sites"], 0)
        self.assertEqual(status["counter_armed"], 0)
        self.assertFalse(status["counter_coverage_complete"])
        self.assertTrue(status["coverage_notes"])

    def test_automatic_clocks_coexist_with_combined_cloak_checks(self):
        from .support import FIXTURE, FRIDA_FIXTURE, fixture_text_digest
        with AgentProcess(FIXTURE, "combined", [fixture_text_digest(), str(FRIDA_FIXTURE.resolve())], env=self.env) as agent:
            self.enable(agent)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("PAYLOAD:macdbg analysis cloak recovered this payload", result["console"])

    def test_two_threads_share_one_pause_budget(self):
        with AgentProcess(FIXTURES[0], "dynamic", ["0", "penalty", "min", "threads"], env=self.env) as agent:
            self.enable(agent)
            agent.cmd("breakpoint_toggle", {"addr": symbol(FIXTURES[0], "timing_pause")})
            for _ in range(8):
                result = agent.continue_to_exit()
                if result.get("event") == "exited":
                    break
                self.assertEqual(result.get("event"), "stop", result)
                time.sleep(0.05)
            self.assert_clean(result)
            self.assertEqual(agent.cmd("clock_status")["hits"]["mach_absolute_time"], 12)

    def test_gui_uses_observation_timestamps_for_user_pauses(self):
        result = run_core_probe('''
            import json, os, queue, time
            os.environ["MACDBG_STATE_DIR"] = STATE_PATH
            from GUI.server.engine import Engine
            from tests.integration.test_timing_rules import FIXTURES, symbol
            engine = Engine(str(FIXTURES[0]), ["dynamic", "0"])
            events = engine.subscribe()
            engine.start()
            seen = []
            def wait_for(text):
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try: event = events.get(timeout=0.5)
                    except queue.Empty: continue
                    seen.append(event)
                    if event.get("t") == "console" and text in event.get("text", ""):
                        return
                raise AssertionError(seen[-10:])
            try:
                wait_for("launched ")
                engine.command("defense", {"key": "analysis_cloak"})
                wait_for("analysis cloak enabled")
                engine.command("defense", {"key": "auto_clock"})
                wait_for("automatic clocks enabled")
                engine.command("toggle_bp", {"addr": symbol(FIXTURES[0], "timing_pause")})
                engine._run_sync(lambda: None)
                for _ in range(3):
                    engine.command("cont", {})
                    wait_for("[stop]")
                    time.sleep(0.08)
                engine.command("cont", {})
                wait_for("process exited with code 0")
                status = engine._run_sync(engine._defense_states)
                print(json.dumps({"events": seen, "status": status}))
            finally:
                engine.shutdown()
        '''.replace("STATE_PATH", repr(self.scratch.name)), timeout=50)
        self.assertTrue(result["status"]["auto_clock_safe"], result)
        status = result["status"]["auto_clock_status"]
        self.assertEqual(status["hits"]["mach_absolute_time"], 6)
        self.assertGreater(status["paused_ns"], 240000000)


if __name__ == "__main__":
    unittest.main()
