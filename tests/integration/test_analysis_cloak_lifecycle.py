import unittest

from .support import run_core_probe, AgentProcess, LATE_IOKIT_FIXTURE


class TargetLifecycleTests(unittest.TestCase):
    def test_late_iokit_restart_defers_retained_unresolved_locations(self):
        with AgentProcess(LATE_IOKIT_FIXTURE, "iokit") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            for run in range(2):
                if run:
                    self.assertTrue(agent.cmd("restart")["ok"])
                    status = agent.cmd("status")["defenses"]
                    self.assertTrue(status["analysis_cloak_safe"], status)
                    self.assertEqual(status["analysis_cloak_deferred"], 1)
                result = agent.continue_to_exit()
                self.assertEqual(result.get("event"), "exited", result)
                self.assertEqual(result["exit"]["code"], 0, result)
                self.assertIn("LATE-IOKIT:clean", result["console"])

    def test_gui_open_disposes_previous_target_then_rearms_late_iokit(self):
        result = run_core_probe('''
            import json
            from macdbg.agent.session import AgentSession
            from GUI.server.engine import Engine
            from tests.integration.support import FIXTURE, LATE_IOKIT_FIXTURE
            s = AgentSession()
            e = Engine.__new__(Engine)
            e.dbg, e.tracer = s.dbg, s.tracer
            e._console = lambda *a, **k: None
            e._emit_state = lambda: None
            e.submit = lambda *a: None
            e._maybe_start_interpose_reader = lambda: None
            try:
                e._c_open_target({"path": str(FIXTURE), "args": ["env"]})
                assert s.dbg.enable_analysis_cloak()[0]
                old_target, old_cloak = s.dbg.target, s.dbg.analysis_cloak
                s.dbg.enable_anti_ptrace()
                e._c_open_target({"path": str(LATE_IOKIT_FIXTURE), "args": ["iokit"]})
                after_open = s.cmd_status()["defenses"]
                retired_hooks = sorted(old_cloak.hidden_bp_ids())
                enabled = s.dbg.enable_analysis_cloak()
                rearmed = s.dbg.analysis_cloak.status()
                outcome = s.dispatch("continue", {"timeout": 15})
                print(json.dumps({"after_open": after_open, "enabled": enabled,
                                  "rearmed": rearmed, "outcome": outcome,
                                  "old_hooks": retired_hooks,
                                  "old_target_valid": old_target.IsValid()}))
            finally:
                s.shutdown(save=False)
        ''')
        self.assertFalse(result["after_open"]["analysis_cloak"], result)
        self.assertFalse(result["after_open"]["anti_ptrace"], result)
        self.assertEqual(result["old_hooks"], [], result)
        self.assertFalse(result["old_target_valid"], result)
        self.assertTrue(result["enabled"][0], result)
        self.assertGreater(result["rearmed"]["resolved"], 0, result)
        self.assertEqual(result["rearmed"]["deferred"], 1, result)
        self.assertEqual(result["outcome"]["event"], "exited", result)
        self.assertEqual(result["outcome"]["exit"]["code"], 0, result)
        self.assertIn("LATE-IOKIT:clean", result["outcome"]["console"])

    def test_gui_attach_disposes_previous_target_cloak(self):
        result = run_core_probe('''
            import json, subprocess, lldb
            from macdbg.agent.session import AgentSession
            from GUI.server.engine import Engine
            from tests.integration.support import FIXTURE
            s = AgentSession(str(FIXTURE), ["env"])
            e = Engine.__new__(Engine)
            e.dbg, e.tracer = s.dbg, s.tracer
            messages = []
            e._console = lambda text, **k: messages.append(text)
            e._emit_state = lambda: None
            child = subprocess.Popen([str(FIXTURE), "wait"])
            old_process = None
            try:
                assert s.start()["ok"]
                assert s.dbg.enable_analysis_cloak()[0]
                old_process = s.dbg.process
                e._c_attach({"pid": child.pid})
                status = s.cmd_status()
                print(json.dumps({"defenses": status["defenses"],
                                  "pid": s.dbg.process.GetProcessID(),
                                  "expected_pid": child.pid,
                                  "old_alive": old_process.IsValid() and old_process.GetState() not in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid),
                                  "enable": s.dbg.enable_analysis_cloak(),
                                  "messages": messages}))
            finally:
                s.shutdown(save=False)
                if old_process is not None and old_process.IsValid():
                    old_process.Kill()
                child.terminate()
                child.wait(timeout=10)
        ''')
        self.assertEqual(result["pid"], result["expected_pid"], result)
        self.assertFalse(result["defenses"]["analysis_cloak"], result)
        self.assertFalse(result["old_alive"], result)
        self.assertFalse(result["enable"][0], result)
        self.assertIn("entry point", result["enable"][1])


class InternalHookProtectionTests(unittest.TestCase):
    def test_gui_structured_mutations_reject_internal_hooks_at_all_locations(self):
        rows = run_core_probe('''
            import json, lldb
            from macdbg.agent.session import AgentSession
            from GUI.server.engine import Engine
            from tests.integration.support import FIXTURE
            s = AgentSession(str(FIXTURE), ["env"])
            e = Engine.__new__(Engine)
            e.dbg, e.tracer = s.dbg, s.tracer
            e._emit_state = lambda: None
            logs = []
            e._console = lambda text, **k: logs.append([text, k.get("error", False)])
            def state(bp):
                if not bp.IsValid():
                    return {"valid": False}
                commands = lldb.SBStringList()
                bp.GetCommandLineCommands(commands)
                return {"valid": True, "enabled": bp.IsEnabled(),
                        "condition": bp.GetCondition() or "",
                        "commands": [commands.GetStringAtIndex(i) for i in range(commands.GetSize())]}
            rows = []
            try:
                assert s.start()["ok"]
                for mode in ("toggle", "secondary", "delete", "disable", "enable", "condition", "commands"):
                    assert s.dbg.enable_analysis_cloak()[0]
                    c = s.dbg.analysis_cloak
                    bid = next(i for i, name in c._entry_hooks.items() if name == "proc_pidpath")
                    bp = s.dbg.target.FindBreakpointByID(bid)
                    if mode == "secondary":
                        bp = s.dbg.target.BreakpointCreateByRegex("^(check_parent|check_sysctl)$")
                        bid = bp.GetID()
                        assert bp.GetNumLocations() >= 2
                        c._bp_ids.add(bid)
                    if mode == "enable":
                        bp.SetEnabled(False)
                    before = state(bp)
                    logs.clear()
                    if mode in ("toggle", "secondary"):
                        addr = bp.GetLocationAtIndex(1 if mode == "secondary" else 0).GetLoadAddress()
                        e._c_toggle_bp({"addr": addr})
                    elif mode == "delete":
                        e._c_bp_delete({"id": bid})
                    elif mode in ("enable", "disable"):
                        e._c_bp_enable({"id": bid})
                    elif mode == "condition":
                        e._c_bp_condition({"id": bid, "cond": "0"})
                    else:
                        e._c_bp_commands({"id": bid, "commands": ["register write x0 0"]})
                    rows.append({"mode": mode, "before": before,
                                 "after": state(s.dbg.target.FindBreakpointByID(bid)),
                                 "logs": list(logs)})
                    c.disable()
                print(json.dumps(rows))
            finally:
                s.shutdown(save=False)
        ''')
        for row in rows:
            with self.subTest(mode=row["mode"]):
                self.assertEqual(row["before"], row["after"], row)
                self.assertTrue(any(error and "internal" in message
                                    for message, error in row["logs"]), row)

    def test_readiness_rejects_missing_disabled_and_unhandled_required_entries(self):
        rows = run_core_probe('''
            import json
            from macdbg.agent.session import AgentSession
            from tests.integration.support import FIXTURE
            s = AgentSession(str(FIXTURE), ["env"])
            rows = []
            try:
                assert s.start()["ok"]
                for family in ("proc_pidpath", "sysctlbyname", "IORegistryEntryCreateCFProperty", "_dyld_get_image_name", "legacy_sysctl", "syscall"):
                    for mutation in ("delete", "disable", "location"):
                        assert s.dbg.enable_analysis_cloak()[0]
                        d, c = s.dbg, s.dbg.analysis_cloak
                        if family == "legacy_sysctl": bid = d.anti_sysctl_bp_id
                        elif family == "syscall": bid = d.syscall_bp_ids[0]
                        else: bid = next(i for i, name in c._entry_hooks.items() if name == family)
                        bp = d.target.FindBreakpointByID(bid)
                        if mutation == "delete": d.target.BreakpointDelete(bid)
                        elif mutation == "disable": bp.SetEnabled(False)
                        else: bp.GetLocationAtIndex(0).SetEnabled(False)
                        rows.append({"family": family, "mutation": mutation,
                                     "ready": c.validate_resume(), "enable": c.enable(),
                                     "state": s.cmd_status()["defenses"]})
                        c.disable()
                assert s.dbg.enable_analysis_cloak()[0]
                s.dbg.analysis_cloak._entry_hooks.clear()
                rows.append({"family": "entry dispatch", "mutation": "lost metadata",
                             "ready": s.dbg.analysis_cloak.validate_resume()})
                print(json.dumps(rows))
            finally:
                s.shutdown(save=False)
        ''')
        for row in rows:
            with self.subTest(family=row["family"], mutation=row["mutation"]):
                self.assertFalse(row["ready"][0], row)
                if "enable" in row:
                    self.assertFalse(row["enable"][0], row)
                    self.assertFalse(row["state"]["analysis_cloak_safe"], row)
                    self.assertTrue(row["state"]["analysis_cloak_error"], row)

    def test_readiness_is_bound_to_its_target_even_when_ids_are_reused(self):
        result = run_core_probe('''
            import json
            from macdbg.agent.session import AgentSession
            from tests.integration.support import FIXTURE, LATE_IOKIT_FIXTURE
            s = AgentSession(str(FIXTURE), ["env"])
            original = None
            try:
                assert s.start()["ok"]
                assert s.dbg.enable_analysis_cloak()[0]
                original = s.dbg.target
                s.dbg.target = s.dbg.dbg.CreateTarget(str(LATE_IOKIT_FIXTURE))
                print(json.dumps({"ready": s.dbg.analysis_cloak.validate_resume(),
                                  "enable": s.dbg.enable_analysis_cloak()}))
            finally:
                if original is not None:
                    s.dbg.target = original
                    s.dbg.dbg.SetSelectedTarget(original)
                s.shutdown(save=False)
        ''')
        self.assertFalse(result["ready"][0], result)
        self.assertFalse(result["enable"][0], result)
        self.assertIn("target", result["ready"][1])
