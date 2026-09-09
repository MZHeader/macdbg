import json
import re
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from . import support
from .support import (
    AgentProcess,
    FIXTURE,
    FRIDA_FIXTURE,
    LATE_IOKIT_FIXTURE,
    STRIPPED_FIXTURE,
    run_fixture_direct,
)


class AnalysisCloakIntegrationTests(unittest.TestCase):
    def assert_cloak_status(self, agent):
        status = agent.cmd("status")
        defenses = status["defenses"]
        self.assertTrue(defenses["analysis_cloak"], status)
        self.assertTrue(defenses["analysis_cloak_safe"], status)
        self.assertIsNone(defenses["analysis_cloak_error"], status)
        self.assertIs(type(defenses["analysis_cloak_resolved"]), int)
        self.assertIs(type(defenses["analysis_cloak_deferred"]), int)
        for name in ("anti_sysctl", "anti_parent", "anti_timing"):
            self.assertTrue(defenses[name], status)

    def test_timing_hides_real_sysctl_breakpoint_latency(self):
        with AgentProcess(FIXTURE, "timing") as agent:
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_sysctl"})["ok"])
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 1, result)
            self.assertIn("TIMING:DETECTED", result["console"])
        with AgentProcess(FIXTURE, "timing") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("TIMING:clean", result["console"])

    def test_syscall_202_ptraced_is_scrubbed(self):
        direct = run_fixture_direct("ptraced")
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("P_TRACED:clean rc=0", direct.stdout)
        for cloak in (False, True):
            with self.subTest(cloak=cloak), AgentProcess(FIXTURE, "ptraced") as agent:
                if cloak:
                    self.assertTrue(agent.enable_cloak()["ok"])
                result = agent.continue_to_exit()
                self.assertEqual(result["event"], "exited", result)
                self.assertEqual(result["exit"]["code"], 0 if cloak else 1, result)
                self.assertIn("P_TRACED:{} rc=0".format("clean" if cloak else "DETECTED"),
                              result["console"])

    def test_cloak_status_and_existing_defense_ownership(self):
        with AgentProcess(FIXTURE, "timing") as agent:
            self.assertTrue(agent.cmd("defense_enable", {"name": "anti_sysctl"})["ok"])
            self.assertTrue(agent.enable_cloak()["ok"])
            self.assert_cloak_status(agent)
            self.assertTrue(agent.cmd("defense_disable", {"name": "analysis_cloak"})["ok"])
            defenses = agent.cmd("status")["defenses"]
            self.assertFalse(defenses["analysis_cloak"])
            self.assertTrue(defenses["anti_sysctl"])
            self.assertFalse(defenses["anti_parent"])
            self.assertFalse(defenses["anti_timing"])

    def test_exec_prompt_dumps_full_command_then_fakes_success(self):
        with AgentProcess(FIXTURE, "exec") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            self.assertTrue(agent.cmd("defense_enable", {"name": "exec_sandbox"})["ok"])
            self.assertTrue(agent.cmd("exec_mode", {"interactive": True})["ok"])
            pending = agent.continue_to_exit()
            self.assertEqual(pending["event"], "pending_decision", pending)
            self.assertEqual(pending["decision"]["kind"], "exec", pending)
            dumped = agent.cmd("dump_exec")
            self.assertTrue(dumped["ok"], dumped)
            body = Path(dumped["path"]).read_text()
            self.assertEqual(body, support.EXEC_DUMP_BODY)
            self.assertEqual(dumped["bytes"], len(body.encode()))
            self.assertEqual(agent.cmd("status")["pending_decision"]["kind"], "exec")
            result = agent.cmd("decide_exec", {"decision": "fake", "timeout": 15})
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("EXEC:fake-or-allowed rc=0", result["console"])
            self.assertNotIn("0123456789", result["console"])

    def test_exec_automatic_dump_preserves_oversized_command(self):
        with AgentProcess(FIXTURE, "exec") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            self.assertTrue(agent.cmd("defense_enable", {"name": "exec_sandbox"})["ok"])
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 1, result)
            self.assertIn("EXEC:blocked rc=-1", result["console"])
            match = re.search(r"full payload \((\d+) B\) → ([^\r\n]+?\.txt)", result["console"])
            self.assertIsNotNone(match, result)
            body = Path(match[2]).read_text()
            self.assertEqual(body, support.EXEC_DUMP_BODY)
            self.assertEqual(int(match[1]), len(body.encode()))

    def test_combined_checks_recover_exact_chacha20_payload(self):
        args = [support.fixture_text_digest(), str(FRIDA_FIXTURE.resolve())]
        hostile = {"DYLD_PRINT_BINDINGS": "1", "NSZombieEnabled": "YES"}
        for cloak in (False, True):
            with self.subTest(cloak=cloak), AgentProcess(
                    FIXTURE, "combined", extra_args=args, env=hostile) as agent:
                if cloak:
                    self.assertTrue(agent.enable_cloak()["ok"])
                    self.assert_cloak_status(agent)
                result = agent.continue_to_exit()
                self.assertEqual(result["event"], "exited", result)
                self.assertEqual(result["exit"]["code"], 0 if cloak else 1, result)
                payload = "PAYLOAD:macdbg analysis cloak recovered this payload"
                if cloak:
                    self.assertIn(payload, result["console"].splitlines())
                    for check in ("ENV", "PARENT", "SYSCTL", "IOKIT", "IMAGES",
                                  "INTEGRITY", "TIMING", "P_TRACED"):
                        self.assertIn(check + ":clean", result["console"])
                    self.assertNotIn("DETECTED", result["console"])
                    restarted = agent.cmd("restart")
                    self.assertEqual(restarted["event"], "stop", restarted)
                    self.assert_cloak_status(agent)
                    rerun = agent.continue_to_exit()
                    self.assertEqual(rerun["event"], "exited", rerun)
                    self.assertEqual(rerun["exit"]["code"], 0, rerun)
                    self.assertIn(payload, rerun["console"].splitlines())
                else:
                    self.assertIn("PAYLOAD:unavailable", result["console"])
                    self.assertNotIn(payload, result["console"])

    def test_shared_hardware_site_keeps_foreign_hook_after_matched_one_shot_is_deleted(self):
        with AgentProcess(FIXTURE, "parent") as agent:
            def script_json(source):
                result = agent.cmd("raw", {"command": "script exec(" + repr(source) + ")"})
                self.assertTrue(result["ok"], result)
                return json.loads(result["output"].strip().splitlines()[-1])

            tid = script_json("import json\nprint(json.dumps(lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetThreadID()))")
            site = support.fixture_symbol("check_parent")
            ids = []
            for owner in (tid + 1000000000, tid):
                result = agent.cmd("raw", {"command":
                    "breakpoint set -H -a {:#x} -o true --thread-id {}".format(site, owner)})
                self.assertTrue(result["ok"], result)
                ids.append(int(re.search(r"Breakpoint (\d+)", result["output"]).group(1)))
            foreign, matched = ids
            stopped = agent.continue_to_exit()
            self.assertEqual(stopped.get("event"), "stop", stopped)
            # Exercise the real wrapper dispatch against LLDB's actual shared
            # stop data and already-removed matching one-shot, without changing
            # the running agent's internal defenses or arming target code patches.
            result = script_json("\n".join([
                "from macdbg.core.debugger import Debugger",
                "from macdbg.core.anti_analysis import AnalysisCloak",
                "d = Debugger.__new__(Debugger)",
                "d.target = lldb.debugger.GetSelectedTarget()",
                "d.process = d.target.GetProcess()",
                "thread = d.process.GetSelectedThread()",
                "before = {'reason': thread.GetStopReason(), 'ids': [thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)]}",
                "before['valid'] = [d.target.FindBreakpointByID(i).IsValid() for i in {!r}]".format(ids),
                "before['foreign_hardware'] = d.target.FindBreakpointByID({}).IsHardware()".format(foreign),
                "d.hardware_bp_ids = set({!r})".format(ids),
                "d._step_cloak_handled_stop = None",
                "d._step_cloak_messages = []",
                "d.analysis_cloak = c = AnalysisCloak(d)",
                "c.enabled = True",
                "c._return_hooks = {{i: ('proc_pidpath', 0, 0) for i in {!r}}}".format(ids),
                "c._return_hook_threads = {!r}".format({foreign: tid + 1000000000, matched: tid}),
                "thread.GetFrameAtIndex(0).FindRegister('x0').SetValueFromCString('0')",
                "d._process_cloak_step_stop(thread)",
                "print(json.dumps({'before': before, 'pending': sorted(c._return_hooks), 'owners': c._return_hook_threads, 'tracked': sorted(d.hardware_bp_ids)}))",
            ]))
            self.assertEqual(result["before"]["reason"], 3)
            self.assertEqual(set(result["before"]["ids"]), set(ids))
            self.assertEqual(result["before"]["valid"], [True, False])
            self.assertTrue(result["before"]["foreign_hardware"])
            self.assertEqual(result["pending"], [foreign], result)
            self.assertEqual(result["owners"], {str(foreign): tid + 1000000000})
            self.assertEqual(result["tracked"], [foreign])

    def test_user_breakpoint_cancels_private_step_plan_and_restores_policy(self):
        digest = support.fixture_text_digest()
        with AgentProcess(FIXTURE, "integrity_slow", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            outer = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_slow_integrity")})
            self.assertTrue(outer["ok"], outer)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            agent.cmd("breakpoint_delete", {"bp_id": outer["bp_id"]})
            user = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_integrity")})
            self.assertTrue(user["ok"], user)
            result = agent.cmd("step_out", {"timeout": 15})
            self.assertEqual(result.get("event"), "stop", result)
            self.assertEqual(result["stop"]["bp_id"], user["bp_id"], result)
            policy = agent.cmd("raw", {"command": "settings show target.require-hardware-breakpoint"})
            self.assertIn("false", policy["output"])
            agent.cmd("breakpoint_delete", {"bp_id": user["bp_id"]})
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("INTEGRITY:clean", result["console"])

    def test_step_policy_remains_active_until_restart(self):
        digest = support.fixture_text_digest()
        with AgentProcess(FIXTURE, "integrity_slow", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            bp = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_slow_integrity")})
            self.assertTrue(bp["ok"], bp)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})
            running = agent.cmd("step_out", {"timeout": 0})
            self.assertEqual(running.get("event"), "running", running)
            policy = agent.cmd("raw", {"command": "settings show target.require-hardware-breakpoint"})
            self.assertIn("true", policy["output"])
            restarted = agent.cmd("restart")
            self.assertEqual(restarted.get("event"), "stop", restarted)
            policy = agent.cmd("raw", {"command": "settings show target.require-hardware-breakpoint"})
            self.assertIn("false", policy["output"])
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("INTEGRITY:clean", result["console"])

    def test_critical_hook_error_during_step_restores_policy_and_stays_stopped(self):
        with AgentProcess(FIXTURE, "parent") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            bp = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_parent")})
            self.assertTrue(bp["ok"], bp)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})
            capacity = int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.optional.breakpoint"], text=True))
            marker = support.fixture_symbol("integrity_breakpoint_site")
            for index in range(capacity - 1):
                self.assertTrue(agent.cmd("breakpoint_toggle", {"addr": marker + index * 4})["ok"])
            result = agent.cmd("step_out", {"timeout": 15})
            self.assertFalse(result["ok"], result)
            self.assertIn("slots", result["error"])
            self.assertEqual(agent.cmd("status")["process_state"], "stopped")
            policy = agent.cmd("raw", {"command": "settings show target.require-hardware-breakpoint"})
            self.assertIn("false", policy["output"])
            self.assertFalse(agent.continue_to_exit()["ok"])

    def test_step_over_applies_cloak_at_api_calls(self):
        cases = (("parent", "check_parent", "proc_pidpath", 0),
                 ("sysctl", "check_sysctl", "sysctlbyname", 1),
                 ("iokit", "copy_cfstring_property", "IORegistryEntryCreateCFProperty", 0),
                 ("images", "check_images", "_dyld_get_image_name", 0))
        for mode, function, api, index in cases:
            with self.subTest(mode=mode):
                extra = [str(FRIDA_FIXTURE)] if mode == "images" else []
                with AgentProcess(FIXTURE, mode, extra_args=extra) as agent:
                    self.assertTrue(agent.enable_cloak()["ok"])
                    text = agent.cmd("raw", {"command": "disassemble -n " + function})["output"]
                    sites = re.findall(r"^\s*(0x[0-9a-f]+).*\bbl\s+.*symbol stub for: " + re.escape(api) + r"\s*$", text, re.M)
                    site = int(sites[index], 16)
                    bp = agent.cmd("breakpoint_toggle", {"addr": site})
                    self.assertTrue(bp["ok"], bp)
                    self.assertEqual(agent.continue_to_exit().get("event"), "stop")
                    self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
                    stepped = agent.cmd("step_over", {"timeout": 15})
                    self.assertEqual(stepped.get("event"), "stop", stepped)
                    self.assertEqual(stepped["stop"]["pc"], site + 4, stepped)
                    result = agent.continue_to_exit()
                    self.assertEqual(result.get("event"), "exited", result)
                    self.assertEqual(result["exit"]["code"], 0, (stepped, result))

    def test_instruction_step_landing_on_hook_is_intercepted(self):
        with AgentProcess(FIXTURE, "parent") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            listing = agent.cmd("breakpoint_list", {"hide_internal": False})
            hook = next(bp["addr"] for bp in listing["breakpoints"] if bp["symbol"] == "proc_pidpath")
            text = agent.cmd("raw", {"command": "disassemble -n check_parent"})["output"]
            site = int(re.search(r"^\s*(0x[0-9a-f]+).*\bbl\s+.*symbol stub for: proc_pidpath\s*$", text, re.M).group(1), 16)
            bp = agent.cmd("breakpoint_toggle", {"addr": site})
            self.assertTrue(bp["ok"], bp)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
            for _ in range(8):
                stepped = agent.cmd("step_in", {"timeout": 15})
                self.assertEqual(stepped.get("event"), "stop", stepped)
                if stepped["stop"]["pc"] == hook:
                    break
            else:
                self.fail("instruction steps did not reach proc_pidpath hook")
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("PARENT:clean", result["console"])

    def test_optimized_inline_step_out_is_rejected_before_text_changes(self):
        fixture = support.OPTIMIZED_FIXTURE
        digest = support.fixture_text_digest(fixture)
        with AgentProcess(fixture, "integrity", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            info = agent.cmd("raw", {"command": "image lookup -v -n check_integrity"})
            blocks = info["output"].split("Address:")[1:]
            # Combined mode introduces another inlined copy in main. Select
            # the direct integrity-mode call exercised by this process.
            main_block = next(block for block in blocks if re.search(
                r"Summary:.*`main.*\[inlined\] check_integrity", block)
                and "[inlined] check_combined" not in block)
            address = int(re.search(r"\[(0x[0-9a-fA-F]+)", main_block).group(1), 16)
            bp = agent.cmd("breakpoint_toggle", {"addr": address})
            self.assertTrue(bp["ok"], bp)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
            before = agent.cmd("status")["pc"]
            result = agent.cmd("step_out", {"timeout": 15})
            self.assertFalse(result["ok"], result)
            self.assertIn("inline step-out", result["error"])
            self.assertEqual(agent.cmd("status")["pc"], before)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertIn("INTEGRITY:clean", result["console"])
            self.assertEqual(result["exit"]["code"], 0, result)

    def test_step_out_applies_all_cloak_hook_families(self):
        for mode in ("parent", "sysctl", "iokit", "images"):
            with self.subTest(mode=mode):
                extra = [str(FRIDA_FIXTURE)] if mode == "images" else []
                with AgentProcess(FIXTURE, mode, extra_args=extra) as agent:
                    self.assertTrue(agent.enable_cloak()["ok"])
                    bp = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_" + mode)})
                    self.assertTrue(bp["ok"], bp)
                    self.assertEqual(agent.continue_to_exit().get("event"), "stop")
                    self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
                    stepped = agent.cmd("step_out", {"timeout": 15})
                    self.assertEqual(stepped.get("event"), "stop", stepped)
                    result = agent.continue_to_exit()
                    self.assertEqual(result.get("event"), "exited", result)
                    self.assertEqual(result["exit"]["code"], 0, (stepped, result))
                    self.assertIn(mode.upper() + ":clean", stepped["console"] + result["console"])

    def test_integrity_step_out_preserves_text(self):
        digest = support.fixture_text_digest()
        with AgentProcess(FIXTURE, "integrity", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            for command in ("step_in_source", "step_over_source"):
                rejected = agent.cmd(command, {"timeout": 15})
                self.assertFalse(rejected["ok"], rejected)
                self.assertIn("use instruction stepping", rejected["error"])
                self.assertEqual(agent.cmd("status")["process_state"], "stopped")
            bp = agent.cmd("breakpoint_toggle", {"addr": support.fixture_symbol("check_integrity")})
            self.assertTrue(bp["ok"], bp)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "stop", result)
            self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
            result = agent.cmd("step_out", {"timeout": 15})
            self.assertEqual(result.get("event"), "stop", result)
            self.assertIn("INTEGRITY:clean", result["console"])
            policy = agent.cmd("raw", {"command": "settings show target.require-hardware-breakpoint"})
            self.assertIn("false", policy["output"])
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)

    def test_cloak_return_hook_slot_failure_leaves_target_stopped(self):
        marker = support.fixture_symbol("integrity_breakpoint_site")
        capacity = int(subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", "hw.optional.breakpoint"], text=True))
        self.assertLessEqual(capacity, 32)
        with AgentProcess(FIXTURE, "parent") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            for index in range(capacity):
                result = agent.cmd("breakpoint_toggle", {"addr": marker + index * 4})
                self.assertTrue(result["ok"], result)
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "stop", result)
            self.assertIn("hardware breakpoint allocation failed", result["console"])
            self.assertNotIn("PARENT:", result["console"])
            self.assertEqual(agent.cmd("status")["process_state"], "stopped")
            blocked = agent.continue_to_exit()
            self.assertFalse(blocked["ok"], blocked)
            self.assertIn("restart at entry", blocked["error"])

    def test_integrity_hardware_slot_exhaustion_is_recoverable(self):
        digest = support.fixture_text_digest()
        marker = support.fixture_symbol("integrity_breakpoint_site")
        with AgentProcess(FIXTURE, "integrity", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            created = []
            for index in range(32):
                result = agent.cmd("breakpoint_toggle", {"addr": marker + index * 4})
                if not result["ok"]:
                    self.assertIn("hardware breakpoint allocation failed", result["error"])
                    self.assertIn("slots", result["error"])
                    break
                created.append(result["bp_id"])
            else:
                # debugserver can defer physical allocation until resume.
                result = agent.cmd("continue", {"timeout": 2})
                self.assertFalse(result["ok"], result)
                self.assertIn("hardware breakpoint", result["error"])
                self.assertIn("slots", result["error"])
                self.assertEqual(agent.cmd("status")["process_state"], "stopped")
            listed = agent.cmd("breakpoint_list")["breakpoints"]
            self.assertEqual({bp["id"] for bp in listed}, set(created))
            agent.clear_user_breakpoints()
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)

    def test_integrity_hardware_breakpoint_preserves_text(self):
        digest = support.fixture_text_digest()
        direct = run_fixture_direct("integrity", extra_args=[digest])
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        with AgentProcess(FIXTURE, "integrity", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            bp = agent.cmd("breakpoint_toggle", {
                "addr": support.fixture_symbol("integrity_breakpoint_site")})
            self.assertTrue(bp["ok"], bp)
            self.assertIn("added (HW)", str(bp))
            scan = agent.cmd("defense_enable", {"name": "direct_syscall"})
            self.assertTrue(scan["ok"], scan)
            self.assertIn("1 svc", scan["message"])
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("INTEGRITY:clean", result["console"])

    def test_integrity_raw_software_breakpoint_blocks_resume(self):
        digest = support.fixture_text_digest()
        with AgentProcess(FIXTURE, "integrity", extra_args=[digest]) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            bp = agent.cmd("raw", {"command": "breakpoint set -a {:#x}".format(
                support.fixture_symbol("integrity_breakpoint_site"))})
            self.assertTrue(bp["ok"], bp)
            result = agent.continue_to_exit()
            self.assertFalse(result["ok"], result)
            self.assertIn("software breakpoint modifies target __text", result["error"])
            status = agent.cmd("status")
            self.assertEqual(status["process_state"], "stopped")
            self.assertTrue(status["defenses"]["analysis_cloak"])
            self.assertFalse(status["defenses"]["analysis_cloak_safe"])
            self.assertIn("software breakpoint modifies target __text",
                          status["defenses"]["analysis_cloak_error"])

    def test_blacklisted_loaded_images_are_cloaked(self):
        dylib = str(FRIDA_FIXTURE.resolve())
        direct = run_fixture_direct("images", extra_args=[dylib])
        self.assertNotEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("IMAGES:DETECTED", direct.stdout)
        self.assertIn("FridaGadget.dylib", direct.stdout)

        with AgentProcess(FIXTURE, "images", extra_args=[dylib]) as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("IMAGES:clean", result["console"])
            self.assertIn(
                "[anti-analysis] cloaked loaded image FridaGadget.dylib",
                result["console"],
            )

            restarted = agent.cmd("restart")
            self.assertTrue(restarted["ok"], restarted)
            self.assertEqual(restarted["event"], "stop", restarted)
            rerun = agent.continue_to_exit()
            self.assertEqual(rerun["event"], "exited", rerun)
            self.assertEqual(rerun["exit"]["code"], 0, rerun)
            self.assertIn("IMAGES:clean", rerun["console"])
            self.assertIn(
                "[anti-analysis] cloaked loaded image FridaGadget.dylib",
                rerun["console"],
            )

    def test_clean_loaded_images_pass_without_rewrite_log(self):
        dylib = "/usr/lib/libSystem.B.dylib"
        direct = run_fixture_direct("images", extra_args=[dylib])
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("IMAGES:clean", direct.stdout)

        with AgentProcess(FIXTURE, "images", extra_args=[dylib]) as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("IMAGES:clean", result["console"])
            self.assertNotIn("cloaked loaded image", result["console"])

    def test_iokit_spoofing_works_for_a_stripped_binary(self):
        with AgentProcess(STRIPPED_FIXTURE, "iokit") as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("IOKIT:clean", result["console"])

    def test_iokit_hook_defers_and_resolves_after_dlopen(self):
        with AgentProcess(LATE_IOKIT_FIXTURE, "") as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            self.assertIn("1 deferred", enabled["message"])
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("LATE-IOKIT:clean", result["console"])

    def test_iokit_platform_identity_is_spoofed(self):
        direct = run_fixture_direct("iokit")
        self.assertNotEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("IOKIT:DETECTED", direct.stdout)

        with AgentProcess(FIXTURE, "iokit") as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn(
                "IOKIT:clean serial=C02ZQ0ABC123 "
                "uuid=8D4C7A12-3F65-4B90-A2DE-61C8E5079F34",
                result["console"],
            )

    def test_hardware_sysctls_are_spoofed(self):
        direct = run_fixture_direct("sysctl")
        self.assertNotEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("SYSCTL:DETECTED", direct.stdout)

        with AgentProcess(FIXTURE, "sysctl") as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn(
                "SYSCTL:clean hv=0 model=Mac14,6 cpu=Apple M2 Pro",
                result["console"],
            )

    def test_parent_paths_are_cloaked(self):
        with AgentProcess(FIXTURE, "parent") as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            result = agent.continue_to_exit()
            self.assertEqual(result["exit"]["code"], 0)
            self.assertIn("PARENT:clean", result["console"])
            self.assertIn("[anti-analysis]", result["console"])

    def test_environment_is_detected_without_cloak_and_clean_with_cloak(self):
        hostile = {"DYLD_PRINT_BINDINGS": "1", "NSZombieEnabled": "YES"}
        self.assertNotEqual(run_fixture_direct("env", env=hostile).returncode, 0)
        with AgentProcess(FIXTURE, "env", env=hostile) as agent:
            enabled = agent.cmd("defense_enable", {"name": "analysis_cloak"})
            self.assertTrue(enabled["ok"], enabled)
            result = agent.cmd("continue", {"timeout": 15})
            self.assertEqual(result["event"], "exited")
            self.assertEqual(result["exit"]["code"], 0)
            self.assertIn("ENV:clean", result["console"])

    def test_restart_filters_hostile_launch_environment(self):
        hostile = {"DYLD_PRINT_BINDINGS": "1", "NSZombieEnabled": "YES"}
        with AgentProcess(FIXTURE, "env", env=hostile) as agent:
            enabled = agent.enable_cloak()
            self.assertTrue(enabled["ok"], enabled)
            restarted = agent.cmd("restart")
            self.assertTrue(restarted["ok"], restarted)
            self.assertEqual(restarted["event"], "stop")
            result = agent.continue_to_exit()
            self.assertEqual(result["event"], "exited")
            self.assertEqual(result["exit"]["code"], 0)
            self.assertIn("ENV:clean", result["console"])

    def test_failed_enter_stops_started_agent(self):
        original_json_run = support._json_run

        for failure in ("json", "timeout", "unsuccessful"):
            with self.subTest(failure=failure):
                agent = AgentProcess(FIXTURE, "env")

                def fail_after_start(argv, env=None, timeout=30):
                    boot = original_json_run(argv, env=env, timeout=timeout)
                    self.assertTrue(boot.get("ok"), boot)
                    if failure == "json":
                        raise json.JSONDecodeError("synthetic", "x", 0)
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(argv, timeout)
                    boot["ok"] = False
                    boot["error"] = "synthetic unsuccessful boot"
                    return boot

                try:
                    with mock.patch.object(support, "_json_run",
                                           side_effect=fail_after_start):
                        if failure == "json":
                            with self.assertRaises(json.JSONDecodeError):
                                agent.__enter__()
                        elif failure == "timeout":
                            with self.assertRaises(subprocess.TimeoutExpired):
                                agent.__enter__()
                        else:
                            with self.assertRaises(AssertionError):
                                agent.__enter__()

                    cp = subprocess.run(
                        [str(support.AGENT), "list"], cwd=support.ROOT,
                        env=agent.env, text=True, capture_output=True,
                        timeout=15, check=True)
                    sessions = json.loads(cp.stdout.strip().splitlines()[-1])
                    self.assertNotIn(
                        agent.session,
                        {item["session"] for item in sessions},
                        "failed __enter__ leaked session {}".format(
                            agent.session))
                finally:
                    subprocess.run(
                        [str(support.AGENT), "stop", agent.session],
                        cwd=support.ROOT, env=agent.env, text=True,
                        capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
