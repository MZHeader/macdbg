"""Benign framework loading and concurrent clocks under debugger defenses."""
import tempfile
import unittest

from .support import AgentProcess, FIXTURE_DIR, FRIDA_FIXTURE, fixture_symbol


class FrameworkInteropTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="macdbg-framework-", dir="/private/tmp")
        self.env = {"MACDBG_STATE_DIR": self.scratch.name, "PYTHONDONTWRITEBYTECODE": "1"}

    def tearDown(self):
        self.scratch.cleanup()

    def run_probe(self, fixture, mode, arguments, cloak=False, clock=False, other=False):
        with AgentProcess(FIXTURE_DIR / fixture, mode, arguments, env=self.env) as agent:
            if cloak:
                self.assertTrue(agent.enable_cloak()["ok"])
            if clock:
                self.assertTrue(agent.cmd("defense_enable", {"name": "auto_clock"})["ok"])
            if other:
                for name in ('anti_ptrace', 'anti_mach_ports', 'anti_csops', 'anti_sigtrap', 'exec_sandbox'):
                    self.assertTrue(agent.cmd('defense_enable', {'name': name})['ok'])
                agent.cmd('exec_mode', {'interactive': True})
            result = agent.cmd("continue", {"timeout": 20}, timeout=30)
            for _ in range(8):
                if result.get('event') != 'pending_decision':
                    break
                self.assertTrue(result['decision']['symbol'].startswith('OSA'), result)
                result = agent.cmd('decide_exec', {'decision': 'allow', 'timeout': 20}, timeout=30)
            for _ in range(2):
                if result.get("event") != "running":
                    break
                result = agent.cmd("wait", {"timeout": 20}, timeout=30)
            diagnostics = {}
            if result.get("event") != "exited":
                if result.get("event") == "running":
                    agent.cmd("interrupt")
                for command in ("thread list", "thread backtrace all", "disassemble --pc --count 8"):
                    diagnostics[command] = agent.cmd("raw", {"command": command})
            self.assertEqual(result.get("event"), "exited", (result, diagnostics))
            status = agent.cmd("clock_status")
            self.assertEqual(result["exit"]["code"], 0, (result, status))
            return result, status

    def test_repeated_image_returns_with_existing_hardware_sites(self):
        with AgentProcess(FIXTURE_DIR / "analysis_fixture", "image_stress", env=self.env) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            self.assertTrue(agent.cmd("defense_enable", {"name": "auto_clock"})["ok"])
            for name in ("check_sysctl", "check_iokit"):
                self.assertTrue(agent.cmd("breakpoint_toggle", {"addr": fixture_symbol(name)})["ok"])
            result = agent.cmd("continue", {"timeout": 60}, timeout=70)
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, result)
            self.assertIn("IMAGE-STRESS:clean", result["console"])

    def test_osa_without_cloak(self):
        result, _ = self.run_probe("framework_fixture", "osa", [])
        self.assertIn("OSA:status=0 result=42", result["console"])

    def test_osa_with_cloak(self):
        result, _ = self.run_probe("framework_fixture", "osa", [str(FRIDA_FIXTURE)], cloak=True)
        self.assertIn("OSA:status=0 result=42", result["console"])

    def test_bundle_enumeration_with_cloak(self):
        result, _ = self.run_probe("framework_fixture", "images", [str(FRIDA_FIXTURE)], cloak=True)
        self.assertIn("BUNDLES:", result["console"])

    def test_osa_application_with_cloak(self):
        result, _ = self.run_probe("framework_fixture", "application", [str(FRIDA_FIXTURE)], cloak=True)
        self.assertIn("OSA:status=0 result=42", result["console"])

    def test_cold_generic_osa_load_with_cloak(self):
        result, _ = self.run_probe("framework_fixture", "application-cold",
            [str(FRIDA_FIXTURE), str(FIXTURE_DIR / "constant.scpt")], cloak=True)
        self.assertIn("OSA:status=0 result=0", result["console"])

    def test_cold_generic_osa_load_without_cloak(self):
        result, _ = self.run_probe("framework_fixture", "application-cold",
            [str(FRIDA_FIXTURE), str(FIXTURE_DIR / "constant.scpt")])
        self.assertIn("OSA:status=0 result=0", result["console"])

    def test_cold_osa_with_all_defenses(self):
        result, _ = self.run_probe("framework_fixture", "application-cold",
            [str(FRIDA_FIXTURE), str(FIXTURE_DIR / "constant.scpt")], cloak=True, clock=True, other=True)
        self.assertIn("OSA:status=0 result=0", result["console"])

    def test_cold_osa_then_iokit_with_all_defenses(self):
        result, _ = self.run_probe("framework_fixture", "application-cold-iokit",
            [str(FRIDA_FIXTURE), str(FIXTURE_DIR / "constant.scpt")], cloak=True, clock=True, other=True)
        self.assertIn("OSA:status=0 result=0", result["console"])
        self.assertIn("IOKIT:readable uuid=8D4C7A12-3F65-4B90-A2DE-61C8E5079F34", result["console"])

    def test_framework_clock_contention(self):
        result, status = self.run_probe("clock_contention_fixture", "threads",
            [str(FIXTURE_DIR / "ClockWorker.dylib")], cloak=True, clock=True)
        self.assertIn("CONTENTION:clean", result["console"])
        self.assertEqual(status["hits"], {})
        self.assertEqual(status["passthrough"], 0)

    def test_application_registration_after_script_and_identity_queries(self):
        for iteration in range(3):
            with self.subTest(iteration=iteration):
                result, _ = self.run_probe("framework_fixture", "late-application-iokit",
                    [str(FRIDA_FIXTURE), str(FIXTURE_DIR / "constant.scpt")],
                    cloak=True, clock=True, other=True)
                self.assertIn("APPLICATION:registration=0", result["console"])

    def test_main_clock_contention_preserves_monotonic_reads(self):
        result, status = self.run_probe("clock_contention_fixture", "local",
            [str(FIXTURE_DIR / "ClockWorker.dylib")], cloak=True, clock=True)
        self.assertIn("CONTENTION:clean", result["console"])
        self.assertEqual(status["hits"].get("mach_absolute_time"), 256)
        self.assertEqual(status["hits"].get("clock_gettime"), 256)


if __name__ == "__main__":
    unittest.main()
