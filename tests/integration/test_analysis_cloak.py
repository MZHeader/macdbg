import json
import subprocess
import unittest
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
