import unittest

from .support import AgentProcess, FIXTURE, run_fixture_direct


class AnalysisCloakIntegrationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
