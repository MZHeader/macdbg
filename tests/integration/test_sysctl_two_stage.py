import errno
import re
import subprocess
import unittest

from .support import AgentProcess, CONTROLLED_SYSCTL_FIXTURE


class ControlledSysctlIntegrationTests(unittest.TestCase):
    def test_two_stage_query_is_independent_of_real_host_string_lengths(self):
        for scenario, model_size, cpu_size in (("shorter", 2, 2),
                                               ("equal", 8, 13),
                                               ("longer", 64, 80)):
            with self.subTest(host=scenario), AgentProcess(
                    CONTROLLED_SYSCTL_FIXTURE, "sysctl_two_stage",
                    env={"MACDBG_TEST_SYSCTL_HOST": scenario}) as agent:
                self.assertTrue(agent.enable_cloak()["ok"])
                result = agent.continue_to_exit()
                self.assertEqual(result.get("event"), "exited", result)
                console = result["console"]
                for name, real_size, spoof_size in (("hw.model", model_size, 8),
                                                    ("machdep.cpu.brand_string", cpu_size, 13)):
                    self.assertIn("HOST-SYSCTL:{} real={} capacity=0 rc=0".format(name, real_size), console)
                    self.assertIn("HOST-SYSCTL:{} real={} capacity={} rc={}".format(
                        name, real_size, spoof_size, -1 if real_size > spoof_size else 0), console)
                status = agent.cmd("status")
                self.assertEqual(result["exit"]["code"], 0, (result, status))
                self.assertIn("SYSCTL-TWO-STAGE:clean", console)
                for name, size in (("kern.hv_vmm_present", 4), ("hw.model", 8),
                                   ("machdep.cpu.brand_string", 13)):
                    self.assertIn("SIZE-PROBE:{} capacity={} returned={} rc=0".format(name, size, size), console)
                self.assertTrue(status["defenses"]["analysis_cloak_safe"], status)

    def test_controlled_host_values_fail_without_cloak(self):
        result = subprocess.run([str(CONTROLLED_SYSCTL_FIXTURE), "sysctl_two_stage"],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 1, result)
        self.assertIn("SYSCTL-TWO-STAGE:DETECTED", result.stdout)

    def test_real_failures_and_write_requests_remain_failed(self):
        cases = (("error", errno.EFAULT), ("error", errno.EINVAL),
                 ("error", errno.ENOENT), ("error", errno.EPERM),
                 ("write", errno.EPERM), ("newlen", errno.EINVAL),
                 ("short", errno.ENOMEM))
        for call, expected_errno in cases:
            with self.subTest(call=call, errno=expected_errno), AgentProcess(
                    CONTROLLED_SYSCTL_FIXTURE, "sysctl_failure",
                    extra_args=[call, str(expected_errno)], env={
                        "MACDBG_TEST_SYSCTL_HOST": "longer",
                        "MACDBG_TEST_SYSCTL_ERROR": str(expected_errno if call == "error" else 0),
                    }) as agent:
                self.assertTrue(agent.enable_cloak()["ok"])
                result = agent.continue_to_exit()
                self.assertEqual(result.get("event"), "exited", result)
                self.assertEqual(result["exit"]["code"], 0, result)
                self.assertIn("SYSCTL-FAILURE:preserved call={} rc=-1 errno={}".format(
                    call, expected_errno), result["console"])
                self.assertNotIn("spoofed sysctlbyname", result["console"])

    def test_step_over_longer_host_query_stops_at_caller_with_success(self):
        with AgentProcess(CONTROLLED_SYSCTL_FIXTURE, "sysctl_two_stage",
                          env={"MACDBG_TEST_SYSCTL_HOST": "longer"}) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            text = agent.cmd("raw", {"command": "disassemble -n check_sysctl_two_stage"})["output"]
            sites = re.findall(r"^\s*(0x[0-9a-f]+).*\bbl\s+.*symbol stub for: sysctlbyname\s*$", text, re.M)
            site = int(sites[1], 16)
            bp = agent.cmd("breakpoint_toggle", {"addr": site})
            self.assertTrue(bp["ok"], bp)
            # The data call is in a loop: skip the fixed-width hypervisor read
            # and stop at the spoof-sized model read, whose host value is 64 B.
            for _ in range(2):
                self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
            stepped = agent.cmd("step_over", {"timeout": 15})
            self.assertEqual(stepped.get("event"), "stop", stepped)
            self.assertEqual(stepped["stop"]["pc"], site + 4, stepped)
            self.assertIn("HOST-SYSCTL:hw.model real=64 capacity=8 rc=-1", stepped["console"])
            self.assertIn("spoofed sysctlbyname(hw.model)", stepped["console"])
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, (stepped, result))
            self.assertIn("SYSCTL-TWO-STAGE:clean", result["console"])

    def test_step_out_of_two_stage_queries_handles_longer_host_values(self):
        with AgentProcess(CONTROLLED_SYSCTL_FIXTURE, "sysctl_two_stage",
                          env={"MACDBG_TEST_SYSCTL_HOST": "longer"}) as agent:
            self.assertTrue(agent.enable_cloak()["ok"])
            text = agent.cmd("raw", {"command": "disassemble -n check_sysctl_two_stage"})["output"]
            address = int(re.search(r"^\s*(0x[0-9a-f]+)", text, re.M).group(1), 16)
            bp = agent.cmd("breakpoint_toggle", {"addr": address})
            self.assertTrue(bp["ok"], bp)
            self.assertEqual(agent.continue_to_exit().get("event"), "stop")
            self.assertTrue(agent.cmd("breakpoint_delete", {"bp_id": bp["bp_id"]})["ok"])
            stepped = agent.cmd("step_out", {"timeout": 15})
            self.assertEqual(stepped.get("event"), "stop", stepped)
            self.assertIn("SYSCTL-TWO-STAGE:clean", stepped["console"])
            result = agent.continue_to_exit()
            self.assertEqual(result.get("event"), "exited", result)
            self.assertEqual(result["exit"]["code"], 0, (stepped, result))


if __name__ == "__main__":
    unittest.main()
