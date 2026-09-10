import unittest

from .support import run_core_probe


class LegacyReturnOwnershipTests(unittest.TestCase):
    def test_shared_site_preserves_foreign_legacy_hook_after_matching_one_shot_deletion(self):
        rows = run_core_probe('''
            import json, lldb
            from macdbg.agent.session import AgentSession
            from tests.integration.support import FIXTURE, fixture_symbol
            rows = []
            for dispatch in ("ordinary", "step", "step_plan_complete"):
                s = AgentSession(str(FIXTURE), ["parent"])
                try:
                    assert s.start()["ok"]
                    d = s.dbg
                    thread = d.process.GetSelectedThread()
                    tid = thread.GetThreadID()
                    error = lldb.SBError()
                    base = d.process.AllocateMemory(2048, 3, error)
                    assert error.Success()
                    buffers = [base, base + 1024]
                    for buf in buffers:
                        assert d.process.WriteMemory(buf + 32, (0x800).to_bytes(4, "little"), error) == 4
                    ids = []
                    for owner in (tid + 1000000000, tid):
                        bp = d.create_hardware_breakpoint_by_address(fixture_symbol("check_parent"))
                        bp.SetOneShot(dispatch != "step_plan_complete")
                        bp.SetThreadID(owner)
                        ids.append(bp.GetID())
                    stopped = s.dispatch("continue", {"timeout": 15})
                    assert stopped["event"] == "stop", stopped
                    thread = d.process.GetSelectedThread()
                    reported = [thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)]
                    valid = [d.target.FindBreakpointByID(i).IsValid() for i in ids]
                    d._flag_scrub_returns = {i: ("sysctl", buf, 0) for i, buf in zip(ids, buffers)}
                    d._flag_scrub_return_threads = dict(zip(ids, (tid + 1000000000, tid)))
                    d._scrub_ptraced = True
                    continues = []
                    d.cont = lambda: continues.append(True)
                    if dispatch == "ordinary":
                        for bid in reported:
                            if d.handle_flag_scrub_hit(bid) is not None:
                                break
                    else:
                        d.analysis_cloak.enabled = True
                        d.analysis_cloak.validate_resume = lambda: (True, "ownership-only probe")
                        if dispatch == "step_plan_complete":
                            class PlanStop:
                                def GetStopReason(self): return lldb.eStopReasonPlanComplete
                                def __getattr__(self, name): return getattr(thread, name)
                            stopped_thread = PlanStop()
                        else:
                            stopped_thread = thread
                        d._process_cloak_step_stop(stopped_thread)
                    rows.append({"dispatch": dispatch, "reported": reported, "ids": ids,
                                 "valid": valid, "flags": [d._read_uint(buf + 32, 4) for buf in buffers],
                                 "pending": sorted(d._flag_scrub_returns),
                                 "owners": d._flag_scrub_return_threads,
                                 "foreign_valid": d.target.FindBreakpointByID(ids[0]).IsValid(),
                                 "continues": len(continues)})
                finally:
                    s.shutdown(save=False)
            print(json.dumps(rows))
        ''')
        for row in rows:
            with self.subTest(dispatch=row["dispatch"]):
                foreign, matched = row["ids"]
                self.assertEqual(set(row["reported"]), {foreign, matched}, row)
                self.assertEqual(row["valid"], [True, row["dispatch"] == "step_plan_complete"], row)
                self.assertEqual(row["flags"], [0x800, 0], row)
                self.assertEqual(row["pending"], [foreign], row)
                self.assertEqual(set(row["owners"]), {str(foreign)}, row)
                self.assertTrue(row["foreign_valid"], row)
                self.assertEqual(row["continues"], 1 if row["dispatch"] == "ordinary" else 0)

    def test_arming_retains_thread_owner_and_restart_clears_it(self):
        row = run_core_probe('''
            import json
            from macdbg.agent.session import AgentSession
            from tests.integration.support import FIXTURE
            s = AgentSession(str(FIXTURE), ["env"])
            try:
                assert s.start()["ok"]
                assert s.dbg.enable_analysis_cloak()[0]
                d = s.dbg
                thread = d.process.GetSelectedThread()
                d._arm_return_scrub(thread, "sysctl", 0x2000, 0x3000)
                before = {"returns": sorted(d._flag_scrub_returns),
                          "owners": getattr(d, "_flag_scrub_return_threads", None),
                          "tid": thread.GetThreadID()}
                restarted = s.dispatch("restart", {})
                print(json.dumps({"before": before, "restart": restarted,
                                  "returns": d._flag_scrub_returns,
                                  "owners": getattr(d, "_flag_scrub_return_threads", None)}))
            finally:
                s.shutdown(save=False)
        ''')
        self.assertTrue(row["before"]["returns"], row)
        self.assertEqual(row["before"]["owners"],
                         {str(i): row["before"]["tid"] for i in row["before"]["returns"]}, row)
        self.assertEqual(row["restart"]["event"], "stop", row)
        self.assertFalse(row["returns"], row)
        self.assertFalse(row["owners"], row)
