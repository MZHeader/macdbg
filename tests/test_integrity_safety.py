import sys
import types
import unittest
from unittest import mock

from macdbg.core.anti_analysis import AnalysisCloak

from macdbg.core import breakpoints as hardware


class Location:
    def __init__(self, addr, enabled=True, resolved=True):
        self.addr, self.enabled, self.resolved = addr, enabled, resolved

    def GetLoadAddress(self):
        return self.addr

    def IsEnabled(self):
        return self.enabled

    def IsResolved(self):
        return self.resolved


class Breakpoint:
    def __init__(self, bp_id, locations, hardware=False, enabled=True, thread_id=0):
        self.id, self.locations = bp_id, locations
        self.hardware, self.enabled = hardware, enabled
        self.thread_id = thread_id

    def GetThreadID(self):
        return self.thread_id

    def SetThreadID(self, thread_id):
        self.thread_id = thread_id

    def SetOneShot(self, value):
        self.one_shot = value

    def GetID(self):
        return self.id

    def GetNumLocations(self):
        return len(self.locations)

    def GetLocationAtIndex(self, index):
        return self.locations[index]

    def IsEnabled(self):
        return self.enabled

    def IsHardware(self):
        return self.hardware

    def IsValid(self):
        return True


class Target:
    def __init__(self, bps, start=0x1000, size=0x100):
        self.bps = list(bps)
        self.text = mock.Mock()
        self.text.IsValid.return_value = True
        self.text.GetLoadAddress.return_value = start
        self.text.GetByteSize.return_value = size

    def GetNumBreakpoints(self):
        return len(self.bps)

    def GetBreakpointAtIndex(self, index):
        return self.bps[index]

    def FindBreakpointByID(self, bp_id):
        return next((bp for bp in self.bps if bp.id == bp_id),
                    types.SimpleNamespace(IsValid=lambda: False))

    def GetExecutable(self):
        return "main"

    def FindModule(self, executable):
        assert executable == "main"
        module = mock.Mock()
        module.IsValid.return_value = True
        module.FindSection.return_value.FindSubSection.return_value = self.text
        return module

    def BreakpointDelete(self, bp_id):
        self.bps = [bp for bp in self.bps if bp.id != bp_id]
        return True


class IntegritySafetyTests(unittest.TestCase):
    def setUp(self):
        self.capacity = mock.patch.object(hardware, "hardware_breakpoint_capacity", return_value=6)
        self.capacity.start()
        self.addCleanup(self.capacity.stop)

    def cloak(self, bps=(), known=(), patches=()):
        debugger = types.SimpleNamespace(
            target=Target(bps), hardware_bp_ids=set(known),
            state=types.SimpleNamespace(patches=patches))
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        return cloak

    def test_every_location_is_checked_and_disabled_locations_are_ignored(self):
        bp = Breakpoint(7, [Location(0x9000), Location(0x1080)])
        cloak = self.cloak([bp])
        self.assertIn("software breakpoint modifies", cloak.validate_integrity(set())[1])
        bp.locations[1].enabled = False
        self.assertTrue(cloak.validate_integrity(set())[0])
        bp.locations[1].enabled = True
        bp.enabled = False
        self.assertTrue(cloak.validate_integrity(set())[0])

    def test_tracking_and_actual_hardware_flag_are_both_required(self):
        bp = Breakpoint(7, [Location(0x1080)], hardware=True)
        cloak = self.cloak([bp], known=[99])
        self.assertFalse(cloak.validate_integrity(set())[0])
        self.assertEqual(cloak.debugger.hardware_bp_ids, set())
        self.assertTrue(cloak.validate_integrity({7})[0])
        bp.hardware = False
        self.assertFalse(cloak.validate_integrity({7})[0])

    def test_unmapped_text_and_uninstalled_hardware_fail_closed(self):
        cloak = self.cloak([Breakpoint(7, [Location(0x1000, resolved=False)], hardware=True)], known=[7])
        self.assertIn("not installed", cloak.validate_integrity(set())[1])
        cloak.debugger.target.text.GetLoadAddress.return_value = 0xffffffffffffffff
        self.assertIn("not mapped", cloak.validate_integrity(set())[1])

    def test_patch_overlap_includes_patch_starting_before_text(self):
        patch = types.SimpleNamespace(addr=0xffe, new=b"1234")
        cloak = self.cloak(patches=[patch])
        self.assertIn("tracked patch modifies", cloak.validate_integrity(set())[1])
        patch.new = b"12"
        self.assertTrue(cloak.validate_integrity(set())[0])
        patch.addr = 0x1100
        self.assertTrue(cloak.validate_integrity(set())[0])

    def test_capacity_counts_other_modules_and_all_owners(self):
        bps = [Breakpoint(n, [Location(0x9000 + n * 4)], hardware=True) for n in range(7)]
        cloak = self.cloak(bps)
        self.assertIn("7 sites exceed 6 slots", cloak.validate_integrity(set())[1])
        bps[0].enabled = False
        self.assertTrue(cloak.validate_integrity(set())[0])
        cloak.debugger._step_active = True
        cloak.debugger._step_target_depth = 2
        self.assertIn("7 sites exceed 6 slots", cloak.validate_integrity(set())[1])

    def test_failed_allocation_removes_only_new_breakpoint(self):
        existing = Breakpoint(1, [Location(0x1000)], hardware=True)
        target = Target([existing])
        result = mock.Mock()
        result.Succeeded.return_value = False
        result.GetError.return_value = "synthetic allocation failure"
        ci = mock.Mock()
        ci.HandleCommand.side_effect = lambda *_: target.bps.append(
            Breakpoint(2, [Location(0x1010)], hardware=True))
        with mock.patch.dict(sys.modules, {"lldb": types.SimpleNamespace(
                SBCommandReturnObject=lambda: result)}):
            with self.assertRaisesRegex(RuntimeError, "slots"):
                hardware.create_hardware_breakpoint(target, ci, "-a 0x1010")
        self.assertEqual(target.bps, [existing])

    def test_hardware_creation_refuses_a_shared_software_site(self):
        existing = Breakpoint(1, [Location(0x1000)])
        target = Target([existing])
        result = mock.Mock()
        result.Succeeded.return_value = True
        ci = mock.Mock()
        ci.HandleCommand.side_effect = lambda *_: target.bps.append(
            Breakpoint(2, [Location(0x1000)], hardware=True))
        with mock.patch.dict(sys.modules, {"lldb": types.SimpleNamespace(
                SBCommandReturnObject=lambda: result)}):
            with self.assertRaisesRegex(RuntimeError, "software breakpoint"):
                hardware.create_hardware_breakpoint(target, ci, "-a 0x1000")
        self.assertEqual(target.bps, [existing])

    def test_tracer_tracks_regex_hardware_and_cleans_up_after_failure(self):
        with mock.patch.dict(sys.modules, {"lldb": types.SimpleNamespace()}):
            from macdbg.core import tracer as tracer_module
        target = Target([])
        target.IsValid = lambda: True
        target.GetExecutable = lambda: types.SimpleNamespace(GetFilename=lambda: "fixture")
        bp1 = Breakpoint(1, [Location(0x1000)], hardware=True)
        bp2 = Breakpoint(2, [Location(0x1020)], hardware=True)
        tracer = tracer_module.Tracer()
        tracer.hardware = True
        with mock.patch.object(tracer_module, "SIGS", {"name": None}), \
                mock.patch.object(tracer_module, "REGEX_SIGS", [("regex", "PROC", None)]), \
                mock.patch.object(hardware, "create_hardware_breakpoint", side_effect=[bp1, bp2]) as create:
            self.assertEqual(tracer.enable(target, ci=object()), (2, 2))
            self.assertIn("-r regex", create.call_args.args)
            copied = tracer.hardware_bp_ids
            copied.clear()
            self.assertEqual(tracer.hardware_bp_ids, {1, 2})
        tracer.disable(target)
        self.assertEqual(tracer.hardware_bp_ids, set())
        target.bps = [bp1]
        with mock.patch.object(tracer_module, "SIGS", {"name": None, "other": None}), \
                mock.patch.object(hardware, "create_hardware_breakpoint", side_effect=[bp1, RuntimeError("slots")]):
            with self.assertRaisesRegex(RuntimeError, "slots"):
                tracer.enable(target, ci=object())
        self.assertFalse(tracer.enabled)
        self.assertEqual(tracer.hardware_bp_ids, set())
        self.assertEqual(target.bps, [])

    def test_gui_gate_rejects_integrity_before_emitting_running(self):
        from tests.test_sysctl_cloak_orchestration import GuiCloakFailureTests
        engine = GuiCloakFailureTests().make_engine()
        engine.dbg.analysis_cloak = mock.Mock()
        engine.dbg.analysis_cloak.validate_resume.return_value = (True, "ready")
        engine.dbg.analysis_cloak.validate_integrity.return_value = (False, "unsafe text")
        engine.tracer.hardware_bp_ids = {9}
        self.assertFalse(engine._begin_resume())
        self.assertFalse(engine._resuming)
        engine._emit.assert_not_called()
        engine._console.assert_called_once_with("[anti-analysis] unsafe text", error=True)

    def test_headless_pump_rejects_integrity_before_calling_resume(self):
        from tests.test_sysctl_cloak_orchestration import AgentSession, FAKE_LLDB, FakeDebugger
        session = AgentSession.__new__(AgentSession)
        session.dbg = FakeDebugger()
        session.dbg.analysis_cloak = mock.Mock()
        session.dbg.analysis_cloak.validate_integrity.return_value = (False, "unsafe text")
        session.tracer = types.SimpleNamespace(hardware_bp_ids={9})
        resume = mock.Mock()
        with mock.patch.object(FAKE_LLDB, "eStateExited", 10, create=True), \
                mock.patch.object(FAKE_LLDB, "eStateInvalid", 0, create=True):
            result = session._pump(resume=resume)
        self.assertEqual(result, {"ok": False, "error": "unsafe text"})
        resume.assert_not_called()

    def test_gui_allocation_failure_clears_running_state_and_allows_retry(self):
        from tests.test_sysctl_cloak_orchestration import GuiCloakFailureTests
        for command, operation in (("_c_step_out", "step_out"),
                                   ("_c_step_over", "step_over"),
                                   ("_c_run_to", "run_to_address")):
            with self.subTest(command=command):
                engine = GuiCloakFailureTests().make_engine()
                engine.dbg.analysis_cloak = mock.Mock()
                engine.dbg.analysis_cloak.validate_resume.return_value = (True, "ready")
                engine.dbg.analysis_cloak.validate_integrity.return_value = (True, "ready")
                engine.tracer.hardware_bp_ids = set()
                engine.dbg.cancel_user_step = mock.Mock()
                engine._addr = lambda _: 0x1000
                action = mock.Mock(side_effect=RuntimeError("hardware breakpoint slots exhausted"))
                setattr(engine.dbg, operation, action)
                getattr(engine, command)({"addr": 0x1000})
                self.assertFalse(engine._resuming)
                engine.dbg.cancel_user_step.assert_called_once_with()
                engine._emit_state.assert_called_once_with()
                action.side_effect = None
                action.return_value = (True, "running") if command == "_c_run_to" else None
                getattr(engine, command)({"addr": 0x1000})
                self.assertTrue(engine._resuming)


class StepHookOwnershipTests(unittest.TestCase):
    def setUp(self):
        from tests.test_sysctl_cloak_orchestration import AgentSession
        debugger_class = AgentSession.__init__.__globals__["Debugger"]
        fake_lldb = debugger_class._process_cloak_step_stop.__globals__["lldb"]
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(fake_lldb, "LLDB_INVALID_THREAD_ID", 0, create=True).start()
        mock.patch.dict(sys.modules, {"lldb": fake_lldb}).start()
        self.dbg = debugger_class.__new__(debugger_class)
        self.dbg.target = Target([])
        self.dbg.hardware_bp_ids = set()
        self.dbg._step_cloak_handled_stop = None
        self.dbg._step_cloak_messages = []
        self.thread = mock.Mock()
        self.thread.GetThreadID.return_value = 222
        self.thread.GetStopReason.return_value = 8  # eStopReasonPlanComplete
        self.thread.GetNumFrames.return_value = 2
        self.frame = self.thread.GetFrameAtIndex.return_value
        self.frame.GetPC.return_value = 0x1000
        self.frame.FindRegister.return_value.GetValueAsUnsigned.return_value = 0
        self.dbg.process = mock.Mock()
        self.dbg.process.GetStopID.return_value = 1
        self.dbg.process.GetSelectedThread.return_value = self.thread
        self.cloak = self.dbg.analysis_cloak = AnalysisCloak(self.dbg)
        self.cloak.enabled = True
        # Resume readiness is independently covered; keep dispatch and hook
        # consumption real while replacing only the external LLDB surface.
        mock.patch.object(self.cloak, "validate_resume", return_value=(True, "ready")).start()

    def test_foreign_thread_leaves_return_hook_for_owner_at_same_pc(self):
        bp = Breakpoint(99, [Location(0x1000)], hardware=True, thread_id=111)
        self.dbg.target.bps.append(bp)
        self.dbg.hardware_bp_ids.add(99)
        self.cloak._return_hooks[99] = ("proc_pidpath", 0x2000, 1024)
        self.cloak._return_hook_threads[99] = 111

        self.dbg._process_cloak_step_stop(self.thread)
        self.assertIn(99, self.cloak._return_hooks)
        self.assertEqual(self.dbg.target.bps, [bp])
        self.assertEqual(self.dbg.hardware_bp_ids, {99})

        self.thread.GetThreadID.return_value = 111
        self.dbg._process_cloak_step_stop(self.thread)
        self.assertEqual(self.cloak._return_hooks, {})
        self.assertEqual(self.dbg.target.bps, [])
        self.assertEqual(self.dbg.hardware_bp_ids, set())
        self.assertEqual(self.cloak._return_hook_threads, {})

    def test_explicit_shared_site_ids_keep_foreign_hook_after_owner_one_shot_deletion(self):
        foreign = Breakpoint(99, [Location(0x1000)], hardware=True, thread_id=111)
        # LLDB has already auto-deleted the matching BP 100, but reports both
        # constituent IDs in the shared site's breakpoint stop reason.
        self.dbg.target.bps.append(foreign)
        self.dbg.hardware_bp_ids.update((99, 100))
        self.cloak._return_hooks.update({
            99: ("proc_pidpath", 0x2000, 1024),
            100: ("proc_pidpath", 0x3000, 1024),
        })
        self.cloak._return_hook_threads.update({99: 111, 100: 222})
        self.thread.GetStopReason.return_value = 3
        self.thread.GetStopReasonDataCount.return_value = 4
        self.thread.GetStopReasonDataAtIndex.side_effect = [99, 1, 100, 1].__getitem__

        self.dbg._process_cloak_step_stop(self.thread)
        self.assertEqual(set(self.cloak._return_hooks), {99})
        self.assertEqual(self.cloak._return_hook_threads, {99: 111})
        self.assertEqual(self.dbg.hardware_bp_ids, {99})
        self.assertEqual(self.dbg.target.bps, [foreign])

    def test_ordinary_dispatch_also_preserves_foreign_return_hook(self):
        self.cloak._return_hooks[99] = ("proc_pidpath", 0x2000, 1024)
        self.cloak._return_hook_threads[99] = 111
        self.assertIsNone(self.cloak.handle_hit(99, resume=False))
        self.assertIn(99, self.cloak._return_hooks)
        self.assertEqual(self.cloak._return_hook_threads, {99: 111})

    def test_return_hook_without_retained_owner_fails_closed(self):
        self.cloak._return_hooks[99] = ("proc_pidpath", 0x2000, 1024)
        message = self.cloak.handle_hit(99, resume=False)
        self.assertIn("missing thread ownership", message)
        self.assertEqual(self.cloak.last_error, message)
        self.assertIn(99, self.cloak._return_hooks)

    def test_hook_cleanup_removes_ownership_on_reset_disable_and_explicit_delete(self):
        for operation in ("clear_return_hooks", "disable", "_delete_breakpoints"):
            with self.subTest(operation=operation):
                self.cloak._return_hooks[99] = ("proc_pidpath", 0x2000, 1024)
                self.cloak._return_hook_threads[99] = 111
                self.dbg.hardware_bp_ids.add(99)
                args = ([99],) if operation == "_delete_breakpoints" else ()
                getattr(self.cloak, operation)(*args)
                self.assertEqual(self.cloak._return_hooks, {})
                self.assertEqual(self.cloak._return_hook_threads, {})
                self.assertEqual(self.dbg.hardware_bp_ids, set())

    def test_global_entry_creates_separate_return_hooks_for_both_threads(self):
        entry = Breakpoint(98, [Location(0x1000)])
        self.dbg.target.bps.append(entry)
        self.cloak._bp_ids.add(98)
        self.cloak._entry_hooks[98] = "proc_pidpath"
        self.frame.FindRegister.side_effect = lambda name: types.SimpleNamespace(
            GetValueAsUnsigned=lambda: {"x1": 0x2000, "x2": 1024, "lr": 0x1100}[name])

        def create_return(address):
            bp = Breakpoint(99 + len(self.cloak._return_hooks), [Location(address)], hardware=True)
            self.dbg.target.bps.append(bp)
            return bp

        self.dbg.create_hardware_breakpoint_by_address = create_return
        for thread_id in (111, 222):
            self.thread.GetThreadID.return_value = thread_id
            self.dbg._process_cloak_step_stop(self.thread)
        self.assertEqual(set(self.cloak._return_hooks), {99, 100})
        self.assertEqual([bp.GetThreadID() for bp in self.dbg.target.bps], [0, 111, 222])
        self.assertEqual(self.cloak._return_hook_threads, {99: 111, 100: 222})


if __name__ == "__main__":
    unittest.main()
