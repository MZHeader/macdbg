import unittest
from unittest.mock import MagicMock, Mock

import lldb

from macdbg.core.breakpoints import (
    consume_hardware_debugger_duplicate, remember_hardware_return,
    remember_continue_positions,
    recover_owned_hardware_stop,
)


class RetiredHardwareStopTests(unittest.TestCase):
    def image_return(self):
        d,p,t,bp=self.debugger()
        d._hardware_recovery=None;d._hardware_recovery_failed=None
        p.GetUniqueID.return_value=123
        bp.GetID.return_value=40;bp.IsEnabled.return_value=True
        d.target.breakpoint_iter.return_value=iter([bp])
        d._traced_hardware_stop=(123,20,30,0x1000,bytes.fromhex('1f2003d5'),40)
        d.analysis_cloak.validate_resume.return_value=(True,'')
        d.analysis_cloak.validate_integrity.return_value=(True,'')
        d._run_execution.side_effect=lambda fn:fn()
        return d,p,t,bp

    def test_missing_image_return_id_executes_instruction_then_continues(self):
        d,p,t,_=self.image_return()
        self.assertEqual(recover_owned_hardware_stop(d,Mock()),'resumed')
        t.StepInstruction.assert_called_once_with(False)
        t.GetFrameAtIndex.return_value.SetPC.assert_not_called()
        p.GetStopID.return_value=22
        t.GetStopReason.return_value=lldb.eStopReasonPlanComplete
        self.assertEqual(recover_owned_hardware_stop(d,Mock()),'internal')
        self.assertIsNone(d._hardware_recovery)

    def test_missing_id_recovery_preserves_real_traps_foreign_sites_and_failed_steps(self):
        for change in ('trap','foreign','thread','user_step'):
            d,p,t,bp=self.image_return()
            if change=='trap':d.read_memory.return_value=bytes.fromhex('000020d4')
            if change=='foreign':
                foreign=Mock();foreign.GetID.return_value=41;foreign.GetNumLocations.return_value=1
                foreign.GetLocationAtIndex.return_value.GetLoadAddress.return_value=0x1000
                d.target.breakpoint_iter.return_value=iter([bp,foreign])
            if change=='thread':bp.GetThreadID.return_value=31
            if change=='user_step':d.in_user_step.return_value=True
            self.assertIsNone(recover_owned_hardware_stop(d,Mock()))
            t.StepInstruction.assert_not_called()
        d,p,t,_=self.image_return()
        self.assertEqual(recover_owned_hardware_stop(d,Mock()),'resumed')
        p.GetStopID.return_value=22
        self.assertEqual(recover_owned_hardware_stop(d,Mock()),'visible')
        self.assertEqual(recover_owned_hardware_stop(d,Mock()),'visible')
        t.StepInstruction.assert_called_once()

    def debugger(self):
        d = Mock()
        d._retired_hardware_return = None
        d._hardware_continue = None
        d._suppress_duplicate_retry = False
        d.in_user_step.return_value = False
        p = MagicMock()
        d.process = p
        p.GetProcessID.return_value = 10
        p.GetStopID.return_value = 20
        p.GetState.return_value = lldb.eStateStopped
        t = Mock()
        p.GetSelectedThread.return_value = t
        p.__iter__.side_effect = lambda: iter([t])
        t.GetThreadID.return_value = 30
        t.GetStopReason.return_value = lldb.eStopReasonBreakpoint
        t.GetStopReasonDataCount.return_value = 2
        t.GetStopReasonDataAtIndex.return_value = 40
        t.GetFrameAtIndex.return_value.GetPC.return_value = 0x1000
        bp = d.target.FindBreakpointByID.return_value
        bp.IsValid.return_value = bp.IsHardware.return_value = True
        bp.GetThreadID.return_value = 30
        bp.GetNumLocations.return_value = 1
        bp.GetLocationAtIndex.return_value.IsResolved.return_value = True
        bp.GetLocationAtIndex.return_value.GetLoadAddress.return_value = 0x1000
        d.read_memory.return_value = bytes.fromhex('1f2003d5')  # nop
        d.target.GetNumBreakpoints.return_value = 0
        remember_hardware_return(d, 40)
        p.GetStopID.return_value = 21
        t.GetStopReason.return_value = lldb.eStopReasonException
        t.GetStopDescription.return_value = 'EXC_BREAKPOINT (code=1, subcode=0x1000)'
        return d, p, t, bp

    def test_exact_duplicate_retries_once_without_skipping_instruction(self):
        d, _, thread, _ = self.debugger()
        self.assertTrue(consume_hardware_debugger_duplicate(d))
        self.assertFalse(consume_hardware_debugger_duplicate(d))
        thread.GetFrameAtIndex.return_value.SetPC.assert_not_called()
        d.write_memory.assert_not_called()

    def test_changed_process_stop_thread_pc_or_instruction_is_preserved(self):
        for field in ('pid', 'stop', 'thread', 'pc', 'code', 'step'):
            with self.subTest(field=field):
                d, p, t, _ = self.debugger()
                if field == 'pid': p.GetProcessID.return_value = 11
                if field == 'stop': p.GetStopID.return_value = 22
                if field == 'thread': t.GetThreadID.return_value = 31
                if field == 'pc': t.GetFrameAtIndex.return_value.GetPC.return_value = 0x1004
                if field == 'code': d.read_memory.return_value = bytes.fromhex('000020d4')
                if field == 'step': d.in_user_step.return_value = True
                self.assertFalse(consume_hardware_debugger_duplicate(d))

    def test_unidentified_exception_signal_and_user_breakpoint_are_preserved(self):
        for reason, description in (
                (lldb.eStopReasonException, 'EXC_BREAKPOINT (code=1, subcode=0x0)'),
                (lldb.eStopReasonException, 'EXC_BAD_ACCESS'),
                (lldb.eStopReasonSignal, 'SIGTRAP'),
                (lldb.eStopReasonBreakpoint, 'breakpoint 41.1')):
            d, _, t, _ = self.debugger()
            t.GetStopReason.return_value = reason
            t.GetStopDescription.return_value = description
            self.assertFalse(consume_hardware_debugger_duplicate(d))

    def test_concurrent_real_stop_and_live_site_are_preserved(self):
        d, p, t, bp = self.debugger()
        other = Mock()
        other.GetStopReason.return_value = lldb.eStopReasonBreakpoint
        p.__iter__.side_effect = lambda: iter([t, other])
        self.assertFalse(consume_hardware_debugger_duplicate(d))
        d, _, _, bp = self.debugger()
        d.target.GetNumBreakpoints.return_value = 1
        d.target.GetBreakpointAtIndex.return_value = bp
        self.assertFalse(consume_hardware_debugger_duplicate(d))

    def test_shared_stop_and_real_trap_instruction_are_not_remembered(self):
        for shared in (True, False):
            d, p, t, _ = self.debugger()
            d._retired_hardware_return = None
            p.GetStopID.return_value = 20
            t.GetStopReason.return_value = lldb.eStopReasonBreakpoint
            if shared:
                t.GetStopReasonDataCount.return_value = 4
            else:
                d.read_memory.return_value = bytes.fromhex('000020d4')
            remember_hardware_return(d, 40)
            self.assertIsNone(d._retired_hardware_return)

    def interrupted_continue(self):
        d, p, t, bp = self.debugger()
        d._retired_hardware_return = None
        d.target.GetTriple.return_value = 'arm64-apple-macosx'
        d.target.GetNumBreakpoints.return_value = 1
        d.target.GetBreakpointAtIndex.return_value = bp
        bp.GetLocationAtIndex.return_value.GetLoadAddress.return_value = 0x2000
        p.GetStopID.return_value = 20
        remember_continue_positions(d)
        p.GetStopID.return_value = 21
        t.GetStopDescription.return_value = 'EXC_BREAKPOINT (code=1, subcode=0x0)'
        return d, p, t, bp

    def test_interrupted_free_continue_retries_only_once(self):
        d, p, _, _ = self.interrupted_continue()
        self.assertTrue(consume_hardware_debugger_duplicate(d))
        remember_continue_positions(d)
        p.GetStopID.return_value = 22
        self.assertFalse(consume_hardware_debugger_duplicate(d))

    def test_interrupted_continue_requires_unchanged_pc_and_instruction(self):
        for changed in ('pc', 'code', 'stop', 'user_step'):
            d, p, t, _ = self.interrupted_continue()
            if changed == 'pc': t.GetFrameAtIndex.return_value.GetPC.return_value = 0x1004
            if changed == 'code': d.read_memory.return_value = bytes.fromhex('000020d4')
            if changed == 'stop': p.GetStopID.return_value = 23
            if changed == 'user_step': d.in_user_step.return_value = True
            self.assertFalse(consume_hardware_debugger_duplicate(d))

    def test_software_only_execution_does_not_arm_continue_retry(self):
        d, _, _, bp = self.interrupted_continue()
        bp.IsHardware.return_value = False
        remember_continue_positions(d)
        self.assertIsNone(d._hardware_continue)
