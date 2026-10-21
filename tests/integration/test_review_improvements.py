import tempfile
import unittest
import re
import subprocess

import lldb

from GUI.server.engine import Engine
from macdbg.core import state
from macdbg.core.debugger import Debugger
from unittest.mock import patch
from .support import FIXTURE_DIR, AgentProcess, fixture_text_digest


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='md-review-regression-', dir='/private/tmp')
        self.addCleanup(scratch.cleanup)
        self.env = {'MACDBG_STATE_DIR':scratch.name,'PYTHONDONTWRITEBYTECODE':'1'}
        override = patch.object(state, 'STATE_DIR', scratch.name)
        override.start()
        self.addCleanup(override.stop)
        self.fixture = str(FIXTURE_DIR / 'workflow_fixture')

    def test_hardware_and_pending_logical_breakpoints_survive_reopen(self):
        d = Debugger()
        try:
            d.create_target(self.fixture); d.launch([])
            address = d.target.FindFunctions('workflow_marker').GetContextAtIndex(0).GetFunction().GetStartAddress().GetLoadAddress(d.target)
            d.hw_breakpoints = True
            _, bid = d.toggle_breakpoint_at(address)
            d.target.FindBreakpointByID(bid).SetCondition('x0 == 0')
            d.target.BreakpointCreateByName('not_yet_loaded_symbol')
            regex = d.target.BreakpointCreateByRegex('^(open|close)$')
            locations = regex.GetNumLocations()
            self.assertGreater(locations, 1)
            self.assertIsNotNone(d.save_state(set()))
            d.create_target(self.fixture); d.launch([])
            self.assertEqual(d.restore_stored_breakpoints(), 3)
            bps = list(d.target.breakpoint_iter())
            self.assertEqual(sum(b.IsHardware() for b in bps), 1)
            hardware = next(b for b in bps if b.IsHardware())
            self.assertEqual(hardware.GetLocationAtIndex(0).GetLoadAddress(), address)
            self.assertEqual(hardware.GetCondition(), 'x0 == 0')
            self.assertEqual(sum(b.GetNumLocations() == 0 for b in bps), 1)
            self.assertTrue(any(b.GetNumLocations() == locations for b in bps))
        finally:
            d.destroy()

    def test_all_defenses_toggle_off_with_zero_inline_syscalls(self):
        engine = Engine(None, [])
        try:
            engine.dbg.create_target(self.fixture); engine.dbg.launch([])
            engine._t_all_anti()
            self.assertEqual(engine.dbg.direct_syscall_bp_ids, [])
            self.assertTrue(engine._defense_states()['all_anti'])
            engine._t_all_anti()
            flags = engine._defense_states()
            for flag in ('all_anti','analysis_cloak','deny_attach','mach','flag_scrubs','sigtrap'):
                self.assertFalse(flags[flag], flag)
        finally:
            engine.dbg.destroy()

    def test_restored_hardware_breakpoint_passes_target_text_integrity_check(self):
        from macdbg.agent.session import AgentSession
        fixture = FIXTURE_DIR/'analysis_fixture'
        digest = fixture_text_digest(fixture)
        first = AgentSession(str(fixture),['integrity',digest])
        try:
            self.assertTrue(first.start()['ok'])
            first.dbg.hw_breakpoints = True
            first.dbg.toggle_breakpoint_at(first.dbg.pc()+4)
        finally:
            first.shutdown()
        second = AgentSession(str(fixture),['integrity',digest])
        try:
            self.assertTrue(second.start()['ok'])
            self.assertTrue(second.dispatch('defense_enable',{'name':'analysis_cloak'})['ok'])
            stopped = second.dispatch('continue',{'timeout':10})
            self.assertEqual(stopped.get('event'),'stop',stopped)
            result = second.dispatch('continue',{'timeout':10})
            self.assertEqual(result.get('event'),'exited',result)
            self.assertEqual(result['exit']['code'],0,result)
            self.assertIn('INTEGRITY:clean',result['console'])
        finally:
            second.shutdown()

    def test_selective_hardware_trace_pairs_returns_and_captures_read_buffer(self):
        with AgentProcess(self.fixture, 'io', env=self.env) as agent:
            configured = agent.cmd('tracer_config', {'hardware':True, 'hooks':['open','read','close'], 'returns':True})
            self.assertTrue(configured['ok'],configured)
            result = agent.cmd('tracer_enable')
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['total'], 3)
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'), 'exited', result)
            rows = agent.cmd('trace_hits')['hits']
            entries = [r for r in rows if r['phase'] == 'entry']
            returns = [r for r in rows if r['phase'] == 'return']
            self.assertEqual(len(entries), 3, rows)
            self.assertEqual(len(returns), 3, rows)
            self.assertEqual({r['invocation'] for r in entries}, {r['invocation'] for r in returns})
            read = next(r for r in returns if r['call'].startswith('read'))
            self.assertEqual(read['return_value'], 16)
            self.assertEqual(read['payload']['captured_bytes'], 16)

    def test_failed_open_captures_signed_result_and_thread_errno(self):
        missing = self.env['MACDBG_STATE_DIR'] + '/missing-parent/file'
        with AgentProcess(self.fixture,'create',[missing],env=self.env) as agent:
            self.assertTrue(agent.cmd('tracer_enable',{'hooks':['open'],'returns':True})['ok'])
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'),'exited',result)
            returned = next(row for row in agent.cmd('trace_hits')['hits'] if row['phase']=='return')
            self.assertEqual(returned['return_value'],-1)
            self.assertEqual(returned['errno'],2)

    def test_memory_diff_monitor_and_first_execution_guard(self):
        with AgentProcess(FIXTURE_DIR / 'memory_analysis_fixture', '', env=self.env) as agent:
            self.assertTrue(agent.cmd('memory_monitor')['ok'])
            self.assertTrue(agent.cmd('raw', {'command':'breakpoint set -n memory_ready'})['ok'])
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'),'stop',result)
            def pointer(expression):
                response = agent.cmd('raw', {'command':'expression -- (unsigned long)(' + expression + ')'})
                self.assertTrue(response['ok'], response)
                return int(re.search(r'=\s*(0x[0-9a-fA-F]+|\d+)', response['output'])[1],0)
            code = pointer('review_region')
            scan = agent.cmd('scan_syscalls',{'addr':code,'size':16})
            self.assertTrue(scan['ok'],scan)
            self.assertEqual(scan['sites'],1)
            buffer = pointer('&review_text[0]')
            snapshot = agent.cmd('memory_snapshot', {'addr':buffer,'size':64})
            self.assertTrue(snapshot['ok'], snapshot)
            guard = agent.cmd('execution_guard', {'addr':code})
            self.assertTrue(guard['ok'],guard)
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'),'stop',result)
            self.assertEqual(result['stop']['reason'],'execute-guard',result)
            self.assertEqual(result['stop']['pc'],code+4)
            diff = agent.cmd('memory_compare', {'id':snapshot['id']})
            self.assertGreater(diff['changed_bytes'],0,diff)
            self.assertTrue(any(s['text']=='after local decoding' for s in diff['strings_added']))
            regions = agent.cmd('memory_map')['regions']
            self.assertTrue(next(r for r in regions if r['base'] <= code < r['end'])['protection'] & 4)
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'),'exited',result)
            self.assertEqual(result['exit']['code'],0,result)
            events = agent.cmd('analysis_events')['hits']
            self.assertTrue(any(e['call']=='new executable region' for e in events),events)

    def test_queued_cloak_reaches_entry_before_running_main(self):
        from macdbg.agent.session import AgentSession
        session = AgentSession(self.fixture, ['io'], stop_at='loader')
        try:
            self.assertTrue(session.start()['ok'])
            queued = session.dispatch('queue_defense',{'name':'analysis_cloak'})
            self.assertTrue(queued['ok'],queued)
            stopped = session.dispatch('continue_to_entry',{'timeout':10})
            self.assertEqual(stopped.get('event'),'stop',stopped)
            self.assertTrue(session.dbg.is_stopped_at_entry_point())
            self.assertTrue(session.dbg.analysis_cloak.enabled)
            self.assertFalse(session.dbg.entry_plan.queued)
            restarted = session.dispatch('restart',{})
            self.assertTrue(restarted['ok'],restarted)
            self.assertTrue(session.dbg.is_stopped_before_initializers())
            self.assertIn('analysis_cloak',session.dbg.entry_plan.queued)
            stopped = session.dispatch('continue_to_entry',{'timeout':10})
            self.assertEqual(stopped.get('event'),'stop',stopped)
            self.assertTrue(session.dbg.analysis_cloak.enabled)
        finally:
            session.shutdown(save=False)

    def test_preserve_identity_matches_native_model_and_custom_profile_is_applied(self):
        expected = subprocess.check_output(['/usr/sbin/sysctl','-n','hw.model'],text=True).strip()
        with AgentProcess(FIXTURE_DIR / 'analysis_fixture','sysctl',env=self.env) as agent:
            self.assertTrue(agent.cmd('identity_profile',{'mode':'preserve'})['ok'])
            self.assertTrue(agent.enable_cloak()['ok'])
            result = agent.continue_to_exit()
            self.assertIn('model='+expected,result['console'])
        with AgentProcess(FIXTURE_DIR / 'analysis_fixture','sysctl',env=self.env) as agent:
            configured = agent.cmd('identity_profile',{'mode':'spoof','model':'MacReview,1','cpu':'Local test CPU'})
            self.assertTrue(configured['ok'],configured)
            self.assertTrue(agent.enable_cloak()['ok'])
            result = agent.continue_to_exit()
            self.assertIn('model=MacReview,1 cpu=Local test CPU',result['console'])

    def test_gui_analysis_commands_and_navigation_preserve_pc(self):
        e = Engine(None,[])
        try:
            e.dbg.create_target(self.fixture);e.dbg.launch([])
            pc = e.dbg.pc()
            e._c_follow_disasm({'addr':pc+4})
            e._c_follow_disasm({'addr':pc+8})
            e._c_navigate_history({'direction':'back'})
            self.assertEqual(e._disasm_follow,pc+4)
            e._c_navigate_history({'direction':'forward'})
            self.assertEqual(e._disasm_follow,pc+8)
            self.assertEqual(e.dbg.pc(),pc)
            e._c_view_options({'memory_width':8})
            self.assertEqual(e._build_state()['memory']['width'],8)
            snapshot = e._c_analysis({'action':'memory_snapshot','addr':pc,'size':16})
            diff = e._c_analysis({'action':'memory_compare','id':snapshot['id']})
            self.assertEqual(diff['changed_bytes'],0)
            self.assertEqual(e._build_state()['stop']['pc'],pc)
        finally:
            e.dbg.destroy()
