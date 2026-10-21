import os
import tempfile
import unittest
from unittest.mock import patch

from macdbg.agent.session import AgentSession
from macdbg.core import state
from macdbg.core.instruction_trace import InstructionTrace
from GUI.server.workspace import Workspace
from .support import FIXTURE_DIR


class InstructionTraceIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='md-record-', dir='/private/tmp')
        self.addCleanup(directory.cleanup)
        override = patch.object(state, 'STATE_DIR', directory.name)
        override.start(); self.addCleanup(override.stop)
        self.session = AgentSession(str(FIXTURE_DIR / 'ui_fixture'), [])
        self.addCleanup(self.session.shutdown, False)
        started = self.session.start()
        self.assertTrue(started['ok'], started)
        self.ws = Workspace(self.session.dbg, self.session._hidden_bp_ids)
        self.trace = self.session.dbg.instruction_trace

    def test_records_real_load_and_historical_state_survives_reopen(self):
        self.ws.command('breakpoint_save', {'expression': 'ui_load', 'kind': 'hardware'})
        self.assertEqual(self.session.dispatch('continue', {'timeout': 10})['event'], 'stop')
        self.trace.start()
        pc = self.session.dbg.pc()
        self.assertEqual(self.session.dispatch('step_in', {'timeout': 10})['event'], 'stop')
        row = self.trace.query()['rows'][0]
        self.assertEqual(row['outcome'], 'stepped', row)
        self.assertEqual(row['pc'], hex(pc))
        self.assertEqual(row['changes']['x0']['after'], '0x1122334455667788')
        self.assertEqual(row['memory'][0]['before'], '8877665544332211')
        self.assertTrue(row['memory'][0]['complete_before'])
        self.assertIn('v0', row['registers'])
        self.trace.stop()
        saved = InstructionTrace(self.session.dbg)
        saved.open(self.trace.path)
        self.assertEqual(saved.read(1), row)
        before_pc = self.session.dbg.pc()
        report = saved.export()
        with open(report['path']) as stream:
            content = stream.read()
        self.assertIn('UNTRUSTED DATA', content)
        self.assertIn('1122334455667788', content)
        self.assertEqual(self.session.dbg.pc(), before_pc)
        self.assertEqual(os.stat(self.trace.path).st_mode & 0o777, 0o600)

    def test_automatic_trace_is_bounded_and_continue_creates_a_gap(self):
        result = self.session.dispatch('instruction_trace_run', {'count': 4, 'seconds': 10})
        self.assertTrue(result['ok'], result)
        instructions = [r for r in self.trace.query()['rows'] if r['type'] == 'instruction']
        self.assertEqual(len(instructions), 4, instructions)
        self.assertFalse(self.trace.run)
        self.ws.command('breakpoint_save', {'expression': 'ui_marker', 'kind': 'hardware'})
        self.session.dispatch('continue', {'timeout': 10})
        self.assertTrue(any(r.get('category') == 'GAP' for r in self.trace.query()['rows']))

    def test_record_limit_and_stop_address_do_not_run_to_exit(self):
        self.trace.start(max_records=2)
        result = self.session.dispatch('instruction_trace_run', {'count': 100, 'seconds': 10})
        self.assertEqual(result['event'], 'stop', result)
        self.assertFalse(self.trace.enabled)
        self.assertIn('limit', self.trace.error)
        self.assertLessEqual(len(self.trace.offsets), 2)

    def test_recorded_store_search_and_automatic_trace_stop_address(self):
        self.trace.start()
        destination=self.ws.address('ui_load')
        result=self.session.dispatch('instruction_trace_run',{'count':100,'seconds':10,'until':hex(destination)})
        self.assertEqual(result['event'],'stop',result)
        self.assertEqual(self.session.dbg.pc(),destination)
        rows=self.trace.query()['rows']
        stores=[r for r in rows if r.get('outcome')=='stepped' and any(m['access']=='write' for m in r.get('memory',[]))]
        self.assertTrue(stores)
        last=stores[-1];access=next(m for m in last['memory'] if m['access']=='write')
        found=self.trace.query(address=access['address'],access='write',before=len(rows)+1,limit=1)
        self.assertEqual(found['rows'][0]['n'],last['n'])
        self.assertNotEqual(access['before'],access['after'])

    def test_cancel_via_concurrent_poll_and_restart_keep_history_separate(self):
        calls=[]
        def cancel():
            calls.append(1)
            if len(calls)==3:self.session.dispatch('interrupt',{})
        result=self.session.dispatch('instruction_trace_run',{'count':100000,'seconds':10},poll_cb=cancel)
        self.assertEqual(result['event'],'stop',result)
        self.assertFalse(self.trace.run)
        self.assertLess(len(self.trace.offsets),10)
        path=self.trace.path
        self.assertTrue(self.session.dispatch('restart',{})['ok'])
        self.assertFalse(self.trace.enabled)
        self.assertEqual(self.trace.path,path)
        self.trace.open(path)
        self.assertTrue(self.trace.readonly)

    def test_user_breakpoint_interrupt_is_not_reported_as_verified_step(self):
        self.ws.command('breakpoint_save',{'expression':'ui_load','kind':'hardware'})
        result=self.session.dispatch('instruction_trace_run',{'count':1000,'seconds':10})
        self.assertEqual(result['event'],'stop',result)
        self.assertEqual(result['stop']['reason'],'breakpoint')
        row=next(r for r in reversed(self.trace.query()['rows']) if r['type']=='instruction')
        self.assertEqual(row['outcome'],'interrupted',row)

    def test_bad_import_and_disk_failure_preserve_an_inspectable_history(self):
        from pathlib import Path
        self.trace.start()
        self.session.dispatch('step_in',{'timeout':10})
        self.trace.stop()
        original_path=self.trace.path
        bad=Path(original_path).with_name('bad-trace.jsonl')
        self.addCleanup(lambda:bad.unlink(missing_ok=True))
        bad.write_bytes(Path(original_path).read_bytes()[:-2])
        with self.assertRaises(ValueError):self.trace.open(str(bad))
        self.assertEqual(self.trace.path,original_path)
        self.trace.start()
        with patch('macdbg.core.instruction_trace.open',side_effect=OSError('simulated full disk')):
            result=self.session.dispatch('instruction_trace_run',{'count':100,'seconds':10})
        self.assertEqual(result['event'],'stop',result)
        self.assertIn('full disk',self.trace.error)
        self.assertFalse(self.trace.enabled)
