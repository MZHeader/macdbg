import queue
import tempfile
import time
import unittest
from unittest.mock import patch

from GUI.server.engine import Engine
from macdbg.core import state
from .support import FIXTURE_DIR


class GuiRecordingLifecycleTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='md-record-gui-',dir='/private/tmp')
        self.addCleanup(directory.cleanup)
        override=patch.object(state,'STATE_DIR',directory.name);override.start();self.addCleanup(override.stop)
        self.engine=Engine(str(FIXTURE_DIR/'ui_fixture'),[])
        self.engine.start();self.addCleanup(self.engine.shutdown)
        self.events=self.engine.subscribe()
        self.wait(lambda row:row.get('t')=='state' and row.get('process_state')=='stopped')

    def wait(self,predicate,seconds=10):
        deadline=time.monotonic()+seconds
        seen=[]
        while time.monotonic()<deadline:
            try:row=self.events.get(timeout=.2)
            except queue.Empty:continue
            seen.append({k:row.get(k) for k in ('t','text','process_state','instruction_trace') if k in row})
            if predicate(row):return row
        self.fail('Timed out: '+str(seen[-10:]))

    def test_gui_automatic_trace_stops_at_count_and_keeps_history_after_exit(self):
        self.engine.command('instruction_trace_run',{'count':5,'seconds':5})
        stopped=self.wait(lambda r:r.get('t')=='state' and r.get('instruction_trace',{}).get('total',0)>=5)
        self.assertEqual(stopped['process_state'],'stopped')
        self.assertFalse(stopped['instruction_trace']['automatic'])
        rows=self.engine.command('instruction_trace',{'action':'query'})['result']['rows']
        self.assertEqual(sum(r['type']=='instruction' for r in rows),5)
        self.engine.command('cont',{})
        self.wait(lambda r:r.get('t')=='state' and r.get('process_state')=='exited')
        self.assertTrue(self.engine.command('instruction_trace',{'action':'read','index':1})['ok'])

    def test_time_limit_stops_a_benign_infinite_loop_and_releases_worker(self):
        preview=self.engine.command('workspace',{'action':'assemble_preview','address':'ui_destination','source':'b ui_destination'})['result']
        self.assertTrue(self.engine.command('workspace',{'action':'assemble_apply','token':preview['token']})['ok'])
        self.engine.command('set_pc',{'addr':preview['address']})
        self.engine.command('instruction_trace_run',{'count':100000,'seconds':.2})
        stopped=self.wait(lambda r:r.get('t')=='state' and r.get('instruction_trace',{}).get('total',0)>0 and not r['instruction_trace']['automatic'],seconds=5)
        self.assertEqual(stopped['process_state'],'stopped')
        self.assertTrue(self.engine.command('workspace',{'action':'dump','address':preview['address'],'size':4})['ok'])
