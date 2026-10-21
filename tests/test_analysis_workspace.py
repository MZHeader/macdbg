import types
import unittest
import tempfile
from unittest import mock

import lldb

from macdbg.core.analysis_memory import MemoryAnalysis
from macdbg.core.anti_analysis import AnalysisCloak, DEFAULT_IDENTITY_PROFILE
from macdbg.core.return_hooks import ReturnHooks


class WorkspaceTests(unittest.TestCase):
    def test_code_captures_from_separate_sessions_do_not_overwrite_each_other(self):
        with tempfile.TemporaryDirectory(prefix='md-memory-unit-',dir='/private/tmp') as directory:
            paths = []
            for _ in range(2):
                d = types.SimpleNamespace(read_memory=lambda address,size:b'a'*size,
                    _dumps_dir=lambda:directory,record_event=mock.Mock(),
                    process=types.SimpleNamespace(GetState=lambda:lldb.eStateStopped))
                memory = MemoryAnalysis(d)
                memory.regions = lambda:[{'base':0x1000,'end':0x1010,'size':16,'protection':5,'name':''}]
                memory.observe()
                paths.append(d.record_event.call_args.kwargs['path'])
            self.assertNotEqual(*paths)

    def test_short_executable_reads_are_not_reported_as_code_changes(self):
        with tempfile.TemporaryDirectory(prefix='md-memory-unit-',dir='/private/tmp') as directory:
            d = types.SimpleNamespace(read_memory=lambda address,size:b'a'*size,
                _dumps_dir=lambda:directory,record_event=mock.Mock())
            memory = MemoryAnalysis(d)
            memory.regions = lambda:[{'base':0x1000,'end':0x1010,'size':16,'protection':5,'name':''}]
            memory.observe(baseline=True)
            d.read_memory = lambda address,size:b'a'*4
            memory.observe()
            d.record_event.assert_not_called()
            d.read_memory = lambda address,size:b'b'*size
            d.process = types.SimpleNamespace(GetState=lambda:lldb.eStateStopped)
            memory.observe()
            self.assertEqual(d.record_event.call_args.args[:2],('MEMORY','executable memory changed'))

    def test_identity_profiles_preserve_real_identifiers_and_share_custom_uuid(self):
        cloak = AnalysisCloak(types.SimpleNamespace(state=None))
        cloak.configure_identity({'mode':'preserve'})
        self.assertNotIn('hw.model',cloak.sysctl_spoofs)
        self.assertNotIn('kern.hostuuid',cloak.sysctl_spoofs)
        self.assertEqual(cloak.iokit_spoofs,{})
        uuid = '11223344-5566-7788-99aa-bbccddeeff00'
        cloak.configure_identity({'mode':'spoof','uuid':uuid,'serial':'TEST-ONLY'})
        self.assertEqual(cloak.sysctl_spoofs['kern.hostuuid'].value,uuid.upper())
        self.assertEqual(cloak.iokit_spoofs['IOPlatformUUID'],uuid.upper())
        self.assertEqual(DEFAULT_IDENTITY_PROFILE['serial'],'C02ZQ0ABC123')
        before = dict(cloak.identity_profile)
        with self.assertRaises(ValueError):
            cloak.configure_identity({'uuid':'invalid'})
        self.assertEqual(cloak.identity_profile,before)
        cloak.enabled = True
        with self.assertRaisesRegex(ValueError,'disable'):
            cloak.configure_identity({'mode':'preserve'})

    def test_snapshot_diff_is_bounded_and_reports_short_current_memory(self):
        data = bytearray(b'encoded content\0')
        d = types.SimpleNamespace(process=types.SimpleNamespace(GetState=lambda:lldb.eStateStopped),
                                  read_memory=lambda address,size:bytes(data[:size]))
        memory = MemoryAnalysis(d)
        snapshot = memory.capture(0x1000,len(data),'before')
        data[:] = b'decoded content\0'
        result = memory.compare(snapshot['id'])
        self.assertTrue(result['complete'])
        self.assertGreater(result['changed_bytes'],0)
        self.assertEqual(result['strings_added'][0]['text'],'decoded content')
        del data[3:]
        self.assertFalse(memory.compare(snapshot['id'])['complete'])
        with self.assertRaises(ValueError):
            memory.capture(0x1000,1024*1024+1)
        for _ in range(9):
            memory.capture(0x1000,3)
        self.assertEqual(len(memory.snapshots),8)
        with self.assertRaisesRegex(ValueError,'expired'):
            memory.compare(snapshot['id'])

    def test_shared_return_site_is_owned_by_thread_and_stack(self):
        debugger = mock.Mock()
        debugger.create_hardware_breakpoint_by_address.side_effect = [
            mock.Mock(GetID=lambda:7),mock.Mock(GetID=lambda:8)]
        hooks = ReturnHooks(debugger)
        def thread(tid,sp):
            t = mock.Mock(GetThreadID=lambda:tid,GetStopReason=lambda:lldb.eStopReasonBreakpoint)
            f = mock.Mock(GetThread=lambda:t,GetPC=lambda:0x2000)
            f.FindRegister.side_effect = lambda name:mock.Mock(GetValueAsUnsigned=lambda:sp if name=='sp' else 0x2000)
            t.GetFrameAtIndex.return_value = f
            return t
        first,second = thread(101,0x8000),thread(102,0x8000)
        hooks.arm(first.GetFrameAtIndex(0),{'call':'first'})
        hooks.arm(second.GetFrameAtIndex(0),{'call':'second'})
        with mock.patch('macdbg.core.breakpoints.remember_hardware_return'):
            self.assertEqual(hooks.consume(thread(102,0x7000)),[])
            self.assertEqual(hooks.consume(second)[0]['payload']['call'],'second')
            self.assertEqual(hooks.ids(),{7})
            self.assertEqual(hooks.consume(first)[0]['payload']['call'],'first')
            self.assertEqual(hooks.ids(),set())
