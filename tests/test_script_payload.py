import unittest
from unittest.mock import Mock, MagicMock

import lldb

from macdbg.core.script_payload import Payload, ScriptPayloadCapture


class PayloadCaptureTests(unittest.TestCase):
    def setUp(self):
        self.memory = {}
        self.values = {'x0': 0, 'x1': 0, 'x2': 0, 'x3': 0, 'lr': 0x7000, 'sp': 0x8000}
        self.frame = Mock()
        def register(name):
            value = Mock()
            value.IsValid.return_value = True
            value.GetValueAsUnsigned.side_effect = lambda: self.values[name]
            return value
        self.frame.FindRegister.side_effect = register
        self.thread = Mock()
        self.thread.GetFrameAtIndex.return_value = self.frame
        self.d = Mock(hardware_bp_ids=set())
        self.d.read_memory.side_effect = lambda addr, size: bytes(self.memory.get(addr, b'')[:size])
        self.capture = ScriptPayloadCapture(self.d)
        self.jobs = []
        self.capture._arm = lambda thread, job: self.jobs.append(dict(job, epoch=self.capture.epoch))

    def descriptor(self, address, handle, kind=0x75746638):
        self.memory[address] = kind.to_bytes(4, 'little') + handle.to_bytes(8, 'little')

    def create(self, address=0x1000, handle=0x5000, data=b'return 42', status=0):
        self.memory[0x4000] = data
        self.values.update(x0=0x75746638, x1=0x4000, x2=len(data), x3=address)
        self.capture._entry(self.thread, 'AECreateDesc')
        self.descriptor(address, handle)
        self.capture._returned(self.jobs.pop(), status)

    def load(self, component=11, script_id=7, descriptor=0x1000, status=0):
        self.values.update(x0=component, x1=descriptor, x2=0, x3=0x3000)
        self.capture._entry(self.thread, 'OSALoad')
        self.memory[0x3000] = script_id.to_bytes(4, 'little')
        self.capture._returned(self.jobs.pop(), status)

    def test_failed_descriptor_and_load_results_do_not_create_associations(self):
        self.create(status=1)
        self.assertIsNone(self.capture._desc_payload(0x1000))
        self.create()
        self.load(status=1)
        self.assertIsNone(self.capture._get(('script', 11, 7)))

    def test_script_ids_are_scoped_to_components_and_survive_descriptor_disposal(self):
        self.create(data=b'return 1')
        self.load(component=11)
        self.create(data=b'return 2')
        self.load(component=22)
        self.values['x0'] = 0x1000
        self.capture._entry(self.thread, 'AEDisposeDesc')
        self.assertEqual(self.capture._get(('script', 11, 7)).data, b'return 1')
        self.assertEqual(self.capture._get(('script', 22, 7)).data, b'return 2')
        self.d.handle_command.assert_not_called()
        self.d.write_memory.assert_not_called()

    def test_disposing_internal_alias_does_not_discard_live_source_owner(self):
        self.create()
        self.descriptor(0x1100, 0x5000)
        self.values['x0'] = 0x1100
        self.capture._entry(self.thread, 'AEDisposeDesc')
        self.assertEqual(self.capture._desc_payload(0x1000).data, b'return 42')

    def test_copied_descriptor_header_is_matched_only_to_a_live_owner(self):
        self.create()
        self.descriptor(0x1100, 0x5000)
        self.assertEqual(self.capture._desc_payload(0x1100).data, b'return 42')
        self.capture._forget_descriptor(0x1000)
        self.assertEqual(self.capture._desc_payload(0x1100).data, b'return 42')
        self.descriptor(0x1100, 0x6000)
        self.descriptor(0x1200, 0x5000)
        self.assertIsNone(self.capture._desc_payload(0x1200))

    def test_missing_input_invalidates_reused_script_id(self):
        self.create()
        self.load()
        self.descriptor(0x2000, 0x9000)
        self.load(descriptor=0x2000)
        self.assertIsNone(self.capture._get(('script', 11, 7)))

    def test_dispose_and_component_close_remove_only_their_script_ids(self):
        self.create()
        self.load(component=11)
        self.load(component=22)
        self.values.update(x0=11, x1=7)
        self.capture._entry(self.thread, 'OSADispose')
        self.assertIsNone(self.capture._get(('script', 11, 7)))
        self.assertIsNotNone(self.capture._get(('script', 22, 7)))
        self.values['x0'] = 22
        self.capture._entry(self.thread, 'CloseComponent')
        self.assertIsNone(self.capture._get(('script', 22, 7)))

    def test_cache_budget_and_epoch_prevent_stale_repopulation(self):
        self.capture.MAX_CACHE = 6
        self.capture._store(('script', 1, 1), Payload(0x75746638, b'AAAA', 'test'))
        self.capture._store(('script', 1, 2), Payload(0x75746638, b'BBBB', 'test'))
        self.assertIsNone(self.capture._get(('script', 1, 1)))
        self.assertEqual(self.capture.cache_bytes, 4)
        job = {'kind': 'script', 'component': 1, 'output': 0x3000,
               'payload': Payload(0x75746638, b'CCCC', 'test'), 'epoch': self.capture.epoch}
        self.memory[0x3000] = (3).to_bytes(4, 'little')
        self.capture._invalidate('missed observation')
        self.capture._returned(job, 0)
        self.assertEqual(self.capture.cache_bytes, 0)

    def test_oversized_input_is_rejected_before_reading_its_buffer(self):
        self.values.update(x0=0x75746638, x1=0x4000, x2=self.capture.MAX_PAYLOAD+1, x3=0x1000)
        with self.assertRaisesRegex(RuntimeError, '4 MiB'):
            self.capture._entry(self.thread, 'AECreateDesc')
        self.d.read_memory.assert_not_called()

    def test_lost_return_observer_invalidates_cache_without_disabling_remaining_capture(self):
        self.create()
        self.capture.entries = {1: 'AECreateDesc'}
        self.capture.returns = {2: {'output': 0x3000}}
        valid, missing = Mock(), Mock()
        missing.IsValid.return_value = False
        self.d.target.FindBreakpointByID.side_effect = lambda bid: valid if bid == 1 else missing
        self.assertTrue(self.capture._valid())
        self.assertEqual(self.capture.returns, {})
        self.assertEqual(self.capture.cache_bytes, 0)
        self.assertIn('lost', self.capture.problem)

    def test_observer_shared_with_user_breakpoint_preserves_user_stop(self):
        process = MagicMock()
        process.GetState.return_value = lldb.eStateStopped
        process.GetProcessID.return_value = 1
        process.GetStopID.return_value = 2
        process.__iter__.side_effect = lambda: iter([self.thread])
        self.d.process = process
        self.thread.GetStopReason.return_value = lldb.eStopReasonBreakpoint
        self.thread.GetStopReasonDataCount.return_value = 4
        self.thread.GetStopReasonDataAtIndex.side_effect = lambda i: 5 if i == 0 else 99
        self.thread.GetThreadID.return_value = 11
        self.frame.IsValid.return_value = True
        self.frame.GetPC.return_value = 0x1000
        location = Mock()
        location.GetLoadAddress.return_value = 0x1000
        bp = MagicMock()
        bp.__iter__.side_effect = lambda: iter([location])
        self.d.target.FindBreakpointByID.return_value = bp
        self.capture.entries = {5: 'AECreateDesc'}
        self.capture._entry = Mock()
        self.assertFalse(self.capture.apply_stop())
        self.assertFalse(self.capture.apply_stop())
        self.capture._entry.assert_called_once()
