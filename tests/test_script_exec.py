import types
import unittest
from unittest.mock import MagicMock, Mock

import lldb

from macdbg.core.script_exec import ScriptExec


class ScriptExecSafetyTests(unittest.TestCase):
    def gate(self, name='OSAExecute'):
        values = {'x0': 0x8888, 'x1': 7, 'x2': 0, 'x3': 0,
                  'x4': 0x3000, 'x5': 0x3000, 'lr': 0x2000, 'sp': 0x4000}
        pc = [0x1000]
        def register(key):
            r = Mock()
            r.IsValid.return_value = True
            r.GetValueAsUnsigned.side_effect = lambda: values[key]
            r.SetValueFromCString.side_effect = lambda text: values.__setitem__(key, int(text, 0)) or True
            return r
        frame = Mock()
        frame.IsValid.return_value = True
        frame.FindRegister.side_effect = register
        frame.GetPC.side_effect = lambda: pc[0]
        frame.SetPC.side_effect = lambda value: pc.__setitem__(0, value) or True
        thread = Mock()
        thread.IsValid.return_value = True
        thread.GetThreadID.return_value = 11
        thread.GetFrameAtIndex.return_value = frame
        thread.GetStopReason.return_value = lldb.eStopReasonBreakpoint
        process = MagicMock()
        process.GetSelectedThread.return_value = thread
        process.GetThreadByID.return_value = thread
        process.GetProcessID.return_value = 1
        process.GetStopID.return_value = 2
        process.GetState.return_value = lldb.eStateStopped
        process.__iter__.side_effect = lambda: iter([thread])
        bp = MagicMock()
        location = Mock()
        location.GetLoadAddress.return_value = 0x1000
        bp.__iter__.side_effect = lambda: iter([location])
        target = Mock()
        target.FindBreakpointByID.return_value = bp
        memory = {0x2000: bytearray.fromhex('1f2003d5'), 0x3000: bytearray(b'X' * 24)}
        d = Mock(process=process, target=target, exec_bp_ids={8: name})
        d.read_memory.side_effect = lambda addr, size: bytes(memory.get(addr, b'')[:size])
        def write(addr, data, **kwargs):
            memory[addr][:len(data)] = data
            return True, ''
        d.write_memory.side_effect = write
        gate = ScriptExec(d)
        gate.capture(8)
        return gate, d, values, pc, memory

    def test_block_preserves_output_and_stack_and_returns_cancellation(self):
        gate, d, values, pc, memory = self.gate()
        gate.resolve('block')
        self.assertEqual(values['x0'], (1 << 64) - 128)
        self.assertEqual(values['sp'], 0x4000)
        self.assertEqual(pc[0], 0x2000)
        self.assertEqual(memory[0x3000], b'X' * 24)
        d.handle_command.assert_not_called()

    def test_fake_writes_only_the_declared_output(self):
        for name, data in [('OSAExecute', bytes(4)),
                           ('OSADoEvent', (0x6e756c6c).to_bytes(4, 'little') + bytes(8))]:
            gate, d, values, pc, memory = self.gate(name)
            gate.resolve('fake')
            self.assertEqual(memory[0x3000], data + b'X' * (24-len(data)))
            self.assertEqual(values['x0'], 0)
            self.assertEqual(values['sp'], 0x4000)
            self.assertEqual(pc[0], 0x2000)
            d.handle_command.assert_not_called()

    def test_changed_context_refuses_decision_without_writes(self):
        gate, d, _, pc, _ = self.gate()
        d.process.GetStopID.return_value = 3
        with self.assertRaisesRegex(RuntimeError, 'context changed'):
            gate.resolve('allow')
        self.assertEqual(pc[0], 0x1000)
        d.write_memory.assert_not_called()

    def test_unreadable_output_keeps_pending_decision_and_target_stopped(self):
        gate, d, values, pc, memory = self.gate()
        del memory[0x3000]
        with self.assertRaisesRegex(RuntimeError, 'cannot preserve'):
            gate.resolve('fake')
        self.assertIsNotNone(gate.pending)
        self.assertEqual(pc[0], 0x1000)
        self.assertEqual(values['x0'], 0x8888)
        d.write_memory.assert_not_called()

    def test_failed_write_rolls_back_and_blocks_resume(self):
        gate, d, _, pc, _ = self.gate()
        d.write_memory.side_effect = [(False, 'partial write'), (True, '')]
        with self.assertRaisesRegex(RuntimeError, 'cannot write'):
            gate.resolve('fake')
        d.write_memory.assert_called_with(0x3000, b'XXXX', track=False)
        self.assertEqual(pc[0], 0x1000)
        with self.assertRaisesRegex(RuntimeError, 'cannot write'):
            gate.require_ready()

    def test_allow_is_scoped_to_this_stop_and_thread(self):
        gate, d, _, pc, _ = self.gate()
        gate.resolve('allow')
        self.assertIsNone(gate.find_hit())
        self.assertEqual(pc[0], 0x1000)
        d.process.GetStopID.return_value = 3
        self.assertEqual(gate.find_hit(), 8)

    def test_simultaneous_entries_require_separate_thread_decisions(self):
        gate, d, _, _, _ = self.gate()
        first = d.process.GetSelectedThread()
        second = Mock()
        second.GetThreadID.return_value = 22
        second.GetStopReason.return_value = lldb.eStopReasonNone
        second.GetFrameAtIndex.return_value = first.GetFrameAtIndex(0)
        d.process.__iter__.side_effect = lambda: iter([first, second])
        d.process.GetThreadByID.side_effect = lambda tid: first if tid == 11 else second
        d.process.SetSelectedThread.side_effect = lambda thread: setattr(d.process.GetSelectedThread, 'return_value', thread)
        gate.resolve('allow')
        self.assertEqual(gate.find_hit(), 8)
        gate.capture(8)
        self.assertEqual(gate.pending['key'][2], 22)
        gate.resolve('allow')
        self.assertIsNone(gate.find_hit())

    def test_pending_decision_blocks_execution_and_reset_discards_it(self):
        gate, _, _, _, _ = self.gate()
        with self.assertRaisesRegex(RuntimeError, 'decision'):
            gate.require_ready()
        gate.reset()
        self.assertIsNone(gate.pending)
        self.assertEqual(gate.allowed, set())
