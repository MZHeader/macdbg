import unittest
import types
from unittest.mock import Mock, MagicMock

from macdbg.core.auto_clock import PauseAccounting, AutomaticClock


class PauseAccountingTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.clock = PauseAccounting(lambda: self.now)

    def test_only_stops_are_subtracted(self):
        self.clock.stop((1, 1))
        self.now += 300
        self.assertEqual(self.clock.total(), 300)
        self.clock.resume()
        self.now += 500
        self.assertEqual(self.clock.total(), 300)
        self.clock.stop((1, 2))
        self.now += 200
        self.assertEqual(self.clock.total(), 500)

    def test_observation_time_includes_gui_queue_delay_and_deduplicates(self):
        self.clock.stop((1, 1), observed_ns=900)
        self.now += 100
        self.clock.stop((1, 1), observed_ns=1050)
        self.assertEqual(self.clock.total(), 200)

    def test_failed_resume_stays_one_continuous_pause(self):
        self.clock.stop((1, 1))
        self.now += 100
        token = self.clock.resume()
        self.now += 50
        self.clock.rollback(token)
        self.assertEqual(self.clock.total(), 150)
        self.clock.resume()
        self.now += 300
        self.assertEqual(self.clock.total(), 150)

    def test_stale_timestamp_cannot_subtract_before_resume(self):
        self.clock.stop((1, 1))
        self.clock.resume()
        self.now += 50
        self.clock.stop((1, 2), observed_ns=900)
        self.assertEqual(self.clock.total(), 50)
        self.clock.reset()
        self.assertEqual(self.clock.total(), 0)


class ClockCallerScopeTests(unittest.TestCase):
    def test_failed_import_restore_keeps_execution_blocked_until_cleanup_succeeds(self):
        clock = AutomaticClock(Mock())
        clock.bindings = Mock()
        clock.bindings.restore.side_effect = RuntimeError('cannot restore clock import')
        with self.assertRaisesRegex(RuntimeError, 'cannot restore'):
            clock.disable()
        self.assertTrue(clock.enabled)
        self.assertEqual(clock.validate(), (False, 'cannot restore clock import'))
        clock.bindings.restore.side_effect = None
        self.assertTrue(clock.disable()[0])
        self.assertFalse(clock.enabled)
        self.assertIsNone(clock.last_error)

    def clock(self, caller):
        frame = Mock()
        frame.GetPC.return_value = 0x8000
        frame.SetPC.side_effect = lambda value: setattr(frame.GetPC, 'return_value', value) or True
        thread = Mock()
        thread.GetFrameAtIndex.return_value = frame
        clock = AutomaticClock(Mock())
        clock._text_range = (0x1000, 0x2000)
        clock.reader = types.SimpleNamespace(lib=types.SimpleNamespace(mach_absolute_time=lambda: 10000),
                                            numer=1, denom=1)
        clock._read = lambda _frame, name: caller if name == 'x30' else 0
        clock._write = Mock()
        clock._adjust = Mock(return_value=7000)
        return clock, thread, frame

    def test_escaped_forwarder_preserves_real_api_execution(self):
        clock, thread, frame = self.clock(0x3000)
        clock._handle(thread, 'mach_absolute_time', None)
        clock._adjust.assert_not_called()
        clock._write.assert_not_called()
        self.assertEqual(frame.GetPC(), 0x8000)
        self.assertEqual(clock.hits, {})
        self.assertEqual(clock.passthrough, 1)

    def test_main_clock_returns_compensated_time(self):
        clock, thread, frame = self.clock(0x1100)
        clock._handle(thread, 'mach_absolute_time', None)
        clock._adjust.assert_called_once_with(10000, 'mach_absolute_time', 1, 1)
        clock._write.assert_called_once_with(thread, 'x0', 7000)
        self.assertEqual(frame.GetPC(), 0x1100)
        self.assertEqual(clock.hits, {'mach_absolute_time': 1})
        self.assertEqual(clock.passthrough, 0)

    def test_incidental_thread_at_clock_entry_is_intercepted(self):
        self.check_incidental_stop(False)

    def test_incidental_clock_does_not_swallow_another_threads_user_stop(self):
        self.check_incidental_stop(True)

    def check_incidental_stop(self, user_stop):
        api = AutomaticClock.apply_stop.__globals__['lldb']
        clock, thread, frame = self.clock(0x1100)
        thread.GetStopReason.return_value = api.eStopReasonNone
        thread.GetThreadID.return_value = 12
        frame.IsValid.return_value = True
        threads = [thread]
        if user_stop:
            other = Mock()
            other.GetStopReason.return_value = api.eStopReasonBreakpoint
            other.GetStopReasonDataCount.return_value = 2
            other.GetStopReasonDataAtIndex.side_effect = [42]
            other.GetFrameAtIndex.return_value.GetPC.return_value = 0x5000
            threads.append(other)
        process = MagicMock()
        process.GetState.return_value = api.eStateStopped
        process.GetProcessID.return_value = 1
        process.GetStopID.return_value = 8
        process.__iter__.return_value = iter(threads)
        clock.debugger.process = process
        clock.enabled = True
        clock.observe_stop = Mock()
        clock.require_ready = Mock()
        clock._hooks = {9: (0x8000, 'mach_absolute_time', None, None)}
        self.assertEqual(clock.apply_stop(), not user_stop)
        clock._write.assert_called_once_with(thread, 'x0', 7000)
        self.assertEqual(frame.GetPC(), 0x1100)


if __name__ == "__main__":
    unittest.main()
