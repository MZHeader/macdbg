import unittest
from unittest.mock import Mock

from macdbg.core.tracer import Tracer


class CallerFilterTests(unittest.TestCase):
    def test_unwind_failure_is_not_classified_as_system_noise(self):
        tracer = Tracer()
        tracer._exec_name = 'go_fixture'
        frame = Mock()
        thread = frame.GetThread.return_value
        thread.GetNumFrames.return_value = 1
        self.assertFalse(tracer._caller_is_noise(frame))
        thread.GetNumFrames.return_value = 2
        thread.GetFrameAtIndex.return_value.IsValid.return_value = False
        self.assertFalse(tracer._caller_is_noise(frame))

    def test_known_system_only_caller_is_still_filtered(self):
        tracer = Tracer()
        tracer._exec_name = 'fixture'
        frame = Mock()
        thread = frame.GetThread.return_value
        thread.GetNumFrames.return_value = 2
        module = thread.GetFrameAtIndex.return_value.GetModule.return_value
        module.GetFileSpec.return_value.GetFilename.return_value = 'libsystem_c.dylib'
        self.assertTrue(tracer._caller_is_noise(frame))
        module.GetFileSpec.return_value.GetFilename.return_value = 'fixture'
        self.assertFalse(tracer._caller_is_noise(frame))
