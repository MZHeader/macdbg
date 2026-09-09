import sys
import types
import unittest
from unittest import mock

from macdbg.core.anti_analysis import AnalysisCloak, IMAGE_REPLACEMENT


class FakeError:
    def __init__(self):
        self.ok = True

    def Success(self):
        return self.ok


FAKE_LLDB = types.SimpleNamespace(SBError=FakeError)


class FakeRegister:
    def __init__(self, value, set_ok=True):
        self.value = value
        self.set_ok = set_ok

    def GetValueAsUnsigned(self):
        return self.value

    def SetValueFromCString(self, value):
        if self.set_ok:
            self.value = int(value)
        return self.set_ok


class FakeFrame:
    def __init__(self, register):
        self.register = register

    def FindRegister(self, name):
        if name != "x0":
            raise AssertionError("unexpected register {}".format(name))
        return self.register


class FakeThread:
    def __init__(self, frame):
        self.frame = frame

    def GetFrameAtIndex(self, _index):
        return self.frame


class FakeProcess:
    def __init__(self, register, cstrings):
        self.thread = FakeThread(FakeFrame(register))
        self.cstrings = dict(cstrings)
        self.continues = 0

    def GetSelectedThread(self):
        return self.thread

    def ReadCStringFromMemory(self, address, _limit, error):
        error.ok = address in self.cstrings
        return self.cstrings.get(address, "")

    def Continue(self):
        self.continues += 1


class FakeTarget:
    def __init__(self):
        self.deleted = []

    def BreakpointDelete(self, bp_id):
        self.deleted.append(bp_id)
        return True


class FakeDebugger:
    def __init__(self, process, commands=()):
        self.process = process
        self.target = FakeTarget()
        self.commands = list(commands)
        self.seen_commands = []
        self.interpose_enabled = False

    def handle_command(self, command):
        self.seen_commands.append(command)
        if not self.commands:
            raise AssertionError("unexpected command: {}".format(command))
        return self.commands.pop(0)


class ImageReturnSafetyTests(unittest.TestCase):
    def test_blacklisted_result_uses_one_cached_allocation(self):
        register = FakeRegister(0x1000)
        process = FakeProcess(
            register,
            {0x1000: "/tmp/FridaGadget.dylib"},
        )
        debugger = FakeDebugger(process, [
            (True, "$0 = 0x5000\n", ""),
            (True, "", ""),
        ])
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            cloak._return_hooks[9] = ("image",)
            first = cloak.handle_hit(9)
            register.value = 0x1000
            cloak._return_hooks[10] = ("image",)
            second = cloak.handle_hit(10)
            disabled = cloak.disable()

        self.assertEqual(first, "cloaked loaded image FridaGadget.dylib")
        self.assertEqual(second, first)
        self.assertEqual(register.value, 0x5000)
        self.assertEqual(process.continues, 2)
        self.assertEqual(disabled, (True, "analysis cloak disabled"))
        self.assertEqual(
            sum("strdup" in command for command in debugger.seen_commands), 1)
        self.assertEqual(
            sum("free" in command for command in debugger.seen_commands), 1)
        self.assertIn("--ignore-breakpoints true", debugger.seen_commands[0])
        self.assertEqual(cloak._cstring_cache, {})

    def test_clean_result_passes_silently_without_allocation(self):
        register = FakeRegister(0x1000)
        process = FakeProcess(
            register,
            {0x1000: "/usr/lib/libSystem.B.dylib"},
        )
        debugger = FakeDebugger(process)
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._return_hooks[9] = ("image",)

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertEqual(message, "")
        self.assertEqual(register.value, 0x1000)
        self.assertEqual(process.continues, 1)
        self.assertEqual(debugger.seen_commands, [])

    def test_unreadable_result_fails_closed(self):
        register = FakeRegister(0x1000)
        process = FakeProcess(register, {})
        debugger = FakeDebugger(process)
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._return_hooks[9] = ("image",)

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertIn("could not read _dyld_get_image_name result", message)
        self.assertEqual(cloak.validate_resume(), (False, message))
        self.assertEqual(process.continues, 0)

    def test_interposition_is_rejected_in_either_enable_order(self):
        register = FakeRegister(0)
        process = FakeProcess(register, {})
        debugger = FakeDebugger(process)
        debugger.interpose_enabled = True
        cloak = AnalysisCloak(debugger)

        enabled, message = cloak.enable()

        self.assertFalse(enabled)
        self.assertIn("incompatible with fork-tree tracing", message)
        self.assertFalse(cloak.enabled)

        debugger.interpose_enabled = False
        cloak.enabled = True
        debugger.interpose_enabled = True
        ready, message = cloak.validate_resume()
        self.assertFalse(ready)
        self.assertIn("incompatible with fork-tree tracing", message)

    def test_replacement_constant_is_an_innocuous_system_image(self):
        self.assertEqual(IMAGE_REPLACEMENT, "/usr/lib/libSystem.B.dylib")


if __name__ == "__main__":
    unittest.main()
