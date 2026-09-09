import sys
import types
import unittest
from unittest import mock

from macdbg.core.anti_analysis import AnalysisCloak


class FakeError:
    def __init__(self):
        self.ok = True

    def Success(self):
        return self.ok


FAKE_LLDB = types.SimpleNamespace(SBError=FakeError)


class FakeRegister:
    def __init__(self, value):
        self.value = value

    def GetValueAsUnsigned(self):
        return self.value


class FakeFrame:
    def __init__(self, **registers):
        self.registers = {
            name: FakeRegister(value) for name, value in registers.items()
        }

    def FindRegister(self, name):
        return self.registers[name]

    def IsValid(self):
        return True


class FakeThread:
    def __init__(self, frame):
        self.frame = frame

    def GetFrameAtIndex(self, _index):
        return self.frame

    def IsValid(self):
        return True


class FakeProcess:
    def __init__(self, frame, cstrings=None):
        self.thread = FakeThread(frame)
        self.cstrings = dict(cstrings or {})
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


class ScriptedDebugger:
    def __init__(self, process, script):
        self.process = process
        self.target = FakeTarget()
        self.script = list(script)
        self.commands = []

    def handle_command(self, command):
        self.commands.append(command)
        if not self.script:
            raise AssertionError("unexpected command: {}".format(command))
        expected, response = self.script.pop(0)
        if expected not in command:
            raise AssertionError(
                "expected {!r} in {!r}".format(expected, command))
        return response


class IOKitCFStringTests(unittest.TestCase):
    def test_cfstring_text_falls_back_to_temporary_target_buffer(self):
        process = FakeProcess(
            FakeFrame(x1=0x1111),
            cstrings={0x3000: "IOPlatformUUID"},
        )
        debugger = ScriptedDebugger(process, [
            ("CFStringGetCStringPtr", (True, "$0 = 0x0\n", "")),
            ("malloc(256)", (True, "$1 = 0x3000\n", "")),
            ("CFStringGetCString", (True, "$2 = 1\n", "")),
            ("free", (True, "", "")),
        ])
        cloak = AnalysisCloak(debugger)

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            text = cloak._cfstring_text(0x1111)

        self.assertEqual(text, "IOPlatformUUID")
        self.assertFalse(debugger.script)
        self.assertTrue(all("--ignore-breakpoints true" in command
                            for command in debugger.commands))

    def test_exact_property_is_cached_and_each_create_result_is_retained(self):
        process = FakeProcess(
            FakeFrame(x1=0x1111),
            cstrings={0x2000: "IOPlatformSerialNumber"},
        )
        debugger = ScriptedDebugger(process, [
            ("CFStringGetCStringPtr", (True, "$0 = 0x2000\n", "")),
            ("CFStringCreateWithCString", (True, "$1 = 0x5000\n", "")),
            ("CFRetain", (True, "$2 = 0x5000\n", "")),
            ("thread return 0x5000", (True, "", "")),
            ("CFStringGetCStringPtr", (True, "$3 = 0x2000\n", "")),
            ("CFRetain", (True, "$4 = 0x5000\n", "")),
            ("thread return 0x5000", (True, "", "")),
            ("CFRelease", (True, "", "")),
        ])
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "IORegistryEntryCreateCFProperty"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            first = cloak.handle_hit(5)
            second = cloak.handle_hit(5)
            disabled = cloak.disable()

        self.assertEqual(
            first,
            "spoofed IORegistryEntryCreateCFProperty("
            "IOPlatformSerialNumber)",
        )
        self.assertEqual(second, first)
        self.assertEqual(disabled, (True, "analysis cloak disabled"))
        creates = [c for c in debugger.commands
                   if "CFStringCreateWithCString" in c]
        retains = [c for c in debugger.commands if "CFRetain" in c]
        releases = [c for c in debugger.commands if "CFRelease" in c]
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(retains), 2)
        self.assertEqual(len(releases), 1)
        self.assertEqual(process.continues, 2)
        self.assertEqual(cloak._cfstring_cache, {})

    def test_similar_property_name_passes_through_unchanged(self):
        process = FakeProcess(
            FakeFrame(x1=0x1111),
            cstrings={0x2000: "IOPlatformSerialNumberExtra"},
        )
        debugger = ScriptedDebugger(process, [
            ("CFStringGetCStringPtr", (True, "$0 = 0x2000\n", "")),
        ])
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "IORegistryEntryCreateCFProperty"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertEqual(message, "")
        self.assertEqual(process.continues, 1)
        self.assertIsNone(cloak.last_error)
        self.assertFalse(debugger.script)

    def test_unreadable_property_key_fails_closed(self):
        process = FakeProcess(FakeFrame(x1=0x1111))
        debugger = ScriptedDebugger(process, [
            ("CFStringGetCStringPtr", (False, "", "synthetic error")),
        ])
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "IORegistryEntryCreateCFProperty"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertIn("could not read IOKit property key", message)
        self.assertEqual(cloak.validate_resume(), (False, message))
        self.assertEqual(process.continues, 0)


if __name__ == "__main__":
    unittest.main()
