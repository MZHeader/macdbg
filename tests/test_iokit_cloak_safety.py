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
    def cont(self):
        self.process.Continue()

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


class HookBreakpoint:
    def __init__(self, bp_id, locations=1, valid=True):
        self.bp_id = bp_id
        self.locations = locations
        self.valid = valid

    def GetID(self):
        return self.bp_id

    def GetNumLocations(self):
        return self.locations

    def GetLocationAtIndex(self, index):
        assert 0 <= index < self.locations
        return types.SimpleNamespace(IsResolved=lambda: True)

    def IsValid(self):
        return self.valid


class FakeFileSpec:
    def __init__(self, name):
        self.name = name

    def GetFilename(self):
        return self.name


class FakeModule:
    def __init__(self, name):
        self.name = name

    def GetFileSpec(self):
        return FakeFileSpec(self.name)


class HookTarget:
    def __init__(self, locations=None, modules=()):
        self.locations = dict(locations or {})
        self.modules = [FakeModule(name) for name in modules]
        self.breakpoints = []
        self.next_id = 100

    def add_breakpoint(self, locations=1):
        bp = HookBreakpoint(self.next_id, locations)
        self.next_id += 1
        self.breakpoints.append(bp)
        return bp

    def BreakpointCreateByName(self, symbol):
        return self.add_breakpoint(self.locations.get(symbol, 1))

    def BreakpointDelete(self, bp_id):
        self.breakpoints = [bp for bp in self.breakpoints
                            if bp.GetID() != bp_id]
        return True

    def GetNumBreakpoints(self):
        return len(self.breakpoints)

    def GetBreakpointAtIndex(self, index):
        return self.breakpoints[index]

    def FindBreakpointByID(self, bp_id):
        for bp in self.breakpoints:
            if bp.GetID() == bp_id:
                return bp
        return HookBreakpoint(bp_id, valid=False)

    def GetNumModules(self):
        return len(self.modules)

    def GetModuleAtIndex(self, index):
        return self.modules[index]


class DeferredDebugger:
    def __init__(self, locations=None, modules=()):
        self.target = HookTarget(locations, modules)
        self.process = FakeProcess(FakeFrame())
        self._scrub_ptraced = False
        self._scrub_parent = False

    def is_stopped_at_entry_point(self):
        return True

    def _enable(self, name):
        bp = self.target.add_breakpoint()
        if name == "anti_sysctl":
            self._scrub_ptraced = True
        elif name == "anti_parent":
            self._scrub_parent = True
        return True, "enabled"

    def _disable(self, name):
        if name == "anti_sysctl":
            self._scrub_ptraced = False
        elif name == "anti_parent":
            self._scrub_parent = False
        return True, "disabled"

    def enable_anti_sysctl(self):
        return self._enable("anti_sysctl")

    def disable_anti_sysctl(self):
        return self._disable("anti_sysctl")

    def enable_anti_parent(self):
        return self._enable("anti_parent")

    def disable_anti_parent(self):
        return self._disable("anti_parent")

    def handle_command(self, _command):
        return True, "", ""


class IOKitCFStringTests(unittest.TestCase):
    def test_cfstring_text_direct_pointer_does_not_need_debug_typedefs(self):
        process = FakeProcess(
            FakeFrame(x1=0x1111),
            cstrings={0x2000: "IOPlatformSerialNumber"},
        )
        debugger = ScriptedDebugger(process, [
            ("CFStringGetCStringPtr", (True, "$0 = 0x2000\n", "")),
        ])
        cloak = AnalysisCloak(debugger)

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            text = cloak._cfstring_text(0x1111)

        self.assertEqual(text, "IOPlatformSerialNumber")
        self.assertNotIn("CFStringRef", debugger.commands[0])

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
        self.assertNotIn("CFStringRef", "\n".join(debugger.commands))

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


class IOKitDeferredHookTests(unittest.TestCase):
    def test_absent_iokit_hook_is_retained_deferred_then_resolves(self):
        debugger = DeferredDebugger(locations={
            "IORegistryEntryCreateCFProperty": 0,
        }, modules=("late_iokit_fixture", "libSystem.B.dylib"))
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertTrue(ok, message)
        self.assertIn("1 deferred", message)
        self.assertEqual(cloak.status()["resolved"], 3)
        self.assertEqual(cloak.status()["deferred"], 1)
        iokit_id = next(bp_id for bp_id, name in cloak._entry_hooks.items()
                        if name == "IORegistryEntryCreateCFProperty")
        self.assertIn(iokit_id, cloak.hidden_bp_ids())

        debugger.target.FindBreakpointByID(iokit_id).locations = 1
        self.assertEqual(cloak.status()["resolved"], 4)
        self.assertEqual(cloak.status()["deferred"], 0)

        self.assertTrue(cloak.disable()[0])
        self.assertNotIn(iokit_id, {
            bp.GetID() for bp in debugger.target.breakpoints
        })
        self.assertEqual(cloak.status()["resolved"], 0)
        self.assertEqual(cloak.status()["deferred"], 0)

    def test_required_hook_with_no_location_still_fails_closed(self):
        debugger = DeferredDebugger(locations={"proc_pidpath": 0})
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertFalse(ok)
        self.assertIn("proc_pidpath", message)
        self.assertFalse(cloak.enabled)

    def test_loaded_iokit_with_no_location_still_fails_closed(self):
        debugger = DeferredDebugger(
            locations={"IORegistryEntryCreateCFProperty": 0},
            modules=("IOKit",),
        )
        cloak = AnalysisCloak(debugger)

        ok, message = cloak.enable()

        self.assertFalse(ok)
        self.assertIn("IORegistryEntryCreateCFProperty", message)
        self.assertFalse(cloak.enabled)


if __name__ == "__main__":
    unittest.main()
