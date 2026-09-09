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
    def __init__(self, value, *, set_ok=True):
        self.value = value
        self.set_ok = set_ok
        self.set_values = []

    def GetValueAsUnsigned(self):
        return self.value

    def SetValueFromCString(self, value):
        self.set_values.append(value)
        if self.set_ok:
            self.value = int(value)
        return self.set_ok


class FakeFrame:
    def __init__(self, return_value, *, register_set_ok=True):
        self.registers = {
            "x0": FakeRegister(return_value, set_ok=register_set_ok),
        }

    def FindRegister(self, name):
        return self.registers[name]


class FakeThread:
    def __init__(self, frame):
        self.frame = frame

    def GetFrameAtIndex(self, _index):
        return self.frame


class FakeProcess:
    def __init__(self, memory, return_value, *, capacity,
                 read_limit=None, write_result=None, register_set_ok=True):
        self.base = 0x1000
        self.memory = bytearray(memory)
        self.capacity = capacity
        self.read_limit = read_limit
        self.write_result = write_result
        self.frame = FakeFrame(return_value,
                               register_set_ok=register_set_ok)
        self.thread = FakeThread(self.frame)
        self.reads = []
        self.writes = []
        self.continues = 0

    def GetSelectedThread(self):
        return self.thread

    def ReadMemory(self, addr, size, error):
        self.reads.append((addr, size))
        error.ok = True
        offset = addr - self.base
        if self.read_limit is not None:
            size = min(size, self.read_limit)
        return bytes(self.memory[offset:offset + size])

    def WriteMemory(self, addr, data, error):
        self.writes.append((addr, data))
        written = len(data) if self.write_result is None else self.write_result
        error.ok = written == len(data)
        offset = addr - self.base
        self.memory[offset:offset + written] = data[:written]
        return written

    def Continue(self):
        self.continues += 1


class FakeTarget:
    def __init__(self):
        self.deleted = []

    def BreakpointDelete(self, bp_id):
        self.deleted.append(bp_id)


class FakeCloakDebugger:
    def cont(self):
        self.process.Continue()

    def __init__(self, process):
        self.process = process
        self.target = FakeTarget()


def handle_proc_pidpath_return(process):
    cloak = AnalysisCloak(FakeCloakDebugger(process))
    cloak._return_hooks[9] = ("proc_pidpath", process.base,
                              process.capacity)
    with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
        message = cloak.handle_hit(9)
    return message, cloak


class ProcPidpathReturnSafetyTests(unittest.TestCase):
    def test_failed_call_preserves_prefilled_marker_buffer_and_return_value(self):
        process = FakeProcess(b"lldb\0", 0, capacity=5)

        message, cloak = handle_proc_pidpath_return(process)

        self.assertEqual(message, "")
        self.assertEqual(process.memory, b"lldb\0")
        self.assertEqual(process.writes, [])
        self.assertEqual(process.frame.registers["x0"].set_values, [])
        self.assertEqual(process.continues, 1)
        self.assertEqual(cloak._return_hooks, {})

    def test_short_capacity_preserves_successful_result_without_overflow(self):
        process = FakeProcess(b"lldb\0", 4, capacity=5)

        message, _cloak = handle_proc_pidpath_return(process)

        self.assertEqual(message, "")
        self.assertEqual(process.memory, b"lldb\0")
        self.assertEqual(process.writes, [])
        self.assertEqual(process.frame.registers["x0"].set_values, [])
        self.assertTrue(all(size <= process.capacity
                            for _addr, size in process.reads))

    def test_failed_writes_do_not_report_or_fabricate_a_cloaked_result(self):
        cases = (
            ("memory", {"write_result": 5}),
            ("register", {"register_set_ok": False}),
            ("short-read", {"read_limit": 6}),
        )
        for name, kwargs in cases:
            with self.subTest(name=name):
                original = b"/lldb\0" + b"x" * 16
                process = FakeProcess(original, 5, capacity=len(original),
                                      **kwargs)

                message, _cloak = handle_proc_pidpath_return(process)

                self.assertEqual(message, "")
                self.assertEqual(process.memory, original)
                self.assertEqual(process.frame.registers["x0"].value, 5)


with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
    from macdbg.core.debugger import Debugger


class SysctlProcessNameSafetyTests(unittest.TestCase):
    def test_cloaks_short_blacklisted_names_without_touching_adjacent_fields(self):
        for name in (b"lldb", b"gdb", b"r2", b"hopper", b"cutter", b"ghidra",
                     b"jtool2", b"dtrace"):
            with self.subTest(name=name):
                prefix = b"before\0"
                suffix = b"after\0"
                process = FakeProcess(prefix + name + b"\0" + suffix, 0,
                                      capacity=648)
                debugger = Debugger.__new__(Debugger)
                debugger.process = process

                message = debugger._scrub_debugger_name(process.base, 0)

                replacement = b"launchd"[:len(name)] + b"\0"
                self.assertIn("scrubbed debugger name", message)
                self.assertEqual(process.memory,
                                 prefix + replacement + suffix)
                self.assertEqual(process.writes,
                                 [(process.base + len(prefix), replacement)])


if __name__ == "__main__":
    unittest.main()
