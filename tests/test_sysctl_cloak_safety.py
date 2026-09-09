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
    def __init__(self, registers):
        self.registers = {
            name: FakeRegister(value) for name, value in registers.items()
        }

    def FindRegister(self, name):
        return self.registers[name]

    def IsValid(self):
        return True


class FakeThread:
    def __init__(self, frame, thread_id=0x1234):
        self.frame = frame
        self.thread_id = thread_id

    def GetFrameAtIndex(self, _index):
        return self.frame

    def GetThreadID(self):
        return self.thread_id

    def IsValid(self):
        return True


class FakeBreakpoint:
    def __init__(self, bp_id, *, valid=True, locations=1):
        self.bp_id = bp_id
        self.valid = valid
        self.locations = locations
        self.one_shot = False
        self.thread_id = None

    def GetID(self):
        return self.bp_id

    def SetOneShot(self, value):
        self.one_shot = value

    def SetThreadID(self, thread_id):
        self.thread_id = thread_id

    def IsValid(self):
        return self.valid

    def GetNumLocations(self):
        return self.locations


class FakeTarget:
    def __init__(self, *, return_bp_valid=True, return_bp_locations=1):
        self.created = []
        self.deleted = []
        self.return_bp_valid = return_bp_valid
        self.return_bp_locations = return_bp_locations

    def BreakpointCreateByAddress(self, address):
        bp = FakeBreakpoint(
            70 + len(self.created),
            valid=self.return_bp_valid,
            locations=self.return_bp_locations,
        )
        self.created.append((address, bp))
        return bp

    def BreakpointDelete(self, bp_id):
        self.deleted.append(bp_id)
        return True


class FakeProcess:
    def __init__(self, frame, memory=None, cstrings=None, write_results=None):
        self.thread = FakeThread(frame)
        self.memory = dict(memory or {})
        self.cstrings = dict(cstrings or {})
        self.write_results = {
            addr: list(results) for addr, results in (write_results or {}).items()
        }
        self.reads = []
        self.writes = []
        self.continues = 0

    def GetSelectedThread(self):
        return self.thread

    def ReadCStringFromMemory(self, address, _limit, error):
        error.ok = address in self.cstrings
        return self.cstrings.get(address, "")

    def ReadMemory(self, address, size, error):
        self.reads.append((address, size))
        data = self.memory.get(address)
        error.ok = data is not None and len(data) >= size
        return bytes(data[:size]) if data is not None else b""

    def WriteMemory(self, address, data, error):
        results = self.write_results.get(address)
        written = results.pop(0) if results else len(data)
        written = min(written, len(data))
        error.ok = written == len(data)
        self.writes.append((address, bytes(data), written))
        current = self.memory.setdefault(address, bytearray(len(data)))
        current[:written] = data[:written]
        return written

    def Continue(self):
        self.continues += 1


class FakeDebugger:
    def cont(self):
        self.process.Continue()

    def __init__(self, process, **target_kwargs):
        self.process = process
        self.target = FakeTarget(**target_kwargs)

    def create_hardware_breakpoint_by_address(self, address):
        return self.target.BreakpointCreateByAddress(address)


def make_return_cloak(name="hw.model", *, returned=0, capacity=128,
                      buffer=b"Mac16,8\0", write_results=None):
    buffer_address = 0x2000
    size_address = 0x3000
    frame = FakeFrame({"x0": returned})
    memory = {
        buffer_address: bytearray(buffer.ljust(capacity, b"\0")),
        size_address: bytearray((len(buffer)).to_bytes(8, "little")),
    }
    process = FakeProcess(frame, memory=memory, write_results=write_results)
    cloak = AnalysisCloak(FakeDebugger(process))
    cloak.enabled = True
    cloak._return_hooks[9] = (
        "cstring", name, buffer_address, size_address, capacity
    )
    cloak._return_hook_threads[9] = 0x1234
    return cloak, process, buffer_address, size_address


class SysctlEntrySafetyTests(unittest.TestCase):
    def test_recognized_name_captures_capacity_on_thread_owned_one_shot(self):
        name_address = 0x1000
        buffer_address = 0x2000
        size_address = 0x3000
        return_address = 0x4000
        frame = FakeFrame({
            "x0": name_address,
            "x1": buffer_address,
            "x2": size_address,
            "lr": return_address,
        })
        process = FakeProcess(
            frame,
            memory={size_address: bytearray((64).to_bytes(8, "little"))},
            cstrings={name_address: "hw.model"},
        )
        cloak = AnalysisCloak(FakeDebugger(process))
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "sysctlbyname"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertEqual(message, "")
        self.assertEqual(process.reads, [(size_address, 8)])
        self.assertEqual(len(cloak.debugger.target.created), 1)
        address, bp = cloak.debugger.target.created[0]
        self.assertEqual(address, return_address)
        self.assertTrue(bp.one_shot)
        self.assertEqual(bp.thread_id, process.thread.thread_id)
        self.assertEqual(
            cloak._return_hooks[bp.bp_id],
            ("cstring", "hw.model", buffer_address, size_address, 64),
        )
        self.assertEqual(process.continues, 1)

    def test_unknown_name_passes_through_without_return_hook(self):
        name_address = 0x1000
        frame = FakeFrame({
            "x0": name_address, "x1": 0x2000, "x2": 0x3000, "lr": 0x4000,
        })
        process = FakeProcess(frame, cstrings={name_address: "kern.osrelease"})
        cloak = AnalysisCloak(FakeDebugger(process))
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "sysctlbyname"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertEqual(message, "")
        self.assertEqual(cloak._return_hooks, {})
        self.assertEqual(cloak.debugger.target.created, [])
        self.assertEqual(process.continues, 1)

    def test_unreadable_capacity_records_critical_error(self):
        name_address = 0x1000
        frame = FakeFrame({
            "x0": name_address, "x1": 0x2000, "x2": 0x3000, "lr": 0x4000,
        })
        process = FakeProcess(frame, cstrings={name_address: "hw.model"})
        cloak = AnalysisCloak(FakeDebugger(process))
        cloak.enabled = True
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "sysctlbyname"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertIn("could not read input capacity", message)
        self.assertEqual(cloak.last_error, message)
        self.assertEqual(cloak._return_hooks, {})
        self.assertEqual(cloak.validate_resume(), (False, cloak.last_error))
        self.assertEqual(process.continues, 0)

    def test_unresolved_return_breakpoint_records_critical_error(self):
        name_address = 0x1000
        size_address = 0x3000
        frame = FakeFrame({
            "x0": name_address, "x1": 0x2000,
            "x2": size_address, "lr": 0x4000,
        })
        process = FakeProcess(
            frame,
            memory={size_address: bytearray((64).to_bytes(8, "little"))},
            cstrings={name_address: "hw.model"},
        )
        debugger = FakeDebugger(process, return_bp_locations=0)
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._bp_ids.add(5)
        cloak._entry_hooks[5] = "sysctlbyname"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(5)

        self.assertIn("could not arm return hook", message)
        self.assertEqual(cloak.last_error, message)
        self.assertEqual(cloak._return_hooks, {})
        self.assertEqual(debugger.target.deleted, [70])
        self.assertEqual(process.continues, 0)


class SysctlReturnSafetyTests(unittest.TestCase):
    def test_u32_spoof_writes_four_bytes_and_preserves_adjacent_memory(self):
        buffer_address = 0x2000
        size_address = 0x3000
        frame = FakeFrame({"x0": 0})
        process = FakeProcess(frame, memory={
            buffer_address: bytearray(b"\xff" * 8),
            size_address: bytearray((8).to_bytes(8, "little")),
        })
        cloak = AnalysisCloak(FakeDebugger(process))
        cloak.enabled = True
        cloak._return_hooks[9] = (
            "u32", "kern.hv_vmm_present",
            buffer_address, size_address, 8,
        )
        cloak._return_hook_threads[9] = 0x1234

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertEqual(
            bytes(process.memory[buffer_address]),
            b"\0\0\0\0\xff\xff\xff\xff",
        )
        self.assertEqual(
            bytes(process.memory[size_address]),
            (4).to_bytes(8, "little"),
        )
        self.assertEqual(
            message, "spoofed sysctlbyname(kern.hv_vmm_present)"
        )
        self.assertEqual(process.continues, 1)

    def test_failed_real_syscall_preserves_result_and_error_state(self):
        cloak, process, buffer_address, size_address = make_return_cloak(
            returned=(1 << 64) - 1
        )
        before_buffer = bytes(process.memory[buffer_address])
        before_size = bytes(process.memory[size_address])

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertEqual(message, "")
        self.assertEqual(process.writes, [])
        self.assertEqual(bytes(process.memory[buffer_address]), before_buffer)
        self.assertEqual(bytes(process.memory[size_address]), before_size)
        self.assertIsNone(cloak.last_error)
        self.assertEqual(process.continues, 1)

    def test_short_capacity_records_critical_error_without_writing(self):
        cloak, process, _buffer_address, _size_address = make_return_cloak(
            capacity=4, buffer=b"Mac\0"
        )

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        expected = "sysctlbyname(hw.model) buffer too small; cloak failed"
        self.assertEqual(message, expected)
        self.assertEqual(cloak.last_error, expected)
        self.assertEqual(process.writes, [])
        self.assertEqual(cloak.validate_resume(), (False, expected))
        self.assertEqual(process.continues, 0)

    def test_partial_buffer_write_rolls_back_and_records_critical_error(self):
        payload_size = len(b"Mac14,6\0")
        cloak, process, buffer_address, size_address = make_return_cloak(
            write_results={0x2000: [3, payload_size]}
        )
        before_buffer = bytes(process.memory[buffer_address])
        before_size = bytes(process.memory[size_address])

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertIn("could not write result buffer", message)
        self.assertEqual(cloak.last_error, message)
        self.assertEqual(bytes(process.memory[buffer_address]), before_buffer)
        self.assertEqual(bytes(process.memory[size_address]), before_size)
        self.assertEqual(cloak.validate_resume(), (False, message))
        self.assertEqual(process.continues, 0)

    def test_partial_size_write_rolls_back_both_outputs(self):
        payload_size = len(b"Mac14,6\0")
        cloak, process, buffer_address, size_address = make_return_cloak(
            write_results={
                0x2000: [payload_size, payload_size],
                0x3000: [4, 8],
            }
        )
        before_buffer = bytes(process.memory[buffer_address])
        before_size = bytes(process.memory[size_address])

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertIn("could not write result size", message)
        self.assertEqual(cloak.last_error, message)
        self.assertEqual(bytes(process.memory[buffer_address]), before_buffer)
        self.assertEqual(bytes(process.memory[size_address]), before_size)
        self.assertEqual(cloak.validate_resume(), (False, message))
        self.assertEqual(process.continues, 0)

    def test_failed_rollback_is_included_in_critical_error(self):
        cloak, process, buffer_address, _size_address = make_return_cloak(
            buffer=b"HostThing\0",
            write_results={0x2000: [5, 2]},
        )
        original = b"HostThin"

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertIn("rollback failed", message)
        self.assertEqual(cloak.last_error, message)
        self.assertNotEqual(
            bytes(process.memory[buffer_address])[:len(b"Mac14,6\0")],
            original,
        )
        self.assertEqual(process.continues, 0)

    def test_size_rollback_is_attempted_if_buffer_rollback_fails(self):
        payload_size = len(b"Mac14,6\0")
        cloak, process, _buffer_address, size_address = make_return_cloak(
            buffer=b"HostThing\0",
            write_results={
                0x2000: [payload_size, 2],
                0x3000: [4, 8],
            },
        )
        before_size = bytes(process.memory[size_address])

        with mock.patch.dict(sys.modules, {"lldb": FAKE_LLDB}):
            message = cloak.handle_hit(9)

        self.assertIn("rollback failed", message)
        self.assertEqual(bytes(process.memory[size_address]), before_size)
        size_writes = [write for write in process.writes
                       if write[0] == size_address]
        self.assertEqual(len(size_writes), 2)
        self.assertEqual(process.continues, 0)

    def test_relaunch_state_reset_clears_return_hooks_and_critical_error(self):
        cloak, _process, _buffer_address, _size_address = make_return_cloak()
        cloak.last_error = "synthetic critical failure"

        cloak.clear_return_hooks()

        self.assertEqual(cloak._return_hooks, {})
        self.assertIsNone(cloak.last_error)


if __name__ == "__main__":
    unittest.main()
