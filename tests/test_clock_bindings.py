import struct
import types
import unittest
from unittest.mock import Mock, patch

from macdbg.core.clock_bindings import ClockBindings, import_slots


class ImportSlotTests(unittest.TestCase):
    def debugger(self, *, pointer_address=0x2000, symbol_index=0,
                 provider='/usr/lib/libSystem.B.dylib', value=0x9000):
        def segment(name, address, fileoff, section=b''):
            return struct.pack('<II16sQQQQIIII', 0x19, 72 + len(section), name,
                               address, 4096, fileoff, 4096, 7, 3, bool(section), 0) + section
        section = struct.pack('<16s16sQQIIIIIIII', b'__got', b'__DATA_CONST',
                              pointer_address, 8, 0x1000, 3, 0, 0, 6, 0, 0, 0)
        library = provider.encode() + b'\0'
        library += bytes((-len(library)) % 8)
        commands = [segment(b'__TEXT', 0x1000, 0),
                    segment(b'__DATA_CONST', 0x2000, 0x1000, section),
                    segment(b'__LINKEDIT', 0x3000, 0x2000),
                    struct.pack('<IIIIII', 2, 24, 0x2000, 1, 0x2020, 32),
                    struct.pack('<20I', 0xb, 80, *([0] * 12), 0x2040, 1, 0, 0, 0, 0),
                    struct.pack('<6I', 0xc, 24 + len(library), 24, 0, 0, 0) + library]
        body = b''.join(commands)
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, len(commands), len(body), 0, 0)
        linkedit = bytearray(4096)
        struct.pack_into('<IBBHQ', linkedit, 0, 1, 1, 0, 0x100, 0)
        name = b'\0_mach_absolute_time\0'
        linkedit[32:32 + len(name)] = name
        struct.pack_into('<I', linkedit, 64, symbol_index)
        memory = {0x1000: header + body, 0x2000: value.to_bytes(8, 'little'), 0x3000: linkedit}
        def read(address, length):
            for start, data in memory.items():
                if start <= address and address + length <= start + len(data):
                    return bytes(data[address - start:address - start + length])
            return b''
        target = Mock()
        target.FindModule.return_value.GetObjectFileHeaderAddress.return_value.GetLoadAddress.return_value = 0x1000
        return types.SimpleNamespace(target=target, read_memory=read)

    def test_system_import_is_located_from_live_metadata(self):
        self.assertEqual(import_slots(self.debugger(), {'mach_absolute_time': 0x9000}),
                         [('mach_absolute_time', 0x2000, (0x9000).to_bytes(8, 'little'))])

    def test_custom_function_with_clock_name_is_not_rebound(self):
        d = self.debugger(provider='/tmp/custom.dylib', value=0xa000)
        self.assertEqual(import_slots(d, {'mach_absolute_time': 0x9000}), [])

    def test_pointer_section_cannot_escape_its_segment(self):
        with self.assertRaisesRegex(RuntimeError, 'escape'):
            import_slots(self.debugger(pointer_address=0x4000), {'mach_absolute_time': 0x9000})

    def test_symbol_index_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, 'symbol index'):
            import_slots(self.debugger(symbol_index=5), {'mach_absolute_time': 0x9000})


class ForwarderRollbackTests(unittest.TestCase):
    def debugger(self):
        d = Mock()
        helper = d.target.FindModule.return_value.FindSection.return_value.FindSubSection.return_value
        helper.IsValid.return_value = False
        d.process.AllocateMemory.return_value = 0x10000
        d.process.IsValid.return_value = True
        d.process.GetProcessID.return_value = 42
        import lldb
        d.process.GetState.return_value = lldb.eStateStopped
        d.handle_command.return_value = (True, '(int) $0 = 0', '')
        return d

    def test_failed_forwarder_write_releases_unpublished_page(self):
        d = self.debugger()
        d.write_memory.return_value = (False, 'partial write')
        bindings = ClockBindings(d, {'mach_absolute_time': 0x9000})
        with patch('macdbg.core.clock_bindings.import_slots', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'cannot write clock forwarder'):
                bindings.install()
        d.process.DeallocateMemory.assert_called_once_with(0x10000)
        self.assertEqual(bindings.proxies, {})
        d.handle_command.assert_not_called()

    def test_partial_import_write_restores_original_pointer(self):
        d = self.debugger()
        original = (0x9000).to_bytes(8, 'little')
        d.write_memory.side_effect = [(True, ''), (False, 'partial write'), (True, '')]
        d.read_memory.return_value = b'\xff' * 4 + original[4:]
        bindings = ClockBindings(d, {'mach_absolute_time': 0x9000})
        with patch('macdbg.core.clock_bindings.import_slots',
                   return_value=[('mach_absolute_time', 0x2000, original)]):
            with self.assertRaisesRegex(RuntimeError, 'cannot bind clock import'):
                bindings.install()
        d.write_memory.assert_called_with(0x2000, original, track=False)
        self.assertEqual(bindings.slots, [])
