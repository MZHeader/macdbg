"""Locate live Mach-O import slots and build process-local clock forwarders."""
from __future__ import annotations

import struct

import lldb


def import_slots(debugger, wanted):
    target = debugger.target
    module = target.FindModule(target.GetExecutable())
    header = module.GetObjectFileHeaderAddress().GetLoadAddress(target)

    def read(address, size):
        data = debugger.read_memory(address, size)
        if len(data) != size:
            raise RuntimeError("cannot read Mach-O import metadata")
        return data

    head = read(header, 32)
    if struct.unpack_from('<I', head)[0] != 0xfeedfacf:
        raise RuntimeError("clock import binding requires a 64-bit Mach-O")
    count, length = struct.unpack_from('<II', head, 16)
    if length > 65536 or count > length // 8:
        raise RuntimeError("invalid Mach-O load commands")
    commands = read(header + 32, length)
    offset = 0
    slots, symtab, indirect, linkedit, slide = [], None, None, None, None
    libraries = []
    for _ in range(count):
        if offset + 8 > length:
            raise RuntimeError('truncated Mach-O load command')
        command, size = struct.unpack_from('<II', commands, offset)
        if size < 8 or offset + size > length:
            raise RuntimeError("invalid Mach-O load command size")
        data = commands[offset:offset + size]
        if command == 0x19:
            if size < 72:
                raise RuntimeError("truncated Mach-O segment")
            name = data[8:24].rstrip(b'\0')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, 24)
            sections = struct.unpack_from('<I', data, 64)[0]
            if 72 + sections * 80 > size:
                raise RuntimeError("truncated Mach-O sections")
            if name == b'__TEXT':
                slide = header - vmaddr
            if name == b'__LINKEDIT':
                linkedit = vmaddr, fileoff, filesize
            for i in range(sections):
                section = data[72 + i * 80:152 + i * 80]
                address, byte_size = struct.unpack_from('<QQ', section, 32)
                flags, first = struct.unpack_from('<II', section, 64)
                if (flags & 0xff) in (6, 7):
                    if byte_size % 8 or byte_size > 1048576:
                        raise RuntimeError("invalid Mach-O import pointer section")
                    if address < vmaddr or address + byte_size > vmaddr + vmsize:
                        raise RuntimeError('Mach-O import pointers escape their segment')
                    slots.append((address, byte_size // 8, first))
        elif command == 2 and size >= 24:
            symtab = struct.unpack_from('<IIII', data, 8)
        elif command == 0xb and size >= 80:
            indirect = struct.unpack_from('<II', data, 56)
        elif command in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023):
            if size < 24:
                raise RuntimeError('truncated Mach-O library command')
            at = struct.unpack_from('<I', data, 8)[0]
            end = data.find(b'\0', at)
            if at < 24 or at >= size or end < 0:
                raise RuntimeError('invalid Mach-O library name')
            libraries.append(data[at:end].decode('utf8', errors='replace'))
        offset += size
    if not slots:
        return []
    if symtab is None or indirect is None or linkedit is None or slide is None:
        raise RuntimeError("missing Mach-O import tables")

    def file_data(at, size):
        vmaddr, fileoff, filesize = linkedit
        if at < fileoff or size > 16777216 or at + size > fileoff + filesize:
            raise RuntimeError("Mach-O import table is out of bounds")
        return read(vmaddr + slide + at - fileoff, size)

    symoff, nsyms, stroff, strsize = symtab
    indoff, nind = indirect
    symbols = file_data(symoff, nsyms * 16)
    strings = file_data(stroff, strsize)
    indices = file_data(indoff, nind * 4)
    result = []
    for address, count, first in slots:
        if first + count > nind:
            raise RuntimeError("Mach-O import index is out of bounds")
        for i in range(count):
            index = struct.unpack_from('<I', indices, (first + i) * 4)[0]
            if index & 0xc0000000:
                continue
            if index >= nsyms:
                raise RuntimeError("Mach-O symbol index is out of bounds")
            string_index = struct.unpack_from('<I', symbols, index * 16)[0]
            end = strings.find(b'\0', string_index)
            if string_index >= strsize or end < 0:
                raise RuntimeError("invalid Mach-O import name")
            name = strings[string_index:end].decode('ascii', errors='replace')
            name = name[1:] if name.startswith('_') else name
            if name in wanted:
                symbol_type = symbols[index * 16 + 4] & 0x0e
                if symbol_type not in (0, 0x0c):
                    continue
                pointer = address + slide + i * 8
                value = read(pointer, 8)
                ordinal = struct.unpack_from('<H', symbols, index * 16 + 6)[0] >> 8
                system_import = (0 < ordinal <= len(libraries)
                                 and libraries[ordinal - 1].startswith(('/usr/lib/', '/System/Library/')))
                if isinstance(wanted, dict) and not system_import and int.from_bytes(value, 'little') != wanted[name]:
                    continue
                result.append((name, pointer, value))
    return result


class ClockBindings:
    def __init__(self, debugger, originals):
        self.debugger = debugger
        self.originals = dict(originals)
        self.proxies = {}
        self.code = {}
        self.slots = []
        self.skipped = []
        self._installing = True
        self.process_id = debugger.process.GetProcessID()

    def install(self):
        d = self.debugger
        imports = import_slots(d, self.originals)
        module = d.target.FindModule(d.target.GetExecutable())
        helper = module.FindSection('__TEXT').FindSubSection('__stub_helper')
        helper_start = helper.GetLoadAddress(d.target) if helper.IsValid() else 0
        helper_end = helper_start + helper.GetByteSize() if helper.IsValid() else 0
        error = lldb.SBError()
        page = d.process.AllocateMemory(4096, lldb.ePermissionsReadable |
                                        lldb.ePermissionsWritable, error)
        if error.Fail() or page in (0, lldb.LLDB_INVALID_ADDRESS):
            raise RuntimeError("cannot allocate clock forwarders: " + (error.GetCString() or "unknown error"))
        try:
            for index, (name, address) in enumerate(self.originals.items()):
                proxy = page + index * 16
                # A frameless tail branch preserves arguments and the caller's LR.
                code = struct.pack('<IIQ', 0x58000050, 0xd61f0200, address)
                ok, message = d.write_memory(proxy, code, track=False)
                if not ok:
                    raise RuntimeError("cannot write clock forwarder: " + message)
                self.proxies[name], self.code[proxy] = proxy, code
            ok, output, message = d.handle_command(
                'expression -l c++ --ignore-breakpoints true -- '
                '(int)mprotect((void*){:#x}, 4096, 5)'.format(page))
            if not ok or not output.strip().endswith('= 0'):
                raise RuntimeError('cannot protect clock forwarders: ' + (message or output).strip())
        except Exception:
            # No import or resolver has received these addresses yet.
            d.process.DeallocateMemory(page)
            self.proxies.clear()
            self.code.clear()
            raise
        try:
            for name, pointer, original in imports:
                value = int.from_bytes(original, 'little')
                if not value:
                    continue
                if value != self.originals[name] and not helper_start <= value < helper_end:
                    self.skipped.append(name)
                    continue
                replacement = self.proxies[name].to_bytes(8, 'little')
                self.slots.append((pointer, original, replacement))
                ok, message = d.write_memory(pointer, replacement, track=False)
                if not ok:
                    raise RuntimeError("cannot bind clock import: " + message)
        except Exception:
            self.restore()
            raise
        self._installing = False
        return self.slots

    def restore(self):
        d = self.debugger
        if (d.process and d.process.IsValid()
                and d.process.GetProcessID() == self.process_id
                and d.process.GetState() == lldb.eStateStopped):
            for pointer, original, replacement in reversed(self.slots):
                if self._installing or d.read_memory(pointer, 8) == replacement:
                    ok, message = d.write_memory(pointer, original, track=False)
                    if not ok:
                        raise RuntimeError("cannot restore clock import: " + message)
        self.slots.clear()
        # Cached dlsym pointers can outlive the toggle. Leave the tiny tail
        # branches mapped until process exit; without hooks they call real APIs.

    def validate(self):
        d = self.debugger
        if d.process.GetState() != lldb.eStateStopped:
            return
        for address, expected in self.code.items():
            if d.read_memory(address, len(expected)) != expected:
                raise RuntimeError("clock forwarder was modified")
        for pointer, _, replacement in self.slots:
            if d.read_memory(pointer, 8) != replacement:
                raise RuntimeError("clock import binding was modified")
