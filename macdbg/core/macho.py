"""Validated file ranges for ARM64 patch export and assembler output.

This is intentionally a small Mach-O range reader, not a loader. All offsets
are checked against the selected slice before a byte can be patched.
"""
import struct

ARM64 = 0x100000c


class MachO:
    def __init__(self, data, subtype=None):
        self.data = data
        self.base, self.length = 0, len(data)
        if len(data) < 32: raise ValueError('Truncated Mach-O')
        magic = struct.unpack_from('>I', data)[0]
        if magic in (0xcafebabe, 0xcafebabf):
            count = struct.unpack_from('>I', data, 4)[0]
            width = 20 if magic == 0xcafebabe else 32
            if not 1 <= count <= 64 or 8 + width * count > len(data): raise ValueError('Invalid fat header')
            candidates = []
            for index in range(count):
                at = 8 + index * width
                cpu, sub = struct.unpack_from('>II', data, at)
                offset, length = struct.unpack_from('>II' if width == 20 else '>QQ', data, at + 8)
                if offset < 8 + width * count or length < 32 or offset + length > len(data):
                    raise ValueError('Invalid architecture slice')
                if cpu == ARM64 and (subtype is None or (sub & 0xffffff) == subtype):
                    candidates.append((offset, length))
            if len(candidates) != 1: raise ValueError('Select an unambiguous ARM64 slice')
            self.base, self.length = candidates[0]
        magic, cpu, self.subtype, _, count, commands_size = struct.unpack_from('<6I', data, self.base)
        if magic != 0xfeedfacf or cpu != ARM64: raise ValueError('Expected a little-endian ARM64 Mach-O')
        if count > 65536 or commands_size > self.length - 32: raise ValueError('Invalid load commands')
        self.sections, self.segments, self.signed, self.encrypted = [], [], False, False
        offset, end = self.base + 32, self.base + 32 + commands_size
        for _ in range(count):
            if offset + 8 > end: raise ValueError('Truncated load command')
            command, size = struct.unpack_from('<II', data, offset)
            if size < 8 or offset + size > end: raise ValueError('Invalid load command size')
            if command == 0x19:
                if size < 72: raise ValueError('Truncated segment')
                name, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<16sQQQQ', data, offset + 8)
                nsects = struct.unpack_from('<I', data, offset + 64)[0]
                if 72 + nsects * 80 > size or fileoff + filesize > self.length:
                    raise ValueError('Invalid segment range')
                self.segments.append({'name': name.rstrip(b'\0').decode('ascii', 'replace'),
                                      'address': vmaddr, 'size': vmsize, 'offset': self.base + fileoff,
                                      'file_size': filesize})
                for index in range(nsects):
                    at = offset + 72 + index * 80
                    name, segment, address, length, fileoff, _, reloff, nreloc, flags = struct.unpack_from('<16s16sQQIIIII', data, at)
                    zero = flags & 0xff in (1, 0xc, 0x12)
                    if not zero and fileoff + length > self.length: raise ValueError('Section exceeds file')
                    if nreloc and (reloff + nreloc * 8 > self.length): raise ValueError('Invalid relocations')
                    self.sections.append({'name': name.rstrip(b'\0').decode('ascii', 'replace'),
                                          'segment': segment.rstrip(b'\0').decode('ascii', 'replace'),
                                          'address': address, 'size': length, 'offset': self.base + fileoff,
                                          'zero': zero, 'relocations': nreloc})
            elif command == 0x1d:
                self.signed = True
            elif command in (0x21, 0x2c):
                if size < 20: raise ValueError('Truncated encryption command')
                self.encrypted |= struct.unpack_from('<I', data, offset + 16)[0] != 0
            offset += size
        if offset != end: raise ValueError('Load-command size mismatch')

    def file_offset(self, address, size):
        if self.encrypted: raise ValueError('Encrypted images cannot be exported as ordinary patches')
        matches = [s for s in self.sections if not s['zero'] and s['address'] <= address and address + size <= s['address'] + s['size']]
        if len(matches) != 1: raise ValueError('Patch is not entirely in one file-backed section')
        s = matches[0]
        return s['offset'] + address - s['address']

    def file_address(self, offset, size):
        matches = [s for s in self.sections if not s['zero'] and s['offset'] <= offset and offset + size <= s['offset'] + s['size']]
        if len(matches) != 1: raise ValueError('Patch offset is outside file-backed sections')
        s = matches[0]
        return s['address'] + offset - s['offset']
