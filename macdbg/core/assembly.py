"""ARM64 assembler backed by the Xcode toolchain, with no target execution."""
import os
import re
import subprocess
import tempfile

from .macho import MachO


def relative_instruction(mnemonic, operands, pc, destination):
    fields = [x.strip() for x in operands.split(',')]
    delta = destination - pc
    if mnemonic in ('adr', 'adrp'):
        match = re.fullmatch(r'x(\d+)', fields[0])
        if not match or int(match[1]) > 30: raise ValueError('ADR destination must be x0–x30')
        if mnemonic == 'adrp': delta = (destination >> 12) - (pc >> 12)
        if not -(1 << 20) <= delta < 1 << 20: raise ValueError('ADR target is out of range')
        encoded = delta & 0x1fffff
        return (0x90000000 if mnemonic == 'adrp' else 0x10000000) | ((encoded & 3) << 29) | ((encoded >> 2) << 5) | int(match[1])
    if delta % 4: raise ValueError('Branch target must be aligned to four bytes')
    delta //= 4
    if mnemonic in ('ldr', 'ldrsw'):
        match = re.fullmatch(r'([xwsdq])(\d+)', fields[0])
        if not match or int(match[2]) > 31: raise ValueError('Invalid literal load register')
        if not -(1 << 18) <= delta < 1 << 18: raise ValueError('Literal load target is out of range')
        bases = {'w': 0x18000000, 'x': 0x58000000, 's': 0x1c000000, 'd': 0x5c000000, 'q': 0x9c000000}
        if mnemonic == 'ldrsw' and match[1] != 'x': raise ValueError('LDRSW requires an x register')
        return (0x98000000 if mnemonic == 'ldrsw' else bases[match[1]]) | ((delta & 0x7ffff) << 5) | int(match[2])
    if mnemonic in ('b', 'bl'):
        if not -(1 << 25) <= delta < 1 << 25: raise ValueError('Branch target is out of range')
        return (0x94000000 if mnemonic == 'bl' else 0x14000000) | (delta & 0x3ffffff)
    if mnemonic.startswith('b.'):
        conditions = dict(zip(('eq','ne','hs','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv'), range(16)))
        conditions.update(cs=2, cc=3)
        if mnemonic[2:] not in conditions: raise ValueError('Unknown branch condition')
        if not -(1 << 18) <= delta < 1 << 18: raise ValueError('Conditional branch target is out of range')
        return 0x54000000 | ((delta & 0x7ffff) << 5) | conditions[mnemonic[2:]]
    match = re.fullmatch(r'([wx])(\d+|zr)', fields[0])
    if not match: raise ValueError('Invalid branch register')
    reg = 31 if match[2] == 'zr' else int(match[2])
    if reg > 31: raise ValueError('Invalid register number')
    if mnemonic in ('cbz', 'cbnz'):
        if not -(1 << 18) <= delta < 1 << 18: raise ValueError('Compare branch target is out of range')
        return 0x34000000 | ((match[1] == 'x') << 31) | ((mnemonic == 'cbnz') << 24) | ((delta & 0x7ffff) << 5) | reg
    if mnemonic in ('tbz', 'tbnz'):
        bit = int(fields[1].lstrip('#'), 0)
        if not 0 <= bit < (64 if match[1] == 'x' else 32): raise ValueError('Invalid bit index')
        if not -(1 << 13) <= delta < 1 << 13: raise ValueError('Test branch target is out of range')
        return 0x36000000 | ((bit >> 5) << 31) | ((bit & 31) << 19) | ((mnemonic == 'tbnz') << 24) | ((delta & 0x3fff) << 5) | reg
    raise ValueError('Unsupported relative instruction')


def assemble(source, address, resolve=None):
    if not isinstance(source, str) or len(source) > 16384 or address < 0 or address % 4:
        raise ValueError('Use an aligned address and at most 16 KiB of assembly')
    lines, labels, offset = [], {}, 0
    for raw in source.splitlines():
        line = raw.split('//', 1)[0].strip()
        if not line: continue
        if re.fullmatch(r'[A-Za-z_]\w*:', line):
            name = line[:-1]
            if name in labels: raise ValueError('Duplicate label: ' + name)
            labels[name] = address + offset
            continue
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9.]*\s*', line) or any(c in line for c in (';', '\\', '"')):
            raise ValueError('Enter instructions and local labels only; assembler directives are not accepted')
        lines.append((address + offset, line)); offset += 4
    if not 1 <= len(lines) <= 256: raise ValueError('Assemble 1–256 ARM64 instructions')
    compiler, replacements = [], {}
    for pc, line in lines:
        parts = line.split(None, 1)
        mnemonic, operands = parts[0].lower(), parts[1] if len(parts) > 1 else ''
        if not re.fullmatch(r'[a-z][a-z0-9.]*', mnemonic):
            raise ValueError('Place local labels on their own line; directives are not accepted')
        if (mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp') or mnemonic.startswith('b.')
                or mnemonic in ('ldr', 'ldrsw') and '[' not in operands):
            expression = operands.split(',')[-1].strip().lstrip('#')
            if expression in labels: destination = labels[expression]
            else:
                try: destination = int(expression, 0)
                except ValueError:
                    if not resolve: raise ValueError('Unknown symbol: ' + expression)
                    destination = resolve(expression)
            replacements[len(compiler)] = relative_instruction(mnemonic, operands, pc, destination)
            compiler.append('nop')
        else:
            compiler.append(line)
    with tempfile.TemporaryDirectory(prefix='macdbg-assemble-') as directory:
        output = os.path.join(directory, 'code.o')
        result = subprocess.run(['/usr/bin/xcrun', 'clang', '-target', 'arm64-apple-macos11', '-c', '-x', 'assembler', '-', '-o', output],
                                input='.text\n' + '\n'.join(compiler) + '\n', capture_output=True, text=True, timeout=15)
        if result.returncode: raise ValueError(result.stderr.strip()[:4000])
        with open(output, 'rb') as stream: image = MachO(stream.read())
        sections = [s for s in image.sections if s['name'] == '__text' and s['segment'] == '__TEXT']
        if len(sections) != 1: raise ValueError('Assembler did not emit one text section')
        section = sections[0]
        if section['relocations']: raise ValueError('Unresolved relocation; use a numeric address or a supported address-aware instruction')
        data = bytearray(image.data[section['offset']:section['offset'] + section['size']])
        if len(data) != len(lines) * 4: raise ValueError('Each input line must emit exactly one ARM64 instruction')
        for index, value in replacements.items(): data[index * 4:index * 4 + 4] = value.to_bytes(4, 'little')
        return bytes(data)
