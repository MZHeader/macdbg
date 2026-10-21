"""Conservative ARM64 operand decoding shared by inspection and recording.

Unknown modes return no access; a guessed address must never become trace evidence.
"""
import re

MASK = (1 << 64) - 1


def integer(text):
    return int(text.strip().lstrip('#'), 0)


def register_value(registers, name):
    name = {'fp': 'x29', 'lr': 'x30', 'wsp': 'sp'}.get(name, name)
    if name in ('xzr', 'wzr'):
        return 0
    key = 'x' + name[1:] if re.fullmatch(r'w\d+', name) else name
    value = registers.get(key)
    if value is None:
        return None
    value = int(value, 16) if isinstance(value, str) else value
    return value & (0xffffffff if name.startswith('w') else MASK)


def memory_access(mnemonic, operands, registers):
    """Return one contiguous access for common scalar, SIMD and pair transfers.

    Exclusive/atomic/SVE operations are intentionally not treated as ordinary
    stores: a write may fail, or touch a predicate-dependent range.
    """
    names = {'ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw',
             'ldur', 'ldurb', 'ldurh', 'ldursb', 'ldursh', 'ldursw',
             'str', 'strb', 'strh', 'stur', 'sturb', 'sturh',
             'ldp', 'ldpsw', 'ldnp', 'stp', 'stnp'}
    if mnemonic not in names:
        return None
    first = operands.split(',')[0].strip()
    if not re.fullmatch(r'(?:[xwqdsbh]\d+|[xw]zr)', first):
        return None
    width = {'x': 8, 'w': 4, 'q': 16, 'd': 8, 's': 4, 'b': 1, 'h': 2}[first[0]]
    if mnemonic.endswith('b'): width = 1
    elif mnemonic.endswith('h'): width = 2
    elif mnemonic.endswith('sw'): width = 4
    if mnemonic in ('ldp', 'ldpsw', 'ldnp', 'stp', 'stnp'): width *= 2
    match = re.search(r'\[(x\d+|sp|fp|lr)([^\]]*)\]', operands)
    if not match:
        literal = re.fullmatch(r'\w+,\s*(0x[\da-fA-F]+)', operands)
        if not literal or not mnemonic.startswith('ld'):
            return None
        address = int(literal[1], 16)
    else:
        base = register_value(registers, match[1])
        if base is None: return None
        rest = match[2].strip().lstrip(',').strip()
        offset = 0
        if rest:
            immediate = re.fullmatch(r'#?(-?(?:0x[\da-fA-F]+|\d+))', rest)
            index = re.fullmatch(r'([wx]\d+)(?:,\s*(lsl|uxtw|sxtw|sxtx)(?:\s*#?(\d+))?)?', rest)
            if immediate:
                offset = integer(immediate[1])
            elif index:
                offset = register_value(registers, index[1])
                if offset is None: return None
                if index[2] in ('sxtw', 'sxtx'):
                    bits = 32 if index[2] == 'sxtw' else 64
                    offset &= (1 << bits) - 1
                    if offset & (1 << (bits - 1)): offset -= 1 << bits
                shift = int(index[3] or 0)
                if shift > 4: return None
                offset <<= shift
            else:
                return None
        address = (base + offset) & MASK
    return {'address': hex(address), 'size': width,
            'access': 'read' if mnemonic.startswith('ld') else 'write',
            'source': 'decoded operand'}
