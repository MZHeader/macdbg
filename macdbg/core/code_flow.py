"""Basic-block constant propagation. No guessed values cross a control boundary."""
import re

from .disasm import _branch_target, _first_hex_addr, _parse_adrp_imm
from .arm64_operands import memory_access, register_value


def reference_candidates(rows, read_memory=None):
    values = {}
    leaders = set()
    for row in rows:
        mn = row['mn']
        if mn in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or mn.startswith('b.'):
            target = _branch_target(row['ops'])
            if target is not None: leaders.add(target)
    candidates = []
    for row in rows:
        mn, ops, pc = row['mn'], row['ops'], row['addr']
        if pc in leaders: values.clear()
        fields = [f.strip() for f in ops.split(',')]
        destination = fields[0] if fields else ''
        old = dict(values)
        new = None
        target = None
        kind = 'basic-block address calculation'
        if mn in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or mn.startswith('b.'):
            target = _branch_target(ops); kind = 'decoded direct'
        elif mn == 'adr':
            new = target = _branch_target(ops)
        elif mn == 'adrp':
            absolute = re.fullmatch(r'\w+,\s*(0x[\da-fA-F]+)', ops)
            new = int(absolute[1], 16) if absolute else None
            relative = _parse_adrp_imm(ops)
            if new is None and relative is not None: new = (pc & ~4095) + (relative << 12)
        elif mn in ('mov', 'movz', 'movn', 'movk') and len(fields) >= 2:
            immediate = re.fullmatch(r'#?(0x[\da-fA-F]+|\d+|-\d+)', fields[1])
            shift = re.fullmatch(r'lsl\s*#?(0|16|32|48)', fields[2]) if len(fields) == 3 else None
            if len(fields) == 2 or shift:
                if immediate:
                    number = int(immediate[1], 0); amount = int(shift[1]) if shift else 0
                    if mn == 'movk':
                        current = register_value(old, destination)
                        if current is not None: new = (current & ~(0xffff << amount)) | ((number & 0xffff) << amount)
                    else:
                        new = number << amount
                        if mn == 'movn': new = ~new
                elif mn == 'mov': new = register_value(old, fields[1])
        elif mn in ('add', 'sub') and len(fields) >= 3:
            left = register_value(old, fields[1])
            immediate = re.fullmatch(r'#?(-?(?:0x[\da-fA-F]+|\d+))', fields[2])
            right = int(immediate[1], 0) if immediate else register_value(old, fields[2])
            shift = re.fullmatch(r'lsl\s*#?(\d+)', fields[3]) if len(fields) == 4 else None
            if left is not None and right is not None and (len(fields) == 3 or shift and int(shift[1]) <= 63):
                if shift: right <<= int(shift[1])
                new = target = left + right if mn == 'add' else left - right
        elif mn in ('ldr', 'ldrsw'):
            access = memory_access(mn, ops, old)
            if access:
                target = int(access['address'], 16); kind = 'inferred memory reference'
                if read_memory and access['size'] in (4, 8) and destination.startswith(('x', 'w')):
                    data = read_memory(target, access['size'])
                    if len(data) == access['size']:
                        new = int.from_bytes(data, 'little', signed=mn == 'ldrsw')
        elif mn in ('br', 'blr'):
            target = register_value(old, destination); kind = 'inferred indirect target from current bytes'
        if target is not None:
            candidates.append({**row, 'target': target & ((1 << 64) - 1), 'kind': kind})
        # Unknown destination writes invalidate the complete x/w alias. Stores,
        # comparisons and hints do not write their first operand.
        key = 'x' + destination[1:] if re.fullmatch(r'[wx]\d+', destination) else destination
        no_write = (mn.startswith(('st', 'b', 'ret', 'cmp', 'cmn', 'tst')) or mn in ('nop', 'prfm', 'dmb', 'dsb', 'isb'))
        if key in values and not no_write: values.pop(key)
        if new is not None and re.fullmatch(r'[wx]\d+', destination):
            values[key] = new & ((1 << (32 if destination[0] == 'w' else 64)) - 1)
        # Pair loads also overwrite the second register; writeback overwrites
        # the base. Dropping it is safer than attempting every addressing mode.
        if mn.startswith('ldp') and len(fields) > 1:
            values.pop('x' + fields[1][1:] if fields[1].startswith('w') else fields[1], None)
        writeback = re.search(r'\[(\w+)[^\]]*\](?:!|,)', ops)
        if writeback: values.pop(writeback[1], None)
        supported = {'adr', 'adrp', 'mov', 'movz', 'movk', 'movn', 'add', 'sub', 'ldr', 'ldrsw',
                     'str', 'strb', 'strh', 'stur', 'sturb', 'sturh', 'stp', 'stnp',
                     'nop', 'cmp', 'cmn', 'tst', 'prfm', 'dmb', 'dsb', 'isb'}
        if mn not in supported:
            values.clear()
        if mn.startswith(('b', 'ret', 'svc', 'hvc', 'smc', 'brk')) or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            values.clear()
    return candidates
