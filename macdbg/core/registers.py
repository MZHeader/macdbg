from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import lldb


@dataclass
class RegRow:
    name: str
    value: str
    changed: bool
    annotation: str = ""


_SKIP_DEREF = {
    "cpsr", "rflags", "eflags", "fpsr", "fpcr", "mxcsr", "fs", "gs",
    "cs", "ds", "es", "ss",
}

_PRIORITY = (
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "fp", "lr", "sp", "pc", "cpsr",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
)


def _looks_like_addr(v: int) -> bool:
    return v >= 0x10000


def _printable_prefix(data: bytes) -> str:
    run: list = []
    terminated = False
    for b in data:
        if 32 <= b < 127:
            run.append(b)
        elif b == 0 and run:
            terminated = True
            break
        else:
            break
    if len(run) < 5:
        return ""
    if not terminated and len(run) < 12:
        return ""
    return bytes(run).decode("ascii", errors="replace")


def _symbolize(target: Optional[lldb.SBTarget], addr: int) -> str:
    if target is None or not target.IsValid():
        return ""
    sb_addr = target.ResolveLoadAddress(addr)
    if not sb_addr.IsValid():
        return ""
    sym = sb_addr.GetSymbol()
    if not sym.IsValid():
        return ""
    name = sym.GetName()
    if not name:
        return ""
    start = sym.GetStartAddress().GetLoadAddress(target)
    offset = addr - start if start != lldb.LLDB_INVALID_ADDRESS else 0
    module = sb_addr.GetModule()
    modname = ""
    if module.IsValid():
        modname = module.GetFileSpec().GetFilename() or ""
    prefix = "{}`".format(modname) if modname and modname != (target.GetExecutable().GetFilename() or "") else ""
    if offset == 0:
        return "{}{}".format(prefix, name)
    if offset < 0 or offset > 0x100000:
        return ""
    return "{}{}+{:#x}".format(prefix, name, offset)


def _in_module(target: Optional[lldb.SBTarget], addr: int) -> bool:
    if target is None or not target.IsValid():
        return False
    sb_addr = target.ResolveLoadAddress(addr)
    if not sb_addr.IsValid():
        return False
    return sb_addr.GetModule().IsValid()


def _annotate_value(
    val_str: str,
    target: Optional[lldb.SBTarget],
    read_mem: Callable[[int, int], bytes],
) -> str:
    try:
        v = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
    except ValueError:
        return ""
    if not _looks_like_addr(v):
        return ""
    sym = _symbolize(target, v)
    if sym:
        return sym
    data = read_mem(v, 64)
    if not data:
        return ""
    s = _printable_prefix(data)
    if s:
        return '"{}"'.format(s[:40])
    if len(data) >= 8:
        ptr = int.from_bytes(data[:8], "little")
        if _looks_like_addr(ptr):
            sym2 = _symbolize(target, ptr)
            if sym2:
                return "-> {}".format(sym2)
            data2 = read_mem(ptr, 64)
            s2 = _printable_prefix(data2)
            if s2:
                return '-> {:#x} "{}"'.format(ptr, s2[:40])
    if _in_module(target, v):
        peek = data[:8]
        return "[{}]".format(" ".join("{:02x}".format(b) for b in peek))
    return ""


# Condition-flag layouts: bit position for each NZCV / status flag. arm64 packs
# them in cpsr; x86-64 in rflags. Shown decoded next to the register and
# toggled from its right-click menu so branch decisions can be flipped live.
CPSR_FLAGS = (("N", 31), ("Z", 30), ("C", 29), ("V", 28))
RFLAGS_FLAGS = (("O", 11), ("S", 7), ("Z", 6), ("C", 0))


def flag_layout_for(reg_name: str):
    n = reg_name.lower()
    if n == "cpsr":
        return CPSR_FLAGS
    if n in ("rflags", "eflags"):
        return RFLAGS_FLAGS
    return None


def _decode_flags(val_str: str, layout) -> str:
    try:
        v = int(val_str, 16) if val_str.lower().startswith("0x") else int(val_str)
    except ValueError:
        return ""
    # Upper-case letter = set, lower-case = clear, so state reads at a glance.
    return "".join(name if (v >> bit) & 1 else name.lower() for name, bit in layout)


def collect(
    frame: Optional[lldb.SBFrame],
    prev: Dict[str, str],
    read_mem: Optional[Callable[[int, int], bytes]] = None,
    target: Optional[lldb.SBTarget] = None,
    annot_cache: Optional[Dict[str, str]] = None,
) -> List[RegRow]:
    if frame is None or not frame.IsValid():
        return []
    seen: Dict[str, str] = {}
    for set_ in frame.GetRegisters():
        for reg in set_:
            name = reg.GetName()
            if not name:
                continue
            val = reg.GetValue() or ""
            seen[name] = val

    def annotate(name: str, val: str) -> str:
        layout = flag_layout_for(name)
        if layout is not None:
            return _decode_flags(val, layout)
        if read_mem is None or name in _SKIP_DEREF:
            return ""
        if annot_cache is not None:
            key = "{}={}".format(name, val)
            if key in annot_cache:
                return annot_cache[key]
            ann = _annotate_value(val, target, read_mem)
            annot_cache[key] = ann
            return ann
        return _annotate_value(val, target, read_mem)

    ordered: List[RegRow] = []
    used = set()
    for name in _PRIORITY:
        if name in seen:
            v = seen[name]
            ordered.append(RegRow(
                name, v,
                prev.get(name) != v if prev else False,
                annotate(name, v),
            ))
            used.add(name)
    for name, val in seen.items():
        if name in used:
            continue
        ordered.append(RegRow(
            name, val,
            prev.get(name) != val if prev else False,
            annotate(name, val),
        ))
    return ordered


def snapshot(rows: List[RegRow]) -> Dict[str, str]:
    return {r.name: r.value for r in rows}
