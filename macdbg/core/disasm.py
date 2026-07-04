from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

import lldb


@dataclass
class DisasmRow:
    addr: int
    raw: bytes
    mnemonic: str
    operands: str
    comment: str
    is_pc: bool
    user_comment: str = ""
    inline_hint: str = ""


_INT_RE = re.compile(r"#-?(?:0x[0-9a-fA-F]+|\d+)")
_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_REG_RE = re.compile(r"\b([xw](?:[12]?\d|3[01])|sp|xzr|wzr|lr|fp)\b", re.IGNORECASE)


def _parse_imm(s: str) -> Optional[int]:
    m = _INT_RE.search(s)
    if not m:
        return None
    tok = m.group(0)[1:]
    try:
        return int(tok, 16) if tok.lower().startswith("0x") or tok.startswith("-0x") else int(tok)
    except ValueError:
        return None


def _first_reg(operands: str) -> Optional[str]:
    m = _REG_RE.search(operands)
    return m.group(0).lower() if m else None


def _first_hex_addr(operands: str) -> Optional[int]:
    m = _HEX_ADDR_RE.search(operands)
    if not m:
        return None
    try:
        v = int(m.group(0), 16)
    except ValueError:
        return None
    if v < 0x10000:
        return None
    return v


_ADRP_IMM_RE = re.compile(r"adrp?\s+[xw]\d+\s*,\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))",
                          re.IGNORECASE)


def _parse_adrp_imm(operands: str) -> Optional[int]:
    """adrp encodes the target as (pc_page + imm * 4096). Some lldb versions
    show that shifted immediate directly (e.g. 'adrp x8, 4'); others show
    the final address (e.g. 'adrp x8, 0x100004000'). This parses just the
    trailing immediate for the former case."""
    m = re.match(r"\s*[xw]\d+\s*,\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))\s*$",
                 operands, re.IGNORECASE)
    if not m:
        return None
    tok = m.group(1)
    try:
        return int(tok, 16) if tok.lower().startswith("0x") or tok.startswith("-0x") else int(tok)
    except ValueError:
        return None


def _preview_addr(read_mem, target: lldb.SBTarget, addr: int) -> str:
    if addr < 0x10000:
        return ""
    if target and target.IsValid():
        sb = target.ResolveLoadAddress(addr)
        if sb.IsValid():
            sym = sb.GetSymbol()
            if sym.IsValid() and sym.GetName():
                name = sym.GetName()
                start = sym.GetStartAddress().GetLoadAddress(target)
                offset = addr - start if start != lldb.LLDB_INVALID_ADDRESS else 0
                if offset == 0:
                    return name
                if 0 < offset < 0x100000:
                    return "{}+{:#x}".format(name, offset)
    if read_mem is None:
        return ""
    data = read_mem(addr, 48)
    if not data:
        return ""
    printable = 0
    end = len(data)
    for i, b in enumerate(data):
        if 32 <= b < 127 or b in (9,):
            printable += 1
        elif b == 0:
            end = i
            break
        else:
            end = i
            break
    if end >= 5 and printable / max(1, end) > 0.85:
        s = data[:end].decode("ascii", errors="replace")
        return '"{}"'.format(s[:60] + ("…" if end > 60 else ""))
    if len(data) >= 8:
        ptr = int.from_bytes(data[:8], "little")
        if ptr >= 0x10000:
            sub = _preview_addr(read_mem, target, ptr)
            if sub:
                return "-> {}".format(sub)
    return ""


def _annotate_pairs(rows: List[DisasmRow], read_mem, target: lldb.SBTarget) -> None:
    """Detect adrp+add / adrp+ldr pairs and attach an inline preview of what
    the computed address holds. arm64 -O0 pattern:
        adrp xN, 0xPAGE
        add  xN, xN, #OFF     ; xN = &PAGE+OFF
        ldr  xN, [xN, #OFF]   ; xN = *(u64*)(PAGE+OFF)
    """
    for i, row in enumerate(rows):
        if row.mnemonic.lower() != "adrp":
            continue
        page = _first_hex_addr(row.operands)
        if page is None:
            imm_val = _parse_adrp_imm(row.operands)
            if imm_val is None:
                continue
            page = (row.addr & ~0xFFF) + (imm_val << 12)
        reg = _first_reg(row.operands)
        if reg is None:
            continue
        for j in range(i + 1, min(i + 6, len(rows))):
            nxt = rows[j]
            mn = nxt.mnemonic.lower()
            if _first_reg(nxt.operands) != reg:
                continue
            if mn == "add":
                imm = _parse_imm(nxt.operands)
                if imm is None:
                    break
                effective = page + imm
                preview = _preview_addr(read_mem, target, effective)
                if preview:
                    nxt.inline_hint = "= {:#x}  {}".format(effective, preview)
                break
            if mn in ("ldr", "ldrb", "ldrh", "ldrsw"):
                imm = _parse_imm(nxt.operands) or 0
                addr = page + imm
                preview = _preview_addr(read_mem, target, addr)
                if preview:
                    nxt.inline_hint = "load @ {:#x}  {}".format(addr, preview)
                break
            if mn in ("adrp",):
                break


def disasm_around(target: lldb.SBTarget, pc: int, count: int = 512,
                  read_mem: Optional[Callable[[int, int], bytes]] = None) -> List[DisasmRow]:
    if not target or not target.IsValid() or pc == 0:
        return []
    start = max(0, pc - count * 2)
    addr = lldb.SBAddress(start, target)
    insns = target.ReadInstructions(addr, count)
    out: List[DisasmRow] = []
    for i in range(insns.GetSize()):
        insn = insns.GetInstructionAtIndex(i)
        a = insn.GetAddress().GetLoadAddress(target)
        err = lldb.SBError()
        raw = bytes(insn.GetData(target).ReadRawData(err, 0, insn.GetByteSize()) or b"")
        out.append(
            DisasmRow(
                addr=a,
                raw=raw,
                mnemonic=insn.GetMnemonic(target) or "",
                operands=insn.GetOperands(target) or "",
                comment=insn.GetComment(target) or "",
                is_pc=(a == pc),
            )
        )
    if read_mem is not None:
        _annotate_pairs(out, read_mem, target)
    return out


def extract_addr(operands: str) -> Optional[int]:
    best: Optional[int] = None
    for m in re.finditer(r"0x[0-9a-fA-F]+", operands):
        try:
            v = int(m.group(0), 16)
        except ValueError:
            continue
        if v < 0x10000:
            continue
        if best is None or v > best:
            best = v
    return best


def format_bytes(b: bytes, width: int = 8) -> str:
    s = " ".join("{:02x}".format(x) for x in b[:width])
    if len(b) > width:
        s += " …"
    return s
