from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

import lldb


@dataclass
class DisasmRow:
    addr: int
    raw: bytes
    mnemonic: str
    operands: str
    comment: str
    is_pc: bool


def disasm_around(target: lldb.SBTarget, pc: int, count: int = 40) -> List[DisasmRow]:
    if not target or not target.IsValid() or pc == 0:
        return []
    start = max(0, pc - 64)
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
