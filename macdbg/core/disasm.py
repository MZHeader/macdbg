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
    gutter: str = "    "
    gutter_styles: List = None
    function_head: str = ""


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


def _addr_base_reg(operands: str) -> Optional[str]:
    """The address-base register of an add/ldr, the second register operand
    that an adrp result flows into, not the destination. None when there is no
    second register."""
    regs = _REG_RE.findall(operands)
    return regs[1].lower() if len(regs) >= 2 else None


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
    """Parse the trailing immediate of an adrp for lldb versions that print
    the shifted immediate ('adrp x8, 4') rather than the final address."""
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
    """Find adrp+add / adrp+ldr pairs and attach a preview of what the
    computed address holds."""
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
            base = _addr_base_reg(nxt.operands)
            if mn == "add" and base == reg:
                imm = _parse_imm(nxt.operands)
                if imm is None:
                    break
                effective = page + imm
                preview = _preview_addr(read_mem, target, effective)
                if preview:
                    nxt.inline_hint = "= {:#x}  {}".format(effective, preview)
                break
            if mn in ("ldr", "ldrb", "ldrh", "ldrsw") and base == reg:
                dest = nxt.operands.split(",", 1)[0].strip()
                if dest[:1].lower() in "dsqvhb" and dest[1:2].isdigit():
                    break
                imm = _parse_imm(nxt.operands) or 0
                addr = page + imm
                preview = _preview_addr(read_mem, target, addr)
                if preview:
                    nxt.inline_hint = "load @ {:#x}  {}".format(addr, preview)
                break
            if _first_reg(nxt.operands) == reg:
                break


def disasm_around(target: lldb.SBTarget, pc: int, count: int = 512,
                  read_mem: Optional[Callable[[int, int], bytes]] = None,
                  center: Optional[int] = None,
                  frame: Optional["lldb.SBFrame"] = None) -> List[DisasmRow]:
    """Disassemble `count` instructions around `center` (default `pc`). `pc`
    marks the pc row when it falls in range. With `frame`, a conditional branch
    at pc is colored green (taken) or red (not taken)."""
    if not target or not target.IsValid() or pc == 0:
        return []
    anchor = center if center is not None else pc
    start = max(0, anchor - count * 2)
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
    _mark_function_heads(out, target)
    _draw_branch_gutter(out, frame=frame)
    return out


def _mark_function_heads(rows: List[DisasmRow], target: lldb.SBTarget) -> None:
    """Set `function_head` on the first row of each function, using the
    function or symbol name (the synthetic name for stripped code)."""
    if not rows:
        return
    prev_name = None
    for r in rows:
        sb = target.ResolveLoadAddress(r.addr)
        if not sb.IsValid():
            continue
        fn = sb.GetFunction()
        name = ""
        start = lldb.LLDB_INVALID_ADDRESS
        if fn.IsValid() and fn.GetName():
            name = fn.GetName()
            start = fn.GetStartAddress().GetLoadAddress(target)
        else:
            sym = sb.GetSymbol()
            if sym.IsValid() and sym.GetName():
                name = sym.GetName()
                start = sym.GetStartAddress().GetLoadAddress(target)
        if not name:
            prev_name = None
            continue
        is_new_function = (name != prev_name)
        prev_name = name
        if is_new_function or r.addr == start:
            r.function_head = name


_BRANCH_MNEMONICS = {
    "b", "bl", "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi", "b.pl",
    "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
    "cbz", "cbnz", "tbz", "tbnz",
}


def _draw_branch_gutter(rows: List[DisasmRow], width: int = 4,
                         frame: Optional["lldb.SBFrame"] = None) -> None:
    """Draw an arrow gutter for branches whose source and target are both in
    view, putting overlapping arrows in separate lanes. With `frame`, colors the
    pc branch green (taken) or red (not taken)."""
    if not rows:
        return
    addr_to_idx = {r.addr: i for i, r in enumerate(rows)}
    branches = []
    for i, r in enumerate(rows):
        mn = r.mnemonic.lower()
        base = mn.split(".")[0]
        if mn not in _BRANCH_MNEMONICS and base != "b" and mn not in ("cbz", "cbnz", "tbz", "tbnz"):
            continue
        if mn == "bl":
            continue
        target = _branch_target(r.operands)
        if target is None:
            continue
        j = addr_to_idx.get(target)
        if j is None:
            continue
        if j == i:
            continue
        top, bot = (i, j) if i < j else (j, i)
        branches.append({"src": i, "dst": j, "top": top, "bot": bot,
                         "cond": mn != "b", "row": r})
    lanes: List[List[dict]] = []
    for br in sorted(branches, key=lambda b: (b["bot"] - b["top"], b["top"])):
        for lane in lanes:
            if all(b["bot"] < br["top"] or b["top"] > br["bot"] for b in lane):
                lane.append(br)
                br["lane"] = lanes.index(lane)
                break
        else:
            lanes.append([br])
            br["lane"] = len(lanes) - 1
    if not branches:
        return
    n_lanes = min(len(lanes), width - 1)
    grid = [[" "] * width for _ in rows]
    styles_per_row: List[List[Optional[str]]] = [[None] * width for _ in rows]
    default_style = "#767676"
    for br in branches:
        lane = br["lane"]
        if lane >= n_lanes:
            continue
        col = width - 2 - lane
        going_down = br["src"] < br["dst"]
        src, dst = br["src"], br["dst"]
        row_style: Optional[str] = None
        if frame is not None and br["row"].is_pc and br["cond"]:
            taken = _evaluate_condition(br["row"], frame)
            if taken is True:
                row_style = "bold #5fd75f"
            elif taken is False:
                row_style = "bold #ff5f5f"
        for k in range(min(src, dst), max(src, dst) + 1):
            if k == src:
                grid[k][col] = "┐" if going_down else "┘"
            elif k == dst:
                grid[k][col] = "└" if going_down else "┌"
            else:
                if grid[k][col] == " ":
                    grid[k][col] = "│"
            if row_style is not None:
                styles_per_row[k][col] = row_style
            if k == dst:
                for c in range(col + 1, width):
                    if grid[k][c] == " ":
                        grid[k][c] = "─"
                        if row_style is not None:
                            styles_per_row[k][c] = row_style
                grid[k][width - 1] = "▶"
                if row_style is not None:
                    styles_per_row[k][width - 1] = row_style
    for i, r in enumerate(rows):
        r.gutter = "".join(grid[i])
        spans = []
        current_style = None
        run_start = 0
        for c, s in enumerate(styles_per_row[i]):
            style = s or default_style
            if current_style is None:
                current_style = style
                run_start = c
            elif style != current_style:
                spans.append((run_start, c, current_style))
                current_style = style
                run_start = c
        if current_style is not None:
            spans.append((run_start, width, current_style))
        r.gutter_styles = spans


def _evaluate_condition(row: DisasmRow, frame: "lldb.SBFrame") -> Optional[bool]:
    """Return True (will be taken), False (will not), or None (unknown)."""
    mn = row.mnemonic.lower()
    ops = row.operands
    if mn in ("cbz", "cbnz"):
        rn = _first_reg(ops)
        if rn is None:
            return None
        v = frame.FindRegister(rn)
        if not v.IsValid():
            return None
        val = v.GetValueAsUnsigned()
        return (val == 0) if mn == "cbz" else (val != 0)
    if mn in ("tbz", "tbnz"):
        rn = _first_reg(ops)
        if rn is None:
            return None
        v = frame.FindRegister(rn)
        if not v.IsValid():
            return None
        imms = _INT_RE.findall(ops)
        if not imms:
            return None
        bit_tok = imms[0][1:]
        try:
            bit = int(bit_tok, 16) if bit_tok.lower().startswith("0x") else int(bit_tok)
        except ValueError:
            return None
        val = v.GetValueAsUnsigned()
        bit_set = ((val >> bit) & 1) == 1
        return (not bit_set) if mn == "tbz" else bit_set
    if not mn.startswith("b."):
        return None
    cond = mn[2:]
    cpsr = frame.FindRegister("cpsr")
    if not cpsr.IsValid():
        return None
    v = cpsr.GetValueAsUnsigned()
    n = (v >> 31) & 1
    z = (v >> 30) & 1
    c = (v >> 29) & 1
    ov = (v >> 28) & 1
    table = {
        "eq": z == 1,
        "ne": z == 0,
        "cs": c == 1, "hs": c == 1,
        "cc": c == 0, "lo": c == 0,
        "mi": n == 1,
        "pl": n == 0,
        "vs": ov == 1,
        "vc": ov == 0,
        "hi": c == 1 and z == 0,
        "ls": c == 0 or z == 1,
        "ge": n == ov,
        "lt": n != ov,
        "gt": z == 0 and n == ov,
        "le": z == 1 or n != ov,
        "al": True,
        "nv": False,
    }
    return table.get(cond)


def _branch_target(operands: str) -> Optional[int]:
    """Extract the branch target from an arm64 branch operand (the last hex
    operand, which is the target for b, b.cond, cbz/cbnz, and tbz/tbnz)."""
    hex_addrs = _HEX_ADDR_RE.findall(operands)
    if not hex_addrs:
        return None
    try:
        return int(hex_addrs[-1], 16)
    except ValueError:
        return None


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
