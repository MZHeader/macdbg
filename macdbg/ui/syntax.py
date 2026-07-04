from __future__ import annotations

import re
from typing import Tuple

from rich.text import Text


COLOR_CFLOW = "bold #ff5555"
COLOR_DATA = "#5fafff"
COLOR_TRAP = "#767676"
COLOR_REG = "#d787ff"
COLOR_IMM = "#ffaf5f"
COLOR_HEX = "#ffaf5f"
COLOR_SYM = "#ffaf5f"
COLOR_WIDTH = "white"
COLOR_SHIFT = "#5fafff"

_CFLOW = {
    "bl", "blr", "br", "b", "ret", "eret", "retab", "retaa",
    "cbz", "cbnz", "tbz", "tbnz", "svc", "hvc", "smc",
    "blraa", "blrab", "blraaz", "blrabz", "braa", "brab", "braaz", "brabz",
}
_TRAP = {"brk", "hlt", "udf", "nop"}
_DATA_PREFIXES = ("ldr", "str", "ldp", "stp", "ldur", "stur", "ldnp", "stnp",
                  "ldar", "stlr", "ldax", "stlx", "ldxr", "stxr", "ldapr")
_DATA = {
    "mov", "movz", "movk", "movn", "mvn",
    "add", "adds", "sub", "subs", "neg", "negs", "adc", "sbc", "adcs", "sbcs",
    "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics",
    "cmp", "cmn", "tst", "teq", "ccmp", "ccmn", "fcmp", "fcmpe",
    "mul", "madd", "msub", "smull", "umull", "sdiv", "udiv",
    "lsl", "lsr", "asr", "ror", "sbfx", "ubfx", "bfi", "bfxil",
    "adr", "adrp",
    "csel", "csinc", "csinv", "cset", "csetm",
    "extr", "rev", "rev16", "rev32", "clz", "cls",
    "fmov", "fadd", "fsub", "fmul", "fdiv",
}


def mnemonic_style(mnemonic: str) -> str:
    m = mnemonic.strip().lower()
    if not m:
        return "white"
    if m in _CFLOW or m.startswith("b."):
        return COLOR_CFLOW
    if m in _TRAP:
        return COLOR_TRAP
    if m in _DATA:
        return COLOR_DATA
    for p in _DATA_PREFIXES:
        if m.startswith(p):
            return COLOR_DATA
    return "white"


_REG_BASE = (
    r"(?:[xw](?:[12]?\d|3[01])|[sdqvhb](?:[12]?\d|3[01])|sp|xzr|wzr|lr|fp|pc)"
)
_REG_RE = re.compile(_REG_BASE, re.IGNORECASE)
_REG_LANE_RE = re.compile(_REG_BASE + r"(\.[0-9a-zA-Z]+)?", re.IGNORECASE)
_SHIFT_KW = {"lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx",
             "sxtb", "sxth", "sxtw", "sxtx", "msl"}

_TOKEN_RE = re.compile(
    r"(?P<ws>\s+)"
    r"|(?P<imm>#-?(?:0x[0-9a-fA-F]+|\d+))"
    r"|(?P<hex>0x[0-9a-fA-F]+)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_.$@]*)"
    r"|(?P<punct>[\[\](){},!])"
    r"|(?P<other>.)"
)

_REG_COLOR = COLOR_REG
_IMM_COLOR = COLOR_IMM
_HEX_COLOR = COLOR_HEX
_SYM_COLOR = COLOR_SYM
_SHIFT_COLOR = COLOR_SHIFT


def style_operands(operands: str) -> Text:
    if not operands:
        return Text("")
    out = Text()
    for m in _TOKEN_RE.finditer(operands):
        tok = m.group(0)
        kind = m.lastgroup
        if kind == "ws":
            out.append(tok)
        elif kind == "imm":
            out.append(tok, style=_IMM_COLOR)
        elif kind == "hex":
            out.append(tok, style=_HEX_COLOR)
        elif kind == "ident":
            low = tok.lower()
            lane = _REG_LANE_RE.fullmatch(tok)
            if lane and _REG_RE.fullmatch(lane.group(0).split(".", 1)[0]):
                base_end = lane.end() - len(lane.group(1) or "")
                out.append(tok[:base_end - lane.start()], style=_REG_COLOR)
                if lane.group(1):
                    out.append(lane.group(1), style=COLOR_WIDTH)
            elif low in _SHIFT_KW:
                out.append(tok, style=_SHIFT_COLOR)
            else:
                out.append(tok, style=_SYM_COLOR)
        elif kind == "punct":
            out.append(tok, style="dim")
        else:
            out.append(tok)
    return out


def style_disasm_line(mnemonic: str, operands: str) -> Tuple[Text, Text]:
    mn = Text("{:<8}".format(mnemonic), style=mnemonic_style(mnemonic))
    op = style_operands(operands)
    return mn, op
