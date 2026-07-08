"""arm64 disassembly tokeniser (Tk-free).

Ports the classifier from macdbg/ui/syntax.py to plain ``(text, css_class)``
spans; the web frontend maps each class to a colour. Kept dependency-free so the
backend never imports tkinter.
"""
from __future__ import annotations

import re
from typing import List, Tuple


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


def mnemonic_class(mnemonic: str) -> str:
    m = mnemonic.strip().lower()
    if not m:
        return "mn"
    if m in _CFLOW or m.startswith("b."):
        return "mn-cflow"
    if m in _TRAP:
        return "mn-trap"
    if m in _DATA:
        return "mn-data"
    for p in _DATA_PREFIXES:
        if m.startswith(p):
            return "mn-data"
    return "mn"


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


def operand_spans(operands: str) -> List[Tuple[str, str]]:
    if not operands:
        return []
    out: List[Tuple[str, str]] = []
    for m in _TOKEN_RE.finditer(operands):
        tok = m.group(0)
        kind = m.lastgroup
        if kind == "ws":
            out.append((tok, "op"))
        elif kind == "imm":
            out.append((tok, "op-imm"))
        elif kind == "hex":
            out.append((tok, "op-hex"))
        elif kind == "ident":
            low = tok.lower()
            lane = _REG_LANE_RE.fullmatch(tok)
            if lane and _REG_RE.fullmatch(lane.group(0).split(".", 1)[0]):
                if lane.group(1):
                    base = tok[: len(tok) - len(lane.group(1))]
                    out.append((base, "op-reg"))
                    out.append((lane.group(1), "op-width"))
                else:
                    out.append((tok, "op-reg"))
            elif low in _SHIFT_KW:
                out.append((tok, "op-shift"))
            else:
                out.append((tok, "op-sym"))
        elif kind == "punct":
            out.append((tok, "op-punct"))
        else:
            out.append((tok, "op"))
    return out
