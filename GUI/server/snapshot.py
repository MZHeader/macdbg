"""Turn core render data (DisasmRow, RegRow, raw bytes) into JSON-serialisable
dicts the web frontend renders. Mirrors what the Tk panes drew."""
from __future__ import annotations

from typing import List, Optional

from macdbg.core.memory import hexdump_rows

from .syntax import mnemonic_class, operand_spans


def _gutter_cols(row) -> List[List[str]]:
    """4 [char, class] pairs for the branch-arrow gutter."""
    gutter = (getattr(row, "gutter", None) or "    ")[:4].ljust(4)
    classes = ["g"] * 4
    for span in (getattr(row, "gutter_styles", None) or []):
        try:
            a, e, style = span
        except (ValueError, TypeError):
            continue
        cls = "g-taken" if "5fd75f" in style else ("g-not" if "ff5f5f" in style else "g")
        for c in range(max(0, a), min(4, e)):
            classes[c] = cls
    return [[gutter[c], classes[c]] for c in range(4)]


def disasm_json(rows) -> List[dict]:
    out = []
    for r in rows:
        out.append({
            "addr": r.addr,
            "gutter": _gutter_cols(r),
            "bp": bool(r.has_breakpoint),
            "bp_on": bool(r.bp_enabled),
            "pc": bool(r.is_pc),
            "bytes": " ".join("{:02x}".format(b) for b in r.raw[:4]),
            "mn": r.mnemonic,
            "mn_cls": mnemonic_class(r.mnemonic),
            "ops": operand_spans(r.operands),
            "hint": r.inline_hint or "",
            "comment": r.comment or "",
            "note": r.user_comment or "",
            "func": r.function_head or "",
        })
    return out


def regs_json(rows) -> List[dict]:
    return [{"name": r.name, "value": r.value, "changed": bool(r.changed),
             "annot": r.annotation or ""} for r in rows]


def hex_json(base: int, data: bytes, width: int = 16,
             focus_addr: Optional[int] = None, focus_len: int = 1) -> dict:
    rows = []
    for addr, hex_part, ascii_part in hexdump_rows(data, base, width):
        rows.append({"addr": addr, "hex": hex_part, "ascii": ascii_part})
    return {"base": base, "width": width, "rows": rows,
            "focus": ({"addr": focus_addr, "len": focus_len}
                      if focus_addr is not None else None)}
