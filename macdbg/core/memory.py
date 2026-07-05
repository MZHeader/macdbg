from __future__ import annotations

from typing import List, Tuple


def hexdump_rows(data: bytes, base_addr: int, width: int = 16) -> List[Tuple[int, str, str]]:
    rows: List[Tuple[int, str, str]] = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hex_part = " ".join("{:02x}".format(b) for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append((base_addr + off, hex_part, ascii_part))
    return rows


def bytes_per_row_for(pane_width: int) -> int:
    """Pick 16 or 8 bytes per hexdump row so the ASCII column stays visible.
    Falls back to 8 when the pane is too narrow or its width isn't known yet."""
    if pane_width < 88:
        return 8
    return 16
