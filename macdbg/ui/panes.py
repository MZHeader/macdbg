from __future__ import annotations

from typing import List, Optional, Tuple

from rich.text import Text
from textual.containers import Vertical
from textual.events import Click
from textual.message import Message
from textual.widgets import DataTable, Input, RichLog, Static

from ..core.disasm import DisasmRow, format_bytes
from ..core.memory import bytes_per_row_for, hexdump_rows
from ..core.registers import RegRow
from .syntax import style_disasm_line


def _force_dimensions_settled(table: DataTable) -> None:
    """Force DataTable to compute its virtual size now so scroll_to works in
    the same tick. Otherwise add_row defers it to on_idle and the paint flashes
    before scroll finds its target."""
    if not getattr(table, "_require_update_dimensions", False):
        return
    try:
        new_rows = table._new_rows.copy()
        table._new_rows.clear()
        table._require_update_dimensions = False
        table._update_dimensions(new_rows)
    except Exception:
        pass


def _settle_and_center(table: DataTable, pc_key, new_keys) -> None:
    if pc_key is None:
        return
    try:
        _force_dimensions_settled(table)
        pc_idx = table.get_row_index(pc_key)
    except Exception:
        return
    try:
        table.move_cursor(row=pc_idx, animate=False, scroll=False)
        visible = max(1, table.size.height - 2)
        target = max(0, pc_idx - visible // 2)
        table.scroll_to(y=target, animate=False, immediate=True)
    except Exception:
        pass


class RightClickTable(DataTable):
    class RightClicked(Message):
        def __init__(self, table: "RightClickTable", row: int, screen_x: int, screen_y: int) -> None:
            self.table = table
            self.row = row
            self.screen_x = screen_x
            self.screen_y = screen_y
            super().__init__()

    async def _on_click(self, event: Click) -> None:
        await super()._on_click(event)
        if event.button == 3:
            row = self.cursor_row
            self.post_message(self.RightClicked(self, row, event.screen_x, event.screen_y))


class DisasmPane(Vertical):
    DEFAULT_CSS = """
    DisasmPane { border: solid $accent; }
    DisasmPane > .title { background: $accent; color: $text; padding: 0 1; }
    DisasmPane RightClickTable > .datatable--cursor {
        background: #ffd75f;
        color: black;
        text-style: bold;
    }
    """

    def compose(self):
        self.title_widget = Static("Disassembly", classes="title")
        yield self.title_widget
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def set_status(self, browsing_addr: Optional[int] = None) -> None:
        if browsing_addr is None:
            self.title_widget.update("Disassembly")
        else:
            self.title_widget.update(
                "Disassembly  (browsing {:#x} — F5 to return to pc)".format(browsing_addr))

    def on_mount(self) -> None:
        self.table.add_columns("flow", "addr", "bytes", "insn")
        self._rows: List[DisasmRow] = []

    def row_at(self, index: int) -> Optional[DisasmRow]:
        i = self._display_to_row.get(index) if hasattr(self, "_display_to_row") else index
        if i is None:
            return None
        if 0 <= i < len(self._rows):
            return self._rows[i]
        return None

    def render_rows(self, rows: List[DisasmRow], center_addr: Optional[int] = None) -> None:
        self._rows = list(rows)
        self._display_to_row = {}
        self.table.clear()
        pc_row_key = None
        center_row_key = None
        new_keys = []
        display_idx = 0
        for row_idx, r in enumerate(rows):
            if r.function_head:
                head = Text.assemble(
                    ("▼ ", "bold #5fd7ff"),
                    (r.function_head + ":", "bold #5fd7ff"),
                )
                banner_key = self.table.add_row(Text(""), Text(""), Text(""), head)
                new_keys.append(banner_key)
                display_idx += 1
            gutter = Text(r.gutter, style="#767676")
            if r.gutter_styles:
                for start, end, style in r.gutter_styles:
                    if end > start:
                        gutter.stylize(style, start, end)
            # A red ● in front of the address marks a breakpoint on this line
            # (hollow ○ when the breakpoint is disabled), like x64dbg's gutter.
            if r.has_breakpoint:
                dot, dot_style = ("●", "bold #ff5f5f") if r.bp_enabled else ("○", "#af5f5f")
                addr = Text.assemble((dot + " ", dot_style), "{:016x}".format(r.addr))
            else:
                addr = Text("  {:016x}".format(r.addr))
            bytez = Text(format_bytes(r.raw))
            mn, op = style_disasm_line(r.mnemonic, r.operands)
            insn = Text.assemble(mn, " ", op)
            if r.comment:
                insn.append("  ; " + r.comment, style="dim green")
            if r.inline_hint:
                insn.append("  ; " + r.inline_hint, style="#5fafff")
            if r.user_comment:
                insn.append("  ← " + r.user_comment, style="bold #ffd75f")
            key = self.table.add_row(gutter, addr, bytez, insn)
            new_keys.append(key)
            self._display_to_row[display_idx] = row_idx
            display_idx += 1
            if r.is_pc:
                pc_row_key = key
            if center_addr is not None and r.addr == center_addr:
                center_row_key = key
        _settle_and_center(self.table, pc_row_key or center_row_key, new_keys)


class RegistersPane(Vertical):
    DEFAULT_CSS = """
    RegistersPane { border: solid $accent; }
    RegistersPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Registers", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False, show_header=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("name", "value")

    def render_rows(self, rows: List[RegRow]) -> None:
        self.table.clear()
        for r in rows:
            name = Text(r.name, style="cyan")
            val = Text(r.value or "?", style="red bold" if r.changed else "white")
            if r.annotation:
                val.append("  " + r.annotation, style="green")
            self.table.add_row(name, val)


class HexPane(Vertical):
    DEFAULT_CSS = """
    HexPane { border: solid $accent; }
    HexPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def __init__(self, title: str = "Memory", **kw):
        super().__init__(**kw)
        self._title = title

    def compose(self):
        yield Static(self._title, classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False, show_header=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("addr", "hex", "ascii")

    def render_bytes(
        self,
        base: int,
        data: bytes,
        focus_addr: Optional[int] = None,
        focus_len: int = 1,
        preserve_scroll: bool = False,
    ) -> None:
        self.table.clear()
        focus_row = None
        width = bytes_per_row_for(self.size.width)
        rows = hexdump_rows(data, base, width=width)
        focus_end = focus_addr + focus_len if focus_addr is not None else None
        for idx, (addr, hex_part, ascii_part) in enumerate(rows):
            addr_txt = Text("{:016x}".format(addr), style="cyan")
            hex_txt = Text(hex_part)
            ascii_txt = Text(ascii_part, style="green")
            if focus_addr is not None and addr + width > focus_addr and addr < focus_end:
                lo = max(0, focus_addr - addr)
                hi = min(width, focus_end - addr)
                if focus_row is None and addr <= focus_addr < addr + width:
                    focus_row = idx
                    addr_txt.stylize("bold black on yellow")
                hex_start = lo * 3
                hex_end = hi * 3 - 1 if hi > 0 else 0
                hex_txt.stylize("bold black on yellow", hex_start, hex_end)
                ascii_txt.stylize("bold black on yellow", lo, hi)
            self.table.add_row(addr_txt, hex_txt, ascii_txt)
        if focus_row is not None and not preserve_scroll:
            self._center_on(focus_row)

    def _center_on(self, focus_row: int, top_bias: int = 3) -> None:
        """Center the cursor on `focus_row`, biased so 1/top_bias of the visible
        rows sit above it. Settles the virtual size first to avoid a flash."""
        try:
            _force_dimensions_settled(self.table)
            self.table.move_cursor(row=focus_row, animate=False, scroll=False)
            visible = max(1, self.table.size.height - 2)
            offset = max(1, visible // top_bias)
            target = max(0, focus_row - offset)
            self.table.scroll_to(y=target, animate=False, immediate=True)
        except Exception:
            pass


class BreakpointsPane(Vertical):
    DEFAULT_CSS = """
    BreakpointsPane { border: solid $accent; }
    BreakpointsPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Breakpoints  (right-click to edit commands / condition)", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table
        self._ids: List[int] = []

    def on_mount(self) -> None:
        self.table.add_columns("id", "addr", "symbol", "cmds", "cond", "en")

    def bp_id_at(self, idx: int) -> Optional[int]:
        if 0 <= idx < len(self._ids):
            return self._ids[idx]
        return None

    def render_rows(self, rows) -> None:
        self.table.clear()
        self._ids = []
        for bp_id, addr, desc, ncmds, enabled, cond in rows:
            self._ids.append(bp_id)
            en_txt = Text("✓" if enabled else "×", style="green" if enabled else "red")
            cmd_txt = Text(str(ncmds) if ncmds else "-",
                           style="yellow bold" if ncmds else "dim")
            cond_short = (cond[:24] + "…") if len(cond) > 24 else cond
            self.table.add_row(
                Text(str(bp_id)),
                Text("{:016x}".format(addr), style="cyan"),
                Text(desc),
                cmd_txt,
                Text(cond_short, style="magenta"),
                en_txt,
            )


class ThreadsPane(Vertical):
    DEFAULT_CSS = """
    ThreadsPane { border: solid $accent; }
    ThreadsPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Threads", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("tid", "#", "name", "pc", "function")

    def render_rows(self, rows) -> None:
        self.table.clear()
        for tid, idx, name, pc, func in rows:
            selected = name.startswith("*")
            style = "bold yellow" if selected else "white"
            self.table.add_row(
                Text(str(tid), style=style),
                Text(str(idx), style=style),
                Text(name, style=style),
                Text("{:016x}".format(pc), style="cyan"),
                Text(func, style=style),
            )


class ModulesPane(Vertical):
    DEFAULT_CSS = """
    ModulesPane { border: solid $accent; }
    ModulesPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Modules", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("name", "base", "size", "triple")

    def render_rows(self, rows) -> None:
        self.table.clear()
        for name, base, size, triple in rows:
            self.table.add_row(
                Text(name, style="bold"),
                Text("{:016x}".format(base), style="cyan"),
                Text("{:#x}".format(size)),
                Text(triple, style="dim"),
            )


class StringsPane(Vertical):
    DEFAULT_CSS = """
    StringsPane { border: solid $accent; }
    StringsPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        self.title_widget = Static("Strings", classes="title")
        yield self.title_widget
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("src", "addr", "len", "string")
        self._rows = []

    def row_at(self, idx: int):
        if 0 <= idx < len(self._rows):
            return self._rows[idx]
        return None

    def render_rows(self, rows) -> None:
        self._rows = list(rows)
        self.table.clear()
        counts = {"bin": 0, "live": 0}
        for origin, addr, s in rows:
            counts[origin] = counts.get(origin, 0) + 1
            src_style = "#5fafff" if origin == "bin" else "#ffaf5f"
            self.table.add_row(
                Text(origin, style=src_style),
                Text("{:016x}".format(addr), style="cyan"),
                Text(str(len(s)), style="dim"),
                Text(s[:200], style="green"),
            )
        self.title_widget.update(
            "Strings  ({} bin, {} live)".format(counts.get("bin", 0), counts.get("live", 0)))


class PatchesPane(Vertical):
    DEFAULT_CSS = """
    PatchesPane { border: solid $accent; }
    PatchesPane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        self.title_widget = Static("Patches", classes="title")
        yield self.title_widget
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("#", "addr", "orig", "new", "size")
        self._patches = []

    def patch_at(self, idx: int):
        if 0 <= idx < len(self._patches):
            return self._patches[idx]
        return None

    def render_rows(self, patches) -> None:
        self._patches = list(patches)
        self.table.clear()
        for i, p in enumerate(patches):
            def _hex(b: bytes) -> str:
                s = b[:16].hex(" ")
                return s + (" …" if len(b) > 16 else "")
            self.table.add_row(
                Text(str(i), style="dim"),
                Text("{:016x}".format(p.addr), style="cyan"),
                Text(_hex(p.orig), style="#ff8787"),
                Text(_hex(p.new), style="#87d75f"),
                Text(str(len(p.new)), style="dim"),
            )
        self.title_widget.update("Patches  ({} tracked)".format(len(patches)))


class BacktracePane(Vertical):
    DEFAULT_CSS = """
    BacktracePane { border: solid $accent; }
    BacktracePane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Call Stack", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("#", "pc", "function", "module")

    def render_rows(self, rows) -> None:
        self.table.clear()
        for idx, pc, fn, mod in rows:
            self.table.add_row(
                Text(str(idx), style="dim"),
                Text("{:016x}".format(pc), style="cyan"),
                Text(fn),
                Text(mod, style="dim"),
            )


class TracePane(Vertical):
    DEFAULT_CSS = """
    TracePane { border: solid $accent; }
    TracePane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        self.title_widget = Static(
            "Trace  (Ctrl+T toggles — arrow keys / mouse wheel to scroll)",
            classes="title",
        )
        yield self.title_widget
        self.table = RightClickTable(
            cursor_type="row",
            zebra_stripes=True,
            show_header=True,
            show_row_labels=False,
        )
        yield self.table

    def set_status(self, enabled: bool, scope: str) -> None:
        state = "ON" if enabled else "off"
        self.title_widget.update(
            "Trace  [{}, scope: {}]  (Ctrl+T toggles, Ctrl+Y scope)".format(state, scope))

    def on_mount(self) -> None:
        self.table.add_column("#", width=5)
        self.table.add_column("cat", width=5)
        self.table.add_column("call")
        self._n_hits = 0
        self._all_hits: List[Tuple[int, str, str]] = []
        self.category_filter = {"FILE": True, "NET": True, "PROC": True}
        self.table.can_focus = True

    def _row_style(self, category: str):
        return {"FILE": "cyan", "NET": "magenta", "PROC": "yellow"}.get(category, "white")

    def _append_visible(self, n: int, category: str, call: str) -> None:
        style = self._row_style(category)
        self.table.add_row(
            Text("{:>4}".format(n), style="dim"),
            Text(category, style=style + " bold"),
            Text(call, style="white"),
        )

    def _rebuild(self) -> None:
        self.table.clear()
        for n, cat, call in self._all_hits:
            if self.category_filter.get(cat, True):
                self._append_visible(n, cat, call)

    def add_hit(self, n: int, category: str, call: str) -> None:
        self._all_hits.append((n, category, call))
        self._n_hits += 1
        if not self.category_filter.get(category, True):
            return
        at_bottom = self.table.cursor_row >= self.table.row_count - 1
        self._append_visible(n, category, call)
        if at_bottom:
            try:
                self.table.action_scroll_end()
                self.table.move_cursor(row=self.table.row_count - 1, animate=False)
            except Exception:
                pass

    def set_category_filter(self, category: str, enabled: bool) -> None:
        if category not in self.category_filter:
            return
        self.category_filter[category] = enabled
        self._rebuild()

    def all_hits(self):
        return list(self._all_hits)

    def clear(self) -> None:
        self.table.clear()
        self._all_hits = []
        self._n_hits = 0


class ConsolePane(Vertical):
    DEFAULT_CSS = """
    ConsolePane { border: solid $accent; }
    ConsolePane > .title { background: $accent; color: $text; padding: 0 1; }
    ConsolePane > RichLog { height: 1fr; }
    ConsolePane > Input { dock: bottom; }
    """

    def compose(self):
        yield Static("Console  (type `:` to focus, Enter to run lldb command)", classes="title")
        self.log_view = RichLog(highlight=True, markup=False, wrap=False, auto_scroll=True)
        yield self.log_view
        self.cmd = Input(placeholder="lldb> ", id="cmd_input")
        yield self.cmd

    def write(self, text: str, error: bool = False) -> None:
        style = "red" if error else "white"
        for line in text.rstrip("\n").splitlines() or [""]:
            self.log_view.write(Text(line, style=style))


class WatchPane(HexPane):
    """A pinned mini-hexdump. The address stays put on step; only the bytes
    refresh. Bind one with Follow in Watch N."""

    def __init__(self, slot: int, **kw):
        super().__init__(title="Watch {}".format(slot), **kw)
        self._slot = slot
        self._binding: Optional[Tuple[int, int, str]] = None

    def compose(self):
        self.title_widget = Static(
            "Watch {}  (empty)".format(self._slot), classes="title")
        yield self.title_widget
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False, show_header=False)
        yield self.table

    @property
    def slot(self) -> int:
        return self._slot

    def binding(self) -> Optional[Tuple[int, int, str]]:
        return self._binding

    def set_binding(self, addr: int, length: int, label: str = "") -> None:
        self._binding = (addr, length, label)
        self._update_title()

    def clear_binding(self) -> None:
        self._binding = None
        self.table.clear()
        self._update_title()

    def _update_title(self) -> None:
        if self._binding is None:
            self.title_widget.update("Watch {}  (empty)".format(self._slot))
            return
        addr, length, label = self._binding
        head = "Watch {}  {:#x}  ({} bytes)".format(self._slot, addr, length)
        if label:
            head += "  — " + label
        self.title_widget.update(head)


class MemoryPane(HexPane):
    DEFAULT_CSS = HexPane.DEFAULT_CSS + """
    MemoryPane > Input { dock: top; }
    """

    def compose(self):
        self.title_widget = Static("Memory  (Ctrl+G to focus address)", classes="title")
        yield self.title_widget
        self.addr_input = Input(placeholder="0x... address to follow", id="mem_addr")
        yield self.addr_input
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False, show_header=False)
        yield self.table

    def sync_follow(self, addr: Optional[int], extra: str = "") -> None:
        if addr is None:
            self.addr_input.value = ""
            self.title_widget.update("Memory  (Ctrl+G to focus address)")
            return
        addr_s = "{:#x}".format(addr)
        if self.addr_input.value != addr_s and not self.addr_input.has_focus:
            self.addr_input.value = addr_s
        suffix = ("  " + extra) if extra else ""
        self.title_widget.update("Memory  ({}{})".format(addr_s, suffix))
