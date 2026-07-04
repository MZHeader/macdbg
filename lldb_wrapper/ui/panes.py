from __future__ import annotations

from typing import List, Optional, Tuple

from rich.text import Text
from textual.containers import Vertical
from textual.events import Click
from textual.message import Message
from textual.widgets import DataTable, Input, RichLog, Static

from ..core.disasm import DisasmRow, format_bytes
from ..core.memory import hexdump_rows
from ..core.registers import RegRow


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
    """

    def compose(self):
        yield Static("Disassembly", classes="title")
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False)
        yield self.table

    def on_mount(self) -> None:
        self.table.add_columns("addr", "bytes", "insn")
        self._rows: List[DisasmRow] = []

    def row_at(self, index: int) -> Optional[DisasmRow]:
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None

    def render_rows(self, rows: List[DisasmRow]) -> None:
        self._rows = list(rows)
        self.table.clear()
        pc_row_key = None
        for r in rows:
            addr = Text("{:016x}".format(r.addr))
            bytez = Text(format_bytes(r.raw))
            insn = Text("{:<8} {}".format(r.mnemonic, r.operands))
            if r.comment:
                insn.append("  ; " + r.comment, style="dim")
            if r.is_pc:
                addr.stylize("bold black on yellow")
                bytez.stylize("black on yellow")
                insn.stylize("bold black on yellow")
            key = self.table.add_row(addr, bytez, insn)
            if r.is_pc:
                pc_row_key = key
        if pc_row_key is not None:
            try:
                pc_idx = self.table.get_row_index(pc_row_key)
                self.table.move_cursor(row=pc_idx, animate=False)
                visible = max(1, self.table.size.height - 2)
                target = max(0, pc_idx - visible // 2)
                self.table.scroll_to(y=target, animate=False)
            except Exception:
                pass


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

    def render_bytes(self, base: int, data: bytes) -> None:
        self.table.clear()
        for addr, hex_part, ascii_part in hexdump_rows(data, base):
            self.table.add_row(
                Text("{:016x}".format(addr), style="cyan"),
                Text(hex_part),
                Text(ascii_part, style="green"),
            )


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


class TracePane(Vertical):
    DEFAULT_CSS = """
    TracePane { border: solid $accent; }
    TracePane > .title { background: $accent; color: $text; padding: 0 1; }
    """

    def compose(self):
        yield Static("Trace  (Ctrl+T toggles — arrow keys / mouse wheel to scroll)", classes="title")
        self.table = RightClickTable(
            cursor_type="row",
            zebra_stripes=True,
            show_header=True,
            show_row_labels=False,
        )
        yield self.table

    def on_mount(self) -> None:
        self.table.add_column("#", width=5)
        self.table.add_column("cat", width=5)
        self.table.add_column("call")
        self._n_hits = 0
        self.table.can_focus = True

    def add_hit(self, n: int, category: str, call: str) -> None:
        colors = {"FILE": "cyan", "NET": "magenta", "PROC": "yellow"}
        style = colors.get(category, "white")
        at_bottom = self.table.cursor_row >= self.table.row_count - 1
        self.table.add_row(
            Text("{:>4}".format(n), style="dim"),
            Text(category, style=style + " bold"),
            Text(call, style="white"),
        )
        self._n_hits += 1
        if at_bottom:
            try:
                self.table.action_scroll_end()
                self.table.move_cursor(row=self.table.row_count - 1, animate=False)
            except Exception:
                pass

    def clear(self) -> None:
        self.table.clear()
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


class MemoryPane(HexPane):
    DEFAULT_CSS = HexPane.DEFAULT_CSS + """
    MemoryPane > Input { dock: top; }
    """

    def compose(self):
        yield Static("Memory  (Ctrl+G to focus address)", classes="title")
        self.addr_input = Input(placeholder="0x... address to follow", id="mem_addr")
        yield self.addr_input
        self.table = RightClickTable(cursor_type="row", zebra_stripes=False, show_header=False)
        yield self.table
