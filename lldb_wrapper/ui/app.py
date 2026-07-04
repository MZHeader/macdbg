from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, TabbedContent, TabPane

from .context import ContextMenu, PromptScreen

from ..core.debugger import Debugger
from ..core.disasm import disasm_around, extract_addr
from ..core.events import EventPump, OutputEvent, StopEvent
from ..core.registers import collect as collect_regs, snapshot as reg_snapshot
from ..core.tracer import Tracer
from .palette import LldbCommandProvider
from .panes import (
    BreakpointsPane,
    ConsolePane,
    DisasmPane,
    HexPane,
    MemoryPane,
    ModulesPane,
    RegistersPane,
    RightClickTable,
    ThreadsPane,
    TracePane,
)


def _parse_bytes(s: str) -> Optional[bytes]:
    s = s.strip()
    if not s:
        return None
    parts = s.split()
    try:
        if len(parts) == 1 and len(parts[0]) > 2:
            hex_str = parts[0][2:] if parts[0].startswith("0x") else parts[0]
            if len(hex_str) % 2:
                return None
            return bytes.fromhex(hex_str)
        out = bytearray()
        for p in parts:
            p = p[2:] if p.startswith("0x") else p
            if not p or len(p) > 2:
                return None
            out.append(int(p, 16))
        return bytes(out)
    except ValueError:
        return None


try:
    import lldb
except ImportError as e:
    raise SystemExit(
        "Could not import lldb. Run via ./run.sh (which sets PYTHONPATH=$(lldb -P))."
    ) from e


class WrapperApp(App):
    COMMANDS = App.COMMANDS | {LldbCommandProvider}

    CSS = """
    Screen { layout: vertical; }
    #top { height: 35%; layout: horizontal; }
    #mid { height: 25%; layout: horizontal; }
    #bot { height: 1fr; layout: horizontal; }
    DisasmPane      { width: 2fr; }
    RegistersPane   { width: 1fr; }
    HexPane, MemoryPane { width: 1fr; }
    #tabs           { width: 3fr; border: solid $accent; }
    ConsolePane     { width: 2fr; }
    TracePane RightClickTable { height: 1fr; }
    """

    BINDINGS = [
        Binding("f7", "step_in", "Step In"),
        Binding("f8", "step_over", "Step Over"),
        Binding("shift+f7", "step_in_src", "Step In (src)"),
        Binding("shift+f8", "step_over_src", "Step Over (src)"),
        Binding("f9", "cont", "Continue"),
        Binding("f2", "toggle_bp", "Toggle BP"),
        Binding("colon", "focus_cmd", "Command", key_display=":"),
        Binding("ctrl+g", "focus_mem", "Goto Addr"),
        Binding("f5", "mem_scroll(-1)", "Mem ↑"),
        Binding("f6", "mem_scroll(1)", "Mem ↓"),
        Binding("ctrl+t", "toggle_trace", "Trace"),
        Binding("ctrl+k", "clear_trace", "Clear Trace"),
        Binding("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self, program: Optional[str], program_args: List[str]) -> None:
        super().__init__()
        self.program = program
        self.program_args = program_args
        self.dbg = Debugger()
        self.pump: Optional[EventPump] = None
        self._prev_regs: Dict[str, str] = {}
        self._mem_follow: Optional[int] = None
        self.tracer = Tracer()
        self._trace_count = 0
        self._output_stop = threading.Event()
        self._output_thread: Optional[threading.Thread] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        self.disasm = DisasmPane()
        self.regs = RegistersPane()
        self.stack = HexPane(title="Stack")
        self.mem = MemoryPane(title="Memory")
        self.bps = BreakpointsPane()
        self.threads_pane = ThreadsPane()
        self.modules_pane = ModulesPane()
        self.trace_pane = TracePane()
        self.console_pane = ConsolePane()

        with Horizontal(id="top"):
            yield self.disasm
            yield self.regs
        with Horizontal(id="mid"):
            yield self.stack
            yield self.mem
        with Horizontal(id="bot"):
            with TabbedContent(id="tabs"):
                with TabPane("Breakpoints", id="tab_bps"):
                    yield self.bps
                with TabPane("Threads", id="tab_threads"):
                    yield self.threads_pane
                with TabPane("Modules", id="tab_modules"):
                    yield self.modules_pane
                with TabPane("Trace", id="tab_trace"):
                    yield self.trace_pane
            yield self.console_pane
        yield Footer()

    def on_mount(self) -> None:
        self.title = "lldb-wrapper"
        self.sub_title = self.program or "(no target)"
        self.pump = EventPump(
            self.dbg.listener,
            on_stop=lambda e: self.call_from_thread(self._on_stop_event, e),
            on_output=lambda e: self.call_from_thread(self._on_output_event, e),
        )
        self.pump.start()
        self._output_thread = threading.Thread(
            target=self._pump_lldb_output, name="lldb-output", daemon=True,
        )
        self._output_thread.start()
        if self.program:
            try:
                self.dbg.create_target(self.program)
                self.dbg.launch([self.program] + list(self.program_args))
                self.console_pane.write("launched {}".format(self.program))
            except Exception as e:
                self.console_pane.write("launch failed: {}".format(e), error=True)

    def on_unmount(self) -> None:
        if self.pump:
            self.pump.stop()
        self._output_stop.set()
        try:
            self.dbg.destroy()
        except Exception:
            pass

    def _pump_lldb_output(self) -> None:
        while not self._output_stop.is_set():
            text = self.dbg.read_output()
            if text:
                self.call_from_thread(self.console_pane.write, text)
            else:
                time.sleep(0.05)

    def _on_stop_event(self, e: StopEvent) -> None:
        if e.state == lldb.eStateStopped:
            if self.tracer.enabled and self._handle_possible_trace_hit():
                return
            self.console_pane.write("[event] state={} ({})".format(e.description, e.state))
            self._refresh_all()
        elif e.state == lldb.eStateExited:
            self.console_pane.write("process exited.")
        else:
            self.console_pane.write("[event] state={} ({})".format(e.description, e.state))

    def _handle_possible_trace_hit(self) -> bool:
        process = self.dbg.process
        if not process or not process.IsValid():
            return False
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return False
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        if thread.GetStopReasonDataCount() < 1:
            return False
        bp_id = thread.GetStopReasonDataAtIndex(0)
        if not self.tracer.is_trace_bp(bp_id):
            return False
        frame = thread.GetFrameAtIndex(0)
        hit = self.tracer.hit_from(frame, process)
        if hit is not None:
            self._trace_count += 1
            self.trace_pane.add_hit(self._trace_count, hit.category, hit.call)
        process.Continue()
        return True

    def _on_output_event(self, e: OutputEvent) -> None:
        self.console_pane.write(e.text, error=e.is_error)

    def _refresh_all(self) -> None:
        frame = self.dbg.frame()
        pc = self.dbg.pc() or 0
        sp = self.dbg.sp() or 0

        if self.dbg.target:
            rows = disasm_around(self.dbg.target, pc, count=40)
            self.disasm.render_rows(rows)

        reg_rows = collect_regs(
            frame,
            self._prev_regs,
            read_mem=self.dbg.read_memory,
            target=self.dbg.target,
        )
        self.regs.render_rows(reg_rows)
        self._prev_regs = reg_snapshot(reg_rows)

        if sp:
            data = self.dbg.read_memory(sp, 16 * 64)
            self.stack.render_bytes(sp, data)

        follow = self._mem_follow if self._mem_follow is not None else pc
        if follow:
            data = self.dbg.read_memory(follow, 16 * 64)
            self.mem.render_bytes(follow, data)

        self.bps.render_rows(self.dbg.breakpoints())
        self.threads_pane.render_rows(self.dbg.threads())
        self.modules_pane.render_rows(self.dbg.modules())

    def action_step_in(self) -> None:
        self.dbg.step_in()

    def action_step_over(self) -> None:
        self.dbg.step_over()

    def action_step_in_src(self) -> None:
        self.dbg.step_in_source()

    def action_step_over_src(self) -> None:
        self.dbg.step_over_source()

    def action_cont(self) -> None:
        self.dbg.cont()

    def action_toggle_bp(self) -> None:
        pc = self.dbg.pc()
        if not pc:
            return
        op, bp_id = self.dbg.toggle_breakpoint_at(pc)
        self.console_pane.write("breakpoint {} #{} @ {:#x}".format(op, bp_id, pc))
        self.bps.render_rows(self.dbg.breakpoints())

    def action_focus_cmd(self) -> None:
        self.console_pane.cmd.focus()

    def action_focus_mem(self) -> None:
        self.mem.addr_input.focus()

    def action_clear_trace(self) -> None:
        self.trace_pane.clear()
        self._trace_count = 0
        self.console_pane.write("[trace] cleared")

    def action_toggle_trace(self) -> None:
        if self.tracer.enabled:
            self.tracer.disable(self.dbg.target)
            self.console_pane.write("[trace] disabled")
        else:
            n = self.tracer.enable(self.dbg.target)
            if n == 0:
                self.console_pane.write(
                    "[trace] no symbols matched (still at entry? libSystem may not be loaded yet — F9 to run past dyld first)",
                    error=True,
                )
                return
            self.console_pane.write("[trace] enabled — watching {} symbols".format(n))
            try:
                self.query_one(TabbedContent).active = "tab_trace"
                self.trace_pane.table.focus()
            except Exception:
                pass
        self.bps.render_rows(self.dbg.breakpoints())

    def action_mem_scroll(self, direction: int) -> None:
        base = self._mem_follow if self._mem_follow is not None else (self.dbg.pc() or 0)
        if not base:
            return
        step = 16 * 32
        new_base = max(0, base + direction * step)
        self._follow_memory(new_base)

    _RELAUNCH_ALIASES = ("run", "r", "process launch")
    _DELETE_ALL_ALIASES = ("br del", "breakpoint delete")

    def _preempt_interactive(self, command: str) -> None:
        c = command.strip()
        cl = c.lower()
        if any(cl == a or cl.startswith(a + " ") for a in self._RELAUNCH_ALIASES):
            if self.dbg.process and self.dbg.process.IsValid() and self.dbg.process.GetState() not in (
                lldb.eStateExited, lldb.eStateInvalid,
            ):
                self.dbg.process.Kill()
                self.console_pane.write("[wrapper] killed existing process before relaunch")
        elif cl in self._DELETE_ALL_ALIASES:
            self.dbg.handle_command("breakpoint delete -f")

    def _run_palette_command(self, command: str) -> None:
        self.console_pane.write("> " + command)
        self._preempt_interactive(command)
        ok, out, err = self.dbg.handle_command(command)
        if out:
            self.console_pane.write(out)
        if err:
            self.console_pane.write(err, error=True)
        if self.dbg.ensure_listening():
            self.console_pane.write("[wrapper] re-hooked event listener to new process")
            self._prev_regs = {}
            self._mem_follow = None
        if self.dbg.process and self.dbg.process.GetState() == lldb.eStateStopped:
            self._refresh_all()

    def on_right_click_table_right_clicked(self, event: RightClickTable.RightClicked) -> None:
        for pane_name, pane in (
            ("regs", self.regs), ("disasm", self.disasm),
            ("mem", self.mem), ("stack", self.stack),
        ):
            if event.table is pane.table:
                self._open_menu_for(pane_name, event.row, event.screen_x, event.screen_y)
                return

    def _open_menu_for(self, pane: str, row: int, x: int, y: int) -> None:
        items = []
        if pane == "regs":
            reg_row = self._reg_row_at(row)
            if reg_row is None:
                return
            addr = self._parse_hex(reg_row.value)
            items = [
                ("Goto (follow in Memory)", lambda: self._follow_memory(addr) if addr else None),
                ("Set breakpoint at value",  lambda: self._toggle_bp(addr) if addr else None),
                ("Edit value…",              lambda: self._prompt_edit_reg(reg_row.name, reg_row.value)),
                ("Copy value",               lambda: self._copy(reg_row.value)),
            ]
            if reg_row.annotation:
                ann = reg_row.annotation
                if ann.startswith('"') and ann.endswith('"'):
                    ann = ann[1:-1]
                items.append(("Copy annotation ({})".format(ann[:24]),
                              lambda a=ann: self._copy(a)))
        elif pane == "disasm":
            drow = self.disasm.row_at(row)
            if drow is None:
                return
            target = extract_addr(drow.operands) or drow.addr
            items = [
                ("Goto (follow operand in Memory)", lambda: self._follow_memory(target)),
                ("Toggle breakpoint here",          lambda: self._toggle_bp(drow.addr)),
                ("Run to cursor",                   lambda: self._run_to(drow.addr)),
                ("Copy address",                    lambda: self._copy("{:#x}".format(drow.addr))),
            ]
        elif pane in ("mem", "stack"):
            base = self._hex_row_addr(pane, row)
            if base is None:
                return
            items = [
                ("Goto qword here (follow ptr)",  lambda: self._follow_qword(base)),
                ("Set watchpoint on this addr",   lambda: self._set_watchpoint(base)),
                ("Edit bytes at this row…",       lambda: self._prompt_edit_mem(base)),
                ("Copy address",                  lambda: self._copy("{:#x}".format(base))),
            ]
        if items:
            self.push_screen(ContextMenu(items, x=max(0, x), y=max(0, y)))

    def _reg_row_at(self, idx: int):
        frame = self.dbg.frame()
        if frame is None:
            return None
        rows = collect_regs(frame, self._prev_regs, read_mem=self.dbg.read_memory, target=self.dbg.target)
        return rows[idx] if 0 <= idx < len(rows) else None

    def _hex_row_addr(self, pane: str, idx: int) -> Optional[int]:
        table = self.mem.table if pane == "mem" else self.stack.table
        if not (0 <= idx < table.row_count):
            return None
        row = table.get_row_at(idx)
        cell = row[0]
        s = cell if isinstance(cell, str) else getattr(cell, "plain", str(cell))
        return self._parse_hex(s)

    @staticmethod
    def _parse_hex(s: str) -> Optional[int]:
        s = s.strip()
        if not s:
            return None
        try:
            return int(s, 16) if not s.startswith("0x") else int(s, 16)
        except ValueError:
            try:
                return int(s)
            except ValueError:
                return None

    def _toggle_bp(self, addr: int) -> None:
        op, bp_id = self.dbg.toggle_breakpoint_at(addr)
        self.console_pane.write("breakpoint {} #{} @ {:#x}".format(op, bp_id, addr))
        self.bps.render_rows(self.dbg.breakpoints())

    def _run_to(self, addr: int) -> None:
        self._run_palette_command("breakpoint set -o true -a {:#x}".format(addr))
        self._run_palette_command("continue")

    def _follow_qword(self, addr: int) -> None:
        data = self.dbg.read_memory(addr, 8)
        if len(data) == 8:
            ptr = int.from_bytes(data, "little")
            self._follow_memory(ptr)
        else:
            self.console_pane.write("could not read qword at {:#x}".format(addr), error=True)

    def _set_watchpoint(self, addr: int) -> None:
        self._run_palette_command("watchpoint set expression -w read_write -- {:#x}".format(addr))

    def _copy(self, text: str) -> None:
        import subprocess
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode())
            if p.returncode == 0:
                self.console_pane.write("[copied] {}".format(text))
                return
        except Exception:
            pass
        try:
            self.copy_to_clipboard(text)
            self.console_pane.write("[copied via OSC 52] {}".format(text))
        except Exception as e:
            self.console_pane.write("clipboard failed: {} (value: {})".format(e, text), error=True)

    def _prompt_edit_reg(self, name: str, current: str) -> None:
        async def _run() -> None:
            val = await self.push_screen_wait(PromptScreen(
                "Edit register {}  —  Ctrl+U clears, Enter writes, Esc cancels".format(name),
                initial=current,
            ))
            if val is None or val.strip() == "" or val.strip() == current.strip():
                return
            try:
                new_val = int(val.strip(), 0)
            except ValueError:
                self.console_pane.write("bad register value: {!r}".format(val), error=True)
                return
            ok, msg = self.dbg.write_register(name, new_val)
            self.console_pane.write(msg, error=not ok)
            self._refresh_all()
        self.run_worker(_run(), exclusive=True)

    def _prompt_edit_mem(self, addr: int) -> None:
        current_bytes = self.dbg.read_memory(addr, 16)
        current_str = " ".join("{:02x}".format(b) for b in current_bytes)

        async def _run() -> None:
            val = await self.push_screen_wait(PromptScreen(
                "Write bytes at {:#x}  —  space-separated hex bytes  "
                "(Ctrl+U clears, Enter writes, Esc cancels)".format(addr),
                initial=current_str,
            ))
            if val is None or val.strip() == "" or val.strip() == current_str.strip():
                return
            data = _parse_bytes(val)
            if data is None:
                self.console_pane.write(
                    "bad byte string {!r} — expected hex like 'de c0 ad de'".format(val),
                    error=True,
                )
                return
            ok, msg = self.dbg.write_memory(addr, data)
            self.console_pane.write(msg, error=not ok)
            self._refresh_all()
        self.run_worker(_run(), exclusive=True)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table is not self.disasm.table:
            return
        row = self.disasm.row_at(event.cursor_row)
        if row is None:
            return
        target = extract_addr(row.operands) or row.addr
        self._follow_memory(target)

    def _follow_memory(self, addr: int) -> None:
        self._mem_follow = addr
        data = self.dbg.read_memory(addr, 16 * 64)
        self.mem.render_bytes(addr, data)
        self.console_pane.write("follow -> {:#x}".format(addr))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "cmd_input":
            cmd = event.value.strip()
            event.input.value = ""
            if not cmd:
                return
            self.console_pane.write("> " + cmd)
            self._preempt_interactive(cmd)
            ok, out, err = self.dbg.handle_command(cmd)
            if out:
                self.console_pane.write(out)
            if err:
                self.console_pane.write(err, error=True)
            if self.dbg.ensure_listening():
                self.console_pane.write("[wrapper] re-hooked event listener to new process")
                self._prev_regs = {}
                self._mem_follow = None
            if self.dbg.process and self.dbg.process.GetState() == lldb.eStateStopped:
                self._refresh_all()
        elif event.input.id == "mem_addr":
            text = event.value.strip()
            try:
                addr = int(text, 0)
                self._mem_follow = addr
                data = self.dbg.read_memory(addr, 16 * 64)
                self.mem.render_bytes(addr, data)
            except ValueError:
                self.console_pane.write("bad address: {}".format(text), error=True)
