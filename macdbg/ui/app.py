from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, TabbedContent, TabPane

from .context import ContextMenu, MultilineEditor, PromptScreen

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
        "Could not import lldb. Run via ./macdbg.sh (which sets PYTHONPATH=$(lldb -P))."
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

    DisasmPane:focus-within,
    RegistersPane:focus-within,
    HexPane:focus-within,
    MemoryPane:focus-within,
    BreakpointsPane:focus-within,
    ThreadsPane:focus-within,
    ModulesPane:focus-within,
    TracePane:focus-within,
    ConsolePane:focus-within,
    #tabs:focus-within {
        border: heavy $primary;
    }
    """

    BINDINGS = [
        Binding("f7", "step_in", "Step In"),
        Binding("f8", "step_over", "Step Over"),
        Binding("f9", "cont", "Continue"),
        Binding("f2", "toggle_bp", "Toggle BP"),
        Binding("colon", "focus_cmd", "Command", key_display=":"),
        Binding("ctrl+g", "focus_mem", "Goto Addr"),
        Binding("ctrl+t", "toggle_trace", "Trace"),
        Binding("ctrl+k", "clear_trace", "Clear Trace"),
        Binding("ctrl+y", "cycle_trace_depth", "Trace Scope"),
        Binding("ctrl+d", "defenses", "Defenses"),
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
    ]

    def __init__(
        self,
        program: Optional[str],
        program_args: List[str],
        attach_pid: Optional[int] = None,
    ) -> None:
        super().__init__()
        self.program = program
        self.program_args = program_args
        self.attach_pid = attach_pid
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
        self.title = "macdbg"
        self.sub_title = (
            "attached to pid {}".format(self.attach_pid) if self.attach_pid
            else (self.program or "(no target)")
        )
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
        if self.attach_pid:
            try:
                self.dbg.attach_pid(self.attach_pid)
                self.console_pane.write("attached to pid {}".format(self.attach_pid))
            except Exception as e:
                self.console_pane.write("attach failed: {}".format(e), error=True)
        elif self.program:
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
            if self._handle_anti_debug_hit():
                return
            if self.tracer.enabled and self._handle_possible_trace_hit():
                return
            self.console_pane.write("[event] state={} ({})".format(e.description, e.state))
            self._refresh_all()
        elif e.state == lldb.eStateExited:
            self.console_pane.write("process exited.")
        else:
            self.console_pane.write("[event] state={} ({})".format(e.description, e.state))

    def _handle_anti_debug_hit(self) -> bool:
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
        for handler in (self.dbg.handle_anti_ptrace_hit,
                        self.dbg.handle_anti_mach_hit,
                        self.dbg.handle_direct_syscall_hit,
                        self.dbg.handle_fork_hit,
                        self.dbg.handle_exec_hit):
            msg = handler(bp_id)
            if msg is not None:
                self.console_pane.write("[anti-debug] " + msg)
                return True
        return False

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

        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))
        self.threads_pane.render_rows(self.dbg.threads())
        self.modules_pane.render_rows(self.dbg.modules())

    def action_step_in(self) -> None:
        self.dbg.step_in()

    def action_step_over(self) -> None:
        self.dbg.step_over()

    def action_cont(self) -> None:
        self.dbg.cont()

    def action_toggle_bp(self) -> None:
        pc = self.dbg.pc()
        if not pc:
            return
        op, bp_id = self.dbg.toggle_breakpoint_at(pc)
        self.console_pane.write("breakpoint {} #{} @ {:#x}".format(op, bp_id, pc))
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def action_focus_cmd(self) -> None:
        self.console_pane.cmd.focus()

    def action_focus_mem(self) -> None:
        self.mem.addr_input.focus()

    def action_cycle_trace_depth(self) -> None:
        cycle = [
            (1,  "strict (immediate caller must be user code)"),
            (5,  "balanced (user code within top 5 frames)"),
            (32, "wide (any user code on the stack)"),
            (0,  "off (log every hit including framework internals)"),
        ]
        current = self.tracer.caller_depth
        for i, (depth, _) in enumerate(cycle):
            if depth == current:
                nxt = cycle[(i + 1) % len(cycle)]
                break
        else:
            nxt = cycle[1]
        self.tracer.caller_depth = nxt[0]
        self.console_pane.write("[trace] scope = {}".format(nxt[1]))

    def _hidden_bp_ids(self) -> set:
        ids = set(self.tracer._bp_to_name)
        if self.dbg.anti_ptrace_bp_id:
            ids.add(self.dbg.anti_ptrace_bp_id)
        if self.dbg.anti_mach_bp_id:
            ids.add(self.dbg.anti_mach_bp_id)
        if self.dbg.direct_syscall_bp_ids:
            ids.update(self.dbg.direct_syscall_bp_ids)
        if self.dbg.fork_bp_ids:
            ids.update(self.dbg.fork_bp_ids)
        if self.dbg.exec_bp_ids:
            ids.update(self.dbg.exec_bp_ids.keys())
        return ids

    def action_defenses(self) -> None:
        def tag(on: bool) -> str:
            return "[on] " if on else "[off]"

        items = [
            ("{}  PT_DENY_ATTACH bypass (symbol hook)".format(tag(bool(self.dbg.anti_ptrace_bp_id))),
             self._toggle_deny_attach_bypass),
            ("{}  Direct-syscall ptrace scan (mov x16,#26 / svc)".format(tag(bool(self.dbg.direct_syscall_bp_ids))),
             self._toggle_direct_syscall_scan),
            ("{}  Mach exception port cloak".format(tag(bool(self.dbg.anti_mach_bp_id))),
             self._toggle_mach_ports_cloak),
            ("{}  Hardware BPs for user breakpoints".format(tag(self.dbg.hw_breakpoints)),
             self._toggle_hw_bps),
            ("{}  Hardware BPs for tracer breakpoints".format(tag(self.tracer.hardware)),
             self._toggle_tracer_hw),
            ("Fork mode: {} (click to cycle off/suppress/identity)".format(self.dbg.fork_mode),
             self._cycle_fork_mode),
            ("{}  Outbound exec sandbox (system/popen/execve/posix_spawn)".format(tag(bool(self.dbg.exec_bp_ids))),
             self._toggle_exec_sandbox),
        ]
        w, h = self.size
        self.push_screen(ContextMenu(items, x=max(0, w // 2 - 25), y=max(0, h // 3)))

    def _toggle_deny_attach_bypass(self) -> None:
        if self.dbg.anti_ptrace_bp_id:
            _, msg = self.dbg.disable_anti_ptrace()
        else:
            _, msg = self.dbg.enable_anti_ptrace()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _toggle_hw_bps(self) -> None:
        self.dbg.hw_breakpoints = not self.dbg.hw_breakpoints
        self.console_pane.write("[anti-debug] hardware breakpoints for user BPs: {}".format(
            "ON" if self.dbg.hw_breakpoints else "OFF"))

    def _toggle_tracer_hw(self) -> None:
        if self.tracer.enabled:
            self.console_pane.write(
                "[anti-debug] disable tracer first (Ctrl+T), then flip HW mode",
                error=True,
            )
            return
        self.tracer.hardware = not self.tracer.hardware
        self.console_pane.write("[anti-debug] hardware breakpoints for tracer: {}".format(
            "ON" if self.tracer.hardware else "OFF"))

    def _toggle_mach_ports_cloak(self) -> None:
        if self.dbg.anti_mach_bp_id:
            _, msg = self.dbg.disable_anti_mach_ports()
        else:
            _, msg = self.dbg.enable_anti_mach_ports()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _toggle_direct_syscall_scan(self) -> None:
        if self.dbg.direct_syscall_bp_ids:
            _, msg = self.dbg.disable_direct_syscall_scan()
        else:
            _, msg = self.dbg.enable_direct_syscall_scan()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _cycle_fork_mode(self) -> None:
        nxt = {"off": "suppress", "suppress": "identity", "identity": "off"}[self.dbg.fork_mode]
        _, msg = self.dbg.set_fork_mode(nxt)
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _toggle_exec_sandbox(self) -> None:
        if self.dbg.exec_bp_ids:
            _, msg = self.dbg.disable_exec_sandbox()
        else:
            _, msg = self.dbg.enable_exec_sandbox()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def action_clear_trace(self) -> None:
        self.trace_pane.clear()
        self._trace_count = 0
        self.console_pane.write("[trace] cleared")

    def action_toggle_trace(self) -> None:
        if self.tracer.enabled:
            self.tracer.disable(self.dbg.target)
            self.console_pane.write("[trace] disabled")
        else:
            total, resolved = self.tracer.enable(self.dbg.target, ci=self.dbg.ci)
            if total == 0:
                self.console_pane.write("[trace] could not create breakpoints", error=True)
                return
            if resolved == 0:
                self.console_pane.write(
                    "[trace] armed {} pending symbols. Locations will resolve as libSystem loads; hits will start appearing then.".format(total)
                )
            else:
                self.console_pane.write(
                    "[trace] enabled: {}/{} symbols already resolved, the rest are pending".format(resolved, total)
                )
            try:
                self.query_one(TabbedContent).active = "tab_trace"
                self.trace_pane.table.focus()
            except Exception:
                pass
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

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
            ("bps", self.bps),
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
        elif pane == "bps":
            bp_id = self.bps.bp_id_at(row)
            if bp_id is None:
                return
            items = [
                ("Edit commands…",    lambda: self._prompt_edit_bp_commands(bp_id)),
                ("Set condition…",    lambda: self._prompt_edit_bp_condition(bp_id)),
                ("Toggle enabled",    lambda: self._toggle_bp_enabled(bp_id)),
                ("Delete",            lambda: self._delete_bp(bp_id)),
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
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

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

    def _prompt_edit_bp_commands(self, bp_id: int) -> None:
        current = "\n".join(self.dbg.bp_commands(bp_id))
        async def _run() -> None:
            val = await self.push_screen_wait(MultilineEditor(
                "Breakpoint #{} commands  (Ctrl+S saves, Esc cancels — one lldb command per line)".format(bp_id),
                initial=current,
            ))
            if val is None or val == current:
                return
            lines = [ln for ln in val.splitlines() if ln.strip()]
            if self.dbg.set_bp_commands(bp_id, lines):
                self.console_pane.write("bp #{}: set {} command(s)".format(bp_id, len(lines)))
            else:
                self.console_pane.write("bp #{}: could not set commands".format(bp_id), error=True)
            self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))
        self.run_worker(_run(), exclusive=True)

    def _prompt_edit_bp_condition(self, bp_id: int) -> None:
        current = ""
        for row in self.dbg.breakpoints():
            if row[0] == bp_id:
                current = row[5]
                break
        async def _run() -> None:
            val = await self.push_screen_wait(PromptScreen(
                "Breakpoint #{} condition  (empty = always fire)".format(bp_id),
                initial=current,
            ))
            if val is None:
                return
            self.dbg.set_bp_condition(bp_id, val.strip())
            self.console_pane.write("bp #{}: condition = {!r}".format(bp_id, val.strip()))
            self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))
        self.run_worker(_run(), exclusive=True)

    def _toggle_bp_enabled(self, bp_id: int) -> None:
        rows = self.dbg.breakpoints()
        enabled = next((r[4] for r in rows if r[0] == bp_id), True)
        self.dbg.set_bp_enabled(bp_id, not enabled)
        self.console_pane.write("bp #{}: {}".format(bp_id, "disabled" if enabled else "enabled"))
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _delete_bp(self, bp_id: int) -> None:
        if self.dbg.target:
            self.dbg.target.BreakpointDelete(bp_id)
        self.console_pane.write("bp #{} deleted".format(bp_id))
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

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
