from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Input, TabbedContent, TabPane

from .context import ContextMenu, MultilineEditor, PromptScreen, ToggleMenu

from ..core.debugger import Debugger
from ..core.disasm import disasm_around, extract_addr
from ..core.events import EventPump, OutputEvent, StopEvent
from ..core.registers import collect as collect_regs, snapshot as reg_snapshot
from ..core.tracer import Tracer
from .palette import LldbCommandProvider
from .panes import (
    BacktracePane,
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
    #top { height: 33%; layout: horizontal; }
    #mid { height: 34%; layout: horizontal; }
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
        Binding("ctrl+d", "defenses", "Defenses", priority=True),
        Binding("ctrl+b", "interrupt", "Break", priority=True),
        Binding("ctrl+f", "mem_search", "Find in Mem", priority=True),
        Binding("ctrl+backslash", "toggle_scroll_lock", "Scroll Lock", priority=True),
        Binding("alt+left", "mem_back", "Mem Back", priority=True),
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
        self._annot_cache: Dict[str, str] = {}
        self._mem_follow: Optional[int] = None
        self._mem_history: List[int] = []
        self.tracer = Tracer()
        self._trace_count = 0
        self._output_stop = threading.Event()
        self._output_thread: Optional[threading.Thread] = None
        self._search_last: Optional[bytes] = None
        self._search_hits: List[int] = []
        self._search_pos: int = 0
        self._mem_follow_len: int = 1
        self._last_rendered_follow: Optional[int] = None

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
        self.backtrace_pane = BacktracePane()
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
                with TabPane("Call Stack", id="tab_backtrace"):
                    yield self.backtrace_pane
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
                restored = self.dbg.restore_stored_breakpoints()
                self.dbg.launch([self.program] + list(self.program_args))
                self.console_pane.write("launched {}".format(self.program))
                if self.dbg.state:
                    self.console_pane.write(
                        "[state] loaded sha={}… ({} bp(s), {} comment(s), {} bookmark(s))".format(
                            self.dbg.state.sha256[:12], restored,
                            len(self.dbg.state.comments),
                            len(self.dbg.state.bookmarks),
                        )
                    )
            except Exception as e:
                self.console_pane.write("launch failed: {}".format(e), error=True)
        else:
            self.console_pane.write(
                "no target loaded. relaunch with a program path or --attach <pid>, "
                "or type ':' then an lldb command (e.g. 'target create /bin/ls') to load one."
            )

    def on_unmount(self) -> None:
        if self.pump:
            self.pump.stop()
        self._output_stop.set()
        try:
            self.dbg.save_state(self._hidden_bp_ids())
        except Exception:
            pass
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
            self.console_pane.write(self._describe_stop())
            self._refresh_all()
        elif e.state == lldb.eStateExited:
            self.console_pane.write(self._describe_exit())
        else:
            self.console_pane.write("[event] state={} ({})".format(e.description, e.state))

    def _describe_exit(self) -> str:
        p = self.dbg.process
        if not p or not p.IsValid():
            return "process exited."
        code = p.GetExitStatus()
        desc = p.GetExitDescription() or ""
        base = "process exited with code {}".format(code)
        return base + (" ({})".format(desc) if desc else "") + "."

    def _describe_stop(self) -> str:
        process = self.dbg.process
        if not process or not process.IsValid():
            return "[stopped]"
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return "[stopped]"
        reason = thread.GetStopReason()
        pc = self.dbg.pc() or 0
        frame = thread.GetFrameAtIndex(0)
        sym = ""
        if frame and frame.IsValid():
            sym = frame.GetFunctionName() or (frame.GetSymbol().GetName() if frame.GetSymbol().IsValid() else "") or ""
        where = " in {}".format(sym) if sym else ""
        if reason == lldb.eStopReasonBreakpoint and thread.GetStopReasonDataCount() >= 1:
            bp_id = thread.GetStopReasonDataAtIndex(0)
            loc_id = thread.GetStopReasonDataAtIndex(1) if thread.GetStopReasonDataCount() >= 2 else 0
            bp = self.dbg.target.FindBreakpointByID(bp_id) if self.dbg.target else None
            cond = (bp.GetCondition() if bp and bp.IsValid() else None) or ""
            cond_txt = " (cond: {})".format(cond) if cond and cond.strip() not in ("", "1") else ""
            return "[stop] breakpoint #{}.{} at {:#x}{}{}".format(bp_id, loc_id, pc, where, cond_txt)
        if reason == lldb.eStopReasonWatchpoint and thread.GetStopReasonDataCount() >= 1:
            wp_id = thread.GetStopReasonDataAtIndex(0)
            return "[stop] watchpoint #{} at {:#x}{}".format(wp_id, pc, where)
        if reason == lldb.eStopReasonPlanComplete:
            return "[stop] step complete at {:#x}{}".format(pc, where)
        if reason == lldb.eStopReasonException:
            return "[stop] exception at {:#x}{}: {}".format(pc, where, thread.GetStopDescription(256))
        if reason == lldb.eStopReasonSignal and thread.GetStopReasonDataCount() >= 1:
            sig = thread.GetStopReasonDataAtIndex(0)
            return "[stop] signal {} at {:#x}{}".format(sig, pc, where)
        if reason == lldb.eStopReasonTrace:
            return "[stop] trace at {:#x}{}".format(pc, where)
        return "[stop] at {:#x}{} (reason={})".format(pc, where, reason)

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
        if self.dbg.exec_interactive:
            peeked = self.dbg.peek_exec_hit(bp_id)
            if peeked is not None:
                name, cmd = peeked
                self._prompt_exec_decision(name, cmd)
                return True
        for handler in (self.dbg.handle_anti_ptrace_hit,
                        self.dbg.handle_anti_mach_hit,
                        self.dbg.handle_direct_syscall_hit,
                        self.dbg.handle_fork_hit,
                        self.dbg.handle_setsid_hit,
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
            comments = self.dbg.state.comments if self.dbg.state else {}
            if comments:
                for r in rows:
                    c = comments.get(r.addr)
                    if c:
                        r.user_comment = c
            self.disasm.render_rows(rows)

        reg_rows = collect_regs(
            frame,
            self._prev_regs,
            read_mem=self.dbg.read_memory,
            target=self.dbg.target,
            annot_cache=self._annot_cache,
        )
        if len(self._annot_cache) > 4096:
            self._annot_cache.clear()
        self.regs.render_rows(reg_rows)
        self._prev_regs = reg_snapshot(reg_rows)

        if sp:
            base, data = self._centered_read(sp, before_rows=8)
            self.stack.render_bytes(base, data, focus_addr=sp)

        follow = self._mem_follow if self._mem_follow is not None else pc
        if follow:
            base, data = self._centered_read(follow, before_rows=32)
            preserve = (follow == self._last_rendered_follow)
            self.mem.render_bytes(base, data, focus_addr=follow,
                                  focus_len=self._mem_follow_len if self._mem_follow is not None else 1,
                                  preserve_scroll=preserve)
            self._last_rendered_follow = follow
            extra = ""
            if self._search_hits and follow in self._search_hits:
                idx = self._search_hits.index(follow)
                extra = "hit {}/{}".format(idx + 1, len(self._search_hits))
            self.mem.sync_follow(follow, extra=extra)

        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))
        self.threads_pane.render_rows(self.dbg.threads())
        self.modules_pane.render_rows(self.dbg.modules())
        self.backtrace_pane.render_rows(self.dbg.backtrace())

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

    def action_interrupt(self) -> None:
        if not self.dbg.process or not self.dbg.process.IsValid():
            self.console_pane.write("[wrapper] no process to interrupt", error=True)
            return
        state = self.dbg.process.GetState()
        if state == lldb.eStateRunning:
            self.dbg.interrupt()
            self.console_pane.write("[wrapper] interrupt requested")
        else:
            self.console_pane.write(
                "[wrapper] process is {} — nothing to interrupt".format(
                    lldb.SBDebugger.StateAsCString(state)))

    def action_toggle_scroll_lock(self) -> None:
        v = self.console_pane.log_view
        v.auto_scroll = not v.auto_scroll
        self.console_pane.write(
            "[wrapper] console auto-scroll: {}".format("ON" if v.auto_scroll else "PAUSED"))

    def action_mem_back(self) -> None:
        if len(self._mem_history) < 2:
            self.console_pane.write("[wrapper] no earlier memory follow", error=True)
            return
        self._mem_history.pop()
        prev = self._mem_history[-1]
        prior = self._mem_history[:]
        self._follow_memory(prev)
        self._mem_history = prior
        self.console_pane.write("mem back -> {:#x}".format(prev))

    def action_mem_search(self) -> None:
        if not self.dbg.process or not self.dbg.process.IsValid():
            self.console_pane.write("[search] no process", error=True)
            return
        state = self.dbg.process.GetState()
        if state != lldb.eStateStopped:
            self.console_pane.write("[search] process not stopped", error=True)
            return
        async def _run() -> None:
            val = await self.push_screen_wait(PromptScreen(
                "Search memory  —  ASCII (e.g. 'firefox') or hex ('de ad be ef' / '0xdeadbeef'). "
                "Prefix 'all:' to include libraries. Enter alone repeats last search.",
                initial="",
            ))
            if val is None:
                return
            v = val.strip()
            if not v:
                if not self._search_hits:
                    self.console_pane.write("[search] no previous search to repeat", error=True)
                    return
                self._search_pos = (self._search_pos + 1) % len(self._search_hits)
                addr = self._search_hits[self._search_pos]
                self._follow_memory(addr, focus_len=len(self._search_last or b"") or 1)
                self.console_pane.write("[search] hit {}/{} at {:#x}".format(
                    self._search_pos + 1, len(self._search_hits), addr))
                return
            scope = "target"
            if v.lower().startswith("all:"):
                scope = "all"
                v = v[4:].lstrip()
            elif v.lower().startswith("all "):
                scope = "all"
                v = v[4:].lstrip()
            needle = self._parse_search_needle(v)
            if needle is None:
                self.console_pane.write(
                    "[search] could not parse {!r} as hex or ASCII".format(v), error=True)
                return
            self.console_pane.write(
                "[search] scope={} — scanning for {} byte(s)…".format(scope, len(needle)))
            hits, scanned = self.dbg.memory_search(
                needle, max_hits=64,
                total_budget_bytes=1024 * 1024 * 1024, scope=scope)
            if not hits:
                self.console_pane.write(
                    "[search] no hits for {!r} in {} (scanned {} MB). "
                    "Prefix with 'all:' to also search libraries.".format(
                        v, scope, scanned // (1024 * 1024)),
                    error=True)
                self._search_hits = []
                self._search_last = needle
                return
            self._search_hits = hits
            self._search_last = needle
            self._search_pos = 0
            self._follow_memory(hits[0], focus_len=len(needle))
            self.console_pane.write(
                "[search] {} hit(s) in scope={}; showing 1/{} at {:#x}. "
                "Ctrl+F Enter for next.".format(
                    len(hits), scope, len(hits), hits[0]))
        self.run_worker(_run(), exclusive=True)

    @staticmethod
    def _parse_search_needle(v: str) -> Optional[bytes]:
        s = v.strip()
        low = s.lower()
        if low.startswith("0x"):
            hx = low[2:]
            if len(hx) % 2:
                hx = "0" + hx
            try:
                return bytes.fromhex(hx)
            except ValueError:
                return None
        parts = s.split()
        if parts and all(len(p) <= 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
            try:
                return bytes(int(p, 16) for p in parts)
            except ValueError:
                pass
        return s.encode()

    _SCOPE_LABELS = {
        1:  "strict",
        5:  "balanced",
        32: "wide",
        0:  "off",
    }

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
        self._update_trace_title()

    def _update_trace_title(self) -> None:
        label = self._SCOPE_LABELS.get(self.tracer.caller_depth, str(self.tracer.caller_depth))
        self.trace_pane.set_status(self.tracer.enabled, label)

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
        if self.dbg.setsid_bp_ids:
            ids.update(self.dbg.setsid_bp_ids)
        if self.dbg.exec_bp_ids:
            ids.update(self.dbg.exec_bp_ids.keys())
        return ids

    def action_defenses(self) -> None:
        def tick(on: bool) -> str:
            return "✓" if on else " "

        def build_items():
            return [
                ("{}  PT_DENY_ATTACH bypass (symbol hook)".format(tick(bool(self.dbg.anti_ptrace_bp_id))),
                 self._toggle_deny_attach_bypass),
                ("{}  Direct-syscall ptrace scan (mov x16,#26 / svc)".format(tick(bool(self.dbg.direct_syscall_bp_ids))),
                 self._toggle_direct_syscall_scan),
                ("{}  Mach exception port cloak".format(tick(bool(self.dbg.anti_mach_bp_id))),
                 self._toggle_mach_ports_cloak),
                ("{}  Hardware BPs for user breakpoints".format(tick(self.dbg.hw_breakpoints)),
                 self._toggle_hw_bps),
                ("{}  Hardware BPs for tracer breakpoints".format(tick(self.tracer.hardware)),
                 self._toggle_tracer_hw),
                ("{}  Fork identity mode (fork+setsid faked, parent runs child path)".format(tick(self.dbg.fork_mode == "identity")),
                 self._toggle_fork_identity),
                ("{}  Outbound exec sandbox (system/popen/execve/posix_spawn)".format(tick(bool(self.dbg.exec_bp_ids))),
                 self._toggle_exec_sandbox),
                ("{}  Exec sandbox: interactive (prompt per call instead of auto-block)".format(tick(self.dbg.exec_interactive)),
                 self._toggle_exec_interactive),
            ]
        w, h = self.size
        self.push_screen(ToggleMenu(build_items, x=max(0, w // 2 - 25), y=max(0, h // 3)))

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

    def _toggle_fork_identity(self) -> None:
        if self.dbg.fork_mode == "identity":
            _, msg = self.dbg.disable_fork_identity()
        else:
            _, msg = self.dbg.enable_fork_identity()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _prompt_exec_decision(self, name: str, cmd: str) -> None:
        def allow():
            self.dbg.resolve_exec(block=False)
            self.console_pane.write('[anti-debug] ALLOWED {}("{}")'.format(name, cmd[:120]))

        def block():
            self.dbg.resolve_exec(block=True)
            self.console_pane.write('[anti-debug] blocked {}("{}") — returned -1'.format(name, cmd[:120]))

        def default_block():
            self.dbg.resolve_exec(block=True)
            self.console_pane.write(
                '[anti-debug] dismissed without choice — blocked {}("{}") — returned -1'.format(
                    name, cmd[:120]))

        title = 'Outbound {}: "{}"'.format(name, cmd[:80])
        items = [
            ("Allow  (let it run and return normally)", allow),
            ("Block  (return -1, do not run)",          block),
        ]
        self.console_pane.write(
            "[anti-debug] {}? paused — choose Allow or Block (Esc = Block)".format(title))
        w, h = self.size
        self.push_screen(ContextMenu(
            items,
            x=max(0, w // 2 - 25),
            y=max(0, h // 3),
            on_dismiss=default_block,
        ))

    def _toggle_exec_sandbox(self) -> None:
        if self.dbg.exec_bp_ids:
            _, msg = self.dbg.disable_exec_sandbox()
        else:
            _, msg = self.dbg.enable_exec_sandbox()
        self.console_pane.write("[anti-debug] " + msg)
        self.bps.render_rows(self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids()))

    def _toggle_exec_interactive(self) -> None:
        self.dbg.exec_interactive = not self.dbg.exec_interactive
        self.console_pane.write("[anti-debug] exec sandbox interactive mode: {}".format(
            "ON" if self.dbg.exec_interactive else "OFF"))

    def action_clear_trace(self) -> None:
        self.trace_pane.clear()
        self._trace_count = 0
        self.console_pane.write("[trace] cleared")

    def action_toggle_trace(self) -> None:
        if self.tracer.enabled:
            self.tracer.disable(self.dbg.target)
            self.console_pane.write("[trace] disabled")
            self._update_trace_title()
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
            self._update_trace_title()
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
            ("bps", self.bps), ("trace", self.trace_pane),
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
            has_comment = bool(self.dbg.state and self.dbg.state.comments.get(drow.addr))
            items = [
                ("Goto (follow operand in Memory)", lambda: self._follow_memory(target)),
                ("Toggle breakpoint here",          lambda: self._toggle_bp(drow.addr)),
                ("Run to cursor",                   lambda: self._run_to(drow.addr)),
                ("Edit comment…" if has_comment else "Add comment…",
                 lambda: self._prompt_edit_comment(drow.addr)),
                ("Copy address",                    lambda: self._copy("{:#x}".format(drow.addr))),
            ]
        elif pane == "trace":
            items = [
                ("Filter and verbosity…",   lambda: self._open_trace_filter(x, y)),
                ("Copy all trace rows",     lambda: self._copy_trace(all_rows=True)),
                ("Copy this row",           lambda: self._copy_trace(all_rows=False, only=row)),
                ("Clear trace",             lambda: (self.trace_pane.clear(), setattr(self, '_trace_count', 0))),
            ]
            if items:
                self.push_screen(ContextMenu(items, x=max(0, x), y=max(0, y)))
            return
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
            return int(s, 16)
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

    def _open_trace_filter(self, x: int, y: int) -> None:
        def tick(on: bool) -> str:
            return "✓" if on else " "

        depth_label = {
            1:  "strict (immediate caller must be user code)",
            5:  "balanced (user code within top 5 frames)",
            32: "wide (any user code on the stack)",
            0:  "off (log every hit including framework internals)",
        }

        def build_items():
            d = self.tracer.caller_depth
            return [
                ("   Verbosity: {} (Enter to cycle)".format(depth_label.get(d, str(d))),
                 self.action_cycle_trace_depth),
                ("{}  FILE calls (open, read, write, stat, …)".format(tick(self.trace_pane.category_filter["FILE"])),
                 lambda: self._toggle_trace_cat("FILE")),
                ("{}  NET calls (socket, connect, send, getaddrinfo, …)".format(tick(self.trace_pane.category_filter["NET"])),
                 lambda: self._toggle_trace_cat("NET")),
                ("{}  PROC calls (system, execve, posix_spawn, dlopen, …)".format(tick(self.trace_pane.category_filter["PROC"])),
                 lambda: self._toggle_trace_cat("PROC")),
            ]
        from .context import ToggleMenu
        self.push_screen(ToggleMenu(build_items, x=max(0, x), y=max(0, y)))

    def _toggle_trace_cat(self, category: str) -> None:
        cur = self.trace_pane.category_filter[category]
        self.trace_pane.set_category_filter(category, not cur)
        self.console_pane.write("[trace] {} calls: {}".format(
            category, "shown" if not cur else "hidden"))

    def _copy_trace(self, all_rows: bool, only: Optional[int] = None) -> None:
        lines: List[str] = []
        if all_rows:
            for n, cat, call in self.trace_pane.all_hits():
                lines.append("{}\t{}\t{}".format(n, cat, call))
        else:
            table = self.trace_pane.table
            if only is not None and 0 <= only < table.row_count:
                row = table.get_row_at(only)
                cells = [c.plain if hasattr(c, "plain") else str(c) for c in row]
                lines.append("\t".join(c.strip() for c in cells))
        if not lines:
            self.console_pane.write("[copy] no trace rows to copy", error=True)
            return
        payload = "\n".join(lines)
        self._copy(payload)
        self.console_pane.write("[copy] {} trace row(s) to clipboard".format(len(lines)))

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

    def _prompt_clear_state(self) -> None:
        if not self.dbg.state:
            self.console_pane.write(
                "[state] no state to clear (target not loaded from a path)", error=True)
            return
        state = self.dbg.state
        path = state.file_path()
        summary = "sha {}… ({} bp(s), {} comment(s), {} bookmark(s))".format(
            state.sha256[:12], len(state.breakpoints), len(state.comments), len(state.bookmarks))

        def do_clear():
            import os
            state.comments.clear()
            state.bookmarks.clear()
            state.breakpoints.clear()
            deleted = False
            try:
                if os.path.exists(path):
                    os.remove(path)
                    deleted = True
            except OSError as e:
                self.console_pane.write("[state] could not delete {}: {}".format(path, e), error=True)
                return
            for i in reversed(range(self.dbg.target.GetNumBreakpoints())):
                bp = self.dbg.target.GetBreakpointAtIndex(i)
                if bp.GetID() in self._hidden_bp_ids():
                    continue
                self.dbg.target.BreakpointDelete(bp.GetID())
            self.console_pane.write(
                "[state] cleared. removed file={} and all user breakpoints.".format(
                    path if deleted else "(none)"))
            self._refresh_all()

        items = [
            ("Yes  — delete state file, drop comments and user BPs", do_clear),
            ("Cancel — keep everything as-is",                        lambda: None),
        ]
        self.console_pane.write(
            "[state] confirm clear for {} — this cannot be undone".format(summary))
        w, h = self.size
        self.push_screen(ContextMenu(items, x=max(0, w // 2 - 25), y=max(0, h // 3)))

    def _prompt_edit_comment(self, addr: int) -> None:
        state = self.dbg.state
        if not state:
            self.console_pane.write("[comment] no persistent state (target not loaded via path)", error=True)
            return
        current = state.comments.get(addr, "")
        async def _run() -> None:
            val = await self.push_screen_wait(PromptScreen(
                "Comment at {:#x}  —  empty to remove, Ctrl+U clears, Esc cancels".format(addr),
                initial=current,
            ))
            if val is None:
                return
            v = val.strip()
            if v:
                state.comments[addr] = v
                self.console_pane.write("[comment] {:#x} = {!r}".format(addr, v))
            else:
                state.comments.pop(addr, None)
                self.console_pane.write("[comment] {:#x} cleared".format(addr))
            state.save()
            self._refresh_all()
        self.run_worker(_run(), exclusive=True)

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

    def _centered_read(self, addr: int, before_rows: int = 32, total_rows: int = 64):
        return self.dbg.read_around(addr, before=before_rows * 16, total=total_rows * 16)

    def _follow_memory(self, addr: int, focus_len: int = 1) -> None:
        self._mem_follow = addr
        self._mem_follow_len = focus_len
        if not self._mem_history or self._mem_history[-1] != addr:
            self._mem_history.append(addr)
            if len(self._mem_history) > 32:
                self._mem_history = self._mem_history[-32:]
        base, data = self._centered_read(addr, before_rows=32)
        self.mem.render_bytes(base, data, focus_addr=addr, focus_len=focus_len)
        self.console_pane.write("follow -> {:#x}".format(addr))

    _CLEAR_STATE_ALIASES = ("clear-state", "macdbg clear-state", "macdbg clear")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "cmd_input":
            cmd = event.value.strip()
            event.input.value = ""
            if not cmd:
                return
            self.console_pane.write("> " + cmd)
            if cmd.lower() in self._CLEAR_STATE_ALIASES:
                self._prompt_clear_state()
                return
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
                self._trace_count = 0
                self._annot_cache.clear()
                self.trace_pane.clear()
            if self.dbg.process and self.dbg.process.GetState() == lldb.eStateStopped:
                self._refresh_all()
        elif event.input.id == "mem_addr":
            text = event.value.strip()
            try:
                addr = int(text, 0)
                self._follow_memory(addr)
            except ValueError:
                self.console_pane.write("bad address: {}".format(text), error=True)
