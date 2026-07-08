"""Headless debugger engine for the web GUI.

Owns Debugger + Tracer (under system Python 3.9, no tkinter), reuses macdbg's
core engine and the TUI's stop-dispatch orchestration, and pushes JSON snapshots
/ console / trace / prompt events to subscribers (the SSE stream). All LLDB
access is serialised onto a single worker thread; the HTTP layer only ever calls
:meth:`command` / :meth:`subscribe`, which are thread-safe.
"""
from __future__ import annotations

import queue
import threading
import time
import traceback
from typing import Dict, List, Optional

import lldb

from macdbg.core.debugger import Debugger
from macdbg.core.disasm import disasm_around, extract_addr
from macdbg.core.events import EventPump, OutputEvent, StopEvent
from macdbg.core.registers import collect as collect_regs, flag_layout_for, snapshot as reg_snapshot
from macdbg.core.state import Watch
from macdbg.core.tracer import Tracer

from . import snapshot


def _parse_bytes(s: str) -> Optional[bytes]:
    s = (s or "").strip()
    if not s:
        return None
    parts = s.split()
    try:
        if len(parts) == 1 and len(parts[0]) > 2:
            hx = parts[0][2:] if parts[0].startswith("0x") else parts[0]
            return bytes.fromhex(hx) if len(hx) % 2 == 0 else None
        out = bytearray()
        for p in parts:
            p = p[2:] if p.startswith("0x") else p
            if not p or len(p) > 2:
                return None
            out.append(int(p, 16))
        return bytes(out)
    except ValueError:
        return None


class Engine:
    def __init__(self, program: Optional[str], program_args: List[str],
                 attach_pid: Optional[int] = None) -> None:
        self.program = program
        self.program_args = program_args or []
        self.attach_pid = attach_pid

        self.dbg = Debugger()
        self.tracer = Tracer()
        self.pump: Optional[EventPump] = None

        self._prev_regs: Dict[str, str] = {}
        self._annot_cache: Dict[str, str] = {}
        self._mem_follow: Optional[int] = None
        self._mem_follow_len = 1
        self._disasm_follow: Optional[int] = None
        self._trace_count = 0
        self._trace_lock = threading.Lock()
        self._strings_bin: List = []
        self._strings_live: List = []
        self._search_last: Optional[bytes] = None
        self._search_hits: List[int] = []
        self._search_pos = 0
        self._resuming = False
        self._pending_exec = None   # (name, cmd, bp_id)
        self._pending_fork = None   # (name,)

        self._q: "queue.Queue" = queue.Queue()
        self._subs: set = set()
        self._subs_lock = threading.Lock()
        self._alive = True

        self._output_stop = threading.Event()
        self._interpose_stop = threading.Event()
        self._interpose_thread: Optional[threading.Thread] = None
        self._interpose_root_pid: Optional[int] = None

    # ---- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self._worker_loop, name="engine", daemon=True).start()
        self.pump = EventPump(
            self.dbg.listener,
            on_stop=lambda e: self.submit(self._on_stop_event, e),
            on_output=lambda e: self._emit({"t": "console", "text": e.text,
                                            "error": e.is_error}),
        )
        self.pump.start()
        threading.Thread(target=self._pump_output, name="lldb-output",
                         daemon=True).start()
        self.submit(self._start_session)

    def shutdown(self) -> None:
        self._alive = False
        self._output_stop.set()
        self._interpose_stop.set()
        if self.pump:
            self.pump.stop()
        try:
            self.dbg.save_state(self._hidden_bp_ids())
        except Exception:
            pass
        try:
            self.dbg.destroy()
        except Exception:
            pass

    def _worker_loop(self) -> None:
        while self._alive:
            try:
                fn, args = self._q.get(timeout=0.3)
            except queue.Empty:
                continue
            try:
                fn(*args)
            except Exception:
                traceback.print_exc()
                self._console("[engine] " + traceback.format_exc(), error=True)

    def submit(self, fn, *args) -> None:
        self._q.put((fn, args))

    def _run_sync(self, fn, *args, timeout: float = 10.0):
        """Run fn on the worker thread and wait for its return value."""
        box = {}
        done = threading.Event()

        def wrap():
            try:
                box["v"] = fn(*args)
            except Exception as e:
                box["e"] = e
            finally:
                done.set()

        self.submit(wrap)
        done.wait(timeout)
        if "e" in box:
            raise box["e"]
        return box.get("v")

    def _ensure_host_platform(self) -> None:
        # "the platform is not connected" on Launch/Attach can happen when the
        # host platform isn't the selected/connected one (e.g. depending on the
        # process context we were spawned in). Re-selecting host is a harmless
        # no-op when it already is.
        try:
            self.dbg.handle_command("platform select host")
        except Exception:
            pass

    def _start_session(self) -> None:
        self._ensure_host_platform()
        if self.attach_pid:
            try:
                self.dbg.attach_pid(self.attach_pid)
                self._console("attached to pid {}".format(self.attach_pid))
                self._maybe_start_interpose_reader()
                self._emit_state()
            except Exception as e:
                self._console("attach failed: {}".format(e), error=True)
        elif self.program:
            self._launch(self.program, self.program_args)
        else:
            self._console("no target loaded. Open a target or attach to a pid, or "
                          "type an lldb command in the console.")
        self._emit({"t": "meta", "target": self.program or "",
                    "attach": self.attach_pid or 0})

    def _launch(self, program: str, args: List[str]) -> None:
        try:
            self._ensure_host_platform()
            self.dbg.create_target(program)
            restored = self.dbg.restore_stored_breakpoints()
            self.dbg.launch(list(args))
            self._console("launched {}".format(program))
            if self.dbg.state:
                self._console("[state] sha={}… ({} bp, {} comment, {} bookmark, "
                              "{} patch, {} watch)".format(
                                  self.dbg.state.sha256[:12], restored,
                                  len(self.dbg.state.comments), len(self.dbg.state.bookmarks),
                                  len(self.dbg.state.patches), len(self.dbg.state.watches)))
            try:
                self._strings_bin = self.dbg.extract_strings(min_len=5)
            except Exception:
                pass
            self._maybe_start_interpose_reader()
            p = self.dbg.process
            if p and p.IsValid():
                st = p.GetState()
                if st == lldb.eStateStopped:
                    self._console("[entry] stopped at entry {:#x}".format(self.dbg.pc() or 0))
                    self._emit_state()
                elif st == lldb.eStateExited:
                    self._console(self._describe_exit(), error=True)
        except Exception as e:
            self._console("launch failed: {}".format(e), error=True)

    # ---- event fan-out -------------------------------------------------------
    def subscribe(self) -> "queue.Queue":
        q: "queue.Queue" = queue.Queue()
        with self._subs_lock:
            self._subs.add(q)
        # a fresh subscriber gets the current state immediately
        self.submit(self._emit_state)
        return q

    def unsubscribe(self, q) -> None:
        with self._subs_lock:
            self._subs.discard(q)

    def _emit(self, obj: dict) -> None:
        with self._subs_lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(obj)
            except Exception:
                pass

    def _console(self, text: str, error: bool = False) -> None:
        self._emit({"t": "console", "text": text, "error": error})

    def _pump_output(self) -> None:
        while not self._output_stop.is_set():
            text = self.dbg.read_output()
            if text:
                self._emit({"t": "console", "text": text, "error": False})
            else:
                time.sleep(0.05)

    # ---- snapshot ------------------------------------------------------------
    def _emit_state(self, disasm_center: Optional[int] = None) -> None:
        self._emit(self._build_state(disasm_center))

    def _build_state(self, disasm_center: Optional[int] = None) -> dict:
        dbg = self.dbg
        frame = dbg.frame()
        pc = dbg.pc() or 0
        sp = dbg.sp() or 0
        running = bool(dbg.process and dbg.process.IsValid()
                       and dbg.process.GetState() == lldb.eStateRunning)
        state = {"t": "state", "pc": pc, "sp": sp, "running": running,
                 "has_process": bool(dbg.process and dbg.process.IsValid())}

        center = disasm_center if disasm_center is not None else self._disasm_follow
        if dbg.target and pc:
            rows = disasm_around(dbg.target, pc, count=400, read_mem=dbg.read_memory,
                                 center=center, frame=frame)
            comments = dbg.state.comments if dbg.state else {}
            bp_addrs = self._user_bp_addrs()
            for r in rows:
                if comments:
                    c = comments.get(r.addr)
                    if c:
                        r.user_comment = c
                if r.addr in bp_addrs:
                    r.has_breakpoint = True
                    r.bp_enabled = bp_addrs[r.addr]
            state["disasm"] = snapshot.disasm_json(rows)
            state["disasm_center"] = center
        else:
            state["disasm"] = []

        self._annot_cache.clear()
        reg_rows = collect_regs(frame, self._prev_regs, read_mem=dbg.read_memory,
                                target=dbg.target, annot_cache=self._annot_cache)
        state["registers"] = snapshot.regs_json(reg_rows)
        self._prev_regs = reg_snapshot(reg_rows)

        if sp:
            base, data = self._centered_read(sp, 8)
            state["stack"] = snapshot.hex_json(base, data, width=10, focus_addr=sp)
        else:
            state["stack"] = None

        follow = self._mem_follow if self._mem_follow is not None else pc
        if follow:
            base, data = self._centered_read(follow, 32)
            flen = self._mem_follow_len if self._mem_follow is not None else 1
            mem = snapshot.hex_json(base, data, width=10, focus_addr=follow, focus_len=flen)
            mem["follow"] = follow
            if self._search_hits and follow in self._search_hits:
                mem["search"] = "hit {}/{}".format(
                    self._search_hits.index(follow) + 1, len(self._search_hits))
            state["memory"] = mem
        else:
            state["memory"] = None

        state["watches"] = self._watches_json()
        state["breakpoints"] = [
            [bid, "{:#x}".format(addr), sym or "", n or "", cond or "",
             bool(en)]
            for bid, addr, sym, n, en, cond in dbg.breakpoints(
                exclude_ids=self._hidden_bp_ids())]
        state["threads"] = [
            [str(tid), idx, name, "{:#x}".format(tpc), fn or ""]
            for tid, idx, name, tpc, fn in dbg.threads()]
        state["modules"] = [
            [name or "", "{:#x}".format(b), "{:#x}".format(sz), triple or ""]
            for name, b, sz, triple in dbg.modules()]
        state["backtrace"] = [
            [idx, "{:#x}".format(fpc), fn or "", mod or ""]
            for idx, fpc, fn, mod in dbg.backtrace()]
        state["patches"] = ([[i, "{:#x}".format(p.addr), p.orig.hex(" "),
                              p.new.hex(" "), len(p.new)]
                             for i, p in enumerate(dbg.state.patches)]
                            if dbg.state else [])
        state["strings"] = ([["bin", "{:#x}".format(a), len(s), s]
                             for a, s in self._strings_bin[:4000]]
                            + [["live", "{:#x}".format(a), len(s), s]
                               for a, s in self._strings_live[:4000]])
        state["trace_status"] = self._trace_status()
        return state

    def _watches_json(self) -> list:
        out = []
        for slot in (1, 2, 3):
            b = self._watch(slot)
            if b is None:
                out.append(None)
                continue
            addr, length, label = b
            data = self.dbg.read_memory(addr, length)
            out.append({"slot": slot, "addr": addr, "len": length, "label": label,
                        **snapshot.hex_json(addr, data or b"", width=10)})
        return out

    def _watch(self, slot: int):
        if not self.dbg.state:
            return None
        for w in self.dbg.state.watches:
            if w.slot == slot:
                return (w.addr, w.length, w.label)
        return None

    def _centered_read(self, addr: int, before_rows: int, total_rows: int = 64):
        return self.dbg.read_around(addr, before=before_rows * 16, total=total_rows * 16)

    # ---- orchestration (port of ui/app.py _on_stop_event) --------------------
    def _on_stop_event(self, e: StopEvent) -> None:
        if e.state in (lldb.eStateStopped, lldb.eStateExited, lldb.eStateCrashed):
            self._resuming = False
        if e.state == lldb.eStateStopped:
            self.dbg.select_stopped_thread()
            if self.dbg.in_user_step():
                if self.tracer.enabled:
                    self._log_trace_hit()
                if self.dbg.advance_user_step(self._hidden_bp_ids()) == "more":
                    self._resuming = True
                    return
                self._console(self._describe_stop())
                self._emit_state()
                return
            if self.dbg.in_fork_shield():
                self.dbg.finish_fork_shield()
                self.dbg.cont()
                return
            if self._handle_anti_debug_hit():
                return
            if self.tracer.enabled and self._handle_possible_trace_hit():
                return
            self._console(self._describe_stop())
            self._emit_state()
        elif e.state == lldb.eStateExited:
            self.dbg.cancel_user_step()
            self._console(self._describe_exit())
            self._emit_state()

    def _describe_exit(self) -> str:
        p = self.dbg.process
        if not p or not p.IsValid():
            return "process exited."
        desc = p.GetExitDescription() or ""
        return "process exited with code {}{}.".format(
            p.GetExitStatus(), " ({})".format(desc) if desc else "")

    def _describe_stop(self) -> str:
        p = self.dbg.process
        if not p or not p.IsValid():
            return "[stopped]"
        thread = p.GetSelectedThread()
        if not thread or not thread.IsValid():
            return "[stopped]"
        reason = thread.GetStopReason()
        pc = self.dbg.pc() or 0
        frame = thread.GetFrameAtIndex(0)
        sym = ""
        if frame and frame.IsValid():
            sym = frame.GetFunctionName() or (
                frame.GetSymbol().GetName() if frame.GetSymbol().IsValid() else "") or ""
        where = " in {}".format(sym) if sym else ""
        if reason == lldb.eStopReasonBreakpoint and thread.GetStopReasonDataCount() >= 1:
            bp_id = thread.GetStopReasonDataAtIndex(0)
            return "[stop] breakpoint #{} at {:#x}{}".format(bp_id, pc, where)
        if reason == lldb.eStopReasonPlanComplete:
            return "[stop] step complete at {:#x}{}".format(pc, where)
        if reason == lldb.eStopReasonException:
            return "[stop] exception at {:#x}{}: {}".format(
                pc, where, thread.GetStopDescription(256))
        if reason == lldb.eStopReasonSignal and thread.GetStopReasonDataCount() >= 1:
            return "[stop] signal {} at {:#x}{}".format(
                thread.GetStopReasonDataAtIndex(0), pc, where)
        return "[stop] at {:#x}{}".format(pc, where)

    @staticmethod
    def _stop_bp_ids(thread) -> List[int]:
        ids = []
        i, n = 0, thread.GetStopReasonDataCount()
        while i < n:
            ids.append(thread.GetStopReasonDataAtIndex(i))
            i += 2
        return ids

    def _exec_caller_site(self) -> Optional[int]:
        thread = self.dbg._thread()
        if thread is None or not self.dbg.target:
            return None
        exec_name = self.dbg.target.GetExecutable().GetFilename() or ""
        for i in range(1, thread.GetNumFrames()):
            fr = thread.GetFrameAtIndex(i)
            if not fr.IsValid():
                break
            m = fr.GetModule()
            if m.IsValid() and (m.GetFileSpec().GetFilename() or "") == exec_name:
                return fr.GetPC()
        return None

    def _handle_anti_debug_hit(self) -> bool:
        p = self.dbg.process
        if not p or not p.IsValid():
            return False
        thread = p.GetSelectedThread()
        if not thread or not thread.IsValid():
            return False
        trap_msg = self.dbg.handle_self_trap(thread)
        if trap_msg is not None:
            self._console("[anti-debug] " + trap_msg)
            return True
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        bp_ids = self._stop_bp_ids(thread)
        if not bp_ids:
            return False
        exec_bp = next((b for b in bp_ids if b in self.dbg.exec_bp_ids), None) \
            if self.dbg.exec_bp_ids else None
        if exec_bp is not None:
            self._log_exec_trace(thread)
            if self.dbg.exec_interactive:
                peeked = self.dbg.peek_exec_hit(exec_bp)
                if peeked is not None:
                    name, cmd = peeked
                    caller = self._exec_caller_site()
                    self._pending_exec = (name, cmd, exec_bp)
                    self._emit_state(disasm_center=caller)
                    self._emit({"t": "prompt", "kind": "exec", "name": name,
                                "cmd": cmd, "caller": caller})
                    return True
        if self.dbg.fork_interactive and self.dbg.fork_bp_ids:
            fork_bp = next((b for b in bp_ids if b in self.dbg.fork_bp_ids), None)
            if fork_bp is not None:
                name = self.dbg.peek_fork_hit(fork_bp)
                if name is not None:
                    caller = self._exec_caller_site()
                    self._pending_fork = (name,)
                    self._emit_state(disasm_center=caller)
                    self._emit({"t": "prompt", "kind": "fork", "name": name,
                                "caller": caller})
                    return True
        for handler in (self.dbg.handle_anti_ptrace_hit, self.dbg.handle_flag_scrub_hit,
                        self.dbg.handle_syscall_hit, self.dbg.handle_anti_timing_hit,
                        self.dbg.handle_anti_mach_hit, self.dbg.handle_direct_syscall_hit,
                        self.dbg.handle_fork_hit, self.dbg.handle_setsid_hit,
                        self.dbg.handle_exec_hit):
            for bp_id in bp_ids:
                msg = handler(bp_id)
                if msg is not None:
                    if msg:
                        self._console("[anti-debug] " + msg)
                    return True
        return False

    def _log_exec_trace(self, thread) -> None:
        if not self.tracer.enabled:
            return
        hit = self.tracer.hit_from(thread.GetFrameAtIndex(0), self.dbg.process)
        if hit is not None:
            self._add_trace(hit.category, hit.call)

    def _log_trace_hit(self) -> bool:
        p = self.dbg.process
        if not p or not p.IsValid():
            return False
        thread = p.GetSelectedThread()
        if not thread or not thread.IsValid():
            return False
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        bp_id = next((b for b in self._stop_bp_ids(thread)
                      if self.tracer.is_trace_bp(b)), None)
        if bp_id is None:
            return False
        hit = self.tracer.hit_from(thread.GetFrameAtIndex(0), p, bp_id=bp_id)
        if hit is not None:
            self._add_trace(hit.category, hit.call)
        return True

    def _handle_possible_trace_hit(self) -> bool:
        if not self._log_trace_hit():
            return False
        thread = self.dbg.process.GetSelectedThread()
        hidden = self._hidden_bp_ids()
        if any(b not in hidden for b in self._stop_bp_ids(thread)):
            return False
        self.dbg.process.Continue()
        return True

    def _add_trace(self, category: str, call: str) -> None:
        with self._trace_lock:
            self._trace_count += 1
            n = self._trace_count
        self._emit({"t": "trace", "n": n, "cat": category, "call": call})

    # ---- hidden bp / user bp maps --------------------------------------------
    def _user_bp_addrs(self) -> Dict[int, bool]:
        out: Dict[int, bool] = {}
        for _id, addr, _d, _n, en, _c in self.dbg.breakpoints(
                exclude_ids=self._hidden_bp_ids()):
            if addr:
                out[addr] = en or out.get(addr, False)
        return out

    def _hidden_bp_ids(self) -> set:
        ids = set(self.tracer._bp_to_name)
        d = self.dbg
        for attr in ("anti_ptrace_bp_id", "anti_sysctl_bp_id", "anti_csops_bp_id",
                     "anti_mach_bp_id"):
            v = getattr(d, attr, 0)
            if v:
                ids.add(v)
        for attr in ("anti_timing_bp_ids", "syscall_bp_ids", "direct_syscall_bp_ids",
                     "fork_bp_ids", "setsid_bp_ids"):
            v = getattr(d, attr, None)
            if v:
                ids.update(v)
        if getattr(d, "_flag_scrub_returns", None):
            ids.update(d._flag_scrub_returns.keys())
        if getattr(d, "exec_bp_ids", None):
            ids.update(d.exec_bp_ids.keys())
        return ids

    # ---- resume gate ---------------------------------------------------------
    def _begin_resume(self) -> bool:
        # Refuse a new step/continue while one is already resolving. `_resuming`
        # is briefly cleared at the top of each stop event; also gate on an
        # in-flight user step so a second step command arriving in that window
        # can't restart the step mid-flight and land inside a stepped-over call.
        if self._resuming or self.dbg.in_user_step():
            return False
        p = self.dbg.process
        if not (p and p.IsValid() and p.GetState() == lldb.eStateStopped):
            return False
        self._resuming = True
        if self._disasm_follow is not None:
            self._disasm_follow = None
        self._emit({"t": "running"})
        return True

    # ===== command dispatch (called from HTTP thread) =========================
    def command(self, name: str, args: dict) -> dict:
        handler = self._COMMANDS.get(name)
        if handler is None:
            return {"ok": False, "error": "unknown command {!r}".format(name)}
        if name in self._SYNC:
            try:
                return {"ok": True, "result": self._run_sync(handler, self, args)}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        self.submit(handler, self, args)
        return {"ok": True}

    # -- helpers to read args
    @staticmethod
    def _addr(args, key="addr"):
        v = args.get(key)
        if v is None:
            return None
        if isinstance(v, str):
            return int(v, 0)
        return int(v)

    # -- execution
    def _c_step_in(self, a):
        if self._begin_resume():
            self.dbg.step_in()

    def _c_step_over(self, a):
        if self._begin_resume():
            self.dbg.step_over()

    def _c_step_out(self, a):
        if self._begin_resume():
            self.dbg.step_out()

    def _c_cont(self, a):
        if self._begin_resume():
            self.dbg.cont()

    def _c_interrupt(self, a):
        p = self.dbg.process
        if p and p.IsValid() and p.GetState() == lldb.eStateRunning:
            self.dbg.interrupt()
            self._console("[wrapper] interrupt requested")
        else:
            self._console("[wrapper] nothing to interrupt")

    def _c_restart(self, a):
        if self.attach_pid:
            self._console("[restart] not available for an attached process", error=True)
            return
        if not self.dbg.target or not self.dbg.target.IsValid():
            self._console("[restart] no target loaded", error=True)
            return
        p = self.dbg.process
        if p and p.IsValid() and p.GetState() not in (lldb.eStateExited, lldb.eStateInvalid):
            p.Kill()
        self._interpose_stop.set()
        if self._interpose_thread is not None:
            self._interpose_thread.join(timeout=0.5)
            self._interpose_thread = None
        hidden = self._hidden_bp_ids()
        for bid in hidden:
            self.dbg.set_bp_enabled(bid, False)
        try:
            self.dbg.launch(list(self.program_args))
        except Exception as e:
            self._console("[restart] relaunch failed: {}".format(e), error=True)
            return
        finally:
            for bid in hidden:
                self.dbg.set_bp_enabled(bid, True)
        self._resuming = False
        self._prev_regs = {}
        self._mem_follow = None
        self._disasm_follow = None
        proc = self.dbg.process
        if proc and proc.IsValid() and proc.GetState() == lldb.eStateStopped:
            self._console("[restart] relaunched, at entry {:#x}".format(self.dbg.pc() or 0))
            self._maybe_start_interpose_reader()
            self._emit_state()

    def _c_toggle_bp(self, a):
        addr = self._addr(a) if a.get("addr") is not None else self.dbg.pc()
        if not addr:
            return
        op, bp_id = self.dbg.toggle_breakpoint_at(addr)
        self._console("breakpoint {} #{} @ {:#x}".format(op, bp_id, addr))
        self._emit_state()

    def _c_run_to(self, a):
        addr = self._addr(a)
        if addr is None or not self._begin_resume():
            return
        ok, msg = self.dbg.run_to_address(addr)
        self._console("[run-to] " + (msg or "running to {:#x}".format(addr)))
        if not ok:
            self._resuming = False
            self._emit_state()

    def _c_set_pc(self, a):
        addr = self._addr(a)
        if addr is None:
            return
        ok, msg = self.dbg.set_pc(addr)
        self._console("[set-pc] " + (msg or "pc → {:#x}".format(addr)))
        if ok:
            self._emit_state()

    # -- navigation
    def _c_follow_mem(self, a):
        addr = self._addr(a)
        if addr is None:
            return
        self._mem_follow = addr
        self._mem_follow_len = int(a.get("len", 1) or 1)
        self._emit_state()

    def _c_follow_disasm(self, a):
        addr = self._addr(a)
        if addr is None:
            return
        self._disasm_follow = addr
        self._console("[disasm] browsing {:#x} (Snap to return to pc)".format(addr))
        self._emit_state()

    def _c_snap_pc(self, a):
        self._disasm_follow = None
        self._emit_state()

    # -- edits
    def _c_write_mem(self, a):
        addr = self._addr(a)
        data = _parse_bytes(a.get("bytes", ""))
        if addr is None or data is None:
            self._console("[mem] bad address or bytes", error=True)
            return
        ok, msg = self.dbg.write_memory(addr, data)
        self._console("[mem] " + msg)
        if ok:
            self._emit_state()

    def _c_write_reg(self, a):
        name = a.get("name", "")
        try:
            v = int(str(a.get("value", "")), 0)
        except ValueError:
            self._console("[reg] bad value", error=True)
            return
        ok, msg = self.dbg.write_register(name, v)
        self._console("[reg] " + msg)
        if ok:
            self._emit_state()

    def _c_flip_flag(self, a):
        reg = a.get("reg", "")
        bit = int(a.get("bit", 0))
        frame = self.dbg.frame()
        if not frame or not frame.IsValid():
            return
        r = frame.FindRegister(reg)
        if not r.IsValid():
            return
        ok, msg = self.dbg.write_register(reg, r.GetValueAsUnsigned() ^ (1 << bit))
        self._console("[reg] " + msg)
        if ok:
            self._emit_state()

    def _c_comment(self, a):
        if not self.dbg.state:
            return
        addr = self._addr(a)
        text = (a.get("text") or "").strip()
        if addr is None:
            return
        if text:
            self.dbg.state.comments[addr] = text
        else:
            self.dbg.state.comments.pop(addr, None)
        self.dbg.state.save()
        self._emit_state()

    # -- breakpoints
    def _c_bp_enable(self, a):
        bid = int(a["id"])
        rows = self.dbg.breakpoints(exclude_ids=self._hidden_bp_ids())
        cur = next((en for i, _addr, _s, _n, en, _c in rows if i == bid), True)
        self.dbg.set_bp_enabled(bid, not cur)
        self._emit_state()

    def _c_bp_delete(self, a):
        self.dbg.handle_command("breakpoint delete {}".format(int(a["id"])))
        self._emit_state()

    def _c_bp_condition(self, a):
        self.dbg.set_bp_condition(int(a["id"]), (a.get("cond") or "").strip())
        self._emit_state()

    def _c_bp_commands(self, a):
        cmds = a.get("commands") or []
        self.dbg.set_bp_commands(int(a["id"]), list(cmds))
        self._emit_state()

    # -- watches
    def _c_watch_set(self, a):
        slot = int(a["slot"])
        addr = self._addr(a)
        if addr is None or not (1 <= slot <= 3) or not self.dbg.state:
            return
        length = int(a.get("len", 32) or 32)
        label = (a.get("label") or "").strip()
        self.dbg.state.watches = [w for w in self.dbg.state.watches if w.slot != slot]
        self.dbg.state.watches.append(Watch(slot=slot, addr=addr, length=length, label=label))
        self.dbg.state.save()
        self._console("[watch {}] pinned {:#x} ({} bytes)".format(slot, addr, length))
        self._emit_state()

    def _c_watch_clear(self, a):
        slot = int(a["slot"])
        if self.dbg.state:
            self.dbg.state.watches = [w for w in self.dbg.state.watches if w.slot != slot]
            self.dbg.state.save()
        self._emit_state()

    # -- search
    def _c_search(self, a):
        p = self.dbg.process
        if not p or not p.IsValid() or p.GetState() != lldb.eStateStopped:
            self._console("[search] process not stopped", error=True)
            return
        v = (a.get("text") or "").strip()
        if not v:
            if not self._search_hits:
                self._console("[search] no previous search", error=True)
                return
            self._search_pos = (self._search_pos + 1) % len(self._search_hits)
            addr = self._search_hits[self._search_pos]
            self._mem_follow = addr
            self._mem_follow_len = len(self._search_last or b"") or 1
            self._console("[search] hit {}/{} at {:#x}".format(
                self._search_pos + 1, len(self._search_hits), addr))
            self._emit_state()
            return
        scope = "target"
        if v.lower().startswith("all:"):
            scope, v = "all", v[4:].lstrip()
        needle = self._parse_needle(v)
        if needle is None:
            self._console("[search] could not parse {!r}".format(v), error=True)
            return
        self._console("[search] scope={} scanning {} byte(s)…".format(scope, len(needle)))
        hits, scanned = self.dbg.memory_search(needle, max_hits=64,
                                               total_budget_bytes=1024 * 1024 * 1024,
                                               scope=scope)
        if not hits:
            self._console("[search] no hits (scanned {} MB). Try 'all:'.".format(
                scanned // (1024 * 1024)), error=True)
            self._search_hits = []
            self._search_last = needle
            return
        self._search_hits, self._search_last, self._search_pos = hits, needle, 0
        self._mem_follow, self._mem_follow_len = hits[0], len(needle)
        self._console("[search] {} hit(s); showing 1/{} at {:#x}".format(
            len(hits), len(hits), hits[0]))
        self._emit_state()

    @staticmethod
    def _parse_needle(v: str):
        s = v.strip()
        if s.lower().startswith("0x"):
            hx = s[2:]
            if len(hx) % 2:
                hx = "0" + hx
            try:
                return bytes.fromhex(hx)
            except ValueError:
                return None
        parts = s.split()
        if parts and all(len(p) <= 2 and all(c in "0123456789abcdefABCDEF" for c in p)
                         for p in parts):
            try:
                return bytes(int(p, 16) for p in parts)
            except ValueError:
                pass
        return s.encode()

    def _c_scan_strings(self, a):
        p = self.dbg.process
        if not p or not p.IsValid():
            return
        self._console("[strings] scanning live memory…")
        try:
            self._strings_live = self.dbg.scan_live_strings(min_len=8)
        except Exception as e:
            self._console("[strings] scan failed: {}".format(e), error=True)
            return
        self._console("[strings] {} live string(s)".format(len(self._strings_live)))
        self._emit_state()

    # -- defenses
    def _c_defense(self, a):
        key = a.get("key", "")
        fn = self._DEFENSE_TOGGLES.get(key)
        if fn is None:
            self._console("[anti-debug] unknown toggle {!r}".format(key), error=True)
            return
        fn(self)
        self._emit_state()

    def _refresh_after_defense(self, msgs):
        for m in msgs:
            self._console("[anti-debug] " + m)

    def _t_all_anti(self):
        d = self.dbg
        on = bool(d.anti_ptrace_bp_id and d.direct_syscall_bp_ids and d.anti_mach_bp_id
                  and d.anti_sysctl_bp_id and d.anti_csops_bp_id and d.anti_timing_bp_ids
                  and d._scrub_parent and d.anti_sigtrap_on)
        seq = ([d.disable_anti_ptrace, d.disable_direct_syscall_scan, d.disable_anti_mach_ports,
                d.disable_anti_sysctl, d.disable_anti_csops, d.disable_anti_timing,
                d.disable_anti_parent, d.disable_anti_sigtrap] if on else
               [d.enable_anti_ptrace, d.enable_direct_syscall_scan, d.enable_anti_mach_ports,
                d.enable_anti_sysctl, d.enable_anti_csops, d.enable_anti_timing,
                d.enable_anti_parent, d.enable_anti_sigtrap])
        self._refresh_after_defense([f()[1] for f in seq])

    def _t_deny_attach(self):
        d = self.dbg
        if d.anti_ptrace_bp_id or d.direct_syscall_bp_ids:
            self._refresh_after_defense([d.disable_anti_ptrace()[1], d.disable_direct_syscall_scan()[1]])
        else:
            self._refresh_after_defense([d.enable_anti_ptrace()[1], d.enable_direct_syscall_scan()[1]])

    def _t_flag_scrubs(self):
        d = self.dbg
        if d.anti_sysctl_bp_id or d.anti_csops_bp_id:
            self._refresh_after_defense([d.disable_anti_sysctl()[1], d.disable_anti_csops()[1]])
        else:
            self._refresh_after_defense([d.enable_anti_sysctl()[1], d.enable_anti_csops()[1]])

    def _t_timing(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_anti_timing if d.anti_timing_bp_ids else d.enable_anti_timing)()[1]])

    def _t_parent(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_anti_parent if d._scrub_parent else d.enable_anti_parent)()[1]])

    def _t_sigtrap(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_anti_sigtrap if d.anti_sigtrap_on else d.enable_anti_sigtrap)()[1]])

    def _t_mach(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_anti_mach_ports if d.anti_mach_bp_id else d.enable_anti_mach_ports)()[1]])

    def _t_hw_bps(self):
        self.dbg.hw_breakpoints = not self.dbg.hw_breakpoints
        self._console("[anti-debug] hardware breakpoints for user BPs: {}".format(
            "ON" if self.dbg.hw_breakpoints else "OFF"))

    def _t_tracer_hw(self):
        if self.tracer.enabled:
            self._console("[anti-debug] disable tracer first, then flip HW mode", error=True)
            return
        self.tracer.hardware = not self.tracer.hardware
        self._console("[anti-debug] hardware breakpoints for tracer: {}".format(
            "ON" if self.tracer.hardware else "OFF"))

    def _t_fork_identity(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_fork_identity if d.fork_mode == "identity" else d.enable_fork_identity)()[1]])

    def _t_fork_interactive(self):
        d = self.dbg
        d.fork_interactive = not d.fork_interactive
        if d.fork_interactive and d.fork_mode != "identity":
            self._refresh_after_defense([d.enable_fork_identity()[1]])
        self._console("[anti-debug] fork intercept prompt: {}".format(
            "ON" if d.fork_interactive else "OFF"))

    def _t_exec_sandbox(self):
        d = self.dbg
        self._refresh_after_defense([(d.disable_exec_sandbox if d.exec_bp_ids else d.enable_exec_sandbox)()[1]])

    def _t_exec_interactive(self):
        self.dbg.exec_interactive = not self.dbg.exec_interactive
        self._console("[anti-debug] exec sandbox interactive: {}".format(
            "ON" if self.dbg.exec_interactive else "OFF"))

    def _defense_states(self) -> dict:
        d = self.dbg
        return {
            "all_anti": bool(d.anti_ptrace_bp_id and d.direct_syscall_bp_ids and d.anti_mach_bp_id
                             and d.anti_sysctl_bp_id and d.anti_csops_bp_id and d.anti_timing_bp_ids
                             and d._scrub_parent and d.anti_sigtrap_on),
            "deny_attach": bool(d.anti_ptrace_bp_id) or bool(d.direct_syscall_bp_ids),
            "mach": bool(d.anti_mach_bp_id),
            "flag_scrubs": bool(d.anti_sysctl_bp_id) or bool(d.anti_csops_bp_id),
            "parent": bool(d._scrub_parent),
            "sigtrap": bool(d.anti_sigtrap_on),
            "timing": bool(d.anti_timing_bp_ids),
            "hw_bps": bool(d.hw_breakpoints),
            "tracer_hw": bool(self.tracer.hardware),
            "fork_identity": d.fork_mode == "identity",
            "fork_interactive": bool(d.fork_interactive),
            "fork_trace": bool(d.interpose_enabled),
            "exec_sandbox": bool(d.exec_bp_ids),
            "exec_interactive": bool(d.exec_interactive),
        }

    # -- tracer
    _SCOPE_LABELS = {1: "strict", 5: "balanced", 32: "wide", 0: "off"}

    def _trace_status(self) -> dict:
        return {"on": bool(self.tracer.enabled),
                "scope": self._SCOPE_LABELS.get(self.tracer.caller_depth,
                                                str(self.tracer.caller_depth)),
                "defenses": self._defense_states()}

    def _c_trace_toggle(self, a):
        if self.tracer.enabled:
            self.tracer.disable(self.dbg.target)
            self._console("[trace] disabled")
        else:
            total, resolved = self.tracer.enable(self.dbg.target, ci=self.dbg.ci)
            if total == 0:
                self._console("[trace] could not create breakpoints", error=True)
                return
            self._console("[trace] enabled: {}/{} symbols resolved".format(resolved, total))
        self._emit_state()

    def _c_trace_scope(self, a):
        order = [1, 5, 32, 0]
        cur = self.tracer.caller_depth
        nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else 5
        self.tracer.caller_depth = nxt
        self._console("[trace] scope = {}".format(self._SCOPE_LABELS[nxt]))
        self._emit_state()

    def _c_trace_clear(self, a):
        with self._trace_lock:
            self._trace_count = 0
        self._emit({"t": "trace_clear"})
        self._console("[trace] cleared")

    def _c_fork_trace(self, a):
        if self.attach_pid:
            self._console("[fork-trace] not available for an attached process", error=True)
            return
        self.dbg.interpose_enabled = not self.dbg.interpose_enabled
        self._console("[fork-trace] whole-tree tracing {} — relaunching".format(
            "ON" if self.dbg.interpose_enabled else "OFF"))
        self._c_restart(a)

    # -- fork/exec decisions
    def _c_decide_exec(self, a):
        if self._pending_exec is None:
            return
        name, cmd, bp_id = self._pending_exec
        decision = a.get("decision", "block")
        if decision == "dump":
            dumped = self.dbg.dump_exec_payload(bp_id)
            if dumped:
                self._console("[anti-debug] payload ({} B) → {}".format(dumped[1], dumped[0]))
            self._emit({"t": "prompt", "kind": "exec", "name": name, "cmd": cmd})
            return
        if decision not in ("allow", "fake", "block"):
            decision = "block"
        self._pending_exec = None
        self.dbg.resolve_exec(decision, name)
        self._console('[anti-debug] {} {}("{}")'.format(decision.upper(), name, cmd[:120]))
        self._emit({"t": "running"})

    def _c_decide_fork(self, a):
        if self._pending_fork is None:
            return
        (name,) = self._pending_fork
        decision = a.get("decision", "parent")
        if decision not in ("parent", "child"):
            decision = "parent"
        self._pending_fork = None
        self.dbg.resolve_fork(decision)
        self._console("[anti-debug] {}() → {}".format(name, decision))
        self._emit({"t": "running"})

    # -- console / palette
    _RELAUNCH = ("run", "r", "process launch")
    _DELALL = ("br del", "breakpoint delete")

    def _c_run_cmd(self, a):
        cmd = (a.get("cmd") or "").strip()
        if not cmd:
            return
        cl = cmd.lower()
        if any(cl == x or cl.startswith(x + " ") for x in self._RELAUNCH):
            p = self.dbg.process
            if p and p.IsValid() and p.GetState() not in (lldb.eStateExited, lldb.eStateInvalid):
                p.Kill()
        elif cl in self._DELALL:
            self.dbg.handle_command("breakpoint delete -f")
        ok, out, err = self.dbg.handle_command(cmd)
        if out:
            self._console(out)
        if err:
            self._console(err, error=True)
        if self.dbg.ensure_listening():
            self._prev_regs = {}
            self._mem_follow = None
        if self.dbg.process and self.dbg.process.GetState() == lldb.eStateStopped:
            self._emit_state()

    def _c_complete(self, a):
        text = a.get("text", "")
        matches = lldb.SBStringList()
        descs = lldb.SBStringList()
        try:
            self.dbg.ci.HandleCompletionWithDescriptions(text, len(text), 0, 40, matches, descs)
        except Exception:
            return []
        out = []
        for i in range(1, matches.GetSize()):
            m = matches.GetStringAtIndex(i) or ""
            d = descs.GetStringAtIndex(i) if i < descs.GetSize() else ""
            cmd = (text.rsplit(" ", 1)[0] + " " + m).strip() if " " in text else m
            out.append({"cmd": cmd.strip(), "match": m, "desc": d})
        return out

    def _c_open_target(self, a):
        path = (a.get("path") or "").strip()
        if not path:
            return
        args = a.get("args") or []
        p = self.dbg.process
        if p and p.IsValid() and p.GetState() not in (lldb.eStateExited, lldb.eStateInvalid):
            p.Kill()
        self.program, self.program_args, self.attach_pid = path, args, None
        self._launch(path, args)

    def _c_attach(self, a):
        try:
            pid = int(str(a.get("pid")), 0)
        except (ValueError, TypeError):
            self._console("[attach] bad pid", error=True)
            return
        try:
            self._ensure_host_platform()
            self.dbg.attach_pid(pid)
            self.attach_pid = pid
            self._console("attached to pid {}".format(pid))
            self._emit_state()
        except Exception as e:
            self._console("attach failed: {}".format(e), error=True)

    def _c_save_state(self, a):
        try:
            path = self.dbg.save_state(self._hidden_bp_ids())
            self._console("[state] saved{}".format(" → " + path if path else ""))
        except Exception as e:
            self._console("[state] save failed: {}".format(e), error=True)

    def _c_refresh(self, a):
        self._emit_state()

    def _c_ui(self, a):
        # relay a UI action (from the native menu bar) to the frontend, which
        # owns the corresponding dialog/modal
        self._emit({"t": "ui", "action": a.get("action", "")})

    def _c_pick_file(self, a):
        """Show a native macOS open panel and launch the chosen binary."""
        import subprocess
        try:
            out = subprocess.run(
                ["osascript", "-e",
                 'POSIX path of (choose file with prompt "Select a Mach-O binary to debug")'],
                capture_output=True, text=True, timeout=180)
        except Exception as e:
            self._console("[open] " + str(e), error=True)
            return
        path = (out.stdout or "").strip()
        if not path:
            return  # cancelled
        self._c_open_target({"path": path, "args": []})

    def _c_list_processes(self, a):
        """Return running processes for the Attach picker (sync command)."""
        import subprocess
        try:
            out = subprocess.run(["ps", "-axo", "pid=,comm="],
                                 capture_output=True, text=True, timeout=10)
        except Exception:
            return []
        procs = []
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            comm = parts[1]
            procs.append({"pid": pid, "name": comm.rsplit("/", 1)[-1], "path": comm})
        procs.sort(key=lambda p: p["pid"], reverse=True)
        return procs

    # ---- interpose reader ----------------------------------------------------
    _INTERPOSE_CAT = {"read": "FILE", "write": "FILE", "open": "FILE",
                      "send": "NET", "recv": "NET", "connect": "NET"}

    def _maybe_start_interpose_reader(self) -> None:
        path = self.dbg.interpose_trace_path
        if not path:
            self.tracer.skip_fd = -1
            return
        if self._interpose_thread is not None:
            return
        self.tracer.skip_fd = self.dbg.INTERPOSE_FD
        self._interpose_root_pid = self.dbg.process.GetProcessID() if self.dbg.process else None
        self._interpose_stop.clear()
        self._interpose_thread = threading.Thread(
            target=self._pump_interpose, args=(path,), name="interpose", daemon=True)
        self._interpose_thread.start()

    @staticmethod
    def _fmt_hexbuf(hexstr: str) -> str:
        try:
            b = bytes.fromhex(hexstr)
        except ValueError:
            return ""
        printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
        if b and printable / len(b) > 0.7:
            return '"{}"'.format(b.decode("ascii", "replace").replace("\n", "\\n")[:80])
        return "<{}B: {}{}>".format(len(b), b[:24].hex(), "…" if len(b) > 24 else "")

    def _format_interpose(self, fields):
        if len(fields) < 2:
            return None
        try:
            pid = int(fields[0])
        except ValueError:
            return None
        if (self.tracer.enabled and self._interpose_root_pid is not None
                and pid == self._interpose_root_pid):
            return None
        fn = fields[1]
        cat = self._INTERPOSE_CAT.get(fn, "PROC")
        tag = "[pid {}] ".format(pid)
        if fn in ("read", "write", "send", "recv") and len(fields) >= 5:
            call = "{}{}({}, {})".format(tag, fn, fields[2], self._fmt_hexbuf(fields[4]))
        elif fn == "connect" and len(fields) >= 3:
            call = "{}connect({}, {})".format(tag, fields[2], fields[3] if len(fields) > 3 else "")
        elif fn == "open" and len(fields) >= 3:
            call = '{}open("{}")'.format(tag, fields[2])
        else:
            call = "{}{}".format(tag, fn)
        return cat, call

    def _pump_interpose(self, path: str) -> None:
        pos, buf = 0, ""
        while not self._interpose_stop.is_set():
            try:
                with open(path, "r") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    pos = fh.tell()
            except OSError:
                chunk = ""
            if not chunk:
                time.sleep(0.08)
                continue
            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()
            for line in lines:
                if not line:
                    continue
                parsed = self._format_interpose(line.split("\t"))
                if parsed:
                    self._add_trace(parsed[0], parsed[1])


# ---- command + toggle tables (bound after class body) ------------------------
Engine._COMMANDS = {
    "step_in": Engine._c_step_in, "step_over": Engine._c_step_over,
    "step_out": Engine._c_step_out, "cont": Engine._c_cont,
    "interrupt": Engine._c_interrupt, "restart": Engine._c_restart,
    "toggle_bp": Engine._c_toggle_bp, "run_to": Engine._c_run_to,
    "set_pc": Engine._c_set_pc, "follow_mem": Engine._c_follow_mem,
    "follow_disasm": Engine._c_follow_disasm, "snap_pc": Engine._c_snap_pc,
    "write_mem": Engine._c_write_mem, "write_reg": Engine._c_write_reg,
    "flip_flag": Engine._c_flip_flag, "comment": Engine._c_comment,
    "bp_enable": Engine._c_bp_enable, "bp_delete": Engine._c_bp_delete,
    "bp_condition": Engine._c_bp_condition, "bp_commands": Engine._c_bp_commands,
    "watch_set": Engine._c_watch_set, "watch_clear": Engine._c_watch_clear,
    "search": Engine._c_search, "scan_strings": Engine._c_scan_strings,
    "defense": Engine._c_defense, "trace_toggle": Engine._c_trace_toggle,
    "trace_scope": Engine._c_trace_scope, "trace_clear": Engine._c_trace_clear,
    "fork_trace": Engine._c_fork_trace, "decide_exec": Engine._c_decide_exec,
    "decide_fork": Engine._c_decide_fork, "run_cmd": Engine._c_run_cmd,
    "complete": Engine._c_complete, "open_target": Engine._c_open_target,
    "attach": Engine._c_attach, "save_state": Engine._c_save_state,
    "refresh": Engine._c_refresh, "pick_file": Engine._c_pick_file,
    "list_processes": Engine._c_list_processes, "ui": Engine._c_ui,
}
Engine._SYNC = {"complete", "list_processes"}
Engine._DEFENSE_TOGGLES = {
    "all_anti": Engine._t_all_anti, "deny_attach": Engine._t_deny_attach,
    "flag_scrubs": Engine._t_flag_scrubs, "timing": Engine._t_timing,
    "parent": Engine._t_parent, "sigtrap": Engine._t_sigtrap, "mach": Engine._t_mach,
    "hw_bps": Engine._t_hw_bps, "tracer_hw": Engine._t_tracer_hw,
    "fork_identity": Engine._t_fork_identity, "fork_interactive": Engine._t_fork_interactive,
    "exec_sandbox": Engine._t_exec_sandbox, "exec_interactive": Engine._t_exec_interactive,
}
