from __future__ import annotations

"""Headless driver for macdbg.core.Debugger, built for a non-interactive
(Claude-facing) caller instead of the Textual UI in macdbg/ui/app.py.

macdbg.core.debugger.Debugger exposes lldb mechanisms (launch/attach, step,
breakpoints, memory, anti-debug toggles) but does not run an event loop or
decide what a stop *means* -- that orchestration lives in WrapperApp. This
module ports the relevant pieces of that orchestration (stop dispatch, fork
shield handshake, anti-debug auto-continue, tracer auto-continue, hidden
breakpoint accounting) so a single-threaded, request/response caller can
drive the debugger the same way the TUI does, one command at a time.

Every public `cmd_*` method returns a plain JSON-serializable dict.  Methods
that resume execution (continue/step/restart/decide_*) block until the
process reaches a genuine stop, exits, or hits an interactive fork/exec
decision point -- see `_pump`.
"""

import os
import time
from typing import Callable, Dict, List, Optional

try:
    import lldb
except ImportError as e:
    raise SystemExit(
        "Could not import lldb. Run via ./agent.sh (which sets PYTHONPATH=$(lldb -P))."
    ) from e

from ..core.debugger import Debugger
from ..core.disasm import disasm_around
from ..core.registers import collect as collect_regs
from ..core.tracer import Tracer
from .client import _RESUME_COMMANDS  # noqa: F401 -- re-exported for server.py

# SBListener.WaitForEvent takes a whole-second uint32_t timeout (see
# EventPump's use of the literal `1` in core/events.py), not a float.
DEFAULT_WAIT_TIMEOUT = 1


def _int_arg(v) -> int:
    """Coerce a JSON arg to an int, accepting ``"0x…"``/``"0o…"``/``"0b…"``
    prefixed strings and plain decimal strings as well as raw ints. Every
    address-shaped field (``addr``, ``value``, ``bp_id``, ``thread_id``,
    ``size``, ``depth``, ``budget_bytes``) is fed through this so a caller
    never has to hand-convert ``0x10001d078`` to ``4295086216`` in JSON --
    that manual conversion is where address typos come from.

    A raw ``bool`` is rejected explicitly (``isinstance(True, int)`` is
    True in Python, so ``int(True)`` would silently yield 1 and mask a
    JSON-shape mismatch upstream).
    """
    if isinstance(v, bool):
        raise ValueError("expected an integer, got bool")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            raise ValueError("empty string is not a number")
        return int(s, 0)
    raise ValueError(
        "expected int or numeric string, got {}".format(type(v).__name__)
    )

_DEFENSES = {
    "anti_ptrace": ("enable_anti_ptrace", "disable_anti_ptrace"),
    "anti_mach_ports": ("enable_anti_mach_ports", "disable_anti_mach_ports"),
    "direct_syscall": ("enable_direct_syscall_scan", "disable_direct_syscall_scan"),
    "fork_identity": ("enable_fork_identity", "disable_fork_identity"),
    "exec_sandbox": ("enable_exec_sandbox", "disable_exec_sandbox"),
}


class SessionError(Exception):
    pass


class AgentSession:
    def __init__(self, program: Optional[str] = None,
                 program_args: Optional[List[str]] = None,
                 attach_pid: Optional[int] = None) -> None:
        self.program = program
        self.program_args = program_args or []
        self.attach_pid = attach_pid
        self.dbg = Debugger()
        self.tracer = Tracer()
        self._trace_hits: List[dict] = []
        self._trace_count = 0
        self._console: List[str] = []
        self._pending: Optional[dict] = None

    # -- lifecycle -----------------------------------------------------

    def start(self) -> dict:
        try:
            if self.attach_pid:
                self.dbg.attach_pid(self.attach_pid)
                self._log("attached to pid {}".format(self.attach_pid))
            elif self.program:
                self.dbg.create_target(self.program)
                # Restoring breakpoints by address before the process/image
                # is actually loaded (matching the TUI's own on_mount order:
                # macdbg/ui/app.py:222-224) creates them against a target
                # that has no live process yet -- core BreakpointCreateByAddress
                # then leaves them permanently "unresolved" and they never
                # fire, even after launch. launch() itself already advances
                # to and stops at the real entry point before returning, so
                # nothing the restored breakpoints could catch has run yet --
                # restoring after launch is equally safe and actually works.
                self.dbg.launch(list(self.program_args))
                restored = self.dbg.restore_stored_breakpoints()
                self._log("launched {}".format(self.program))
                if self.dbg.state:
                    self._log(
                        "[state] loaded sha={}... ({} bp(s), {} comment(s), "
                        "{} bookmark(s), {} patch(es), {} watch(es))".format(
                            self.dbg.state.sha256[:12], restored,
                            len(self.dbg.state.comments),
                            len(self.dbg.state.bookmarks),
                            len(self.dbg.state.patches),
                            len(self.dbg.state.watches),
                        )
                    )
            else:
                self._log("no target loaded")
        except Exception as e:
            return {"ok": False, "error": str(e), "console": self._drain_console()}
        self._drain_lldb_pipe()
        result: dict = {"ok": True, "console": self._drain_console()}
        p = self.dbg.process
        if p and p.IsValid():
            st = p.GetState()
            if st == lldb.eStateStopped:
                self.dbg.select_stopped_thread()
                result["event"] = "stop"
                result["stop"] = self._describe_stop()
            elif st == lldb.eStateExited:
                result["event"] = "exited"
                result["exit"] = self._describe_exit()
        return result

    def shutdown(self, save: bool = True) -> dict:
        if save:
            try:
                self.dbg.save_state(self._hidden_bp_ids())
            except Exception:
                pass
        try:
            self.dbg.destroy()
        except Exception:
            pass
        return {"ok": True}

    # -- dispatch --------------------------------------------------------

    def dispatch(self, cmd: str, args: dict, poll_cb: Optional[Callable[[], None]] = None) -> dict:
        args = args or {}
        try:
            if cmd in _RESUME_COMMANDS:
                return self._dispatch_resume(cmd, args, poll_cb)
            return self._dispatch_plain(cmd, args)
        except SessionError as e:
            return {"ok": False, "error": str(e)}
        except (KeyError, ValueError, TypeError) as e:
            # Almost always bad caller input (missing/malformed args), not a
            # real internal fault -- label it as such rather than "internal
            # error", which reads as a bug in us instead of the request.
            return {"ok": False, "error": "invalid arguments: {}: {}".format(type(e).__name__, e)}
        except Exception as e:
            return {"ok": False, "error": "internal error: {}: {}".format(type(e).__name__, e)}

    def _dispatch_resume(self, cmd: str, args: dict, poll_cb) -> dict:
        timeout = args.get("timeout")
        if self._pending is not None and cmd not in ("decide_fork", "decide_exec"):
            # A resume issued while a fork/exec decision is pending would
            # otherwise just call dbg.cont()/step_*() directly, letting the
            # intercepted call through unshielded and leaving self._pending
            # stale once the process moves on.
            return {"ok": False, "error":
                     "a {} decision is pending on bp #{}; call decide_{} first "
                     "(or inspect it via 'status')".format(
                         self._pending["kind"], self._pending["bp_id"], self._pending["kind"])}
        if cmd == "continue":
            return self._pump(resume=self.dbg.cont, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "step_in":
            return self._pump(resume=self.dbg.step_in, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "step_over":
            return self._pump(resume=self.dbg.step_over, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "step_out":
            return self._pump(resume=self.dbg.step_out, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "step_in_source":
            return self._pump(resume=self.dbg.step_in_source, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "step_over_source":
            return self._pump(resume=self.dbg.step_over_source, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "wait":
            return self._pump(resume=None, max_wait=timeout, poll_cb=poll_cb)
        if cmd == "decide_fork":
            return self._decide_fork(args.get("decision", "parent"), timeout, poll_cb)
        if cmd == "decide_exec":
            return self._decide_exec(args.get("decision", "block"), timeout, poll_cb)
        raise SessionError("unknown resume command {!r}".format(cmd))

    def _dispatch_plain(self, cmd: str, args: dict) -> dict:
        if cmd == "status":
            return self.cmd_status()
        if cmd == "restart":
            return self.cmd_restart()
        if cmd == "interrupt":
            self.dbg.interrupt()
            return {"ok": True}
        if cmd == "breakpoint_toggle":
            addr = _int_arg(args["addr"])
            existing = self._bp_id_at_addr(addr)
            if existing is not None:
                guard = self._guard_hidden_bp(existing)
                if guard is not None:
                    return guard
            kind, bp_id = self.dbg.toggle_breakpoint_at(addr)
            return {"ok": True, "action": kind, "bp_id": bp_id}
        if cmd == "breakpoint_list":
            exclude = self._hidden_bp_ids() if args.get("hide_internal", True) else None
            rows = self.dbg.breakpoints(exclude)
            return {"ok": True, "breakpoints": [
                {"id": i, "addr": a, "symbol": s, "commands": c, "enabled": en, "condition": cond}
                for (i, a, s, c, en, cond) in rows
            ]}
        if cmd == "breakpoint_enable":
            bp_id = _int_arg(args["bp_id"])
            guard = self._guard_hidden_bp(bp_id)
            if guard is not None:
                return guard
            ok = self.dbg.set_bp_enabled(bp_id, bool(args["enabled"]))
            return {"ok": ok}
        if cmd == "breakpoint_condition":
            bp_id = _int_arg(args["bp_id"])
            guard = self._guard_hidden_bp(bp_id)
            if guard is not None:
                return guard
            ok = self.dbg.set_bp_condition(bp_id, args.get("condition") or "")
            return {"ok": ok}
        if cmd == "breakpoint_commands":
            bp_id = _int_arg(args["bp_id"])
            guard = self._guard_hidden_bp(bp_id)
            if guard is not None:
                return guard
            ok = self.dbg.set_bp_commands(bp_id, list(args.get("commands") or []))
            return {"ok": ok}
        if cmd == "breakpoint_delete":
            if not self.dbg.target:
                return {"ok": False, "error": "no target"}
            bp_id = _int_arg(args["bp_id"])
            guard = self._guard_hidden_bp(bp_id)
            if guard is not None:
                return guard
            ok = self.dbg.target.BreakpointDelete(bp_id)
            return {"ok": bool(ok)}
        if cmd == "registers":
            return self.cmd_registers()
        if cmd == "backtrace":
            if not self._process_stopped():
                return {"ok": True, "frames": []}
            rows = self.dbg.backtrace()
            return {"ok": True, "frames": [
                {"index": i, "pc": pc, "function": fn, "module": mod}
                for (i, pc, fn, mod) in rows
            ]}
        if cmd == "threads":
            if not self._process_stopped():
                # core Debugger.threads() keys off process.IsValid(), which
                # stays true after exit, so it would otherwise report a
                # phantom thread for a dead process.
                return {"ok": True, "threads": []}
            rows = self.dbg.threads()
            return {"ok": True, "threads": [
                {"tid": tid, "index": idx, "name": name, "pc": pc, "function": fn}
                for (tid, idx, name, pc, fn) in rows
            ]}
        if cmd == "select_thread":
            thread_id = _int_arg(args["thread_id"])
            # core Debugger.select_thread -> SBProcess.SetSelectedThreadByID
            # returns False for an unknown id but STILL resets the selection
            # to thread 0 as a side effect -- every subsequent
            # registers/backtrace/memory-read command would then silently
            # operate on the wrong thread. Validate first so a rejected
            # request never touches the real selection at all.
            if not self._process_stopped():
                return {"ok": False, "error": "no stopped process"}
            valid_tids = {tid for (tid, _idx, _name, _pc, _fn) in self.dbg.threads()}
            if thread_id not in valid_tids:
                return {"ok": False, "error": "no thread with id {}".format(thread_id)}
            ok = self.dbg.select_thread(thread_id)
            return {"ok": ok}
        if cmd == "modules":
            rows = self.dbg.modules()
            return {"ok": True, "modules": [
                {"name": name, "base": base, "size": size, "triple": triple}
                for (name, base, size, triple) in rows
            ]}
        if cmd == "disasm":
            raw_addr = args.get("addr")
            addr = _int_arg(raw_addr) if raw_addr is not None else None
            return self.cmd_disasm(addr, _int_arg(args.get("count", 64)))
        if cmd == "read_memory":
            return self.cmd_read_memory(_int_arg(args["addr"]), _int_arg(args["size"]))
        if cmd == "write_memory":
            data = bytes.fromhex(args["hex"])
            ok, msg = self.dbg.write_memory(_int_arg(args["addr"]), data)
            return {"ok": ok, "message": msg}
        if cmd == "write_register":
            ok, msg = self.dbg.write_register(args["name"], _int_arg(args["value"]))
            return {"ok": ok, "message": msg}
        if cmd == "memory_search":
            return self.cmd_memory_search(args)
        if cmd == "extract_strings":
            hits = self.dbg.extract_strings(min_len=_int_arg(args.get("min_len", 5)))
            return {"ok": True, "strings": [{"addr": a, "text": s} for (a, s) in hits]}
        if cmd == "scan_live_strings":
            hits = self.dbg.scan_live_strings(
                min_len=_int_arg(args.get("min_len", 8)),
                budget_bytes=_int_arg(args.get("budget_bytes", 512 * 1024 * 1024)),
            )
            return {"ok": True, "strings": [{"addr": a, "text": s} for (a, s) in hits]}
        if cmd == "defense_enable":
            return self._defense(args["name"], True)
        if cmd == "defense_disable":
            return self._defense(args["name"], False)
        if cmd == "fork_mode":
            self.dbg.fork_interactive = bool(args.get("interactive", False))
            return {"ok": True, "fork_interactive": self.dbg.fork_interactive}
        if cmd == "exec_mode":
            self.dbg.exec_interactive = bool(args.get("interactive", False))
            return {"ok": True, "exec_interactive": self.dbg.exec_interactive}
        if cmd == "dump_exec":
            return self.cmd_dump_exec()
        if cmd == "tracer_enable":
            was_enabled = self.tracer.enabled
            self.tracer.hardware = bool(args.get("hardware", False))
            total, resolved = self.tracer.enable(self.dbg.target, ci=self.dbg.ci)
            return {"ok": True, "total": total, "resolved": resolved, "already_enabled": was_enabled}
        if cmd == "tracer_disable":
            self.tracer.disable(self.dbg.target)
            return {"ok": True}
        if cmd == "tracer_depth":
            self.tracer.caller_depth = _int_arg(args["depth"])
            return {"ok": True, "caller_depth": self.tracer.caller_depth}
        if cmd == "trace_hits":
            since = _int_arg(args.get("since", 0))
            return {"ok": True, "hits": [h for h in self._trace_hits if h["n"] > since]}
        if cmd == "raw":
            ok, out, err = self.dbg.handle_command(args["command"])
            return {"ok": ok, "output": out, "error_output": err}
        if cmd == "save":
            path = self.dbg.save_state(self._hidden_bp_ids())
            return {"ok": path is not None, "path": path}
        raise SessionError("unknown command {!r}".format(cmd))

    # -- fork/exec decisions ---------------------------------------------

    _FORK_DECISIONS = ("parent", "child")
    _EXEC_DECISIONS = ("block", "fake", "allow")

    def _decide_fork(self, decision: str, timeout, poll_cb) -> dict:
        if not self._pending or self._pending.get("kind") != "fork":
            return {"ok": False, "error": "no pending fork decision"}
        # core Debugger.resolve_fork treats anything other than the literal
        # string "child" as "parent" -- an unrecognized token would otherwise
        # silently take the most permissive (real, unshielded) branch. Reject
        # it here instead and leave the decision pending so the caller can
        # retry with a valid one.
        if decision not in self._FORK_DECISIONS:
            return {"ok": False, "error": "invalid fork decision {!r}; choose one of {}".format(
                decision, self._FORK_DECISIONS)}
        self._pending = None
        return self._pump(resume=lambda: self.dbg.resolve_fork(decision),
                           max_wait=timeout, poll_cb=poll_cb)

    def _decide_exec(self, decision: str, timeout, poll_cb) -> dict:
        if not self._pending or self._pending.get("kind") != "exec":
            return {"ok": False, "error": "no pending exec decision"}
        # Same reasoning as _decide_fork: core Debugger.resolve_exec only
        # special-cases "block" and "fake" -- anything else (a typo, an empty
        # string) falls through to "allow" and actually runs the intercepted
        # call. Validate here so a bad decision can't silently fail open.
        if decision not in self._EXEC_DECISIONS:
            return {"ok": False, "error": "invalid exec decision {!r}; choose one of {}".format(
                decision, self._EXEC_DECISIONS)}
        pending = self._pending
        self._pending = None
        return self._pump(
            resume=lambda: self.dbg.resolve_exec(decision, name=pending.get("symbol", "")),
            max_wait=timeout, poll_cb=poll_cb)

    def cmd_dump_exec(self) -> dict:
        if not self._pending or self._pending.get("kind") != "exec":
            return {"ok": False, "error": "no pending exec decision"}
        res = self.dbg.dump_exec_payload(self._pending["bp_id"])
        if res is None:
            return {"ok": False, "error": "dump failed"}
        path, n = res
        return {"ok": True, "path": path, "bytes": n}

    def _defense(self, name: str, enable: bool) -> dict:
        pair = _DEFENSES.get(name)
        if pair is None:
            return {"ok": False, "error": "unknown defense {!r}; choose from {}".format(
                name, sorted(_DEFENSES))}
        method = getattr(self.dbg, pair[0 if enable else 1])
        ok, msg = method()
        return {"ok": ok, "message": msg}

    # -- read-only introspection ------------------------------------------

    def cmd_status(self) -> dict:
        p = self.dbg.process
        state = lldb.SBDebugger.StateAsCString(p.GetState()) if p and p.IsValid() else "none"
        return {
            "ok": True,
            "program": self.program,
            "attach_pid": self.attach_pid,
            "process_state": state,
            "pc": self.dbg.pc(),
            "pending_decision": self._pending,
            "tracer_enabled": self.tracer.enabled,
            "trace_hit_count": self._trace_count,
        }

    def _process_stopped(self) -> bool:
        p = self.dbg.process
        return bool(p and p.IsValid() and p.GetState() == lldb.eStateStopped)

    def cmd_registers(self) -> dict:
        frame = self.dbg.frame()
        if frame is None and self._process_stopped():
            # LLDB sometimes clears the "selected thread" after an interrupt --
            # cmd_registers would then bail with "no stopped frame" even though
            # `raw {"command": "register read"}` still works, because the
            # command interpreter falls back to thread 0 implicitly. Mirror
            # that fallback so callers don't have to manually select_thread
            # after every interrupt.
            proc = self.dbg.process
            if proc and proc.GetNumThreads() > 0:
                for i in range(proc.GetNumThreads()):
                    t = proc.GetThreadAtIndex(i)
                    if t and t.IsValid():
                        proc.SetSelectedThread(t)
                        frame = self.dbg.frame()
                        if frame is not None:
                            break
        if frame is None:
            return {"ok": False, "error": "no stopped frame"}
        rows = collect_regs(frame, prev={}, read_mem=self.dbg.read_memory,
                             target=self.dbg.target, annot_cache={})
        return {"ok": True, "registers": [
            {"name": r.name, "value": r.value, "annotation": r.annotation} for r in rows
        ]}

    def cmd_disasm(self, addr: Optional[int], count: int) -> dict:
        if not self.dbg.target:
            return {"ok": False, "error": "no target"}
        # count<=0 rounds/clamps to nonsense (a negative even count still
        # passes a negative uint32 straight into the SWIG binding and blows
        # up with a raw C++ TypeError) -- clamp to a sane minimum first.
        count = max(1, int(count))
        count = count + (count % 2)
        explicit = addr is not None
        # dbg.pc() is None/0 once the process has exited; disasm_around
        # short-circuits to [] whenever its `pc` arg is 0, which wrongly
        # empties out a request for a perfectly valid explicit address (the
        # static __text section is still there even with no live process).
        # Fall back to the requested center for the pc arg in that case --
        # it only affects which row gets marked is_pc.
        pc = self.dbg.pc() or 0
        center = int(addr) if explicit else pc
        if pc == 0 and explicit:
            pc = center
        # disasm_around windows its read as [center - count*2, center + count*2)
        # -- a byte-count heuristic, not an instruction-aligned one. Two
        # consequences for a headless, non-visual caller (the TUI's DisasmPane
        # gets away with this because a human scrolls past the noise):
        #  1. On fixed-width ISAs (arm64: 4 bytes/insn) an odd `count` makes
        #     count*2 not a multiple of 4, so the window starts mid-instruction
        #     and every row decodes as garbage.
        #  2. On variable-length ISAs (x86_64) walking past the end of a small
        #     function into embedded data (string constants, padding) desyncs
        #     the decoder for the rest of the window, with no resync point.
        # Fix: round the window to an even instruction count (fixes #1), and
        # clamp/filter to the enclosing function or symbol's real address
        # range when it can be resolved (fixes #2), falling back to the
        # __text section bounds when no function/symbol covers `center`.
        bounds = self._function_bounds(center) or self._text_bounds()
        if bounds is not None:
            lo, hi = bounds
            if explicit and (center < lo or center >= hi):
                # An address explicitly outside the resolved range is a bad
                # request, not "please show me the nearest valid spot" --
                # silently relocating it there (the old behavior, and for a
                # while only applied below the range, not above) hides the
                # mistake and can return real-looking instructions from the
                # wrong address entirely.
                return {"ok": False, "error":
                         "address {:#x} is outside its resolved range [{:#x}, {:#x})".format(
                             center, lo, hi)}
        raw_center = center

        def _clamp(cnt: int) -> int:
            if bounds is None:
                result = raw_center
            else:
                lo, hi = bounds
                min_c, max_c = lo + cnt * 2, hi - cnt * 2
                if max_c < min_c:
                    result = (lo + hi) // 2  # window doesn't fit -- center it
                else:
                    result = max(min_c, min(raw_center, max_c))
            # arm64 instructions are fixed 4-byte width; an unaligned center
            # makes disasm_around's byte-offset window start mid-instruction
            # and decode garbage for the whole request -- most likely to bite
            # exactly on the `(lo + hi) // 2` fallback above, or once `cnt`
            # has been halved down to an odd number by the retry loop below.
            return result & ~0x3

        def _attempt(cnt: int, ctr: int) -> List:
            rows = disasm_around(self.dbg.target, pc, count=cnt,
                                  read_mem=self.dbg.read_memory, center=ctr,
                                  frame=self.dbg.frame())
            if bounds is not None:
                lo, hi = bounds
                rows = [r for r in rows if lo <= r.addr < hi]
            return rows

        # target.ReadInstructions (inside disasm_around) is all-or-nothing:
        # if `count` instructions would run past the end of contiguously
        # mapped memory it returns an *empty* list rather than a partial one.
        # A huge `count` first clamps the center way out past `hi` (there's
        # nowhere for a window that big to fit), so retrying with a smaller
        # count must *recompute* the center from scratch each time -- reusing
        # the previous (now oversized) center just repeats the same failure.
        # The post-bounds-filter is checked too (not just the raw decode
        # result), since a fit-by-force window can decode fine but land
        # entirely outside the range on a very small function.
        rows = _attempt(count, _clamp(count))
        attempts = 0
        while not rows and count > 2 and attempts < 20:
            count = max(2, count // 2)
            count = count + (count % 2)  # keep it even every halving, not just once
            rows = _attempt(count, _clamp(count))
            attempts += 1
        return {"ok": True, "instructions": [
            {"addr": r.addr, "bytes": r.raw.hex(), "mnemonic": r.mnemonic,
             "operands": r.operands, "comment": r.comment, "is_pc": r.is_pc}
            for r in rows
        ]}

    def _function_bounds(self, addr: int) -> Optional[tuple]:
        target = self.dbg.target
        if not target:
            return None
        sb_addr = lldb.SBAddress(addr, target)
        ctx = target.ResolveSymbolContextForAddress(
            sb_addr, lldb.eSymbolContextFunction | lldb.eSymbolContextSymbol)
        fn = ctx.GetFunction()
        if fn and fn.IsValid():
            lo = fn.GetStartAddress().GetLoadAddress(target)
            hi = fn.GetEndAddress().GetLoadAddress(target)
            if lo != lldb.LLDB_INVALID_ADDRESS and hi > lo:
                return lo, hi
        sym = ctx.GetSymbol()
        if sym and sym.IsValid():
            lo = sym.GetStartAddress().GetLoadAddress(target)
            hi = sym.GetEndAddress().GetLoadAddress(target)
            if lo != lldb.LLDB_INVALID_ADDRESS and hi > lo:
                return lo, hi
        return None

    def _text_bounds(self) -> Optional[tuple]:
        target = self.dbg.target
        if not target:
            return None
        exe_name = target.GetExecutable().GetFilename() or ""
        for m in target.module_iter():
            if (m.GetFileSpec().GetFilename() or "") != exe_name:
                continue
            sec = m.FindSection("__TEXT")
            if not sec or not sec.IsValid():
                continue
            sub = sec.FindSubSection("__text")
            if sub and sub.IsValid():
                lo = sub.GetLoadAddress(target)
                return lo, lo + sub.GetByteSize()
        return None

    def cmd_read_memory(self, addr: int, size: int) -> dict:
        data = self.dbg.read_memory(addr, size)
        if not data and size:
            return {"ok": False, "error": "read failed or unreadable"}
        printable = sum(1 for b in data if 32 <= b < 127)
        ascii_ = printable / len(data) > 0.6 if data else False
        return {"ok": True, "addr": addr, "hex": data.hex(),
                "ascii": data.decode("ascii", "replace") if ascii_ else None}

    def cmd_memory_search(self, args: dict) -> dict:
        needle_hex = args.get("needle_hex")
        needle = bytes.fromhex(needle_hex) if needle_hex else args.get("needle_ascii", "").encode()
        if not needle:
            return {"ok": False, "error": "needle_hex or needle_ascii required"}
        max_hits = _int_arg(args.get("max_hits", 32))
        if max_hits <= 0:
            # core Debugger.memory_search appends a hit *then* checks
            # len(hits) >= max_hits, so max_hits=0 still returns one hit.
            return {"ok": True, "hits": [], "bytes_scanned": 0}
        kwargs = {"max_hits": max_hits, "scope": args.get("scope", "target")}
        if "budget_bytes" in args:
            # Exposes core's total_budget_bytes so a caller can bound a
            # scope="all" scan themselves -- it defaults to a multi-GB sweep
            # of the whole address space, which can take tens of seconds.
            kwargs["total_budget_bytes"] = _int_arg(args["budget_bytes"])
        hits, scanned = self.dbg.memory_search(needle, **kwargs)
        return {"ok": True, "hits": [hex(h) for h in hits], "bytes_scanned": scanned}

    def cmd_restart(self) -> dict:
        if self.attach_pid:
            return {"ok": False, "error": "restart not available for an attached process"}
        if not self.dbg.target or not self.dbg.target.IsValid():
            return {"ok": False, "error": "no target loaded"}
        # Check the binary is still there *before* killing the current
        # process -- launch() itself can fail for other reasons too, but this
        # catches the common case (binary deleted/replaced/rights removed
        # mid-session) without destroying a working session over it.
        if self.program and not os.access(self.program, os.X_OK):
            return {"ok": False, "error":
                     "refusing to restart: {!r} is no longer executable "
                     "(deleted, replaced, or permissions changed?)".format(self.program)}
        # A pending fork/exec decision refers to a breakpoint hit in the
        # process we're about to kill -- resolving it after relaunch would
        # act on the wrong (or a nonexistent) stop. Restart makes it moot.
        self._pending = None
        p = self.dbg.process
        if p and p.IsValid() and p.GetState() not in (lldb.eStateExited, lldb.eStateInvalid):
            p.Kill()
        hidden = self._hidden_bp_ids()
        for bid in hidden:
            self.dbg.set_bp_enabled(bid, False)
        try:
            self.dbg.launch(list(self.program_args))
        except Exception as e:
            return {"ok": False, "error": "relaunch failed: {}".format(e)}
        finally:
            for bid in hidden:
                self.dbg.set_bp_enabled(bid, True)
        self._drain_lldb_pipe()
        proc = self.dbg.process
        result: dict = {"ok": True, "console": self._drain_console()}
        if proc and proc.IsValid():
            st = proc.GetState()
            if st == lldb.eStateStopped:
                self.dbg.select_stopped_thread()
                result["event"] = "stop"
                result["stop"] = self._describe_stop()
            elif st == lldb.eStateExited:
                result["event"] = "exited"
                result["exit"] = self._describe_exit()
        return result

    # -- the event pump ----------------------------------------------------

    def _pump(self, resume: Optional[Callable[[], None]] = None,
              wait_timeout: float = DEFAULT_WAIT_TIMEOUT,
              max_wait: Optional[float] = None,
              poll_cb: Optional[Callable[[], None]] = None) -> dict:
        """Resume (if given) and poll dbg.listener until a genuine stop,
        an exit, or an interactive fork/exec decision point is reached.
        Anti-debug and tracer breakpoint hits are handled and auto-continued
        transparently, mirroring WrapperApp._on_stop_event."""
        p = self.dbg.process
        if not p or not p.IsValid() or p.GetState() in (lldb.eStateExited, lldb.eStateInvalid):
            return {"ok": False, "error":
                     "process is not running (already exited or never started); "
                     "use 'restart' to relaunch"}
        if max_wait is not None and not isinstance(max_wait, (int, float)):
            # Validate before resume() runs -- otherwise a bad timeout value
            # resumes the process and then blows up on the comparison below,
            # leaving it running uncontrolled with no way back but interrupt.
            return {"ok": False, "error": "timeout must be a number, got {!r}".format(max_wait)}
        if resume is not None:
            resume()
        event = lldb.SBEvent()
        wait_timeout = max(1, int(wait_timeout))
        # Wall-clock deadline, checked every iteration regardless of whether
        # WaitForEvent actually timed out. The old code only advanced
        # `waited` in the "no event" branch, so a target that emits at least
        # one process event (e.g. STDOUT) per wait_timeout tick -- a chatty
        # runaway loop, exactly the case a timeout exists to catch -- kept
        # `got` truthy forever and the deadline was never evaluated: the
        # documented timeout silently never fired.
        deadline = time.monotonic() + max_wait if max_wait is not None else None

        def _deadline_hit() -> Optional[dict]:
            # Only ever consulted right before looping back for another
            # WaitForEvent -- never before a genuine stop/exited/terminated/
            # pending_decision result is returned. The first version of this
            # fix checked the deadline unconditionally at the top of the
            # loop, which could discard an already-dequeued terminal event
            # that landed in the very tick the deadline crossed (WaitForEvent
            # removes it from the listener queue, so that stop was gone for
            # good -- a later `wait` would just hang or time out again).
            if deadline is not None and time.monotonic() >= deadline:
                return {"ok": True, "event": "running",
                        "console": self._drain_console(),
                        "note": "still running after {}s; call 'wait' or 'interrupt'".format(max_wait)}
            return None

        while True:
            got = self.dbg.listener.WaitForEvent(wait_timeout, event)
            self._drain_lldb_pipe()
            if poll_cb is not None:
                poll_cb()
            if not got:
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            if not lldb.SBProcess.EventIsProcessEvent(event):
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            etype = event.GetType()
            if etype & lldb.SBProcess.eBroadcastBitSTDOUT:
                proc = lldb.SBProcess.GetProcessFromEvent(event)
                chunk = proc.GetSTDOUT(4096)
                if chunk:
                    self._log(chunk)
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            if etype & lldb.SBProcess.eBroadcastBitSTDERR:
                proc = lldb.SBProcess.GetProcessFromEvent(event)
                chunk = proc.GetSTDERR(4096)
                if chunk:
                    self._log(chunk, error=True)
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            if not (etype & lldb.SBProcess.eBroadcastBitStateChanged):
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            state = lldb.SBProcess.GetStateFromEvent(event)
            if state == lldb.eStateRunning:
                hit = _deadline_hit()
                if hit is not None:
                    return hit
                continue
            if state == lldb.eStateStopped:
                self.dbg.select_stopped_thread()
                if self.dbg.in_fork_shield():
                    self.dbg.finish_fork_shield()
                    self.dbg.cont()
                    hit = _deadline_hit()
                    if hit is not None:
                        return hit
                    continue
                pending = self._check_pending_interactive()
                if pending is not None:
                    self._pending = pending
                    return {"ok": True, "event": "pending_decision",
                            "decision": pending, "console": self._drain_console()}
                if self._try_auto_anti_debug():
                    hit = _deadline_hit()
                    if hit is not None:
                        return hit
                    continue
                if self.tracer.enabled and self._try_trace_hit():
                    hit = _deadline_hit()
                    if hit is not None:
                        return hit
                    continue
                return {"ok": True, "event": "stop", "stop": self._describe_stop(),
                        "console": self._drain_console()}
            if state == lldb.eStateExited:
                self._pending = None
                return {"ok": True, "event": "exited", "exit": self._describe_exit(),
                        "console": self._drain_console()}
            if state in (lldb.eStateCrashed, lldb.eStateDetached, lldb.eStateInvalid):
                self._pending = None
                return {"ok": True, "event": "terminated",
                        "lldb_state": lldb.SBDebugger.StateAsCString(state),
                        "console": self._drain_console()}
            hit = _deadline_hit()
            if hit is not None:
                return hit
            continue

    # -- ported orchestration (WrapperApp._handle_anti_debug_hit et al.) --

    @staticmethod
    def _stop_bp_ids(thread) -> List[int]:
        ids: List[int] = []
        n = thread.GetStopReasonDataCount()
        i = 0
        while i < n:
            ids.append(thread.GetStopReasonDataAtIndex(i))
            i += 2
        return ids

    def _check_pending_interactive(self) -> Optional[dict]:
        process = self.dbg.process
        if not process or not process.IsValid():
            return None
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return None
        bp_ids = self._stop_bp_ids(thread)
        if not bp_ids:
            return None
        if self.dbg.exec_bp_ids:
            exec_bp = next((b for b in bp_ids if b in self.dbg.exec_bp_ids), None)
            if exec_bp is not None:
                self._log_exec_trace(thread)
                if self.dbg.exec_interactive:
                    peeked = self.dbg.peek_exec_hit(exec_bp)
                    if peeked is not None:
                        name, cmd = peeked
                        return {"kind": "exec", "bp_id": exec_bp, "symbol": name, "command": cmd}
        if self.dbg.fork_interactive and self.dbg.fork_bp_ids:
            fork_bp = next((b for b in bp_ids if b in self.dbg.fork_bp_ids), None)
            if fork_bp is not None:
                name = self.dbg.peek_fork_hit(fork_bp)
                if name is not None:
                    return {"kind": "fork", "bp_id": fork_bp, "symbol": name}
        return None

    def _log_exec_trace(self, thread) -> None:
        if not self.tracer.enabled:
            return
        frame = thread.GetFrameAtIndex(0)
        hit = self.tracer.hit_from(frame, self.dbg.process)
        if hit is not None:
            self._trace_count += 1
            self._trace_hits.append({"n": self._trace_count, "category": hit.category, "call": hit.call})

    def _try_auto_anti_debug(self) -> bool:
        process = self.dbg.process
        if not process or not process.IsValid():
            return False
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return False
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        bp_ids = self._stop_bp_ids(thread)
        if not bp_ids:
            return False
        for handler in (self.dbg.handle_anti_ptrace_hit,
                        self.dbg.handle_anti_mach_hit,
                        self.dbg.handle_direct_syscall_hit,
                        self.dbg.handle_fork_hit,
                        self.dbg.handle_setsid_hit,
                        self.dbg.handle_exec_hit):
            for bp_id in bp_ids:
                msg = handler(bp_id)
                if msg is not None:
                    self._log("[anti-debug] " + msg)
                    return True
        return False

    def _try_trace_hit(self) -> bool:
        process = self.dbg.process
        if not process or not process.IsValid():
            return False
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return False
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        bp_id = next((b for b in self._stop_bp_ids(thread) if self.tracer.is_trace_bp(b)), None)
        if bp_id is None:
            return False
        frame = thread.GetFrameAtIndex(0)
        hit = self.tracer.hit_from(frame, process, bp_id=bp_id)
        if hit is not None:
            self._trace_count += 1
            self._trace_hits.append({"n": self._trace_count, "category": hit.category, "call": hit.call})
        self.dbg.cont()
        return True

    def _bp_id_at_addr(self, addr: int) -> Optional[int]:
        # dbg.breakpoints() only reports location 0 of each breakpoint, but
        # core Debugger.toggle_breakpoint_at (which this guards) matches
        # against ALL locations -- checking only breakpoints() here could
        # miss a multi-location internal breakpoint whose matching location
        # isn't index 0, letting toggle silently delete it past the guard.
        target = self.dbg.target
        if not target:
            return None
        for i in range(target.GetNumBreakpoints()):
            bp = target.GetBreakpointAtIndex(i)
            for j in range(bp.GetNumLocations()):
                if bp.GetLocationAtIndex(j).GetLoadAddress() == addr:
                    return bp.GetID()
        return None

    def _guard_hidden_bp(self, bp_id: int) -> Optional[dict]:
        """Refuse to let a caller directly mutate a tracer/anti-debug
        breakpoint -- disabling, deleting, or reconditioning one silently
        defeats the defense while `status`/`breakpoint_list` (default) keep
        reporting it as armed. The caller must go through
        defense_disable/tracer_disable instead."""
        if bp_id in self._hidden_bp_ids():
            return {"ok": False, "error":
                     "bp_id {} belongs to an internal defense/tracer breakpoint; "
                     "use defense_disable/tracer_disable instead of editing it directly".format(bp_id)}
        return None

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

    def _describe_exit(self) -> dict:
        p = self.dbg.process
        if not p or not p.IsValid():
            return {"text": "process exited."}
        code = p.GetExitStatus()
        desc = p.GetExitDescription() or ""
        text = "process exited with code {}".format(code) + (" ({})".format(desc) if desc else "") + "."
        return {"text": text, "code": code, "description": desc}

    def _describe_stop(self) -> dict:
        process = self.dbg.process
        if not process or not process.IsValid():
            return {"text": "[stopped]"}
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return {"text": "[stopped]"}
        reason = thread.GetStopReason()
        pc = self.dbg.pc() or 0
        frame = thread.GetFrameAtIndex(0)
        sym = ""
        if frame and frame.IsValid():
            sym = frame.GetFunctionName() or (
                frame.GetSymbol().GetName() if frame.GetSymbol().IsValid() else "") or ""
        info = {"pc": pc, "function": sym, "thread_id": thread.GetThreadID(), "reason_code": reason}
        where = " in {}".format(sym) if sym else ""
        if reason == lldb.eStopReasonBreakpoint and thread.GetStopReasonDataCount() >= 1:
            bp_id = thread.GetStopReasonDataAtIndex(0)
            loc_id = thread.GetStopReasonDataAtIndex(1) if thread.GetStopReasonDataCount() >= 2 else 0
            bp = self.dbg.target.FindBreakpointByID(bp_id) if self.dbg.target else None
            cond = (bp.GetCondition() if bp and bp.IsValid() else None) or ""
            cond_txt = " (cond: {})".format(cond) if cond and cond.strip() not in ("", "1") else ""
            info.update(reason="breakpoint", bp_id=bp_id, loc_id=loc_id,
                        text="[stop] breakpoint #{}.{} at {:#x}{}{}".format(bp_id, loc_id, pc, where, cond_txt))
            return info
        if reason == lldb.eStopReasonWatchpoint and thread.GetStopReasonDataCount() >= 1:
            wp_id = thread.GetStopReasonDataAtIndex(0)
            info.update(reason="watchpoint", wp_id=wp_id,
                        text="[stop] watchpoint #{} at {:#x}{}".format(wp_id, pc, where))
            return info
        if reason == lldb.eStopReasonPlanComplete:
            info.update(reason="step", text="[stop] step complete at {:#x}{}".format(pc, where))
            return info
        if reason == lldb.eStopReasonException:
            desc = thread.GetStopDescription(256)
            info.update(reason="exception", description=desc,
                        text="[stop] exception at {:#x}{}: {}".format(pc, where, desc))
            return info
        if reason == lldb.eStopReasonSignal and thread.GetStopReasonDataCount() >= 1:
            sig = thread.GetStopReasonDataAtIndex(0)
            info.update(reason="signal", signal=sig,
                        text="[stop] signal {} at {:#x}{}".format(sig, pc, where))
            return info
        if reason == lldb.eStopReasonTrace:
            info.update(reason="trace", text="[stop] trace at {:#x}{}".format(pc, where))
            return info
        info.update(reason="other", text="[stop] at {:#x}{} (reason={})".format(pc, where, reason))
        return info

    # -- console buffer ------------------------------------------------

    def _log(self, text: str, error: bool = False) -> None:
        if error:
            text = "\n".join("! " + l for l in text.splitlines()) + ("\n" if text.endswith("\n") else "")
        self._console.append(text)

    def _drain_lldb_pipe(self) -> None:
        while True:
            text = self.dbg.read_output()
            if not text:
                return
            self._console.append(text)

    def _drain_console(self) -> str:
        text = "".join(self._console)
        self._console = []
        return text
