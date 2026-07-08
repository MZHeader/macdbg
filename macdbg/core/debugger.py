from __future__ import annotations

import os
import re
import struct
import time
from typing import Dict, List, Optional, Tuple

import lldb

from .state import BinaryState, StoredBP, Patch, load_for, STATE_DIR


def _looks_like_string(span: bytes, wanted: set) -> bool:
    if not span:
        return False
    if len(set(span)) == 1:
        return False
    letters = sum(1 for b in span if b in wanted)
    if letters == 0:
        return False
    if letters < max(2, len(span) // 4):
        return False
    return True


class Debugger:
    def __init__(self) -> None:
        self.dbg = lldb.SBDebugger.Create()
        self.dbg.SetAsync(True)
        self.ci = self.dbg.GetCommandInterpreter()
        self.target: Optional[lldb.SBTarget] = None
        self.process: Optional[lldb.SBProcess] = None
        self.listener: lldb.SBListener = self.dbg.GetListener()
        self._attached: bool = False
        self.state: Optional[BinaryState] = None
        self.interpose_enabled: bool = False
        self.interpose_trace_path: Optional[str] = None
        # State for completing an in-flight user step across stop events, so a
        # step's thread plan surviving a tracer/anti-debug breakpoint is driven
        # by frame depth rather than left to be hijacked by an auto-continue.
        self._step_active: bool = False
        self._step_target_depth: Optional[int] = None

        self._out_r_fd, self._out_w_fd = os.pipe()
        os.set_blocking(self._out_r_fd, False)
        self._out_w_file = os.fdopen(self._out_w_fd, "w", buffering=1)
        self.dbg.SetOutputFileHandle(self._out_w_file, False)
        self.dbg.SetErrorFileHandle(self._out_w_file, False)

        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("settings set target.disable-aslr true", ret, False)

    def read_output(self, max_bytes: int = 4096) -> str:
        try:
            data = os.read(self._out_r_fd, max_bytes)
        except (BlockingIOError, OSError):
            return ""
        return data.decode("utf-8", errors="replace") if data else ""

    def create_target(self, path: str) -> lldb.SBTarget:
        err = lldb.SBError()
        self.target = self.dbg.CreateTarget(path, None, None, True, err)
        if not err.Success() or not self.target.IsValid():
            raise RuntimeError(f"CreateTarget failed: {err.GetCString()}")
        try:
            self.state = load_for(path)
        except Exception:
            self.state = None
        return self.target

    def restore_stored_breakpoints(self) -> int:
        if not self.state or not self.target or not self.target.IsValid():
            return 0
        n = 0
        for sbp in self.state.breakpoints:
            bp = self.target.BreakpointCreateByAddress(sbp.addr)
            if not bp.IsValid():
                continue
            if sbp.condition:
                bp.SetCondition(sbp.condition)
            if sbp.commands:
                sl = lldb.SBStringList()
                for line in sbp.commands:
                    sl.AppendString(line)
                bp.SetCommandLineCommands(sl)
            bp.SetEnabled(sbp.enabled)
            n += 1
        return n

    def snapshot_user_breakpoints(self, exclude_ids: set) -> List[StoredBP]:
        out: List[StoredBP] = []
        if not self.target:
            return out
        for i in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(i)
            if bp.GetID() in exclude_ids:
                continue
            if bp.GetNumLocations() == 0:
                continue
            loc = bp.GetLocationAtIndex(0)
            addr = loc.GetLoadAddress()
            if addr == lldb.LLDB_INVALID_ADDRESS or addr == 0:
                continue
            symbol = ""
            try:
                symbol = loc.GetAddress().GetSymbol().GetName() or ""
            except Exception:
                pass
            sl = lldb.SBStringList()
            bp.GetCommandLineCommands(sl)
            commands = [sl.GetStringAtIndex(j) for j in range(sl.GetSize())]
            out.append(StoredBP(
                addr=addr,
                symbol=symbol,
                condition=bp.GetCondition() or "",
                commands=commands,
                enabled=bp.IsEnabled(),
            ))
        return out

    def save_state(self, exclude_ids: set) -> Optional[str]:
        if not self.state:
            return None
        self.state.breakpoints = self.snapshot_user_breakpoints(exclude_ids)
        return self.state.save()

    def interpose_dylib(self) -> str:
        """Path to the DYLD interposer. A prebuilt universal (arm64+x86_64) dylib
        ships in the repo so a stock box with no toolchain and no network works
        out of the box; it's only recompiled from source if the prebuilt is
        missing or doesn't cover this machine's architecture. Returns '' if
        neither is usable."""
        here = os.path.dirname(os.path.abspath(__file__))
        native = os.path.join(os.path.dirname(here), "native")
        dylib = os.path.join(native, "interpose.dylib")
        src = os.path.join(native, "interpose.c")
        if os.path.exists(dylib) and self._dylib_covers_host(dylib):
            return dylib
        if not os.path.exists(src):
            return dylib if os.path.exists(dylib) else ""
        import subprocess
        try:
            subprocess.run(
                ["clang", "-dynamiclib", "-O2", "-o", dylib, src],
                check=True, capture_output=True,
            )
        except Exception:
            return dylib if os.path.exists(dylib) else ""
        return dylib

    @staticmethod
    def _dylib_covers_host(dylib: str) -> bool:
        # The bundled dylib is universal, but a machine could be an arch neither
        # slice covers; if lipo can't confirm the host arch is present, fall back
        # to recompiling.
        import platform
        import subprocess
        host = platform.machine()
        try:
            out = subprocess.run(
                ["lipo", "-archs", dylib], capture_output=True, text=True, check=True
            ).stdout
        except Exception:
            return True
        return host in out.split()

    # The interposer's trace records go to this fixed fd (opened by an lldb file
    # action, inherited across the fork tree) rather than one the interposer
    # opens itself. A known number lets the lldb tracer skip its own hits on it,
    # so the interposer's writes don't get double-traced as garbage rows.
    INTERPOSE_FD = 199

    def _interpose_env(self, info: lldb.SBLaunchInfo) -> List[str]:
        dylib = self.interpose_dylib()
        if not dylib:
            self.interpose_trace_path = None
            return []
        import tempfile
        fd, path = tempfile.mkstemp(prefix="macdbg-trace-", suffix=".tsv")
        os.close(fd)
        self.interpose_trace_path = path
        info.AddOpenFileAction(self.INTERPOSE_FD, path, False, True)
        return [
            "DYLD_INSERT_LIBRARIES={}".format(dylib),
            "MACDBG_TRACE_FD={}".format(self.INTERPOSE_FD),
        ]

    def launch(self, argv: List[str]) -> lldb.SBProcess:
        assert self.target is not None
        # Drop any step-in-progress state from a prior run so the first stop of
        # the fresh process can't be mistaken for a step to complete.
        self._step_active = False
        self._step_target_depth = None
        self._pending_step_scrubs = None
        self._fake_clock = 0
        self._anti_timing_logged = False
        self._clear_flag_scrub_returns()
        info = lldb.SBLaunchInfo(argv)
        info.SetLaunchFlags(
            lldb.eLaunchFlagStopAtEntry | lldb.eLaunchFlagDisableASLR
        )
        # A fresh SBLaunchInfo launches with an empty environment, so the target
        # sees no PATH and anything it shells out to (do shell script, system,
        # posix_spawn) falls back to /usr/bin:/bin and can't find tools in
        # /usr/sbin like system_profiler. Inherit our environment, minus the
        # PYTHONPATH macdbg.sh injected for its own use.
        env = ["{}={}".format(k, v) for k, v in os.environ.items() if k != "PYTHONPATH"]
        # The interposer rides DYLD_INSERT_LIBRARIES into every child of the fork
        # tree and reports to a temp file macdbg tails, so children get traced
        # even though lldb can't follow a fork on macOS.
        if self.interpose_enabled:
            env += self._interpose_env(info)
        else:
            self.interpose_trace_path = None
        info.SetEnvironmentEntries(env, True)
        was_async = self.dbg.GetAsync()
        self.dbg.SetAsync(False)
        try:
            err = lldb.SBError()
            self.process = self.target.Launch(info, err)
            if not err.Success():
                raise RuntimeError(f"Launch failed: {err.GetCString()}")
            self._attached = False
            self._advance_to_entry_point()
        finally:
            self.dbg.SetAsync(was_async)
        self._hook_listener(self.process)
        return self.process

    def entry_point_address(self) -> Optional[int]:
        """Load address of the executable's entry point (LC_MAIN entryoff plus
        the image base), not dyld's _dyld_start. Falls back to the
        start/_start/main symbol, or None."""
        if not self.target or not self.target.IsValid():
            return None
        exec_name = self.target.GetExecutable().GetFilename() or ""
        exec_mod = None
        for i in range(self.target.GetNumModules()):
            m = self.target.GetModuleAtIndex(i)
            if m.GetFileSpec().GetFilename() == exec_name:
                exec_mod = m
                break
        if exec_mod is None:
            return None
        hdr = exec_mod.GetObjectFileHeaderAddress().GetLoadAddress(self.target)
        if hdr not in (0, lldb.LLDB_INVALID_ADDRESS):
            entryoff = self._read_lc_main_entryoff(hdr)
            if entryoff is not None:
                return hdr + entryoff
        for name in ("start", "_start", "main"):
            syms = exec_mod.FindSymbols(name)
            for j in range(syms.GetSize()):
                sym = syms.GetContextAtIndex(j).GetSymbol()
                if sym.IsValid():
                    a = sym.GetStartAddress().GetLoadAddress(self.target)
                    if a not in (0, lldb.LLDB_INVALID_ADDRESS):
                        return a
        return None

    def _read_lc_main_entryoff(self, hdr_addr: int) -> Optional[int]:
        """Find LC_MAIN's entryoff in the Mach-O header at hdr_addr. 64-bit
        little-endian only; None otherwise."""
        head = self.read_memory(hdr_addr, 32)
        if len(head) < 32:
            return None
        magic = struct.unpack_from("<I", head, 0)[0]
        if magic != 0xFEEDFACF:
            return None
        ncmds = struct.unpack_from("<I", head, 16)[0]
        sizeofcmds = struct.unpack_from("<I", head, 20)[0]
        cmds = self.read_memory(hdr_addr + 32, min(sizeofcmds, 65536))
        LC_MAIN = 0x80000028
        off = 0
        for _ in range(ncmds):
            if off + 8 > len(cmds):
                break
            cmd, cmdsize = struct.unpack_from("<II", cmds, off)
            if cmdsize == 0:
                break
            if cmd == LC_MAIN and off + 16 <= len(cmds):
                return struct.unpack_from("<Q", cmds, off + 8)[0]
            off += cmdsize
        return None

    def _advance_to_entry_point(self) -> None:
        """Run from _dyld_start to the executable's entry point with a one-shot
        breakpoint. Debugger must be synchronous. If an earlier user breakpoint
        fires first we stop there and drop the one-shot."""
        if not self.process or not self.process.IsValid():
            return
        if self.process.GetState() != lldb.eStateStopped:
            return
        ep = self.entry_point_address()
        if ep is None or (self.pc() or 0) == ep:
            return
        bp = self.target.BreakpointCreateByAddress(ep)
        if not bp.IsValid():
            return
        bp.SetOneShot(True)
        bp_id = bp.GetID()
        self.process.Continue()
        if self.process.GetState() != lldb.eStateStopped or (self.pc() or 0) != ep:
            self.target.BreakpointDelete(bp_id)

    def attach_pid(self, pid: int) -> lldb.SBProcess:
        self.target = self.dbg.CreateTarget("")
        if not self.target.IsValid():
            raise RuntimeError("failed to create empty target for attach")
        err = lldb.SBError()
        info = lldb.SBAttachInfo(pid)
        info.SetWaitForLaunch(False)
        self.process = self.target.Attach(info, err)
        if not err.Success() or not self.process or not self.process.IsValid():
            raise RuntimeError(
                "attach failed: {}".format(err.GetCString() or "unknown"))
        self._attached = True
        self._hook_listener(self.process)
        return self.process

    def _hook_listener(self, process: lldb.SBProcess) -> None:
        mask = (
            lldb.SBProcess.eBroadcastBitStateChanged
            | lldb.SBProcess.eBroadcastBitSTDOUT
            | lldb.SBProcess.eBroadcastBitSTDERR
        )
        process.GetBroadcaster().AddListener(self.listener, mask)

    def ensure_listening(self) -> bool:
        if not self.target or not self.target.IsValid():
            return False
        current = self.target.GetProcess()
        if not current.IsValid():
            return False
        if self.process is None or current.GetProcessID() != self.process.GetProcessID():
            self.process = current
            self._hook_listener(self.process)
            return True
        return False

    def destroy(self) -> None:
        if self.process and self.process.IsValid():
            if self._attached:
                self.process.Detach()
            else:
                self.process.Kill()
        try:
            self._out_w_file.close()
        except Exception:
            pass
        lldb.SBDebugger.Destroy(self.dbg)

    def cont(self) -> None:
        if self.process:
            self.process.Continue()

    def run_to_address(self, addr: int) -> Tuple[bool, str]:
        """Set a one-shot breakpoint at `addr` and continue to it. Returns
        (started, message). Refuses unless the process is stopped and `addr`
        resolves to a real code location, so a stray run-to on a non-code line
        (or while already running) can't silently turn into a run to exit."""
        if not self.target or not self.target.IsValid() or not self.process:
            return False, "no process"
        if self.process.GetState() != lldb.eStateStopped:
            return False, "process is running"
        cur = self.pc()
        if cur is not None and addr == cur:
            return False, "already at {:#x}".format(addr)
        bp = self.target.BreakpointCreateByAddress(addr)
        if (not bp.IsValid() or bp.GetNumLocations() == 0
                or not bp.GetLocationAtIndex(0).IsResolved()):
            if bp.IsValid():
                self.target.BreakpointDelete(bp.GetID())
            return False, "no runnable code at {:#x}".format(addr)
        bp.SetOneShot(True)
        t = self._thread()
        if t:
            bp.SetThreadID(t.GetThreadID())
        self.process.Continue()
        return True, "running to {:#x}".format(addr)

    def step_in(self) -> None:
        t = self._thread()
        if t:
            # Single instruction, no depth target: whatever it lands on is the
            # stop, even if that is a traced libSystem entry.
            self._step_active = True
            self._step_target_depth = None
            self._pending_step_scrubs = None
            t.StepInstruction(False)

    def step_out(self) -> None:
        """Run until the current frame returns (gdb's 'finish')."""
        t = self._thread()
        if t:
            self._step_active = True
            self._step_target_depth = t.GetNumFrames() - 1
            self._pending_step_scrubs = None
            t.StepOut()

    _CALL_MNEMONICS = {"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"}

    def _is_call_at(self, pc: int) -> bool:
        if not self.target or not self.target.IsValid():
            return False
        insns = self.target.ReadInstructions(lldb.SBAddress(pc, self.target), 1)
        if insns.GetSize() < 1:
            return False
        mn = (insns.GetInstructionAtIndex(0).GetMnemonic(self.target) or "").lower()
        return mn in self._CALL_MNEMONICS

    def step_over(self) -> None:
        """Step over the current instruction.

        We never use StepInstruction(step_over=True): its step-over-a-call thread
        plan can run to process exit on some call sites (indirect / PAC calls
        especially). Instead:
          * non-call: StepInstruction(False), a single instruction step.
          * call: StepInstruction(False) to step *into* the callee, then
            advance_user_step() runs back out to the caller frame.
        advance_user_step() completes the step by frame depth, so tracer /
        anti-debug breakpoints firing inside the callee can't hijack it into a
        free run (the "step over runs away when Trace is on" bug)."""
        t = self._thread()
        if not t or not self.target or not self.target.IsValid():
            return
        frame = t.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return
        self._step_active = True
        self._pending_step_scrubs = None
        if self._is_call_at(frame.GetPC()):
            self._step_target_depth = t.GetNumFrames()
        else:
            self._step_target_depth = None
        t.StepInstruction(False)

    def advance_user_step(self, auto_bp_ids=None) -> str:
        """Called on every stop. Drives an in-flight user step to completion.

        Returns 'inactive' when no user step is running (caller handles the stop
        normally), 'more' when it re-issued a StepOut and the loop should keep
        pumping without surfacing this stop, or 'done' when the step has landed
        and its stop should be surfaced.

        `auto_bp_ids` is the set of tracer / anti-debug breakpoint ids: a stop on
        one of those inside the stepped-over callee is transparent (keep going),
        but a genuine user breakpoint there ends the step so it can be seen."""
        if not self._step_active:
            return "inactive"
        t = self._thread()
        if not t or not t.GetFrameAtIndex(0).IsValid():
            self._step_active = False
            self._step_target_depth = None
            self._pending_step_scrubs = None
            return "done"
        # A sysctl/csops call we let run during this step may have just returned;
        # scrub its now-filled buffer before doing anything else.
        self._resolve_pending_step_scrubs(t)
        # Single-instruction step (step-in, or step-over of a non-call): done.
        if self._step_target_depth is None:
            self._step_active = False
            return "done"
        # Still inside the callee. Stopping on a breakpoint here is either a
        # genuine user breakpoint (end the step, x64dbg-style) or a defense
        # breakpoint we must neutralise transparently so stepping *through* an
        # anti-debug call still gets the same protection a plain continue would.
        if t.GetStopReason() == lldb.eStopReasonBreakpoint:
            auto = set(auto_bp_ids or ())
            hit = {t.GetStopReasonDataAtIndex(i)
                   for i in range(0, t.GetStopReasonDataCount(), 2)}
            if hit - auto:
                self._step_active = False
                self._step_target_depth = None
                return "done"
            for bp_id in hit:
                self._defense_step_action(bp_id, t)
        # Complete once we're back at or above the target frame depth. This is
        # re-checked *after* _defense_step_action because a fake-the-call defense
        # (ptrace/mach/setsid) pops the callee frame via `thread return`, which
        # can itself finish the step -- StepOut-ing again would overshoot.
        if t.GetNumFrames() <= self._step_target_depth:
            self._step_active = False
            self._step_target_depth = None
            return "done"
        t.StepOut()
        return "more"

    def _resolve_pending_step_scrubs(self, thread) -> None:
        """Scrub any deferred sysctl/csops buffer whose call frame has returned
        (current depth shallower than the depth recorded when the call began)."""
        if not self._pending_step_scrubs:
            return
        cur = thread.GetNumFrames()
        remaining = []
        for depth, kind, buf, oldlenp in self._pending_step_scrubs:
            if cur < depth:
                self._scrub_flag(kind, buf, oldlenp)
            else:
                remaining.append((depth, kind, buf, oldlenp))
        self._pending_step_scrubs = remaining or None

    def _arm_step_scrub(self, thread, kind: str) -> None:
        """Record a sysctl/csops output buffer (from a direct libc symbol call) to
        scrub once the call returns, using the same entry-side argument checks as
        handle_flag_scrub_hit."""
        frame = thread.GetFrameAtIndex(0)
        oldlenp = 0
        if kind == "sysctl":
            mib = frame.FindRegister("x0").GetValueAsUnsigned()
            namelen = frame.FindRegister("x1").GetValueAsUnsigned()
            oldp = frame.FindRegister("x2").GetValueAsUnsigned()
            oldlenp = frame.FindRegister("x3").GetValueAsUnsigned()
            buf = oldp
        else:  # csops
            ops = frame.FindRegister("x1").GetValueAsUnsigned()
            useraddr = frame.FindRegister("x2").GetValueAsUnsigned()
            oldp = useraddr
            mib = namelen = 1  # unused for csops
            buf = useraddr
        self._queue_step_scrub(thread, kind, mib, namelen, oldp, oldlenp, buf,
                               ops if kind == "csops" else 0)

    def _arm_step_scrub_syscall(self, thread, kind: str) -> None:
        """Same as _arm_step_scrub but for the syscall() wrapper, whose args are
        stack-passed (mib/oldp/etc. come from the stack, not x0..)."""
        frame = thread.GetFrameAtIndex(0)
        if kind == "sysctl":
            mib, namelen, oldp, oldlenp = self._syscall_args(frame, 4)
            self._queue_step_scrub(thread, kind, mib, namelen, oldp, oldlenp, oldp, 0)
        else:  # csops
            _pid, ops, useraddr = self._syscall_args(frame, 3)
            self._queue_step_scrub(thread, kind, 1, 1, useraddr, 0, useraddr, ops)

    def _queue_step_scrub(self, thread, kind, mib, namelen, oldp, oldlenp, buf, ops) -> None:
        if kind == "sysctl":
            if not (mib and oldp and namelen >= 3):
                return
            err = lldb.SBError()
            head = self.process.ReadMemory(mib, 12, err)
            if not (err.Success() and head and len(head) == 12):
                return
            name = [int.from_bytes(head[i:i + 4], "little") for i in (0, 4, 8)]
            if not (name[0] == self._CTL_KERN and name[1] == self._KERN_PROC
                    and name[2] == self._KERN_PROC_PID):
                return
        else:  # csops
            if not (buf and ops == self._CS_OPS_STATUS):
                return
        if self._pending_step_scrubs is None:
            self._pending_step_scrubs = []
        self._pending_step_scrubs.append((thread.GetNumFrames(), kind, buf, oldlenp))

    def _defense_step_action(self, bp_id: int, thread) -> None:
        """Apply a defense whose breakpoint fired *inside a user step*, without a
        free process.Continue() (which would abandon the step and run away).
          * fake-the-call defenses (ptrace/mach/setsid) -> `thread return`, which
            pops the callee frame so the step's depth check finishes it.
          * inline ptrace-deny svc -> skip the instruction in place.
          * sysctl/csops scrub -> defer: let the step's StepOut run the call,
            then _resolve_pending_step_scrubs scrubs the filled buffer.
        Anything else is left for the enclosing StepOut to run normally."""
        if not self.process:
            return
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return
        ret = lldb.SBCommandReturnObject()
        if bp_id == self.anti_ptrace_bp_id:
            if frame.FindRegister("x0").GetValueAsUnsigned() == 31:  # PT_DENY_ATTACH
                self.ci.HandleCommand("thread return 0", ret, False)
            return
        if bp_id == self.anti_mach_bp_id:
            cnt_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
            if cnt_ptr:
                err = lldb.SBError()
                self.process.WriteMemory(cnt_ptr, b"\x00\x00\x00\x00", err)
            self.ci.HandleCommand("thread return 0", ret, False)
            return
        if self.setsid_bp_ids and bp_id in self.setsid_bp_ids and self.fork_mode == "identity":
            fake_sid = self.process.GetProcessID() or 1
            self.ci.HandleCommand("thread return {}".format(fake_sid), ret, False)
            return
        if self.direct_syscall_bp_ids and bp_id in self.direct_syscall_bp_ids:
            x16 = frame.FindRegister("x16").GetValueAsUnsigned()
            x0 = frame.FindRegister("x0").GetValueAsUnsigned()
            if x16 == 26 and x0 == 31:  # ptrace(PT_DENY_ATTACH) via inline svc
                pc = frame.GetPC()
                self.ci.HandleCommand("register write x0 0", ret, False)
                self.ci.HandleCommand("register write pc {:#x}".format(pc + 4), ret, False)
            return
        if self.anti_timing_bp_ids and bp_id in self.anti_timing_bp_ids:
            self.ci.HandleCommand("thread return {}".format(self._advance_fake_clock()),
                                  ret, False)
            return
        if self.syscall_bp_ids and bp_id in self.syscall_bp_ids:
            num = frame.FindRegister("x0").GetValueAsUnsigned()
            if (num == self._SYS_PTRACE and self.anti_ptrace_bp_id
                    and self._syscall_args(frame, 1)[0] == 31):
                self.ci.HandleCommand("thread return 0", ret, False)  # avoid the kill
            elif num == self._SYS_SYSCTL and (self._scrub_ptraced or self._scrub_parent):
                self._arm_step_scrub_syscall(thread, "sysctl")
            elif num == self._SYS_CSOPS and self.anti_csops_bp_id:
                self._arm_step_scrub_syscall(thread, "csops")
            return
        if bp_id == self.anti_sysctl_bp_id:
            self._arm_step_scrub(thread, "sysctl")
            return
        if bp_id == self.anti_csops_bp_id:
            self._arm_step_scrub(thread, "csops")
            return
        if self._flag_scrub_returns and bp_id in self._flag_scrub_returns:
            # A return one-shot armed by a prior non-step hit fired during the
            # step; scrub now and retire it.
            kind, buf, oldlenp = self._flag_scrub_returns.pop(bp_id)
            self.target.BreakpointDelete(bp_id)
            self._scrub_flag(kind, buf, oldlenp)

    def set_pc(self, addr: int) -> Tuple[bool, str]:
        """Redirect execution: point the program counter at `addr` (x64dbg's
        'Set New Origin Here'). Does not run; the next step/continue proceeds
        from there. No verification that `addr` is a valid instruction boundary
        -- that is the caller's call, same as x64dbg."""
        if not self.process or self.process.GetState() != lldb.eStateStopped:
            return False, "process is not stopped"
        frame = self.frame()
        if frame is None:
            return False, "no frame"
        if not frame.SetPC(addr):
            return False, "could not set pc to {:#x}".format(addr)
        return True, "pc set to {:#x}".format(addr)

    def in_user_step(self) -> bool:
        return self._step_active

    def cancel_user_step(self) -> None:
        self._step_active = False
        self._step_target_depth = None
        self._pending_step_scrubs = None

    def step_in_source(self) -> None:
        t = self._thread()
        if t:
            t.StepInto()

    def step_over_source(self) -> None:
        t = self._thread()
        if t:
            t.StepOver()

    def interrupt(self) -> None:
        if self.process:
            self.process.Stop()

    def _thread(self) -> Optional[lldb.SBThread]:
        if not self.process or not self.process.IsValid():
            return None
        t = self.process.GetSelectedThread()
        return t if t and t.IsValid() else None

    def frame(self) -> Optional[lldb.SBFrame]:
        t = self._thread()
        if not t:
            return None
        f = t.GetSelectedFrame()
        return f if f and f.IsValid() else None

    def pc(self) -> Optional[int]:
        f = self.frame()
        return f.GetPC() if f else None

    def sp(self) -> Optional[int]:
        f = self.frame()
        return f.GetSP() if f else None

    def write_memory(self, addr: int, data: bytes, track: bool = True) -> Tuple[bool, str]:
        if not self.process:
            return False, "no process"
        state = self.process.GetState()
        if state != lldb.eStateStopped:
            return False, "process not stopped (state={})".format(
                lldb.SBDebugger.StateAsCString(state))
        orig = self.read_memory(addr, len(data))
        err = lldb.SBError()
        n = self.process.WriteMemory(addr, data, err)
        if not err.Success():
            return False, err.GetCString() or "write failed"
        if n != len(data):
            return False, "partial write: {}/{} bytes".format(n, len(data))
        check = self.read_memory(addr, len(data))
        if check[:len(data)] != data:
            return False, "verify failed: wrote {} but read back {}".format(
                data.hex(), check[:len(data)].hex())
        if track and self.state and orig and len(orig) >= len(data):
            self._record_patch(addr, orig[:len(data)], data)
        return True, "wrote {} byte(s) at {:#x}".format(n, addr)

    def _record_patch(self, addr: int, orig: bytes, new: bytes) -> None:
        if not self.state:
            return
        for i, p in enumerate(self.state.patches):
            if p.addr == addr and len(p.new) == len(new):
                self.state.patches[i] = Patch(addr=addr, orig=p.orig, new=new)
                return
        self.state.patches.append(Patch(addr=addr, orig=orig, new=new))

    def revert_patch(self, index: int) -> Tuple[bool, str]:
        if not self.state or not (0 <= index < len(self.state.patches)):
            return False, "no such patch"
        p = self.state.patches[index]
        ok, msg = self.write_memory(p.addr, p.orig, track=False)
        if ok:
            del self.state.patches[index]
            return True, "reverted {} byte(s) at {:#x}".format(len(p.orig), p.addr)
        return False, "revert failed: {}".format(msg)

    def write_register(self, name: str, value: int) -> Tuple[bool, str]:
        f = self.frame()
        if f is None:
            return False, "no frame"
        reg = f.FindRegister(name)
        if not reg.IsValid():
            return False, "unknown register {}".format(name)
        err = lldb.SBError()
        ok = reg.SetValueFromCString("{:#x}".format(value), err)
        if not ok or not err.Success():
            return False, err.GetCString() or "register write refused"
        check = f.FindRegister(name).GetValueAsUnsigned()
        if check != value:
            return False, "verify failed: wrote {:#x} but read back {:#x}".format(value, check)
        return True, "wrote {} = {:#x}".format(name, value)

    def read_memory(self, addr: int, size: int) -> bytes:
        if not self.process:
            return b""
        err = lldb.SBError()
        while size >= 1:
            data = self.process.ReadMemory(addr, size, err)
            if err.Success():
                return data
            if size == 1:
                return b""
            size //= 2
        return b""

    def read_around(self, addr: int, before: int, total: int) -> Tuple[int, bytes]:
        """Read `total` bytes around `addr`, with about `before` bytes ahead of
        it, stitching across adjacent readable regions."""
        if not self.process or not self.process.IsValid():
            return addr, b""
        info = lldb.SBMemoryRegionInfo()
        err = self.process.GetMemoryRegionInfo(addr, info)
        if not err.Success() or not info.IsReadable():
            return addr, b""
        aligned = addr & ~0xF
        desired_base = aligned - before
        base = max(info.GetRegionBase(), desired_base) & ~0xF
        return base, self._read_stitched(base, total)

    def _read_stitched(self, base: int, total: int) -> bytes:
        out = bytearray()
        addr = base
        while len(out) < total:
            want = total - len(out)
            info = lldb.SBMemoryRegionInfo()
            err = self.process.GetMemoryRegionInfo(addr, info)
            if not err.Success():
                break
            if not info.IsReadable():
                if len(out) == 0:
                    addr = info.GetRegionEnd()
                    continue
                break
            region_end = info.GetRegionEnd()
            chunk_size = min(want, region_end - addr)
            if chunk_size <= 0:
                break
            data = self.read_memory(addr, chunk_size)
            if not data:
                break
            out.extend(data)
            addr += len(data)
            if len(data) < chunk_size:
                break
        return bytes(out)

    hw_breakpoints: bool = False
    anti_ptrace_bp_id: int = 0
    anti_csops_bp_id: int = 0
    anti_timing_bp_ids: Optional[List[int]] = None
    # One shared sysctl breakpoint drives two independent scrubs, tracked by
    # these owner flags: P_TRACED (anti_sysctl) and the parent-name scrub
    # (anti_parent). The breakpoint is armed while either owner is on.
    anti_sysctl_bp_id: int = 0
    _scrub_ptraced: bool = False
    _scrub_parent: bool = False
    # not a breakpoint: a flag. When on, an EXC_BREAKPOINT (brk the target set
    # on itself, not one of ours) is forwarded to the target's own SIGTRAP
    # handler instead of stopping, defeating self-trap debugger checks.
    anti_sigtrap_on: bool = False
    # libc syscall()/__syscall() hook, auto-armed while any of the ptrace/flag
    # defenses is on, so the same checks issued through the syscall() wrapper
    # (bypassing the libc symbol and the __text svc scan) are still neutralised.
    syscall_bp_ids: Optional[List[int]] = None
    # monotonic fake clock fed to the hooked time sources so a self-timing check
    # can't see the milliseconds our stop/continue hooks actually cost. (A
    # "real-clock minus paused-time" version was tried and abandoned: LLDB's
    # async event delivery leaves ~ms of stopped time unaccounted, so it hid
    # latency worse than this does. See git history / the timing comment below.)
    _fake_clock: int = 0
    _fake_clock_step: int = 100
    _anti_timing_logged: bool = False
    # return-address one-shots waiting to scrub a flag out of a syscall's output
    # buffer once the call fills it: {ret_bp_id: (kind, buffer_addr)}.
    _flag_scrub_returns: Optional[Dict[int, tuple]] = None
    # scrubs deferred while a user step runs: [(frame_depth_at_call, kind, buf)].
    # We can't Continue mid-step, so instead of a return one-shot we let the
    # step's own StepOut run the call, then scrub once its frame has returned.
    _pending_step_scrubs: Optional[List[tuple]] = None
    anti_mach_bp_id: int = 0
    direct_syscall_bp_ids: Optional[List[int]] = None
    fork_bp_ids: Optional[List[int]] = None
    fork_mode: str = "off"
    exec_bp_ids: Optional[Dict[int, str]] = None
    exec_interactive: bool = False
    fork_interactive: bool = False
    _fork_shield_hw_bp: int = 0
    _fork_shield_saved: Optional[List[int]] = None

    def toggle_breakpoint_at(self, addr: int) -> Tuple[str, int]:
        assert self.target is not None
        for i in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(i)
            for j in range(bp.GetNumLocations()):
                loc = bp.GetLocationAtIndex(j)
                if loc.GetLoadAddress() == addr:
                    bp_id = bp.GetID()
                    self.target.BreakpointDelete(bp_id)
                    return ("removed", bp_id)
        if self.hw_breakpoints:
            ret = lldb.SBCommandReturnObject()
            self.ci.HandleCommand("breakpoint set -H -a {:#x}".format(addr), ret, False)
            for i in range(self.target.GetNumBreakpoints()):
                bp = self.target.GetBreakpointAtIndex(i)
                for j in range(bp.GetNumLocations()):
                    if bp.GetLocationAtIndex(j).GetLoadAddress() == addr:
                        return ("added (HW)", bp.GetID())
            return ("added (HW)", 0)
        bp = self.target.BreakpointCreateByAddress(addr)
        return ("added", bp.GetID())

    def enable_anti_ptrace(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.anti_ptrace_bp_id:
            return True, "already enabled"
        bp = self.target.BreakpointCreateByName("ptrace")
        if not bp.IsValid():
            return False, "ptrace symbol not found"
        self.anti_ptrace_bp_id = bp.GetID()
        self._sync_syscall_bp()
        return True, "PT_DENY_ATTACH bypass armed (bp #{})".format(bp.GetID())

    def disable_anti_ptrace(self) -> Tuple[bool, str]:
        if not self.target or not self.anti_ptrace_bp_id:
            return True, "already disabled"
        self.target.BreakpointDelete(self.anti_ptrace_bp_id)
        self.anti_ptrace_bp_id = 0
        self._sync_syscall_bp()
        return True, "PT_DENY_ATTACH bypass disabled"

    # -- parent-identity cloak ------------------------------------------------
    # A sample that reads its parent's name -- via getppid() then
    # sysctl(KERN_PROC_PID, ppid), or by pulling e_ppid straight out of its own
    # kinfo_proc -- sees "debugserver"/"lldb" and knows it's debugged. Both paths
    # end in a sysctl(KERN_PROC_PID) whose p_comm we can rewrite, so instead of
    # faking getppid (which would lie to every legitimate caller) we scrub the
    # debugger's *name* out of the sysctl result. getppid is left untouched.

    def enable_anti_parent(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        self._scrub_parent = True
        ok, why = self._ensure_sysctl_bp()
        if not ok:
            self._scrub_parent = False
            return False, why
        self._sync_syscall_bp()
        return True, "parent cloak armed: debugger names scrubbed from sysctl(KERN_PROC) results"

    def disable_anti_parent(self) -> Tuple[bool, str]:
        self._scrub_parent = False
        self._maybe_release_sysctl_bp()
        self._sync_syscall_bp()
        return True, "parent cloak disabled"

    # -- SIGTRAP self-trap forwarder ------------------------------------------
    # A sample installs its own SIGTRAP handler then executes brk #0. Undebugged,
    # the kernel turns that into SIGTRAP and the handler runs; under a debugger
    # the EXC_BREAKPOINT is caught and the handler never fires, so the sample
    # knows it's watched (and we'd re-trap on the same brk forever). When armed,
    # we do what the kernel would: run the target's own SIGTRAP handler. Not a
    # breakpoint -- just a flag consulted on every exception stop.

    def enable_anti_sigtrap(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        self.anti_sigtrap_on = True
        return True, "self-trap forwarder armed: brk #0 routed to the target's SIGTRAP handler"

    def disable_anti_sigtrap(self) -> Tuple[bool, str]:
        self.anti_sigtrap_on = False
        return True, "self-trap forwarder disabled"

    def _read_signal_handler(self, signo: int) -> Optional[int]:
        """The target's registered handler for `signo`, read via in-process
        sigaction. None if unreadable; 0 == SIG_DFL, 1 == SIG_IGN.

        Run through the command interpreter (which falls back to C++ for this C
        frame, where SBFrame.EvaluateExpression does not) with breakpoints off so
        the injected malloc/sigaction call can't re-enter a defense hook."""
        expr = ("expression -l c++ --ignore-breakpoints true -- "
                "void *b=(void*)malloc(16);"
                "((int(*)(int,void*,void*))sigaction)({},(void*)0,b);"
                "void *h=*(void**)b;((void(*)(void*))free)(b);h").format(signo)
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand(expr, ret, False)
        if not ret.Succeeded():
            return None
        m = re.search(r"=\s*(0x[0-9a-fA-F]+)", ret.GetOutput() or "")
        if not m:
            return None
        return int(m.group(1), 16)

    def handle_self_trap(self, thread) -> Optional[str]:
        """If the target hit a brk it planted on itself (EXC_BREAKPOINT, not one
        of our breakpoints) and anti_sigtrap is on, run its own SIGTRAP handler
        the way the kernel would when undebugged. Returns a message if handled,
        None otherwise (so the caller surfaces the stop normally)."""
        if not self.anti_sigtrap_on or not self.process:
            return None
        if not thread or not thread.IsValid():
            return None
        if thread.GetStopReason() != lldb.eStopReasonException:
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        pc = frame.GetPC()
        # Only act on a real brk instruction -- leave other exceptions alone.
        insns = self.target.ReadInstructions(lldb.SBAddress(pc, self.target), 1)
        if insns.GetSize() < 1:
            return None
        mn = (insns.GetInstructionAtIndex(0).GetMnemonic(self.target) or "").lower()
        if mn != "brk":
            return None
        SIGTRAP = 5
        handler = self._read_signal_handler(SIGTRAP)
        ret = lldb.SBCommandReturnObject()
        if handler is None or handler in (0, 1):
            # SIG_DFL / SIG_IGN / unreadable: step past the brk so we don't trap
            # on it forever. Keeps the session usable even if we can't forward.
            self.ci.HandleCommand("register write pc {:#x}".format(pc + 4), ret, False)
            self.process.Continue()
            return "self-trap: no SIGTRAP handler, skipped brk at {:#x}".format(pc)
        # Deliver: x0 = signo, lr = after the brk (so a handler that returns
        # normally resumes past it), pc = the handler.
        self.ci.HandleCommand("register write x0 {}".format(SIGTRAP), ret, False)
        self.ci.HandleCommand("register write lr {:#x}".format(pc + 4), ret, False)
        self.ci.HandleCommand("register write pc {:#x}".format(handler), ret, False)
        self.process.Continue()
        return "self-trap: ran target SIGTRAP handler {:#x} for brk at {:#x}".format(handler, pc)

    def enable_anti_mach_ports(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.anti_mach_bp_id:
            return True, "already enabled"
        bp = self.target.BreakpointCreateByName("task_get_exception_ports")
        if not bp.IsValid():
            return False, "task_get_exception_ports symbol not found"
        self.anti_mach_bp_id = bp.GetID()
        return True, "Mach exception port cloak armed (bp #{})".format(bp.GetID())

    def disable_anti_mach_ports(self) -> Tuple[bool, str]:
        if not self.target or not self.anti_mach_bp_id:
            return True, "already disabled"
        self.target.BreakpointDelete(self.anti_mach_bp_id)
        self.anti_mach_bp_id = 0
        return True, "Mach exception port cloak disabled"

    def handle_anti_mach_hit(self, bp_id: int) -> Optional[str]:
        if bp_id != self.anti_mach_bp_id or not self.process:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        masks_cnt_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
        if masks_cnt_ptr:
            err = lldb.SBError()
            self.process.WriteMemory(masks_cnt_ptr, b"\x00\x00\x00\x00", err)
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("thread return 0", ret, False)
        self.process.Continue()
        return "cloaked task_get_exception_ports (returned 0 masks)"

    # -- sysctl(P_TRACED) / csops(CS_DEBUGGED) flag scrubbing -----------------
    # Both checks read a real kernel result we must let through, then test one
    # bit. We can't fake the whole call like ptrace; instead we tag the relevant
    # call at entry, let it run, and clear the offending bit in its output buffer
    # on return so the caller sees a clean flag.

    _P_TRACED = 0x00000800       # extern_proc.p_flag, offset 32 in kinfo_proc
    _KINFO_PROC_PFLAG_OFF = 32
    _CS_DEBUGGED = 0x10000000
    _CS_OPS_STATUS = 0
    _CTL_KERN = 1
    _KERN_PROC = 14
    _KERN_PROC_PID = 1

    def _clear_flag_scrub_returns(self) -> None:
        """Drop any pending return-address one-shots. Called on (re)launch so a
        one-shot armed but never reached (process died mid-call) can't fire in a
        fresh run -- with ASLR off its address recurs -- and scrub a stale
        buffer. The entry breakpoints stay; only the transient returns go."""
        if self._flag_scrub_returns and self.target and self.target.IsValid():
            for bp_id in list(self._flag_scrub_returns):
                self.target.BreakpointDelete(bp_id)
        self._flag_scrub_returns = None

    def _ensure_sysctl_bp(self) -> Tuple[bool, str]:
        """Arm the shared sysctl breakpoint if not already armed."""
        if self.anti_sysctl_bp_id:
            return True, "already armed"
        bp = self.target.BreakpointCreateByName("sysctl")
        if not bp.IsValid():
            return False, "sysctl symbol not found"
        self.anti_sysctl_bp_id = bp.GetID()
        return True, "armed"

    def _maybe_release_sysctl_bp(self) -> None:
        """Delete the shared sysctl breakpoint once no owner needs it."""
        if (not self._scrub_ptraced and not self._scrub_parent
                and self.anti_sysctl_bp_id and self.target):
            self.target.BreakpointDelete(self.anti_sysctl_bp_id)
            self.anti_sysctl_bp_id = 0

    def enable_anti_sysctl(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        self._scrub_ptraced = True
        ok, why = self._ensure_sysctl_bp()
        if not ok:
            self._scrub_ptraced = False
            return False, why
        self._sync_syscall_bp()
        return True, "sysctl(P_TRACED) scrub armed"

    def disable_anti_sysctl(self) -> Tuple[bool, str]:
        self._scrub_ptraced = False
        self._maybe_release_sysctl_bp()
        self._sync_syscall_bp()
        return True, "sysctl(P_TRACED) scrub disabled"

    def enable_anti_csops(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.anti_csops_bp_id:
            return True, "already enabled"
        bp = self.target.BreakpointCreateByName("csops")
        if not bp.IsValid():
            return False, "csops symbol not found"
        self.anti_csops_bp_id = bp.GetID()
        self._sync_syscall_bp()
        return True, "csops(CS_DEBUGGED) scrub armed (bp #{})".format(bp.GetID())

    def disable_anti_csops(self) -> Tuple[bool, str]:
        if not self.target or not self.anti_csops_bp_id:
            return True, "already disabled"
        self.target.BreakpointDelete(self.anti_csops_bp_id)
        self.anti_csops_bp_id = 0
        self._sync_syscall_bp()
        return True, "csops(CS_DEBUGGED) scrub disabled"

    _DEBUGGER_NAMES = (b"debugserver", b"lldb", b"gdb")
    _KINFO_PROC_SIZE = 648   # sizeof(struct kinfo_proc) on macOS arm64

    def _arm_return_scrub(self, thread, kind: str, buf: int, oldlenp: int = 0) -> None:
        ret_addr = thread.GetFrameAtIndex(0).FindRegister("lr").GetValueAsUnsigned()
        if not ret_addr:
            return
        bp = self.target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetThreadID(thread.GetThreadID())
        if self._flag_scrub_returns is None:
            self._flag_scrub_returns = {}
        self._flag_scrub_returns[bp.GetID()] = (kind, buf, oldlenp)

    def _scrub_debugger_name(self, buf: int, oldlenp: int) -> Optional[str]:
        """Rewrite a debugger process name (p_comm) in a returned kinfo_proc to
        'launchd'. Scans the buffer rather than trusting a hardcoded p_comm
        offset, and only touches a name that actually matches a debugger."""
        err = lldb.SBError()
        length = self._KINFO_PROC_SIZE
        if oldlenp:
            n = self._read_uint(oldlenp, 8)
            if n:
                length = min(int(n), 4096)
        data = self.process.ReadMemory(buf, length, err)
        if not err.Success() or not data:
            return None
        for kw in self._DEBUGGER_NAMES:
            idx = data.find(kw)
            if idx >= 0 and idx + 8 <= len(data):
                self.process.WriteMemory(buf + idx, b"launchd\x00", err)
                return "scrubbed debugger name '{}' from sysctl(KERN_PROC) result".format(kw.decode())
        return ""

    def _read_uint(self, addr: int, size: int) -> Optional[int]:
        err = lldb.SBError()
        data = self.process.ReadMemory(addr, size, err)
        if not err.Success() or not data:
            return None
        return int.from_bytes(data, "little")

    def _scrub_flag(self, kind: str, buf: int, oldlenp: int = 0) -> Optional[str]:
        err = lldb.SBError()
        if kind == "sysctl":
            msgs = []
            if self._scrub_ptraced:
                addr = buf + self._KINFO_PROC_PFLAG_OFF
                data = self.process.ReadMemory(addr, 4, err)
                if err.Success() and data:
                    flag = int.from_bytes(data, "little")
                    if flag & self._P_TRACED:
                        self.process.WriteMemory(
                            addr, (flag & ~self._P_TRACED).to_bytes(4, "little"), err)
                        msgs.append("scrubbed P_TRACED from sysctl(KERN_PROC) result")
            if self._scrub_parent:
                m = self._scrub_debugger_name(buf, oldlenp)
                if m:
                    msgs.append(m)
            return "; ".join(msgs)
        if kind == "csops":
            data = self.process.ReadMemory(buf, 4, err)
            if not err.Success() or not data:
                return None
            flag = int.from_bytes(data, "little")
            if not (flag & self._CS_DEBUGGED):
                return ""
            self.process.WriteMemory(buf, (flag & ~self._CS_DEBUGGED).to_bytes(4, "little"), err)
            return "scrubbed CS_DEBUGGED from csops(CS_OPS_STATUS) result"
        return None

    def handle_flag_scrub_hit(self, bp_id: int) -> Optional[str]:
        """Entry side tags a P_TRACED/CS_DEBUGGED query and arms a return-address
        one-shot; return side clears the bit in the now-filled buffer. Returns a
        message to log, "" for handled-but-silent, or None if not ours."""
        if not self.process:
            return None
        # Return side: a tagged call has come back.
        if self._flag_scrub_returns and bp_id in self._flag_scrub_returns:
            kind, buf, oldlenp = self._flag_scrub_returns.pop(bp_id)
            self.target.BreakpointDelete(bp_id)
            msg = self._scrub_flag(kind, buf, oldlenp)
            self.process.Continue()
            return msg if msg else ""
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        if bp_id == self.anti_sysctl_bp_id:
            mib = frame.FindRegister("x0").GetValueAsUnsigned()
            namelen = frame.FindRegister("x1").GetValueAsUnsigned()
            oldp = frame.FindRegister("x2").GetValueAsUnsigned()
            oldlenp = frame.FindRegister("x3").GetValueAsUnsigned()
            if mib and oldp and namelen >= 3:
                err = lldb.SBError()
                head = self.process.ReadMemory(mib, 12, err)
                if err.Success() and head and len(head) == 12:
                    name = [int.from_bytes(head[i:i + 4], "little") for i in (0, 4, 8)]
                    # {CTL_KERN, KERN_PROC, KERN_PROC_PID, ...} is the per-process
                    # query that carries both P_TRACED and the parent's p_comm.
                    # Both scrubs only act when their marker is present, so arming
                    # on every such query (own pid or parent pid) is harmless.
                    if (name[0] == self._CTL_KERN and name[1] == self._KERN_PROC
                            and name[2] == self._KERN_PROC_PID):
                        self._arm_return_scrub(thread, "sysctl", oldp, oldlenp)
            self.process.Continue()
            return ""
        if bp_id == self.anti_csops_bp_id:
            ops = frame.FindRegister("x1").GetValueAsUnsigned()
            useraddr = frame.FindRegister("x2").GetValueAsUnsigned()
            if useraddr and ops == self._CS_OPS_STATUS:
                self._arm_return_scrub(thread, "csops", useraddr)
            self.process.Continue()
            return ""
        return None

    # -- syscall() wrapper multiplexer ----------------------------------------
    # ptrace / sysctl / csops issued via the libc syscall() wrapper skip both the
    # symbol hooks above and the __text svc scan (the svc lives in libsystem).
    # We hook syscall()/__syscall() itself; the BSD number is in x0 and the real
    # args are shifted up one register (x0=number, x1=arg0, ...). We dispatch to
    # the same neutralisations, gated on which defenses are actually on.
    _SYS_PTRACE = 26
    _SYS_CSOPS = 169
    _SYS_SYSCTL = 202

    def _syscall_wanted(self) -> bool:
        return bool(self.anti_ptrace_bp_id or self._scrub_ptraced
                    or self._scrub_parent or self.anti_csops_bp_id)

    def _sync_syscall_bp(self) -> None:
        """Arm the syscall()/__syscall() hook while any ptrace/flag defense is on,
        release it once none are. Called from each of those enables/disables."""
        if not self.target or not self.target.IsValid():
            return
        want = self._syscall_wanted()
        if want and not self.syscall_bp_ids:
            ids = []
            for sym in ("syscall", "__syscall"):
                bp = self.target.BreakpointCreateByName(sym, "libsystem_kernel.dylib")
                if not bp.IsValid() or bp.GetNumLocations() == 0:
                    bp = self.target.BreakpointCreateByName(sym)
                if bp.IsValid() and bp.GetNumLocations() > 0:
                    ids.append(bp.GetID())
            self.syscall_bp_ids = ids or None
        elif not want and self.syscall_bp_ids:
            for bp_id in self.syscall_bp_ids:
                self.target.BreakpointDelete(bp_id)
            self.syscall_bp_ids = None

    def _syscall_args(self, frame, n: int) -> List[int]:
        """The first n arguments of a libc syscall() call. syscall(int, ...) is
        variadic, and on arm64 Darwin variadic args are passed on the stack, so
        arg i is *(uint64*)(sp + 8*i) -- not in x1.., which hold stale values."""
        sp = frame.FindRegister("sp").GetValueAsUnsigned()
        return [self._read_uint(sp + 8 * i, 8) or 0 for i in range(n)]

    def handle_syscall_hit(self, bp_id: int) -> Optional[str]:
        """A syscall()/__syscall() call: neutralise ptrace-deny / sysctl-P_TRACED
        / csops-CS_DEBUGGED issued this way. Always resumes (returns "" for the
        ones we let pass), so we never stop on an unrelated syscall()."""
        if not self.syscall_bp_ids or bp_id not in self.syscall_bp_ids or not self.process:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        num = frame.FindRegister("x0").GetValueAsUnsigned()
        if num == self._SYS_PTRACE and self.anti_ptrace_bp_id:
            if self._syscall_args(frame, 1)[0] == 31:  # PT_DENY_ATTACH
                ret = lldb.SBCommandReturnObject()
                self.ci.HandleCommand("thread return 0", ret, False)
                self.process.Continue()
                return "blocked ptrace(PT_DENY_ATTACH) via syscall()"
        elif num == self._SYS_SYSCTL and (self._scrub_ptraced or self._scrub_parent):
            mib, namelen, oldp, oldlenp = self._syscall_args(frame, 4)
            if mib and oldp and namelen >= 3:
                err = lldb.SBError()
                head = self.process.ReadMemory(mib, 12, err)
                if err.Success() and head and len(head) == 12:
                    name = [int.from_bytes(head[i:i + 4], "little") for i in (0, 4, 8)]
                    if (name[0] == self._CTL_KERN and name[1] == self._KERN_PROC
                            and name[2] == self._KERN_PROC_PID):
                        self._arm_return_scrub(thread, "sysctl", oldp, oldlenp)
        elif num == self._SYS_CSOPS and self.anti_csops_bp_id:
            _pid, ops, useraddr = self._syscall_args(frame, 3)
            if useraddr and ops == self._CS_OPS_STATUS:
                self._arm_return_scrub(thread, "csops", useraddr)
        self.process.Continue()
        return ""

    # -- timing cloak ---------------------------------------------------------
    # A self-timing check reads a monotonic clock before and after a sensitive
    # call; a debugger that hooks that call adds milliseconds the check catches.
    # We feed the common monotonic clock sources a fake clock that advances a
    # small fixed step per call, so any measured delta stays tiny no matter how
    # long we were really stopped. Each returns a uint64 in x0, so one thread
    # return covers them all. Scoped to libsystem_kernel.dylib. Limits: a direct
    # `mrs x0, cntvct_el0` read can't be hooked, wall-clock `gettimeofday`
    # returns a struct we don't fake, and the constant step is a uniform-clock
    # fingerprint a sophisticated check could notice -- this hides latency from
    # ordinary threshold checks, it is not a perfect clock emulation. (A
    # real-clock-minus-paused-time version was tried and dropped: LLDB's async
    # event delivery leaves ~ms of stopped time unaccounted, so it hid latency
    # worse than this constant-step clock does.)
    _TIMING_SYMBOLS = ("mach_absolute_time", "mach_continuous_time",
                       "clock_gettime_nsec_np")

    def enable_anti_timing(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.anti_timing_bp_ids:
            return True, "already enabled"
        ids = []
        for sym in self._TIMING_SYMBOLS:
            bp = self.target.BreakpointCreateByName(sym, "libsystem_kernel.dylib")
            if not bp.IsValid() or bp.GetNumLocations() == 0:
                bp = self.target.BreakpointCreateByName(sym)
            if bp.IsValid() and bp.GetNumLocations() > 0:
                ids.append(bp.GetID())
        if not ids:
            return False, "no monotonic clock symbols found"
        self.anti_timing_bp_ids = ids
        self._anti_timing_logged = False
        return True, "timing cloak armed: fake clock for {} source(s)".format(len(ids))

    def disable_anti_timing(self) -> Tuple[bool, str]:
        if not self.target or not self.anti_timing_bp_ids:
            return True, "already disabled"
        for bp_id in self.anti_timing_bp_ids:
            self.target.BreakpointDelete(bp_id)
        self.anti_timing_bp_ids = None
        return True, "timing cloak disabled"

    def _advance_fake_clock(self) -> int:
        self._fake_clock += self._fake_clock_step
        return self._fake_clock

    def handle_anti_timing_hit(self, bp_id: int) -> Optional[str]:
        """A monotonic clock source was called: return the next fake-clock value
        instead of the real one, so timing checks can't see our stop/continue
        latency. All the hooked sources return a uint64 in x0."""
        if not self.anti_timing_bp_ids or bp_id not in self.anti_timing_bp_ids:
            return None
        if not self.process:
            return None
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("thread return {}".format(self._advance_fake_clock()),
                              ret, False)
        self.process.Continue()
        if not self._anti_timing_logged:
            self._anti_timing_logged = True
            return "timing cloak: feeding monotonic clock sources a fake clock"
        return ""

    def enable_direct_syscall_scan(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.direct_syscall_bp_ids is None:
            self.direct_syscall_bp_ids = []
        if self.direct_syscall_bp_ids:
            return True, "already armed"
        exec_name = self.target.GetExecutable().GetFilename() or ""
        exec_mod = None
        for i in range(self.target.GetNumModules()):
            m = self.target.GetModuleAtIndex(i)
            if m.GetFileSpec().GetFilename() == exec_name:
                exec_mod = m
                break
        if exec_mod is None:
            return False, "target executable module not found"
        text_bytes = b""
        text_load = 0
        for i in range(exec_mod.GetNumSections()):
            sec = exec_mod.GetSectionAtIndex(i)
            if sec.GetName() != "__TEXT":
                continue
            for j in range(sec.GetNumSubSections()):
                sub = sec.GetSubSectionAtIndex(j)
                if sub.GetName() == "__text":
                    text_load = sub.GetLoadAddress(self.target)
                    err = lldb.SBError()
                    raw = sub.GetSectionData().ReadRawData(err, 0, sub.GetByteSize())
                    if err.Success() and raw:
                        text_bytes = bytes(raw)
                    break
            break
        if not text_bytes:
            return False, "could not read __text"
        if text_load == 0 or text_load == lldb.LLDB_INVALID_ADDRESS:
            return False, "target __text not mapped yet — launch the process first"
        svc_pattern = b"\x01\x10\x00\xd4"
        found = []
        for off in range(0, len(text_bytes) - 3, 4):
            if text_bytes[off:off + 4] == svc_pattern:
                svc_addr = text_load + off
                bp = self.target.BreakpointCreateByAddress(svc_addr)
                if bp.IsValid():
                    self.direct_syscall_bp_ids.append(bp.GetID())
                    found.append(svc_addr)
        return True, "direct-syscall scan: {} svc #0x80 site(s) armed in target __text".format(len(found))

    def disable_direct_syscall_scan(self) -> Tuple[bool, str]:
        if not self.target or not self.direct_syscall_bp_ids:
            return True, "already disabled"
        for bp_id in self.direct_syscall_bp_ids:
            self.target.BreakpointDelete(bp_id)
        self.direct_syscall_bp_ids = []
        return True, "direct-syscall scan disabled"

    def handle_direct_syscall_hit(self, bp_id: int) -> Optional[str]:
        if not self.direct_syscall_bp_ids or bp_id not in self.direct_syscall_bp_ids:
            return None
        if not self.process:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        x16 = frame.FindRegister("x16").GetValueAsUnsigned()
        x0 = frame.FindRegister("x0").GetValueAsUnsigned()
        pc = frame.GetPC()
        ret = lldb.SBCommandReturnObject()
        if x16 == 26 and x0 == 31:
            self.ci.HandleCommand("register write x0 0", ret, False)
            self.ci.HandleCommand("register write pc {:#x}".format(pc + 4), ret, False)
            self.process.Continue()
            return "blocked direct ptrace(PT_DENY_ATTACH) svc at {:#x}".format(pc)
        self.process.Continue()
        return "direct svc #{} passed (op={:#x})".format(x16, x0)

    _FORK_SYMBOLS = ("fork", "vfork")
    _SETSID_SYMBOLS = ("setsid",)
    setsid_bp_ids: Optional[List[int]] = None
    _EXEC_SYMBOLS = ("system", "popen", "execve", "execvp",
                     "posix_spawn", "posix_spawnp")

    def enable_fork_identity(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.fork_bp_ids is None:
            self.fork_bp_ids = []
        if self.setsid_bp_ids is None:
            self.setsid_bp_ids = []
        if self.fork_bp_ids:
            self.fork_mode = "identity"
            return True, "fork identity already armed"
        for name in self._FORK_SYMBOLS:
            bp = self.target.BreakpointCreateByName(name)
            if bp.IsValid():
                self.fork_bp_ids.append(bp.GetID())
        for name in self._SETSID_SYMBOLS:
            bp = self.target.BreakpointCreateByName(name)
            if bp.IsValid():
                self.setsid_bp_ids.append(bp.GetID())
        self.fork_mode = "identity"
        return True, "fork identity armed (fork+setsid faked; use direct-syscall scan for inline svc)"

    def disable_fork_identity(self) -> Tuple[bool, str]:
        if not self.target:
            self.fork_mode = "off"
            return True, "fork identity already off"
        for bp_id in (self.fork_bp_ids or []):
            self.target.BreakpointDelete(bp_id)
        for bp_id in (self.setsid_bp_ids or []):
            self.target.BreakpointDelete(bp_id)
        self.fork_bp_ids = []
        self.setsid_bp_ids = []
        self.fork_mode = "off"
        self.fork_interactive = False
        return True, "fork identity disabled"

    def handle_setsid_hit(self, bp_id: int) -> Optional[str]:
        if not self.setsid_bp_ids or bp_id not in self.setsid_bp_ids or not self.process:
            return None
        if self.fork_mode != "identity":
            return None
        fake_sid = self.process.GetProcessID() or 1
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("thread return {}".format(fake_sid), ret, False)
        self.process.Continue()
        return "identity: setsid() faked, returned {} (real call would fail)".format(fake_sid)

    def peek_fork_hit(self, bp_id: int) -> Optional[str]:
        """If stopped on a fork/vfork breakpoint, return its name without acting,
        so the caller can prompt for parent-vs-child. None otherwise."""
        if not self.fork_bp_ids or bp_id not in self.fork_bp_ids or not self.process:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        return frame.GetFunctionName() or "fork"

    def resolve_fork(self, decision: str = "parent") -> None:
        """parent: let the real fork happen (child runs untraced, we stay on the
        parent). child: fake the return as 0 so the current process walks the
        child code path in-process, where it stays traceable."""
        if not self.process:
            return
        if decision == "child":
            ret = lldb.SBCommandReturnObject()
            self.ci.HandleCommand("thread return 0", ret, False)
            self.process.Continue()
            return
        # A real fork copies our breakpoints into the child, which then dies on
        # the first inherited trap before it can exec. Lift every breakpoint
        # across the fork so the child's memory is clean, and catch the parent's
        # return with a hardware breakpoint (not inherited by the child). The
        # saved breakpoints go back on the next stop, in finish_fork_shield.
        if not self._arm_fork_shield():
            self.process.Continue()
            return
        self.process.Continue()

    def _arm_fork_shield(self) -> bool:
        if not self.target:
            return False
        thread = self.process.GetSelectedThread()
        frame = thread.GetFrameAtIndex(0) if thread and thread.IsValid() else None
        ret_addr = frame.FindRegister("lr").GetValueAsUnsigned() if frame else 0
        if not ret_addr:
            return False
        n_before = self.target.GetNumBreakpoints()
        ro = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("breakpoint set -H -a {:#x}".format(ret_addr), ro, False)
        if self.target.GetNumBreakpoints() <= n_before:
            return False
        hw_bp = self.target.GetBreakpointAtIndex(n_before)
        # If no debug register was free the breakpoint resolves to nothing; abort
        # rather than disable everything and lose the return (and all tracing).
        if hw_bp.GetNumLocations() == 0:
            self.target.BreakpointDelete(hw_bp.GetID())
            return False
        saved = []
        for i in range(n_before):
            bp = self.target.GetBreakpointAtIndex(i)
            if bp.IsEnabled():
                bp.SetEnabled(False)
                saved.append(bp.GetID())
        self._fork_shield_hw_bp = hw_bp.GetID()
        self._fork_shield_saved = saved
        return True

    def in_fork_shield(self) -> bool:
        return self._fork_shield_hw_bp != 0

    def finish_fork_shield(self) -> None:
        """Back in the parent after the real fork: drop the temporary hardware
        breakpoint and re-arm everything we lifted."""
        if self.target:
            if self._fork_shield_hw_bp:
                self.target.BreakpointDelete(self._fork_shield_hw_bp)
            for bid in (self._fork_shield_saved or []):
                bp = self.target.FindBreakpointByID(bid)
                if bp.IsValid():
                    bp.SetEnabled(True)
        self._fork_shield_hw_bp = 0
        self._fork_shield_saved = None

    def handle_fork_hit(self, bp_id: int) -> Optional[str]:
        if not self.fork_bp_ids or bp_id not in self.fork_bp_ids or not self.process:
            return None
        if self.fork_mode != "identity" or self.fork_interactive:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        fname = frame.GetFunctionName() or "fork"
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("thread return 0", ret, False)
        self.process.Continue()
        return "identity: {}() returned 0, parent takes child code path".format(fname)

    def enable_exec_sandbox(self) -> Tuple[bool, str]:
        if not self.target or not self.target.IsValid():
            return False, "no target"
        if self.exec_bp_ids is None:
            self.exec_bp_ids = {}
        if self.exec_bp_ids:
            return True, "already enabled"
        for name in self._EXEC_SYMBOLS:
            bp = self.target.BreakpointCreateByName(name)
            if bp.IsValid():
                self.exec_bp_ids[bp.GetID()] = name
        return True, "exec sandbox armed ({} symbol(s))".format(len(self.exec_bp_ids))

    def disable_exec_sandbox(self) -> Tuple[bool, str]:
        if not self.target or not self.exec_bp_ids:
            return True, "already disabled"
        for bp_id in self.exec_bp_ids:
            self.target.BreakpointDelete(bp_id)
        self.exec_bp_ids = {}
        return True, "exec sandbox disabled"

    def _read_full_cstr(self, addr: int, cap: int = 1 << 20) -> str:
        """Whole C string at addr, up to cap bytes. Unlike the tracer's 256-byte
        preview this keeps everything, so a dropper's inline script survives."""
        if not addr or not self.process:
            return ""
        err = lldb.SBError()
        s = self.process.ReadCStringFromMemory(addr, cap, err)
        return s if (err.Success() and s) else ""

    def _read_argv(self, addr: int, max_args: int = 8192) -> List[str]:
        """Walk a NULL-terminated char** and read each argument in full. This is
        where osascript -e <script> or sh -c <script> hides the real payload."""
        if not addr or not self.process:
            return []
        out: List[str] = []
        err = lldb.SBError()
        for i in range(max_args):
            slot = self.process.ReadPointerFromMemory(addr + i * 8, err)
            if not err.Success() or slot == 0:
                break
            out.append(self._read_full_cstr(slot))
        return out

    def _capture_exec(self, bp_id: int) -> Optional[dict]:
        """Full argument capture for the exec BP we're paused on. Reads the whole
        command string and, for exec/posix_spawn, the entire argv vector."""
        if not self.exec_bp_ids or bp_id not in self.exec_bp_ids or not self.process:
            return None
        name = self.exec_bp_ids[bp_id]
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)

        def reg(n: str) -> int:
            r = frame.FindRegister(n)
            return r.GetValueAsUnsigned() if r.IsValid() else 0

        if name in ("system", "popen"):
            return {"sym": name, "path": None,
                    "cmd": self._read_full_cstr(reg("x0")), "argv": None}
        if name in ("execve", "execvp"):
            return {"sym": name, "path": self._read_full_cstr(reg("x0")),
                    "cmd": None, "argv": self._read_argv(reg("x1"))}
        if name.startswith("posix_spawn"):
            return {"sym": name, "path": self._read_full_cstr(reg("x1")),
                    "cmd": None, "argv": self._read_argv(reg("x4"))}
        return {"sym": name, "path": self._read_full_cstr(reg("x0")),
                "cmd": None, "argv": None}

    @staticmethod
    def _exec_preview(cap: dict) -> str:
        if cap["cmd"] is not None:
            return cap["cmd"] or "<unreadable>"
        parts = [cap["path"] or "<unreadable>"]
        argv = cap["argv"] or []
        rest = argv[1:] if (argv and argv[0] == cap["path"]) else argv
        if rest:
            parts.append(" ".join(rest))
        return " ".join(parts)

    @staticmethod
    def exec_payload_len(cap: dict) -> int:
        if cap["cmd"] is not None:
            return len(cap["cmd"])
        return len(cap["path"] or "") + sum(len(a) for a in (cap["argv"] or []))

    def peek_exec_hit(self, bp_id: int) -> Optional[Tuple[str, str]]:
        """If stopped at an exec BP, return (symbol, preview) without continuing.
        The preview now includes argv, so callers see the start of the actual
        payload rather than just the interpreter path. Caller decides what next."""
        cap = self._capture_exec(bp_id)
        if cap is None:
            return None
        return cap["sym"], self._exec_preview(cap)

    def _dumps_dir(self) -> str:
        """Dumps sit beside the sample's state in ~/.macdbg/<name>-<sha>/dumps/."""
        if self.state:
            return self.state.dumps_dir()
        return os.path.join(STATE_DIR, "unknown", "dumps")

    def dump_exec_payload(self, bp_id: int) -> Optional[Tuple[str, int]]:
        """Write the full command / argv for the exec we're paused on to
        ~/.macdbg/dumps/ and return (path, bytes). None if not on an exec BP."""
        cap = self._capture_exec(bp_id)
        if cap is None:
            return None
        lines = ["symbol: {}".format(cap["sym"])]
        if cap["path"] is not None:
            lines.append("path: {}".format(cap["path"]))
        if cap["cmd"] is not None:
            lines.append("command:")
            lines.append(cap["cmd"])
        if cap["argv"] is not None:
            lines.append("argv ({} entries):".format(len(cap["argv"])))
            for i, a in enumerate(cap["argv"]):
                lines.append("  [{}] {}".format(i, a))
        body = "\n".join(lines) + "\n"
        dumps = self._dumps_dir()
        os.makedirs(dumps, exist_ok=True)
        pid = self.process.GetProcessID() if self.process else 0
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(dumps, "{}-pid{}-{}.txt".format(stamp, pid, cap["sym"]))
        n = 0
        while os.path.exists(path):
            n += 1
            path = os.path.join(
                dumps, "{}-pid{}-{}-{}.txt".format(stamp, pid, cap["sym"], n))
        with open(path, "w") as f:
            f.write(body)
        return path, len(body)

    def resolve_exec(self, decision: str = "block", name: str = "") -> None:
        if not self.process:
            return
        ret = lldb.SBCommandReturnObject()
        if decision == "block":
            self.ci.HandleCommand("thread return -1", ret, False)
        elif decision == "fake":
            self.ci.HandleCommand(
                "thread return {}".format(self._exec_success_value(name)), ret, False)
        self.process.Continue()

    @staticmethod
    def _exec_success_value(name: str) -> int:
        # What each call returns on success: system(3) and posix_spawn(2) return
        # 0, so a sample that checks only the return code believes the command
        # ran. popen returns an unfakeable FILE* and execve does not return on
        # success, so 0 is the best available for those.
        return 0

    EXEC_LARGE_PAYLOAD = 200

    def autodump_large_exec(self, bp_id: int) -> Optional[Tuple[str, int]]:
        """Dump the full payload only when it's too big to fit the preview, so a
        20kb dropper script is never silently lost whatever the caller decides."""
        cap = self._capture_exec(bp_id)
        if cap is None or self.exec_payload_len(cap) <= self.EXEC_LARGE_PAYLOAD:
            return None
        return self.dump_exec_payload(bp_id)

    def handle_exec_hit(self, bp_id: int) -> Optional[str]:
        cap = self._capture_exec(bp_id)
        if cap is None:
            return None
        if self.exec_interactive:
            return None
        name = cap["sym"]
        note = ""
        dumped = self.autodump_large_exec(bp_id)
        if dumped:
            note = " — full payload ({} B) → {}".format(dumped[1], dumped[0])
        self.resolve_exec("block", name)
        return 'blocked {}("{}") — returned -1{}'.format(
            name, self._exec_preview(cap)[:120], note)

    def handle_anti_ptrace_hit(self, bp_id: int) -> Optional[str]:
        if bp_id != self.anti_ptrace_bp_id or not self.process:
            return None
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        req = frame.FindRegister("x0").GetValueAsUnsigned()
        PT_DENY_ATTACH = 31
        if req != PT_DENY_ATTACH:
            self.process.Continue()
            return "ptrace(op={}) allowed through".format(req)
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand("thread return 0", ret, False)
        self.process.Continue()
        return "blocked ptrace(PT_DENY_ATTACH) — returned 0 without syscall"

    def breakpoints(self, exclude_ids: Optional[set] = None) -> List[Tuple[int, int, str, int, bool, str]]:
        out: List[Tuple[int, int, str, int, bool, str]] = []
        if not self.target:
            return out
        skip = exclude_ids or set()
        for i in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(i)
            bp_id = bp.GetID()
            if bp_id in skip:
                continue
            addr = 0
            desc = ""
            if bp.GetNumLocations() > 0:
                loc = bp.GetLocationAtIndex(0)
                addr = loc.GetLoadAddress()
                desc = str(loc.GetAddress().GetSymbol().GetName() or "")
            cmd_list = lldb.SBStringList()
            bp.GetCommandLineCommands(cmd_list)
            out.append((bp_id, addr, desc, cmd_list.GetSize(), bp.IsEnabled(), bp.GetCondition() or ""))
        return out

    def bp_commands(self, bp_id: int) -> List[str]:
        if not self.target:
            return []
        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            return []
        sl = lldb.SBStringList()
        bp.GetCommandLineCommands(sl)
        return [sl.GetStringAtIndex(i) for i in range(sl.GetSize())]

    def set_bp_commands(self, bp_id: int, commands: List[str]) -> bool:
        if not self.target:
            return False
        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            return False
        sl = lldb.SBStringList()
        for line in commands:
            if line.strip():
                sl.AppendString(line)
        bp.SetCommandLineCommands(sl)
        return True

    def set_bp_condition(self, bp_id: int, cond: str) -> bool:
        if not self.target:
            return False
        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            return False
        bp.SetCondition(cond or None)
        return True

    def set_bp_enabled(self, bp_id: int, enabled: bool) -> bool:
        if not self.target:
            return False
        bp = self.target.FindBreakpointByID(bp_id)
        if not bp.IsValid():
            return False
        bp.SetEnabled(enabled)
        return True

    def threads(self) -> List[Tuple[int, int, str, int, str]]:
        out: List[Tuple[int, int, str, int, str]] = []
        if not self.process or not self.process.IsValid():
            return out
        selected_tid = self.process.GetSelectedThread().GetThreadID()
        for i in range(self.process.GetNumThreads()):
            th = self.process.GetThreadAtIndex(i)
            frame = th.GetFrameAtIndex(0)
            pc = frame.GetPC() if frame and frame.IsValid() else 0
            func = ""
            if frame and frame.IsValid():
                func = frame.GetFunctionName() or frame.GetSymbol().GetName() or ""
            name = th.GetName() or th.GetQueueName() or ""
            marker = "*" if th.GetThreadID() == selected_tid else " "
            out.append((th.GetThreadID(), i, "{}{}".format(marker, name), pc, func))
        return out

    def select_thread(self, thread_id: int) -> bool:
        if not self.process:
            return False
        return self.process.SetSelectedThreadByID(thread_id)

    def select_stopped_thread(self) -> bool:
        """Select the thread that actually caused the stop. With several threads
        lldb often leaves a parked one selected, so a breakpoint hit on a worker
        looks like a reason-less stop and the handlers reading GetSelectedThread()
        miss it. Prefer a breakpoint thread, then any with a real stop reason,
        else leave it. Returns True if it changed."""
        if not self.process or not self.process.IsValid():
            return False
        sel = self.process.GetSelectedThread()
        if sel and sel.IsValid() and sel.GetStopReason() == lldb.eStopReasonBreakpoint:
            return False
        best = None
        for i in range(self.process.GetNumThreads()):
            th = self.process.GetThreadAtIndex(i)
            if not th.IsValid():
                continue
            reason = th.GetStopReason()
            if reason == lldb.eStopReasonBreakpoint:
                best = th
                break
            if best is None and reason not in (
                lldb.eStopReasonNone, lldb.eStopReasonInvalid,
            ):
                best = th
        if best is None:
            return False
        if sel and sel.IsValid() and best.GetThreadID() == sel.GetThreadID():
            return False
        return self.process.SetSelectedThreadByID(best.GetThreadID())

    def modules(self) -> List[Tuple[str, int, int, str]]:
        out: List[Tuple[int, str, int, int, str]] = []
        if not self.target:
            return []
        for i in range(self.target.GetNumModules()):
            m = self.target.GetModuleAtIndex(i)
            name = m.GetFileSpec().GetFilename() or ""
            base = 0
            size = 0
            for s in range(m.GetNumSections()):
                sec = m.GetSectionAtIndex(s)
                la = sec.GetLoadAddress(self.target)
                if la != lldb.LLDB_INVALID_ADDRESS and la != 0:
                    if base == 0 or la < base:
                        base = la
                    size += sec.GetByteSize()
            triple = m.GetTriple() or ""
            out.append((base, name, base, size, triple))
        out.sort()
        return [(name, base, size, triple) for _, name, base, size, triple in out]

    _STRING_SECTIONS = (
        "__cstring", "__oslogstring", "__ustring",
        "__objc_methname", "__objc_classname", "__objc_methtype",
        "__const",
    )

    def scan_live_strings(self, min_len: int = 8,
                          budget_bytes: int = 512 * 1024 * 1024) -> List[Tuple[int, str]]:
        """Scan heap, stack, and private mmap regions for null-terminated ASCII
        runs that look like real strings. Skips libraries and the target's own
        static sections. Bounded by `budget_bytes`."""
        if not self.process or not self.process.IsValid():
            return []
        exec_name = ""
        if self.target and self.target.IsValid():
            exec_name = self.target.GetExecutable().GetFilename() or ""
        target_ranges, _ = self._scope_metadata(exec_name)
        out: List[Tuple[int, str]] = []
        scanned = 0
        addr = 0
        seen_end = -1
        for _ in range(8192):
            info = lldb.SBMemoryRegionInfo()
            err = self.process.GetMemoryRegionInfo(addr, info)
            if not err.Success():
                break
            base = info.GetRegionBase()
            end = info.GetRegionEnd()
            if end <= seen_end or end == base:
                break
            seen_end = end
            size = end - base
            addr = end
            if not info.IsReadable() or size <= 0:
                continue
            if not self._region_in_target_scope(base, exec_name):
                continue
            if self._range_overlaps_any(base, end, target_ranges):
                continue
            chunk_size = 4 * 1024 * 1024
            off = 0
            while off < size:
                if scanned >= budget_bytes:
                    return out
                take = min(chunk_size, size - off)
                rerr = lldb.SBError()
                data = self.process.ReadMemory(base + off, take, rerr)
                if not rerr.Success() or not data:
                    break
                scanned += len(data)
                self._collect_printable_runs(bytes(data), base + off, min_len, out)
                off += take
        return out

    @staticmethod
    def _range_overlaps_any(base: int, end: int, ranges) -> bool:
        for lo, hi in ranges:
            if lo < end and hi > base:
                return True
        return False

    @staticmethod
    def _collect_printable_runs(data: bytes, base: int, min_len: int,
                                out: List[Tuple[int, str]]) -> None:
        run_start = None
        letters_or_paths = set(b"abcdefghijklmnopqrstuvwxyz"
                               b"ABCDEFGHIJKLMNOPQRSTUVWXYZ/.-_")
        for i, b in enumerate(data):
            if 32 <= b < 127 or b in (9, 10, 13):
                if run_start is None:
                    run_start = i
                continue
            if run_start is not None:
                if b == 0 and (i - run_start) >= min_len:
                    span = data[run_start:i]
                    if _looks_like_string(span, letters_or_paths):
                        try:
                            out.append((base + run_start, span.decode("ascii")))
                        except UnicodeDecodeError:
                            pass
                run_start = None

    def extract_strings(self, min_len: int = 5) -> List[Tuple[int, str]]:
        """Extract null-terminated strings from the executable's string sections.
        Returns (load_address, string)."""
        if not self.target or not self.target.IsValid():
            return []
        exec_name = self.target.GetExecutable().GetFilename() or ""
        exec_mod = None
        for i in range(self.target.GetNumModules()):
            m = self.target.GetModuleAtIndex(i)
            if m.GetFileSpec().GetFilename() == exec_name:
                exec_mod = m
                break
        if exec_mod is None:
            return []
        out: List[Tuple[int, str]] = []
        for s in range(exec_mod.GetNumSections()):
            sec = exec_mod.GetSectionAtIndex(s)
            self._collect_strings_in(sec, min_len, out)
        return out

    def _collect_strings_in(self, sec, min_len: int, out) -> None:
        if sec.GetNumSubSections() > 0:
            for i in range(sec.GetNumSubSections()):
                self._collect_strings_in(sec.GetSubSectionAtIndex(i), min_len, out)
            return
        name = sec.GetName() or ""
        if name not in self._STRING_SECTIONS:
            return
        load = sec.GetLoadAddress(self.target)
        if load == lldb.LLDB_INVALID_ADDRESS or load == 0:
            return
        err = lldb.SBError()
        data = sec.GetSectionData().ReadRawData(err, 0, sec.GetByteSize())
        if not err.Success() or not data:
            return
        raw = bytes(data)
        start = 0
        for i, b in enumerate(raw):
            if b == 0:
                span = raw[start:i]
                if len(span) >= min_len:
                    try:
                        s = span.decode("ascii")
                    except UnicodeDecodeError:
                        start = i + 1
                        continue
                    if all(32 <= ord(c) < 127 or c in "\t\n\r" for c in s):
                        out.append((load + start, s))
                start = i + 1

    def handle_command(self, cmd: str) -> Tuple[bool, str, str]:
        ret = lldb.SBCommandReturnObject()
        self.ci.HandleCommand(cmd, ret, False)
        return (ret.Succeeded(), ret.GetOutput() or "", ret.GetError() or "")

    def backtrace(self) -> List[Tuple[int, int, str, str]]:
        out: List[Tuple[int, int, str, str]] = []
        thread = self._thread()
        if not thread:
            return out
        for i in range(thread.GetNumFrames()):
            f = thread.GetFrameAtIndex(i)
            if not f.IsValid():
                break
            pc = f.GetPC()
            fn = f.GetFunctionName() or (f.GetSymbol().GetName() if f.GetSymbol().IsValid() else "") or "?"
            mod = ""
            m = f.GetModule()
            if m.IsValid():
                mod = m.GetFileSpec().GetFilename() or ""
            out.append((i, pc, fn, mod))
        return out

    def memory_search(self, needle: bytes, max_hits: int = 32,
                      total_budget_bytes: int = 4 * 1024 * 1024 * 1024,
                      scope: str = "target") -> Tuple[List[int], int]:
        """Search process memory for `needle`. scope "target" covers the binary's
        own sections plus anonymous regions (heap, stack, mmaps); scope "all"
        covers every readable region. Returns (hits, bytes_scanned).
        """
        if not self.process or not self.process.IsValid() or not needle:
            return [], 0
        exec_name = ""
        if self.target and self.target.IsValid():
            exec_name = self.target.GetExecutable().GetFilename() or ""
        hits: List[int] = []
        scanned = 0
        addr = 0
        seen_end = -1
        for _ in range(8192):
            info = lldb.SBMemoryRegionInfo()
            err = self.process.GetMemoryRegionInfo(addr, info)
            if not err.Success():
                break
            base = info.GetRegionBase()
            end = info.GetRegionEnd()
            if end <= seen_end or end == base:
                break
            seen_end = end
            size = end - base
            addr = end
            if not info.IsReadable() or size <= 0:
                continue
            if scope == "target" and not self._region_in_target_scope(base, exec_name):
                continue
            chunk_size = 4 * 1024 * 1024
            off = 0
            carry = b""
            while off < size:
                if scanned >= total_budget_bytes:
                    return hits, scanned
                take = min(chunk_size, size - off)
                rerr = lldb.SBError()
                data = self.process.ReadMemory(base + off, take, rerr)
                if not rerr.Success() or not data:
                    break
                scanned += len(data)
                buf = carry + data
                start = 0
                while True:
                    idx = buf.find(needle, start)
                    if idx < 0:
                        break
                    hits.append(base + off - len(carry) + idx)
                    if len(hits) >= max_hits:
                        return hits, scanned
                    start = idx + 1
                carry = buf[-(len(needle) - 1):] if len(needle) > 1 else b""
                off += take
        return hits, scanned

    def _region_in_target_scope(self, addr: int, exec_name: str) -> bool:
        if not self.target or not self.target.IsValid():
            return True
        target_ranges, cache_low = self._scope_metadata(exec_name)
        for lo, hi in target_ranges:
            if lo <= addr < hi:
                return True
        if cache_low is not None and addr >= cache_low:
            return False
        return True

    def _scope_metadata(self, exec_name: str):
        cache = getattr(self, "_range_cache", None)
        if cache and cache[0] == exec_name:
            return cache[1], cache[2]
        target: List[Tuple[int, int]] = []
        other_header_low: Optional[int] = None
        for i in range(self.target.GetNumModules()):
            m = self.target.GetModuleAtIndex(i)
            name = m.GetFileSpec().GetFilename() or ""
            is_target = (name == exec_name)
            if is_target:
                for s in range(m.GetNumSections()):
                    sec = m.GetSectionAtIndex(s)
                    la = sec.GetLoadAddress(self.target)
                    if la == lldb.LLDB_INVALID_ADDRESS or la == 0:
                        continue
                    target.append((la, la + sec.GetByteSize()))
            else:
                hdr = m.GetObjectFileHeaderAddress().GetLoadAddress(self.target)
                if hdr != lldb.LLDB_INVALID_ADDRESS and hdr != 0:
                    if other_header_low is None or hdr < other_header_low:
                        other_header_low = hdr
        self._range_cache = (exec_name, target, other_header_low)
        return target, other_header_low
