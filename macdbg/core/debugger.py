from __future__ import annotations

import os
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
            t.StepInstruction(False)

    def step_out(self) -> None:
        """Run until the current frame returns (gdb's 'finish')."""
        t = self._thread()
        if t:
            t.StepOut()

    def step_over(self) -> None:
        """Step over the current instruction, stepping over calls.

        This used to set a one-shot breakpoint at pc+4 and `process.Continue()`
        for arm64 calls, on the theory that StepInstruction(True) degrades to
        step-in on stripped call sites. But Continue is unbounded: if the callee
        never returns cleanly to pc+4 (a large function that hits another
        breakpoint, longjmps, or exits), the step-over turned into a full run --
        the reported "step over just continues" bug. StepInstruction(True) is a
        bounded thread plan that steps over calls correctly (verified on
        stripped target binaries) and, like step_in, can never run away, so we
        use it directly."""
        t = self._thread()
        if t:
            t.StepInstruction(True)

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
        return True, "PT_DENY_ATTACH bypass armed (bp #{})".format(bp.GetID())

    def disable_anti_ptrace(self) -> Tuple[bool, str]:
        if not self.target or not self.anti_ptrace_bp_id:
            return True, "already disabled"
        self.target.BreakpointDelete(self.anti_ptrace_bp_id)
        self.anti_ptrace_bp_id = 0
        return True, "PT_DENY_ATTACH bypass disabled"

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
