from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

import lldb

from .state import BinaryState, StoredBP, load_for


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

    def launch(self, argv: List[str]) -> lldb.SBProcess:
        assert self.target is not None
        info = lldb.SBLaunchInfo(argv)
        info.SetLaunchFlags(
            lldb.eLaunchFlagStopAtEntry | lldb.eLaunchFlagDisableASLR
        )
        err = lldb.SBError()
        self.process = self.target.Launch(info, err)
        if not err.Success():
            raise RuntimeError(f"Launch failed: {err.GetCString()}")
        self._attached = False
        self._hook_listener(self.process)
        return self.process

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

    def step_in(self) -> None:
        t = self._thread()
        if t:
            t.StepInstruction(False)

    _CALL_MNEMONICS = {"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"}

    def step_over(self) -> None:
        """Step over the current instruction. lldb's SBThread.StepInstruction(True)
        can silently degrade to step-in when it cannot identify a call site in
        stripped code, so for arm64 call instructions we set a one-shot BP at
        pc+4 and continue — the reliable classical implementation."""
        t = self._thread()
        if not t or not self.target or not self.target.IsValid():
            return
        frame = t.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return
        pc = frame.GetPC()
        insns = self.target.ReadInstructions(lldb.SBAddress(pc, self.target), 1)
        if insns.GetSize() >= 1:
            mn = (insns.GetInstructionAtIndex(0).GetMnemonic(self.target) or "").lower()
            if mn in self._CALL_MNEMONICS:
                bp = self.target.BreakpointCreateByAddress(pc + 4)
                bp.SetOneShot(True)
                bp.SetThreadID(t.GetThreadID())
                if self.process:
                    self.process.Continue()
                return
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

    def write_memory(self, addr: int, data: bytes) -> Tuple[bool, str]:
        if not self.process:
            return False, "no process"
        state = self.process.GetState()
        if state != lldb.eStateStopped:
            return False, "process not stopped (state={})".format(
                lldb.SBDebugger.StateAsCString(state))
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
        return True, "wrote {} byte(s) at {:#x}".format(n, addr)

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
        """Read `total` bytes containing `addr`, with roughly `before` bytes of
        context before it. Walks across adjacent readable regions if the desired
        range crosses a boundary."""
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

    def handle_fork_hit(self, bp_id: int) -> Optional[str]:
        if not self.fork_bp_ids or bp_id not in self.fork_bp_ids or not self.process:
            return None
        if self.fork_mode != "identity":
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

    def peek_exec_hit(self, bp_id: int) -> Optional[Tuple[str, str]]:
        """If this stop is at an exec BP, return (symbol, command_string) without
        advancing the process. The caller decides whether to allow or block."""
        if not self.exec_bp_ids or bp_id not in self.exec_bp_ids or not self.process:
            return None
        name = self.exec_bp_ids[bp_id]
        thread = self.process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if name in ("system", "popen"):
            cmd_ptr = frame.FindRegister("x0").GetValueAsUnsigned()
        elif name.startswith("posix_spawn"):
            cmd_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
        else:
            cmd_ptr = frame.FindRegister("x0").GetValueAsUnsigned()
        err = lldb.SBError()
        cmd = self.process.ReadCStringFromMemory(cmd_ptr, 512, err) if cmd_ptr else ""
        cmd = cmd if err.Success() else "<unreadable>"
        return name, cmd

    def resolve_exec(self, block: bool) -> None:
        if not self.process:
            return
        if block:
            ret = lldb.SBCommandReturnObject()
            self.ci.HandleCommand("thread return -1", ret, False)
        self.process.Continue()

    def handle_exec_hit(self, bp_id: int) -> Optional[str]:
        peeked = self.peek_exec_hit(bp_id)
        if peeked is None:
            return None
        if self.exec_interactive:
            return None
        name, cmd = peeked
        self.resolve_exec(block=True)
        return 'blocked {}("{}") — returned -1'.format(name, cmd[:120])

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
        """Search process memory for `needle`.
        scope:
          "target"  — target binary's own sections + anonymous regions
                      (heap, stack, private mmaps). Skips other modules.
          "all"     — every readable region including dyld/libSystem/frameworks.
        Returns (hits, bytes_scanned).
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
