from __future__ import annotations

import os
from typing import List, Optional, Tuple

import lldb


class Debugger:
    def __init__(self) -> None:
        self.dbg = lldb.SBDebugger.Create()
        self.dbg.SetAsync(True)
        self.ci = self.dbg.GetCommandInterpreter()
        self.target: Optional[lldb.SBTarget] = None
        self.process: Optional[lldb.SBProcess] = None
        self.listener: lldb.SBListener = self.dbg.GetListener()

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
        return self.target

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
            self.process.Kill()
        lldb.SBDebugger.Destroy(self.dbg)

    def cont(self) -> None:
        if self.process:
            self.process.Continue()

    def step_in(self) -> None:
        t = self._thread()
        if t:
            t.StepInstruction(False)

    def step_over(self) -> None:
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
        bp = self.target.BreakpointCreateByAddress(addr)
        return ("added", bp.GetID())

    def breakpoints(self) -> List[Tuple[int, int, str]]:
        out: List[Tuple[int, int, str]] = []
        if not self.target:
            return out
        for i in range(self.target.GetNumBreakpoints()):
            bp = self.target.GetBreakpointAtIndex(i)
            addr = 0
            desc = ""
            if bp.GetNumLocations() > 0:
                loc = bp.GetLocationAtIndex(0)
                addr = loc.GetLoadAddress()
                desc = str(loc.GetAddress().GetSymbol().GetName() or "")
            out.append((bp.GetID(), addr, desc))
        return out

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
