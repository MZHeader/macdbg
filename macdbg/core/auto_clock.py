"""Compensate observed debugger pauses at OS clock entries and ARM counters."""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

import lldb

from .breakpoints import create_hardware_breakpoint, validate_hardware_capacity
from .clock_bindings import ClockBindings
from .state import STATE_DIR
from .timing import TimingDefense


class PauseAccounting:
    def __init__(self, now=time.monotonic_ns):
        self.now = now
        self.reset()

    def reset(self):
        self.paused_ns = 0
        self.stopped_at = None
        self.key = None
        self.resumed_at = 0

    def stop(self, key, observed_ns=None):
        stamp = self.now() if observed_ns is None else observed_ns
        if key == self.key:
            return
        self.key = key
        self.stopped_at = max(stamp, self.resumed_at)

    def total(self):
        return self.paused_ns + (max(0, self.now() - self.stopped_at)
                                 if self.stopped_at is not None else 0)

    def resume(self):
        token = (self.paused_ns, self.stopped_at, self.key, self.resumed_at)
        stamp = self.now()
        if self.stopped_at is not None:
            self.paused_ns += max(0, stamp - self.stopped_at)
        self.stopped_at = None
        self.resumed_at = stamp
        return token

    def rollback(self, token):
        self.paused_ns, self.stopped_at, self.key, self.resumed_at = token


class Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


class Timespec(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_int64), ("nanoseconds", ctypes.c_int64)]


class SystemClocks:
    # Darwin elapsed-time clocks. Process/thread CPU clocks must run in target.
    CLOCK_IDS = {0, 4, 5, 6, 8, 9}

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        for name in ("mach_absolute_time", "mach_continuous_time"):
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = [], ctypes.c_uint64
        self.lib.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
        self.lib.mach_timebase_info.restype = ctypes.c_int
        base = Timebase()
        if self.lib.mach_timebase_info(ctypes.byref(base)) or not base.numer or not base.denom:
            raise RuntimeError("cannot read host Mach timebase")
        self.numer, self.denom = base.numer, base.denom
        self.lib.clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(Timespec)]
        self.lib.clock_gettime.restype = ctypes.c_int
        self.counter_lib = None

    def ns(self, clock_id):
        ts = Timespec()
        if self.lib.clock_gettime(clock_id, ctypes.byref(ts)):
            raise RuntimeError("host clock_gettime failed")
        return ts.seconds * 1000000000 + ts.nanoseconds

    def load_counters(self):
        if self.counter_lib:
            return
        source = Path(__file__).resolve().parents[1] / "native" / "clock_reader.c"
        digest = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
        directory = Path(STATE_DIR) / "native"
        directory.mkdir(parents=True, exist_ok=True)
        library = directory / ("clock-reader-" + digest + ".dylib")
        if not library.exists():
            fd, temporary = tempfile.mkstemp(suffix=".dylib", dir=directory)
            os.close(fd)
            try:
                result = subprocess.run(["/usr/bin/clang", "-arch", "arm64", "-O2", "-dynamiclib",
                                         str(source), "-o", temporary],
                                        capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise RuntimeError("host counter reader build failed: " + result.stderr.strip())
                os.replace(temporary, library)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        self.counter_lib = ctypes.CDLL(str(library))
        for name in ("macdbg_cntvct", "macdbg_cntpct", "macdbg_cntfrq"):
            fn = getattr(self.counter_lib, name)
            fn.argtypes, fn.restype = [], ctypes.c_uint64
        self.frequency = self.counter_lib.macdbg_cntfrq()
        if not self.frequency:
            raise RuntimeError("host counter frequency is zero")


class AutomaticClock:
    API_NAMES = ("mach_absolute_time", "mach_continuous_time", "clock_gettime", "gettimeofday",
                 "mach_wait_until")
    SCAN_LIMIT = 4 * 1024 * 1024

    def __init__(self, debugger):
        self.debugger = debugger
        self.enabled = False
        self.last_error = None
        self.pauses = PauseAccounting()
        self.reader = None
        self._hooks = {}
        self._handled = set()
        self._last = {}
        self.hits = {}
        self.passthrough = 0
        self.counter_sites = 0
        self.counter_armed = 0
        self.scan_complete = False
        self.coverage_notes = []
        self._text_range = (0, 0)
        self._process_id = None
        self.bindings = None
        self._resolver_returns = {}
        self.resolutions = {}

    def hidden_bp_ids(self):
        return set(self._hooks) | set(self._resolver_returns)

    def observe_stop(self, observed_ns=None):
        process = self.debugger.process
        if self.enabled and process and process.IsValid() and process.GetState() == lldb.eStateStopped:
            self.pauses.stop((process.GetProcessID(), process.GetStopID()), observed_ns)

    def _api_address(self, name):
        target = self.debugger.target
        contexts = target.FindSymbols(name, lldb.eSymbolTypeCode)
        addresses = set()
        for i in range(contexts.GetSize()):
            context = contexts.GetContextAtIndex(i)
            module = context.GetModule()
            path = str(module.GetFileSpec())
            if not path.startswith("/usr/lib/"):
                continue
            address = context.GetSymbol().GetStartAddress().GetLoadAddress(target)
            if address not in (0, lldb.LLDB_INVALID_ADDRESS):
                addresses.add(address)
        if len(addresses) != 1:
            raise RuntimeError("cannot uniquely resolve OS clock entry " + name)
        return addresses.pop()

    def _scan_counters(self):
        start, end = self._text_range
        target = self.debugger.target
        limit = min(end, start + self.SCAN_LIMIT)
        sites = []
        at = start
        while at < limit:
            instructions = target.ReadInstructions(lldb.SBAddress(at, target), min(2048, (limit - at) // 4))
            if not instructions.GetSize():
                break
            for i in range(instructions.GetSize()):
                instruction = instructions.GetInstructionAtIndex(i)
                if (instruction.GetMnemonic(target) or "").lower() != "mrs":
                    continue
                operand = (instruction.GetOperands(target) or "").lower()
                match = re.fullmatch(r"(x(?:[12]?\d|30)|xzr),\s*(cntvct_el0|cntpct_el0)", operand)
                if match:
                    sites.append((instruction.GetAddress().GetLoadAddress(target), match[1], match[2]))
            at += instructions.GetSize() * 4
        self.scan_complete = at >= end
        if not self.scan_complete:
            self.coverage_notes.append("main text counter scan is incomplete (4 MiB limit or unreadable code)")
        return sites

    def enable(self):
        if self.enabled:
            return self.validate()
        try:
            d = self.debugger
            if not d.is_stopped_at_entry_point() or d.in_user_step():
                raise RuntimeError("automatic clock mode must be enabled at the initial entry stop; restart first")
            if d.target.GetPlatform().GetName() != "host":
                raise RuntimeError("automatic clocks require the local host platform")
            if not (d.target.GetTriple() or "").startswith("arm64-"):
                raise RuntimeError("automatic clocks currently require native ARM64")
            if d.timing.enabled:
                raise RuntimeError("disable manual timing rules before enabling automatic clocks")
            self.reader = SystemClocks()
            self.coverage_notes = []
            module = d.target.FindModule(d.target.GetExecutable())
            section = module.FindSection("__TEXT").FindSubSection("__text")
            start = section.GetLoadAddress(d.target)
            if not section.IsValid() or start in (0, lldb.LLDB_INVALID_ADDRESS):
                raise RuntimeError("cannot locate main executable text")
            self._text_range = (start, start + section.GetByteSize())
            originals = {name: self._api_address(name) for name in (*self.API_NAMES, 'dlsym')}
            self.bindings = ClockBindings(d, originals)
            imports = self.bindings.install()
            if not imports:
                self.coverage_notes.append('no supported clock or dlsym imports found in the main executable')
            if self.bindings.skipped:
                self.coverage_notes.append('custom clock bindings left unchanged: ' + ', '.join(sorted(set(self.bindings.skipped))))
            for name, address in self.bindings.proxies.items():
                bp = d.target.BreakpointCreateByAddress(address)
                if not bp.IsValid() or bp.GetNumLocations() != 1:
                    if bp.IsValid(): d.target.BreakpointDelete(bp.GetID())
                    raise RuntimeError("cannot arm clock forwarder " + name)
                self._hooks[bp.GetID()] = (address, name, None, self.bindings.code[address])
            sites = self._scan_counters()
            self.counter_sites = len(sites)
            self.counter_armed = 0
            if sites:
                self.reader.load_counters()
                counter_ids = []
                try:
                    for address, register, kind in sites:
                        expected = d.read_memory(address, 4)
                        if len(expected) != 4:
                            raise RuntimeError("cannot read counter instruction")
                        bp = create_hardware_breakpoint(d.target, d.ci, "-a {:#x}".format(address), reserve=1)
                        counter_ids.append(bp.GetID())
                        d.hardware_bp_ids.add(bp.GetID())
                        self._hooks[bp.GetID()] = (address, kind, register, expected)
                    self.counter_armed = len(counter_ids)
                except RuntimeError as error:
                    for bp_id in counter_ids:
                        d.target.BreakpointDelete(bp_id)
                        d.hardware_bp_ids.discard(bp_id)
                        self._hooks.pop(bp_id, None)
                    self.coverage_notes.append("direct counters uncovered: " + str(error))
            self.enabled = True
            self.last_error = None
            self._process_id = d.process.GetProcessID()
            self.pauses.reset()
            self._handled.clear()
            self._last.clear()
            self.hits.clear()
            self.resolutions.clear()
            self.passthrough = 0
            self.observe_stop()
            return True, "automatic clocks enabled ({} APIs, {}/{} direct counters){}".format(
                len(self.API_NAMES), self.counter_armed, self.counter_sites,
                "; " + "; ".join(self.coverage_notes) if self.coverage_notes else "")
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            self.disable()
            self.last_error = str(error)
            return False, self.last_error

    def disable(self):
        d = self.debugger
        for bp_id in self.hidden_bp_ids():
            if d.target and d.target.IsValid():
                d.target.BreakpointDelete(bp_id)
            d.hardware_bp_ids.discard(bp_id)
        self._hooks.clear()
        self._resolver_returns.clear()
        if self.bindings is not None:
            try:
                self.bindings.restore()
            except RuntimeError as error:
                self.enabled = True
                self.last_error = str(error)
                raise
            self.bindings = None
        self._handled.clear()
        self.enabled = False
        self.last_error = None
        self.pauses.reset()
        self.hits.clear()
        self._last.clear()
        self.resolutions.clear()
        self.counter_sites = self.counter_armed = self.passthrough = 0
        self.scan_complete = False
        self.coverage_notes = []
        self._process_id = None
        self._text_range = (0, 0)
        return True, "automatic clocks disabled; restart before re-enabling"

    def validate(self):
        if not self.enabled:
            return True, "automatic clocks disabled"
        if self.last_error:
            return False, self.last_error
        try:
            d = self.debugger
            if not d.process or d.process.GetProcessID() != self._process_id:
                raise RuntimeError("automatic clock hooks belong to a different process")
            if len(self._hooks) != len(self.API_NAMES) + 1 + self.counter_armed:
                raise RuntimeError("automatic clock hooks are missing")
            validate_hardware_capacity(d.target, reserve=int(d._step_plan_active))
            for bp_id, (address, kind, register, expected) in self._hooks.items():
                bp = d.target.FindBreakpointByID(bp_id)
                if not bp.IsValid() or not bp.IsEnabled() or bp.IsOneShot() or bp.GetNumLocations() != 1:
                    raise RuntimeError("automatic clock breakpoint was modified")
                location = bp.GetLocationAtIndex(0)
                if not location.IsEnabled() or not location.IsResolved() or location.GetLoadAddress() != address:
                    raise RuntimeError("automatic clock breakpoint is unresolved or moved")
                TimingDefense._check_filters(bp)
                TimingDefense._check_filters(location)
                if register is not None:
                    if not bp.IsHardware():
                        raise RuntimeError("counter breakpoint is not hardware-backed")
                    if d.process.GetState() == lldb.eStateStopped and d.read_memory(address, 4) != expected:
                        raise RuntimeError("counter instruction changed; restart and rescan")
            if self.bindings is None:
                raise RuntimeError('clock import bindings are missing')
            self.bindings.validate()
            for bp_id, (address, owner, _name) in self._resolver_returns.items():
                bp = d.target.FindBreakpointByID(bp_id)
                if (not bp.IsValid() or not bp.IsEnabled() or not bp.IsHardware()
                        or bp.IsOneShot() or bp.GetThreadID() != owner
                        or bp.GetNumLocations() != 1):
                    raise RuntimeError('clock resolver return hook was modified')
                location = bp.GetLocationAtIndex(0)
                if not location.IsEnabled() or not location.IsResolved() or location.GetLoadAddress() != address:
                    raise RuntimeError('clock resolver return hook moved or became unresolved')
                TimingDefense._check_filters(bp, owner)
                TimingDefense._check_filters(location, owner)
            return True, "automatic clock hooks ready"
        except (RuntimeError, ValueError) as error:
            self.last_error = str(error)
            return False, self.last_error

    def require_ready(self):
        ok, message = self.validate()
        if not ok:
            raise RuntimeError(message)

    def _adjust(self, real, domain, scale=1, divisor=1, monotonic=True):
        value = max(0, real - self.pauses.total() * scale // divisor)
        if monotonic:
            value = max(value, self._last.get(domain, 0))
            self._last[domain] = value
        return value

    @staticmethod
    def _read(frame, name):
        error = lldb.SBError()
        value = frame.FindRegister(name).GetValueAsUnsigned(error, 0)
        if error.Fail():
            raise RuntimeError("cannot read clock argument " + name)
        return value

    @staticmethod
    def _write(thread, name, value):
        error = lldb.SBError()
        register = thread.GetFrameAtIndex(0).FindRegister(name)
        if not register.SetValueFromCString(hex(value), error) or error.Fail():
            raise RuntimeError("cannot write clock result " + name)
        actual = thread.GetFrameAtIndex(0).FindRegister(name).GetValueAsUnsigned(error, 0)
        if error.Fail() or actual != value:
            raise RuntimeError("clock register verification failed")

    def _writable(self, address, length):
        if not address:
            return False
        end = address + length
        while address < end:
            info = lldb.SBMemoryRegionInfo()
            error = self.debugger.process.GetMemoryRegionInfo(address, info)
            if error.Fail() or not info.IsWritable() or info.GetRegionEnd() <= address:
                return False
            address = min(end, info.GetRegionEnd())
        return True

    def _handle(self, thread, kind, register):
        frame = thread.GetFrameAtIndex(0)
        pc = frame.GetPC()
        reader = self.reader
        if kind == 'dlsym':
            caller = self._read(frame, 'x30')
            if not self._text_range[0] <= caller < self._text_range[1]:
                return
            error = lldb.SBError()
            name = self.debugger.process.ReadCStringFromMemory(self._read(frame, 'x1'), 128, error)
            if error.Fail() or name not in self.bindings.proxies:
                return
            bp = self.debugger.create_hardware_breakpoint_by_address(caller)
            bp.SetThreadID(thread.GetThreadID())
            self._resolver_returns[bp.GetID()] = (caller, thread.GetThreadID(), name)
            return
        if register is not None:
            fn = reader.counter_lib.macdbg_cntvct if kind == "cntvct_el0" else reader.counter_lib.macdbg_cntpct
            value = self._adjust(fn(), kind, reader.frequency, 1000000000)
            if register != "xzr":
                self._write(thread, register, value)
            destination = pc + 4
        else:
            destination = self._read(frame, "x30")
            compensate = self._text_range[0] <= destination < self._text_range[1]
            if not compensate:
                self.passthrough += 1
                return
            if kind == "mach_wait_until":
                if not compensate:
                    return
                deadline = self._read(frame, "x0")
                ticks = self.pauses.total() * reader.denom // reader.numer
                self._write(thread, "x0", min((1 << 64) - 1, deadline + ticks))
                self.hits[kind] = self.hits.get(kind, 0) + 1
                return  # Run the real kernel wait with the translated deadline.
            if kind.startswith("mach_"):
                real = getattr(reader.lib, kind)()
                value = (self._adjust(real, kind, reader.denom, reader.numer)
                         if compensate else real)
            else:
                clock_id = self._read(frame, "x0") if kind == "clock_gettime" else 0
                address = self._read(frame, "x1" if kind == "clock_gettime" else "x0")
                size = 16 if kind == "clock_gettime" else 12
                if (clock_id not in reader.CLOCK_IDS or not self._writable(address, size)
                        or (kind == "gettimeofday" and self._read(frame, "x1"))):
                    if compensate:
                        self.passthrough += 1
                    return  # Preserve the original API's errors and unsupported clock domains.
                real = reader.ns(clock_id)
                ns = (self._adjust(real, ("clock", clock_id), monotonic=clock_id != 0)
                      if compensate else real)
                seconds, nanos = divmod(ns, 1000000000)
                data = struct.pack("<qq", seconds, nanos) if kind == "clock_gettime" else struct.pack("<qi", seconds, nanos // 1000)
                ok, error = self.debugger.write_memory(address, data, track=False)
                if not ok:
                    raise RuntimeError("cannot write clock buffer: " + error)
                value = 0
            self._write(thread, "x0", value)
        # Clock forwarders are frameless; preserve SP and every non-result
        # register while returning directly to their caller.
        if not thread.GetFrameAtIndex(0).SetPC(destination):
            raise RuntimeError("cannot advance past clock read")
        if thread.GetFrameAtIndex(0).GetPC() != destination:
            raise RuntimeError("cannot advance past clock read")
        if register is not None or compensate:
            self.hits[kind] = self.hits.get(kind, 0) + 1

    def apply_stop(self):
        if not self.enabled:
            return False
        self.observe_stop()
        self.require_ready()
        process = self.debugger.process
        if process.GetState() != lldb.eStateStopped:
            return False
        key = (process.GetProcessID(), process.GetStopID())
        self._handled = {item for item in self._handled if item[:2] == key}
        matched, foreign = False, False
        hidden = self.hidden_bp_ids()
        for thread in process:
            reason = thread.GetStopReason()
            ids = {thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)} if reason == lldb.eStopReasonBreakpoint else set()
            foreign |= bool(ids - hidden) or reason not in (
                lldb.eStopReasonNone, lldb.eStopReasonInvalid, lldb.eStopReasonBreakpoint)
            # All-stop can catch another thread at an armed clock entry before
            # it reports its own breakpoint. LLDB may step over that entry on
            # resume, so intercept by PC even for an incidental stopped thread.
            if reason not in (lldb.eStopReasonBreakpoint, lldb.eStopReasonPlanComplete,
                              lldb.eStopReasonNone, lldb.eStopReasonInvalid):
                continue
            frame = thread.GetFrameAtIndex(0)
            if not frame.IsValid():
                continue
            pc = frame.GetPC()
            for bp_id, (address, owner, name) in list(self._resolver_returns.items()):
                if pc != address or thread.GetThreadID() != owner:
                    continue
                matched = True
                result = self._read(frame, 'x0')
                if result == self.bindings.originals[name]:
                    self._write(thread, 'x0', self.bindings.proxies[name])
                    self.resolutions[name] = self.resolutions.get(name, 0) + 1
                from .breakpoints import remember_hardware_return
                remember_hardware_return(self.debugger, bp_id)
                if not self.debugger.delete_breakpoint(bp_id):
                    self.last_error = 'cannot retire clock resolver return hook'
                    raise RuntimeError(self.last_error)
                del self._resolver_returns[bp_id]
            for bp_id, (address, kind, register, _) in self._hooks.items():
                if pc != address:
                    continue
                matched = True
                token = key + (thread.GetThreadID(), bp_id)
                if token in self._handled:
                    continue
                try:
                    self._handle(thread, kind, register)
                    self._handled.add(token)
                except RuntimeError as error:
                    self.last_error = str(error)
                    raise
        return matched and not foreign

    def status(self):
        ok, message = self.validate()
        return {"enabled": self.enabled, "safe": self.enabled and ok,
                "error": self.last_error if ok else message,
                "scope": "main-executable callers and scanned main text",
                "apis": list(self.API_NAMES) if self.enabled else [],
                "entry_points": dict(self.bindings.proxies) if self.bindings else {},
                "import_bindings": len(self.bindings.slots) if self.bindings else 0,
                "dynamic_resolutions": dict(self.resolutions),
                "counter_kinds": ["cntvct_el0", "cntpct_el0"],
                "counter_sites": self.counter_sites, "counter_armed": self.counter_armed,
                "counter_coverage_complete": self.scan_complete and self.counter_sites == self.counter_armed,
                "scan_complete": self.scan_complete,
                "coverage_notes": list(self.coverage_notes), "hits": dict(self.hits),
                "passthrough": self.passthrough,
                "paused_ns": self.pauses.total() if self.enabled else 0}
