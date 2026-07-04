from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import lldb


FILE = "FILE"
NET = "NET"
PROC = "PROC"


@dataclass
class TraceHit:
    category: str
    call: str


def _read_cstr(process: lldb.SBProcess, addr: int, cap: int = 256) -> str:
    if addr == 0:
        return "NULL"
    err = lldb.SBError()
    s = process.ReadCStringFromMemory(addr, cap, err)
    if not err.Success():
        return "<unreadable>"
    return s or ""


def _read_bytes(process: lldb.SBProcess, addr: int, n: int) -> bytes:
    if addr == 0 or n <= 0:
        return b""
    err = lldb.SBError()
    data = process.ReadMemory(addr, min(n, 128), err)
    return data if err.Success() else b""


def _fmt_bytes(b: bytes) -> str:
    if not b:
        return '""'
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    if printable / len(b) > 0.8:
        s = b.decode("ascii", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
        return '"{}"'.format(s[:60] + ("…" if len(b) > 60 else ""))
    return "<{}B: {}{}>".format(len(b), b[:24].hex(), "…" if len(b) > 24 else "")


def _reg(frame: lldb.SBFrame, name: str) -> int:
    r = frame.FindRegister(name)
    return r.GetValueAsUnsigned() if r.IsValid() else 0


def _fmt_sockaddr(process: lldb.SBProcess, addr: int) -> str:
    if addr == 0:
        return "NULL"
    data = _read_bytes(process, addr, 28)
    if len(data) < 8:
        return "{:#x}".format(addr)
    family = data[1]
    if family == 2 and len(data) >= 8:
        port = struct.unpack(">H", data[2:4])[0]
        ip = ".".join(str(b) for b in data[4:8])
        return "{}:{}".format(ip, port)
    if family == 30 and len(data) >= 28:
        port = struct.unpack(">H", data[2:4])[0]
        ip6 = data[8:24]
        parts = [struct.unpack(">H", ip6[i:i+2])[0] for i in range(0, 16, 2)]
        return "[{}]:{}".format(":".join("{:x}".format(p) for p in parts), port)
    return "family={} {:#x}".format(family, addr)


def _f_open(frame, p):
    path = _read_cstr(p, _reg(frame, "x0"))
    flags = _reg(frame, "x1")
    return 'open("{}", {:#x})'.format(path, flags)


def _f_openat(frame, p):
    fd = _reg(frame, "x0")
    path = _read_cstr(p, _reg(frame, "x1"))
    flags = _reg(frame, "x2")
    return 'openat({}, "{}", {:#x})'.format(fd, path, flags)


def _f_close(frame, p):
    return "close({})".format(_reg(frame, "x0"))


def _f_read(frame, p):
    return "read(fd={}, buf={:#x}, n={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"))


def _f_write(frame, p):
    fd = _reg(frame, "x0")
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    return "write({}, {}, n={})".format(fd, _fmt_bytes(_read_bytes(p, buf, n)), n)


def _f_fopen(frame, p):
    path = _read_cstr(p, _reg(frame, "x0"))
    mode = _read_cstr(p, _reg(frame, "x1"))
    return 'fopen("{}", "{}")'.format(path, mode)


def _f_popen(frame, p):
    cmd = _read_cstr(p, _reg(frame, "x0"))
    mode = _read_cstr(p, _reg(frame, "x1"))
    return 'popen("{}", "{}")'.format(cmd, mode)


def _f_system(frame, p):
    return 'system("{}")'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_execve(frame, p):
    return 'execve("{}", …)'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_socket(frame, p):
    dom, ty, proto = _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2")
    return "socket(domain={}, type={}, proto={})".format(dom, ty, proto)


def _f_connect(frame, p):
    fd = _reg(frame, "x0")
    return "connect({}, {})".format(fd, _fmt_sockaddr(p, _reg(frame, "x1")))


def _f_bind(frame, p):
    fd = _reg(frame, "x0")
    return "bind({}, {})".format(fd, _fmt_sockaddr(p, _reg(frame, "x1")))


def _f_send(frame, p):
    fd = _reg(frame, "x0")
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    return "send({}, {}, n={})".format(fd, _fmt_bytes(_read_bytes(p, buf, n)), n)


def _f_recv(frame, p):
    return "recv(fd={}, buf={:#x}, n={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"))


def _f_sendto(frame, p):
    fd = _reg(frame, "x0")
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    dst = _reg(frame, "x4")
    return "sendto({}, {}, n={}, to={})".format(
        fd, _fmt_bytes(_read_bytes(p, buf, n)), n, _fmt_sockaddr(p, dst))


def _f_getaddrinfo(frame, p):
    host = _read_cstr(p, _reg(frame, "x0"))
    service = _read_cstr(p, _reg(frame, "x1"))
    return 'getaddrinfo("{}", "{}")'.format(host, service)


def _f_printf(frame, p):
    return 'printf("{}", …)'.format(_read_cstr(p, _reg(frame, "x0")).rstrip("\n"))


def _f_fprintf(frame, p):
    return 'fprintf(fd={}, "{}", …)'.format(
        _reg(frame, "x0"), _read_cstr(p, _reg(frame, "x1")).rstrip("\n"))


def _f_snprintf(frame, p):
    return 'snprintf(buf={:#x}, n={}, "{}", …)'.format(
        _reg(frame, "x0"), _reg(frame, "x1"),
        _read_cstr(p, _reg(frame, "x2")).rstrip("\n"))


def _f_puts(frame, p):
    return 'puts("{}")'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_fputs(frame, p):
    return 'fputs("{}", fd={})'.format(_read_cstr(p, _reg(frame, "x0")), _reg(frame, "x1"))


SIGS: Dict[str, Tuple[str, Callable]] = {
    "open":             (FILE, _f_open),
    "open$NOCANCEL":    (FILE, _f_open),
    "openat":           (FILE, _f_openat),
    "close":            (FILE, _f_close),
    "close$NOCANCEL":   (FILE, _f_close),
    "read":             (FILE, _f_read),
    "read$NOCANCEL":    (FILE, _f_read),
    "write":            (FILE, _f_write),
    "write$NOCANCEL":   (FILE, _f_write),
    "fopen":            (FILE, _f_fopen),
    "printf":           (FILE, _f_printf),
    "fprintf":          (FILE, _f_fprintf),
    "snprintf":         (FILE, _f_snprintf),
    "sprintf":          (FILE, _f_snprintf),
    "puts":             (FILE, _f_puts),
    "fputs":            (FILE, _f_fputs),
    "popen":            (PROC, _f_popen),
    "system":           (PROC, _f_system),
    "execve":           (PROC, _f_execve),
    "execvp":           (PROC, _f_execve),
    "socket":           (NET,  _f_socket),
    "connect":          (NET,  _f_connect),
    "connect$NOCANCEL": (NET,  _f_connect),
    "bind":             (NET,  _f_bind),
    "send":             (NET,  _f_send),
    "send$NOCANCEL":    (NET,  _f_send),
    "recv":             (NET,  _f_recv),
    "recv$NOCANCEL":    (NET,  _f_recv),
    "sendto":           (NET,  _f_sendto),
    "sendto$NOCANCEL":  (NET,  _f_sendto),
    "getaddrinfo":      (NET,  _f_getaddrinfo),
}


class Tracer:
    _NOISY_MODULES = (
        "dyld", "libsystem_", "libobjc", "libc++",
        "CoreFoundation", "Foundation",
    )

    def __init__(self) -> None:
        self._bp_ids: List[int] = []
        self._bp_to_name: Dict[int, str] = {}
        self.enabled = False

    def enable(self, target: lldb.SBTarget) -> int:
        if self.enabled or not target or not target.IsValid():
            return 0
        for name in SIGS:
            bp = target.BreakpointCreateByName(name)
            if not bp.IsValid():
                continue
            if bp.GetNumLocations() > 0:
                self._bp_ids.append(bp.GetID())
                self._bp_to_name[bp.GetID()] = name
            else:
                target.BreakpointDelete(bp.GetID())
        self.enabled = len(self._bp_ids) > 0
        return len(self._bp_ids)

    def disable(self, target: lldb.SBTarget) -> None:
        if not target or not target.IsValid():
            self._bp_ids.clear()
            self._bp_to_name.clear()
            self.enabled = False
            return
        for bp_id in self._bp_ids:
            target.BreakpointDelete(bp_id)
        self._bp_ids.clear()
        self._bp_to_name.clear()
        self.enabled = False

    def is_trace_bp(self, bp_id: int) -> bool:
        return bp_id in self._bp_to_name

    def hit_from(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,
        user_only: bool = True,
    ) -> Optional[TraceHit]:
        if not frame or not frame.IsValid():
            return None
        name = frame.GetFunctionName() or ""
        for candidate in (name, name.lstrip("_")):
            if candidate in SIGS:
                cat, fmt = SIGS[candidate]
                if user_only and self._caller_is_noise(frame):
                    return None
                try:
                    call = fmt(frame, process)
                except Exception as e:
                    call = "{}(...) [formatter error: {}]".format(candidate, e)
                return TraceHit(category=cat, call=call)
        return None

    def _caller_is_noise(self, frame: lldb.SBFrame) -> bool:
        thread = frame.GetThread()
        for i in range(1, min(thread.GetNumFrames(), 8)):
            f = thread.GetFrameAtIndex(i)
            if not f.IsValid():
                break
            module = f.GetModule()
            if not module.IsValid():
                continue
            modname = module.GetFileSpec().GetFilename() or ""
            if any(modname.startswith(pfx) for pfx in self._NOISY_MODULES):
                continue
            return False
        return True
