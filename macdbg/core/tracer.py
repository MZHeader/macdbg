from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import lldb

from .network_capture import NetworkCapture, FOUNDATION_PATTERN, RESUME_PATTERN, RUSTLS_WRITE_PATTERN, TLS_CLOSES, TLS_WRITES
from .http_capture import body_record, CAPTURE_LIMIT
from .return_hooks import ReturnHooks


FILE = "FILE"
NET = "NET"
PROC = "PROC"

# Calls whose first arg is a file descriptor, used to skip hits on the interpose
# trace fd so its writes aren't double-traced.
_FD_CALLS = {"read", "write", "pread", "pwrite", "close",
             "send", "recv", "sendto", "recvfrom", "sendmsg", "writev"}


@dataclass
class TraceHit:
    category: str
    call: str
    details: dict = field(default_factory=dict)


def _hit(category, call, frame, process):
    thread = frame.GetThread()
    caller = thread.GetFrameAtIndex(1)
    details = {"phase": "entry", "pid": process.GetProcessID(), "tid": thread.GetThreadID(),
               "symbol": frame.GetFunctionName() or "",
               "argument_registers": {"x{}".format(i): hex(_reg(frame, "x{}".format(i))) for i in range(8)}}
    if caller and caller.IsValid():
        details.update(caller=hex(caller.GetPC()),
                       caller_module=caller.GetModule().GetFileSpec().GetFilename() or "")
    else:
        details['caller_unavailable'] = True
        details['link_register'] = hex(_reg(frame, 'lr'))
    return TraceHit(category, call, details)


def _read_cstr(process: lldb.SBProcess, addr: int, cap: int = 4096) -> str:
    if addr == 0:
        return "NULL"
    err = lldb.SBError()
    s = process.ReadCStringFromMemory(addr, cap, err)
    if not err.Success():
        return "<unreadable>"
    if s and len(s.encode('utf-8', 'replace')) >= cap - 1:
        return s + '… [capture limit]'
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


def _read_mem(process: lldb.SBProcess, addr: int, n: int, cap: int) -> bytes:
    if not addr or n <= 0:
        return b""
    err = lldb.SBError()
    data = process.ReadMemory(addr, min(n, cap), err)
    return data if err.Success() else b""


def _fmt_text(b: bytes, limit: int = 256) -> str:
    if not b:
        return '""'
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return '"{}{}"'.format(s[:limit], "…" if len(b) > limit else "")


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


def _f_tls_read(frame, p):
    return '{}(context={:#x}, buf={:#x}, capacity={})'.format(
        frame.GetFunctionName() or 'TLS read', _reg(frame,'x0'), _reg(frame,'x1'), _reg(frame,'x2'))


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


def _f_gethostbyname(frame, p):
    return 'gethostbyname("{}")'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_accept(frame, p):
    return "accept(fd={})".format(_reg(frame, "x0"))


def _f_listen(frame, p):
    return "listen(fd={}, backlog={})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_shutdown(frame, p):
    return "shutdown(fd={}, how={})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_setsockopt(frame, p):
    return "setsockopt(fd={}, level={}, name={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"))


def _f_recvfrom(frame, p):
    return "recvfrom(fd={}, buf={:#x}, n={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"))


def _f_stat(frame, p):
    return 'stat("{}")'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_fstat(frame, p):
    return "fstat(fd={}, buf={:#x})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_access(frame, p):
    return 'access("{}", mode={:#x})'.format(
        _read_cstr(p, _reg(frame, "x0")), _reg(frame, "x1"))


def _f_unlink(frame, p):
    return 'unlink("{}")'.format(_read_cstr(p, _reg(frame, "x0")))


def _f_rename(frame, p):
    return 'rename("{}", "{}")'.format(
        _read_cstr(p, _reg(frame, "x0")),
        _read_cstr(p, _reg(frame, "x1")))


def _f_chmod(frame, p):
    return 'chmod("{}", {:#o})'.format(
        _read_cstr(p, _reg(frame, "x0")), _reg(frame, "x1"))


def _f_mkdir(frame, p):
    return 'mkdir("{}", {:#o})'.format(
        _read_cstr(p, _reg(frame, "x0")), _reg(frame, "x1"))


def _f_pread(frame, p):
    return "pread(fd={}, buf={:#x}, n={}, off={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"), _reg(frame, "x3"))


def _f_pwrite(frame, p):
    fd = _reg(frame, "x0")
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    off = _reg(frame, "x3")
    return "pwrite({}, {}, n={}, off={})".format(fd, _fmt_bytes(_read_bytes(p, buf, n)), n, off)


def _f_dup(frame, p):
    return "dup(fd={})".format(_reg(frame, "x0"))


def _f_dup2(frame, p):
    return "dup2(from={}, to={})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_mmap(frame, p):
    return "mmap(addr={:#x}, len={}, prot={:#x}, flags={:#x}, fd={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"),
        _reg(frame, "x2"), _reg(frame, "x3"), _reg(frame, "x4"))


def _f_dlopen(frame, p):
    return 'dlopen("{}", flags={:#x})'.format(
        _read_cstr(p, _reg(frame, "x0")), _reg(frame, "x1"))


def _f_dlsym(frame, p):
    return 'dlsym(handle={:#x}, "{}")'.format(
        _reg(frame, "x0"), _read_cstr(p, _reg(frame, "x1")))


def _f_posix_spawn(frame, p):
    return 'posix_spawn("{}", …)'.format(_read_cstr(p, _reg(frame, "x1")))


def _f_fork(frame, p):
    return "fork()"


def _f_kill(frame, p):
    return "kill(pid={}, sig={})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_fread(frame, p):
    return "fread(buf={:#x}, size={}, n={}, fp={:#x})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"), _reg(frame, "x3"))


def _f_fwrite(frame, p):
    buf = _reg(frame, "x0")
    size = _reg(frame, "x1")
    n = _reg(frame, "x2")
    total = size * n if size and n and size * n < 4096 else 0
    return "fwrite({}, size={}, n={}, fp={:#x})".format(
        _fmt_bytes(_read_bytes(p, buf, total)) if total else "{:#x}".format(buf),
        size, n, _reg(frame, "x3"))


def _f_fclose(frame, p):
    return "fclose(fp={:#x})".format(_reg(frame, "x0"))


def _f_pclose(frame, p):
    return "pclose(fp={:#x})".format(_reg(frame, "x0"))



def _f_connectx(frame, p):
    fd = _reg(frame, "x0")
    eps = _reg(frame, "x1")
    dst = "?"
    if eps:
        raw = _read_bytes(p, eps + 24, 8)
        if len(raw) == 8:
            dst = _fmt_sockaddr(p, int.from_bytes(raw, "little"))
    return "connectx({}, {})".format(fd, dst)


def _f_recvmsg(frame, p):
    return "recvmsg(fd={}, msg={:#x})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_sendmsg(frame, p):
    return "sendmsg(fd={}, msg={:#x})".format(_reg(frame, "x0"), _reg(frame, "x1"))


def _f_writev(frame, p):
    return "writev(fd={}, iov={:#x}, count={})".format(
        _reg(frame, "x0"), _reg(frame, "x1"), _reg(frame, "x2"))


def _looks_like_port(s: str) -> bool:
    return bool(s) and len(s) <= 5 and s.isdigit()


def _f_nw_endpoint_create_host(frame, p):
    host = _read_cstr(p, _reg(frame, "x0"))
    port = _read_cstr(p, _reg(frame, "x1"))
    if _looks_like_port(port):
        return 'nw_endpoint_create_host("{}", "{}")'.format(host, port)
    return 'nw_endpoint_create_host("{}")'.format(host)


def _f_nw_connection_start(frame, p):
    return "nw_connection_start()"


def _f_nw_connection_send(frame, p):
    return "nw_connection_send()"


def _f_nw_connection_receive(frame, p):
    return "nw_connection_receive()"


def _f_task_resume(frame, p):
    # Structured inspection happens once in NetworkCapture.observe.
    return frame.GetFunctionName() or "NSURLSession request"


def _f_cfurl_bytes(frame, p):
    ptr = _reg(frame, "x1")
    n = _reg(frame, "x2")
    if not ptr or n <= 0 or n > 8192:
        return "CFURLCreateWithBytes()"
    err = lldb.SBError()
    data = p.ReadMemory(ptr, min(n, 512), err)
    if not err.Success() or not data:
        return "CFURLCreateWithBytes()"
    url = data.decode("utf-8", "replace")
    return 'URL "{}"'.format(url[:200])


def _f_tls_write(frame, p):
    # Plaintext side of TLS, before encryption; buffer x1, length x2.
    name = (frame.GetFunctionName() or "SSL_write").lstrip("_")
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    data = _read_mem(p, buf, n, 1024)
    return "{}({} B) {}".format(name, n, _fmt_text(data))


def _f_tls_close(frame, p):
    return "{}({:#x})".format(frame.GetFunctionName(), _reg(frame, "x0"))


def _f_aead_seal(frame, p):
    # BoringSSL/aws-lc AEAD seal (rustls path when there's no SSL_write).
    # Plaintext is the in/in_len args: x6, x7.
    name = (frame.GetFunctionName() or "EVP_AEAD_CTX_seal").lstrip("_")
    buf = _reg(frame, "x6")
    n = _reg(frame, "x7")
    data = _read_mem(p, buf, n, 1024)
    return "{}({} B) {}".format(name, n, _fmt_text(data))


def _f_rustls_write(frame, p):
    # rustls Writer::write, plaintext &[u8] in x1/x2. Matched by regex since the
    # symbol has a per-build hash; gone entirely if the binary is stripped.
    if '::write_vectored' in (frame.GetFunctionName() or ''):
        return 'rustls Writer::write_vectored(iov={:#x}, count={})'.format(
            _reg(frame, 'x1'), _reg(frame, 'x2'))
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    data = _read_mem(p, buf, n, 1024)
    return "rustls Writer::write({} B) {}".format(n, _fmt_text(data))


# Symbol patterns for Rust methods and Foundation request/task selectors.
REGEX_SIGS: List[Tuple[str, str, Callable]] = [
    (RUSTLS_WRITE_PATTERN, NET, _f_rustls_write),
    (FOUNDATION_PATTERN, NET, _f_task_resume),
    (RESUME_PATTERN, NET, _f_task_resume),
]


SIGS: Dict[str, Tuple[str, Callable]] = {
    'SSL_read': (NET, _f_tls_read),
    'SSL_read_ex': (NET, _f_tls_read),
    'SSLRead': (NET, _f_tls_read),
    **{name: (NET, _f_tls_close) for name in TLS_CLOSES},
    "open":               (FILE, _f_open),
    "open$NOCANCEL":      (FILE, _f_open),
    "openat":             (FILE, _f_openat),
    "close":              (FILE, _f_close),
    "close$NOCANCEL":     (FILE, _f_close),
    "read":               (FILE, _f_read),
    "read$NOCANCEL":      (FILE, _f_read),
    "write":              (FILE, _f_write),
    "write$NOCANCEL":     (FILE, _f_write),
    "writev":             (FILE, _f_writev),
    "writev$NOCANCEL":    (FILE, _f_writev),
    "pread":              (FILE, _f_pread),
    "pwrite":             (FILE, _f_pwrite),
    "fopen":              (FILE, _f_fopen),
    "fread":              (FILE, _f_fread),
    "fwrite":             (FILE, _f_fwrite),
    "fclose":             (FILE, _f_fclose),
    "stat":               (FILE, _f_stat),
    "stat$INODE64":       (FILE, _f_stat),
    "lstat":              (FILE, _f_stat),
    "lstat$INODE64":      (FILE, _f_stat),
    "fstat":              (FILE, _f_fstat),
    "fstat$INODE64":      (FILE, _f_fstat),
    "access":             (FILE, _f_access),
    "unlink":             (FILE, _f_unlink),
    "rename":             (FILE, _f_rename),
    "chmod":              (FILE, _f_chmod),
    "mkdir":              (FILE, _f_mkdir),
    "rmdir":              (FILE, _f_unlink),
    "dup":                (FILE, _f_dup),
    "dup2":               (FILE, _f_dup2),
    "mmap":               (FILE, _f_mmap),
    "popen":              (PROC, _f_popen),
    "pclose":             (PROC, _f_pclose),
    "system":             (PROC, _f_system),
    "execve":             (PROC, _f_execve),
    "execvp":             (PROC, _f_execve),
    "posix_spawn":        (PROC, _f_posix_spawn),
    "posix_spawnp":       (PROC, _f_posix_spawn),
    "fork":               (PROC, _f_fork),
    "vfork":              (PROC, _f_fork),
    "kill":               (PROC, _f_kill),
    "dlopen":             (PROC, _f_dlopen),
    "dlsym":              (PROC, _f_dlsym),
    "socket":             (NET,  _f_socket),
    "connect":            (NET,  _f_connect),
    "connect$NOCANCEL":   (NET,  _f_connect),
    "bind":               (NET,  _f_bind),
    "listen":             (NET,  _f_listen),
    "accept":             (NET,  _f_accept),
    "accept$NOCANCEL":    (NET,  _f_accept),
    "send":               (NET,  _f_send),
    "send$NOCANCEL":      (NET,  _f_send),
    "recv":               (NET,  _f_recv),
    "recv$NOCANCEL":      (NET,  _f_recv),
    "sendto":             (NET,  _f_sendto),
    "sendto$NOCANCEL":    (NET,  _f_sendto),
    "recvfrom":           (NET,  _f_recvfrom),
    "recvfrom$NOCANCEL":  (NET,  _f_recvfrom),
    "connectx":           (NET,  _f_connectx),
    "recvmsg":            (NET,  _f_recvmsg),
    "recvmsg$NOCANCEL":   (NET,  _f_recvmsg),
    "sendmsg":            (NET,  _f_sendmsg),
    "sendmsg$NOCANCEL":   (NET,  _f_sendmsg),
    "nw_endpoint_create_host": (NET, _f_nw_endpoint_create_host),
    "nw_connection_start":     (NET, _f_nw_connection_start),
    "nw_connection_send":      (NET, _f_nw_connection_send),
    "nw_connection_receive":   (NET, _f_nw_connection_receive),
    "CFURLCreateWithBytes":    (NET, _f_cfurl_bytes),
    "SSL_write":          (NET,  _f_tls_write),
    "SSL_write_ex":       (NET,  _f_tls_write),
    "SSLWrite":           (NET,  _f_tls_write),
    "BoringSSL_SSL_write": (NET, _f_tls_write),
    "mbedtls_ssl_write":  (NET,  _f_tls_write),
    "wolfSSL_write":      (NET,  _f_tls_write),
    "gnutls_record_send": (NET,  _f_tls_write),
    "tls_write":          (NET,  _f_tls_write),
    "crypto/tls.(*Conn).Write": (NET, _f_tls_write),
    "EVP_AEAD_CTX_seal":  (NET,  _f_aead_seal),
    "shutdown":           (NET,  _f_shutdown),
    "setsockopt":         (NET,  _f_setsockopt),
    "getaddrinfo":        (NET,  _f_getaddrinfo),
    "gethostbyname":      (NET,  _f_gethostbyname),
    "gethostbyname2":     (NET,  _f_gethostbyname),
}


class Tracer:
    PRESETS = {'file': ['open', 'read', 'write'],
               'network': ['connect', 'send', 'recv'],
               'tls': ['SSL_read', 'SSL_write'],
               'process': ['system', 'execve', 'posix_spawn']}
    RETURN_APIS = {'open', 'openat', 'close', 'read', 'pread', 'write', 'pwrite',
                  'connect', 'send', 'recv', 'sendto', 'recvfrom', 'socket',
                  'SSL_read', 'SSL_read_ex', 'SSLRead', 'SSL_write', 'SSL_write_ex'}

    def __init__(self) -> None:
        self._bp_ids: List[int] = []
        self._hardware_bp_ids: set[int] = set()
        self._bp_to_name: Dict[int, str] = {}
        self._regex_bps: Dict[int, Tuple[str, Callable]] = {}
        self.enabled = False
        self._exec_name: str = ""
        self.caller_depth: int = 5
        self.hardware: bool = False
        self.skip_fd: int = -1
        self.network = NetworkCapture()
        self.debugger = None
        self.hooks = None
        self.capture_returns = False
        self.returns = None

    def configure(self, *, hooks=None, preset=None, hardware=False, returns=False):
        if self.enabled:
            raise ValueError('disable tracing before changing capture settings')
        if preset is not None:
            if preset not in self.PRESETS and preset != 'all':
                raise ValueError('unknown trace preset')
            hooks = self.PRESETS.get(preset)
        if hooks is not None:
            if not isinstance(hooks, list) or not hooks or any(h not in SIGS for h in hooks):
                raise ValueError('select one or more known API names')
            hooks = list(dict.fromkeys(hooks))
        self.hooks = hooks
        self.hardware = bool(hardware)
        self.capture_returns = bool(returns)

    def configuration(self):
        from .breakpoints import hardware_breakpoint_capacity, hardware_usage
        try:
            budget = {'capacity': hardware_breakpoint_capacity(),
                      'used': hardware_usage(self.debugger.target) if self.debugger else 0,
                      'reserved': 2}
        except RuntimeError as error:
            budget = {'error': str(error)}
        return {'hooks': self.hooks, 'hardware': self.hardware, 'returns': self.capture_returns,
                'presets': self.PRESETS, 'available': sorted(SIGS), 'hardware_budget': budget,
                'active_hooks': [{'name': name, 'locations': self.debugger.target.FindBreakpointByID(bid).GetNumLocations()}
                                 for bid, name in self._bp_to_name.items()] if self.debugger else [],
                'coverage': 'API-entry observations, not proof of successful I/O. Missing caller stacks are retained. '
                            'Go crypto/tls and Rust rustls plaintext require resolvable writer symbols; stripped or inlined '
                            'functions may be unavailable. HTTP/2 is not decoded. Incoming buffers require return capture; '
                            'Go/Rust TLS decrypted reads are not supported. Hardware return sites are finite.'}

    @property
    def hardware_bp_ids(self) -> set[int]:
        return set(self._hardware_bp_ids) | (self.returns.ids() if self.returns else set())

    def _create_breakpoint(self, target, ci, name, regex=False):
        # Reading argument registers after a prologue is not reliable. Use the
        # command API for payload hooks because the SB name/regex overloads do
        # not expose skip-prologue on the supported LLDB Python bindings.
        entry = True
        if not self.hardware:
            if ci is not None:
                import shlex
                before = {bp.GetID() for bp in target.breakpoint_iter()}
                result = lldb.SBCommandReturnObject()
                ci.HandleCommand("breakpoint set --skip-prologue false {} {}".format(
                    "-r" if regex else "-F", shlex.quote(name)), result, False)
                created = [bp for bp in target.breakpoint_iter() if bp.GetID() not in before]
                if not result.Succeeded() or len(created) != 1:
                    for bp in created:
                        target.BreakpointDelete(bp.GetID())
                    self.disable(target)
                    raise RuntimeError("cannot arm network trace hook " + name)
                return created[0]
            return (target.BreakpointCreateByRegex(name) if regex
                    else target.BreakpointCreateByName(name))
        from .breakpoints import create_hardware_breakpoint
        import shlex
        try:
            bp = create_hardware_breakpoint(
                target, ci, ("-r " if regex else "-F ") + shlex.quote(name)
                + (" --skip-prologue false" if entry else ""),
                require_location=False, reserve=2)
        except RuntimeError:
            self.disable(target)
            raise
        self._hardware_bp_ids.add(bp.GetID())
        return bp

    def enable(self, target: lldb.SBTarget, ci: Optional[lldb.SBCommandInterpreter] = None) -> Tuple[int, int]:
        if self.enabled or not target or not target.IsValid():
            return (0, 0)
        self._exec_name = target.GetExecutable().GetFilename() or ""
        if self.hardware and self.hooks is None:
            self.hooks = list(self.PRESETS['file'])
        if self.capture_returns and self.debugger is None:
            raise RuntimeError('return capture requires a debugger session')
        if self.debugger and self.returns is None:
            self.returns = ReturnHooks(self.debugger)
        resolved_now = 0
        for name in (self.hooks if self.hooks is not None else SIGS):
            bp = self._create_breakpoint(target, ci, name)
            if not bp.IsValid():
                continue
            self._bp_ids.append(bp.GetID())
            self._bp_to_name[bp.GetID()] = name
            if bp.GetNumLocations() > 0:
                resolved_now += 1
        for pattern, cat, fmt in (REGEX_SIGS if self.hooks is None else []):
            rbp = self._create_breakpoint(target, ci, pattern, regex=True)
            if not rbp.IsValid():
                continue
            self._bp_ids.append(rbp.GetID())
            self._bp_to_name[rbp.GetID()] = pattern
            self._regex_bps[rbp.GetID()] = (cat, fmt)
            if rbp.GetNumLocations() > 0:
                resolved_now += 1
        self.enabled = True
        return (len(self._bp_ids), resolved_now)

    def disable(self, target: lldb.SBTarget) -> None:
        if self.returns:
            self.returns.clear()
        self.network.reset()
        self._hardware_bp_ids.clear()
        if not target or not target.IsValid():
            self._bp_ids.clear()
            self._bp_to_name.clear()
            self._regex_bps.clear()
            self.enabled = False
            return
        for bp_id in self._bp_ids:
            target.BreakpointDelete(bp_id)
        self._bp_ids.clear()
        self._bp_to_name.clear()
        self._regex_bps.clear()
        self.enabled = False

    def is_trace_bp(self, bp_id: int) -> bool:
        return bp_id in self._bp_to_name or bool(self.returns and bp_id in self.returns.ids())

    def hidden_ids(self):
        return set(self._bp_to_name) | ((self.returns.ids() | self.returns.retired) if self.returns else set())

    def return_hits(self, thread, process):
        if not self.returns:
            return []
        hits = []
        for observation in self.returns.consume(thread):
            entry = observation['payload']
            name, args = entry['name'], entry['args']
            raw = _reg(thread.GetFrameAtIndex(0), 'x0')
            width = 64 if name in {'read','pread','write','pwrite','recv','send','recvfrom','sendto'} else 32
            value = raw & ((1 << width) - 1)
            if value & (1 << (width - 1)):
                value -= 1 << width
            details = {**entry['details'], 'phase':'return', 'invocation':observation['invocation'],
                       'return_value':value, 'return_register':hex(raw)}
            if value == -1 and not name.startswith('SSL'):
                details['errno'] = self.debugger.analysis_cloak._read_errno(thread, lldb)
            size = max(0, value)
            if name in {'SSL_read_ex','SSLRead'}:
                success = value == (1 if name == 'SSL_read_ex' else 0)
                data = self.debugger.read_memory(args[3], 8) if success else b''
                size = int.from_bytes(data, 'little') if len(data) == 8 else 0
            if name in {'read','pread','recv','recvfrom','SSL_read','SSL_read_ex','SSLRead'} and size:
                length = min(size, args[2], CAPTURE_LIMIT)
                data = self.debugger.read_memory(args[1], length)
                details['payload'] = body_record(data, size, '', status='unreadable' if len(data) < length else None)
                details['capture_source'] = name + ' return'
            hits.append(TraceHit(entry['category'], '{} → {}'.format(name, value), details))
        return hits

    def flush_network(self, process=None):
        requests = self.network.http.flush()
        if not requests:
            return []
        details = {"phase": "capture-end", "http_requests": requests}
        if process and process.IsValid():
            details["pid"] = process.GetProcessID()
        return [TraceHit(NET, "Incomplete HTTP requests at end of capture", details)]

    def hit_from(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,
        user_only: bool = True,
        bp_id: Optional[int] = None,
    ) -> Optional[TraceHit]:
        if not frame or not frame.IsValid():
            return None
        if self.skip_fd >= 0:
            fname = (frame.GetFunctionName() or "").lstrip("_")
            if fname.split("$", 1)[0] in _FD_CALLS and _reg(frame, "x0") == self.skip_fd:
                return None
        if bp_id is not None and bp_id in self._regex_bps:
            cat, fmt = self._regex_bps[bp_id]
            return self._format_hit(cat, fmt, frame, process, user_only)
        name = frame.GetFunctionName() or ""
        for candidate in (name, name.lstrip("_")):
            if candidate in SIGS:
                cat, fmt = SIGS[candidate]
                return self._format_hit(cat, fmt, frame, process, user_only)
        return None

    def _format_hit(self, category, formatter, frame, process, user_only):
        name = frame.GetFunctionName() or ""
        try:
            details = self.network.observe(frame, process, name)
        except Exception as error:
            details = {"capture_source": name, "capture_error": str(error)}
        if details.get("payload") or details.get("http_requests") or details.get('capture_stream'):
            category = NET
        if user_only and category != NET and self._caller_is_noise(frame):
            return None
        try:
            call = formatter(frame, process)
        except Exception as error:
            call = "{}(...) [formatter error: {}]".format(name, error)
        if call is None:
            return None
        requests = details.get("http_requests", [])
        if requests:
            request = requests[-1]
            call = "{} {} [{}; body {} B, {}]".format(
                request.get("method", "HTTP"), request.get("url", "")[:200],
                name, request["body"]["captured_bytes"], request["body"]["status"])
        hit = _hit(category, call, frame, process)
        hit.details.update(details)
        api = name.lstrip('_').split('$', 1)[0]
        if self.capture_returns and api in self.RETURN_APIS:
            try:
                # Link the return by invocation, without exporting the same
                # outbound request/body twice as if two requests were made.
                returned = {key: value for key, value in hit.details.items()
                            if key not in ('payload', 'http_requests', 'capture_source', 'assembly_skipped')}
                returned['entry_call'] = call
                hit.details['invocation'] = self.returns.arm(frame, {
                    'name': api, 'args': [_reg(frame, 'x'+str(i)) for i in range(8)],
                    'category':category, 'details':returned})
                hit.details['return_status'] = 'pending'
            except RuntimeError as error:
                hit.details['return_status'] = 'unavailable'
                hit.details['return_error'] = str(error)
        return hit

    def _caller_is_noise(self, frame: lldb.SBFrame) -> bool:
        if not self._exec_name or self.caller_depth <= 0:
            return False
        thread = frame.GetThread()
        limit = min(1 + self.caller_depth, thread.GetNumFrames())
        # Go's libc trampolines can leave LLDB with only frame zero. An
        # unavailable caller is not evidence of a system-only call chain.
        if limit <= 1:
            return False
        for i in range(1, limit):
            f = thread.GetFrameAtIndex(i)
            if not f.IsValid():
                return False
            module = f.GetModule()
            if not module.IsValid():
                return False
            modname = module.GetFileSpec().GetFilename() or ""
            if modname == self._exec_name:
                return False
        return True
