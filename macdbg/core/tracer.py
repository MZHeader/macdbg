from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import lldb


FILE = "FILE"
NET = "NET"
PROC = "PROC"

# Calls whose first arg is a file descriptor, used to skip hits on the interpose
# trace fd so its writes aren't double-traced.
_FD_CALLS = {"read", "write", "pread", "pwrite", "close",
             "send", "recv", "sendto", "recvfrom"}


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


def _eval_str(frame, expr: str) -> Optional[str]:
    try:
        v = frame.EvaluateExpression(expr)
    except Exception:
        return None
    if not v or not v.IsValid() or not v.GetError().Success():
        return None
    s = v.GetObjectDescription()
    if not s or s in ("<nil>", "nil", "<null>", "(null)"):
        return None
    return s


def _f_task_resume(frame, p):
    # resume fires once per request, so it catches the default GET too. Read the
    # method and URL off the request via the runtime; None on eval failure.
    task = _reg(frame, "x0")
    if not task:
        return None
    method = _eval_str(frame, "(id)[(id)[(id)%d currentRequest] HTTPMethod]" % task)
    if not method:
        return None
    url = _eval_str(frame, "(id)[[(id)[(id)%d currentRequest] URL] absoluteString]" % task)
    return "{} {}".format(method, url[:200]) if url else 'HTTP method "{}"'.format(method)


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
    buf = _reg(frame, "x1")
    n = _reg(frame, "x2")
    data = _read_mem(p, buf, n, 1024)
    return "rustls Writer::write({} B) {}".format(n, _fmt_text(data))


# (pattern, category, formatter) for symbols with per-build hashes. The
# "rustls..conn" prefix only exists in statically linked rustls so nothing else
# collides; "::write::h" matches write, not flush/write_all/write_vectored.
REGEX_SIGS: List[Tuple[str, str, Callable]] = [
    (r"rustls..conn.*Writer.*::write::h", NET, _f_rustls_write),
]


SIGS: Dict[str, Tuple[str, Callable]] = {
    "open":               (FILE, _f_open),
    "open$NOCANCEL":      (FILE, _f_open),
    "openat":             (FILE, _f_openat),
    "close":              (FILE, _f_close),
    "close$NOCANCEL":     (FILE, _f_close),
    "read":               (FILE, _f_read),
    "read$NOCANCEL":      (FILE, _f_read),
    "write":              (FILE, _f_write),
    "write$NOCANCEL":     (FILE, _f_write),
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
    "fstat":              (FILE, _f_stat),
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
    "-[NSURLSessionTask resume]": (NET, _f_task_resume),
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
    def __init__(self) -> None:
        self._bp_ids: List[int] = []
        self._bp_to_name: Dict[int, str] = {}
        self._regex_bps: Dict[int, Tuple[str, Callable]] = {}
        self.enabled = False
        self._exec_name: str = ""
        self.caller_depth: int = 5
        self.hardware: bool = False
        self.skip_fd: int = -1

    def enable(self, target: lldb.SBTarget, ci: Optional[lldb.SBCommandInterpreter] = None) -> Tuple[int, int]:
        if self.enabled or not target or not target.IsValid():
            return (0, 0)
        self._exec_name = target.GetExecutable().GetFilename() or ""
        resolved_now = 0
        for name in SIGS:
            if self.hardware and ci is not None:
                n_before = target.GetNumBreakpoints()
                ret = lldb.SBCommandReturnObject()
                ci.HandleCommand("breakpoint set -H -n {}".format(name), ret, False)
                if target.GetNumBreakpoints() <= n_before:
                    continue
                bp = target.GetBreakpointAtIndex(n_before)
            else:
                bp = target.BreakpointCreateByName(name)
            if not bp.IsValid():
                continue
            self._bp_ids.append(bp.GetID())
            self._bp_to_name[bp.GetID()] = name
            if bp.GetNumLocations() > 0:
                resolved_now += 1
        for pattern, cat, fmt in REGEX_SIGS:
            rbp = target.BreakpointCreateByRegex(pattern)
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
        return bp_id in self._bp_to_name

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
            if user_only and cat != NET and self._caller_is_noise(frame):
                return None
            try:
                call = fmt(frame, process)
            except Exception as e:
                call = "regex hook [formatter error: {}]".format(e)
            return TraceHit(category=cat, call=call) if call is not None else None
        name = frame.GetFunctionName() or ""
        for candidate in (name, name.lstrip("_")):
            if candidate in SIGS:
                cat, fmt = SIGS[candidate]
                if user_only and cat != NET and self._caller_is_noise(frame):
                    return None
                try:
                    call = fmt(frame, process)
                except Exception as e:
                    call = "{}(...) [formatter error: {}]".format(candidate, e)
                if call is None:
                    return None
                return TraceHit(category=cat, call=call)
        return None

    def _caller_is_noise(self, frame: lldb.SBFrame) -> bool:
        if not self._exec_name or self.caller_depth <= 0:
            return False
        thread = frame.GetThread()
        limit = min(1 + self.caller_depth, thread.GetNumFrames())
        for i in range(1, limit):
            f = thread.GetFrameAtIndex(i)
            if not f.IsValid():
                break
            module = f.GetModule()
            if not module.IsValid():
                continue
            modname = module.GetFileSpec().GetFilename() or ""
            if modname == self._exec_name:
                return False
        return True
