"""Bounded observations of outbound API inputs, before TLS encryption.

These are entry observations, not evidence of successful delivery. Foundation
getters are evaluated with a timeout; request streams are never consumed.
"""
from collections import OrderedDict
import json
import struct

import lldb

from .http_capture import CAPTURE_LIMIT, HEADER_LIMIT, HTTPRequestCapture, body_record


TLS_WRITES = {
    "SSL_write", "SSL_write_ex", "SSLWrite", "BoringSSL_SSL_write",
    "mbedtls_ssl_write", "wolfSSL_write", "gnutls_record_send", "tls_write",
    "crypto/tls.(*Conn).Write",
}
TLS_CLOSES = {"SSL_free": ("SSL_write", "SSL_write_ex"),
              "SSLDisposeContext": ("SSLWrite",),
              "BoringSSL_SSL_free": ("BoringSSL_SSL_write",),
              "mbedtls_ssl_free": ("mbedtls_ssl_write",),
              "wolfSSL_free": ("wolfSSL_write",),
              "gnutls_deinit": ("gnutls_record_send",), "tls_free": ("tls_write",),
              "EVP_AEAD_CTX_cleanup": ("EVP_AEAD_CTX_seal",)}
FOUNDATION_PATTERN = (r"-\[.* (dataTaskWithRequest:|dataTaskWithRequest:completionHandler:|"
                      r"uploadTaskWithRequest:fromData:|uploadTaskWithRequest:fromData:completionHandler:|"
                      r"uploadTaskWithRequest:fromFile:|uploadTaskWithRequest:fromFile:completionHandler:|"
                      r"uploadTaskWithStreamedRequest:)\]")
RESUME_PATTERN = r"-\[(NSURLSessionTask|__NSCF[^ ]*Task) resume\]"


def _reg(frame, name):
    value = frame.FindRegister(name)
    return value.GetValueAsUnsigned() if value.IsValid() else 0


def _read(process, address, length, cap=CAPTURE_LIMIT):
    if not address or length <= 0:
        return b""
    error = lldb.SBError()
    # Preserve any readable prefix even when LLDB reports a partial read.
    return process.ReadMemory(address, min(length, cap), error) or b""


def _evaluate(frame, expression):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC_plus_plus)
    options.SetIgnoreBreakpoints(True)
    options.SetUnwindOnError(True)
    options.SetTryAllThreads(False)
    options.SetTimeoutInMicroSeconds(500000)
    value = frame.EvaluateExpression(expression, options)
    if not value or not value.IsValid() or not value.GetError().Success():
        raise ValueError("request getter unavailable")
    return value


def _integer(frame, expression):
    return _evaluate(frame, expression).GetValueAsUnsigned()


def _string(frame, expression):
    # NSString bytes are bounded before being transferred out of the inferior.
    obj = _integer(frame, "(unsigned long)(id)(%s)" % expression)
    if not obj:
        return None
    size = _integer(frame, "(unsigned long)[(id)%d lengthOfBytesUsingEncoding:4]" % obj)
    ptr = _integer(frame, "(unsigned long)[(id)%d UTF8String]" % obj)
    data = _read(frame.GetThread().GetProcess(), ptr, size, HEADER_LIMIT)
    if len(data) != size:
        raise ValueError("request string exceeds limit or is unreadable")
    return data.decode("utf-8")


def _data(frame, process, obj, content_type=""):
    if not obj:
        return body_record(b"", 0, content_type)
    length = _integer(frame, "(unsigned long)[(id)%d length]" % obj)
    ptr = _integer(frame, "(unsigned long)[(id)%d bytes]" % obj) if length else 0
    data = _read(process, ptr, length)
    status = "unreadable" if len(data) < min(length, CAPTURE_LIMIT) else None
    return body_record(data, length, content_type, status=status)


def _request(frame, process, name):
    resume = name.endswith(" resume]")
    obj = (_integer(frame, "(unsigned long)[(id)%d currentRequest]" % _reg(frame, "x0"))
           if resume else _reg(frame, "x2"))
    if not obj:
        return None
    request = {"source": "foundation", "stage": "resume" if resume else "creation",
               "request_object": hex(obj), "headers": [], "warnings": [], "complete": False}
    if resume:
        request["task_object"] = hex(_reg(frame, "x0"))
    for key, expr in (("method", "(id)[(id)%d HTTPMethod]" % obj),
                      ("url", "(id)[(id)[(id)%d URL] absoluteString]" % obj)):
        try:
            request[key] = _string(frame, expr) or ""
        except (ValueError, UnicodeError):
            request[key] = ""
            request["warnings"].append(key + " unavailable")
    headers_ok = False
    try:
        # Serialize the dictionary inside the inferior, then copy bounded NSData
        # bytes. No object descriptions (which can truncate/escape content).
        headers = _integer(frame, "(unsigned long)[(id)%d allHTTPHeaderFields]" % obj)
        if headers:
            encoded = _integer(frame, '(unsigned long)[(id)objc_getClass("NSJSONSerialization") '
                               'dataWithJSONObject:(id)%d options:0 error:0]' % headers)
            if not encoded:
                raise ValueError("headers unavailable")
            length = _integer(frame, "(unsigned long)[(id)%d length]" % encoded)
            if length > HEADER_LIMIT:
                raise ValueError("headers exceed 64 KiB capture limit")
            ptr = _integer(frame, "(unsigned long)[(id)%d bytes]" % encoded)
            values = json.loads(_read(process, ptr, length, HEADER_LIMIT))
            request["headers"] = [{"name": k, "value": v} for k, v in values.items()]
        headers_ok = True
    except (ValueError, UnicodeError, AttributeError):
        request["warnings"].append("request headers unavailable or exceed 64 KiB")
    content_type = next((h["value"] for h in request["headers"]
                         if h["name"].lower() == "content-type"), "")
    content_encoding = next((h["value"] for h in request["headers"]
                             if h["name"].lower() == "content-encoding"), "")
    if content_encoding and content_encoding.lower().strip() != "identity":
        content_type = ""  # Preserve encoded bytes without guessing form/JSON values.
        request["warnings"].append("Content-Encoding body retained without decompression")
    try:
        if "fromData:" in name:
            request["body"] = _data(frame, process, _reg(frame, "x3"), content_type)
            request["body_source"] = "upload data argument"
        elif "fromFile:" in name:
            request["body"] = body_record(b"", status="unavailable")
            request["body_source"] = "upload file"
            request["warnings"].append("file upload body is not read at this hook")
        elif "uploadTaskWithStreamedRequest:" in name:
            request["body"] = body_record(b"", status="unavailable")
            request["body_source"] = "upload stream"
            request["warnings"].append("request body stream is not consumed")
        else:
            data = _integer(frame, "(unsigned long)[(id)%d HTTPBody]" % obj)
            stream = 0 if data else _integer(frame, "(unsigned long)[(id)%d HTTPBodyStream]" % obj)
            request["body"] = (_data(frame, process, data, content_type) if data
                               else body_record(b"", status="unavailable") if stream or resume
                               else body_record(b"", 0, content_type))
            request["body_source"] = "HTTPBody" if data else "HTTPBodyStream" if stream else "none"
            if stream:
                request["warnings"].append("request body stream is not consumed")
            elif resume and not data:
                request["warnings"].append("task request has no retained body; see creation/write captures")
    except (ValueError, UnicodeError):
        request["body"] = body_record(b"", status="unavailable")
        request["warnings"].append("request body getter unavailable")
    request["warnings"].append("application request headers; transport may add or change headers")
    request["complete"] = (headers_ok and bool(request.get("method")) and bool(request.get("url"))
                           and request["body"]["status"] == "complete")
    return request


class NetworkCapture:
    def __init__(self):
        self.http = HTTPRequestCapture()
        self.sockets = OrderedDict()
        self.send_entries = OrderedDict()
        self.process_id = None

    def reset(self):
        self.http.reset()
        self.sockets.clear()
        self.send_entries.clear()
        self.process_id = None

    def _iov(self, process, address, count):
        if count > 1024:
            raise ValueError("iovec count exceeds capture limit")
        descriptors = _read(process, address, count * 16)
        if len(descriptors) != count * 16:
            raise ValueError("iovec descriptors unavailable")
        chunks, total, captured = [], 0, 0
        gap = False
        for ptr, length in struct.iter_unpack("<QQ", descriptors):
            total += length
            if not gap and captured < CAPTURE_LIMIT:
                piece = _read(process, ptr, length, CAPTURE_LIMIT - captured)
                chunks.append(piece)
                captured += len(piece)
                gap = len(piece) < min(length, CAPTURE_LIMIT - (captured - len(piece)))
        return b"".join(chunks), total

    def observe(self, frame, process, name):
        identity = process.GetUniqueID()
        if identity != self.process_id:
            self.reset()
            self.process_id = identity
        pid = process.GetProcessID()
        function = name.lstrip("_").split("$", 1)[0]
        descriptor = "pid:{}:fd:{}".format(pid, _reg(frame, "x0"))
        if function in ("connect", "connectx"):
            self.http.discard(descriptor)
            self.sockets[descriptor] = True
            self.sockets.move_to_end(descriptor)
            while len(self.sockets) > 256:
                old, _ = self.sockets.popitem(last=False)
                self.http.discard(old)
        if function == "close" or (function == "shutdown" and _reg(frame, "x1") in (1, 2)):
            requests = self.http.flush(descriptor)
            self.sockets.pop(descriptor, None)
            return {"http_requests": requests} if requests else {}
        if function in TLS_CLOSES:
            requests = []
            for writer in TLS_CLOSES[function]:
                key = "pid:{}:{}:{:#x}".format(pid, writer, _reg(frame, "x0"))
                requests.extend(self.http.flush(key))
            return {"http_requests": requests} if requests else {}
        if "TaskWith" in name or name.endswith(" resume]"):
            request = _request(frame, process, name)
            return {"capture_source": name, "http_requests": [request]} if request else {}
        is_tls = function in TLS_WRITES or ("rustls" in function and "Writer" in function)
        is_aead = function == "EVP_AEAD_CTX_seal"
        is_send = function in ("send", "sendto", "sendmsg")
        is_write = function in ("write", "writev") and descriptor in self.sockets
        if not (is_tls or is_aead or is_send or is_write):
            return {}
        if function in ("sendmsg", "writev"):
            address = _reg(frame, "x1")
            if function == "sendmsg":
                header = _read(process, address, 28)
                if len(header) != 28:
                    raise ValueError("sendmsg header unavailable")
                address, count = struct.unpack_from("<QI", header, 16)
            else:
                count = _reg(frame, "x2")
            data, length = self._iov(process, address, count)
        else:
            address, length = (_reg(frame, "x6"), _reg(frame, "x7")) if is_aead else (
                _reg(frame, "x1"), _reg(frame, "x2"))
            # SSL_write and wolfSSL_write take signed int lengths.
            if function in ("SSL_write", "wolfSSL_write", "BoringSSL_SSL_write"):
                length &= 0xffffffff
                if length & 0x80000000:
                    raise ValueError("negative TLS write length")
            data = _read(process, address, length)
        key = ("pid:{}:{}:{:#x}".format(pid, function, _reg(frame, "x0"))
               if is_tls or is_aead else descriptor)
        payload = body_record(data, length, status=("unreadable"
                              if len(data) < min(length, CAPTURE_LIMIT) else None))
        nested = False
        if is_send or is_write:
            # Darwin send() wraps sendto(). Preserve both API observations but
            # do not append the inner buffer to the same socket stream twice.
            caller = frame.GetThread().GetFrameAtIndex(1)
            if caller and caller.IsValid():
                caller_name = (caller.GetFunctionName() or "").lstrip("_").split("$", 1)[0]
                nested = caller_name in ("send", "sendto", "sendmsg", "write", "writev")
            # libsystem_c send tail-calls libsystem_kernel __sendto, so there
            # need not be an outer frame. Match the same argument buffer AND
            # entry stack/return site on the same thread, consuming the marker
            # once. A subsequent send refreshes it even for identical bytes.
            if function in ("send", "sendto"):
                tid = frame.GetThread().GetThreadID()
                entry = (descriptor, address, length, _reg(frame, "sp"), _reg(frame, "lr"))
                previous = self.send_entries.pop(tid, None)
                if function == "send":
                    self.send_entries[tid] = entry
                    while len(self.send_entries) > 64:
                        self.send_entries.popitem(last=False)
                elif entry[3] and entry[4] and previous == entry:
                    nested = True
        details = {"capture_source": name, "capture_stream": key, "payload": payload,
                   "http_requests": [] if nested else self.http.feed(key, data, total_length=length)}
        if nested:
            details["assembly_skipped"] = "nested socket write; outer API input already observed"
        for request in details["http_requests"]:
            request["warnings"].append("assembled API-entry buffers; failed, partial or retried writes are not reconciled")
        return details
