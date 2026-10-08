"""Bounded, passive HTTP request inspection; no networking or decompression.

Raw body bytes are always retained as base64. Structured values are supplemental
and are only decoded from a complete body. This parser covers HTTP/1.x, not TLS
records or HTTP/2. Callers should keep their raw writes as well as these records.
"""
import base64
import codecs
from collections import OrderedDict
from email.message import Message
import json
import math
import re
from urllib.parse import parse_qsl


CAPTURE_LIMIT = 256 * 1024
HEADER_LIMIT = 64 * 1024
MAX_STREAMS = 64
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_REQUEST_LINE = re.compile(rb"([^ ]{1,32}) ([^\x00-\x20\x7f]+) (HTTP/1\.[01])\Z")
_SAFE_CHARSETS = {
    "ascii", "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be",
    "utf-32", "utf-32-le", "utf-32-be", "shift_jis", "euc_jp", "gbk",
    "gb18030", "big5", "euc_kr", "cp932", "cp949", "cp950", "koi8-r", "koi8-u",
} | {"iso8859-{}".format(n) for n in range(1, 17)} | {
    "cp{}".format(n) for n in range(1250, 1259)
}


def _media_type(value):
    message = Message()
    message["content-type"] = value if isinstance(value, str) and value else "application/octet-stream"
    return message


def _charset_name(value):
    # A declared charset is untrusted input. Avoid invoking transformation
    # codecs (including compression) or slow codecs such as punycode.
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        name = codecs.lookup(value).name
    except (LookupError, ValueError):
        return None
    return name if name in _SAFE_CHARSETS else None


def _parameter(message, name, header="content-type"):
    value = message.get_param(name, header=header)
    if not isinstance(value, tuple):
        return value
    charset = _charset_name(value[0] or "ascii")
    if charset is None:
        return None
    try:
        return value[2].encode("latin-1").decode(charset, errors="strict")
    except (UnicodeError, ValueError):
        return None


def _body_charset(content_type):
    media = _media_type(content_type)
    # A missing charset permits UTF-8; a present but invalid/unsupported one
    # does not justify guessing a different character encoding.
    if media.get_param("charset") is None:
        return "utf-8"
    return _charset_name(_parameter(media, "charset"))


def _json_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number")
    return result


def _json_integer(value):
    if len(value) > 1024:
        raise ValueError("JSON integer exceeds inspection limit")
    return int(value)


def _json_constant(value):
    raise ValueError("Invalid JSON constant")


def _check_json_depth(text):
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > 64:
                raise ValueError("JSON depth exceeds inspection limit")
        elif character in "]}":
            depth -= 1


def _record_bytes(data, total_length=None, content_type="", status=None):
    available = len(data)
    captured = bytes(data[:CAPTURE_LIMIT])
    total = available if total_length is None else max(available, int(total_length))
    truncated = total > len(captured) or status == "truncated"
    record = {
        "encoding": "base64", "data": base64.b64encode(captured).decode("ascii"),
        "captured_bytes": len(captured), "total_bytes": total,
        "truncated": truncated,
        "status": status or ("truncated" if truncated else "complete"),
    }
    if truncated and record["status"] == "complete":
        record["status"] = "truncated"
    # Unavailable data and a successfully captured empty body are different.
    if status == "unavailable" and total_length is None:
        record["total_bytes"] = None
    if record["status"] != "unavailable":
        charset = _body_charset(content_type)
        if charset is not None:
            try:
                record["text"] = captured.decode(charset, errors="strict")
            except (UnicodeError, LookupError, ValueError):
                pass
    return record


def body_record(data, total_length=None, content_type="", status=None):
    """Represent bounded captured bytes without loss or guessed replacement text.

    ``total_length`` is the original byte length when only a prefix was read.
    An explicit status (for example ``incomplete`` or ``unavailable``) prevents
    the prefix from being interpreted as a complete form or JSON document.
    """
    record = _record_bytes(data, total_length, content_type, status)
    if record["status"] != "complete" or record["truncated"]:
        return record
    media = _media_type(content_type).get_content_type()
    text = record.get("text")
    if media == "application/x-www-form-urlencoded" and text is not None:
        try:
            charset = _body_charset(content_type)
            record["fields"] = [
                {"name": name, "value": value}
                for name, value in parse_qsl(text, keep_blank_values=True,
                                             encoding=charset, errors="strict",
                                             max_num_fields=4096)
            ]
        except (ValueError, UnicodeError, LookupError):
            pass
    elif (media == "application/json" or media.endswith("+json")) and text is not None:
        try:
            _check_json_depth(text)
            record["json"] = json.loads(text, parse_float=_json_float,
                                        parse_int=_json_integer, parse_constant=_json_constant)
        except (ValueError, RecursionError):
            pass
    elif media == "multipart/form-data":
        parts = _multipart_parts(bytes(data), content_type)
        if parts is not None:
            record["parts"] = parts
    return record


def _headers(data):
    headers = []
    for line in data.split(b"\r\n") if data else []:
        if b":" not in line:
            raise ValueError("Malformed header line")
        name, value = line.split(b":", 1)
        if not _TOKEN.fullmatch(name) or any(c == 127 or (c < 32 and c != 9) for c in value):
            raise ValueError("Malformed header name or value")
        headers.append({"name": name.decode("ascii"),
                        "value": value.decode("latin-1").strip(" \t")})
    return headers


def _multipart_parts(data, content_type):
    boundary = _parameter(_media_type(content_type), "boundary")
    if not boundary or len(boundary) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in boundary):
        return None
    try:
        marker = b"--" + boundary.encode("ascii")
    except UnicodeError:
        return None
    # Delimiters must occupy an entire line; a boundary appearing in file bytes
    # is not itself a delimiter. Refuse incomplete/malformed multipart bodies.
    delimiter = re.compile(rb"(?:\A|\r\n)" + re.escape(marker) + rb"(--)?(?:\r\n|\Z)")
    matches = []
    for match in delimiter.finditer(data):
        matches.append(match)
        if len(matches) > 257:
            return None
    if not matches or not matches[-1].group(1):
        return None
    parts = []
    for index, match in enumerate(matches[:-1]):
        if match.group(1):
            return None
        section = data[match.end():matches[index + 1].start()]
        header_end = section.find(b"\r\n\r\n")
        if header_end < 0 or header_end + 4 > HEADER_LIMIT:
            return None
        try:
            headers = _headers(section[:header_end])
        except ValueError:
            return None
        values = {}
        for item in headers:
            name = item["name"].lower()
            if name in values and name in ("content-type", "content-disposition"):
                return None
            values[name] = item["value"]
        disposition = Message()
        disposition["content-disposition"] = values.get("content-disposition", "")
        if disposition.get_content_disposition() != "form-data":
            return None
        part_type = values.get("content-type", "")
        part = {"name": _parameter(disposition, "name", header="content-disposition"),
                "headers": headers, "content_type": part_type,
                "body": _record_bytes(section[header_end + 4:], content_type=part_type)}
        transfer_encoding = values.get("content-transfer-encoding", "").strip().lower()
        encoded = transfer_encoding not in ("", "binary", "7bit", "8bit")
        if encoded:
            part["transfer_encoding"] = transfer_encoding
            part["warnings"] = ["Part transfer encoding retained without decoding"]
        filename_parameter = disposition.get_param("filename", header="content-disposition")
        if filename_parameter is not None:
            part["filename"] = _parameter(disposition, "filename", header="content-disposition")
            if part["filename"] is None:
                part.setdefault("warnings", []).append("Filename parameter could not be decoded")
        elif "text" in part["body"] and not encoded:
            part["value"] = part["body"]["text"]
        parts.append(part)
    return parts


class _Stream:
    def __init__(self, key):
        self.key = key
        self.buffer = bytearray()
        self.request = None
        self.body = bytearray()
        self.body_seen = 0
        self.mode = "headers"
        self.remaining = 0
        self.expected = None
        self.content_type = ""

    def take_body(self, count):
        retain = min(count, CAPTURE_LIMIT - len(self.body))
        self.body.extend(self.buffer[:retain])
        del self.buffer[:count]
        self.body_seen += count


class HTTPRequestCapture:
    """Assemble bounded HTTP/1 request streams keyed by socket/TLS identity.

    ``feed`` returns records as framing completes or a read gap invalidates it.
    ``flush`` returns incomplete requests at close. Evictions also return an
    incomplete record; every record contains its original ``stream`` key.
    """
    def __init__(self, max_streams=MAX_STREAMS):
        self.max_streams = max(1, min(MAX_STREAMS, int(max_streams)))
        self._streams = OrderedDict()

    def reset(self):
        self._streams.clear()

    def discard(self, key):
        self._streams.pop(key, None)

    def has_pending(self, key):
        return key in self._streams

    def _finish(self, stream, complete=False, status=None, warning=None):
        if stream.request is None:
            # A valid request line still identifies an incomplete request when
            # the headers themselves are cut off or exceed the capture bound.
            line, separator, rest = bytes(stream.buffer[:HEADER_LIMIT]).partition(b"\r\n")
            match = _REQUEST_LINE.fullmatch(line) if separator else None
            if not match or not _TOKEN.fullmatch(match.group(1)):
                return None
            method, url, version = match.groups()
            stream.request = {"method": method.decode("ascii"), "url": url.decode("latin-1"),
                              "version": version.decode("ascii"), "headers": [],
                              "source": "http1", "stream": stream.key,
                              "warnings": ["Request headers are incomplete"]}
            for header in rest.split(b"\r\n")[:-1]:
                try:
                    stream.request["headers"].extend(_headers(header))
                except ValueError:
                    break
        request = stream.request
        if warning:
            request["warnings"].append(warning)
        total = stream.expected if stream.expected is not None else stream.body_seen
        if stream.body_seen > CAPTURE_LIMIT:
            status = status or "truncated"
        status = status or ("complete" if complete else "incomplete")
        request["body"] = body_record(stream.body, total, stream.content_type, status)
        if not complete and stream.expected is None:
            request["body"]["total_bytes"] = None
        request["complete"] = complete and request["body"]["status"] == "complete"
        if request["body"]["truncated"] and "Body capture limit exceeded" not in request["warnings"]:
            if total > CAPTURE_LIMIT:
                request["warnings"].append("Body capture limit exceeded")
        return request

    def flush(self, key=None):
        keys = list(self._streams) if key is None else [key]
        result = []
        for stream_key in keys:
            stream = self._streams.pop(stream_key, None)
            if stream is not None:
                request = self._finish(stream, warning="Stream ended before request completed")
                if request is not None:
                    result.append(request)
        return result

    def feed(self, key, data, total_length=None):
        result = []
        stream = self._streams.pop(key, None)
        if stream is None:
            if not data:
                return result
            stream = _Stream(key)
        self._streams[key] = stream
        while len(self._streams) > self.max_streams:
            _, evicted = self._streams.popitem(last=False)
            request = self._finish(evicted, warning="Stream evicted at capture stream limit")
            if request is not None:
                result.append(request)
        # Incremental ingestion keeps buffers bounded even for a very large
        # write containing multiple requests or an oversized body.
        for offset in range(0, len(data), 16384):
            stream.buffer.extend(data[offset:offset + 16384])
            valid = self._consume(stream, result)
            if not valid:
                self.discard(key)
                return result
        if total_length is not None and total_length > len(data):
            request = self._finish(stream, status="truncated",
                                   warning="Payload read was short; stream has missing bytes")
            if request is not None:
                result.append(request)
            self.discard(key)
        elif stream.request is None and not stream.buffer:
            self.discard(key)
        return result

    def _new_request(self, stream, block):
        line, _, rest = block.partition(b"\r\n")
        match = _REQUEST_LINE.fullmatch(line)
        if not match or not _TOKEN.fullmatch(match.group(1)):
            return False
        method, url, version = match.groups()
        stream.request = {"method": method.decode("ascii"), "url": url.decode("latin-1"),
                          "version": version.decode("ascii"), "headers": [],
                          "source": "http1", "stream": stream.key, "warnings": []}
        stream.request["headers"] = _headers(rest)
        values = {}
        for header in stream.request["headers"]:
            values.setdefault(header["name"].lower(), []).append(header["value"])
        content_types = values.get("content-type", [])
        stream.content_type = content_types[0] if len(content_types) == 1 else ""
        if len(content_types) > 1:
            stream.request["warnings"].append("Multiple Content-Type headers; body interpretation disabled")
        content_encodings = [encoding.strip().lower()
                             for item in values.get("content-encoding", [])
                             for encoding in item.split(",")]
        if any(encoding != "identity" for encoding in content_encodings):
            stream.content_type = ""
            stream.request["warnings"].append("Encoded request body retained without decoding")
        lengths = values.get("content-length", [])
        transfer = values.get("transfer-encoding", [])
        if lengths and transfer:
            raise ValueError("Conflicting Transfer-Encoding and Content-Length")
        if transfer:
            codings = [value.strip().lower() for item in transfer for value in item.split(",")]
            if codings != ["chunked"]:
                raise ValueError("Unsupported or ambiguous Transfer-Encoding")
            stream.mode = "chunk_size"
        else:
            numbers = [value.strip() for item in lengths for value in item.split(",")]
            if numbers and (any(not re.fullmatch(r"[0-9]{1,19}", n) for n in numbers)
                            or len(set(int(n) for n in numbers)) != 1):
                raise ValueError("Invalid or conflicting Content-Length")
            stream.expected = int(numbers[0]) if numbers else 0
            stream.remaining = stream.expected
            stream.mode = "fixed"
        return True

    def _complete(self, stream, result):
        result.append(self._finish(stream, complete=True))
        stream.request = None
        stream.body.clear()
        stream.body_seen = 0
        stream.mode = "headers"
        stream.expected = None
        stream.content_type = ""

    def _consume(self, stream, result):
        try:
            while True:
                if stream.mode == "headers":
                    end = stream.buffer.find(b"\r\n\r\n")
                    if end < 0:
                        if len(stream.buffer) > HEADER_LIMIT:
                            raise ValueError("HTTP header capture limit exceeded")
                        prefix = bytes(stream.buffer).split(b" ", 1)[0]
                        if prefix and (len(prefix) > 32 or not _TOKEN.fullmatch(prefix)):
                            return False
                        return True
                    if end + 4 > HEADER_LIMIT:
                        raise ValueError("HTTP header capture limit exceeded")
                    block = bytes(stream.buffer[:end])
                    del stream.buffer[:end + 4]
                    if not self._new_request(stream, block):
                        return False
                if stream.mode == "fixed":
                    count = min(len(stream.buffer), stream.remaining)
                    stream.take_body(count)
                    stream.remaining -= count
                    if stream.remaining:
                        return True
                    self._complete(stream, result)
                    continue
                if stream.mode == "chunk_size":
                    end = stream.buffer.find(b"\r\n")
                    if end < 0:
                        if len(stream.buffer) > 8192:
                            raise ValueError("Chunk size line capture limit exceeded")
                        return True
                    line = bytes(stream.buffer[:end])
                    del stream.buffer[:end + 2]
                    size = line.split(b";", 1)[0]
                    if end > 8192:
                        raise ValueError("Chunk size line capture limit exceeded")
                    if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", size):
                        raise ValueError("Malformed chunk size")
                    stream.remaining = int(size, 16)
                    stream.mode = "chunk_data" if stream.remaining else "trailers"
                if stream.mode == "chunk_data":
                    count = min(len(stream.buffer), stream.remaining)
                    stream.take_body(count)
                    stream.remaining -= count
                    if stream.remaining:
                        return True
                    stream.mode = "chunk_crlf"
                if stream.mode == "chunk_crlf":
                    if len(stream.buffer) < 2:
                        return True
                    if stream.buffer[:2] != b"\r\n":
                        raise ValueError("Missing chunk terminator")
                    del stream.buffer[:2]
                    stream.mode = "chunk_size"
                    continue
                if stream.mode == "trailers":
                    if stream.buffer[:2] == b"\r\n":
                        del stream.buffer[:2]
                    else:
                        end = stream.buffer.find(b"\r\n\r\n")
                        if end < 0:
                            if len(stream.buffer) > HEADER_LIMIT:
                                raise ValueError("Trailer capture limit exceeded")
                            return True
                        if end + 4 > HEADER_LIMIT:
                            raise ValueError("Trailer capture limit exceeded")
                        stream.request["trailers"] = _headers(bytes(stream.buffer[:end]))
                        if any(header["name"].lower() in ("content-length", "transfer-encoding")
                               for header in stream.request["trailers"]):
                            raise ValueError("Framing header is not allowed in trailers")
                        del stream.buffer[:end + 4]
                    self._complete(stream, result)
        except ValueError as error:
            status = "truncated" if "capture limit exceeded" in str(error) else "malformed"
            request = self._finish(stream, status=status, warning=str(error))
            if request is not None:
                result.append(request)
            return False
