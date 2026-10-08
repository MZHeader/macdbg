import base64
import json
import unittest

from macdbg.core.http_capture import (
    CAPTURE_LIMIT, HEADER_LIMIT, HTTPRequestCapture, body_record,
)


def request(body=b"", extra=b"", path=b"/submit"):
    return (b"POST " + path + b" HTTP/1.1\r\nHost: local.test\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n" + extra + b"\r\n" + body)


class BodyRecordTests(unittest.TestCase):
    def test_binary_bytes_are_lossless_and_never_replacement_decoded(self):
        data = b"\x00\xff\xfe\x80payload"
        result = body_record(data)
        self.assertEqual(base64.b64decode(result["data"]), data)
        self.assertNotIn("text", result)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["truncated"])

    def test_form_preserves_duplicate_fields_blank_values_and_unicode(self):
        result = body_record(b"name=a&name=b&blank=&flag&word=caf%C3%A9&plus=a+b",
                             content_type="application/x-www-form-urlencoded")
        self.assertEqual(result["fields"], [
            {"name": "name", "value": "a"}, {"name": "name", "value": "b"},
            {"name": "blank", "value": ""}, {"name": "flag", "value": ""},
            {"name": "word", "value": "caf\u00e9"}, {"name": "plus", "value": "a b"},
        ])

    def test_json_and_declared_charset(self):
        result = body_record(b'{"message":"caf\xe9","n":4}',
                             content_type="application/example+json; charset=iso-8859-1")
        self.assertEqual(result["json"], {"message": "caf\u00e9", "n": 4})
        self.assertNotIn("json", body_record(b"{bad}", content_type="application/json"))
        self.assertNotIn("text", body_record(b"a", content_type="text/plain; charset=missing-codec"))

    def test_json_nonfinite_values_huge_integers_and_depth_are_not_exported(self):
        for data in (b"NaN", b"Infinity", b"-Infinity", b"1e400", b'{"x":NaN}',
                     b"9" * 2048, b"[" * 4096 + b"0" + b"]" * 4096):
            with self.subTest(prefix=data[:20]):
                result = body_record(data, content_type="application/json")
                self.assertNotIn("json", result)
                self.assertEqual(base64.b64decode(result["data"]), data)
                json.dumps(result, allow_nan=False)
        text = "[[[\\\"" * 100
        result = body_record(json.dumps({"text": text}).encode("utf-8"), content_type="application/json")
        self.assertEqual(result["json"], {"text": text})

    def test_untrusted_codec_names_are_not_invoked(self):
        for content_type in ("text/plain; charset=punycode", "text/plain; charset=unicode_escape",
                             "text/plain; charset=zlib", 'text/plain; charset="utf-8\x00"',
                             "text/plain; charset*=punycode''abc",
                             "text/plain; charset=" + "x" * 1000):
            with self.subTest(content_type=content_type[:70]):
                result = body_record(b"text", content_type=content_type)
                self.assertNotIn("text", result)
                self.assertEqual(base64.b64decode(result["data"]), b"text")
        self.assertEqual(body_record(b"text", content_type="text/plain; charset*=ascii''utf-8")["text"], "text")

    def test_partial_values_are_not_reported_as_complete_structured_bodies(self):
        for status in ("incomplete", "unavailable", "truncated"):
            result = body_record(b"a=1", content_type="application/x-www-form-urlencoded", status=status)
            self.assertNotIn("fields", result)
            self.assertEqual(result["status"], status)
        short = body_record(b"{}", total_length=40, content_type="application/json")
        self.assertTrue(short["truncated"])
        self.assertNotIn("json", short)
        missing = body_record(b"", status="unavailable")
        self.assertEqual(missing["status"], "unavailable")
        self.assertIsNone(missing["total_bytes"])
        self.assertNotIn("text", missing)

    def test_body_cap_retains_exact_prefix(self):
        data = b"x" * (CAPTURE_LIMIT + 31)
        result = body_record(data)
        self.assertEqual(result["captured_bytes"], CAPTURE_LIMIT)
        self.assertEqual(result["total_bytes"], len(data))
        self.assertTrue(result["truncated"])
        self.assertEqual(result["status"], "truncated")
        self.assertEqual(base64.b64decode(result["data"]), data[:CAPTURE_LIMIT])

    def test_multipart_fields_file_bytes_and_false_boundary(self):
        body = (b"--edge\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\none\r\n"
                b"--edge\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.bin\"\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n\xff\x00--edge\r\n--edge-not-boundary\r\n"
                b"--edge--\r\n")
        result = body_record(body, content_type='multipart/form-data; boundary="edge"')
        self.assertEqual(result["parts"][0]["name"], "tag")
        self.assertEqual(result["parts"][0]["value"], "one")
        file_part = result["parts"][1]
        self.assertEqual(file_part["filename"], "sample.bin")
        self.assertEqual(base64.b64decode(file_part["body"]["data"]),
                         b"\xff\x00--edge\r\n--edge-not-boundary")
        self.assertEqual(base64.b64decode(result["data"]), body)
        self.assertNotIn("parts", body_record(body[:-12], content_type="multipart/form-data; boundary=edge"))

    def test_multipart_encoded_parameters_and_ambiguous_headers(self):
        body = (b"--edge\r\nContent-Disposition: form-data; name*=utf-8''caf%C3%A9; "
                b"filename*=punycode''abc\r\n\r\nfile-data\r\n--edge--\r\n")
        result = body_record(body, content_type="multipart/form-data; boundary=edge")
        part, = result["parts"]
        self.assertEqual(part["name"], "caf\u00e9")
        self.assertIsNone(part["filename"])
        self.assertNotIn("value", part)
        self.assertTrue(part["warnings"])
        self.assertNotIn("parts", body_record(body, content_type="multipart/form-data; boundary*=punycode''abc"))
        ambiguous = body.replace(b"\r\n\r\nfile-data", b"\r\nContent-Disposition: form-data; name=other\r\n\r\nfile-data")
        self.assertNotIn("parts", body_record(ambiguous, content_type="multipart/form-data; boundary=edge"))
        encoded = (b"--edge\r\nContent-Disposition: form-data; name=field\r\n"
                   b"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--edge--\r\n")
        part, = body_record(encoded, content_type="multipart/form-data; boundary=edge")["parts"]
        self.assertNotIn("value", part)
        self.assertEqual(part["body"]["text"], "aGVsbG8=")
        self.assertEqual(part["transfer_encoding"], "base64")


class HTTPRequestCaptureTests(unittest.TestCase):
    def test_request_split_at_every_byte_preserves_headers_and_form(self):
        parser = HTTPRequestCapture()
        data = request(b"a=1&a=2&empty=", b"Content-Type: application/x-www-form-urlencoded\r\n"
                       b"X-Tag: first\r\nX-Tag: second\r\n")
        results = []
        for byte in data:
            results.extend(parser.feed("socket", bytes([byte])))
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertTrue(result["complete"])
        self.assertEqual((result["method"], result["url"], result["version"]),
                         ("POST", "/submit", "HTTP/1.1"))
        self.assertEqual(result["stream"], "socket")
        self.assertEqual([h["value"] for h in result["headers"] if h["name"] == "X-Tag"],
                         ["first", "second"])
        self.assertEqual(result["body"]["fields"], [
            {"name": "a", "value": "1"}, {"name": "a", "value": "2"},
            {"name": "empty", "value": ""},
        ])
        self.assertFalse(parser.has_pending("socket"))

    def test_coalesced_requests_and_no_length_request(self):
        parser = HTTPRequestCapture()
        data = request(b"body") + b"GET /two HTTP/1.1\r\nHost: local.test\r\n\r\n" + request(b"3")
        results = parser.feed("s", data)
        self.assertEqual([r["url"] for r in results], ["/submit", "/two", "/submit"])
        self.assertEqual([r["body"]["text"] for r in results], ["body", "", "3"])
        self.assertTrue(all(r["complete"] for r in results))

    def test_chunked_split_extensions_trailers_and_next_request(self):
        data = (b"POST /chunks HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Type: application/json\r\n\r\n"
                b"4;ext=value\r\n{\"n\"\r\n3\r\n:2}\r\n0\r\nX-End: yes\r\n\r\n" + request())
        for step in (1, 7, 4096):
            with self.subTest(step=step):
                parser = HTTPRequestCapture()
                results = []
                for offset in range(0, len(data), step):
                    results.extend(parser.feed("s", data[offset:offset + step]))
                self.assertEqual(len(results), 2)
                self.assertEqual(results[0]["body"]["json"], {"n": 2})
                self.assertEqual(results[0]["trailers"], [{"name": "X-End", "value": "yes"}])
                self.assertTrue(all(result["complete"] for result in results))

    def test_close_flushes_partial_body_with_known_expected_size(self):
        parser = HTTPRequestCapture()
        self.assertEqual(parser.feed("s", request(b"abcdef")[:-3]), [])
        self.assertTrue(parser.has_pending("s"))
        result, = parser.flush("s")
        self.assertFalse(result["complete"])
        self.assertEqual(result["body"]["text"], "abc")
        self.assertEqual(result["body"]["total_bytes"], 6)
        self.assertEqual(result["body"]["status"], "incomplete")
        self.assertFalse(parser.has_pending("s"))

    def test_short_read_invalidates_stream_and_preserves_available_body(self):
        parser = HTTPRequestCapture()
        data = request(b"abcdef")
        result, = parser.feed("s", data[:-3], total_length=len(data))
        self.assertFalse(result["complete"])
        self.assertEqual(result["body"]["status"], "truncated")
        self.assertEqual(result["body"]["text"], "abc")
        self.assertTrue(any("missing bytes" in warning for warning in result["warnings"]))
        self.assertFalse(parser.has_pending("s"))
        self.assertEqual(parser.feed("s", b"def"), [])

    def test_large_body_is_bounded_and_following_request_still_parsed(self):
        parser = HTTPRequestCapture()
        data = request(b"z" * (CAPTURE_LIMIT + 17)) + request(b"next")
        results = parser.feed("s", data)
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["complete"])
        self.assertEqual(results[0]["body"]["status"], "truncated")
        self.assertEqual(results[0]["body"]["captured_bytes"], CAPTURE_LIMIT)
        self.assertEqual(results[0]["body"]["total_bytes"], CAPTURE_LIMIT + 17)
        self.assertEqual(results[1]["body"]["text"], "next")
        self.assertTrue(results[1]["complete"])

    def test_body_and_stream_storage_stay_bounded_with_unfinished_large_requests(self):
        parser = HTTPRequestCapture(max_streams=2)
        header = b"POST / HTTP/1.1\r\nContent-Length: 100000000\r\n\r\n"
        for key in ("a", "b", "c"):
            parser.feed(key, header)
            for _ in range(8):
                parser.feed(key, b"x" * HEADER_LIMIT)
            self.assertLessEqual(len(parser._streams), 2)
            for stream in parser._streams.values():
                self.assertLessEqual(len(stream.body), CAPTURE_LIMIT)
                self.assertLessEqual(len(stream.buffer), HEADER_LIMIT)
        results = parser.flush()
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result["body"]["truncated"] for result in results))

    def test_encoded_or_ambiguous_content_types_keep_raw_without_structured_values(self):
        for extra in (b"Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
                      b"Content-Type: application/json\r\nContent-Type: text/plain\r\n"):
            result, = HTTPRequestCapture().feed("s", request(b'{"n":2}', extra))
            self.assertNotIn("json", result["body"])
            self.assertEqual(base64.b64decode(result["body"]["data"]), b'{"n":2}')
            self.assertTrue(result["warnings"])

    def test_malformed_and_ambiguous_framing_is_explicit(self):
        headers = [b"Content-Length: 2\r\nContent-Length: 3\r\n",
                   b"Content-Length: -1\r\n", b"Content-Length: abc\r\n",
                   b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
                   b"Transfer-Encoding: gzip, chunked\r\n", b"bad header\r\n"]
        for header in headers:
            with self.subTest(header=header):
                parser = HTTPRequestCapture()
                result, = parser.feed("s", b"POST / HTTP/1.1\r\n" + header + b"\r\nxyz")
                self.assertFalse(result["complete"])
                self.assertEqual(result["body"]["status"], "malformed")
                self.assertTrue(result["warnings"])
                self.assertFalse(parser.has_pending("s"))
        for wire in (b"QQ\r\na\r\n", b"1\r\naZZ"):
            parser = HTTPRequestCapture()
            result, = parser.feed("s", b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + wire)
            self.assertEqual(result["body"]["status"], "malformed")

    def test_unknown_binary_or_http2_is_not_misidentified(self):
        parser = HTTPRequestCapture()
        for data in (b"\x16\x03\x03\x00\xff", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\n\r\n", b"nonsense\r\n\r\n"):
            self.assertEqual(parser.feed("s", data), [])
            self.assertFalse(parser.has_pending("s"))

    def test_header_limit_and_partial_headers_produce_incomplete_records(self):
        parser = HTTPRequestCapture()
        data = b"POST / HTTP/1.1\r\nX-Large: " + b"a" * HEADER_LIMIT
        result, = parser.feed("s", data)
        self.assertFalse(result["complete"])
        self.assertIn("HTTP header capture limit exceeded", result["warnings"])
        self.assertEqual(result["body"]["status"], "truncated")
        parser.feed("s", b"POST / HTTP/1.1\r\nHost: local.test\r\nX-Incomplete:")
        partial, = parser.flush("s")
        self.assertEqual(partial["headers"], [{"name": "Host", "value": "local.test"}])
        self.assertEqual(partial["body"]["status"], "incomplete")

    def test_chunked_incomplete_size_unknown_and_body_cap(self):
        parser = HTTPRequestCapture()
        header = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertEqual(parser.feed("s", header + b"5\r\nabc"), [])
        partial, = parser.flush("s")
        self.assertEqual(partial["body"]["text"], "abc")
        self.assertIsNone(partial["body"]["total_bytes"])
        self.assertEqual(partial["body"]["status"], "incomplete")
        body = b"z" * (CAPTURE_LIMIT + 3)
        wire = header + format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n0\r\n\r\n"
        capped, = parser.feed("s", wire)
        self.assertFalse(capped["complete"])
        self.assertEqual(capped["body"]["status"], "truncated")
        self.assertEqual(capped["body"]["total_bytes"], len(body))
        self.assertEqual(capped["body"]["captured_bytes"], CAPTURE_LIMIT)

    def test_chunk_and_trailer_metadata_limits_and_invalid_trailer_framing(self):
        header = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        for wire in (b"1;" + b"a" * 8192 + b"\r\nx\r\n0\r\n\r\n",
                     b"0\r\nX-Large: " + b"a" * HEADER_LIMIT + b"\r\n\r\n"):
            result, = HTTPRequestCapture().feed("s", header + wire)
            self.assertEqual(result["body"]["status"], "truncated")
            self.assertFalse(result["complete"])
        result, = HTTPRequestCapture().feed("s", header + b"0\r\nContent-Length: 100\r\n\r\n")
        self.assertFalse(result["complete"])
        self.assertEqual(result["body"]["status"], "malformed")

    def test_repeated_identical_lengths_are_accepted(self):
        parser = HTTPRequestCapture()
        result, = parser.feed("s", b"POST / HTTP/1.1\r\nContent-Length: 3, 03\r\n"
                              b"Content-Length: 3\r\n\r\nabc")
        self.assertTrue(result["complete"])
        self.assertEqual(result["body"]["text"], "abc")

    def test_lru_eviction_preserves_attribution_and_reset_discard(self):
        parser = HTTPRequestCapture(max_streams=2)
        partial = request(b"1234")[:-2]
        parser.feed("old", partial)
        parser.feed("keep", partial)
        parser.feed("old", b"3")
        evicted, = parser.feed("new", partial)
        self.assertEqual(evicted["stream"], "keep")
        self.assertFalse(evicted["complete"])
        self.assertFalse(parser.has_pending("keep"))
        parser.discard("new")
        self.assertFalse(parser.has_pending("new"))
        parser.reset()
        self.assertEqual(parser.flush(), [])


if __name__ == "__main__":
    unittest.main()
