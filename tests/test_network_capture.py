"""API argument capture tests; no target process or network traffic is needed."""
import base64
import struct
import unittest
from unittest.mock import Mock

from macdbg.core.http_capture import CAPTURE_LIMIT
from macdbg.core.network_capture import NetworkCapture


def http_request(body=b"abcdef"):
    return (b"POST /submit HTTP/1.1\r\nHost: local.test\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


def mock_frame(caller=None, tid=17, **registers):
    frame = Mock()

    def register(name):
        result = Mock()
        result.IsValid.return_value = name in registers
        result.GetValueAsUnsigned.return_value = registers.get(name, 0)
        return result

    frame.FindRegister.side_effect = register
    parent = Mock()
    parent.IsValid.return_value = caller is not None
    parent.GetFunctionName.return_value = caller
    frame.GetThread.return_value.GetFrameAtIndex.return_value = parent
    frame.GetThread.return_value.GetThreadID.return_value = tid
    return frame


def mock_process(identity, memory):
    process = Mock()
    process.GetUniqueID.return_value = identity
    process.GetProcessID.return_value = identity

    def read(address, size, error):
        result = memory.get(address, b"")[:size]
        if len(result) < size:
            error.SetErrorString("test unreadable memory suffix")
        return result

    process.ReadMemory.side_effect = read
    return process


class NetworkCaptureTests(unittest.TestCase):
    def setUp(self):
        self.memory = {}
        self.process = mock_process(101, self.memory)
        self.capture = NetworkCapture()

    def observe(self, name, caller=None, tid=17, **registers):
        return self.capture.observe(mock_frame(caller=caller, tid=tid, **registers), self.process, name)

    def send(self, data, fd=4, caller=None, function="send"):
        self.memory[0x1000] = data
        return self.observe(function, caller=caller, x0=fd, x1=0x1000, x2=len(data))

    def connect(self, fd=4):
        self.observe("connect", x0=fd)

    def test_tls_memory_reads_and_payload_are_bounded(self):
        self.memory[0x1000] = b"\xff" * (CAPTURE_LIMIT + 73)
        details = self.observe("SSL_write", x0=0x2000, x1=0x1000, x2=CAPTURE_LIMIT + 73)
        self.assertEqual(self.process.ReadMemory.call_args.args[:2], (0x1000, CAPTURE_LIMIT))
        self.assertEqual(details["payload"]["captured_bytes"], CAPTURE_LIMIT)
        self.assertEqual(details["payload"]["total_bytes"], CAPTURE_LIMIT + 73)
        self.assertEqual(details["payload"]["status"], "truncated")
        self.assertEqual(base64.b64decode(details["payload"]["data"]), b"\xff" * CAPTURE_LIMIT)
        self.assertEqual(details["capture_stream"], "pid:101:SSL_write:0x2000")
        self.assertEqual(details["http_requests"], [])

    def test_signed_tls_lengths_reject_negative_and_ignore_upper_register_bits(self):
        for function in ("SSL_write", "wolfSSL_write", "BoringSSL_SSL_write"):
            with self.subTest(function=function):
                with self.assertRaisesRegex(ValueError, "negative TLS write length"):
                    self.observe(function, x0=0x2000, x1=0x1000, x2=0xFFFFFFFF)
        self.process.ReadMemory.assert_not_called()
        self.memory[0x1000] = b"abc"
        result = self.observe("SSL_write", x0=0x2000, x1=0x1000, x2=0xDEADBEEF00000003)
        self.assertEqual(result["payload"]["total_bytes"], 3)
        self.assertEqual(result["payload"]["text"], "abc")

    def test_aead_captures_plaintext_from_x6_x7(self):
        self.memory[0x6000] = b"plaintext"
        self.memory[0x1000] = b"output-buffer"
        result = self.observe("EVP_AEAD_CTX_seal", x0=0x2000, x1=0x1000, x2=0x3000,
                              x6=0x6000, x7=9)
        self.assertEqual(self.process.ReadMemory.call_args.args[:2], (0x6000, 9))
        self.assertEqual(result["payload"]["text"], "plaintext")
        self.assertEqual(result["capture_stream"], "pid:101:EVP_AEAD_CTX_seal:0x2000")

    def test_rustls_scalar_and_vectored_writes_share_sink_not_wrapper(self):
        wire = http_request()
        self.memory.update({0x1000: wire[:13], 0x1100: wire[13:27], 0x1200: wire[27:],
                            0x2000: struct.pack('<Q', 0x9000),
                            0x2100: struct.pack('<Q', 0x9000),
                            0x3000: struct.pack('<QQQQ', 0x1100, 14, 0x1200, len(wire)-27)})
        name = '<rustls::conn::connection::Writer as std::io::Write>::'
        first = self.observe(name+'write::h0123abcd', x0=0x2000, x1=0x1000, x2=13)
        second = self.observe(name+'write_vectored', x0=0x2100, x1=0x3000, x2=2)
        self.assertEqual(first['capture_stream'], second['capture_stream'])
        self.assertEqual(second['http_requests'][0]['body']['text'], 'abcdef')
        self.assertTrue(second['http_requests'][0]['complete'])
        self.assertEqual(self.observe(name+'write_all', x0=0x2000, x1=0x1000, x2=13), {})

    def test_rustls_missing_sink_is_not_merged_into_unknown_connection(self):
        self.memory[0x1000] = http_request()
        with self.assertRaisesRegex(ValueError, 'sink unavailable'):
            self.observe('<rustls::conn::Writer as std::io::Write>::write',
                         x0=0x2000, x1=0x1000, x2=len(self.memory[0x1000]))

    def test_sendmsg_and_writev_preserve_only_contiguous_readable_prefix(self):
        for function in ("sendmsg", "writev"):
            with self.subTest(function=function):
                self.capture.reset()
                self.connect()
                self.process.ReadMemory.reset_mock()
                self.memory.update({0x2000: b"abc", 0x3000: b"de", 0x4000: b"xyz"})
                self.memory[0x5000] = b"".join(struct.pack("<QQ", address, length) for address, length in
                                             ((0x2000, 3), (0x3000, 4), (0x4000, 3)))
                self.memory[0x6000] = b"\x00" * 16 + struct.pack("<QI", 0x5000, 3)
                result = self.observe(function, x0=4, x1=0x6000 if function == "sendmsg" else 0x5000,
                                      x2=3)
                payload = result["payload"]
                self.assertEqual(base64.b64decode(payload["data"]), b"abcde")
                self.assertEqual(payload["total_bytes"], 10)
                self.assertEqual(payload["captured_bytes"], 5)
                self.assertEqual(payload["status"], "unreadable")
                reads = [call.args[0] for call in self.process.ReadMemory.call_args_list]
                self.assertIn(0x3000, reads)
                self.assertNotIn(0x4000, reads)
                self.assertFalse(self.capture.http.has_pending("pid:101:fd:4"))

    def test_iovec_cap_stops_reads_but_counts_all_declared_lengths(self):
        self.connect()
        self.memory[0x2000] = b"\xff" * CAPTURE_LIMIT
        self.memory[0x3000] = b"unread suffix"
        self.memory[0x5000] = struct.pack("<QQQQ", 0x2000, CAPTURE_LIMIT + 12, 0x3000, 13)
        result = self.observe("writev", x0=4, x1=0x5000, x2=2)
        self.assertEqual(result["payload"]["captured_bytes"], CAPTURE_LIMIT)
        self.assertEqual(result["payload"]["total_bytes"], CAPTURE_LIMIT + 25)
        self.assertEqual(result["payload"]["status"], "truncated")
        self.assertNotIn(0x3000, [call.args[0] for call in self.process.ReadMemory.call_args_list])

    def test_invalid_iovec_descriptors_fail_before_guessing_payload(self):
        self.connect()
        with self.assertRaisesRegex(ValueError, "iovec count exceeds"):
            self.observe("writev", x0=4, x1=0x5000, x2=1025)
        self.process.ReadMemory.assert_not_called()
        self.memory[0x5000] = b"\x00" * 15
        with self.assertRaisesRegex(ValueError, "iovec descriptors unavailable"):
            self.observe("writev", x0=4, x1=0x5000, x2=1)
        with self.assertRaisesRegex(ValueError, "sendmsg header unavailable"):
            self.observe("sendmsg", x0=4, x1=0x6000)

    def test_unreadable_memory_is_not_a_successful_empty_capture(self):
        result = self.observe("SSL_write", x0=0x2000, x1=0x9999, x2=25)
        self.assertEqual(result["payload"]["status"], "unreadable")
        self.assertEqual(result["payload"]["captured_bytes"], 0)
        self.assertEqual(result["payload"]["total_bytes"], 25)
        self.assertTrue(result["payload"]["truncated"])
        self.assertEqual(result["http_requests"], [])

    def test_nested_sendto_retains_raw_without_duplicating_assembly(self):
        wire = http_request()
        outer = self.send(wire[:-4])
        self.assertEqual(outer["http_requests"], [])
        nested = self.send(wire[:-4], caller="_send$NOCANCEL", function="sendto")
        self.assertEqual(base64.b64decode(nested["payload"]["data"]), wire[:-4])
        self.assertEqual(nested["http_requests"], [])
        self.assertIn("nested socket write", nested["assembly_skipped"])
        request, = self.send(wire[-4:])["http_requests"]
        self.assertEqual(request["body"]["text"], "abcdef")
        self.assertTrue(request["complete"])
        self.assertTrue(any("API-entry" in warning for warning in request["warnings"]))

    def test_tail_called_sendto_matches_entry_once_and_preserves_raw(self):
        wire = http_request()
        self.memory[0x1000] = wire
        registers = {"x0": 4, "x1": 0x1000, "x2": len(wire), "sp": 0x8000, "lr": 0x9000}
        outer = self.observe("send", **registers)
        self.assertEqual(len(outer["http_requests"]), 1)
        inner = self.observe("__sendto", **registers)
        self.assertEqual(inner["http_requests"], [])
        self.assertIn("assembly_skipped", inner)
        self.assertEqual(base64.b64decode(inner["payload"]["data"]), wire)
        # The entry marker is consumed once: a later direct call is observable.
        direct = self.observe("__sendto", **registers)
        self.assertEqual(len(direct["http_requests"]), 1)
        self.assertNotIn("assembly_skipped", direct)

    def test_repeated_identical_send_and_tail_call_pairs_each_record_a_request(self):
        wire = http_request()
        self.memory[0x1000] = wire
        registers = {"x0": 4, "x1": 0x1000, "x2": len(wire), "sp": 0x8000, "lr": 0x9000}
        requests = []
        for _ in range(3):
            requests.extend(self.observe("send", **registers)["http_requests"])
            self.assertEqual(self.observe("__sendto", **registers)["http_requests"], [])
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request["body"]["text"] == "abcdef" for request in requests))
        # A second send refreshes an unmatched marker even for identical input.
        self.assertEqual(len(self.observe("send", **registers)["http_requests"]), 1)
        self.assertEqual(len(self.observe("send", **registers)["http_requests"]), 1)

    def test_tail_call_pair_requires_same_descriptor_buffer_stack_and_return_site(self):
        wire = http_request()
        self.memory[0x1000] = self.memory[0x2000] = wire
        registers = {"x0": 4, "x1": 0x1000, "x2": len(wire), "sp": 0x8000, "lr": 0x9000}
        for field, changed in (("x0", 5), ("x1", 0x2000), ("x2", len(wire) + 1),
                               ("sp", 0x8010), ("lr", 0x9004)):
            with self.subTest(field=field):
                self.capture.reset()
                self.observe("send", **registers)
                different = self.observe("__sendto", **dict(registers, **{field: changed}))
                self.assertNotIn("assembly_skipped", different)
                self.assertEqual(len(different["http_requests"]), 1)

    def test_missing_stack_or_return_register_does_not_claim_a_tail_call_match(self):
        wire = http_request()
        self.memory[0x1000] = wire
        registers = {"x0": 4, "x1": 0x1000, "x2": len(wire), "sp": 0x8000, "lr": 0x9000}
        for missing in ("sp", "lr"):
            with self.subTest(missing=missing):
                self.capture.reset()
                incomplete = {name: value for name, value in registers.items() if name != missing}
                self.observe("send", **incomplete)
                direct = self.observe("__sendto", **incomplete)
                self.assertNotIn("assembly_skipped", direct)
                self.assertEqual(len(direct["http_requests"]), 1)

    def test_tail_call_markers_are_independent_between_threads(self):
        wire = http_request()
        self.memory[0x1000] = wire
        registers = {"x0": 4, "x1": 0x1000, "x2": len(wire), "sp": 0x8000, "lr": 0x9000}
        self.observe("send", tid=17, **registers)
        other_thread = self.observe("__sendto", tid=18, **registers)
        self.assertNotIn("assembly_skipped", other_thread)
        self.assertEqual(len(other_thread["http_requests"]), 1)
        self.observe("send", tid=18, **registers)
        for tid in (17, 18):
            inner = self.observe("__sendto", tid=tid, **registers)
            self.assertIn("assembly_skipped", inner)
            self.assertEqual(inner["http_requests"], [])

    def test_close_and_send_shutdown_flush_pending_outgoing_request(self):
        for function, how in (("close", 0), ("shutdown", 1), ("shutdown", 2)):
            with self.subTest(function=function, how=how):
                self.capture.reset()
                self.connect()
                self.send(http_request()[:-4])
                request, = self.observe(function, x0=4, x1=how)["http_requests"]
                self.assertFalse(request["complete"])
                self.assertEqual(request["body"]["text"], "ab")
                self.assertEqual(request["body"]["status"], "incomplete")
                self.assertFalse(self.capture.http.has_pending("pid:101:fd:4"))
                self.assertNotIn("pid:101:fd:4", self.capture.sockets)

    def test_shutdown_read_preserves_outgoing_stream_and_socket_tracking(self):
        self.connect()
        wire = http_request()
        self.send(wire[:-4])
        self.assertEqual(self.observe("shutdown", x0=4, x1=0), {})
        self.assertTrue(self.capture.http.has_pending("pid:101:fd:4"))
        self.assertIn("pid:101:fd:4", self.capture.sockets)
        request, = self.send(wire[-4:])["http_requests"]
        self.assertTrue(request["complete"])
        self.assertEqual(request["body"]["text"], "abcdef")

    def test_process_identity_change_resets_socket_and_assembly_state(self):
        self.connect()
        self.send(http_request()[:-4])
        process = mock_process(102, self.memory)
        self.capture.observe(mock_frame(), process, "unrelated_function")
        self.assertEqual(self.capture.process_id, 102)
        self.assertEqual(len(self.capture.sockets), 0)
        self.assertFalse(self.capture.http.has_pending("pid:101:fd:4"))
        self.assertEqual(self.capture.http.flush(), [])
        self.memory[0x1000] = http_request(b"new process")
        details = self.capture.observe(mock_frame(x0=4, x1=0x1000, x2=len(self.memory[0x1000])),
                                       process, "send")
        request, = details["http_requests"]
        self.assertEqual(request["stream"], "pid:102:fd:4")
        self.assertEqual(request["body"]["text"], "new process")

    def test_reused_os_pid_with_new_lldb_identity_does_not_reuse_pending_request(self):
        self.connect()
        self.send(http_request()[:-4])
        replacement = mock_process(102, self.memory)
        replacement.GetProcessID.return_value = 101
        self.capture.observe(mock_frame(), replacement, "unrelated_function")
        self.assertEqual(self.capture.process_id, 102)
        self.assertFalse(self.capture.http.has_pending("pid:101:fd:4"))
        self.assertEqual(len(self.capture.sockets), 0)

    def test_tls_context_cleanup_flushes_matching_writers_only(self):
        wire = http_request()[:-4]
        self.memory[0x1000] = wire
        for writer, context in (("SSL_write", 0x4000), ("SSL_write_ex", 0x4000), ("SSL_write", 0x5000)):
            self.observe(writer, x0=context, x1=0x1000, x2=len(wire))
        result = self.observe("SSL_free", x0=0x4000)
        self.assertEqual({request["stream"] for request in result["http_requests"]},
                         {"pid:101:SSL_write:0x4000", "pid:101:SSL_write_ex:0x4000"})
        self.assertTrue(all(not request["complete"] for request in result["http_requests"]))
        self.assertFalse(self.capture.http.has_pending("pid:101:SSL_write:0x4000"))
        self.assertFalse(self.capture.http.has_pending("pid:101:SSL_write_ex:0x4000"))
        self.assertTrue(self.capture.http.has_pending("pid:101:SSL_write:0x5000"))

    def test_only_tracked_sockets_are_captured_by_generic_write(self):
        self.memory[0x1000] = b"file-data"
        self.assertEqual(self.observe("write", x0=4, x1=0x1000, x2=9), {})
        self.process.ReadMemory.assert_not_called()
        self.connect()
        result = self.observe("write", x0=4, x1=0x1000, x2=9)
        self.assertEqual(result["payload"]["text"], "file-data")


if __name__ == "__main__":
    unittest.main()
