import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

from macdbg.core.script_preview import readable_content, PREVIEW_CHARS


def payload(data, kind=0x73637074):
    return types.SimpleNamespace(data=data, descriptor_type=kind)


class ScriptPreviewTests(unittest.TestCase):
    def test_run_only_content_preserves_ignored_result_commands_without_execution(self):
        with tempfile.TemporaryDirectory(prefix='macdbg-preview-', dir='/private/tmp') as tmp:
            root = pathlib.Path(tmp)
            marker = root / 'marker'
            source = root / 'fixture.applescript'
            compiled = root / 'fixture.scpt'
            source.write_text('on greet(value)\nreturn "Hello " & value\nend greet\n'
                              'do shell script "printf harmless > ' + str(marker) + '"\n'
                              'greet("reader")\nreturn 42\n')
            subprocess.run(['/usr/bin/osacompile', '-x', '-o', str(compiled), str(source)],
                           check=True, capture_output=True)
            content = readable_content(payload(compiled.read_bytes()))
            self.assertEqual(content.kind, 'reconstructed', content.note)
            for text in ('on greet', 'do shell script', 'printf harmless', 'Hello ', 'return 42'):
                self.assertIn(text, content.text)
            self.assertFalse(marker.exists())
            self.assertTrue(content.dump_bytes().startswith(b'-- Static reconstruction'))

    def test_source_encodings_keep_content_and_report_decoding_failure(self):
        source = 'return "café"\n'
        for kind, encoding in [(0x75746638, 'utf-8'), (0x75747874, 'utf-16-le'),
                               (0x75743136, 'utf-16-be'), (0x54455854, 'mac_roman')]:
            with self.subTest(encoding=encoding):
                content = readable_content(payload(source.encode(encoding), kind))
                self.assertEqual(content.kind, 'source')
                self.assertEqual(content.text, source)
                self.assertEqual(content.dump_bytes(), source.encode('utf-8'))
        self.assertEqual(readable_content(payload(b'\xff', 0x75746638)).kind, 'unavailable')

    def test_invalid_compiled_input_fails_without_metadata_substitution(self):
        content = readable_content(payload(b'not compiled AppleScript'))
        self.assertEqual(content.kind, 'unavailable')
        self.assertEqual(content.text, '')
        self.assertIn('unavailable', content.note)

    def test_parser_timeout_preserves_raw_capture(self):
        original = payload(b'Fasd')
        with patch('macdbg.core.script_preview.subprocess.run', side_effect=subprocess.TimeoutExpired('worker', 6)):
            content = readable_content(original)
        self.assertEqual(content.kind, 'unavailable')
        self.assertIn('timed out', content.note)
        self.assertEqual(original.data, b'Fasd')

    def test_preview_is_bounded_but_dump_retains_full_source(self):
        data = b'a' * (PREVIEW_CHARS + 5)
        content = readable_content(payload(data, 0x75746638))
        self.assertTrue(content.preview()['truncated'])
        self.assertEqual(len(content.preview()['text']), PREVIEW_CHARS)
        self.assertEqual(content.dump_bytes(), data)
