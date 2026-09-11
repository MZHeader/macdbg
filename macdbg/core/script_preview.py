"""Readable views of captured script inputs, independent of the debuggee."""
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys

PREVIEW_CHARS = 256 * 1024
RECONSTRUCTION_NOTE = ('Static reconstruction of compiled AppleScript; names, properties and control flow '
                       'may be incomplete. Original captured bytes are preserved separately.')


@dataclass(frozen=True)
class ScriptContent:
    text: str = ''
    kind: str = 'unavailable'
    note: str = ''

    def preview(self):
        return {'text': self.text[:PREVIEW_CHARS], 'kind': self.kind, 'note': self.note,
                'truncated': len(self.text) > PREVIEW_CHARS}

    def dump_bytes(self):
        header = '-- ' + self.note.replace('\n', '\n-- ') + '\n\n' if self.kind == 'reconstructed' else ''
        return (header + self.text).encode('utf-8')


def readable_content(payload):
    if payload.descriptor_type == 0x73637074:
        try:
            result = subprocess.run(
                [sys.executable, '-I', str(Path(__file__).with_name('script_preview_worker.py'))],
                input=payload.data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=6, check=False)
            if result.returncode:
                return ScriptContent(note='Static decompilation failed or exceeded its resource limit; raw bytes remain available.')
            decoded = json.loads(result.stdout)
            if decoded.get('error'):
                return ScriptContent(note='Static decompilation unavailable: ' + decoded['error'])
            note = RECONSTRUCTION_NOTE
            if decoded.get('warnings'):
                note += '\nParser warnings: ' + '\n'.join(decoded['warnings'])
            return ScriptContent(decoded['text'], 'reconstructed', note)
        except subprocess.TimeoutExpired:
            return ScriptContent(note='Static decompilation timed out; raw bytes remain available.')
        except (OSError, ValueError, KeyError) as error:
            return ScriptContent(note='Static decompilation unavailable: ' + str(error)[:512])
    encodings = {0x75746638: 'utf-8', 0x75747874: 'utf-16-le',
                 0x75743136: 'utf-16-be', 0x54455854: 'mac_roman'}
    encoding = encodings.get(payload.descriptor_type)
    if encoding is None:
        return ScriptContent(note='No text decoder for this descriptor type; raw bytes remain available.')
    if encoding.startswith('utf-16') and payload.data.startswith((b'\xff\xfe', b'\xfe\xff')):
        encoding = 'utf-16'
    try:
        return ScriptContent(payload.data.decode(encoding), 'source', 'Captured source (' + encoding + ').')
    except UnicodeError as error:
        return ScriptContent(note='Source text decoding failed: ' + str(error)[:512])
