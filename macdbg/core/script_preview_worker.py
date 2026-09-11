"""Bounded, standalone static OSA parser. Never invokes an OSA component."""
import contextlib
import io
import json
from pathlib import Path
import resource
import sys

MAX_INPUT = 4 * 1024 * 1024
MAX_TEXT = 2 * 1024 * 1024


class Diagnostics:
    def __init__(self):
        self.messages = []

    def write(self, text):
        if len(self.messages) < 20 and any(
                word in text.lower() for word in ('warning', 'error', 'not implemented', 'failed')):
            self.messages.append(text[:512].strip())
        return len(text)

    def flush(self):
        pass


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    except (ValueError, OSError):
        pass  # Some macOS versions do not implement address-space limits.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    diagnostics = Diagnostics()
    try:
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError('compiled input exceeds 4 MiB')
        with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
            from macdbg._vendor.osa.jinmo_applescript_disassembler.engine.fasparser import Loader
            from macdbg._vendor.osa.applescript_decompiler.decompiler import run_decompiler
            text = run_decompiler(Loader().load(io.BytesIO(data)))
        if not text or not text.strip():
            raise ValueError('no script handlers recovered')
        if len(text.encode('utf-8')) > MAX_TEXT:
            raise ValueError('reconstructed text exceeds 2 MiB')
        result = {'text': text, 'warnings': diagnostics.messages}
    except Exception as error:
        result = {'error': type(error).__name__ + ': ' + str(error)[:512]}
    sys.stdout.write(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    main()
