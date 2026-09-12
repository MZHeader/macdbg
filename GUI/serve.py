#!/usr/bin/env python3
"""macdbg backend (headless).

Runs under the system interpreter (/usr/bin/python3 — the only one that can
`import lldb`). Boots the debugger engine + the localhost HTTP/SSE server, prints
its port as ``PORT=<n>`` on stdout, then blocks. The native-window front-end
(GUI/gui.py, under Python 3.13 + pywebview) spawns this and loads the URL.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading


def _ensure_paths() -> None:
    gui_dir = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(gui_dir)
    for p in (gui_dir, repo):
        if p not in sys.path:
            sys.path.insert(0, p)


def main() -> int:
    _ensure_paths()
    try:
        import lldb  # noqa: F401
    except ImportError as e:
        sys.stderr.write("Could not import lldb (need PYTHONPATH=$(/usr/bin/lldb -P)).\n")
        raise SystemExit(1) from e

    p = argparse.ArgumentParser(prog="macdbg-serve")
    p.add_argument("program", nargs="?")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.add_argument("--attach", type=int, default=None)
    p.add_argument("--stop-at", choices=("entry", "loader"), default="entry")
    argv = [a for a in sys.argv[1:]
            if not a.startswith(("-psn_", "-NS", "-Apple"))]
    ns = p.parse_args(argv)

    from server.engine import Engine
    from server import httpd

    engine = Engine(program=ns.program, program_args=ns.args or [], attach_pid=ns.attach)
    engine.dbg.launch_stop = ns.stop_at
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    parent = os.getppid() if os.environ.pop("MACDBG_WATCH_PARENT", None) == "1" else None
    engine.start()
    _httpd, port = httpd.serve(engine, port=0, on_shutdown=done.set)
    sys.stdout.write("TOKEN={}\n".format(_httpd.token))
    sys.stdout.write("PORT={}\n".format(port))
    sys.stdout.flush()
    try:
        while not done.wait(0.25):
            if parent is not None and os.getppid() != parent:
                break
    except KeyboardInterrupt:
        pass
    finally:
        _httpd.shutdown()
        engine.shutdown()
        _httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
