#!/usr/bin/env python3
"""macdbg GUI entry point (web UI).

Boots the debugger engine + a localhost HTTP/SSE server under the system
interpreter (/usr/bin/python3, the only one that can `import lldb`), then opens
the frontend in a chromeless Chrome/Brave/Edge --app window so it looks like a
native app. Closing that window shuts the backend down. Falls back to the
default browser if no Chromium-based browser is installed.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request

LOCK = os.path.expanduser("~/.macdbg/gui.lock")


def _ensure_paths() -> None:
    gui_dir = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(gui_dir)
    for p in (gui_dir, repo):
        if p not in sys.path:
            sys.path.insert(0, p)


_CHROMIUM = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]


def _find_browser():
    for path in _CHROMIUM:
        if os.path.isfile(path):
            return path
    return None


def _open_app_window(url: str):
    """Launch a chromeless Chromium app window; return the Popen, or None if no
    Chromium browser is installed (caller then falls back to Safari)."""
    browser = _find_browser()
    if not browser:
        return None
    profile = os.path.expanduser("~/.macdbg/gui-chrome")
    os.makedirs(profile, exist_ok=True)
    return subprocess.Popen([
        browser,
        "--app=" + url,
        "--user-data-dir=" + profile,
        "--no-first-run", "--no-default-browser-check",
        "--window-size=1680,1040",
        "--class=macdbg",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _running_instance_url():
    """If another macdbg GUI is already serving, return its URL, else None. A
    stale lock — dead port, or some unrelated service that grabbed it — is
    ignored and removed so we start a fresh instance instead of trying to focus
    a window that isn't there."""
    try:
        with open(LOCK) as f:
            port = int(f.read().strip())
    except (OSError, ValueError):
        return None
    url = "http://127.0.0.1:{}/".format(port)
    try:
        # Verify it's actually us (index.html is titled 'macdbg'), not just any
        # process that happens to hold the port.
        if b"macdbg" in urllib.request.urlopen(url, timeout=0.5).read(4096):
            return url
    except Exception:
        pass
    try:
        os.remove(LOCK)
    except OSError:
        pass
    return None


def _open_fallback(url: str) -> None:
    """No Chromium browser: open in Safari (present on every Mac), then fall back
    to the default browser if even that fails."""
    try:
        subprocess.Popen(["/usr/bin/open", "-a", "Safari", url],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    except Exception:
        pass
    import webbrowser
    webbrowser.open(url)


def main() -> int:
    _ensure_paths()
    try:
        import lldb  # noqa: F401
    except ImportError as e:
        sys.stderr.write("Could not import lldb. Run via GUI/run.sh or macdbg.app "
                         "(they set PYTHONPATH=$(/usr/bin/lldb -P)).\n")
        raise SystemExit(1) from e

    p = argparse.ArgumentParser(prog="macdbg-gui")
    p.add_argument("program", nargs="?")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.add_argument("--attach", type=int, default=None)
    p.add_argument("--port", type=int, default=0)
    argv = [a for a in sys.argv[1:]
            if not a.startswith("-psn_") and not a.startswith("-NS")
            and not a.startswith("-Apple")]
    ns = p.parse_args(argv)

    # Single instance: if one is already running, just focus its window and
    # exit — don't spin up a second backend / browser window (e.g. when the
    # Dock icon is clicked again).
    existing = _running_instance_url()
    if existing:
        sys.stderr.write("macdbg already running — focusing existing window.\n")
        if _open_app_window(existing) is None:
            _open_fallback(existing)
        return 0

    from server.engine import Engine
    from server import httpd

    engine = Engine(program=ns.program, program_args=ns.args or [], attach_pid=ns.attach)
    engine.start()
    _httpd, port = httpd.serve(engine, port=ns.port)
    url = "http://127.0.0.1:{}/".format(port)
    sys.stderr.write("macdbg GUI serving at {}\n".format(url))
    try:
        os.makedirs(os.path.dirname(LOCK), exist_ok=True)
        with open(LOCK, "w") as f:
            f.write(str(port))
    except OSError:
        pass

    # Turn SIGTERM (logout, `pkill`, LaunchServices quit) into a clean exit so
    # the `finally` below shuts the backend down and removes the lock — otherwise
    # a killed instance leaves an orphaned backend and a stale lock that makes the
    # next launch think it's "already running".
    try:
        signal.signal(signal.SIGTERM, lambda *_a: sys.exit(0))
    except Exception:
        pass

    proc = _open_app_window(url)
    try:
        if proc is not None:
            proc.wait()  # chromeless Chromium window: block until it's closed
        else:
            # No Chromium browser installed — fall back to Safari.
            _open_fallback(url)
            sys.stderr.write("No Chromium browser found — opened in Safari. "
                             "Press Ctrl+C here to quit macdbg.\n")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()
        try:
            os.remove(LOCK)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
