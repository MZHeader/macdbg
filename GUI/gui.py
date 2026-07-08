#!/usr/bin/env python3
"""macdbg native window (front-end).

Runs under a Python that has pywebview (e.g. python.org 3.13). Spawns the
debugger backend (GUI/serve.py, under /usr/bin/python3 for lldb), reads the port
it prints, and renders the web UI in a real native macOS window (WKWebView) — a
proper app: own window, own dock icon, a native "macdbg" menu bar, normal quit.

Falls back to the default browser if pywebview isn't available.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

GUI = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(GUI)
_URL = None  # backend base URL, set once the backend reports its port

# Import the native GUI toolkit (pywebview + pyobjc) eagerly, at module load,
# while the interpreter is pristine — before we spawn the backend subprocess or
# start reader threads. Importing pyobjc *after* that activity was observed to
# fail with a spurious "cannot import _objc / circular import" only when the app
# was launched from Finder. Importing here sidesteps it.
try:
    import webview as _webview
    from webview.menu import Menu, MenuAction, MenuSeparator
    import Foundation as _Foundation
    import AppKit as _AppKit
    _HAVE_NATIVE = True
except Exception as _e:  # pywebview/pyobjc unavailable -> browser fallback
    _webview = None
    _HAVE_NATIVE = False
    sys.stderr.write("[gui] native toolkit unavailable at import: {!r}\n".format(_e))


def _lldb_pythonpath() -> str:
    try:
        return subprocess.check_output(["/usr/bin/lldb", "-P"], text=True).strip()
    except Exception:
        return ""


def _native_arch() -> str:
    try:
        r = subprocess.run(["sysctl", "-n", "hw.optional.arm64"],
                           capture_output=True, text=True)
        return "arm64" if r.stdout.strip() == "1" else "x86_64"
    except Exception:
        return "x86_64"


def _start_backend(args):
    env = os.environ.copy()
    # The 3.9 backend needs only lldb + the repo — NOT the 3.13 pywebview vendor
    # dir that may be on our PYTHONPATH.
    env["PYTHONPATH"] = ":".join(p for p in (_lldb_pythonpath(), REPO) if p)
    # Give lldb/debugserver a sane environment when launched outside a terminal.
    env["PATH"] = (env.get("PATH", "") + ":/usr/bin:/bin:/usr/sbin:/sbin").strip(":")
    if not env.get("DEVELOPER_DIR"):
        try:
            env["DEVELOPER_DIR"] = subprocess.check_output(
                ["xcode-select", "-p"], text=True).strip()
        except Exception:
            pass
    if not env.get("SDKROOT"):
        try:
            env["SDKROOT"] = subprocess.check_output(
                ["xcrun", "--show-sdk-path"], text=True, env=env).strip()
        except Exception:
            dd = env.get("DEVELOPER_DIR", "")
            if dd:
                env["SDKROOT"] = dd + "/SDKs/MacOSX.sdk"
    # Force native arch so lldb's host platform matches an arm64 target (see run.sh).
    be = subprocess.Popen(
        ["/usr/bin/arch", "-" + _native_arch(),
         "/usr/bin/python3", os.path.join(GUI, "serve.py")] + args,
        env=env, stdout=subprocess.PIPE, text=True)
    port = None
    deadline = time.time() + 25
    while time.time() < deadline:
        line = be.stdout.readline()
        if not line:
            if be.poll() is not None:
                break
            continue
        if line.strip().startswith("PORT="):
            try:
                port = int(line.strip()[5:])
            except ValueError:
                pass
            break
    threading.Thread(target=lambda: [None for _ in be.stdout], daemon=True).start()
    return be, port


def post(name, args=None):
    """Fire a backend command (from a native menu item)."""
    if not _URL:
        return
    try:
        req = urllib.request.Request(
            _URL + "cmd",
            data=json.dumps({"name": name, "args": args or {}}).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


def _set_app_name(name: str) -> None:
    """Rename the macOS menu-bar app title (otherwise it says 'Python')."""
    try:
        bundle = _Foundation.NSBundle.mainBundle()
        info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
        if info is not None:
            info["CFBundleName"] = name
    except Exception:
        pass


def _set_dock_icon() -> None:
    try:
        icns = os.path.join(GUI, "macdbg.icns")
        if os.path.exists(icns):
            img = _AppKit.NSImage.alloc().initWithContentsOfFile_(icns)
            if img is not None:
                _AppKit.NSApplication.sharedApplication().setApplicationIconImage_(img)
    except Exception:
        pass


def _open_dialog():
    if not _webview.windows:
        return
    paths = _webview.windows[0].create_file_dialog(_webview.OPEN_DIALOG,
                                                   allow_multiple=False)
    if paths:
        post("open_target", {"path": paths[0], "args": []})


def _build_menu():
    return [
        Menu("File", [
            MenuAction("Open Target…", _open_dialog),
            MenuAction("Attach to Process…", lambda: post("ui", {"action": "attach"})),
            MenuSeparator(),
            MenuAction("Save State", lambda: post("save_state")),
        ]),
        Menu("Debug", [
            MenuAction("Continue", lambda: post("cont")),
            MenuAction("Step Into", lambda: post("step_in")),
            MenuAction("Step Over", lambda: post("step_over")),
            MenuAction("Step Out", lambda: post("step_out")),
            MenuSeparator(),
            MenuAction("Toggle Breakpoint at PC", lambda: post("toggle_bp")),
            MenuAction("Interrupt", lambda: post("interrupt")),
            MenuAction("Restart", lambda: post("restart")),
        ]),
        Menu("Breakpoints", [
            MenuAction("Toggle at PC", lambda: post("toggle_bp")),
            MenuAction("Remove All", lambda: post("run_cmd", {"cmd": "breakpoint delete -f"})),
        ]),
        Menu("Trace", [
            MenuAction("Toggle Tracer", lambda: post("trace_toggle")),
            MenuAction("Cycle Scope", lambda: post("trace_scope")),
            MenuAction("Clear", lambda: post("trace_clear")),
            MenuAction("Filter Categories…", lambda: post("ui", {"action": "trace_filter"})),
            MenuSeparator(),
            MenuAction("Trace Whole Fork Tree", lambda: post("fork_trace")),
        ]),
        Menu("Defenses", [
            MenuAction("Open Defenses Menu…", lambda: post("ui", {"action": "defenses"})),
            MenuAction("Enable ALL Anti-Debug", lambda: post("defense", {"key": "all_anti"})),
        ]),
        Menu("View", [
            MenuAction("Command Palette…", lambda: post("ui", {"action": "palette"})),
            MenuAction("Find in Memory…", lambda: post("ui", {"action": "find"})),
            MenuAction("Go to Address…", lambda: post("ui", {"action": "goto"})),
            MenuAction("Snap Disasm to PC", lambda: post("snap_pc")),
            MenuAction("Scan Live Strings", lambda: post("scan_strings")),
        ]),
    ]


def _run_selftest(url: str, out_path: str) -> None:
    """Headless check (no window): confirm the backend launched a target.
    Writes PASS/FAIL to out_path. Enabled via MACDBG_SELFTEST=<path>."""
    res = "FAIL: no state"
    try:
        r = urllib.request.urlopen(url + "events", timeout=10)
        deadline = time.time() + 10
        buf = b""
        while time.time() < deadline:
            ch = r.read(1)
            if not ch:
                break
            buf += ch
            if buf.endswith(b"\n\n"):
                for line in buf.split(b"\n"):
                    if line.startswith(b"data: "):
                        try:
                            obj = json.loads(line[6:])
                        except Exception:
                            continue
                        if obj.get("t") == "state" and obj.get("pc"):
                            res = "PASS pc={:#x} rows={}".format(
                                obj["pc"], len(obj.get("disasm", [])))
                            raise StopIteration
                        if obj.get("t") == "console" and "launch failed" in obj.get("text", ""):
                            res = "FAIL: " + obj["text"]
                            raise StopIteration
                buf = b""
    except StopIteration:
        pass
    except Exception as e:
        res = "FAIL: " + str(e)
    with open(out_path, "w") as f:
        f.write(res)


def _log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def _try_native_window() -> bool:
    """Show the native pywebview window. Returns True if it ran (and was later
    closed); False if pywebview is unavailable/fails so the caller can fall back
    to a browser window."""
    import traceback
    if not _HAVE_NATIVE or _webview is None:
        return False
    try:
        _set_app_name("macdbg")
        _set_dock_icon()
        # Drop pywebview's default Edit / View menus — we have our own native
        # menus, and text copy is handled in-page (Cmd+C on a selection).
        try:
            _webview.settings['SHOW_DEFAULT_MENUS'] = False
        except Exception:
            pass
        _webview.create_window("macdbg", _URL, width=1680, height=1040,
                               min_size=(1100, 720), background_color="#1b1b1c")
        try:
            menu = _build_menu()
        except Exception:
            menu = None
        if menu is not None:
            _webview.start(menu=menu)
        else:
            _webview.start()
        return True
    except Exception:
        _log("[gui] native window failed:\n" + traceback.format_exc())
        return False


def _browser_open(url: str):
    """Open the UI in a chromeless Chromium window, else Safari. Returns a Popen
    to wait on, or None."""
    for b in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
              "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"):
        if os.path.isfile(b):
            prof = os.path.expanduser("~/.macdbg/gui-chrome")
            os.makedirs(prof, exist_ok=True)
            return subprocess.Popen(
                [b, "--app=" + url, "--user-data-dir=" + prof, "--no-first-run",
                 "--no-default-browser-check", "--window-size=1680,1040"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["/usr/bin/open", "-a", "Safari", url],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return None


def main() -> int:
    global _URL
    args = [a for a in sys.argv[1:] if not a.startswith(("-psn_", "-NS", "-Apple"))]
    be, port = _start_backend(args)
    if not port:
        sys.stderr.write("macdbg backend failed to start.\n")
        if be:
            be.terminate()
        return 1
    _URL = "http://127.0.0.1:{}/".format(port)
    sys.stderr.write("macdbg backend on {}\n".format(_URL))

    selftest = os.environ.get("MACDBG_SELFTEST")
    if selftest:
        _run_selftest(_URL, selftest)
        be.terminate()
        return 0

    try:
        if _try_native_window():
            return 0
        # Native window unavailable/failed — fall back to a browser window so the
        # user still gets a working UI rather than nothing.
        sys.stderr.write("[gui] falling back to a browser window\n")
        proc = _browser_open(_URL)
        if proc is not None:
            proc.wait()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        be.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
