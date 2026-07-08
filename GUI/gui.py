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

_APP_VERSION = "1.1.0"
_about_handler = None  # keep a strong ref: NSMenuItem doesn't retain its target

_REPO_URL = "https://github.com/MZHeader/macdbg"


def _about_credits():
    """Attributed string for the About panel body: the tagline plus a clickable
    link to the GitHub repo."""
    try:
        desc = ("GUI Debugger for macOS.\n"
                "For reverse engineers and malware analysts.\n\n")
        link = "github.com/MZHeader/macdbg"
        s = _Foundation.NSMutableAttributedString.alloc().initWithString_(desc + link)
        whole = _Foundation.NSMakeRange(0, s.length())
        para = _AppKit.NSMutableParagraphStyle.alloc().init()
        para.setAlignment_(_AppKit.NSTextAlignmentCenter)
        s.addAttribute_value_range_(_AppKit.NSParagraphStyleAttributeName, para, whole)
        s.addAttribute_value_range_(_AppKit.NSFontAttributeName,
                                    _AppKit.NSFont.systemFontOfSize_(11), whole)
        s.addAttribute_value_range_(_AppKit.NSLinkAttributeName, _REPO_URL,
                                    _Foundation.NSMakeRange(len(desc), len(link)))
        return s
    except Exception:
        return None


if _HAVE_NATIVE:
    class _AboutHelper(_Foundation.NSObject):
        """Standard About panel with macdbg's identity instead of Python's."""
        def showAboutPanel_(self, sender):
            try:
                opts = {"ApplicationName": "macdbg", "Version": ""}
                if _APP_VERSION:
                    opts["ApplicationVersion"] = _APP_VERSION
                icns = os.path.join(GUI, "macdbg.icns")
                if os.path.exists(icns):
                    img = _AppKit.NSImage.alloc().initWithContentsOfFile_(icns)
                    if img is not None:
                        opts["ApplicationIcon"] = img
                credits = _about_credits()
                if credits is not None:
                    opts["Credits"] = credits
                _AppKit.NSApplication.sharedApplication() \
                    .orderFrontStandardAboutPanelWithOptions_(opts)
            except Exception:
                pass
else:
    _AboutHelper = None


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
    """Give the menu bar / About panel macdbg's identity instead of Python's:
    the app name, and clear the Python Software Foundation copyright the About
    panel otherwise pulls from the interpreter's bundle."""
    try:
        bundle = _Foundation.NSBundle.mainBundle()
        for info in (bundle.infoDictionary(), bundle.localizedInfoDictionary()):
            if info is None:
                continue
            try:
                info["CFBundleName"] = name
                info["NSHumanReadableCopyright"] = ""
            except Exception:
                pass
    except Exception:
        pass
    try:
        # Also the process name — the About/Hide/Quit panel titles fall back to it.
        _Foundation.NSProcessInfo.processInfo().setProcessName_(name)
    except Exception:
        pass


def _run_on_main(fn) -> None:
    """Run fn on the AppKit main thread (menu/UI mutations must happen there)."""
    try:
        _Foundation.NSOperationQueue.mainQueue().addOperationWithBlock_(fn)
    except Exception:
        try:
            fn()
        except Exception:
            pass


def _rename_app_menu(name: str = "macdbg") -> None:
    """AppKit builds the application (Apple) menu from the process name — which is
    'Python' here — so the items read 'About Python', 'Hide Python', 'Quit
    Python'. Setting CFBundleName doesn't touch those already-built items, so walk
    the menu once the app is running and swap 'Python' for the app name."""
    try:
        app = _AppKit.NSApplication.sharedApplication()
        main = app.mainMenu()
        if main is None or main.numberOfItems() == 0:
            return
        app_item = main.itemAtIndex_(0)
        app_item.setTitle_(name)
        sub = app_item.submenu()
        if sub is None:
            return
        sub.setTitle_(name)
        for i in range(sub.numberOfItems()):
            it = sub.itemAtIndex_(i)
            t = it.title()
            if t and "Python" in t:
                it.setTitle_(t.replace("Python", name))
        _wire_about(sub)
    except Exception:
        pass


def _wire_about(sub) -> None:
    """Point the 'About' item at our own panel so it shows macdbg's name/version/
    icon instead of the Python framework's."""
    global _about_handler
    if _AboutHelper is None:
        return
    try:
        for i in range(sub.numberOfItems()):
            it = sub.itemAtIndex_(i)
            if (it.title() or "").startswith("About"):
                _about_handler = _AboutHelper.alloc().init()
                it.setTarget_(_about_handler)
                it.setAction_("showAboutPanel:")
                break
    except Exception:
        pass


def _apply_identity_on_main() -> None:
    """Set the dock icon (again — AppKit resets it during launch, so before the
    run loop is too early) and fix the app menu. Must run on the main thread."""
    _set_dock_icon()
    _rename_app_menu()


def _after_start(*_args) -> None:
    """Runs once the GUI loop is up — via webview.start's func AND the window
    'shown' event (belt and suspenders across pywebview versions). The dock icon
    and app menu exist by now, so apply our identity on the main thread.
    Idempotent, so firing from both hooks is harmless."""
    _run_on_main(_apply_identity_on_main)


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
        win = _webview.create_window("macdbg", _URL, width=1680, height=1040,
                                     min_size=(1100, 720), background_color="#1b1b1c")
        try:
            win.events.shown += _after_start  # 2nd trigger; some pywebview builds
        except Exception:                     # ignore start()'s func argument
            pass
        try:
            menu = _build_menu()
        except Exception:
            menu = None
        if menu is not None:
            _webview.start(_after_start, menu=menu)
        else:
            _webview.start(_after_start)
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
