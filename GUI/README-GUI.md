# macdbg GUI

A macOS **GUI** for macdbg, styled after x64dbg / WinDbg. It reuses macdbg's
existing LLDB engine (`macdbg/core/`) — the same engine the TUI and the headless
agent drive — so it has the full capability set: debugging, the syscall/network
tracer, the anti-anti-debug bypass suite, fork/exec sandboxing, watches,
comments, command palette, and per-binary persistence.

## Why two processes

LLDB's Python bindings load **only** under `/usr/bin/python3` (Python 3.9, CLT),
whose only bundled GUI toolkit is Apple's deprecated **Tk 8.5.9** — which renders
blank windows on modern macOS. So a single-process native GUI is impossible. The
UI is therefore split:

- **Backend** (`GUI/serve.py` + `GUI/server/`) runs under system Python 3.9, owns
  the debugger, and exposes it over a localhost HTTP + Server-Sent-Events bridge.
- **Native window** (`GUI/gui.py`) runs under Python 3.13 with **pywebview**
  (WKWebView). It spawns the backend and renders the UI in a real native macOS
  window — own window, own menu bar, normal close/quit. No browser.

It behaves like one app; two processes is just an implementation detail forced by
the lldb / Python-version constraint.

## Requirements

- Xcode Command Line Tools (for lldb).
- For the native window: a Python 3.13 with pywebview — `python3 -m pip install pywebview`.
  Without it, the launcher falls back to a chromeless Chromium / Safari browser window.

## Run

```sh
GUI/run.sh                 # start screen (File → Open / Attach)
GUI/run.sh test/hello      # launch a target
GUI/run.sh --attach 12345  # attach to a running pid
```

Double-clickable app:

```sh
GUI/build_app.sh           # produces GUI/macdbg.app
open GUI/macdbg.app
open GUI/macdbg.app --args test/hello
```

`run.sh` prefers the native pywebview window; if no pywebview Python is found it
falls back to `GUI/main.py`, which opens the UI in a chromeless Chromium `--app`
window (or a Safari tab).

## Layout

x64dbg-style: a toolbar, then Disassembly (left) beside Registers over a
Memory/Stack/Watch tab group; a bottom row of Breakpoints / Call Stack / Strings
/ Patches / Threads / Modules / Trace tabs beside the Console.

- **Disassembly** — control-flow arrow gutter (green/red on the live pc branch),
  breakpoint dots, ▶ pc marker, syntax highlighting, inline adrp-deref hints,
  lldb comments, gold user comments, function banners.
- **Registers** — changed values in red, pointer/string annotations, flag decode.
- **Memory / Stack / Watch** — hex + ascii with focus highlighting; Memory has an
  address bar; watches stay pinned as you step.
- **Console** — lldb command entry with history.

## Keys

| Key | Action | Key | Action |
|-----|--------|-----|--------|
| F7 / F8 / F6 | Step in / over / out | Ctrl/⌘+T | Toggle tracer |
| F9 | Continue | Ctrl/⌘+Y | Cycle trace scope |
| F2 | Toggle breakpoint at pc | Ctrl/⌘+K | Clear trace |
| F5 | Snap disasm to pc | Ctrl/⌘+D | Defenses menu |
| Ctrl/⌘+R | Restart | Ctrl/⌘+B | Interrupt |
| Ctrl/⌘+G | Go to address | Ctrl/⌘+F | Find in memory |
| Ctrl/⌘+P | Command palette | | |

Right-click any pane for its context menu (follow, edit value/bytes, set PC,
run-to-here, add comment, pin to a watch, edit breakpoint commands/condition,
etc.). The **Defenses** button exposes every anti-anti-debug bypass as a live
checkbox; fork/exec interception pops a decision dialog per call.

## Architecture

```
GUI/
  run.sh             launcher: native window if pywebview present, else browser
  gui.py             native window (Python 3.13 + pywebview); spawns the backend
  serve.py           backend entry (Python 3.9 + lldb); prints its port, blocks
  main.py            browser fallback (chromeless Chromium / Safari)
  build_app.sh       assembles macdbg.app
  server/
    engine.py        Engine: Debugger+Tracer, worker thread serialising all LLDB
                     access, ported stop-orchestration, snapshot builder,
                     command dispatch, SSE event emit
    snapshot.py      core render data (DisasmRow/RegRow/bytes) -> JSON
    syntax.py        arm64 mnemonic/operand tokeniser (Tk-free)
    httpd.py         stdlib HTTP: GET / , GET /events (SSE), POST /cmd
  web/
    index.html       self-contained x64dbg-style frontend
```

LLDB stop/output events arrive on the EventPump thread and are serialised onto a
single engine worker thread, which decides what each stop means (user-step
completion, fork-shield, anti-debug auto-continue, tracer auto-continue, or a
real stop) and pushes a JSON snapshot to the browser over SSE. Commands flow the
other way as `POST /cmd`.

Runs unsigned locally — launch + attach work because LLDB spawns Apple-signed
`debugserver`.
