# macdbg GUI

## Launch

Use Apple Silicon and the Xcode Command Line Tools. Run these commands from the repository root.

```sh
GUI/run.sh                                  # open the workspace
GUI/run.sh /path/to/binary                  # launch a target
GUI/run.sh --attach 12345                   # attach to a running process
GUI/run.sh --stop-at loader /path/to/binary  # stop before initializers
```

You can also open the bundled `macdbg.app` from Finder or run `open macdbg.app --args /path/to/binary`. Keep the app in the checkout so it can find the launcher and debugger code. To rebuild the bundle, run `GUI/build_app.sh`.

### Native window

The launcher uses pywebview and WKWebView when it finds a Python with the native dependencies. Otherwise it opens the interface in Chromium or Safari. The launcher automatically checks for a virtual environment at `~/.macdbg/venv`.

```sh
python3 -m venv ~/.macdbg/venv
~/.macdbg/venv/bin/python3 -m pip install pywebview
```

Set `MACDBG_PYTHON` to use a specific Python interpreter. For an offline Mac, copy the ARM64 bundle that matches the interpreter's Python version from the [native-deps release](https://github.com/MZHeader/macdbg/releases/tag/native-deps). The command below installs the Python 3.13 bundle.

```sh
export MACDBG_PYTHON=/path/to/python3.13
GUI/get-native-deps.sh ./pywebview-macos-arm64-cp313.tar.gz
```

If the app fails to open, check `~/.macdbg/launch.log`.

## Workspace

- **CPU** keeps disassembly, registers, the stack and a four-tab dump pane in view. Select an instruction for its details. Right-click a row to follow an address, edit a value or add a comment.
- **Breakpoints** manages software and hardware breakpoints and memory watchpoints. Breakpoints can have conditions and LLDB commands to run on hit. Breakpoints, comments and bookmarks are saved per binary.
- **Graph**, **Symbols** and **References** show the selected function's control flow, loaded symbols and references in the chosen module.
- **API Trace** records supported file, process and network calls. Use **Configure** to select hooks and enable return capture. Open **Details** on a network row for captured headers and bodies, or use **Export JSONL** for the full trace. Captures are capped at 64 KiB for headers and 256 KiB for bodies. See the [testing guide](../docs/testing.md#connectivity-simulation-and-capture-boundaries) for supported APIs and protocols.
- **Console** accepts LLDB commands and supports history and tab completion. **Actions** searches debugger actions and opens the separate LLDB command palette.

See [historical debugging](../docs/historical-debugging.md) for Time Machine, patch export and environment controls.

## Default shortcuts

| Key | Action | Key | Action |
| --- | --- | --- | --- |
| F7 / F8 / F6 | Step in / over / out | ⌘T | Toggle API Trace |
| F9 | Continue | ⌘Y | Cycle trace scope |
| F2 | Toggle breakpoint | ⌘K | Clear trace |
| F5 | Return disassembly to the PC | ⌘D | Open Defenses |
| F3 | Open target | ⌘B | Interrupt |
| ⌘R | Restart | ⌘G | Go to address or symbol |
| ⌘F | Find in memory | ⌘P | Open Actions |

## How it runs

`GUI/serve.py` starts the backend with system Python and Xcode's LLDB bindings. One debugger worker handles commands and stop events. The frontend in `GUI/web/` sends commands over localhost HTTP and receives snapshots over Server-Sent Events. The HTTP bridge requires a per-session credential. `GUI/gui.py` hosts the frontend in a native window, and `GUI/main.py` opens it in a browser.
