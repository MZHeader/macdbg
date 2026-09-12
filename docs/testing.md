# Testing macdbg

Tests use benign, locally compiled fixtures. Run on an authorized macOS host with Xcode command-line tools; no malware or external network endpoint is needed.

Build the fixtures:

```sh
make -C tests/integration
```

Use system Python and LLDB's bundled Python bindings. Keep generated session data in a short disposable path:

```sh
export PYTHONPATH="$(xcrun lldb -P):$PWD"
export MACDBG_STATE_DIR=/private/tmp/macdbg-tests
export PYTHONDONTWRITEBYTECODE=1
/usr/bin/python3 -m unittest discover -s tests -t . -v
```

Integration tests start and stop their own LLDB sessions. The workflow tests cover classic exec decisions, early initializers, process states, persistence, navigation, HTTP credentials, and interposer semantics. Existing integration modules cover cloak identity and integrity, automatic clocks, timing rules, OSA execution, and framework interactions.

After the run, `MACDBG_STATE_DIR=/private/tmp/macdbg-tests ./agent.sh list` should have no live sessions. The fixture build in `tests/integration/build/` and the temporary session directory are disposable. `make -C tests/integration clean` removes the fixture build.

For a native GUI check, launch `GUI/run.sh tests/integration/build/workflow_fixture`. Add a breakpoint, quit with Cmd+Q, and reopen the same target: the breakpoint should return and the old backend should have exited. Repeat using the window close button. Confirm Go To accepts `workflow_marker` and `$pc + 4`, and a finished target shows Exited with Restart available.

To regenerate the shipped fork-tree interposer:

```sh
clang -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 -std=c11 -O2 -Wall -Wextra -dynamiclib macdbg/native/interpose.c -o macdbg/native/interpose.dylib
```
