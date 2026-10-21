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

The historical-debugging tests are `tests.integration.test_instruction_trace` and `tests.integration.test_recording_lifecycle`: real register/memory transitions, bounded recording, previous-write search, saved history, interruption, restart, disk errors and GUI-worker deadlines. `tests.integration.test_patch_workflow` assembles and runs a changed fixture, exports a signed copy, replays a hash-bound manifest, and rejects stale previews and invalid originals. `tests.integration.test_environment_tools` checks native signal context, loopback HTTP simulation, reachability flags, late executable mappings, API-trace coexistence and independent child attachment. All generated copies and session data are temporary.

For builds outside the checkout, use `make -C tests/integration BUILD=/private/tmp/macdbg-check/build` and set `MACDBG_FIXTURE_DIR=/private/tmp/macdbg-check/build` when running tests. Keep `MACDBG_STATE_DIR` in the same disposable tree. Close native windows and stop test sessions before removing it.

`tests.test_http_capture` and `tests.test_network_capture` cover HTTP framing, payload limits, binary/form/JSON/multipart bodies, missing memory, socket/TLS lifecycle, and nested write observations. `tests.integration.test_http_capture` uses the ARM64 `http_fixture` and a loopback server to verify POST headers/body bytes through Foundation, separate upload data, unchanged body streams, split socket writes, and HTTPS. The HTTPS case creates a temporary test certificate; only that fixture's loopback HTTPS mode accepts its self-signed certificate. All server, certificate and session resources are cleaned by the tests.

After the run, `MACDBG_STATE_DIR=/private/tmp/macdbg-tests ./agent.sh list` should have no live sessions. The fixture build in `tests/integration/build/` and the temporary session directory are disposable. `make -C tests/integration clean` removes the fixture build.

For a native GUI check, launch `GUI/run.sh tests/integration/build/workflow_fixture`. Add a breakpoint, quit with Cmd+Q, and reopen the same target: the breakpoint should return and the old backend should have exited. Repeat using the window close button. Confirm Go To accepts `workflow_marker` and `$pc + 4`, and a finished target shows Exited with Restart available.

To regenerate the shipped fork-tree interposer:

```sh
clang -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 -std=c11 -O2 -Wall -Wextra -dynamiclib macdbg/native/interpose.c -o macdbg/native/interpose.dylib
```
