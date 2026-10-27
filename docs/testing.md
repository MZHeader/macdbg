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

## Go and Rust network regression tests

The optional language fixtures read and write a benign marker file, then POST a fixed form to loopback or `connectivity.macdbg.invalid`. They disable proxies and use HTTP/1.1. TLS verification stays enabled; the tests generate a temporary CA and server certificate and explicitly supply that CA to the clients. Nothing is installed in the system trust store.

Build with the installed ARM64 Go and Rust toolchains. Cargo downloads the locked test dependencies on the first build. Keep binaries and caches together outside the checkout:

```sh
export MACDBG_REVIEW_DIR=/private/tmp/macdbg-languages
mkdir -p "$MACDBG_REVIEW_DIR/build"
make -C tests/integration BUILD="$MACDBG_REVIEW_DIR/build"
GOCACHE="$MACDBG_REVIEW_DIR/go-cache" go build \
  -o "$MACDBG_REVIEW_DIR/build/go_fixture" tests/integration/language_fixtures/go_fixture.go
CARGO_HOME="$MACDBG_REVIEW_DIR/cargo-cache" CARGO_TARGET_DIR="$MACDBG_REVIEW_DIR/rust-target" \
  cargo build --locked --release --manifest-path tests/integration/language_fixtures/rust/Cargo.toml
export MACDBG_GO_FIXTURE="$MACDBG_REVIEW_DIR/build/go_fixture"
export MACDBG_RUST_FIXTURE="$MACDBG_REVIEW_DIR/rust-target/release/macdbg-review-rust"
export MACDBG_FIXTURE_DIR="$MACDBG_REVIEW_DIR/build"
export MACDBG_STATE_DIR="$MACDBG_REVIEW_DIR/state"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$(xcrun lldb -P):$PWD"
/usr/bin/python3 -m unittest tests.integration.test_language_network \
  tests.integration.test_environment_tools -v
```

The language suite checks full file paths longer than 256 bytes, HTTP and HTTPS request headers/body bytes, HTTP response bytes with return capture, exact-domain HTTP/HTTPS simulation, and rejection of an untrusted responder certificate. It verifies the server's actual received bytes and checks that one request produces one assembled request record, including when return capture is enabled. Language tests skip when their fixture environment variables are absent. The environment suite also checks invalid TLS configuration rollback and shutdown with a stalled TLS handshake.

The 2026-10-27 review used ARM64 macOS 27.0.1, Go 1.27.3, Rust 1.98.1, reqwest 0.12.28 and rustls 0.23.46. It found and fixed missing Go file events when LLDB could not unwind libc trampolines, missing Rust plaintext at demangled/vectored writer symbols, duplicate outbound requests on return events, and 256-byte pathname truncation. The HTTPS responder was added in that review.

## Connectivity simulation and capture boundaries

Configure while the target is paused, before its DNS lookup. A headless HTTPS example is:

```sh
./agent.sh cmd SESSION offline_network --json '{"rules":[{"host":"connectivity.macdbg.invalid","port":443,"body":"fixture-online","tls_cert":"/absolute/server.crt","tls_key":"/absolute/server.key"}]}'
./agent.sh cmd SESSION tracer_enable
./agent.sh cmd SESSION continue --timeout 15
./agent.sh cmd SESSION trace_hits
./agent.sh cmd SESSION analysis_events
```

The GUI exposes the same certificate/key fields in **Environment → Offline connectivity**. Port 443 requires TLS credentials. For TLS on another port, specify `"tls":true`. Certificates must cover the original hostname and be trusted by the target. This is a real TLS handshake, not a certificate/pinning bypass. `analysis_events` records the configured hostname, redirection and local response; colocated API entry hooks can see rewritten DNS/connect arguments. Unmatched traffic follows the normal stack.

| Surface | Verified coverage / boundary |
| --- | --- |
| C/libc, Go and Rust file access | Observed paths through supported libc calls, including Go calls with unavailable caller stacks. Events describe attempts; enable returns for results. |
| Foundation HTTP/HTTPS capture | Request URL, headers and in-memory body captured before encryption. Streams are not consumed. |
| Go `crypto/tls` and Rust rustls | HTTP/1.1 request plaintext when writer symbols resolve. Rust scalar/vectored writes share the connection's sink identity. |
| Incoming traffic | Optional hardware return hooks capture socket read buffers and supported C TLS read buffers. Go/Rust decrypted TLS response hooks are not implemented. |
| HTTP/HTTPS simulation | Exact `getaddrinfo` names and IPv4 `connect` destinations. Go's default Darwin resolver and reqwest's tested resolver work; custom DNS, `connectx`/Network.framework and proxy routing are not redirected. |
| Stripping/optimization | Libc file/socket hooks remain useful. Internal TLS plaintext hooks need surviving symbols and non-inlined code; check `tracer_config.active_hooks` location counts. No generic stripped-Go/rustls plaintext recovery is provided. |
| Protocols and isolation | HTTP/2, QUIC and application encryption are not decoded. This feature is not a network sandbox. |

The Go internal ABI and Rust native ABI are not stable contracts; re-run these fixtures when toolchains or TLS libraries change. References: https://go.dev/src/cmd/compile/abi-internal and https://doc.rust-lang.org/reference/items/functions.html#extern-function-qualifier.

After the run, `MACDBG_STATE_DIR=/private/tmp/macdbg-tests ./agent.sh list` should have no live sessions. The fixture build in `tests/integration/build/` and the temporary session directory are disposable. `make -C tests/integration clean` removes the fixture build.

For a native GUI check, launch `GUI/run.sh tests/integration/build/workflow_fixture`. Add a breakpoint, quit with Cmd+Q, and reopen the same target: the breakpoint should return and the old backend should have exited. Repeat using the window close button. Confirm Go To accepts `workflow_marker` and `$pc + 4`, and a finished target shows Exited with Restart available.

To regenerate the shipped fork-tree interposer:

```sh
clang -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 -std=c11 -O2 -Wall -Wextra -dynamiclib macdbg/native/interpose.c -o macdbg/native/interpose.dylib
```
