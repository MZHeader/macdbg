# ARM64 analysis workflow implementation plan

Scope agreed on 2026-10-21: close the practical gaps identified in the x64dbg comparison, add historical debugging and an LLM-readable execution log, and validate on benign local ARM64 fixtures. README and release notes are excluded.

## 1. Instruction recording and Time Machine

- Record instruction bytes, symbols/module identity, thread and stop identity, full register state, register changes, decoded memory accesses, branch destinations and debugger interventions.
- Provide bounded automatic instruction stepping with count/time/address limits, cancellation, and interruption at real breakpoints, signals and exceptions.
- Store history on disk; browse older records without reading live memory. Search instructions, addresses, values and memory accesses, including previous observed writes.
- Export a verbose JSONL log and a readable context report with provenance, coverage, gaps and target data explicitly identified as untrusted input. Reopen recordings after a session ends.
- Time Machine initially means historical inspection. True reverse execution needs deterministic scheduling and recorded/replayed syscalls, signals, mappings and external effects, or a VM snapshot/replay backend. Register/memory rollback is not advertised as process rewind.
- Acceptance: real ARM64 loads/stores/branches reproduce expected register and memory transitions; interrupted or unrecorded execution appears as gaps; imported history matches original records; browsing never mutates the target.

## 2. Assembly and persistent patching

- Add an ARM64 assembly preview/editor with address-aware branches, compiler diagnostics, before/after bytes and disassembly, and verified application through existing undo.
- Export patches to a separate binary with address-to-file validation and original-byte checks. Preserve the source, reject unmappable/runtime-only patches, and report signing implications.
- Export/import portable patch manifests bound to the original file hash; validate the complete patch set before applying it.
- Acceptance: assemble and execute benign modified functions; branch targets match the requested address; export bytes and manifest replay match; incorrect originals, overlaps and runtime-only patches fail safely.

## 3. Code navigation

- Extend references beyond adjacent ADRP pairs using conservative basic-block constant propagation, including address construction and pointer loads. Label direct, inferred and observed edges separately.
- Add configurable graph/range budgets, continuation and trace-derived coverage/indirect destinations. Keep unresolved edges and incomplete scans visible.
- Acceptance: fixtures include non-adjacent address formation, clobbers, branches, indirect calls and tables; no stale constants survive control-flow boundaries or unknown writes.

## 4. Signals, processes and anti-debug coverage

- Expose native LLDB signal delivery/stop policies so real signal handlers can receive OS-generated context instead of relying on simple-handler emulation.
- Add explicit tracking of new/changed executable ranges for inline syscall coverage, reporting byte limits, missed regions and hardware-slot exhaustion.
- Add opt-in offline connectivity simulation for configured domains: real local TCP/HTTP responses, selected reachability API overrides, and traceable DNS/connect redirection. Report unsupported DNS stacks and TLS certificate validation; never turn every failed connection into a fictitious success.
- Add related-process visibility and independently controlled child debug sessions, preserving the parent session. Do not equate a late child attach with interception before its first instruction.
- Acceptance: genuine SA_SIGINFO handlers, late executable mappings, child attach/switch/detach and resource exhaustion retain real stops and clear ownership.

## 5. Reliability and delivery

- Add repeatable lifecycle, concurrency and failure-path integration tests for the new workflows, including recording cancellation, restart, export failures and detached/terminated targets.
- Run focused tests, the existing full suite and native UI checks; investigate failures rather than hiding them with retries.
- Remove generated binaries and temporary session/build data. Commit and push only intended source, test and design files.

Passing fixtures demonstrates the tested behavior. It does not establish universal anti-debug coverage, arbitrary obfuscation recovery or x64dbg's accumulated real-world maturity.

## Delivery and validation — 2026-10-21

The implementation covers all five work areas above, including the added offline connectivity and LLM-context requirements. Usage and the reverse-execution design boundary are in `historical-debugging.md`.

- Full regression suite: **389 tests passed** in 695.931 seconds. Additional focused checks covered the final short-decode coverage reporting and recorder shutdown/export ordering. JavaScript syntax and workspace model checks passed.
- Native UI: bounded recording, historical register/memory inspection, reopening history after process exit, LLM context export, assembly preview/application, signed binary export, and configured offline HTTP gating were exercised. The patched fixture returned 42; the connectivity fixture received its local response and exited with code 0.
- Hardware stop reliability: ten image-enumeration stress runs completed, exercising four recoveries of retired hardware return stops. Twenty API-trace runs retained all three entries and their three returns. Recovery executes a checked instruction; it does not skip PC, retain idle return sites, or swallow unrelated traps.
- Only benign ARM64 fixtures and loopback responders were used. Generated binaries, patched copies and session/log output were isolated in a disposable directory for removal after validation.

Remaining boundaries are deliberate and visible: Time Machine is historical inspection, child debugging is independent late attach, static analysis is conservative and bounded, and offline connectivity does not fabricate pinned TLS or provide a network sandbox. These are not claims of universal protection bypass or deterministic reverse execution.
