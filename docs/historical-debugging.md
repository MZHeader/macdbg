# Historical debugging and execution context

## What Time Machine does

Time Machine records single-instruction steps to a private, append-only JSONL file in the sample's dumps directory. Record starts a new history; Trace Run also starts recording if necessary. Trace Run stops on its instruction/time/address limit, a user breakpoint, signal, exception, thread change or recording error. Pause cancels automatic stepping. Ordinary Continue is explicitly recorded as a gap, not as an instruction trace.

Each instruction contains its bytes, mnemonic, operands, module, symbol, thread, stop ID, registers before execution, changes at the following stop, and captured memory before/after. Supported memory operands include ordinary scalar, SIMD and pair loads/stores, including indexed addressing. Atomic/exclusive/SVE accesses are not inferred. Optional captured ranges supplement operand memory. Other threads and kernel work can run between stops; records do not establish exclusive causation for every observed change.

The viewer reads saved records, not current process registers or memory. Its back/forward buttons and slider move the historical cursor without changing the live CPU. PC/value/text/access filters and Previous observed write help track a buffer or value through recorded execution. Following a historical address into the live CPU is a separate action; the code at that address may have changed since recording.

Limits are 100,000 records, 128 MiB per recording, four optional 4 KiB ranges, 500 results per query and 5,000 records scanned per search page. Recording stops when its limit is reached. No rolling eviction silently discards the beginning. An incomplete final line in an imported recording is rejected. Old recordings remain available after a restart or new recording.

## LLM context

The JSONL is the complete verbose log within those limits. Export LLM context creates a readable `.log` containing provenance, loaded modules, coverage and numbered records. Export up to 10,000 records per report to keep context windows manageable; the response identifies the next range. Target strings, symbol names and buffers are explicitly marked as untrusted data. No log is automatically uploaded or sent to a model.

Enable API Trace when API arguments/results are useful: its observed calls are also copied into the instruction recording. Defense interventions, simulated network responses, debugger edits, raw command boundaries and execution gaps are recorded alongside instructions. A useful analysis prompt asks for conclusions tied to record numbers, separates observed behavior from inference, and asks which missing paths would change the conclusion.

Headless examples (with an existing session named `inspect`):

```sh
./agent.sh cmd inspect instruction_trace --json '{"action":"start","vectors":true}'
./agent.sh cmd inspect instruction_trace_run --json '{"count":1000,"seconds":30}'
./agent.sh cmd inspect instruction_trace --json '{"action":"query","offset":0,"limit":100}'
./agent.sh cmd inspect instruction_trace --json '{"action":"export","start":1,"count":1000}'
./agent.sh cmd inspect instruction_trace --json '{"action":"stop"}'
```

The `open` action accepts `path`; `read` accepts a one-based `index`. `query` accepts `text`, `address`, `access` (`read`, `write`, `snapshot`) and an optional exclusive `before` index for reverse search. Trace Run's optional `until` is an aligned numeric address. `status` includes recorder status while another client is tracing; `interrupt` cancels it.

## True reverse execution: design boundary

Restoring PC, registers and selected bytes does not rewind a process. A correct rewind must account for all threads, mapping changes, signals and exception contexts, kernel objects, file offsets, randomness, clocks, sockets and effects outside the process. Fork introduces independent address spaces and ownership; code signing and platform debug restrictions add further constraints on macOS. This implementation deliberately offers no misleading “restore execution” button.

Two plausible future backends are deterministic record/replay (control scheduling and intercept every nondeterministic input) and VM-level checkpoints/replay (restore the guest, devices and virtual disk together, with external networking isolated or recorded). Either requires a substantial execution backend beyond LLDB's ordinary process API. A checkpoint-only prototype should first prove identical replay on multi-threaded fixtures with signals, mappings, file I/O and child processes before being described as a reverse debugger. The current JSONL schema is useful analysis evidence, not a sufficient replay log.

## Assembly and patch export

Use Assemble in the CPU header or application actions. Enter ARM64 instructions and optional local labels; preview bytes/disassembly, then apply. Branches, ADR/ADRP and literal-load destinations use absolute addresses, resolvable symbols or local labels. Xcode's integrated assembler validates other instructions. Directives and unresolved relocations are rejected. An optional replacement span pads with NOPs. Applying a stale preview is refused; ordinary UI undo remains available before execution resumes.

Patches offers a separate binary export and a portable JSON manifest. Both require file-backed ranges whose original bytes match the unchanged source hash. Runtime-only mappings and relocated bytes are rejected. Export never overwrites a file. Optional ad-hoc signing signs only the copy and does not restore vendor identity, entitlements or trust. Import validates every manifest range before mutation and rolls back a failed application. Overlapping live edits are normalized to their earliest originals and latest replacements.

## Environment controls

Native signal policies configure LLDB's stop/deliver/notify behavior. Real Unix signals retain OS-generated `siginfo` and context; Mach exceptions and arbitrary BRK traps are not converted into Unix signals. The simple self-trap defense retains its original limitations.

Executable syscall monitoring rescans changed non-system executable regions at stops and supported mapping/protection/library API returns. Coverage is bounded to 256 KiB per region and 8 MiB per scan, with finite hardware breakpoint slots. Missing bytes or exhausted slots are surfaced as visible stops. Inline mapping syscalls that execute without an observed stop remain a coverage gap.

Related processes lists live descendants. Debug in new window gives a child an independent debugger, retaining the parent session. It is a late attach, not atomic follow-fork: child execution before attach may be missed, and platform attach restrictions still apply. Closing an attached session detaches; closing a launched session kills its target.

Offline connectivity is configured with literal domain rules, destination port, HTTP status/body and optional reachability overrides. Matching `getaddrinfo` calls resolve to synthetic loopback addresses; matching IPv4 `connect` calls go to a real local responder. Unmatched calls retain their normal behavior. This is not a network sandbox. Custom DNS, proxy stacks, direct syscalls, HTTPS certificate validation and pinned TLS require other handling. At most 64 KiB of scratch argument buffers remain until process exit so disabling a rule cannot free arguments still in use by a stopped thread. Every substitution is logged.

```sh
./agent.sh cmd inspect offline_network --json '{"enabled":true,"rules":[{"host":"connectivity.example.test","port":80,"status":204,"body":""}],"reachability":true}'
./agent.sh cmd inspect signal_policy --json '{"signal":"SIGUSR1","stop":false,"deliver":true,"notify":false}'
./agent.sh cmd inspect syscall_monitor --json '{"enabled":true}'
./agent.sh cmd inspect related_processes
```
