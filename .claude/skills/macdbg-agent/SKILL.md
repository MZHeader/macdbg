---
name: macdbg-agent
description: Drive the macdbg LLDB wrapper as a headless debugger from Claude — launch/attach a macOS binary, set breakpoints, step, read/write memory and registers, and toggle anti-anti-debug bypasses (PT_DENY_ATTACH, Mach exception ports, fork/exec interception), all via JSON commands over agent.sh instead of the interactive Textual TUI. Use this whenever the user wants Claude itself to debug, trace, or reverse-engineer a macOS binary in this repo (or any target binary/pid) rather than just editing macdbg's own source.
---

# macdbg headless agent

macdbg is normally a full-screen Textual TUI (`./macdbg.sh <binary>`) that a
human drives interactively. For Claude to drive it directly, this repo has a
second, headless entry point — `./agent.sh` — that runs the same LLDB-backed
`Debugger` core (`macdbg/core/debugger.py`) behind a small JSON protocol
instead of the TUI. Always use `./agent.sh` for agent-driven debugging; do
not try to script `./macdbg.sh` itself (it blocks the terminal in a Textual
event loop and has no non-interactive mode).

Everything below assumes the current directory is the macdbg repo root
(where `agent.sh` lives) and macOS with Xcode command line tools (`lldb`)
installed. This only works on macOS — the whole tool is LLDB/Mach-O specific.

## Mental model

`agent.sh start` launches a background daemon process that owns one live
LLDB session (one target, one or more threads). All later commands
(`agent.sh cmd <session> <command>`) talk to that daemon over a local Unix
socket and return JSON. The daemon keeps running — with breakpoints,
register state, etc. all intact — between your tool calls, until you
explicitly `agent.sh stop <session>`. **Always stop a session when you're
done with it** — it holds a live child process and an LLDB debugger object
open until then.

Commands that resume execution (`continue`, `step_in`, `step_over`,
`step_out`, `step_in_source`, `step_over_source`, `decide_fork`,
`decide_exec`) block until the process reaches the next genuine stop, exits,
or hits an interactive fork/exec decision point. Anti-debug and tracer
breakpoint hits are handled and auto-continued transparently — you only see
"real" stops (your own breakpoints, step completions, signals, exceptions).

## Starting a session

```
./agent.sh start --session <name> [--attach <pid>] <program> [args...]
```

`--session`, `--attach`, and `--boot-timeout` are global options and **must
come before the program path** — anything after the program path (including
flags) is passed to the target binary itself, not parsed by macdbg-agent.
Giving both a program path and `--attach` is rejected outright rather than
silently picking one.

```
./agent.sh start --session s1 ./test/hello
./agent.sh start --session s2 --attach 12345
```

Session names are plain identifiers only — no `/`, no `..`, max 40 characters
(the control socket's path has a fixed OS limit). Omit `--session` to get an
auto-generated one.

The response includes a `boot` object: the initial console output and
either an `event: "stop"` (stopped at the entry point, ready to go) or
`event: "exited"` (the binary ran to completion before you could do
anything — rare, usually means it exited during startup).

## Sending commands

```
./agent.sh cmd <session> <command> [--json '{"arg": "value"}'] [--timeout SECONDS]
```

The response is one JSON object, always with `"ok": true|false`. Resuming
commands additionally include `event` (`stop` / `exited` / `running` /
`pending_decision` / `terminated`), a `console` field with any buffered
lldb/child stdout+stderr text collected since the last drain, and a `stop`
or `exit` object describing what happened.

`--timeout` bounds how long a resume command waits for the *next* stop
before giving up and returning `event: "running"` (the process is still
going — call `wait` again, or `interrupt` to force a stop). Omit it to
block indefinitely (fine for short-running code; risky for a target that
might genuinely loop forever — see Interrupting below).

For non-resume commands, `--timeout` instead bounds how long the client
waits for a response at all (protects against a wedged daemon) — it
defaults to 60s, generous enough for the slow ones (a `memory_search` with
`scope: "all"` or a `scan_live_strings` over a large process can
legitimately take tens of seconds); pass an explicit `--timeout` to raise it
further if a scan needs more than that. `--timeout 0` on a non-resume
command means "fail almost immediately" (a ~0.01s floor), not "wait
forever" — omit `--timeout` entirely for the 60s default instead.

## Command reference

Lifecycle / status:
- `status` — process state, pc, pending decision, tracer state. Safe to call concurrently while a **resume** command (`continue`/`step_*`/`wait`/`decide_*`) is mid-flight from a separate `agent.sh cmd` invocation — answered on that command's next poll tick. It does *not* get answered concurrently during a slow plain command (see Known limitations).
- `restart` — kill and relaunch the same target (not available when attached).
- `interrupt` — force-stop a running process. Same concurrency scope as `status` above: works while a resume command is in flight, not during a slow plain command.
- `save` — persist breakpoints to `~/.macdbg/<binary>-<sha>/state.json` (also happens automatically on `stop`).

Execution control (all take optional `{"timeout": N}`):
- `continue`, `step_in` (single instruction), `step_over`, `step_out`, `step_in_source`, `step_over_source`, `wait` (keep waiting without issuing a new resume — use after a `running` timeout).

Breakpoints:
- `breakpoint_toggle {"addr": N}` — add if absent, remove if present, at an absolute load address. Address-only — to break by symbol name (e.g. a libSystem/imported function like `pthread_create` or `getaddrinfo`), use `raw {"command": "breakpoint set -n <symbol>"}` and read the resulting bp id/address back from its `output`.
- `breakpoint_list {"hide_internal": true}` — internal tracer/anti-debug breakpoints are hidden by default.
- `breakpoint_enable {"bp_id": N, "enabled": true|false}`
- `breakpoint_condition {"bp_id": N, "condition": "x0 == 5"}`
- `breakpoint_commands {"bp_id": N, "commands": ["print $x0"]}`
- `breakpoint_delete {"bp_id": N}`
- All of the above (plus `breakpoint_toggle` by address) refuse to touch a breakpoint that belongs to an internal defense or the tracer — you'd otherwise be able to silently disable a defense while `status`/`breakpoint_list` kept reporting it as armed. Use `defense_disable`/`tracer_disable` instead.

Introspection (no args unless noted):
- `registers` — annotated register dump for the selected frame; each entry is `{"name", "value", "annotation"}`. When a register looks like a pointer, `annotation` dereferences it — a string, symbol name, or preview of what it points to. This is usually the fastest way to read a just-decoded/decrypted buffer (e.g. after `step_out` of a decode routine, check whether the return-value register's `annotation` already shows the plaintext) — often faster than a manual `read_memory`.
- `backtrace`, `threads`, `modules`
- `select_thread {"thread_id": N}`
- `disasm {"addr": N, "count": 64}` — both optional (default count 64); defaults to a window around the current pc. The window is clamped to the enclosing function/symbol (or the `__text` section if that can't be resolved), so it never returns fewer/more instructions than actually belong to that function — it won't show adjacent functions even if `count` is large.

Memory:
- `read_memory {"addr": N, "size": N}` — returns hex, and ascii if the bytes look printable.
- `write_memory {"addr": N, "hex": "9090"}`
- `write_register {"name": "x0", "value": 5}`
- `memory_search {"needle_hex": "...", "scope": "target"|"all", "max_hits": 32, "budget_bytes": N}` (or `"needle_ascii"` instead of `needle_hex`) — `scope: "all"` can legitimately take tens of seconds on this host; pass `budget_bytes` to cap how much it scans, and/or a generous `--timeout`.

Strings:
- `extract_strings {"min_len": 5}` — from the executable's static string sections (works before launch).
- `scan_live_strings {"min_len": 8, "budget_bytes": N}` — scans live heap/stack memory (needs a running process; can be slow — `budget_bytes` bounds it, default 512MiB).

Anti-anti-debug defenses (`name` is one of `anti_ptrace`, `anti_mach_ports`, `direct_syscall`, `fork_identity`, `exec_sandbox`):
- `defense_enable {"name": "..."}` / `defense_disable {"name": "..."}`

Fork/exec interactive decisions — by default these auto-resolve (identity mode blocks/fakes the call and keeps going); set interactive mode first if you want to inspect before deciding:
- `fork_mode {"interactive": true}`, `exec_mode {"interactive": true}`
- When interactive, a `continue`/`step_*` response can come back with `event: "pending_decision"` and a `decision` object (`kind: "fork"|"exec"`, plus `symbol`/`command`).
- `decide_fork {"decision": "parent"|"child"}` — resume as the branch you choose. Any other string is rejected (the decision stays pending so you can retry) rather than silently defaulting to "parent".
- `decide_exec {"decision": "block"|"fake"|"allow"}` — block returns -1, fake returns 0 without running it, allow lets it actually execute. Any other string is rejected the same way rather than silently defaulting to "allow".
- `dump_exec` — while an exec decision is pending, write the full command/argv to a dump file and return its path (useful before deciding).
- While a fork/exec decision is pending, `continue`/`step_*` are refused (call `decide_fork`/`decide_exec` first) — resuming directly would bypass the shield and let the intercepted call through unshielded.

Tracing (libSystem/network/file call tracer, separate from breakpoints):
- `tracer_enable {"hardware": false}`, `tracer_disable`, `tracer_depth {"depth": 5}`
- Only captures calls made **after** it's enabled — nothing retroactive. Enable it at the initial entry stop (before your first `continue`) if you want the full call history from process start; enabling mid-session after already stepping past interesting code silently misses everything before that point. After a `restart`, `tracer_enable` reports `already_enabled: true` with `total`/`resolved` both `0` — that's just "no new breakpoints were needed," not "nothing is hooked": the hooks are still armed and hits are still captured.
- `trace_hits {"since": 0}` — poll accumulated trace hits newer than hit number `since`. Each hit is `{"n": int, "category": "FILE"|"NET"|"PROC", "call": "human-readable call + args, e.g. connect(5, 1.2.3.4:443)"}`. `send`/`recv` and their `sendto`/`recvfrom` counterparts may each log the same logical operation once per underlying libSystem symbol actually called — expect occasional near-duplicate entries for one real call.

Escape hatch:
- `raw {"command": "memory region 0x100000000"}` — run any literal lldb command through the command interpreter; returns `output`/`error_output`. Use this for anything not covered above.
- `raw` is unrestricted and bypasses the hidden-breakpoint guard described above (e.g. `raw {"command": "breakpoint delete 2"}` can delete an internal defense/tracer breakpoint that the structured `breakpoint_*` commands would refuse to touch). That's inherent to giving it full command-interpreter access — don't use it to touch a breakpoint id you got from `breakpoint_list {"hide_internal": false}`.

## Session management

- `agent.sh status <session>` / `agent.sh interrupt <session>` — shorthands for the commands above.
- `agent.sh list` — every known session, alive or not.
- `agent.sh logs <session> [-n N]` — daemon's own stderr/stdout (for diagnosing a session that failed to start or crashed).
- `agent.sh stop <session>` — saves breakpoint state, detaches (if attached) or kills (if launched) the target, tears down the daemon. **Always do this when finished** — do not just abandon a session.

## Example: bypass PT_DENY_ATTACH and confirm

```
./agent.sh start --session s1 ./test/denyatt
./agent.sh cmd s1 defense_enable --json '{"name": "anti_ptrace"}'
./agent.sh cmd s1 continue --json '{"timeout": 10}'
./agent.sh stop s1
```

## Known limitations

- Interrupting a `continue`/`step_*` must come from a separate `agent.sh cmd ... interrupt` invocation (a new connection) — you can't send it down the same blocked call. If you don't know whether the target will halt on its own, launch the resume command with a `timeout`, or run it in the background and send `interrupt` from a second call if it doesn't return in a reasonable time.
- One `Debugger` per daemon process — don't try to juggle multiple targets in a single session; start a new named session per target instead.
- Concurrent `status`/`interrupt`/`quit` only work while a **resume** command (`continue`/`step_*`/`wait`/`decide_*`) is in flight — those are the only commands that poll for another connection while running. A slow *plain* command (`memory_search {"scope":"all"}`, `scan_live_strings` on a large process, `raw` running something slow) blocks the daemon's single accept loop entirely until it returns; `status`/`interrupt` sent during that window queue behind it and may hit the client's default 60s timeout. Bound such scans with `budget_bytes` and/or size `--timeout` accordingly.
- Sending anything other than `status`/`interrupt`/`quit` while another command is in flight gets a `"session busy"` error — retry once the in-flight command returns.
