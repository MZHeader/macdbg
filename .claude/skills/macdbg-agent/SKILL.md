---
name: macdbg-agent
description: Drive the macdbg LLDB wrapper as a headless debugger from Claude — launch/attach a macOS binary, set breakpoints, step, read/write memory and registers, and toggle anti-anti-debug bypasses (PT_DENY_ATTACH, Mach exception ports, fork/exec interception), all via JSON commands over agent.sh instead of the interactive Textual TUI. Use this whenever the user wants Claude itself to debug, trace, or reverse-engineer a macOS binary in this repo (or any target binary/pid) rather than just editing macdbg's own source.
---

# macdbg headless agent

macdbg's interactive TUI (`./macdbg.sh <binary>`) is unusable from an agent
because it owns the terminal. `./agent.sh` is the second, headless entry
point: same LLDB-backed `Debugger` core (`macdbg/core/debugger.py`), driven
by a JSON protocol over a Unix socket instead of the TUI. Only works on
macOS with Xcode command line tools (`lldb`) installed. Run every command
from the macdbg repo root.

## Mental model

`agent.sh start` launches a background daemon process that owns one live
LLDB session (one target, one or more threads). All later commands
(`agent.sh cmd <session> <command>`) talk to that daemon over a local Unix
socket and return JSON. The daemon keeps running — with breakpoints,
register state, patched memory, etc. all intact — between your tool calls,
until you explicitly `agent.sh stop <session>`. **Always stop a session
when you're done with it** — it holds a live child process and an LLDB
debugger object open until then.

Commands that resume execution (`continue`, `step_*`, `wait`,
`decide_fork`, `decide_exec`) block until the process reaches the next
genuine stop, exits, or hits an interactive fork/exec decision. Anti-debug
and tracer breakpoint hits are handled and auto-continued transparently —
you only see "real" stops (your own breakpoints, step completions,
signals, exceptions).

## Starting a session

```
./agent.sh start --session <name> [--attach <pid>] <program> [args...]
```

`--session`, `--attach`, and `--boot-timeout` are global options and **must
come before the program path** — anything after the program path is passed
to the target itself. Giving both a program path and `--attach` is
rejected.

Session names are plain identifiers only (no `/`, no `..`, max 40 chars —
Unix socket path limit). Omit `--session` for an auto-generated one.

The response includes a `boot` object with the initial console output and
either an `event: "stop"` (paused at the entry breakpoint, ready to go) or
`event: "exited"` (rare, means the target exited during startup).

## Sending commands

```
./agent.sh cmd <session> <command> [--json '{"arg": "value"}'] [--timeout SECONDS]
```

Every response is one JSON object with `"ok": true|false`. Resuming
commands additionally include `event` (`stop` / `exited` / `running` /
`pending_decision` / `terminated`), a `console` field with any buffered
stdout/stderr collected since the last drain, and a `stop` or `exit`
object describing what happened.

`--timeout` on a **resume** command bounds how long to wait for the next
stop — omit it to block indefinitely; if it fires you get `event:
"running"` and the process is still going (call `wait` to keep waiting, or
`interrupt` from a separate `agent.sh cmd` to force a stop).

`--timeout` on a **plain** command instead bounds how long the client
waits for a response at all. Defaults to 60s — enough for the slow ones
(`memory_search` with `scope: "all"`, `scan_live_strings` on a large
process, `extract_strings` on a big binary). `--timeout 0` means "fail
almost immediately," not "wait forever" — omit it entirely for the 60s
default.

**Every numeric field accepts either a JSON integer or a string** —
`{"addr": "0x10001d078"}` and `{"addr": 4295086392}` resolve to the same
address. Hex/octal/binary prefixes (`0x`, `0o`, `0b`) all work. Prefer the
hex form for addresses; hand-converting to decimal is where transcription
errors happen.

## Command reference

Lifecycle:
- `status` — process state, pc, pending decision, tracer state.
- `restart` — kill and relaunch the same target (not available when attached).
- `interrupt` — force-stop a running process.
- `save` — persist breakpoints to `~/.macdbg/<binary>-<sha>/state.json`
  (also happens automatically on `stop`).

Execution control (all take optional `{"timeout": N}`):
- `continue`, `step_in` (single instruction), `step_over`, `step_out`,
  `step_in_source`, `step_over_source`, `wait` (keep waiting without
  issuing a new resume — use after a `running` timeout).

Breakpoints:
- `breakpoint_toggle {"addr": N}` — add if absent, remove if present.
  Address-only; for symbol-name breakpoints see the "raw idioms" section
  below.
- `breakpoint_list {"hide_internal": true}` — internal tracer/defense
  breakpoints are hidden by default.
- `breakpoint_enable {"bp_id": N, "enabled": true|false}`
- `breakpoint_condition {"bp_id": N, "condition": "x0 == 5"}`
- `breakpoint_commands {"bp_id": N, "commands": ["print $x0"]}`
- `breakpoint_delete {"bp_id": N}`
- These all refuse to touch a breakpoint that belongs to a defense or the
  tracer — otherwise you could silently disarm a defense while
  `breakpoint_list` kept reporting it as armed. Use
  `defense_disable`/`tracer_disable` to turn those off properly.

Introspection:
- `registers` — annotated register dump for the currently selected frame.
  Each entry is `{"name", "value", "annotation"}` where `value` is a
  hex-formatted string like `"0x000000010001d078"` (not a raw integer).
  `annotation` dereferences pointer-shaped values into a string, symbol
  name, or preview — usually the fastest way to read a
  just-decoded/decrypted buffer (e.g. after `step_out` of a decoder,
  check whether the return-value register's `annotation` already shows
  the plaintext). Auto-selects thread 0 if no thread is currently
  selected (LLDB clears that in some post-interrupt paths), so you don't
  need to call `select_thread` first after every interrupt.
- `backtrace`, `threads`, `modules`, `select_thread {"thread_id": N}`.
- `disasm {"addr": N, "count": 64}` — both optional; defaults to a window
  around the current pc. **Clamped to the enclosing function/symbol** (or
  the `__text` section if nothing else covers `addr`) — never shows
  adjacent functions even for large `count`. If you want a raw window
  that ignores function boundaries (e.g. to inspect the byte
  immediately after a function), use `raw {"command": "disassemble -s
  ADDR -c N"}` instead.

Memory:
- `read_memory {"addr": N, "size": N}` — returns `hex` (always) and
  `ascii` (only when the bytes look printable).
- `write_memory {"addr": N, "hex": "9090"}` — patches persist in the live
  process; do not persist across `restart` (the binary is re-mapped).
- `write_register {"name": "x0", "value": N}`.
- `memory_search {"needle_hex": "…", "scope": "target"|"all", "max_hits":
  32, "budget_bytes": N}` — or `"needle_ascii"` instead of `needle_hex`.
  `scope: "all"` can take tens of seconds; bound with `budget_bytes`
  and/or a generous `--timeout`.

Strings:
- `extract_strings {"min_len": 5}` — from the executable's static string
  sections; works before launch. Returns `{"strings": [{"addr": N,
  "text": "…"}, …]}`.
- `scan_live_strings {"min_len": 8, "budget_bytes": N}` — scans live
  heap/stack memory; needs a running process. Same response shape.
  Default `budget_bytes` is 512 MiB.

Anti-anti-debug defenses (`name` is one of `anti_ptrace`,
`anti_mach_ports`, `direct_syscall`, `fork_identity`, `exec_sandbox`):
- `defense_enable {"name": "…"}` / `defense_disable {"name": "…"}`.

Fork/exec interactive decisions — by default these auto-resolve
(identity/sandbox mode blocks/fakes the call and keeps going); set
interactive mode first to inspect:
- `fork_mode {"interactive": true}`, `exec_mode {"interactive": true}`.
- When interactive, a resume can come back with `event:
  "pending_decision"` and a `decision` object (`kind: "fork"|"exec"`, plus
  `symbol`/`command`).
- `decide_fork {"decision": "parent"|"child"}` — resume as your choice;
  bad strings are rejected rather than silently defaulting.
- `decide_exec {"decision": "block"|"fake"|"allow"}` — block returns -1,
  fake returns 0 without running, allow actually executes. Same
  rejection rule.
- `dump_exec` — while an exec decision is pending, write the full
  command/argv to a dump file and return its path.
- While a decision is pending, `continue`/`step_*` are refused — resuming
  directly would bypass the shield.

Tracing (libSystem/network/file call tracer, separate from breakpoints):
- `tracer_enable {"hardware": false}`, `tracer_disable`,
  `tracer_depth {"depth": 5}`.
- Only captures calls made **after** it's enabled — nothing retroactive.
  Enable it at the initial entry stop (before your first `continue`) if
  you want the full call history from process start.
- `trace_hits {"since": 0}` — poll accumulated hits newer than hit number
  `since`. Each hit is `{"n": int, "category": "FILE"|"NET"|"PROC",
  "call": "human-readable"}`.

Escape hatch:
- `raw {"command": "…"}` — run any literal lldb command through the
  command interpreter; returns `output`/`error_output`. This is powerful
  and unrestricted — it can delete internal defense/tracer breakpoints
  the structured commands would refuse to touch. Do not use it to touch
  a breakpoint id you got from `breakpoint_list {"hide_internal":
  false}`. See "raw idioms" below for what to reach for.

## Raw idioms you'll actually use

Most reversing work on a Cocoa binary funnels through `raw` for the
things LLDB does well and macdbg doesn't wrap. The workflows I hit
constantly:

**Address → function name.** By far the most common one — every time you
see an address in a register or a xref and want to know what it is:
```
raw {"command": "image lookup -a 0x100047df4"}
```

**Symbol → address (exact name):**
```
raw {"command": "image lookup -n \"-[NSApplication run]\""}
```

**Symbol → address (regex, useful when you don't know the exact selector):**
```
raw {"command": "image lookup -r -n \"delegate\""}
```

**Break by symbol name** (the structured `breakpoint_toggle` is
address-only):
```
raw {"command": "breakpoint set -n \"-[MyController doSomething:]\""}
```
The response's `output` includes the breakpoint id and the resolved
address — read them back if you want to manage the breakpoint later.

**Break on every call to an Objective-C selector.** On arm64 the compiler
emits per-selector `objc_msgSend$foo` stubs; setting a breakpoint on that
stub fires every time anyone calls `[obj foo]`. Discover them with
`nm -a <binary> | grep 'objc_msgSend\$'`.
```
raw {"command": "breakpoint set -n \"objc_msgSend$description\""}
```

**Call an Objective-C method at runtime** (invaluable for
reverse-engineering — poke at any Cocoa object without patching, or drive
a decode routine with test input):
```
raw {"command": "expression -l objc -O -- [NSApp delegate]"}
raw {"command": "expression -l objc -O -- [(id)0x12345 description]"}
```
`-l objc` selects the ObjC parser; `-O` prints via `-description` instead
of dumping the raw struct. Watch out for two footguns: LLDB prints a
`BOOL` return as `<nil>` when it's 0 (wrap in `[NSNumber
numberWithBool:…]` for a clean value), and reading private ivars with
`(Type *)ptr->_ivar` fails on stripped binaries (`does not have a member
named` errors) — fall back to KVC with `[obj valueForKey:@"foo"]` or, if
KVC's own accessor bailout throws, read the ivar offset from
`_OBJC_IVAR_$_Class._ivar` (via `nm`) and add it to the object pointer
manually.

**Word-formatted memory dump** (nicer than `read_memory`'s raw hex when
you're looking at instructions or pointer tables):
```
raw {"command": "memory read -f x -c 4 0x10001d078"}
```
`-f x` = hex words, `-c 4` = four words. For string content, use
`-f s`; for byte-oriented dumps, `read_memory` is fine.

**Disassemble past the auto-clamp** — `disasm` refuses addresses outside
the enclosing function, which is usually right but occasionally not:
```
raw {"command": "disassemble -s 0x10001d078 -c 8"}
```

**Look up what module and section an address belongs to** (useful when
you don't yet know if an address is in `__text`, a stub, or a data
section):
```
raw {"command": "image lookup --verbose --address 0x1000a7c38"}
```

## Session management

- `agent.sh status <session>` / `agent.sh interrupt <session>` — shorthands
  for the same JSON commands.
- `agent.sh list` — every known session, alive or not.
- `agent.sh logs <session> [-n N]` — the daemon's own stderr/stdout, for
  diagnosing a session that failed to start or crashed.
- `agent.sh stop <session>` — saves breakpoint state, detaches or kills
  the target, tears down the daemon. **Always do this when finished** —
  don't just abandon a session.

## Example: bypass PT_DENY_ATTACH and confirm

```
./agent.sh start --session s1 ./test/denyatt
./agent.sh cmd s1 defense_enable --json '{"name": "anti_ptrace"}'
./agent.sh cmd s1 continue --json '{"timeout": 10}'
./agent.sh stop s1
```

## Concurrency

The daemon's accept loop is single-threaded. During a **resume** command
(`continue`/`step_*`/`wait`/`decide_*`), the daemon polls the socket
between stops, so `status`/`interrupt`/`quit` sent from a *separate*
`agent.sh cmd` invocation get answered promptly. Any other command sent
during that window gets `{"error": "session busy"}` — retry when the
in-flight command returns.

During a **slow plain** command (a `scope: "all"` memory search, a big
`scan_live_strings`, a long-running `raw`), the accept loop is fully
blocked until it returns — even `status` and `interrupt` will queue and
may hit the client's 60s default timeout. Bound such calls with
`budget_bytes` and/or a larger `--timeout`.

You can't interrupt a `continue` down the same blocked call — the
interrupt must come from a fresh connection. If a target might genuinely
loop forever, launch the resume with a `timeout` and send `interrupt`
from a second `agent.sh cmd` if it doesn't come back.

One daemon per target: don't juggle multiple targets in a single session,
start a new named session per binary.
