# Command reference

All rows below use `./agent.sh cmd SESSION COMMAND --json 'ARGS'`.
Omit `--json` for commands without arguments. Addresses and integer fields accept
JSON numbers or numeric strings such as `"0x100004000"`. Use runtime addresses
from the current session; ASLR makes addresses from a previous launch unreliable.

## Inspect and edit a stopped process

| Command | Arguments / result |
| --- | --- |
| `registers` | `registers[]`: `name`, hex-string `value`, `annotation`. Check annotations for pointed-to strings/data. |
| `threads` | `threads[]`: `tid`, `index`, `name`, `pc`, `function`. |
| `select_thread` | `{"thread_id":1234}`; use `tid`, not the display index. |
| `backtrace` | `frames[]`: `index`, `pc`, `function`, `module`. |
| `modules` | `modules[]`: `name`, `base`, `size`, `triple`. |
| `disasm` | `{"addr":"0x100004000","count":32}`; omit address for current PC. Stops at the containing function/section boundary. |
| `read_memory` | `{"addr":"0x100004000","size":64}` → `hex`, optional `ascii`. |
| `write_memory` | `{"addr":"0x100004000","hex":"00000000"}`. Changes live memory; restart reloads the binary. |
| `write_register` | `{"name":"w8","value":0}`. |
| `set_pc` | `{"addr":"0x100004000"}`; changes PC without running. |
| `memory_search` | `{"needle_ascii":"marker","scope":"target","max_hits":16,"budget_bytes":16777216}` → hex-string `hits[]`, `bytes_scanned`. `needle_hex` and `scope:"all"` are alternatives. |
| `extract_strings` | `{"min_len":5}` → `strings[]` with `addr`, `text`; executable sections. |
| `scan_live_strings` | `{"min_len":8,"budget_bytes":16777216}` → same shape; live process memory, usually while stopped. |

`step_in`, `step_over`, and `step_out` accept `--timeout 15`. Source-level
`step_in_source` / `step_over_source` are refused by cloak and timing modes.
After stepping out of a decoder, inspect `registers`, then read the returned
buffer using its pointer and a verified length. Memory reads can be short;
check the returned hex length before treating a buffer as complete.

LLDB can lose its selected frame after an interrupt. `registers` selects a valid
thread when necessary; alternatively use `threads` and `select_thread` before
requesting a backtrace. An empty frame list alone does not prove the process exited.

## Breakpoints

```sh
./agent.sh cmd SESSION breakpoint_toggle --json '{"addr":"0x100004000"}'
./agent.sh cmd SESSION breakpoint_list
./agent.sh cmd SESSION breakpoint_condition --json '{"bp_id":3,"condition":"x0 == 5"}'
./agent.sh cmd SESSION breakpoint_enable --json '{"bp_id":3,"enabled":false}'
./agent.sh cmd SESSION breakpoint_delete --json '{"bp_id":3}'
```

`breakpoint_toggle` returns `action` and `bp_id`; calling it again removes the
breakpoint at that address. `breakpoint_list.breakpoints[]` uses `id`, `addr`,
`symbol`, `enabled`, `condition`, and `commands`. `breakpoint_commands` takes
`{"bp_id":3,"commands":["register read x0"]}`.
Internal defense/tracer IDs are hidden by default and reject structured edits.
Manage their owner with `defense_disable` / `tracer_disable` instead.

## Tracing

```sh
./agent.sh cmd SESSION tracer_enable --json '{"hardware":true}'
./agent.sh cmd SESSION tracer_depth --json '{"depth":5}'
./agent.sh cmd SESSION continue --timeout 15
./agent.sh cmd SESSION trace_hits --json '{"since":0}'
./agent.sh cmd SESSION tracer_disable
```

Enable before the calls you want to observe; nothing is captured retroactively.
Each hit has `n`, `category` (`FILE`, `NET`, `PROC`), and `call`. Reuse the highest
`n` as the next `since` cursor. Hardware mode preserves code bytes but has finite
slots. A resume response's `console` also contains stop/defense diagnostics.

## Raw LLDB when the wrapper has no command

```sh
./agent.sh cmd SESSION raw --json '{"command":"image lookup -n main"}'
./agent.sh cmd SESSION raw --json '{"command":"image lookup -a 0x100004000"}'
./agent.sh cmd SESSION raw --json '{"command":"image lookup --verbose --address 0x100004000"}'
./agent.sh cmd SESSION raw --json '{"command":"disassemble -s 0x100004000 -c 16"}'
./agent.sh cmd SESSION raw --json '{"command":"memory read -f x -c 4 0x100004000"}'
```

Returns `ok`, `output`, and `error_output`. For symbol breakpoints use
`breakpoint set -n SYMBOL`; with the cloak enabled, resolve the address first
and use `breakpoint_toggle` so the breakpoint is hardware-backed.

Objective-C inspection such as `expression -l objc -O -- [NSApp delegate]`
executes target code. It can invoke side effects or disturb runtime locks;
it is not equivalent to a memory read. Raw continue, thread return, register
writes and breakpoint edits bypass wrapper checks. Do not use them to cross a
pending execution decision or repair a missing internal hook.
