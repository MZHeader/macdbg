---
name: macdbg-agent
description: Drive macdbg through agent.sh to launch or attach to macOS processes, inspect stops, trace calls, and use anti-debug defenses. Use for debugging a target, not ordinary edits to macdbg's source.
---

# Drive macdbg

Run `./agent.sh` from the macdbg checkout. It starts a headless LLDB daemon;
subsequent commands address that session by name. No GUI or MCP server is needed.
Requires macOS and Xcode command-line tools (`xcrun lldb -P` must work).
Use the host or guest authorized for the target. `exec_sandbox` intercepts calls;
it does not isolate filesystem or network access.

## Start and inspect

```sh
./agent.sh list
./agent.sh start --session inspect /path/to/program arg1
./agent.sh cmd inspect status
./agent.sh cmd inspect registers
./agent.sh cmd inspect disasm --json '{"count":32}'
```

`list` returns an array of session records; use `alive` to distinguish live
sessions from old records. `logs` prints plain text. Other commands return JSON objects.
Choose an unused session name. Start returns `session`, daemon `pid`, and `boot`;
check `ok` and `boot.event` before proceeding. A normal launch stops at entry.
For checks in constructors, use `start --stop-at loader --session inspect /path/to/program`.
This stops before initializers; arm `anti_ptrace` or
`exec_sandbox` before continuing. `status.before_initializers` confirms the
initial loader stop. Cloak and automatic clocks still require the main entry stop.
For an existing process, use `start --session inspect --attach 1234` without a
program path. Put `--session`, `--attach`, and `--boot-timeout` before the program;
anything after its path is a target argument. Use short session names made from
letters, digits, `_`, and `-`, starting with a letter (maximum 40 characters).

## Configure before continuing

Enable only the defenses needed for the task. These examples require the initial
entry stop; attach sessions cannot enable entry-only modes.

```sh
./agent.sh cmd inspect defense_enable --json '{"name":"analysis_cloak"}'
./agent.sh cmd inspect defense_enable --json '{"name":"auto_clock"}'
./agent.sh cmd inspect status
./agent.sh cmd inspect clock_status
```

Check each command's `ok`, then `defenses.analysis_cloak_safe` and
`clock_status.safe`. A safe clock hook does not mean every counter is covered;
also inspect `counter_coverage_complete` and `coverage_notes`.

Read the relevant reference before using its mode:

- [Defenses](references/defenses.md): choose toggles, check readiness, handle integrity errors.
- [Automatic clocks](references/automatic-clocks.md): compensate pauses without locating a timing check.
- [Timing rules](references/timing-rules.md): change a register or branch at a verified decision site.
- [Exec and scripts](references/exec-sandbox.md): stop before execution, inspect and dump content, decide what runs.
- [Commands](references/commands.md): arguments, return fields, tracing and raw LLDB examples.

## Run, read the result, then choose the next action

```sh
./agent.sh cmd inspect continue --timeout 15
```

| Response | Next action |
| --- | --- |
| `ok:false` | Read `error` or `message`; do not assume the requested change happened. |
| `event:stop` | Inspect `stop` for reason/PC/thread. Some interrupt responses contain only text; use `status` and `backtrace` to get the current context. |
| `event:running` | The target is still executing. Use `wait --timeout 15`, or `interrupt` to stop it. Do not issue another continue. |
| `event:pending_decision` | Read `decision.kind`, `symbol`, and `command`; use `decide_exec` or `decide_fork`. Continue/step will be refused. |
| `event:exited` | Read `exit.code` and `console`; the daemon remains alive until stopped. |
| `event:terminated` | Read `lldb_state` and `console`; the process crashed, detached, or became invalid. |

`status` reports `process_state`, `pc`, `pending_decision`, and `defenses`.
It does not resume execution. To pause a running target:

```sh
./agent.sh cmd inspect interrupt
./agent.sh cmd inspect wait --timeout 15
./agent.sh cmd inspect status
./agent.sh cmd inspect registers
./agent.sh cmd inspect backtrace
```

After a timed resume has returned, `wait` consumes the interrupt's stop event;
polling status alone can leave LLDB reporting stale running state. If a resume
call is still in flight in another client, let that call return the stop instead
of sending a second wait. Handle the returned event: the target can exit before
the interrupt arrives. Check `process_state` before inspecting frames.

On resume commands, `--timeout` bounds the wait for a stop, not execution time.
Omitting it waits indefinitely. On other commands it bounds only the client's
response wait (60 seconds by default); a timed-out memory scan can still occupy
the daemon. Prefer bounded scans. See [Commands](references/commands.md).

The daemon accepts `status` and `interrupt` from a second client during a resume
wait. Other concurrent commands return `session busy`. During a slow ordinary
command, even status/interrupt can queue. Do not resend a timed-out mutation
without checking whether it already took effect.

## Finish or hand off

```sh
./agent.sh cmd inspect save
./agent.sh stop inspect
./agent.sh list
```

Stop sessions you created when finished, unless the user wants one left open.
For a handoff, report the session, process state, stop location, enabled defenses,
and dump paths. `stop` saves state and kills a launched target or detaches from
an attached one. `restart` kills/relaunches the same target, clears pending
choices, and preserves requested defenses; it is unavailable for attach sessions.
New sessions start with defenses off. Use status to check what survived a restart.

For startup/connection failures use `./agent.sh logs inspect -n 80` and `list`.
If using `MACDBG_STATE_DIR`, keep it absolute and short (for example `/tmp/md-run`)
and set the same value on every call; macOS Unix-socket paths are limited.
