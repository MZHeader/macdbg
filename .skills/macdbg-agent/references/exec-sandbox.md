# Inspect execution before deciding

Enable before script descriptor creation/loading if you want payload capture.
Enabling later can still intercept execution, but cannot recover earlier inputs.

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"exec_sandbox"}'
./agent.sh cmd SESSION exec_mode --json '{"interactive":true}'
./agent.sh cmd SESSION continue --timeout 15
```

Expect `event:"pending_decision"`, with `decision.kind:"exec"`, `symbol`, and
`command`. The command contains process arguments, source, or approximate script
reconstruction. GUI equivalents: **Sandbox exec & scripts**, **Prompt on execution**.
Without interactive mode, calls are blocked automatically.

```sh
./agent.sh cmd SESSION dump_exec
./agent.sh cmd SESSION decide_exec --json '{"decision":"block"}' --timeout 15
```

| Choice | Effect |
| --- | --- |
| `dump_exec` | Writes files and stays paused. This is its own command, not a `decide_exec` value. |
| `block` | Skips the call. Process APIs return failure; OSA returns cancellation (`-128`) and preserves output storage. |
| `fake` | Skips the call and returns success. OSA gets an empty result, not the value the script would produce. |
| `allow` | Executes the real call. A nested or simultaneous call can require another decision. |

After a decision, process the returned event again. Decisions resume free
execution rather than completing an earlier step plan. Continue/step cannot
cross a pending choice. Restart discards old choices; do not replay them.

## Read the dump response

- `path`, `bytes`: exact captured input. Compiled OSA uses `.scpt` (binary;
  printing it as text produces gibberish). Process calls produce command/argv text.
- `content_path`, `content_bytes`: readable UTF-8 source or an AppleScript
  reconstruction, when available. Read this file to inspect compiled script content.
- `content_error`: raw bytes were saved, but readable content is unavailable.
- `ok:false`, `error`: capture/dump failed; do not treat metadata as a payload.

OSA dumps use mode `0600`. The bundled static decompiler does not run AppleScript
or need network access. Run-only reconstruction can lose names, properties or
control flow; preserve the original bytes. Preview is capped at 256 Ki characters;
reconstructed text at 2 MiB, with a six-second worker timeout. Raw OSA inputs are
capped at 4 MiB. Process strings are capped at 1 MiB each and argv at 8,192 entries.

## Coverage and missing content

Process APIs: `system`, `popen`, `execve`, `execvp`, `posix_spawn`, `posix_spawnp`.
OSA APIs: `OSAExecute`, `OSAExecuteEvent`, `OSALoadExecute`, `OSACompileExecute`,
`OSADoScript`, `OSADoEvent`, `OSADoScriptFile`. Deferred hooks resolve when the
framework loads. Loading/compilation alone is not treated as execution.

Capture follows observed descriptor creation/replacement, copies, and successful
load/compile results. Disposal, component close, restart and cache eviction retire
associations. A loaded script can retain input after descriptor disposal. These
are input snapshots, not dumps of subsequently modified runtime state.

For missing capture, restart with the gate enabled earlier. File-reference-only
loads, augmented script contexts, private interpreter entry points and unobserved
input changes may still be unavailable. The gate is not filesystem/network
containment; use the environment authorized for the target.

## Fork decisions

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"fork_identity"}'
./agent.sh cmd SESSION fork_mode --json '{"interactive":true}'
./agent.sh cmd SESSION continue --timeout 15
./agent.sh cmd SESSION decide_fork --json '{"decision":"child"}' --timeout 15
```

Only decide after receiving `decision.kind:"fork"`. `child` follows the child
path in-process; `parent` allows the real fork and the child runs untraced.
Noninteractive identity mode fakes the child path. Do not assume choosing parent
keeps all resulting execution under the debugger.
