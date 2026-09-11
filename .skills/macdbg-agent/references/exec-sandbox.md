# Process and OSA execution interception

Enable `exec_sandbox` before descriptor creation and script loading to capture
payloads, or before an execution call to gate it without earlier input capture. It includes both
process-launch APIs and in-process OSA script execution on ARM64. It is an
execution gate, not a general filesystem, network, or process-containment sandbox.
Keep untrusted targets in the separately isolated environment authorized by the user.

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"exec_sandbox"}'
./agent.sh cmd SESSION exec_mode --json '{"interactive":true}'
./agent.sh cmd SESSION continue --json '{"timeout":20}'
```

The GUI controls are **Sandbox exec & scripts** and **Prompt on execution**.
Without interactive mode, intercepted calls are blocked automatically.

Covered process APIs: `system`, `popen`, `execve`, `execvp`, `posix_spawn`,
and `posix_spawnp`.

Covered OSA APIs: `OSAExecute`, `OSAExecuteEvent`, `OSALoadExecute`,
`OSACompileExecute`, `OSADoScript`, `OSADoEvent`, and `OSADoScriptFile`.
Hooks can be armed before OpenScripting loads. Loading and compilation alone
are not treated as execution. Calls through resolved pointers to these exports
are covered; direct component dispatch or other interpreter entry points are not.
Objective-C script APIs are covered only when they reach one of these OSA exports.

An OSA stop uses the existing `pending_decision` response with `kind: "exec"`
and the OSA symbol name. The GUI restores a pending decision after reconnect. Continue and instruction stepping cannot cross an
unresolved decision. A decision ends the previous step plan and resumes free
execution. The decision is bound to the stopped process, thread, PC, and stop ID;
stale contexts are rejected. Other simultaneous OSA entries require their own
decisions before the process can resume.

```sh
./agent.sh cmd SESSION dump_exec
./agent.sh cmd SESSION decide_exec --json '{"decision":"block","timeout":20}'
```

For OSA calls:

- **Allow** executes the real API. Nested execution calls may prompt again.
- **Block** skips the call and returns `userCanceledErr` (`-128`). Output storage
  is preserved.
- **Fake success (empty result)** skips the call and returns success with
  `kOSANullScript` or a null `AEDesc`, as appropriate. It does not manufacture a
  script value or reply event; callers requiring one can still reject that result.
- **Dump content + raw** writes the exact captured script input. Compiled OSA data is
  saved as `.scpt`; UTF-8 source is saved as `.applescript.txt`. Other supported
  text encodings retain their raw bytes with a binary suffix. A readable UTF-8
  `.applescript.txt` companion is also saved when text decoding or static
  decompilation succeeds. The popup shows script content first; size, SHA-256
  and descriptor metadata are under **Capture details**. It reports both saved
  paths and preserves them on reconnect. Dumps use mode `0600`.
  Headless `dump_exec` retains `path` / `bytes` for raw input and adds
  `content_path` / `content_bytes`, or `content_error` when unavailable.
  Dumping does not resume execution or call the script engine.

Compiled AppleScript, including supported run-only scripts, is reconstructed
using the bundled pure Python decompiler in a separate worker. No installation
or network access is required. This is approximate analysis text, not original
authored source or guaranteed recompilable code: names, properties, terminology
and control flow can be incomplete. Unsupported or malformed inputs report an
explicit preview error; raw dumps remain available. The worker has a six-second
wall timeout, a three-second CPU limit and a 2 MiB text limit. Previews show up to
256 Ki characters; readable dumps retain the full recovered text within that
limit. Source descriptors are decoded according to their declared encoding.

Capture observes `AECreateDesc` and `AEReplaceDescData` inputs, follows descriptor
copies, and associates successful `OSALoad` / `OSACompile` results with their
component and script ID. `OSACopyID` and `OSACopyScript` preserve associations;
descriptor/script disposal, component close and restart retire them. A loaded
script retains its captured input after the original descriptor is disposed.
These are input snapshots, not serializations of later runtime state.

Each input is limited to 4 MiB. The capture cache is bounded to 32 MiB and 128
associations, with at most eight pending return observations. Return hooks use
hardware in the main executable and software elsewhere. Capacity failures,
unreadable input and eviction can leave a script uncaptured; the execution gate
still applies. Script contexts augmented by later compilation, file-reference-only
loading, private APIs, and unobserved descriptor edits are outside capture coverage.

If no input was captured, Dump explicitly reports that it is unavailable and
writes no substitute metadata file. Restart with the sandbox enabled earlier for
ordinary descriptor-based loads. Scripts loaded through uncovered APIs still need
separate recovery. Popup buttons are bound to the originating stop so an old
request cannot approve or dump a newer call.

Failed output/register writes keep execution stopped. Restart clears pending
contexts and re-arms enabled hooks; opening a target afresh clears defenses.
Raw LLDB execution is an escape hatch outside this gate's contract.

Benign regression tests:

```sh
make -C tests/integration all
/usr/bin/python3 -m unittest -v tests.integration.test_script_exec
```

The scripts only return constants and, where needed to prove execution, write
an `executed` marker in the test's disposable directory. Block and Fake assert
that the marker is absent; Allow asserts it is present.
