# macdbg

A Textual TUI for LLDB. Gives you a multi-pane view of the running process. Includes a lazy syscall & network tracer that works on forked processes, defeats anti-debugging checks, and lets you edit registers and memory in place.

![Main view](docs/img/main-v4.png)

## Who Is This For

Reverse engineers and malware analysts debugging macOS binaries who aren't very good at remembering CLI commands and want an experience closer to x64dbg. The Trace tab gives results with no breakpoints needed and the debugger has built-in functionality to defeat common anti-debug techniques.

## Requirements

- macOS with the Xcode Command Line Tools installed

## Install

```sh
git clone https://github.com/MZHeader/macdbg
cd macdbg
./macdbg.sh /path/to/your/binary
```

## Syscall and Network Tracer

Feeling lazy? `Ctrl+T` arms breakpoints on common file, process, and network entry points in libSystem. Each hit logs the call with parsed arguments and the process auto-continues, so tracing does not stop execution.

![Trace tab](docs/img/trace.png)

## Anti-anti-debug

`Ctrl+D` opens a menu of toggles, all off by default.

![Defenses menu](docs/img/debug-menu.png)

**Anti-debug**

- **Defeat PT_DENY_ATTACH via libc** hooks `ptrace` and returns `0`, so the deny flag never reaches the kernel.
- **Defeat inline PT_DENY_ATTACH** catches the same call when the sample skips libc and runs `svc #0x80` directly.
- **Cloak Mach exception ports** hooks `task_get_exception_ports` to report none, so the process looks unattached.
- **Scrub P_TRACED from sysctl** lets `sysctl(KERN_PROC)` run, then clears the `P_TRACED` bit in the returned `kinfo_proc` so the classic sysctl check sees an untraced process.
- **Scrub CS_DEBUGGED from csops** does the same for `csops(CS_OPS_STATUS)`, clearing the `CS_DEBUGGED` code-signing flag modern samples check.

**Breakpoints**

- **Hardware breakpoints for your breakpoints** leave the bytes in `__TEXT` untouched, so a prologue-hash check passes.
- **Hardware breakpoints for the tracer** do the same for tracer BPs. Turn it on before `Ctrl+T`.

**Forks**
> For cases where the sample forks, the parent exits, and the child detaches with `setsid`.

- **Run child path in-process** fakes `fork`/`vfork` to `0` and `setsid` to a real sid.
- **Prompt each fork** stops on every fork and asks whether to stay in the parent or enter the child. Answer per site.
- **Trace the whole fork tree** shows the syscalls of children lldb can't follow.

![Fork decision prompt](docs/img/follow-fork.png)

**Exec**
> For samples that call something like `killall Terminal`, we can just intercept it, say no, and spoof a success result.

- **Intercept outbound exec** hooks `system`, `popen`, `execve`, `execvp`, `posix_spawn`, and `posix_spawnp`.
- **Prompt each call** offers Allow, Fake success, Block, or Dump per call, otherwise auto-blocks.

![Exec sandbox prompt](docs/img/exec-prompt.png)

The preview reads the full `argv`, so a dropper hiding its script behind `osascript -e` shows the script, not just the interpreter. Pick **Dump payload to file** to write the whole command to `~/.macdbg/<binary>-<sha>/dumps/`.

![Dumping an osascript payload](docs/img/exec-dump.png)

![The dumped payload on disk](docs/img/exec-payload.png)

## Breakpoint Scripting

The Breakpoints tab shows id, address, symbol, attached-command count, condition, and enabled state. Right-click any breakpoint row → **Edit commands** and you get a full-screen editor for the lldb command list. Ctrl+S saves and Esc cancels. One lldb command per line, exactly as if you'd used the interactive `breakpoint command add` form without the multi-line prompt.

![Breakpoint commands](docs/img/breakpoint-commands.png)

## Edit Registers and Memory

Right-click any register row and pick **Edit value**. The prompt is prefilled with the current value so you can see what you're overwriting, and Ctrl+U clears it if you want to replace it all.

![Edit register](docs/img/edit-register.png)

Right-click any memory or stack row and pick **Edit bytes**. Same idea, prefilled with the current 16 bytes as space-separated hex.

![Edit memory](docs/img/edit-memory.png)

## Command Palette

Ctrl+P opens a fuzzy palette over every lldb command, with lldb's own help text as the description.

![Command palette](docs/img/ctrl-p.png)

![Fuzzy search](docs/img/fuzzy-search.png)

## Themes

Lots of themes to choose from :)

![Themes](docs/img/theme.png)

## Headless / agentic

`./agent.sh` is the same debugger driven by JSON over a Unix socket instead of a TUI. Made for scripts, cron jobs, and agentic use.

```sh
./agent.sh start --session s1 /path/to/binary
./agent.sh cmd s1 breakpoint_toggle --json '{"addr": "0x100003f88"}'
./agent.sh cmd s1 continue --json '{"timeout": 10}'
./agent.sh stop s1
```

The daemon holds one live LLDB session per name and keeps state (breakpoints, register overrides, patched memory) between commands. Every JSON handler has an equivalent to what the TUI does, plus a `raw` command that runs any lldb command literally.

A Claude Code skill at `.claude/skills/macdbg-agent/SKILL.md` documents the protocol plus recipes for reversing Cocoa apps. Drop this repo into a project and Claude drives the debugger directly.

## Keys

| Key | Action |
|-----|--------|
| F2 | Toggle breakpoint at pc |
| F5 | Disassembly back to pc (after browsing) |
| F6 | Execute till return (step out of current frame) |
| F7 | Step in (instruction) |
| F8 | Step over (instruction) |
| F9 | Continue |
| Ctrl+R | Restart (kill and re-run to the entry point) |
| Enter (in disasm) | Follow operand address in the memory pane |
| `:` | Focus the console command bar |
| Ctrl+B | Interrupt a running process |
| Ctrl+D | Defenses menu |
| Ctrl+F | Search process memory (target scope by default; prefix `all:` for libraries) |
| Ctrl+G | Go to an address in the disassembly view (browse; F5 or the next step snaps back to pc) |
| Ctrl+K | Clear the trace tab |
| Ctrl+P | Command palette |
| Ctrl+T | Toggle the tracer |
| Ctrl+Y | Cycle trace scope (strict / balanced / wide / off) |
| Ctrl+C | Quit |
| Right click on a row | Pane-specific context menu |

Whatever you type in the console goes into `SBCommandInterpreter.HandleCommand`. If a command would trigger an interactive Y/N prompt (`run`, `br del`), the wrapper answers it for you before the command reaches lldb.

## Additional Features

- **Memory search.** Target-only scope by default (binary plus heap and stack). Prefix `all:` to widen to loaded libraries. Ctrl+F Enter cycles to the next hit.
- **Per-binary persistence** at `~/.macdbg/<name>-<sha>/state.json`. Breakpoints with conditions and command scripts, comments, and bookmarks come back next time you open the same binary. The directory is named for the binary but suffixed with a slice of its sha256, so two samples that share a name never collide; dumps for the same sample sit alongside in `dumps/`. Old flat `~/.macdbg/<sha256>.json` files migrate here automatically on first open.
- **Disasm comments.** Right-click a disasm row and pick **Add comment**. Persists across sessions and renders as a bold gold `← note` in the disasm line.
- **Jump arrow gutter.** Left-side control flow lines for every branch whose source and target are both visible. At the current pc, the arrow is colored **green if the branch will be taken** and **red if not**, evaluated live from register values and CPSR flags.
- **Function name markers.** `▼ funcname:` banner rows at function boundaries wherever lldb has symbol info.
- **Inline dereference hints.** `adrp + add` and `adrp + ldr` pairs get a bright blue `; = 0x…  "resolved string"` or `; load @ 0x…  symbol` comment showing what the address materializes to, right in the disasm line.
- **Follow in disassembly.** Right-click a call or branch operand, or a register value, pick Follow in disassembly, and browse that address without moving pc. F5 snaps back.
- **Call Stack tab.** Full backtrace of the selected thread with pc, function, and module.
- **Watch windows.** Three pinned mini hexdumps next to Memory and Stack. Right-click any address, register value, memory row, or string → **Follow in Watch 1/2/3** to pin it. The address stays put as you step; only the bytes refresh. Handy for watching an inline decryption stub fill a stack buffer with plaintext byte by byte. Bindings persist per binary in `~/.macdbg/<name>-<sha>/state.json`. Right-click a watch pane for length, label, and clear controls.