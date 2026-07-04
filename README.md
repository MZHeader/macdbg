# macdbg

A Textual TUI for Apple's system LLDB. Gives you a multi-pane view of the running process instead of typing `register read`, `disassemble`, and `memory read` on every stop.

## What's in each pane

**Disassembly.** The current instruction is centered every time the process stops. Right-click a row to toggle a breakpoint, run-to-cursor, follow the operand address into the memory pane, or copy the address.

**Registers.** Each value gets annotated with what it points at. The priority is: symbol lookup (`main+0x24`, `dyld`_main_thread`), then a printable string with a NUL terminator or a run of at least 12 printable characters, then a one-hop pointer chase to another symbol or string, then a raw 8-byte peek if the address falls inside a loaded module. Nothing shows for values that aren't confidently interpretable, which keeps random ints from being decorated with garbage. Right-click a row to follow the value in memory, set a breakpoint at that address, edit the value (opens a prompt prefilled with the current value so you can see what you're overwriting), copy the hex, or copy the decoded annotation.

**Stack and Memory.** Hex dumps, 16 bytes per row, native DataTable scroll. Right-click any row to follow the qword at that address, set a watchpoint on it, edit the row's bytes (prompt is prefilled with the current 16 bytes as space-separated hex), or copy the address. Edits go through `SBProcess.WriteMemory` and verify by reading back, so a failed write is reported instead of silently ignored.

**Breakpoints.** Shows id, address, symbol, number of attached commands, condition, and enabled state. Right-click a row for four actions: Edit commands opens a full-screen editor for the command list (Ctrl+S saves, Esc cancels); Set condition takes an lldb expression; Toggle enabled flips the ✓ / × column; Delete removes the bp. Tracer breakpoints and anti-debug internal breakpoints are excluded from this pane so it doesn't fill with plumbing.

**Threads and Modules.** Live view of the process's threads and loaded images. Auto-populated on every stop, sorted by thread id and module load address respectively.

**Trace.** Toggle with Ctrl+T. Sets pending breakpoints on file, process, and network entry points in libSystem. Each hit is logged with parsed arguments and the process auto-continues, so tracing does not stop execution.

Coverage:

- File: `open`, `openat`, `close`, `read`, `write`, `pread`, `pwrite`, `fopen`, `fread`, `fwrite`, `fclose`, `stat`, `lstat`, `fstat`, `access`, `unlink`, `rename`, `chmod`, `mkdir`, `rmdir`, `dup`, `dup2`, `mmap`, plus the `$NOCANCEL` and `$INODE64` variants that libc uses under the hood.
- Process: `popen`, `pclose`, `system`, `execve`, `execvp`, `posix_spawn`, `posix_spawnp`, `fork`, `vfork`, `kill`, `dlopen`, `dlsym`.
- Network: `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`, `setsockopt`, `getaddrinfo`, `gethostbyname`, `gethostbyname2`.

Hits are filtered by caller depth. The default keeps a hit if user code appears in the top 5 callstack frames, which catches indirect dispatch through GCD blocks, `objc_msgSend`, `libcurl`, and CFNetwork without letting internal DNS resolution or CoreGraphics chatter through. Cycle strict (1) / balanced (5) / wide (32) / off (0) with Ctrl+Y. Ctrl+K clears the tab.

**Console.** Bottom right. Type `:` to focus. Anything you enter goes into `SBCommandInterpreter.HandleCommand`, so every lldb command is available, including breakpoint scripts, watchpoints, `expression`, `image dump`, and so on. Output from auto-continue breakpoint scripts is captured through a pipe and printed here too, so `p (const char*)$x0` on a hit will show the string in the console rather than disappearing into the debugger's default output stream.

## Anti-anti-debug (Ctrl+D)

A menu of independent toggles, all off by default:

- **PT_DENY_ATTACH bypass (symbol hook).** Sets a breakpoint on `ptrace`. When it fires with `x0 == PT_DENY_ATTACH`, we run `thread return 0` so the syscall never reaches the kernel and the process survives.
- **Direct-syscall ptrace scan.** Walks the target's `__text` for every `svc #0x80` and sets a breakpoint at each site. At hit-time, checks `x16 == 26 && x0 == 31`. If both match, patches `x0 = 0` and advances `pc` past the svc. Catches inline-asm ptrace calls that skip the libc symbol.
- **Mach exception port cloak.** Hooks `task_get_exception_ports`, writes 0 to the caller's `*masksCnt` buffer, and thread-returns 0. The sample sees a successful call reporting zero installed exception ports.
- **Hardware breakpoints for user BPs.** Future `toggle_bp` calls use `-H`, so `__TEXT` bytes aren't patched with `brk`. Defeats integrity checks that hash a function's prologue.
- **Hardware breakpoints for tracer BPs.** Same idea applied to the tracer's set of libSystem breakpoints. Toggle this before enabling the tracer, not after.

Verified end-to-end against a canary (`test/denyfour.c`) that runs all four checks in sequence.

## Command palette

Ctrl+P opens a fuzzy palette over every lldb command, with lldb's own help text as the description. Type `bre` to filter for `breakpoint`, `mem rea` for `memory read`, `thread s` for the subcommands under `thread`. Pick a hit and it runs through the console.

## Requirements

macOS with Xcode Command Line Tools installed, so `/usr/bin/lldb` is present. The wrapper uses the system Python (`/usr/bin/python3`, 3.9) because that's what Apple's `lldb` module was built against. Textual is vendored under `./vendor`, so nothing needs installing.

## Run

```sh
./run.sh /path/to/your/binary
```

Point it at a binary you compiled yourself, or any non-signed Homebrew binary. System binaries under `/bin`, `/usr/bin`, and other SIP-protected paths are blocked from being debugged and will fail to launch.

`run.sh` sets `PYTHONPATH=$(lldb -P)` so `import lldb` resolves to the framework build. ASLR is disabled on every launch so addresses stay stable across runs.

## Keys

| Key | Action |
|-----|--------|
| F7 | Step in (instruction) |
| F8 | Step over (instruction) |
| F9 | Continue |
| F2 | Toggle breakpoint at pc |
| Enter (in disasm) | Follow operand address in the memory pane |
| `:` | Focus the console command bar |
| Ctrl+G | Focus the memory follow-address input |
| Ctrl+P | Command palette |
| Ctrl+T | Toggle the tracer |
| Ctrl+K | Clear the trace tab |
| Ctrl+Y | Cycle trace scope (strict / balanced / wide / off) |
| Ctrl+D | Defenses menu |
| Ctrl+C | Quit |
| Right click on a row | Pane-specific context menu |

Whatever you type in the console goes into `SBCommandInterpreter.HandleCommand`. If a command would trigger an interactive Y/N prompt (`run`, `br del`), the wrapper answers it for you before the command reaches lldb.
