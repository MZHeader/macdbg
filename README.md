# macdbg

A Textual TUI for Apple's system LLDB. Gives you a multi-pane view of the running process.

![Main view](docs/img/main.png)

## Run

```sh
./macdbg.sh /path/to/your/binary
```

Requires macOS with Xcode Command Line Tools installed (so `/usr/bin/lldb` is present) and the system Python at `/usr/bin/python3`. Textual is vendored under `./vendor`, so nothing needs installing.

`macdbg.sh` sets `PYTHONPATH=$(lldb -P)` so `import lldb` resolves to the framework build. ASLR is disabled on every launch so addresses stay stable across runs.

## Edit registers and memory in place

Right-click any register row and pick **Edit value**. The prompt is prefilled with the current value so you can see what you're overwriting, and Ctrl+U clears if you want to replace it all.

![Edit register](docs/img/edit-register.png)

Right-click any memory or stack row and pick **Edit bytes**. Same idea, prefilled with the current 16 bytes as space-separated hex.

![Edit memory](docs/img/edit-memory.png)

## Breakpoint scripting

The Breakpoints tab shows id, address, symbol, attached-command count, condition, and enabled state. Right-click any breakpoint row → **Edit commands** and you get a full-screen editor for the lldb command list. Ctrl+S saves and Esc cancels. One lldb command per line, exactly as if you'd used the interactive `breakpoint command add` form without the multi-line prompt.

![Breakpoint commands](docs/img/breakpoint-commands.png)

## Syscall and network tracer

Feeling lazy? Ctrl+T arms pending breakpoints on file, process, and network entry points in libSystem. Each hit logs the call with parsed arguments and the process auto-continues, so tracing does not stop execution.

![Trace tab](docs/img/trace.png)

## Anti-anti-debug

Ctrl+D opens a menu of independent bypass toggles, all off by default:

![Defenses menu](docs/img/debug-menu.png)

- **PT_DENY_ATTACH** bypass breaks on `ptrace`, and if it's called with the deny flag we return `0` without calling the kernel.
- **Direct-syscall ptrace scan** finds every raw svc `#0x80` in the target's `__text` and checks each one at runtime. If it's a `ptrace` deny call, we skip it. Catches `ptrace` calls that bypass libc.
- **Mach exception port cloak** intercepts `task_get_exception_ports` and returns zero ports, so the sample thinks nothing is attached.
- **Hardware BPs for user breakpoints** switches new breakpoints to hardware mode, which doesn't patch code bytes. Beats prologue-hash checks.
- **Hardware BPs for tracer breakpoints** does the same for tracer breakpoints. Flip it before turning the tracer on.

## Command palette

Ctrl+P opens a fuzzy palette over every lldb command, with lldb's own help text as the description.

![Command palette](docs/img/ctrl-p.png)

![Fuzzy search](docs/img/fuzzy-search.png)

## Themes

Lots of themes to choose from :)

![Themes](docs/img/theme.png)

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
| Ctrl+C | Exit (disabled, kept so accidental Ctrl+C doesn't kill your session) |
| Right click on a row | Pane-specific context menu |

Whatever you type in the console goes into `SBCommandInterpreter.HandleCommand`. If a command would trigger an interactive Y/N prompt (`run`, `br del`), the wrapper answers it for you before the command reaches lldb.
