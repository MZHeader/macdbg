# macdbg

A Textual TUI for Apple's system LLDB. You get a multi-pane view of the running process instead of typing `register read`, `disassemble`, and `memory read` on every stop.

The disasm pane keeps the current instruction centered on every step. The registers pane annotates each value with its symbol, string, or a one-hop pointer chase where it can. The stack and memory panes are hex dumps you can scroll (F5/F6) and edit (right-click, Edit bytes). Bottom tabs cover breakpoints, threads, modules, and a syscall/network trace that filters out dyld and libSystem noise so you only see calls that came from your binary. The console at the bottom right accepts any raw lldb command, and Ctrl+P opens a fuzzy palette over every lldb command with lldb's own help text attached.

## Requirements

macOS with Xcode Command Line Tools installed, so `/usr/bin/lldb` is present. The wrapper uses the system Python (`/usr/bin/python3`, 3.9) because that's what Apple's `lldb` module was built against.

## Run

```sh
./run.sh /path/to/your/binary
```

Textual is vendored in `./vendor`, so the wrapper runs on a machine that has never seen the internet as long as `/usr/bin/lldb` and `/usr/bin/python3` are present.

Point it at a binary you compiled yourself, or any non-signed Homebrew binary. System binaries under `/bin`, `/usr/bin`, and other SIP-protected paths are blocked from being debugged and will fail to launch.

`run.sh` sets `PYTHONPATH=$(lldb -P)` so `import lldb` resolves to the framework build. ASLR is disabled on every launch, so addresses stay stable across runs.

## Keys

| Key | Action |
|-----|--------|
| F7 | Step in (instruction) |
| F8 | Step over (instruction) |
| F9 | Continue |
| F2 | Toggle breakpoint at pc |
| Enter (in disasm) | Follow operand address in the memory pane |
| `:` | Focus the console command bar |
| Ctrl+G | Focus the memory "follow address" input |
| Ctrl+P | Command palette (fuzzy over lldb commands, subcommands too) |
| Ctrl+T | Toggle the tracer (auto BPs on libc I/O and network calls) |
| Ctrl+K | Clear the trace tab |
| Ctrl+D | Defenses menu (PT_DENY_ATTACH bypass, hardware BP mode) |
| Ctrl+C | Quit |
| Right click on a row | Context menu (goto, breakpoint, edit, copy) |

Whatever you type in the console goes straight into `SBCommandInterpreter.HandleCommand`, so every lldb command is available. If a command would trigger an interactive Y/N prompt (`run`, `br del`), the wrapper handles the prompt for you before the command reaches lldb.
