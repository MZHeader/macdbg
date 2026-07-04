# lldb-wrapper

x64dbg-style Textual TUI on top of Apple's system LLDB.

Live panes for disassembly, registers, stack, memory, plus tabs for
breakpoints / threads / modules, and a console that accepts raw lldb
commands. Select any row in the disassembly and the memory pane follows
the operand address (x64dbg-style "follow in dump").

## Requirements

- macOS with Xcode Command Line Tools (`/usr/bin/lldb` present).
- System Python 3.9 (`/usr/bin/python3`).
- `pip install --user textual` (into the system Python — see below).

```sh
/usr/bin/python3 -m pip install --user textual
```

## Run

```sh
./run.sh /bin/ls          # system binaries are usually blocked by macOS
./run.sh test/hello       # tiny sample
./run.sh test/fakemal     # XOR-decrypt strings, fake C2 beacon, worker thread
```

Rebuild the test binaries with `make -C test`.

`run.sh` sets `PYTHONPATH` to `$(lldb -P)` so `import lldb` resolves
against the framework build shipped with the CLT.

## Keys

| Key    | Action                                     |
|--------|--------------------------------------------|
| F7     | Step in                                    |
| F8     | Step over                                  |
| F9     | Continue                                   |
| F2     | Toggle breakpoint at current pc            |
| Enter  | (in disasm) Follow operand address in Memory pane |
| `:`    | Focus the raw lldb command bar             |
| Ctrl+G | Focus the memory "follow address" input    |
| F5 / F6 | Scroll memory pane up / down by 512 B     |
| Ctrl+T | Toggle **Trace** — auto-BP libc I/O + net calls, log to Trace tab |
| Ctrl+K | Clear the Trace tab                        |
| Ctrl+C | Quit                                       |
| Ctrl+P | Command palette — fuzzy search all lldb commands (subcommands too, e.g. `thread s`) |
| Right-click on a row | Context menu (goto / breakpoint / edit / copy) — pane-specific |

Anything typed in the command bar is passed straight to
`SBCommandInterpreter.HandleCommand`, so all lldb commands still work.
