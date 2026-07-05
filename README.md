# macdbg

A Textual TUI for Apple's system LLDB. Gives you a multi-pane view of the running process. Includes a lazy syscall & network tracer, defeats anti-debugging checks, and lets you edit registers and memory in place.

![Main view](docs/img/main-v4.png)

## Who Is This For

For reverse engineers debugging macOS binaries who aren't very good at remembering CLI commands and want an experience closer to x64dbg.

## Requirements

- macOS with the Xcode Command Line Tools installed (`xcode-select --install`) — this provides `/usr/bin/lldb` and `/usr/bin/python3`, both of which macdbg uses directly.

There is nothing to `pip install`: LLDB's Python bindings come from the system LLDB (they are not on PyPI) and the UI dependencies (textual, rich, and friends) are vendored under [`vendor/`](vendor), so a clone is self-contained. The one native component, the fork-tree tracer's interposer, ships as a prebuilt universal (arm64 + x86_64) dylib in [`macdbg/native/`](macdbg/native), so a stock offline box needs no compiler; the source sits beside it and is only recompiled if the prebuilt is missing or doesn't cover the host architecture.

## Install

```sh
git clone https://github.com/MZHeader/macdbg
cd macdbg
./macdbg.sh /path/to/your/binary
```

`macdbg.sh` is the entry point: it points `PYTHONPATH` at the system LLDB bindings (`lldb -P`) and the vendored dependencies, then launches the TUI. Run it from the clone.

## Syscall and Network Tracer

Feeling lazy? Ctrl+T arms breakpoints on file, process, and network entry points in libSystem. Each hit logs the call with parsed arguments and the process auto-continues, so tracing does not stop execution.

The tracer also hooks the plaintext side of TLS, so for a sample that rolls its own TLS over raw sockets the socket `send`/`recv` only carry ciphertext, but the cleartext request — the full URL, headers, and body — shows up at the write call before encryption. This is how you recover a C2 endpoint like `api.telegram.org/bot<token>/sendMessage` that never appears on the wire in the clear. Covered write functions: `SSL_write`/`SSL_write_ex` (OpenSSL/BoringSSL), `SSLWrite` (Secure Transport), `mbedtls_ssl_write`, `wolfSSL_write`, `gnutls_record_send`, `tls_write` (LibreSSL), Go's `crypto/tls.(*Conn).Write`, `EVP_AEAD_CTX_seal` (the BoringSSL/aws-lc record-sealing primitive), and rustls's `<Writer as std::io::Write>::write` (matched by regex since its symbol carries a per-build hash). Go and rustls both put the plaintext slice pointer and length in the same registers the C functions use, so one reader handles all of them.

The catch is symbols. The C write functions resolve only if the sample links the TLS library dynamically; the Go and rustls hooks resolve only if the binary keeps its symbol table. A fully stripped in-language TLS stack — `go build -ldflags "-s -w"`, or a Rust build with `strip = true` — exposes no name to hook, and the plaintext is cleared before the socket `write`, so it isn't recoverable by scanning memory at send time either. For those the realistic options are finding the write function by hand (disassembly) and breakpointing it, or extracting the TLS session keys and decrypting the ciphertext the tracer already logs.

![Trace tab](docs/img/trace.png)

### Tracing forked children

lldb on macOS cannot follow a fork into the child — there is no `PTRACE_TRACEFORK`, and a debugger that attaches to a forked child can read its memory but its breakpoints never fire. So a sample whose real work happens in a forked child (a C2 handler loop, a per-connection worker) is invisible to the breakpoint tracer, which only ever sees the parent.

The **Fork-tree syscall trace** toggle in the Ctrl+D menu fills that gap without ptrace. It relaunches the target with a small interposer dylib on `DYLD_INSERT_LIBRARIES`, which is inherited across `fork`, so every child that isn't a restricted system binary reports its `read`/`write`/`send`/`recv`/`connect`/`open` calls — with decoded buffer contents — into the trace pane, tagged by pid. This is how you see the commands a forked C2 child receives and the data it sends back, which lldb alone can't show. It complements the breakpoint tracer: the interposer covers the children, the breakpoint tracer covers the parent (so parent calls aren't double-listed).

The limit is `exec`. Because the parent is ptrace-traced, macOS marks its children restricted, and `dyld` drops `DYLD_INSERT_LIBRARIES` when a restricted process calls `exec`. So a fork **without** exec — the child runs the sample's own code — is fully traced; a fork **followed by exec** loses the interposer at the exec (into `/bin/sh` and other system binaries it would be stripped regardless). For a fork+exec child the parent side is usually the useful view anyway: the command it feeds the child over the pipe shows up in the parent's traced `write`.

## Anti-anti-debug

Ctrl+D opens a menu of independent bypass toggles, all off by default:

![Defenses menu](docs/img/debug-menu.png)

- **Anti-ptrace: defeat PT_DENY_ATTACH via libc** hooks `ptrace` and returns `0` when the deny flag is set, so the kernel never sees the call.
- **Anti-ptrace: defeat inline PT_DENY_ATTACH** catches the same denial when the sample skips libc and issues `svc #0x80` inline.
- **Anti-debug: cloak Mach exception ports** hooks `task_get_exception_ports` and returns zero ports, so nothing looks attached.
- **Stealth BPs for your breakpoints** puts your breakpoints in hardware registers instead of patching bytes in `__TEXT`, which beats prologue-hash checks.
- **Stealth BPs for the tracer** does the same for tracer BPs. Flip it before enabling the tracer.
- **Fork intercept: run child path in-process** makes `fork`/`vfork` return `0` and `setsid` return a positive fake sid, so the current process walks the child code path in-process and no debugger reattach is needed. This is the tool for a *daemonization gate* (fork, parent `_exit`s, child `setsid`s to detach). It is the wrong tool for a fork that immediately `execvp`s a helper — that would exec your traced process into the helper and lose it — so pair it with the prompt below on a sample that does both.
- **Fork intercept: prompt each fork** halts on every `fork`/`vfork` and asks per call site: **Stay in parent** (let the real fork happen, child runs untraced, you keep debugging the parent — right for a fork+exec where the interesting logic drives a pipe/PTY from the parent) or **Enter child in-process** (fake the return to `0` and walk the child branch in-process, right for a fork whose child is C2 logic rather than an `exec`). Lets you mix both in one sample.
- **Exec sandbox: intercept outbound exec** hooks `system`, `popen`, `execve`, `execvp`, `posix_spawn`, and `posix_spawnp`. With the prompt off it auto-blocks (returns `-1`); with **prompt each call** on it halts on each and offers Allow, Fake success (block the call but return a success value, so a sample that checks the result keeps running instead of detecting the block), Block, or Dump payload. The preview reads the whole command and, for the exec/spawn calls, the full `argv`, so a dropper that hides its script in `osascript -e <script>` or `sh -c <script>` shows up instead of just the interpreter path. Dump payload writes the full command and `argv` to `~/.macdbg/<binary>-<sha>/dumps/` when you pick it; unattended auto-block writes large payloads there on its own since there's no prompt to ask.

### What The Fork Bypass Defeats

This is the macOS daemonization gate. Parent exits to look like normal termination, and the child re-parents to launchd and detaches from the controlling TTY so a debugger attached to the parent loses visibility. If either call fails, the sample bails without running the payload.

```c
pid_t pid = fork();
if (pid < 0) {
    return;
}
if (pid > 0) {
    _exit(0);
}

pid_t sid = setsid();
if (sid < 0) {
    return;
}
```

The compiled form checks the sign bit directly (`tst x0, #0x80000000` or `tbnz x0, #31, <bail>`) rather than comparing to `-1`. Fork identity mode returns `0` from `fork` and a positive value from `setsid` so both branches walk into the payload block instead of the abort path.

### What The Exec Sandbox Defeats

Samples that harden themselves against dynamic analysis by killing the analyst's environment. A common pattern is `killall Terminal`.

```c
system("uname -a");
if (some_check()) {
    system("killall Terminal");
}
decrypt_c2_config();
```

Auto-block mode intercepts every outbound exec and returns `-1`. Interactive mode is more useful for real triage: the recon `system("uname -a")` gets an Allow so the sample sees real output. The `system("killall Terminal")` gets a Block and returns `-1`. Sample believes both fired and keeps executing into the payload.

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
| Ctrl+G | Focus the memory follow-address input |
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