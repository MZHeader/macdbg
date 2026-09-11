# Automatic clock compensation

Prefer this mode when debugger pauses inflate elapsed-time checks and the
check's decision site is not yet known. It requires no manual timing rule,
threshold, register assignment, or decoded target symbol.

At the initial entry stop:

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"auto_clock"}'
./agent.sh cmd SESSION clock_status
./agent.sh cmd SESSION continue --json '{"timeout":15}'
```

The GUI equivalent is **Defenses → Hide debugger pauses**. Enable Analysis
cloak separately if target-text integrity and other anti-analysis defenses are
needed. Manual `anti_timing` rules and automatic clocks are mutually exclusive;
neither mode is implicitly enabled by Analysis cloak or Enable ALL.

## What it covers

- Main-executable imports for `mach_absolute_time`, `mach_continuous_time`,
  `clock_gettime`, `gettimeofday`, and `mach_wait_until`. The import slots are
  discovered from live Mach-O metadata; no target-specific addresses are needed.
- The executable's `dlsym` import is also routed through a forwarder. Successful
  resolutions of the supported OS clocks receive their corresponding forwarder
  pointer. Unknown symbols, failed lookups, and custom implementations retain
  their real results. The compensation scope is callers returning into the
  main executable's `__TEXT,__text`.
- A process-wide budget subtracts observed debugger-stop time. Actual execution
  and target sleeps advance time. Mach tick conversions use the real timebase;
  inline counter conversions use the counter frequency. Results for monotonic
  clocks are nondecreasing without fixed increments per call.
- A bounded scan (4 MiB) of current main text finds `CNTVCT_EL0` and
  `CNTPCT_EL0` reads. They are intercepted using hardware breakpoints. A small
  native reader is compiled from the repository into `MACDBG_STATE_DIR/native`
  (or `~/.macdbg/native`) and loaded only into the debugger.
- A small process-local page holds frameless tail branches to the real APIs.
  It is written as data, then protected read/execute. Software breakpoints live
  on these forwarders; system clock routines and main `__text` are unchanged.
  Frameworks keep their original imports and clocks. A forwarder called from
  outside the main text also passes through to the real API.
- Direct counters and pending `dlsym` return hooks use hardware slots. Counter
  allocation failure rolls back those hooks and reports partial counter coverage.
  A resolver return that cannot be armed blocks progress rather than silently
  returning an unprotected clock pointer.
- Main-executable `mach_wait_until` calls translate virtual Mach deadlines to
  real deadlines at entry. Other absolute wait APIs and further debugger pauses
  during a kernel wait are not virtualized.

## Operational boundaries

`clock_status` exposes `enabled`, `safe`, `error`, `scope`, `apis`, `hits`,
`passthrough`, `paused_ns`, `counter_kinds`, `counter_sites`, `counter_armed`,
`counter_coverage_complete`, `scan_complete`, and `coverage_notes`. Safe means
that installed hooks validate; inspect counter coverage separately. A truncated
scan or exhausted counter slots must not be reported as complete protection.
`entry_points` maps names to current forwarder addresses; `import_bindings`
counts rebound import slots and `dynamic_resolutions` records routed lookups.
To break on a virtualized API call, use its reported entry point. Breakpoints
on the original system routine only see calls that actually reach that routine.

Unsupported clock IDs, CPU clocks, invalid output buffers, and timezone
requests to `gettimeofday` run through the original API. Successful compensated calls leave
target errno alone. Framework-internal scheduling remains on real clocks.

Enable only at entry. Same-target restart re-arms an enabled mode with fresh
pause/hit state. New targets and sessions start disabled. To turn it off:

```sh
./agent.sh cmd SESSION defense_disable --json '{"name":"auto_clock"}'
```

Disabling cannot undo already returned timestamps; restart before re-enabling
or testing comparisons across the mode change. Original import values are
restored when still owned by the mode. Forwarders remain mapped until process
exit so cached pointers continue calling the real APIs after disable.
Modified/deleted hooks, bindings, forwarder code, or counter instructions block
execution with an error. Use structured controls to
manage the mode, rather than manipulating internal breakpoint IDs.

Continue, instruction step-in/over/out, GUI and headless event handling share
pause accounting. Clock reads are intercepted atomically and may advance PC to
the caller or the instruction after a counter read. User stops at shared sites
are preserved. Source-level stepping is refused while this mode is on.

This is approximate compensation, not an undetectable virtual machine. Import
values and resolved clock pointers change, and the forwarder page is observable.
Pointers cached before activation, unsupported import layouts, other resolution
APIs, and direct calls that bypass the discovered bindings are outside coverage.
Transport/scheduling overhead before stop observation remains measurable.
Host monotonic accounting retains the distinction between clocks that include
system sleep and those that exclude it. Calls from other modules, generated
code, other counter instructions, external clocks/watchdogs, and raw LLDB
execution or target-side expressions can escape the coverage/accounting model.

## Benign validation only

```sh
make -C tests/integration all
/usr/bin/python3 -m unittest -v tests.integration.test_auto_clock tests.integration.test_framework_interop
```

The tests use controlled programs that read clocks, run arithmetic, optionally
sleep, and print results. They insert debugger pauses and assert that checks
pass with automatic compensation and no manual timing rules; intentional target
sleeps must still be visible. Additional tests cover waits, errors, monotonic
reads, GUI events, thread ownership, stepping and partial counter coverage.
Executing a supplied analysis target requires separate user authorization.
