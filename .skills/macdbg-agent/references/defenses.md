# Choose and check defenses

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"analysis_cloak"}'
./agent.sh cmd SESSION status
```

Use `defense_disable` with the same name to turn a mode off.

| Name | Use for |
| --- | --- |
| `analysis_cloak` | Environment, parent, VM/hardware identity, loaded-image and `P_TRACED` checks, with main-code integrity protection. Enable at entry. |
| `auto_clock` | Timing inflated by debugger pauses; [clock guide](automatic-clocks.md). Enable at entry. |
| `anti_timing` | A known timing decision; configure [rules](timing-rules.md) first. |
| `anti_ptrace` | `ptrace(PT_DENY_ATTACH)` through libc. |
| `direct_syscall` | Supported inline ARM64 `svc` calls for `PT_DENY_ATTACH`. |
| `anti_mach_ports` | `task_get_exception_ports` inspection. |
| `anti_sysctl` | Clear `P_TRACED` from `sysctl(KERN_PROC)` results. |
| `anti_csops` | Clear `CS_DEBUGGED` from `csops(CS_OPS_STATUS)`. |
| `anti_parent` | Scrub debugger parent names in `sysctl(KERN_PROC)` results. |
| `anti_sigtrap` | Forward a target's own `brk #0` to its registered SIGTRAP handler. |
| `fork_identity` | Follow the child path in-process without a real fork. |
| `exec_sandbox` | Intercept process/OSA execution; [decision and dump guide](exec-sandbox.md). |

The libc `syscall()` wrapper is covered for ptrace/sysctl/csops when their
corresponding defense is on. This does not cover arbitrary inline syscalls.
The cloak includes sysctl/parent protection, but does not turn on every toggle
above. In particular, clocks and execution interception must be enabled separately.

## Cloak readiness

Require `status.defenses.analysis_cloak_safe == true`. Read
`analysis_cloak_error` if false. `analysis_cloak_deferred` can be nonzero before
IOKit loads; a loaded but unresolved or disabled required hook is an error.

Cloak requires hardware breakpoints in main executable text and rejects tracked
text patches. If slots are exhausted, remove an unneeded user breakpoint or
reduce tracing; never substitute a software breakpoint. Instruction step-in is
one instruction; step-over/out use bounded hardware plans. Source-level stepping
and step-out from an inline frame are refused. New targets start with defenses
off; same-target restart rearms requested defenses.

Cloak cannot coexist with fork-tree DYLD interposition. Prefer a new session
when changing analysis strategy. Hook/instruction validation errors require
repair or restart, not repeated continue attempts.

## Coverage that matters when interpreting a result

- Sanitizes known DYLD/debugger environment variables, selected parent names,
  supported sysctl hardware/VM keys, two IOKit identity properties, and known
  instrumentation image names. It does not hide every possible inspection API.
- `kern.hostuuid` shares the IOKit UUID. Numeric-MIB UUID queries and
  `gethostuuid()` are outside that addition; native unsupported-key errors stay.
- Target `__TEXT,__text` stays intact; import slots and other data can still change.
- Self-trap forwarding does not cover arbitrary BRK values, SIGILL, or handlers
  requiring full signal context. Runtime assertions remain real stops.
- IOKit string handling and self-trap lookup still use target-side helper calls.
  Intermittent Objective-C/LaunchServices lock assertions remain unresolved on
  macOS 15. Capture the backtrace; do not skip the trap or claim a bypass succeeded.

Exact spoof constants and blacklist entries are in `macdbg/core/anti_analysis.py`.
Check them when analyzing a value comparison instead of assuming a particular
machine identity from the toggle name.
