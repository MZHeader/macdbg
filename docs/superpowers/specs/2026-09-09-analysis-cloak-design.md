# Analysis Cloak Design

## Objective

Add a reusable, opt-in `analysis_cloak` defense to macdbg that defeats the
documented environment, parent-process, virtualization, hardware-identity,
loaded-image, text-integrity, timing, and `sysctl` checks without patching the
sample's control flow. Validate the defense against compiled ARM64 macOS
fixtures, including a combined fixture whose failed checks corrupt a derived
ChaCha20 key and prevent recovery of a known payload.

All development and testing takes place in the isolated
`/Users/liamchugg/Projects/macdbg/testing` repository copy. The original
repository remains untouched.

## Scope

### Included

- Remove these variables from the target environment:
  `DYLD_INSERT_LIBRARIES`, `DYLD_FORCE_FLAT_NAMESPACE`,
  `DYLD_PRINT_LIBRARIES`, `DYLD_PRINT_INITIALIZERS`, `DYLD_PRINT_BINDINGS`,
  `DYLD_IMAGE_SUFFIX`, `MallocStackLogging`, `MallocStackLoggingNoCompact`, and
  `NSZombieEnabled`.
- Hide blacklisted debugger and analysis-tool names returned for a parent
  process through `sysctl(KERN_PROC)` and full-path process APIs such as
  `proc_pidpath`.
- Return a clean value for `kern.hv_vmm_present`.
- Return plausible deterministic values for `hw.model`,
  `machdep.cpu.brand_string`, `IOPlatformSerialNumber`, and
  `IOPlatformUUID`.
- Hide blacklisted paths returned by dyld image enumeration.
- Preserve the target's `__TEXT,__text` bytes by requiring hardware
  breakpoints for every macdbg-managed breakpoint in that section while the
  cloak is active.
- Reuse the existing timing cloak and syscall-number-202 `P_TRACED` scrub.
- Expose one composite defense through both the GUI and headless agent while
  retaining useful individual toggles.
- Preserve the existing exec prompt and disk-dump behavior: Allow, Fake
  success, Block, or Dump, plus automatic dumping of oversized payloads.

### Excluded from v1

- Compatibility between the analysis cloak and the DYLD fork-tree interposer.
- Hiding direct `mrs cntvct_el0` timing reads or wall-clock APIs not already
  covered by the timing defense.
- Generic concealment from arbitrary private or undocumented inspection APIs.
- Forging arbitrary SHA-256 results or patching sample-specific check sites.
- x86_64 support.

## Approach

Use selective API virtualization rather than call-site patches or hash-result
forgery. macdbg will intercept the APIs that expose analysis signals, allow
ordinary calls to behave normally, and rewrite only blacklisted results. This
keeps the defense reusable and avoids changing target `__text`, which is itself
part of the sample's integrity check.

The new `macdbg/core/anti_analysis.py` module owns policy and classification:

- environment-variable and tool/image blacklists;
- deterministic clean hardware identity values;
- pure helpers for case-insensitive blacklist matching, launch-environment
  filtering, path replacement, and sysctl-value selection;
- defense breakpoint ownership and per-process scratch state.

`macdbg/core/debugger.py` remains responsible for LLDB mechanisms: creating
breakpoints, reading arguments, arming thread-specific return breakpoints,
writing result buffers/registers, allocating target-side replacement strings,
and continuing the process. The GUI engine and agent session only dispatch the
composite toggle, include its breakpoint IDs in the hidden set, and surface
status/messages.

## Defense Behavior

### Environment

When the cloak is enabled, macdbg filters the nine variables from every future
`SBLaunchInfo` environment. Because the GUI and agent initially stop at the
program entry point before the sample's `main`, enabling the cloak also calls
`unsetenv` inside the stopped target for each variable. This makes `getenv`,
`_NSGetEnviron`, and direct `environ` iteration agree. Enabling the cloak after
the target has begun executing is rejected with a clear instruction to restart
at entry.

### Parent identity

The existing `sysctl(KERN_PROC_PID)` return scrub is expanded to match the full
case-insensitive tool blacklist, not only `debugserver`, `lldb`, and `gdb`.
Calls to `proc_pidpath` are allowed to complete, then their output buffer is
replaced with `/sbin/launchd` only when the returned path contains a blacklisted
name. Unrelated process paths are untouched.

### Hypervisor and hardware sysctls

A breakpoint on `sysctlbyname` records recognized names and output buffers at
entry and uses a thread-specific one-shot breakpoint at the return address.
After a successful real call:

- `kern.hv_vmm_present` becomes integer zero;
- `hw.model` becomes `Mac14,6`;
- `machdep.cpu.brand_string` becomes `Apple M2 Pro`.

The implementation respects the caller-provided buffer size, NUL-terminates
strings, and updates the returned length when the API provides a length pointer.
Unknown sysctl names pass through without modification.
Successful length-only queries (`oldp == NULL`) publish the spoof payload's
size through `oldlenp` without writing a data buffer. Unreadable or unwritable
length storage retains the same rollback and fail-closed behavior.

### IOKit identity

`IORegistryEntryCreateCFProperty` is intercepted only for
`IOPlatformSerialNumber` and `IOPlatformUUID`. macdbg identifies the incoming
`CFStringRef` key through an LLDB expression with breakpoints ignored and
returns a newly created target-side `CFString` containing deterministic clean
values:

- serial: `C02ZQ0ABC123`;
- UUID: `8D4C7A12-3F65-4B90-A2DE-61C8E5079F34`.

If CoreFoundation evaluation is unavailable, the hook reports failure instead
of silently claiming that the property was cloaked.

### Loaded images

`_dyld_get_image_name` is allowed to return normally. A thread-specific return
breakpoint inspects the returned C string. If it contains a blacklisted image
name, macdbg replaces `x0` with a target-allocated pointer to
`/usr/lib/libSystem.B.dylib`. It never overwrites dyld-owned memory, and clean
image paths pass through unchanged.

This hides enumeration results only. The v1 cloak refuses to coexist with
macdbg's fork-tree interposer because the interposer intentionally introduces
both a forbidden environment variable and a loaded image.

### `__TEXT,__text` integrity

The cloak does not forge hashes. Instead, it prevents macdbg from changing the
bytes being hashed:

- the temporary entry breakpoint is removed before the sample runs;
- direct `svc #0x80` scan sites use hardware breakpoints;
- structured user breakpoint creation uses hardware breakpoints while the
  cloak is active;
- tracer hardware mode is required if tracer locations resolve inside the
  main executable's `__text`;
- before every resume, macdbg inspects all breakpoint locations within the
  target `__text` range and rejects the resume if any location is not known to
  be hardware-backed;
- tracked patches overlapping `__text` also block resume.

If a hardware slot cannot be allocated, enabling the relevant breakpoint or
continuing fails explicitly. macdbg never falls back to a software breakpoint
while integrity protection is active.

### Existing protections

The composite defense enables the current `anti_sysctl`, `anti_timing`, and
parent-related handling. Syscall 202 continues to use the existing
`syscall`/`__syscall` multiplexer and return-buffer scrub. Timing continues to
virtualize `mach_absolute_time`, `mach_continuous_time`, and
`clock_gettime_nsec_np` with the documented fixed-step limitation.

## State and Failure Handling

Enabling `analysis_cloak` is transactional. macdbg reports each armed,
deferred, or failed hook. A symbol breakpoint that is valid but awaiting a
framework load may remain deferred; before the first resume, every API imported
by the current executable must have a resolved hook. Missing critical hooks,
unsafe target-text breakpoints, text patches, enabling after entry, or active
fork-tree interposition block execution with an actionable error.

Every actual rewrite emits one concise `[anti-analysis]` message. Repeated
high-frequency timing calls retain the existing log suppression. Relaunch clears
return-breakpoint and target-allocation state, reapplies launch filtering, and
re-arms the composite defense.
Replacing the target through Open or Attach disposes its target-owned defense
state. A new target starts with the cloak off and can enable it at its own
entry stop; same-target restart preserves the requested mode.

Disabling the cloak removes only breakpoints and allocations owned by the
cloak, disables the composite-owned existing defenses, and restores normal
software-breakpoint policy. It does not undo unrelated user configuration.

## Interfaces

Headless agent:

```text
defense_enable  {"name":"analysis_cloak"}
defense_disable {"name":"analysis_cloak"}
```

Status reports whether the cloak is enabled, whether integrity mode is safe,
and counts for resolved/deferred hooks. Internal cloak and return breakpoints
remain hidden from normal breakpoint listings and protected from structured
mutation.

The GUI Defenses menu gains `Analysis cloak` and includes it in `Enable ALL
anti-debug bypasses`. Attempting to enable fork-tree tracing while the cloak is
active, or vice versa, returns a visible incompatibility error.

## Test Strategy

Tests live under tracked `tests/`, because the repository's existing `test/`
directory is ignored. Pure policy tests run without importing LLDB. macOS
integration tests compile temporary ARM64 fixtures and drive them through
`agent.sh`.

The fixtures cover:

1. `getenv`, `_NSGetEnviron`, and direct `environ` inspection.
2. Parent identification through `sysctl(KERN_PROC_PID)` and `proc_pidpath`.
3. `kern.hv_vmm_present`, `hw.model`, and
   `machdep.cpu.brand_string` through `sysctlbyname`.
4. `IOPlatformSerialNumber` and `IOPlatformUUID` through IOKit.
5. Dyld enumeration after loading a deliberately named
   `FridaGadget.dylib` fixture.
6. In-memory SHA-256 of the fixture's own `__TEXT,__text`, with the expected
   baseline digest supplied independently of that section.
7. `mach_timebase_info` plus `mach_absolute_time` threshold detection.
8. syscall number 202 with `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}` and a
   `P_TRACED` assertion.
9. Existing exec interception, including interactive Dump and oversized
   automatic dumps.
10. A combined fixture where each failure XORs a distinct constant into a
    password-derived ChaCha20 key. The uncontrolled/debugged run must not
    recover the known plaintext; the cloaked agent run must recover it exactly.

Each feature follows red-green-refactor: first compile or run a test that fails
because the behavior is absent, then add the smallest implementation, then run
the focused test and full suite. End-to-end sessions are always stopped so no
debugged child or agent daemon remains alive.

## Acceptance Criteria

- The original `/Users/liamchugg/Projects/macdbg` working tree has no new source
  modifications from this project.
- All new unit and integration tests pass in the isolated `testing` copy.
- Each standalone fixture demonstrates detection without its corresponding
  defense and a clean result with the defense enabled.
- The combined fixture prints the exact known payload only with
  `analysis_cloak` enabled.
- The fixture's in-process `__text` digest remains identical to its clean
  baseline while all required defense breakpoints are armed.
- Existing defense, tracing, GUI, agent, and exec-dump behaviors exercised by
  regression tests continue to work.
- No agent session, debug target, or temporary server remains running after the
  test suite completes.
