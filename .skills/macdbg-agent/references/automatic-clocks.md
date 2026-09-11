# Automatic clock compensation

Use when debugger pauses inflate elapsed time and you have not identified the
check's decision site. Native ARM64 only; enable at the initial entry stop.

```sh
./agent.sh cmd SESSION defense_enable --json '{"name":"auto_clock"}'
./agent.sh cmd SESSION clock_status
./agent.sh cmd SESSION continue --timeout 15
```

GUI: **Defenses → Hide debugger pauses**. `analysis_cloak` can be enabled
alongside it; `anti_timing` cannot. Neither timing mode is enabled by the cloak.

## Read the status before claiming coverage

| Field | How to use it |
| --- | --- |
| `enabled`, `safe`, `error` | Require enabled/safe; resolve errors before resuming. |
| `apis`, `import_bindings`, `dynamic_resolutions` | Check which main-executable clock bindings were found. |
| `counter_sites`, `counter_armed`, `counter_coverage_complete`, `scan_complete`, `coverage_notes` | Check inline-counter coverage separately; `safe` can be true with partial coverage. |
| `hits`, `paused_ns`, `passthrough` | Check whether the relevant calls actually reached compensation. Zero hits is not proof the target has no timing check. |
| `entry_points` | Current forwarder addresses. Break here to observe virtualized calls, not at the original shared-library entry. |

Covers discovered main-executable imports and its `dlsym` lookups for
`mach_absolute_time`, `mach_continuous_time`, `clock_gettime`, `gettimeofday`,
and `mach_wait_until`, plus recognized main-text `CNTVCT_EL0`/`CNTPCT_EL0`
reads. Counter scanning is limited to 4 MiB and available hardware slots.

Observed debugger-stop time is subtracted. Actual execution and intentional
sleeps still advance time. The pause budget is shared across threads, continue,
and instruction stepping. Intercepted clock reads are handled atomically;
source-level stepping is refused.

Calls from other modules, CPU/unsupported clocks and invalid arguments use native
behavior. Cached pointers from before activation, undiscovered bindings, generated
code, other counter instructions, external clocks and watchdogs are not covered.
Transport/scheduling overhead remains measurable. Main-caller `mach_wait_until`
deadlines are translated at entry; pauses during an existing kernel wait and
other absolute-deadline APIs are not virtualized.

Disable with `defense_disable {"name":"auto_clock"}`. Restart before comparing
results across mode changes or enabling again; old returned timestamps cannot be
undone. Same-target restart rearms the mode and clears hit/pause state. Modified
hooks, import slots or counter instructions block resume. Use the structured
toggle to restore bindings; leave internal breakpoint IDs alone.
