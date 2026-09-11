# Timing decision rules

For an automatic first attempt, use [Automatic clocks](automatic-clocks.md).
Manual timing rules remain the advanced option for verified decision sites;
the two modes cannot be enabled simultaneously.

Use when a verified timing decision must be neutralized while preserving code
bytes. This is a rule engine for native ARM64 main-executable instructions,
not automatic detection, clock virtualization, or a process-wide guarantee.
Clock APIs, dynamically resolved clocks, and direct counter reads can all feed
decisions handled this way; determine the actual decision and live register
meaning through analysis first. Do not infer a safe action from a clock import.

## Configure and toggle

At a stopped process, with `anti_timing` disabled and no step in progress:

```text
timing_rule_add {"name":"elapsed-result","addr":"<load-address>","register":"w8","value":0}
timing_rule_add {"name":"elapsed-bits","addr":"<load-address>","register":"x8","mask":"0xff","value":0}
timing_rule_add {"name":"elapsed-branch","addr":"<load-address>","redirect":"<success-address>"}
timing_rule_remove {"name":"elapsed-result"}
timing_rules
defense_enable {"name":"anti_timing"}
defense_disable {"name":"anti_timing"}
```

These are alternative actions, not three rules to add at the same address.
Only one rule per instruction is allowed. Numeric fields accept JSON integers
or numeric strings. Register actions support `x0`–`x30` and `w0`–`w30`;
W-register writes zero-extend into X. Without a mask the whole named register
width is replaced. With a mask, `(old & ~mask) | value` preserves other bits;
the value must contain only masked bits. Redirect rules change PC without
executing the original instruction; verify the destination's required state.

Each rule captures instruction bytes and saves offsets relative to the main
executable header. In launch sessions, Save/Stop persists them in the per-binary,
SHA-256-keyed state. Do not store a runtime address as a reusable fixed address.
Rules reload disabled in new sessions; enabled rules rearm on same-target
restart after validating instruction bytes. New targets clear the previous
target's rules and hooks before loading their own saved configuration.
Rules added to attached processes are session-local because attach sessions
do not currently have a saved per-binary state object.

The GUI has **Defenses → Configure timing rules** and a separate **Timing
rules** toggle. Neither Analysis cloak nor Enable ALL enables timing rules.

## Execution and troubleshooting

- Hardware breakpoints are required, even with the cloak off. Capacity or
  byte-validation failures are explicit; there is no software fallback.
- Use Analysis cloak as well when every managed breakpoint in target text
  must preserve code integrity. Timing rules own only their own sites.
- Rules operate on the hitting thread, log old/new values, and preserve user
  breakpoints at shared sites. Instruction step-in/over/out retain ownership
  of execution; source-level steps are refused while timing rules are active.
- `timing_rules` returns `enabled`, `safe`, `error`, `armed`, `hits`, and
  `rules`. `status.defenses` includes `anti_timing`, `anti_timing_safe`,
  `anti_timing_armed`, and `anti_timing_error`.
- An enabled rule whose hook or instruction was changed blocks resume.
  Disable it, repair/reconfigure, and re-enable. A failed action holds the
  process stopped; do not repeatedly resume past the error.
- The raw LLDB command remains unrestricted and can invalidate guarantees.
  Use structured timing commands to manage rule hooks, rather than deleting
  or modifying internal breakpoint IDs.
- Timing rules do not automatically cover other modules, newly generated
  code, external clocks or watchdog processes. Disabling a rule affects future
  hits; it does not undo state edits already applied to the current process.

## Benign regression fixtures

The fixtures only read local clocks, run arithmetic, optionally sleep, and
print output. They test minimum/maximum timing aggregation, key corruption,
register/mask/redirect actions, and several clock sources including a direct
ARM counter. Use these controlled programs for validation:

```sh
make -C tests/integration build/timing_fixture build/timing_fixture_optimized
/usr/bin/python3 -m unittest -v tests.integration.test_timing_rules
```

Tests create temporary per-test state directories and clean up their sessions.
Build products stay under ignored `tests/integration/build/`. For other
isolated experiments, set `MACDBG_STATE_DIR` to an absolute scratch directory;
this redirects both saved debugger state and agent session records. Always
stop created sessions. Executing a supplied analysis target requires the
user's authorization; fixture testing does not imply it.
