# Timing decision rules

Use for a decision instruction you have verified through analysis. For an
automatic first attempt use [automatic clocks](automatic-clocks.md); the two
modes cannot run together. Rules require native ARM64 main-executable addresses.

Stop the target and leave `anti_timing` disabled while adding/removing rules.
Choose one action for each instruction. The addresses below are placeholders;
read the live disassembly and verify register meaning before replacing them.

```sh
./agent.sh cmd SESSION timing_rule_add --json '{"name":"elapsed-result","addr":"0x100004000","register":"w8","value":0}'
./agent.sh cmd SESSION timing_rules
./agent.sh cmd SESSION defense_enable --json '{"name":"anti_timing"}'
./agent.sh cmd SESSION continue --timeout 15
./agent.sh cmd SESSION timing_rules
```

Alternative action arguments:

| Action | Fields passed to `timing_rule_add` |
| --- | --- |
| Replace a register | `name`, `addr`, `register`, `value`. Registers: `x0`–`x30`, `w0`–`w30`; W writes zero-extend into X. |
| Replace selected bits | Add `mask`, e.g. `"0xff"`. Applies `(old & ~mask) | value`; value must contain only masked bits. |
| Skip to a verified destination | `name`, `addr`, `redirect`. Changes PC without executing the original instruction; verify destination state. |

```sh
./agent.sh cmd SESSION defense_disable --json '{"name":"anti_timing"}'
./agent.sh cmd SESSION timing_rule_remove --json '{"name":"elapsed-result"}'
./agent.sh cmd SESSION save
```

`timing_rules` returns `enabled`, `safe`, `error`, `armed`, `hits`, and `rules`.
Require safe/armed rules and inspect hit counts and console old/new values after
running. An import of a clock API alone does not identify a safe patch site.

Rules save expected instruction bytes and main-module offsets, not reusable
absolute addresses. Save/stop persists launch-session rules; new sessions load
them disabled. Same-target restart validates and rearms enabled rules. Attach
session rules are not persisted.

Hardware slots are required even without cloak. Exhaustion, changed instructions
or missing hooks block resume. Remove unneeded user breakpoints or disable and
correct the rule; do not delete its internal hook through raw LLDB. Instruction
step-in/over/out are supported; source-level stepping is refused. Enable cloak
separately if other managed breakpoints must also preserve main-code bytes.
Rules cover their configured sites only and do not change clocks or undo earlier
register/PC edits when disabled.
