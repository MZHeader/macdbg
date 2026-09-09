# Analysis Cloak Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and verify an opt-in macOS analysis cloak that neutralizes the documented environment, parent, virtualization, hardware-identity, image-enumeration, text-integrity, timing, and `P_TRACED` checks while preserving command dumping.

**Architecture:** A focused `AnalysisCloak` component owns blacklist policy, LLDB hook state, return-side rewrites, and integrity validation. `Debugger` supplies low-level process/breakpoint helpers, while the GUI engine and headless agent share the same composite defense and stop-dispatch behavior. Tests use pure Python policy cases plus a compiled ARM64 fixture driven through the real `agent.sh` protocol.

**Tech Stack:** Python 3.9+, LLDB Python API, macOS ARM64 ABI, C/Objective-C fixtures, CoreFoundation, IOKit, CommonCrypto, `unittest`, clang.

**Spec:** `docs/superpowers/specs/2026-09-09-analysis-cloak-design.md`

## Global Constraints

- Work only in `/Users/liamchugg/Projects/macdbg/testing`; do not modify `/Users/liamchugg/Projects/macdbg` source files.
- Support ARM64 macOS 11.0 or later and the system LLDB Python bindings.
- Add no PyPI runtime dependency.
- Keep the cloak opt-in and off by default.
- Do not patch sample control flow or forge SHA-256 outputs.
- Do not support simultaneous analysis cloaking and fork-tree DYLD interposition in v1.
- Preserve the current exec prompt and disk-dump behavior.
- Every production behavior must have a test that was observed failing first.
- Stop every headless agent session created by integration tests, including failed tests.

---

## File Map

- Create `macdbg/core/anti_analysis.py`: policy constants, pure classifiers,
  `AnalysisCloak`, return-hook bookkeeping, target-side string allocation, and
  integrity validation.
- Modify `macdbg/core/debugger.py`: instantiate the cloak, expose composite
  enable/disable methods, filter launch environments, provide hardware
  breakpoint helpers, and delegate cloak stop handling.
- Modify `macdbg/core/tracer.py`: record hardware breakpoint IDs and expose them
  for integrity validation.
- Modify `macdbg/agent/session.py`: expose `analysis_cloak`, hide its internal
  breakpoints, validate before resume, and dispatch its stops.
- Modify `GUI/server/engine.py`: mirror the agent integration and surface cloak
  errors/status.
- Modify `GUI/web/app.js`: add the composite defense toggle and incompatibility
  messaging.
- Create `tests/test_anti_analysis_policy.py`: LLDB-free unit tests.
- Create `tests/integration/support.py`: build and headless-agent helpers with
  unconditional cleanup.
- Create `tests/integration/analysis_fixture.m`: one mode-selectable ARM64 test
  executable covering every check and the combined key path.
- Create `tests/integration/FridaGadget.c`: deliberately suspicious dylib.
- Create `tests/integration/test_analysis_cloak.py`: real LLDB integration tests.
- Create `tests/integration/Makefile`: deterministic fixture builds.
- Modify `README.md` and `.claude/skills/macdbg-agent/SKILL.md`: document the new
  defense, constraints, and agent command.

---

### Task 1: Pure Analysis Policy

**Files:**
- Create: `macdbg/core/anti_analysis.py`
- Create: `tests/__init__.py`
- Create: `tests/test_anti_analysis_policy.py`

**Interfaces:**
- Produces: `FORBIDDEN_ENV: frozenset[str]`, `TOOL_MARKERS: Sequence[str]`,
  `IMAGE_MARKERS: Sequence[str]`, `SYSCTL_SPOOFS: dict[str, SpoofValue]`.
- Produces: `contains_marker(value: str, markers: Sequence[str]) -> bool`.
- Produces: `filter_environment(entries: Iterable[str]) -> list[str]`.
- Produces: `SpoofValue(kind: str, value: Union[int, str])`.

- [ ] **Step 1: Write failing policy tests**

```python
# tests/test_anti_analysis_policy.py
import unittest

from macdbg.core.anti_analysis import (
    FORBIDDEN_ENV, IMAGE_MARKERS, SYSCTL_SPOOFS, TOOL_MARKERS,
    contains_marker, filter_environment,
)


class PolicyTests(unittest.TestCase):
    def test_filters_only_forbidden_environment_names(self):
        env = ["PATH=/usr/bin", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
               "NSZombieEnabled=YES", "SAFE_DYLD_INSERT_LIBRARIES=keep"]
        self.assertEqual(filter_environment(env),
                         ["PATH=/usr/bin", "SAFE_DYLD_INSERT_LIBRARIES=keep"])
        self.assertEqual(len(FORBIDDEN_ENV), 9)

    def test_tool_matching_is_case_insensitive_and_bounds_short_r2(self):
        self.assertTrue(contains_marker("/usr/bin/debugserver", TOOL_MARKERS))
        self.assertTrue(contains_marker("/Applications/Cutter.app", TOOL_MARKERS))
        self.assertTrue(contains_marker("/usr/local/bin/r2", TOOL_MARKERS))
        self.assertFalse(contains_marker("/tmp/worker2/cache", TOOL_MARKERS))

    def test_image_matching_is_case_insensitive(self):
        self.assertTrue(contains_marker("/tmp/FridaGadget.dylib", IMAGE_MARKERS))
        self.assertTrue(contains_marker("libsubstrate.dylib", IMAGE_MARKERS))
        self.assertFalse(contains_marker("/usr/lib/libSystem.B.dylib", IMAGE_MARKERS))

    def test_sysctl_spoofs_are_deterministic(self):
        self.assertEqual(SYSCTL_SPOOFS["kern.hv_vmm_present"].value, 0)
        self.assertEqual(SYSCTL_SPOOFS["hw.model"].value, "Mac14,6")
        self.assertEqual(SYSCTL_SPOOFS["machdep.cpu.brand_string"].value,
                         "Apple M2 Pro")
```

- [ ] **Step 2: Run the tests and observe the missing-module failure**

Run: `python3 -m unittest -v tests.test_anti_analysis_policy`

Expected: `ModuleNotFoundError: No module named 'macdbg.core.anti_analysis'`.

- [ ] **Step 3: Implement the policy module**

```python
# macdbg/core/anti_analysis.py
from dataclasses import dataclass
import re
from typing import Iterable, Sequence, Union

FORBIDDEN_ENV = frozenset({
    "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_INITIALIZERS",
    "DYLD_PRINT_BINDINGS", "DYLD_IMAGE_SUFFIX", "MallocStackLogging",
    "MallocStackLoggingNoCompact", "NSZombieEnabled",
})

TOOL_MARKERS = (
    "lldb", "debugserver", "lldb-rpc-server", "frida-server", "frida-trace",
    "hopper", "radare2", "r2", "cutter", "ghidra", "x64dbgi",
    "binaryninja", "gdb", "class-dump", "mitmproxy", "charles", "proxyman",
    "objection", "jtool2", "dtrace", "fs_usage",
)
IMAGE_MARKERS = (
    "frida", "fridagadget", "substrate", "mobilesubstrate", "sbinjector",
    "libcycript", "revealserver", "dobby", "fishhook", "cycript",
    "sslkillswitch",
)

@dataclass(frozen=True)
class SpoofValue:
    kind: str
    value: Union[int, str]

SYSCTL_SPOOFS = {
    "kern.hv_vmm_present": SpoofValue("u32", 0),
    "hw.model": SpoofValue("cstring", "Mac14,6"),
    "machdep.cpu.brand_string": SpoofValue("cstring", "Apple M2 Pro"),
}

def contains_marker(value: str, markers: Sequence[str]) -> bool:
    folded = value.casefold()
    for marker in markers:
        m = marker.casefold()
        if len(m) <= 2:
            if re.search(r"(?:^|[/\\._-])" + re.escape(m) +
                         r"(?:$|[/\\._-])", folded):
                return True
        elif m in folded:
            return True
    return False

def filter_environment(entries: Iterable[str]) -> list[str]:
    return [entry for entry in entries
            if entry.split("=", 1)[0] not in FORBIDDEN_ENV]
```

- [ ] **Step 4: Run policy tests**

Run: `python3 -m unittest -v tests.test_anti_analysis_policy`

Expected: four tests pass.

- [ ] **Step 5: Commit the policy layer**

```bash
git add macdbg/core/anti_analysis.py tests/__init__.py tests/test_anti_analysis_policy.py
git commit -m "feat: define analysis cloak policy"
```

---

### Task 2: Integration Harness and Environment Cloaking

**Files:**
- Modify: `macdbg/core/anti_analysis.py`
- Modify: `macdbg/core/debugger.py:27-220`
- Modify: `macdbg/agent/session.py:45-80,163-365,430-560`
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/support.py`
- Create: `tests/integration/analysis_fixture.m`
- Create: `tests/integration/Makefile`
- Create: `tests/integration/test_analysis_cloak.py`

**Interfaces:**
- Produces: `AnalysisCloak(debugger)` with `enabled: bool`,
  `enable() -> tuple[bool, str]`, `disable() -> tuple[bool, str]`,
  `filter_launch_environment(entries) -> list[str]`,
  `scrub_live_environment() -> tuple[bool, str]`,
  `hidden_bp_ids() -> set[int]`, `handle_hit(bp_id) -> Optional[str]`, and
  `status() -> dict`.
- Produces: `Debugger.enable_analysis_cloak()` and
  `Debugger.disable_analysis_cloak()` returning `(bool, str)`.
- Extends agent `_DEFENSES` with `analysis_cloak`.
- Produces: `AgentProcess` context manager used by every later integration test.

- [ ] **Step 1: Write the environment fixture and failing agent test**

The fixture accepts a mode as `argv[1]` and returns nonzero when a check detects
analysis. Start with this exact environment mode:

```objective-c
// tests/integration/analysis_fixture.m
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crt_externs.h>

static const char *bad_env[] = {
    "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_INITIALIZERS", "DYLD_PRINT_BINDINGS",
    "DYLD_IMAGE_SUFFIX", "MallocStackLogging", "MallocStackLoggingNoCompact",
    "NSZombieEnabled", NULL
};

static int check_environment(void) {
    int bad = 0;
    for (int i = 0; bad_env[i]; i++) bad |= getenv(bad_env[i]) != NULL;
    char **entries = *_NSGetEnviron();
    for (char **p = entries; p && *p; p++)
        for (int i = 0; bad_env[i]; i++) {
            size_t n = strlen(bad_env[i]);
            bad |= strncmp(*p, bad_env[i], n) == 0 && (*p)[n] == '=';
        }
    return bad;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "env") == 0) {
        int bad = check_environment();
        printf("ENV:%s\n", bad ? "DETECTED" : "clean");
        return bad;
    }
    return 65;
}
```

Create the initial fixture Makefile; later tasks extend `all` with the test
dylib:

```make
# tests/integration/Makefile
BUILD := build
FIXTURE := $(BUILD)/analysis_fixture
CFLAGS := -arch arm64 -O0 -g -Wall -Wextra
FRAMEWORKS := -framework CoreFoundation -framework IOKit

.PHONY: all clean
all: $(FIXTURE)

$(BUILD):
	mkdir -p $@

$(FIXTURE): analysis_fixture.m | $(BUILD)
	clang $(CFLAGS) $(FRAMEWORKS) $< -o $@

clean:
	rm -rf $(BUILD)
```

Create empty package markers `tests/__init__.py` and
`tests/integration/__init__.py` so `/usr/bin/python3 -m unittest` imports the
suite consistently.

Implement `tests/integration/support.py` as a real subprocess wrapper (the
fixture constants are reused by every test):

```python
# tests/integration/support.py
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agent.sh"
FIXTURE_DIR = ROOT / "tests" / "integration" / "build"
FIXTURE = FIXTURE_DIR / "analysis_fixture"
FRIDA_FIXTURE = FIXTURE_DIR / "FridaGadget.dylib"

def _json_run(argv, env=None, timeout=30):
    cp = subprocess.run([str(x) for x in argv], cwd=ROOT, env=env,
                        text=True, capture_output=True, timeout=timeout)
    line = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else "{}"
    value = json.loads(line)
    value["client_returncode"] = cp.returncode
    value["client_stderr"] = cp.stderr
    return value

def run_fixture_direct(mode, extra_args=None, env=None):
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(
        [str(FIXTURE), mode] + list(extra_args or []), env=merged,
        text=True, capture_output=True, timeout=15)

class AgentProcess:
    def __init__(self, fixture, mode, extra_args=None, env=None):
        self.fixture = Path(fixture)
        self.mode = mode
        self.extra_args = list(extra_args or [])
        self.env = os.environ.copy()
        self.env.update(env or {})
        self.session = "cloak_{}_{}".format(os.getpid(), uuid.uuid4().hex[:8])
        self.boot = None

    def __enter__(self):
        self.boot = _json_run(
            [AGENT, "start", "--session", self.session, self.fixture,
             self.mode] + self.extra_args,
            env=self.env, timeout=40)
        if not self.boot.get("ok"):
            raise AssertionError("agent start failed: {!r}".format(self.boot))
        return self

    def cmd(self, name, args=None, timeout=20):
        return _json_run(
            [AGENT, "cmd", self.session, name, "--json",
             json.dumps(args or {}), "--timeout", str(timeout)],
            env=self.env, timeout=timeout + 15)

    def enable_cloak(self):
        return self.cmd("defense_enable", {"name": "analysis_cloak"})

    def continue_to_exit(self):
        return self.cmd("continue", {"timeout": 15}, timeout=20)

    def __exit__(self, _exc_type, _exc, _tb):
        subprocess.run([str(AGENT), "stop", self.session], cwd=ROOT,
                       env=self.env, text=True, capture_output=True, timeout=15)
```

Add the test:

```python
def test_environment_is_detected_without_cloak_and_clean_with_cloak(self):
    hostile = {"DYLD_PRINT_BINDINGS": "1", "NSZombieEnabled": "YES"}
    self.assertNotEqual(run_fixture_direct("env", env=hostile).returncode, 0)
    with AgentProcess(FIXTURE, "env", env=hostile) as agent:
        enabled = agent.cmd("defense_enable", {"name": "analysis_cloak"})
        self.assertTrue(enabled["ok"], enabled)
        result = agent.cmd("continue", {"timeout": 15})
        self.assertEqual(result["event"], "exited")
        self.assertEqual(result["exit"]["code"], 0)
        self.assertIn("ENV:clean", result["console"])
```

- [ ] **Step 2: Build and observe the missing-defense failure**

Run: `make -C tests/integration clean all && /usr/bin/python3 -m unittest -v tests.integration.test_analysis_cloak.AnalysisCloakIntegrationTests.test_environment_is_detected_without_cloak_and_clean_with_cloak`

Expected: direct execution detects the variables; the agent command fails with
`unknown defense 'analysis_cloak'`.

- [ ] **Step 3: Add the controller skeleton and launch filtering**

Implement `AnalysisCloak` with ownership tracking for pre-existing defenses:

```python
class AnalysisCloak:
    def __init__(self, debugger):
        self.debugger = debugger
        self.enabled = False
        self._bp_ids = set()
        self._return_hooks = {}
        self._owned_existing = set()

    def filter_launch_environment(self, entries):
        return filter_environment(entries) if self.enabled else list(entries)

    def scrub_live_environment(self):
        for name in sorted(FORBIDDEN_ENV):
            ok, _out, err = self.debugger.handle_command(
                'expression -l c++ --ignore-breakpoints true -- '
                '(int)unsetenv("{}")'.format(name))
            if not ok:
                return False, "could not unset {}: {}".format(name, err.strip())
        return True, "removed {} analysis environment variables".format(
            len(FORBIDDEN_ENV))

    def hidden_bp_ids(self):
        return set(self._bp_ids) | set(self._return_hooks)
```

In `Debugger.__init__`, instantiate after core fields are ready:

```python
from .anti_analysis import AnalysisCloak
self.analysis_cloak = AnalysisCloak(self)
```

In `Debugger.launch`, filter the environment before
`SetEnvironmentEntries`:

```python
env = self.analysis_cloak.filter_launch_environment(env)
```

`enable_analysis_cloak` must require a stopped process at the entry point,
enable `anti_sysctl`, `anti_parent`, and `anti_timing` only if not already on,
remember which ones it owns, scrub the live environment, then set `enabled`.
On failure, roll back only state it acquired.

Add `analysis_cloak` to `_DEFENSES` and include cloak IDs in
`AgentSession._hidden_bp_ids()`.

- [ ] **Step 4: Run the focused integration and policy tests**

Run: `python3 -m unittest -v tests.test_anti_analysis_policy tests.integration.test_analysis_cloak.AnalysisCloakIntegrationTests.test_environment_is_detected_without_cloak_and_clean_with_cloak`

Expected: all pass; teardown leaves `./agent.sh list` with no live test session.

- [ ] **Step 5: Commit environment cloaking**

```bash
git add macdbg/core/anti_analysis.py macdbg/core/debugger.py macdbg/agent/session.py tests/integration
git commit -m "feat: sanitize target analysis environment"
```

---

### Task 3: Parent-Process Path Cloaking

**Files:**
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`
- Modify: `macdbg/core/anti_analysis.py`
- Modify: `macdbg/core/debugger.py:880-1214`
- Modify: `macdbg/agent/session.py:700-850`
- Modify: `GUI/server/engine.py:420-568`

**Interfaces:**
- Extends: `AnalysisCloak.enable()` with `proc_pidpath` breakpoint.
- Produces: `AnalysisCloak.handle_hit(bp_id: int) -> Optional[str]`.
- Produces: shared `Debugger.handle_analysis_cloak_hit(bp_id)` delegate used by
  both stop orchestrators.

- [ ] **Step 1: Extend the fixture and write the failing parent test**

Add a `parent` mode that calls `proc_pidpath(getppid(), buffer, sizeof buffer)`
and `sysctl({CTL_KERN,KERN_PROC,KERN_PROC_PID,getppid()}, kinfo, size, NULL, 0)`, then checks both
returned paths/names with the full tool marker policy. Print
`PARENT:DETECTED` or `PARENT:clean`.

```python
def test_parent_paths_are_cloaked(self):
    with AgentProcess(FIXTURE, "parent") as agent:
        self.assertTrue(agent.enable_cloak()["ok"])
        result = agent.continue_to_exit()
        self.assertEqual(result["exit"]["code"], 0)
        self.assertIn("PARENT:clean", result["console"])
        self.assertIn("[anti-analysis]", result["console"])
```

- [ ] **Step 2: Run and observe failure**

Run the parent test alone. Expected: nonzero exit with `PARENT:DETECTED`
because `proc_pidpath` still returns a debugserver path.

- [ ] **Step 3: Implement entry/return handling**

At `proc_pidpath` entry, capture `x1` buffer and `x2` capacity, then arm a
thread-specific one-shot at `lr`. On return, read at most the captured capacity;
if `contains_marker(path, TOOL_MARKERS)` is true, write `/sbin/launchd\0` and set
`x0` to `len("/sbin/launchd")`.

Replace `Debugger._DEBUGGER_NAMES` matching in `_scrub_debugger_name` with the
shared case-insensitive policy. Rewrite only the matched NUL-terminated field,
using `launchd\0` and zero-filling the remainder of the original field so no
blacklisted suffix survives.

Add `handle_analysis_cloak_hit` before existing flag scrub handlers in both
`AgentSession._try_auto_anti_debug` and `Engine._handle_anti_debug_hit`.

- [ ] **Step 4: Run parent plus existing sysctl fixture tests**

Run: `python3 -m unittest -v tests.integration.test_analysis_cloak.AnalysisCloakIntegrationTests.test_parent_paths_are_cloaked`

Expected: pass, with both parent APIs reporting clean.

- [ ] **Step 5: Commit parent cloaking**

```bash
git add macdbg/core/anti_analysis.py macdbg/core/debugger.py macdbg/agent/session.py GUI/server/engine.py tests/integration
git commit -m "feat: cloak parent analysis tool paths"
```

---

### Task 4: Hypervisor and Hardware Sysctl Spoofing

**Files:**
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`
- Modify: `macdbg/core/anti_analysis.py`

**Interfaces:**
- Extends: `AnalysisCloak` with a `sysctlbyname` entry breakpoint.
- Extends: return-hook payload with `(kind, name, buffer, size_pointer,
  capacity)`.

- [ ] **Step 1: Add the sysctl fixture mode and failing test**

The `sysctl` mode must call the real `sysctlbyname` for all three names and
require the deterministic spoof values exactly:

```objective-c
int hv = -1; size_t hvn = sizeof(hv);
char model[128] = {0}, cpu[128] = {0};
size_t modeln = sizeof(model), cpun = sizeof(cpu);
sysctlbyname("kern.hv_vmm_present", &hv, &hvn, NULL, 0);
sysctlbyname("hw.model", model, &modeln, NULL, 0);
sysctlbyname("machdep.cpu.brand_string", cpu, &cpun, NULL, 0);
int bad = hv != 0 || strcmp(model, "Mac14,6") || strcmp(cpu, "Apple M2 Pro");
printf("SYSCTL:%s hv=%d model=%s cpu=%s\n", bad ? "DETECTED" : "clean",
       hv, model, cpu);
```

The test asserts the direct fixture is not already the exact spoof tuple, then
requires `SYSCTL:clean` under the cloak.

- [ ] **Step 2: Run and observe the exact-value assertion fail**

Expected: the cloaked run returns the host's actual `hw.model` or CPU string,
not the deterministic values.

- [ ] **Step 3: Implement size-safe sysctl return rewriting**

At entry, read `x0` as a C string and ignore names absent from
`SYSCTL_SPOOFS`. Capture `x1`, `x2`, and the input capacity from `*x2`; arm a
thread-specific return breakpoint. At return:

```python
if spoof.kind == "u32":
    payload = int(spoof.value).to_bytes(4, "little")
else:
    payload = str(spoof.value).encode() + b"\0"
if not buffer or capacity < len(payload):
    return "sysctlbyname({}) buffer too small; cloak failed".format(name)
process.WriteMemory(buffer, payload, error)
process.WriteMemory(size_pointer, len(payload).to_bytes(8, "little"), error)
```

Treat a failed write as a critical cloak error recorded in
`AnalysisCloak.last_error`; resume validation must reject the next continue.

- [ ] **Step 4: Run sysctl, environment, and parent tests**

Run the three focused integration tests. Expected: all pass.

- [ ] **Step 5: Commit sysctl spoofing**

```bash
git add macdbg/core/anti_analysis.py tests/integration
git commit -m "feat: spoof anti-analysis sysctls"
```

---

### Task 5: IOKit Identity Spoofing

**Files:**
- Modify: `tests/integration/Makefile`
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`
- Modify: `macdbg/core/anti_analysis.py`

**Interfaces:**
- Extends: `AnalysisCloak` with `IORegistryEntryCreateCFProperty` handling.
- Produces internal helpers:
  `_cfstring_text(pointer: int) -> Optional[str]` and
  `_make_cfstring(text: str) -> Optional[int]`.

- [ ] **Step 1: Add IOKit linkage, fixture mode, and failing test**

Link the fixture with `-framework CoreFoundation -framework IOKit`. The `iokit`
mode obtains `IOPlatformExpertDevice`, reads `IOPlatformSerialNumber` and
`IOPlatformUUID`, converts both CF values to UTF-8, and requires:

```text
C02ZQ0ABC123
8D4C7A12-3F65-4B90-A2DE-61C8E5079F34
```

The integration test requires `IOKIT:clean` and both values in stdout.

- [ ] **Step 2: Run and observe host identity failure**

Expected: nonzero exit because at least one real host property differs.

- [ ] **Step 3: Implement CF key recognition and replacement**

Use breakpoint-ignored expressions and parse the final pointer with the regular
expression `r"=\s*(0x[0-9a-fA-F]+)"`:

```python
def _make_cfstring(self, text):
    expr = ('expression -l c++ --ignore-breakpoints true -- '
            '(void*)CFStringCreateWithCString((void*)0, "{}", 0x08000100)')
    return self._eval_pointer(expr.format(_escape_c_string(text)))
```

For the incoming key, first try `CFStringGetCStringPtr(key, 0x08000100)` and
read the returned pointer. If it is null, allocate a 256-byte target buffer,
call `CFStringGetCString(key, buffer, 256, 0x08000100)`, read the buffer, and
free it. Only the two exact property names are intercepted. Use `thread return
<replacement-pointer>` so the caller receives a retained CF object consistent
with the Create rule. Cache one replacement object per property for the life of
the process and release/reset caches during restart or disable.

- [ ] **Step 4: Run IOKit and all earlier integration tests**

Expected: all pass without expression errors or recursive defense hits.

- [ ] **Step 5: Commit IOKit spoofing**

```bash
git add macdbg/core/anti_analysis.py tests/integration
git commit -m "feat: spoof IOKit platform identity"
```

---

### Task 6: Loaded-Image Name Cloaking

**Files:**
- Modify: `tests/integration/Makefile`
- Create: `tests/integration/FridaGadget.c`
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`
- Modify: `macdbg/core/anti_analysis.py`

**Interfaces:**
- Extends: `AnalysisCloak` with `_dyld_get_image_name` return handling.
- Produces: cached target-side C string
  `/usr/lib/libSystem.B.dylib` used only for blacklisted results.

- [ ] **Step 1: Add suspicious dylib fixture and failing image test**

```c
// tests/integration/FridaGadget.c
__attribute__((visibility("default"))) int frida_fixture_marker(void) {
    return 0x1337;
}
```

Build it as `FridaGadget.dylib`. The fixture's `images` mode calls `dlopen` on
the absolute path passed in `argv[2]`, iterates `_dyld_image_count()` and
`_dyld_get_image_name(i)`, and fails if any path matches the image blacklist.
The test first requires direct execution to print `IMAGES:DETECTED`, then
requires the cloaked run to print `IMAGES:clean`.

- [ ] **Step 2: Run and observe `FridaGadget.dylib` detection**

Expected: cloaked run exits nonzero and prints the suspicious path.

- [ ] **Step 3: Implement return-side image replacement**

At every `_dyld_get_image_name` entry, arm a thread-specific return breakpoint.
At return, read `x0` as a C string. If it matches `IMAGE_MARKERS`, allocate the
replacement once using a breakpoint-ignored `strdup` expression and write its
pointer to `x0`. Do not modify dyld-owned string memory. Clean paths return
without logging; replacements log the original basename.

Before arming, reject `analysis_cloak` if `debugger.interpose_enabled` is true.
Also reject enabling interposition while the cloak is active in both GUI and
agent pathways.

- [ ] **Step 4: Run image and earlier integration tests**

Expected: direct run detects the dylib; cloaked run sees only the replacement;
all previous tests remain green.

- [ ] **Step 5: Commit image cloaking**

```bash
git add macdbg/core/anti_analysis.py tests/integration
git commit -m "feat: hide blacklisted loaded images"
```

---

### Task 7: Integrity-Safe Hardware Breakpoints

**Files:**
- Modify: `macdbg/core/debugger.py:790-879,1346-1420`
- Modify: `macdbg/core/tracer.py:516-575`
- Modify: `macdbg/core/anti_analysis.py`
- Modify: `macdbg/agent/session.py:179-220,500-650`
- Modify: `GUI/server/engine.py:569-686`
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`

**Interfaces:**
- Produces: `Debugger.create_hardware_breakpoint_by_address(addr) -> SBBreakpoint`.
- Produces: `Debugger.hardware_bp_ids: set[int]`.
- Produces: `Tracer.hardware_bp_ids: set[int]`.
- Produces: `AnalysisCloak.validate_integrity(extra_hardware_ids: set[int]) ->
  tuple[bool, str]`.

- [ ] **Step 1: Add the self-text hash fixture and failing test**

The fixture's `integrity` mode finds its own Mach-O header with
`_dyld_get_image_header(0)`, locates `LC_SEGMENT_64/__TEXT/__text`, hashes the
mapped bytes using `CC_SHA256`, and compares against the 64-character digest in
`argv[2]`. Add an exported, never-called `integrity_breakpoint_site` function.

The Python test computes the on-disk `__text` digest with
`xcrun llvm-objdump --macho --section=__TEXT,__text --full-leading-addr
--show-raw-insn` parsing or a small Mach-O parser in `support.py`, resolves the
marker address with `nm`, then:

1. starts the fixture under macdbg;
2. enables `analysis_cloak`;
3. adds a structured breakpoint at the marker;
4. asserts the breakpoint reports `added (HW)`;
5. continues and requires `INTEGRITY:clean`.

Also add a negative test using
`raw {"command":"breakpoint set -a {:#x}".format(marker_addr)}` and
require continue to be rejected with `software breakpoint modifies target
__text`.

- [ ] **Step 2: Run and observe software-breakpoint failure**

Expected: the structured breakpoint is software-backed or the hash reports
`INTEGRITY:DETECTED`; the raw-breakpoint resume is not yet rejected.

- [ ] **Step 3: Centralize hardware breakpoint creation**

Move the existing CLI construction into one helper:

```python
def create_hardware_breakpoint_by_address(self, addr):
    before = self.target.GetNumBreakpoints()
    ret = lldb.SBCommandReturnObject()
    self.ci.HandleCommand("breakpoint set -H -a {:#x}".format(addr), ret, False)
    if not ret.Succeeded() or self.target.GetNumBreakpoints() <= before:
        raise RuntimeError(ret.GetError() or "hardware breakpoint allocation failed")
    bp = self.target.GetBreakpointAtIndex(before)
    if bp.GetNumLocations() == 0:
        self.target.BreakpointDelete(bp.GetID())
        raise RuntimeError("hardware breakpoint has no resolved location")
    self.hardware_bp_ids.add(bp.GetID())
    return bp
```

Use it for structured user breakpoints whenever `hw_breakpoints` or the cloak
is active, and for direct-syscall scan sites whenever the cloak is active.
When the cloak is active, also use it for `AnalysisCloak`'s thread-specific
return breakpoints and the existing `_arm_return_scrub` one-shots because their
return addresses can lie inside the hashed target section. After creation set
the same one-shot/thread-ID attributes currently used by software return
breakpoints. Remove IDs from the set when breakpoints are deleted. Make
`Tracer` record IDs created with `-H` and expose a copy through a property.

- [ ] **Step 4: Add fail-closed resume validation**

Determine the main executable's mapped `__text` range. For every enabled
breakpoint location within that range, require its ID in
`Debugger.hardware_bp_ids | extra_hardware_ids`. Reject tracked patches whose
`[addr, addr + len(new))` overlaps the range. Return an exact actionable error.

Call validation before `resume()` in `AgentSession._pump` and before setting
`Engine._resuming` in `_begin_resume`. A failed validation must leave the
process stopped.

- [ ] **Step 5: Run integrity and prior tests**

Expected: hardware path preserves the digest; raw software breakpoint is
blocked; all earlier tests pass.

- [ ] **Step 6: Commit integrity-safe breakpoint handling**

```bash
git add macdbg/core/debugger.py macdbg/core/tracer.py macdbg/core/anti_analysis.py macdbg/agent/session.py GUI/server/engine.py tests/integration
git commit -m "feat: preserve target text under analysis cloak"
```

---

### Task 8: Combined Checks, Timing, Syscall 202, and Command Dumps

**Files:**
- Modify: `tests/integration/analysis_fixture.m`
- Modify: `tests/integration/test_analysis_cloak.py`
- Modify: `tests/integration/support.py`
- Modify: `macdbg/core/anti_analysis.py`
- Modify: `macdbg/agent/session.py`

**Interfaces:**
- Extends fixture modes: `timing`, `ptraced`, `exec`, and `combined`.
- Verifies existing `anti_timing`, syscall-wrapper multiplexing, interactive
  exec decisions, and dump paths through the composite defense.

- [ ] **Step 1: Add failing timing and syscall-202 cases**

`timing` calls `mach_timebase_info`, reads `mach_absolute_time`, performs a
`sysctl(KERN_PROC_PID)` query that is intercepted by `anti_sysctl`, reads the
clock again, converts to nanoseconds, and treats a delta above 5 milliseconds
as detected. The negative run enables `anti_sysctl` alone so LLDB's
entry/return breakpoint latency is visible; the positive run enables the
composite cloak so the same flag scrub is protected by the fake clock. Require
`TIMING:DETECTED` in the negative run and `TIMING:clean` with the cloak.

`ptraced` invokes:

```objective-c
int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
struct kinfo_proc info = {0}; size_t n = sizeof(info);
long rc = syscall(202, mib, 4, &info, &n, NULL, 0);
int bad = rc == 0 && (info.kp_proc.p_flag & P_TRACED) != 0;
```

Require direct/debugged execution to detect `P_TRACED` and the composite cloak
to print `P_TRACED:clean`.

- [ ] **Step 2: Run the cases and confirm composite ownership gaps**

Expected: any missing composite activation or stop dispatch makes at least one
case fail. Do not change code until the expected failure is observed.

- [ ] **Step 3: Fix only missing composite lifecycle behavior**

Ensure `AnalysisCloak.enable()` acquires existing defenses in this order:
`anti_sysctl`, `anti_parent`, `anti_timing`; record only defenses that were off.
On disable or failed enable, release only those recorded names in reverse order.
Ensure relaunch clears cloak return hooks and target allocations without turning
off the requested composite mode.

Extend `cmd_status()` with a `defenses` object and assert during this task that
it reports `analysis_cloak: true`, `analysis_cloak_safe: true`, no error, and
integer resolved/deferred hook counts after enablement.

- [ ] **Step 4: Add exec prompt/dump regression tests**

The fixture's `exec` mode calls `system` with a command longer than 200 bytes.
The test enables `exec_sandbox`, enables interactive mode, continues to
`pending_decision`, calls `dump_exec`, reads the returned file, and asserts it
contains the entire command. Then choose `fake` and require clean exit. A second
noninteractive run asserts the existing oversized automatic dump message.

- [ ] **Step 5: Add combined ChaCha20 fixture and test**

Add this compact RFC 8439 core to the fixture, using explicit little-endian
loads/stores so the fixture remains deterministic:

```c
static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7); \
} while (0)

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static void chacha20_block(uint8_t out[64], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    static const uint32_t c[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t s[16], x[16];
    memcpy(s, c, sizeof c);
    for (int i = 0; i < 8; i++) s[4+i] = load32(key + 4*i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13+i] = load32(nonce + 4*i);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8],x[12]); QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]); QR(x[3],x[4],x[9],x[14]);
    }
    for (int i = 0; i < 16; i++) store32(out + 4*i, x[i] + s[i]);
}
static void chacha20_xor(uint8_t *data, size_t n, const uint8_t key[32]) {
    const uint8_t nonce[12] = {0};
    uint8_t stream[64];
    for (uint32_t block = 0; n; block++) {
        chacha20_block(stream, key, block + 1, nonce);
        size_t take = n < sizeof stream ? n : sizeof stream;
        for (size_t i = 0; i < take; i++) data[i] ^= stream[i];
        data += take; n -= take;
    }
}
```

Each failed check XORs a distinct nonzero byte into a different position of a
32-byte password buffer before `CC_SHA256` derivation. At fixture startup,
derive the clean key from an untouched copy of the password and encrypt this
plaintext in memory:

```text
macdbg analysis cloak recovered this payload
```

Then run environment, parent, sysctl, IOKit, images, integrity, timing, and
syscall-202 checks, mutate the candidate password for every failure, derive the
candidate key, and decrypt the ciphertext with it. Print bytes only when they
equal the complete expected plaintext; otherwise print `PAYLOAD:unavailable`.
The test requires an uncloaked debug run not to print the plaintext and a
cloaked run to print the exact line
`PAYLOAD:macdbg analysis cloak recovered this payload`.

- [ ] **Step 6: Run the entire integration suite**

Run: `make -C tests/integration clean all && /usr/bin/python3 -m unittest -v tests.integration.test_analysis_cloak`

Expected: every standalone and combined case passes; command dump files contain
full payloads; `./agent.sh list` reports no live test sessions.

- [ ] **Step 7: Commit combined and regression coverage**

```bash
git add macdbg/core/anti_analysis.py macdbg/agent/session.py tests/integration
git commit -m "test: verify complete analysis cloak workflow"
```

---

### Task 9: GUI Integration and Status Reporting

**Files:**
- Modify: `GUI/server/engine.py:49-1305`
- Modify: `GUI/web/app.js:815-875`
- Modify: `tests/test_anti_analysis_policy.py`
- Create: `tests/test_analysis_cloak_surfaces.py`

**Interfaces:**
- Extends GUI command key: `analysis_cloak`.
- Extends defense status JSON with:
  `analysis_cloak`, `analysis_cloak_safe`, `analysis_cloak_resolved`,
  `analysis_cloak_deferred`, and `analysis_cloak_error`.

- [ ] **Step 1: Write failing surface-contract tests**

Use source-level contract tests that do not import LLDB:

```python
class SurfaceContractTests(unittest.TestCase):
    def test_gui_exposes_analysis_cloak(self):
        js = Path("GUI/web/app.js").read_text()
        self.assertIn("['analysis_cloak', 'Analysis cloak'", js)
```

- [ ] **Step 2: Run and observe missing GUI toggle**

Run: `python3 -m unittest -v tests.test_analysis_cloak_surfaces`

Expected: GUI assertion fails.

- [ ] **Step 3: Wire the GUI engine**

Add a `_t_analysis_cloak` handler that calls the same
`Debugger.enable_analysis_cloak`/disable pair. Include cloak IDs in
`_hidden_bp_ids`, call cloak stop handling before other anti-debug handlers,
call integrity validation in `_begin_resume`, and return the five status fields
from `_defense_states`/`_trace_status`.

Add `analysis_cloak` to `_t_all_anti` so the existing “Enable ALL anti-debug
bypasses” action arms it and refreshes the combined state consistently.

When cloak enablement fails, emit its exact error to the console and immediately
refresh defense state. Reject `_c_fork_trace` while cloak is enabled with:
`analysis cloak is incompatible with fork-tree tracing in v1`.

- [ ] **Step 4: Add the frontend toggle**

Insert in the Defenses modal:

```javascript
['analysis_cloak', 'Analysis cloak',
 'environment · parent · VM/hardware · images · text integrity · timing'],
```

Render an unsafe/error state using the existing defense status and console
mechanisms; do not add a second dialog system.

- [ ] **Step 5: Run surface contracts and integration suite**

Expected: surface tests pass, integration tests remain green.

- [ ] **Step 6: Commit GUI integration**

```bash
git add GUI/server/engine.py GUI/web/app.js tests/test_analysis_cloak_surfaces.py
git commit -m "feat: expose analysis cloak in GUI"
```

---

### Task 10: Documentation and Final Verification

**Files:**
- Modify: `README.md`
- Modify: `.claude/skills/macdbg-agent/SKILL.md`
- Modify: `pyproject.toml`
- Modify: `GUI/README-GUI.md`

**Interfaces:**
- Documents the exact GUI and agent commands, spoof values, incompatibilities,
  integrity restrictions, and test commands.
- Corrects existing GUI/TUI and app-path drift encountered during review.

- [ ] **Step 1: Make the documentation contract fail**

Extend `tests/test_analysis_cloak_surfaces.py` to require all of these literal
terms in both README and agent skill where applicable:

```python
for term in ("analysis_cloak", "kern.hv_vmm_present", "IOPlatformUUID",
             "hardware breakpoints", "fork-tree"):
    self.assertIn(term, readme)
self.assertIn("`analysis_cloak`", agent_skill)
```

Run the surface test and observe failure before editing documentation.

- [ ] **Step 2: Update user and agent documentation**

Document:

- how to enable the composite defense in GUI and agent;
- the environment variables and APIs covered;
- deterministic spoof values;
- why fork-tree tracing is rejected;
- why target-text breakpoints become hardware and can fail when slots run out;
- timing and private-API limitations;
- preserved exec prompt/dump behavior.

Change `pyproject.toml` description/keywords from Textual TUI to GUI/headless
LLDB wrapper. Change `GUI/README-GUI.md` app paths from `GUI/macdbg.app` to the
repository-root `macdbg.app`.

- [ ] **Step 3: Run static and unit verification**

Run:

```bash
python3 -m unittest -v tests.test_anti_analysis_policy tests.test_analysis_cloak_surfaces
/usr/bin/python3 -m compileall -q macdbg GUI/server
git diff --check
```

Expected: all tests pass, compileall exits zero, and diff check is silent.

- [ ] **Step 4: Run clean end-to-end verification**

Run:

```bash
make -C tests/integration clean all
/usr/bin/python3 -m unittest -v tests.integration.test_analysis_cloak
./agent.sh list
```

Expected: all integration tests pass, combined output contains the exact known
payload, and no test session is alive.

- [ ] **Step 5: Inspect the final diff and preserve copied user changes**

Run:

```bash
git status --short
git diff --stat HEAD~1
git diff --check
```

Confirm that pre-existing copied changes to `GUI/build_app.sh`,
`macdbg.app/Contents/MacOS/macdbg`, `.agents/`, and
`macdbg.app/Contents/_CodeSignature/` were not included in feature commits.

- [ ] **Step 6: Commit documentation**

```bash
git add README.md .claude/skills/macdbg-agent/SKILL.md pyproject.toml GUI/README-GUI.md tests/test_analysis_cloak_surfaces.py
git commit -m "docs: document analysis cloak workflow"
```

- [ ] **Step 7: Request final code review**

Use `superpowers:requesting-code-review` against the full feature commit range,
address any findings with new failing regression tests, then rerun Steps 3-5.
