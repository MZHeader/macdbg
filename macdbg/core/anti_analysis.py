from dataclasses import dataclass
import re
from typing import Iterable, Optional, Sequence, Union


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


class AnalysisCloak:
    _EXISTING_DEFENSES = (
        ("anti_sysctl", "_scrub_ptraced"),
        ("anti_parent", "_scrub_parent"),
        ("anti_timing", "anti_timing_bp_ids"),
    )

    def __init__(self, debugger):
        self.debugger = debugger
        self.enabled: bool = False
        self._bp_ids: set[int] = set()
        self._return_hooks: dict[int, tuple[str, int, int]] = {}
        self._owned_existing = set()
        self._owned_existing_bp_ids = {}

    def enable(self) -> tuple[bool, str]:
        if self.enabled:
            return True, "analysis cloak already enabled"
        if not self.debugger.is_stopped_at_entry_point():
            return (False,
                    "analysis cloak must be enabled while stopped at the "
                    "entry point; restart the target")

        acquired = []
        for name, state_attr in self._EXISTING_DEFENSES:
            if getattr(self.debugger, state_attr):
                continue
            before_ids = self._breakpoint_ids()
            ok, message = getattr(self.debugger, "enable_" + name)()
            added_ids = self._breakpoint_ids() - before_ids
            if not ok:
                if getattr(self.debugger, state_attr):
                    getattr(self.debugger, "disable_" + name)()
                self._delete_breakpoints(added_ids)
                self._rollback_existing(acquired)
                return False, "could not enable {}: {}".format(name, message)
            acquired.append(name)
            self._owned_existing.add(name)
            self._owned_existing_bp_ids[name] = added_ids

        target = self.debugger.target
        create_bp = getattr(target, "BreakpointCreateByName", None)
        if create_bp is not None:
            bp = create_bp("proc_pidpath")
            if not bp.IsValid() or bp.GetNumLocations() == 0:
                if bp.IsValid():
                    target.BreakpointDelete(bp.GetID())
                self._rollback_existing(acquired)
                return False, "could not enable proc_pidpath cloak: symbol not found"
            self._bp_ids.add(bp.GetID())

        ok, message = self.scrub_live_environment()
        if not ok:
            self._delete_breakpoints(self._bp_ids)
            self._bp_ids.clear()
            self._rollback_existing(acquired)
            return False, message

        self.enabled = True
        return True, "analysis cloak enabled; {}".format(message)

    def disable(self) -> tuple[bool, str]:
        self._delete_breakpoints(set(self._bp_ids) | set(self._return_hooks))
        self._bp_ids.clear()
        self._return_hooks.clear()
        for name in reversed([item[0] for item in self._EXISTING_DEFENSES]):
            if name in self._owned_existing:
                getattr(self.debugger, "disable_" + name)()
                self._delete_breakpoints(
                    self._owned_existing_bp_ids.pop(name, set()))
        self._owned_existing.clear()
        self.enabled = False
        return True, "analysis cloak disabled"

    def _rollback_existing(self, acquired):
        for name in reversed(acquired):
            getattr(self.debugger, "disable_" + name)()
            self._delete_breakpoints(
                self._owned_existing_bp_ids.pop(name, set()))
            self._owned_existing.discard(name)

    def _breakpoint_ids(self):
        target = getattr(self.debugger, "target", None)
        if target is None:
            return set()
        return {
            target.GetBreakpointAtIndex(index).GetID()
            for index in range(target.GetNumBreakpoints())
        }

    def _delete_breakpoints(self, bp_ids):
        target = getattr(self.debugger, "target", None)
        if target is None:
            return
        for bp_id in bp_ids:
            target.BreakpointDelete(bp_id)

    def filter_launch_environment(self, entries) -> list[str]:
        return filter_environment(entries) if self.enabled else list(entries)

    def scrub_live_environment(self) -> tuple[bool, str]:
        for name in sorted(FORBIDDEN_ENV):
            ok, _out, err = self.debugger.handle_command(
                'expression -l c++ --ignore-breakpoints true -- '
                '(int)unsetenv("{}")'.format(name))
            if not ok:
                return False, "could not unset {}: {}".format(name, err.strip())
        return True, "removed {} analysis environment variables".format(
            len(FORBIDDEN_ENV))

    def hidden_bp_ids(self) -> set[int]:
        owned_existing = set()
        for bp_ids in self._owned_existing_bp_ids.values():
            owned_existing.update(bp_ids)
        return (set(self._bp_ids) | set(self._return_hooks)
                | owned_existing)

    def handle_hit(self, bp_id: int) -> Optional[str]:
        process = getattr(self.debugger, "process", None)
        target = getattr(self.debugger, "target", None)
        if process is None or target is None:
            return None

        hook = self._return_hooks.pop(bp_id, None)
        if hook is not None:
            target.BreakpointDelete(bp_id)
            _kind, buffer, capacity = hook
            import lldb
            err = lldb.SBError()
            data = process.ReadMemory(buffer, capacity, err) if capacity else b""
            message = ""
            if err.Success() and data:
                path = data.split(b"\0", 1)[0].decode("utf-8", errors="replace")
                if contains_marker(path, TOOL_MARKERS):
                    replacement = b"/sbin/launchd\0"
                    process.WriteMemory(buffer, replacement, err)
                    frame = process.GetSelectedThread().GetFrameAtIndex(0)
                    frame.FindRegister("x0").SetValueFromCString(
                        str(len(replacement) - 1))
                    message = "cloaked parent process path from proc_pidpath"
            process.Continue()
            return message

        if bp_id not in self._bp_ids:
            return None
        thread = process.GetSelectedThread()
        if not thread or not thread.IsValid():
            return None
        frame = thread.GetFrameAtIndex(0)
        if not frame or not frame.IsValid():
            return None
        buffer = frame.FindRegister("x1").GetValueAsUnsigned()
        capacity = frame.FindRegister("x2").GetValueAsUnsigned()
        return_address = frame.FindRegister("lr").GetValueAsUnsigned()
        if buffer and capacity and return_address:
            bp = target.BreakpointCreateByAddress(return_address)
            bp.SetOneShot(True)
            bp.SetThreadID(thread.GetThreadID())
            self._return_hooks[bp.GetID()] = (
                "proc_pidpath", buffer, capacity)
        process.Continue()
        return ""

    def clear_return_hooks(self) -> None:
        self._delete_breakpoints(self._return_hooks)
        self._return_hooks.clear()

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "resolved": len(self._bp_ids),
            "deferred": 0,
            "error": None,
        }
