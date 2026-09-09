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
    "libcycript", "libreveal", "revealserver", "dobby", "fishhook", "cycript",
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

IOKIT_SPOOFS = {
    "IOPlatformSerialNumber": "C02ZQ0ABC123",
    "IOPlatformUUID": "8D4C7A12-3F65-4B90-A2DE-61C8E5079F34",
}

ParentReturnHook = tuple[str, int, int]
SysctlReturnHook = tuple[str, str, int, int, int]
ImageReturnHook = tuple[str]
ReturnHook = Union[ParentReturnHook, SysctlReturnHook, ImageReturnHook]

IMAGE_REPLACEMENT = "/usr/lib/libSystem.B.dylib"


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


def _escape_c_string(text: str) -> str:
    return (text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            .replace("\0", "\\0"))


class AnalysisCloak:
    _EXISTING_DEFENSES = (
        ("anti_sysctl", "_scrub_ptraced"),
        ("anti_parent", "_scrub_parent"),
        ("anti_timing", "anti_timing_bp_ids"),
    )

    def __init__(self, debugger):
        self.debugger = debugger
        self.enabled: bool = False
        self.last_error: Optional[str] = None
        self._bp_ids: set[int] = set()
        self._entry_hooks: dict[int, str] = {}
        self._return_hooks: dict[int, ReturnHook] = {}
        self._cfstring_cache: dict[str, int] = {}
        self._cstring_cache: dict[str, int] = {}
        self._owned_existing = set()
        self._owned_existing_bp_ids = {}

    def enable(self) -> tuple[bool, str]:
        if self.enabled:
            return True, "analysis cloak already enabled"
        self.last_error = None
        if getattr(self.debugger, "interpose_enabled", False):
            return (False,
                    "analysis cloak is incompatible with fork-tree tracing "
                    "in v1")
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
            for symbol in (
                    "proc_pidpath", "sysctlbyname",
                    "IORegistryEntryCreateCFProperty",
                    "_dyld_get_image_name"):
                bp = create_bp(symbol)
                can_defer = (
                    symbol == "IORegistryEntryCreateCFProperty"
                    and not self._module_loaded("IOKit"))
                if (not bp.IsValid()
                        or (bp.GetNumLocations() == 0 and not can_defer)):
                    if bp.IsValid():
                        target.BreakpointDelete(bp.GetID())
                    self._delete_breakpoints(self._bp_ids)
                    self._bp_ids.clear()
                    self._entry_hooks.clear()
                    self._rollback_existing(acquired)
                    return (False, "could not enable {} cloak: symbol not found"
                            .format(symbol))
                self._bp_ids.add(bp.GetID())
                self._entry_hooks[bp.GetID()] = symbol

        ok, message = self.scrub_live_environment()
        if not ok:
            self._delete_breakpoints(self._bp_ids)
            self._bp_ids.clear()
            self._entry_hooks.clear()
            self._rollback_existing(acquired)
            return False, message

        self.enabled = True
        hook_status = self.status()
        return (True,
                "analysis cloak enabled; {}; {} resolved, {} deferred hooks"
                .format(message, hook_status["resolved"],
                        hook_status["deferred"]))

    def disable(self) -> tuple[bool, str]:
        self._release_cfstrings()
        self._release_cstrings()
        self._delete_breakpoints(set(self._bp_ids) | set(self._return_hooks))
        self._bp_ids.clear()
        self._entry_hooks.clear()
        self._return_hooks.clear()
        for name in reversed([item[0] for item in self._EXISTING_DEFENSES]):
            if name in self._owned_existing:
                getattr(self.debugger, "disable_" + name)()
                self._delete_breakpoints(
                    self._owned_existing_bp_ids.pop(name, set()))
        self._owned_existing.clear()
        self.enabled = False
        self.last_error = None
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

    def _module_loaded(self, marker: str) -> bool:
        target = getattr(self.debugger, "target", None)
        if target is None or not hasattr(target, "GetNumModules"):
            return False
        folded = marker.casefold()
        for index in range(target.GetNumModules()):
            module = target.GetModuleAtIndex(index)
            file_spec = module.GetFileSpec()
            name = file_spec.GetFilename() or ""
            if folded == name.casefold():
                return True
        return False

    def _hook_counts(self) -> tuple[int, int]:
        target = getattr(self.debugger, "target", None)
        if target is None:
            return 0, 0
        resolved = 0
        deferred = 0
        for bp_id in self._bp_ids:
            bp = target.FindBreakpointByID(bp_id)
            if not bp or not bp.IsValid():
                continue
            if bp.GetNumLocations() > 0:
                resolved += 1
            else:
                deferred += 1
        return resolved, deferred

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
            import lldb
            message = ""
            thread = process.GetSelectedThread()
            frame = thread.GetFrameAtIndex(0)
            result = frame.FindRegister("x0")
            returned = result.GetValueAsUnsigned()
            if hook[0] == "image":
                message = self._handle_image_return(result, returned, lldb)
            elif len(hook) == 3:
                _kind, buffer, capacity = hook
                replacement = b"/sbin/launchd\0"
                if 0 < returned <= capacity and capacity >= len(replacement):
                    err = lldb.SBError()
                    read_size = min(capacity, max(returned + 1,
                                                  len(replacement)))
                    data = process.ReadMemory(buffer, read_size, err)
                    nul = data.find(b"\0") if data else -1
                    if (err.Success() and len(data) == read_size
                            and nul >= 0):
                        path = data[:nul].decode("utf-8", errors="replace")
                        if contains_marker(path, TOOL_MARKERS):
                            original = data[:len(replacement)]
                            written = process.WriteMemory(buffer, replacement, err)
                            if err.Success() and written == len(replacement):
                                if (result.SetValueFromCString(
                                        str(len(replacement) - 1))
                                        and result.GetValueAsUnsigned()
                                        == len(replacement) - 1):
                                    message = (
                                        "cloaked parent process path from "
                                        "proc_pidpath")
                                else:
                                    result.SetValueFromCString(str(returned))
                                    rollback = lldb.SBError()
                                    process.WriteMemory(buffer, original, rollback)
                            elif written:
                                rollback = lldb.SBError()
                                process.WriteMemory(buffer, original, rollback)
            else:
                kind, name, buffer, size_pointer, capacity = hook
                if returned == 0:
                    spoof = SYSCTL_SPOOFS[name]
                    payload = (int(spoof.value).to_bytes(4, "little")
                               if kind == "u32" else
                               str(spoof.value).encode() + b"\0")
                    if not buffer or not size_pointer or capacity < len(payload):
                        message = self._critical(
                            "sysctlbyname({}) buffer too small; cloak failed"
                            .format(name))
                    else:
                        original = self._read_exact(buffer, len(payload), lldb)
                        original_size = self._read_exact(size_pointer, 8, lldb)
                        if original is None or original_size is None:
                            message = self._critical(
                                "sysctlbyname({}) could not preserve real result; "
                                "cloak failed".format(name))
                        elif not self._write_exact(buffer, payload, lldb):
                            rollback_ok = self._write_exact(
                                buffer, original, lldb)
                            rollback = ("; rollback failed"
                                        if not rollback_ok else "")
                            message = self._critical(
                                "sysctlbyname({}) could not write result buffer; "
                                "cloak failed{}".format(name, rollback))
                        else:
                            size = len(payload).to_bytes(8, "little")
                            if not self._write_exact(size_pointer, size, lldb):
                                buffer_rollback_ok = self._write_exact(
                                    buffer, original, lldb)
                                size_rollback_ok = self._write_exact(
                                    size_pointer, original_size, lldb)
                                rollback_ok = (buffer_rollback_ok
                                               and size_rollback_ok)
                                rollback = ("; rollback failed"
                                            if not rollback_ok else "")
                                message = self._critical(
                                    "sysctlbyname({}) could not write result size; "
                                    "cloak failed{}".format(name, rollback))
                            else:
                                message = "spoofed sysctlbyname({})".format(name)
            if self.last_error is None:
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
        entry_kind = self._entry_hooks.get(bp_id)
        if entry_kind is None:
            return None
        if entry_kind == "IORegistryEntryCreateCFProperty":
            return self._handle_iokit_entry(frame)
        if entry_kind == "_dyld_get_image_name":
            return_address = frame.FindRegister("lr").GetValueAsUnsigned()
            entry_message = ""
            if return_address:
                bp = target.BreakpointCreateByAddress(return_address)
                if bp.IsValid() and bp.GetNumLocations() > 0:
                    bp.SetOneShot(True)
                    bp.SetThreadID(thread.GetThreadID())
                    self._return_hooks[bp.GetID()] = ("image",)
                else:
                    if bp.IsValid():
                        target.BreakpointDelete(bp.GetID())
                    entry_message = self._critical(
                        "_dyld_get_image_name could not arm return hook; "
                        "cloak failed")
            else:
                entry_message = self._critical(
                    "_dyld_get_image_name has no return address; cloak failed")
            if self.last_error is None:
                process.Continue()
            return entry_message
        buffer = frame.FindRegister("x1").GetValueAsUnsigned()
        size_pointer = frame.FindRegister("x2").GetValueAsUnsigned()
        return_address = frame.FindRegister("lr").GetValueAsUnsigned()
        hook = None
        entry_message = ""
        if entry_kind == "proc_pidpath":
            capacity = size_pointer
            if buffer and capacity:
                hook = ("proc_pidpath", buffer, capacity)
        else:
            import lldb
            name_pointer = frame.FindRegister("x0").GetValueAsUnsigned()
            err = lldb.SBError()
            name = (process.ReadCStringFromMemory(name_pointer, 256, err)
                    if name_pointer else "")
            if err.Success() and name in SYSCTL_SPOOFS:
                size_data = (self._read_exact(size_pointer, 8, lldb)
                             if size_pointer else None)
                if size_data is not None:
                    capacity = int.from_bytes(size_data, "little")
                    hook = (SYSCTL_SPOOFS[name].kind, name, buffer,
                            size_pointer, capacity)
                else:
                    entry_message = self._critical(
                        "sysctlbyname({}) could not read input capacity; "
                        "cloak failed".format(name))
        if hook is not None and return_address:
            bp = target.BreakpointCreateByAddress(return_address)
            if (entry_kind != "sysctlbyname"
                    or (bp.IsValid() and bp.GetNumLocations() > 0)):
                bp.SetOneShot(True)
                bp.SetThreadID(thread.GetThreadID())
                self._return_hooks[bp.GetID()] = hook
            else:
                if bp.IsValid():
                    target.BreakpointDelete(bp.GetID())
                entry_message = self._critical(
                    "sysctlbyname({}) could not arm return hook; cloak failed"
                    .format(hook[1]))
        elif hook is not None and entry_kind == "sysctlbyname":
            entry_message = self._critical(
                "sysctlbyname({}) could not arm return hook; cloak failed"
                .format(hook[1]))
        if self.last_error is None:
            process.Continue()
        return entry_message

    def _handle_image_return(self, result, returned: int, lldb_module) -> str:
        process = self.debugger.process
        if not returned:
            return ""

        error = lldb_module.SBError()
        path = process.ReadCStringFromMemory(returned, 4096, error)
        if not error.Success():
            return self._critical(
                "could not read _dyld_get_image_name result; cloak failed")
        if not contains_marker(path, IMAGE_MARKERS):
            return ""

        replacement = self._cstring_cache.get(IMAGE_REPLACEMENT)
        if replacement is None:
            replacement = self._eval_pointer(
                'expression -l c++ --ignore-breakpoints true -- '
                '(void*)strdup("{}")'.format(
                    _escape_c_string(IMAGE_REPLACEMENT)))
            if not replacement:
                return self._critical(
                    "could not allocate loaded-image replacement; cloak "
                    "failed")
            self._cstring_cache[IMAGE_REPLACEMENT] = replacement

        if (not result.SetValueFromCString(str(replacement))
                or result.GetValueAsUnsigned() != replacement):
            return self._critical(
                "could not replace _dyld_get_image_name result; cloak failed")
        basename = path.rsplit("/", 1)[-1]
        return "cloaked loaded image {}".format(basename)

    def _handle_iokit_entry(self, frame) -> str:
        process = self.debugger.process
        key_pointer = frame.FindRegister("x1").GetValueAsUnsigned()
        key = self._cfstring_text(key_pointer)
        if key is None:
            return self._critical(
                "could not read IOKit property key; cloak failed")
        if key not in IOKIT_SPOOFS:
            process.Continue()
            return ""

        replacement = self._cfstring_cache.get(key)
        if replacement is None:
            replacement = self._make_cfstring(IOKIT_SPOOFS[key])
            if not replacement:
                return self._critical(
                    "could not create replacement for {}; cloak failed"
                    .format(key))
            # The Create reference owned by this cache keeps one stable object
            # alive for the process lifetime. Each intercepted Create call gets
            # a separate retain below for the caller to release.
            self._cfstring_cache[key] = replacement

        retain = self._eval_pointer(
            "expression -l c++ --ignore-breakpoints true -- "
            "(void*)CFRetain((void*){:#x})".format(replacement))
        if retain != replacement:
            return self._critical(
                "could not retain replacement for {}; cloak failed"
                .format(key))

        ok, _out, err = self.debugger.handle_command(
            "thread return {:#x}".format(replacement))
        if not ok:
            self.debugger.handle_command(
                "expression -l c++ --ignore-breakpoints true -- "
                "(void)CFRelease((void*){:#x})".format(replacement))
            return self._critical(
                "could not return replacement for {}; cloak failed: {}"
                .format(key, err.strip()))

        process.Continue()
        return "spoofed IORegistryEntryCreateCFProperty({})".format(key)

    def _eval_pointer(self, expression: str) -> Optional[int]:
        ok, output, _error = self.debugger.handle_command(expression)
        if not ok:
            return None
        matches = re.findall(r"=\s*(0x[0-9a-fA-F]+)", output)
        if not matches:
            return None
        return int(matches[-1], 16)

    def _eval_integer(self, expression: str) -> Optional[int]:
        ok, output, _error = self.debugger.handle_command(expression)
        if not ok:
            return None
        matches = re.findall(r"=\s*(-?[0-9]+)", output)
        if not matches:
            return None
        return int(matches[-1])

    def _cfstring_text(self, pointer: int) -> Optional[str]:
        if not pointer:
            return None
        import lldb
        c_string = self._eval_pointer(
            "expression -l c++ --ignore-breakpoints true -- "
            "(void*)((const char *(*)(const void *, unsigned int))"
            "CFStringGetCStringPtr)((const void*){:#x}, 0x08000100)"
            .format(pointer))
        if c_string is None:
            return None
        if c_string:
            error = lldb.SBError()
            value = self.debugger.process.ReadCStringFromMemory(
                c_string, 256, error)
            return value if error.Success() else None

        buffer = self._eval_pointer(
            "expression -l c++ --ignore-breakpoints true -- "
            "(void*)malloc(256)")
        if not buffer:
            return None
        value = None
        copied = self._eval_integer(
            "expression -l c++ --ignore-breakpoints true -- "
            "(int)((unsigned char (*)(const void *, char *, long, "
            "unsigned int))CFStringGetCString)((const void*){:#x}, "
            "(char*){:#x}, 256, 0x08000100)".format(pointer, buffer))
        if copied == 1:
            error = lldb.SBError()
            candidate = self.debugger.process.ReadCStringFromMemory(
                buffer, 256, error)
            if error.Success():
                value = candidate
        freed, _out, _error = self.debugger.handle_command(
            "expression -l c++ --ignore-breakpoints true -- "
            "(void)free((void*){:#x})".format(buffer))
        return value if freed else None

    def _make_cfstring(self, text: str) -> Optional[int]:
        expression = (
            'expression -l c++ --ignore-breakpoints true -- '
            '(void*)CFStringCreateWithCString((void*)0, "{}", '
            '0x08000100)')
        return self._eval_pointer(
            expression.format(_escape_c_string(text)))

    def _release_cfstrings(self) -> None:
        pointers = set(self._cfstring_cache.values())
        self._cfstring_cache.clear()
        for pointer in pointers:
            self.debugger.handle_command(
                "expression -l c++ --ignore-breakpoints true -- "
                "(void)CFRelease((void*){:#x})".format(pointer))

    def _release_cstrings(self) -> None:
        pointers = set(self._cstring_cache.values())
        self._cstring_cache.clear()
        for pointer in pointers:
            self.debugger.handle_command(
                "expression -l c++ --ignore-breakpoints true -- "
                "(void)free((void*){:#x})".format(pointer))

    def _read_exact(self, address: int, size: int, lldb_module):
        error = lldb_module.SBError()
        data = self.debugger.process.ReadMemory(address, size, error)
        if not error.Success() or data is None or len(data) != size:
            return None
        return bytes(data)

    def _write_exact(self, address: int, data: bytes, lldb_module) -> bool:
        error = lldb_module.SBError()
        written = self.debugger.process.WriteMemory(address, data, error)
        return error.Success() and written == len(data)

    def _critical(self, message: str) -> str:
        if self.last_error is None:
            self.last_error = message
        return self.last_error

    def validate_resume(self) -> tuple[bool, str]:
        if (self.enabled
                and getattr(self.debugger, "interpose_enabled", False)):
            self._critical(
                "analysis cloak is incompatible with fork-tree tracing in v1")
        if self.enabled and self._module_loaded("IOKit"):
            for bp_id, symbol in self._entry_hooks.items():
                if symbol != "IORegistryEntryCreateCFProperty":
                    continue
                bp = self.debugger.target.FindBreakpointByID(bp_id)
                if (not bp or not bp.IsValid()
                        or bp.GetNumLocations() == 0):
                    self._critical(
                        "IORegistryEntryCreateCFProperty hook did not resolve "
                        "after IOKit loaded; cloak failed")
        if self.enabled and self.last_error:
            return False, self.last_error
        return True, "analysis cloak ready"

    def clear_return_hooks(self) -> None:
        self._delete_breakpoints(self._return_hooks)
        self._return_hooks.clear()
        self._release_cfstrings()
        self._release_cstrings()
        self.last_error = None

    def status(self) -> dict:
        resolved, deferred = self._hook_counts()
        return {
            "enabled": self.enabled,
            "resolved": resolved,
            "deferred": deferred,
            "error": self.last_error,
        }
