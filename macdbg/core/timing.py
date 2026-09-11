"""Hardware-backed rules for analyst-verified timing decisions.

Rules change stopped thread state; they neither synthesize a global clock nor
resume the process. The execution controller retains ownership of stepping.
"""
from __future__ import annotations

import re

import lldb

from .breakpoints import create_hardware_breakpoint, validate_hardware_capacity


def integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("expected an integer or numeric string")
    return int(value, 0) if isinstance(value, str) else value


def register_bits(name):
    if not isinstance(name, str) or not re.fullmatch(r"[xw](?:[12]?\d|30)", name):
        raise ValueError("timing rules require an ARM64 x0-x30 or w0-w30 register")
    return 32 if name.startswith("w") else 64


def rewritten_value(old, value, mask, bits):
    limit = (1 << bits) - 1
    if not 0 <= value <= limit or not 0 < mask <= limit or value & ~mask:
        raise ValueError("value must fit the register and contain only masked bits")
    return (old & (limit ^ mask)) | value


class TimingDefense:
    def __init__(self, debugger):
        self.debugger = debugger
        self.rules = []
        self.enabled = False
        self.last_error = None
        self._hooks = {}
        self._handled = set()
        self.hits = {}

    def _stopped(self):
        process = self.debugger.process
        if not process or not process.IsValid() or process.GetState() != lldb.eStateStopped:
            raise ValueError("timing rules require a stopped process")
        if self.debugger.in_user_step():
            raise ValueError("finish or cancel the current step before changing timing rules")

    def _module(self):
        target = self.debugger.target
        if not target or not target.IsValid():
            raise ValueError("no target")
        if not (target.GetTriple() or "").startswith(("arm64", "aarch64")):
            raise ValueError("timing rules currently support native ARM64 targets")
        module = target.FindModule(target.GetExecutable())
        if not module.IsValid():
            raise ValueError("main executable is not loaded")
        base = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if base in (0, lldb.LLDB_INVALID_ADDRESS):
            raise ValueError("main executable has no load address")
        return module, base

    def _instruction(self, address):
        module, _ = self._module()
        section = module.FindSection("__TEXT").FindSubSection("__text")
        start = section.GetLoadAddress(self.debugger.target)
        if (not section.IsValid() or address % 4 or start == lldb.LLDB_INVALID_ADDRESS
                or not start <= address <= start + section.GetByteSize() - 4):
            raise ValueError("rule addresses must be aligned instructions in main __TEXT,__text")
        data = self.debugger.read_memory(address, 4)
        if len(data) != 4:
            raise ValueError("cannot read timing rule instruction")
        return data.hex()

    def _persist(self):
        state = self.debugger.state
        if state is not None:
            state.timing_rules = [dict(rule) for rule in self.rules]

    def add(self, args):
        self._stopped()
        if self.enabled:
            raise ValueError("disable timing rules before editing them")
        allowed = {"name", "addr", "register", "value", "mask", "redirect"}
        if set(args) - allowed:
            raise ValueError("unknown timing rule fields: " + ", ".join(sorted(set(args) - allowed)))
        name = args.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("rule name must be 1-64 letters, digits, dots, underscores or hyphens")
        if any(rule["name"] == name for rule in self.rules):
            raise ValueError("timing rule name already exists")
        address = integer(args["addr"])
        _, base = self._module()
        rule = {"name": name, "offset": address - base,
                "expected": self._instruction(address)}
        if any(r["offset"] == rule["offset"] for r in self.rules):
            raise ValueError("only one timing action is allowed at each instruction")
        if "redirect" in args:
            if set(args) & {"register", "value", "mask"}:
                raise ValueError("choose a register action or a redirect, not both")
            destination = integer(args["redirect"])
            if destination == address:
                raise ValueError("redirect must advance to a different instruction")
            rule.update(redirect_offset=destination - base,
                        redirect_expected=self._instruction(destination))
        else:
            register = args["register"]
            bits = register_bits(register)
            value = integer(args["value"])
            mask = integer(args.get("mask", (1 << bits) - 1))
            rewritten_value(0, value, mask, bits)
            rule.update(register=register, value=value, mask=mask)
        self.rules.append(rule)
        self.last_error = None
        self._persist()
        return dict(rule)

    def remove(self, name):
        self._stopped()
        if self.enabled:
            raise ValueError("disable timing rules before editing them")
        if not any(rule["name"] == name for rule in self.rules):
            raise ValueError("unknown timing rule")
        self.rules = [rule for rule in self.rules if rule["name"] != name]
        self.last_error = None
        self._persist()

    def _validated_rules(self):
        _, base = self._module()
        if not isinstance(self.rules, list):
            raise ValueError("saved timing rules must be a list")
        names, sites = set(), set()
        for saved in self.rules:
            if not isinstance(saved, dict):
                raise ValueError("saved timing rule must be an object")
            rule = dict(saved)
            name = rule["name"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
                    or name in names):
                raise ValueError("invalid or duplicate saved timing rule name")
            offset = integer(rule["offset"])
            rule["offset"] = offset
            address = base + offset
            if address in sites:
                raise ValueError("duplicate timing rule address")
            names.add(name)
            sites.add(address)
            if self._instruction(address) != rule["expected"]:
                raise ValueError("instruction changed for timing rule " + name)
            if "redirect_offset" in rule:
                if set(rule) != {"name", "offset", "expected", "redirect_offset", "redirect_expected"}:
                    raise ValueError("invalid saved redirect rule")
                rule["redirect_offset"] = integer(rule["redirect_offset"])
                destination = base + rule["redirect_offset"]
                if destination == address or self._instruction(destination) != rule["redirect_expected"]:
                    raise ValueError("redirect instruction changed for timing rule " + name)
            else:
                if set(rule) != {"name", "offset", "expected", "register", "value", "mask"}:
                    raise ValueError("invalid saved register rule")
                bits = register_bits(rule["register"])
                rule["value"], rule["mask"] = integer(rule["value"]), integer(rule["mask"])
                rewritten_value(0, rule["value"], rule["mask"], bits)
            yield rule, address

    def enable(self):
        if self.enabled:
            return self.validate()
        try:
            self._stopped()
            automatic = getattr(self.debugger, "auto_clock", None)
            if automatic and automatic.enabled:
                raise ValueError("disable automatic clocks before enabling manual timing rules")
            if not self.rules:
                raise ValueError("configure at least one timing rule before enabling anti_timing")
            validated = list(self._validated_rules())
            for rule, address in validated:
                bp = create_hardware_breakpoint(self.debugger.target, self.debugger.ci,
                                                "-a {:#x}".format(address))
                self._hooks[bp.GetID()] = (rule, address)
                self.debugger.hardware_bp_ids.add(bp.GetID())
            self.enabled = True
            self.last_error = None
            self._handled.clear()
            self.hits.clear()
            return True, "timing rules enabled ({} hardware sites)".format(len(self._hooks))
        except (ValueError, KeyError, TypeError, RuntimeError) as error:
            self.disable()
            self.last_error = str(error)
            return False, self.last_error

    def disable(self):
        target = self.debugger.target
        for bp_id in self._hooks:
            if target and target.IsValid():
                target.BreakpointDelete(bp_id)
            self.debugger.hardware_bp_ids.discard(bp_id)
        self._hooks.clear()
        self._handled.clear()
        self.enabled = False
        self.last_error = None
        return True, "timing rules disabled"

    def hidden_bp_ids(self):
        return set(self._hooks)

    @staticmethod
    def _check_filters(breakpoint, owner=None):
        if (breakpoint.GetCondition() or breakpoint.GetIgnoreCount()
                or breakpoint.GetAutoContinue()
                or breakpoint.GetThreadID() not in (lldb.LLDB_INVALID_THREAD_ID, owner)
                or breakpoint.GetThreadIndex() not in (0, lldb.LLDB_INVALID_INDEX32)
                or breakpoint.GetThreadName() or breakpoint.GetQueueName()):
            raise ValueError("timing breakpoint filters were modified; disable and re-enable")
        commands = lldb.SBStringList()
        breakpoint.GetCommandLineCommands(commands)
        if commands.GetSize():
            raise ValueError("timing breakpoint has commands; disable and re-enable")

    def validate(self):
        if not self.enabled:
            return True, "timing rules disabled"
        if self.last_error:
            return False, self.last_error
        try:
            target = self.debugger.target
            if not self._hooks or len(self._hooks) != len(self.rules):
                raise ValueError("timing rule hooks are missing; disable and re-enable")
            validate_hardware_capacity(target, reserve=int(self.debugger._step_plan_active))
            for bp_id, (_, address) in self._hooks.items():
                bp = target.FindBreakpointByID(bp_id)
                if (not bp.IsValid() or not bp.IsEnabled() or not bp.IsHardware()
                        or bp.GetNumLocations() != 1 or bp.IsOneShot()):
                    raise ValueError("timing breakpoint was modified; disable and re-enable")
                location = bp.GetLocationAtIndex(0)
                if not location.IsEnabled() or not location.IsResolved() or location.GetLoadAddress() != address:
                    raise ValueError("timing breakpoint is disabled or moved; disable and re-enable")
                self._check_filters(bp)
                self._check_filters(location)
            sites = {address for _, address in self._hooks.values()}
            for index in range(target.GetNumBreakpoints()):
                bp = target.GetBreakpointAtIndex(index)
                if bp.IsEnabled() and not bp.IsHardware():
                    for j in range(bp.GetNumLocations()):
                        location = bp.GetLocationAtIndex(j)
                        if location.IsEnabled() and location.GetLoadAddress() in sites:
                            raise ValueError("software breakpoint overlaps a timing rule; remove it before resuming")
            process = self.debugger.process
            if process and process.GetState() == lldb.eStateStopped:
                list(self._validated_rules())
            return True, "timing rules ready"
        except (ValueError, KeyError, TypeError, RuntimeError) as error:
            self.last_error = str(error)
            return False, self.last_error

    def require_ready(self):
        ok, message = self.validate()
        if not ok:
            raise RuntimeError(message)

    def apply_stop(self):
        """Return (messages, exclusively_ours) without resuming any thread."""
        if not self.enabled:
            return [], False
        self.require_ready()
        process = self.debugger.process
        if not process or process.GetState() != lldb.eStateStopped:
            return [], False
        stop_id = process.GetStopID()
        # Keep deduplication bounded while allowing multiple stopped threads.
        self._handled = {key for key in self._handled if key[:2] == (process.GetProcessID(), stop_id)}
        messages, matched, foreign = [], False, False
        for thread in process:
            reason = thread.GetStopReason()
            ids = {thread.GetStopReasonDataAtIndex(i)
                   for i in range(0, thread.GetStopReasonDataCount(), 2)} if reason == lldb.eStopReasonBreakpoint else set()
            frame = thread.GetFrameAtIndex(0)
            if not frame.IsValid():
                continue
            pc = frame.GetPC()
            hooks = [(bid, rule) for bid, (rule, addr) in self._hooks.items() if addr == pc]
            foreign |= bool(ids - self.hidden_bp_ids()) or reason not in (
                lldb.eStopReasonNone, lldb.eStopReasonInvalid, lldb.eStopReasonBreakpoint)
            if reason not in (lldb.eStopReasonBreakpoint, lldb.eStopReasonPlanComplete):
                continue
            for bid, rule in hooks:
                matched = True
                key = (process.GetProcessID(), stop_id, thread.GetThreadID(), bid)
                if key in self._handled:
                    continue
                try:
                    if "redirect_offset" in rule:
                        _, base = self._module()
                        destination = base + rule["redirect_offset"]
                        if not frame.SetPC(destination) or thread.GetFrameAtIndex(0).GetPC() != destination:
                            raise ValueError("could not redirect program counter")
                        detail = "pc {:#x} -> {:#x}".format(pc, destination)
                    else:
                        name = rule["register"]
                        bits = register_bits(name)
                        # Use the physical X register to enforce W-write zero extension.
                        register = frame.FindRegister("x" + name[1:])
                        if not register.IsValid():
                            raise ValueError("register is unavailable: " + name)
                        error = lldb.SBError()
                        old = register.GetValueAsUnsigned(error, 0)
                        if error.Fail():
                            raise ValueError(error.GetCString() or "register read failed")
                        value = rewritten_value(old, rule["value"], rule["mask"], bits)
                        if not register.SetValueFromCString(hex(value), error) or error.Fail():
                            raise ValueError(error.GetCString() or "register write failed")
                        actual = thread.GetFrameAtIndex(0).FindRegister("x" + name[1:]).GetValueAsUnsigned(error, 0)
                        if error.Fail() or actual != value:
                            raise ValueError("register write verification failed")
                        detail = "{} {:#x} -> {:#x}".format(name, old, value)
                    self._handled.add(key)
                    self.hits[rule["name"]] = self.hits.get(rule["name"], 0) + 1
                    messages.append("[timing] {} thread {}: {}".format(rule["name"], thread.GetThreadID(), detail))
                except (ValueError, RuntimeError) as error:
                    self.last_error = "timing rule {}: {}".format(rule["name"], error)
                    raise RuntimeError(self.last_error) from error
        return messages, matched and not foreign

    def status(self):
        ok, error = self.validate()
        return {"enabled": self.enabled, "safe": self.enabled and ok,
                "error": self.last_error if ok else error,
                "armed": len(self._hooks), "hits": dict(self.hits),
                "rules": self.rules}
