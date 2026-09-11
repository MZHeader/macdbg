"""Shared hardware breakpoint allocation with transactional LLDB ownership."""
import functools
import re
import subprocess


def remember_hardware_return(debugger, bp_id):
    """Remember only an owned, sole hardware return stop before its deletion."""
    import lldb
    try:
        process = debugger.process
        thread = process.GetSelectedThread()
        bp = debugger.target.FindBreakpointByID(bp_id)
        if (not bp.IsValid() or not bp.IsHardware()
                or thread.GetStopReason() != lldb.eStopReasonBreakpoint
                or thread.GetStopReasonDataCount() != 2
                or thread.GetStopReasonDataAtIndex(0) != bp_id
                or bp.GetThreadID() != thread.GetThreadID()):
            return
        pc = thread.GetFrameAtIndex(0).GetPC()
        if not any(bp.GetLocationAtIndex(i).IsResolved()
                   and bp.GetLocationAtIndex(i).GetLoadAddress() == pc
                   for i in range(bp.GetNumLocations())):
            return
        code = debugger.read_memory(pc, 4)
        if len(code) != 4 or int.from_bytes(code, 'little') & 0xffe0001f == 0xd4200000:
            return
        key = (process.GetProcessID(), process.GetStopID())
        debugger._retired_hardware_return = (key, thread.GetThreadID(), pc, code)
    except AttributeError:
        # Older bindings without the required ownership metadata get no retry.
        return


def remember_continue_positions(debugger):
    """Snapshot stopped threads before a free continue with hardware sites."""
    import lldb
    debugger._hardware_continue = None
    if getattr(debugger, '_suppress_duplicate_retry', False):
        debugger._suppress_duplicate_retry = False
        return
    if debugger.in_user_step():
        return
    target, process = debugger.target, debugger.process
    if (not (target.GetTriple() or '').startswith('arm64-')
            or process.GetState() != lldb.eStateStopped):
        return
    armed = any(target.GetBreakpointAtIndex(i).IsEnabled()
                and target.GetBreakpointAtIndex(i).IsHardware()
                and any(target.GetBreakpointAtIndex(i).GetLocationAtIndex(j).IsResolved()
                        for j in range(target.GetBreakpointAtIndex(i).GetNumLocations()))
                for i in range(target.GetNumBreakpoints()))
    if not armed:
        return
    positions, instructions = {}, {}
    for thread in process:
        frame = thread.GetFrameAtIndex(0)
        if not frame.IsValid():
            continue
        pc = frame.GetPC()
        if pc not in instructions:
            instructions[pc] = debugger.read_memory(pc, 4)
        code = instructions[pc]
        if len(code) == 4 and int.from_bytes(code, 'little') & 0xffe0001f != 0xd4200000:
            positions[thread.GetThreadID()] = (pc, code)
    debugger._hardware_continue = (process.GetProcessID(), process.GetStopID(), positions)


def consume_hardware_debugger_duplicate(debugger):
    """Retry once for a retired hardware stop or an interrupted continue.

    No instruction is skipped. Any intervening stop, different thread/PC,
    changed instruction, live breakpoint, or concurrent real stop rejects it.
    """
    import lldb
    retired = getattr(debugger, '_retired_hardware_return', None)
    debugger._retired_hardware_return = None
    continued = getattr(debugger, '_hardware_continue', None)
    debugger._hardware_continue = None
    if (not retired and not continued) or debugger.in_user_step():
        return False
    process = debugger.process
    if process.GetState() != lldb.eStateStopped:
        return False
    key = (process.GetProcessID(), process.GetStopID() - 1)
    matched = []
    for thread in process:
        reason = thread.GetStopReason()
        if reason in (lldb.eStopReasonNone, lldb.eStopReasonInvalid):
            continue
        if reason != lldb.eStopReasonException:
            return False
        owner, pc = thread.GetThreadID(), thread.GetFrameAtIndex(0).GetPC()
        description = thread.GetStopDescription(256) or ''
        match = re.fullmatch(r'EXC_BREAKPOINT \(code=1, subcode=(0x[0-9a-fA-F]+)\)', description)
        if not match:
            return False
        subcode = int(match[1], 16)
        code = None
        if retired and retired[:3] == (key, owner, pc) and subcode == pc:
            code = retired[3]
        # Darwin can complete a single step after a free continue without PC
        # progress when hardware sites are armed. This mirrors LLDB's
        # StopInfoMachException::WasContinueInterrupted compatibility check.
        elif continued and continued[:2] == key and subcode == 0:
            previous = continued[2].get(owner)
            if previous and previous[0] == pc:
                code = previous[1]
        if code is None or debugger.read_memory(pc, 4) != code:
            return False
        matched.append(pc)
    if not matched:
        return False
    for i in range(debugger.target.GetNumBreakpoints()):
        bp = debugger.target.GetBreakpointAtIndex(i)
        if bp.IsEnabled() and any(
                bp.GetLocationAtIndex(j).IsEnabled()
                and bp.GetLocationAtIndex(j).GetLoadAddress() in matched
                for j in range(bp.GetNumLocations())):
            return False
    debugger._suppress_duplicate_retry = True
    return True


@functools.lru_cache(maxsize=1)
def hardware_breakpoint_capacity():
    # debugserver itself uses this sysctl. Its HardwarePreferred path can
    # silently install software traps after resource exhaustion, even though
    # SBBreakpoint.IsHardware() stays true. Bound requests ourselves.
    try:
        output = subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", "hw.optional.breakpoint"],
            stderr=subprocess.PIPE, text=True, timeout=5)
        count = int(output.strip())
        if count > 0:
            return count
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    raise RuntimeError("cannot determine hardware breakpoint slots; "
                       "local ARM64 hardware breakpoint support is required")


def validate_hardware_capacity(target, reserve=0):
    addresses = set()
    for i in range(target.GetNumBreakpoints()):
        bp = target.GetBreakpointAtIndex(i)
        if not bp.IsEnabled() or not bp.IsHardware():
            continue
        for j in range(bp.GetNumLocations()):
            location = bp.GetLocationAtIndex(j)
            if location.IsEnabled():
                addresses.add(location.GetLoadAddress())
    requested = len(addresses) + reserve
    if requested and requested > hardware_breakpoint_capacity():
        raise RuntimeError(
            "hardware breakpoint allocation failed: {} sites exceed {} slots; "
            "delete or disable hardware breakpoints, or reduce traced sites"
            .format(requested, hardware_breakpoint_capacity()))


def create_hardware_breakpoint(target, ci, selector, require_location=True, reserve=0):
    import lldb
    if ci is None:
        raise RuntimeError("hardware breakpoints require an LLDB command interpreter")
    before = {target.GetBreakpointAtIndex(i).GetID()
              for i in range(target.GetNumBreakpoints())}
    result = lldb.SBCommandReturnObject()
    ci.HandleCommand("breakpoint set -H " + selector, result, False)
    created = [target.GetBreakpointAtIndex(i)
               for i in range(target.GetNumBreakpoints())
               if target.GetBreakpointAtIndex(i).GetID() not in before]
    if (not result.Succeeded() or len(created) != 1
            or not created[0].IsValid()
            or not created[0].IsHardware()
            or (require_location and created[0].GetNumLocations() == 0)
            or not all(created[0].GetLocationAtIndex(i).IsResolved()
                       for i in range(created[0].GetNumLocations()))):
        for bp in created:
            target.BreakpointDelete(bp.GetID())
        raise RuntimeError(
            "hardware breakpoint allocation failed ({}); free hardware breakpoint "
            "slots or reduce traced sites: {}".format(
                selector, (result.GetError() or "no resolved hardware location").strip()))
    try:
        hardware_addresses = {
            created[0].GetLocationAtIndex(i).GetLoadAddress()
            for i in range(created[0].GetNumLocations())}
        for i in range(target.GetNumBreakpoints()):
            bp = target.GetBreakpointAtIndex(i)
            if bp.IsHardware() or not bp.IsEnabled():
                continue
            if any(bp.GetLocationAtIndex(j).IsEnabled()
                   and bp.GetLocationAtIndex(j).GetLoadAddress() in hardware_addresses
                   for j in range(bp.GetNumLocations())):
                raise RuntimeError(
                    "hardware breakpoint shares a software breakpoint site; "
                    "delete the software breakpoint first")
        validate_hardware_capacity(target, reserve)
    except RuntimeError:
        for bp in created:
            target.BreakpointDelete(bp.GetID())
        raise
    return created[0]
