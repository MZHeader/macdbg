"""Shared hardware breakpoint allocation with transactional LLDB ownership."""
import functools
import re
import subprocess


def restore_breakpoint(debugger, stored):
    """Use LLDB's logical resolver, retaining pending/multiple/module locations."""
    import json
    import tempfile
    import lldb
    target = debugger.target
    before = {bp.GetID() for bp in target.breakpoint_iter()}
    try:
        if stored.specification:
            # LLDB's format includes module/file addresses, resolver and filters.
            # Do not collapse a pending symbol or regex into its first location.
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as file:
                json.dump([stored.specification], file)
                file.flush()
                restored = lldb.SBBreakpointList(target)
                error = target.BreakpointsCreateFromFile(lldb.SBFileSpec(file.name), restored)
            if error.Fail() or restored.GetSize() != 1:
                raise RuntimeError('cannot restore breakpoint: ' + (error.GetCString() or 'invalid resolver'))
            bp = restored.GetBreakpointAtIndex(0)
        elif stored.hardware:
            bp = debugger.create_hardware_breakpoint_by_address(stored.addr)
        else:
            bp = target.BreakpointCreateByAddress(stored.addr)
        if not bp.IsValid() or bp.IsHardware() != stored.hardware:
            raise RuntimeError('restored breakpoint backing does not match saved hardware policy')
        if stored.hardware:
            validate_hardware_capacity(target)
            debugger.hardware_bp_ids.add(bp.GetID())
        return bp
    except Exception:
        for bp in list(target.breakpoint_iter()):
            if bp.GetID() not in before:
                debugger.delete_breakpoint(bp.GetID())
        raise


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
    debugger._retired_step_candidate = None
    retired_candidate = None
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
            retired_candidate = (owner, pc)
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
    if len(matched) == 1:
        debugger._retired_step_candidate = retired_candidate
    return True


def start_hardware_recovery(debugger, owner, pc, log, source):
    process = debugger.process
    thread = process.GetSelectedThread()
    if thread.GetThreadID() != owner: return 'visible'
    if not debugger.analysis_cloak.validate_resume()[0]: return 'visible'
    if not debugger.analysis_cloak.validate_integrity(debugger.extra_hardware_bp_ids())[0]: return 'visible'
    key = (process.GetUniqueID(), owner, pc)
    debugger._hardware_recovery = (process.GetUniqueID(), process.GetStopID(), owner, pc)
    log('[debugger] single-stepping an owned hardware site with missing stop ID')
    debugger.record_event('DEBUGGER', 'Recovered an unclassified hardware stop without skipping its instruction',
                          pc=hex(pc), thread=owner, source=source)
    try:
        debugger._run_execution(lambda: thread.StepInstruction(False))
    except Exception:
        debugger._hardware_recovery = None
        debugger._hardware_recovery_failed = key
        raise
    return 'resumed'


def recover_owned_hardware_stop(debugger, log):
    """Single-step a passive API trace site whose hardware stop lost its ID.

    Darwin can report EXC_BREAKPOINT at a live hardware return site instead of
    its logical breakpoint. Never advance PC manually or classify arbitrary
    exceptions: require the exact thread/site, unchanged non-BRK instruction,
    no colocated foreign breakpoint and no concurrent real stop. A recovery
    that does not finish as an instruction step is surfaced, never retried.
    """
    import lldb
    process = debugger.process
    traced = getattr(debugger, '_traced_hardware_stop', None)
    debugger._traced_hardware_stop = None
    token = getattr(debugger, '_hardware_recovery', None)
    if isinstance(token, tuple):
        debugger._hardware_recovery = None
        identity, stop, owner, pc = token
        thread = process.GetSelectedThread()
        if (process.GetUniqueID() == identity and process.GetStopID() == stop + 1
                and thread.GetThreadID() == owner
                and thread.GetStopReason() in (lldb.eStopReasonPlanComplete, lldb.eStopReasonTrace)
                and all(t.GetThreadID() == owner or t.GetStopReason() in (lldb.eStopReasonNone, lldb.eStopReasonInvalid) for t in process)):
            debugger._hardware_recovery_failed = None
            debugger._suppress_duplicate_retry = False
            return 'internal'
        debugger._hardware_recovery_failed = (identity, owner, pc)
        return 'visible'
    if debugger.in_user_step() or not process or process.GetState() != lldb.eStateStopped:
        return None
    thread = process.GetSelectedThread()
    if thread.GetStopReason() != lldb.eStopReasonException:
        debugger._hardware_recovery_failed = None
        return None
    pc, owner = thread.GetFrameAtIndex(0).GetPC(), thread.GetThreadID()
    if (thread.GetStopDescription(256) or '').lower() != 'exc_breakpoint (code=1, subcode={:#x})'.format(pc):
        return None
    key = (process.GetUniqueID(), owner, pc)
    if getattr(debugger, '_hardware_recovery_failed', None) == key: return 'visible'
    traced_site = (isinstance(traced, tuple) and traced[:4] ==
                   (process.GetUniqueID(), process.GetStopID()-1, owner, pc)
                   and debugger.read_memory(pc,4) == traced[4])
    if not traced_site: return None
    bid = traced[5]
    bp = debugger.target.FindBreakpointByID(bid)
    if (not bp.IsValid() or not bp.IsHardware() or not bp.IsEnabled()
            or bp.GetThreadID() not in (owner, lldb.LLDB_INVALID_THREAD_ID)):
        return None
    code = debugger.read_memory(pc, 4)
    if len(code) != 4 or int.from_bytes(code, 'little') & 0xffe0001f == 0xd4200000: return None
    if any(t.GetThreadID() != owner and t.GetStopReason() not in (lldb.eStopReasonNone, lldb.eStopReasonInvalid) for t in process):
        return None
    for other in debugger.target.breakpoint_iter():
        if other.GetID() != bid and other.IsEnabled() and any(
                other.GetLocationAtIndex(i).IsEnabled() and other.GetLocationAtIndex(i).GetLoadAddress() == pc
                for i in range(other.GetNumLocations())):
            return None
    return start_hardware_recovery(debugger, owner, pc, log, 'previously observed API trace stop')


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


def hardware_usage(target):
    if not target or not target.IsValid():
        return 0
    addresses = set()
    for i in range(target.GetNumBreakpoints()):
        bp = target.GetBreakpointAtIndex(i)
        if not bp.IsEnabled() or not bp.IsHardware():
            continue
        for j in range(bp.GetNumLocations()):
            location = bp.GetLocationAtIndex(j)
            if location.IsEnabled() and location.IsResolved():
                addresses.add(location.GetLoadAddress())
    return len(addresses)


def validate_hardware_capacity(target, reserve=0):
    requested = hardware_usage(target) + reserve
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
