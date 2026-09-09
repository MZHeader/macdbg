"""Shared hardware breakpoint allocation with transactional LLDB ownership."""
import functools
import subprocess


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
