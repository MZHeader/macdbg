"""Opt-in rescanning of changed executable memory at debugger stops."""
import hashlib


class SyscallMonitor:
    def __init__(self, debugger):
        self.dbg = debugger
        self.enabled = False
        self.previous = {}
        self.owned = set()
        self.locations = {}
        self.rows = []
        self.owns_memory_monitor = False
        self.previously_requested = False

    def configure(self, enabled=True):
        if enabled:
            if self.enabled: return self.status()
            self.previously_requested = self.dbg.direct_syscall_requested
            self.owns_memory_monitor = not self.dbg.memory_analysis.enabled
            self.dbg.memory_analysis.enable()
            self.enabled = True
            self.observe()
        else:
            for bid in list(self.owned): self.dbg.delete_breakpoint(bid)
            self.dbg.direct_syscall_bp_ids = [bid for bid in self.dbg.direct_syscall_bp_ids or [] if bid not in self.owned]
            if self.enabled and not self.dbg.direct_syscall_bp_ids:
                self.dbg.direct_syscall_requested = self.previously_requested
            self.owned.clear(); self.locations.clear(); self.previous.clear(); self.rows.clear(); self.enabled = False
            if self.owns_memory_monitor: self.dbg.memory_analysis.disable()
            self.owns_memory_monitor = False
        return self.status()

    def observe(self):
        if not self.enabled: return False
        remaining, rows, failed = 8 * 1024 * 1024, [], False
        active = set()
        ranges = []
        for region in self.dbg.memory_analysis.regions():
            if not region['protection'] & 4 or region['name'].startswith(('/System/', '/usr/lib/')): continue
            base = region['base']; size = min(region['size'], 256 * 1024, remaining)
            if size <= 0:
                rows.append({'address': hex(base), 'bytes': 0, 'error': '8 MiB scan budget exhausted', 'omitted': region['size']}); continue
            size -= size % 4; remaining -= size; active.add(base)
            ranges.append((base, base + size))
            data = self.dbg.read_memory(base, size)
            row = {'address': hex(base), 'bytes': len(data), 'omitted': region['size'] - size}
            if len(data) != size:
                row['error'] = 'Partial executable read'; failed = True; rows.append(row); continue
            digest = hashlib.sha256(data).digest()
            signature = (digest, size)
            if self.previous.get(base) != signature:
                stale = {bid for bid in self.owned if base <= self.locations.get(bid, -1) < base + size}
                for bid in stale: self.dbg.delete_breakpoint(bid)
                self.owned -= stale
                for bid in stale: self.locations.pop(bid, None)
                self.dbg.direct_syscall_bp_ids = [bid for bid in self.dbg.direct_syscall_bp_ids or [] if bid not in stale]
                before = set(self.dbg.direct_syscall_bp_ids or [])
                try:
                    result = self.dbg.scan_live_syscalls(base, size)
                    created = set(self.dbg.direct_syscall_bp_ids or []) - before
                    self.owned.update(created)
                    for bid in created:
                        self.locations[bid] = self.dbg.target.FindBreakpointByID(bid).GetLocationAtIndex(0).GetLoadAddress()
                    self.previous[base] = signature
                    row['new_sites'] = result['sites']
                except (RuntimeError, ValueError) as error:
                    row['error'] = str(error); failed = True
            rows.append(row)
        for base in set(self.previous) - active: self.previous.pop(base, None)
        stale = {bid for bid in self.owned if not any(start <= self.locations.get(bid,-1) < end for start,end in ranges)}
        for bid in stale:
            self.dbg.delete_breakpoint(bid); self.locations.pop(bid, None)
        self.owned -= stale
        self.dbg.direct_syscall_bp_ids = [bid for bid in self.dbg.direct_syscall_bp_ids or [] if bid not in stale]
        self.rows = rows
        return failed

    def status(self):
        return {'enabled': self.enabled, 'sites': len(self.owned), 'regions': self.rows,
                'coverage': 'At debugger stops and supported mmap/mprotect/dlopen returns: first 256 KiB of each non-system executable region, at most 8 MiB per scan. Hardware sites are finite. Unobserved inline mapping syscalls can execute before a scan.'}
