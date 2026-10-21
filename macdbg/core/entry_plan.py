"""Queue entry-only defenses while preserving the early-loader analysis stop."""
class EntryPlan:
    MODES = ('analysis_cloak', 'auto_clock')

    def __init__(self, debugger):
        self.debugger = debugger
        self.queued = set()
        self.bp = None
        self.error = None

    def clear(self, keep_queue=False):
        if self.bp and self.debugger.target:
            self.debugger.delete_breakpoint(self.bp)
        self.bp = None
        self.error = None
        if not keep_queue:
            self.queued.clear()

    def queue(self, name, enabled):
        if name not in self.MODES:
            raise ValueError('only Analysis cloak and automatic clocks can be queued at entry')
        if not self.debugger.is_stopped_before_initializers():
            raise ValueError('queue entry defenses at the initial loader stop')
        (self.queued.add if enabled else self.queued.discard)(name)
        return {'queued':sorted(self.queued)}

    def arm(self):
        d = self.debugger
        if self.bp:
            return
        address = d.entry_point_address()
        if not address:
            raise RuntimeError('main entry address is unavailable')
        bp = d.create_hardware_breakpoint_by_address(address)
        self.bp = bp.GetID()

    def apply_stop(self):
        d = self.debugger
        if not self.bp or not d.is_stopped_at_entry_point():
            return False
        d.delete_breakpoint(self.bp)
        self.bp = None
        for name in self.MODES:
            if name not in self.queued:
                continue
            ok, message = getattr(d, 'enable_' + name)()
            d.record_event('DEFENSE', message, defense=name, ready=ok)
            if not ok:
                self.error = message
                raise RuntimeError(message)
            self.queued.remove(name)
        return True  # Always expose the entry stop, even without queued modes.
