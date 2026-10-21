"""Thread/stack-owned return observations shared by tracing and memory tracking."""
import lldb


class ReturnHooks:
    def __init__(self, debugger, limit=128):
        self.debugger, self.limit = debugger, limit
        self.pending = {}
        self.sequence = 0
        self.retired = set()

    def ids(self):
        return set(self.pending)

    def clear(self):
        for bid in list(self.pending):
            self.debugger.delete_breakpoint(bid)
        self.pending.clear()
        self.retired.clear()

    def arm(self, frame, payload):
        if len(self.pending) >= self.limit:
            raise RuntimeError('pending return observation limit reached')
        address = frame.FindRegister('lr').GetValueAsUnsigned()
        if not address:
            raise RuntimeError('return address unavailable')
        bp = self.debugger.create_hardware_breakpoint_by_address(address)
        tid = frame.GetThread().GetThreadID()
        bp.SetThreadID(tid)
        self.sequence += 1
        self.pending[bp.GetID()] = dict(tid=tid, sp=frame.FindRegister('sp').GetValueAsUnsigned(),
            address=address, payload=payload, invocation=self.sequence)
        return self.sequence

    def consume(self, thread):
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return []
        frame = thread.GetFrameAtIndex(0)
        pc, sp = frame.GetPC(), frame.FindRegister('sp').GetValueAsUnsigned()
        # Match our ownership, not just LLDB's list: different logical return
        # hooks can share a single hardware site on different threads.
        matches = [(bid, item) for bid, item in self.pending.items()
                   if item['tid'] == thread.GetThreadID() and item['address'] == pc and item['sp'] == sp]
        if not matches:
            return []
        self.retired = {bid for bid, _ in matches}
        # Tail-recursive calls can share SP/LR. Report each observed invocation.
        from .breakpoints import remember_hardware_return
        for bid, _ in matches:
            remember_hardware_return(self.debugger, bid)
            self.debugger.delete_breakpoint(bid)
            del self.pending[bid]
        return [item for _, item in reversed(matches)]
