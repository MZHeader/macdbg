"""Bounded forwarding of simple ARM64 self-traps with context restoration.

This deliberately refuses siginfo, alternate-stack, mask and reentrancy semantics
that cannot be emulated by an ordinary handler invocation.
"""
import struct

import lldb


class SelfTrapForwarder:
    def __init__(self, debugger):
        self.debugger = debugger
        self.active = {}
        self.error = None

    def hidden_ids(self):
        return {entry['bp'] for entry in self.active.values()}

    def reset(self):
        for entry in self.active.values():
            self.debugger.delete_breakpoint(entry['bp'])
            if self.debugger.process and self.debugger.process.IsValid():
                self.debugger.process.DeallocateMemory(entry['stack'])
        self.active.clear()
        self.error = None

    def _action(self):
        d = self.debugger
        error = lldb.SBError()
        address = d.process.AllocateMemory(16, lldb.ePermissionsReadable | lldb.ePermissionsWritable, error)
        if error.Fail():
            raise RuntimeError('cannot allocate sigaction query buffer')
        try:
            result = lldb.SBCommandReturnObject()
            d.ci.HandleCommand('expression -l c++ --ignore-breakpoints true -- '
                '((int(*)(int,void*,void*))sigaction)(5, (void*)0, (void*){:#x})'.format(address), result, False)
            if not result.Succeeded() or not (result.GetOutput() or '').strip().endswith('= 0'):
                raise RuntimeError('cannot query the target SIGTRAP action')
            data = d.read_memory(address, 16)
            if len(data) != 16:
                raise RuntimeError('short sigaction result')
            return struct.unpack('<QII', data)
        finally:
            d.process.DeallocateMemory(address)

    def forward(self, thread):
        d = self.debugger
        if not d.anti_sigtrap_on or thread.GetStopReason() != lldb.eStopReasonException:
            return None
        frame = thread.GetFrameAtIndex(0)
        pc = frame.GetPC()
        module = frame.GetModule()
        path = str(module.GetFileSpec()) if module.IsValid() else ''
        if path.startswith(('/System/Library/', '/usr/lib/')) or d.read_memory(pc, 4) != b'\x00\x00\x20\xd4':
            return None
        if self.active:
            raise RuntimeError('nested/concurrent self-trap forwarding is unsupported; target remains stopped')
        # Save bytes before the sigaction expression can disturb vector/flag state.
        registers = {}
        names = ['x' + str(i) for i in range(29)] + ['fp', 'lr', 'sp', 'cpsr', 'fpsr', 'fpcr']
        names += ['v' + str(i) for i in range(32)]
        for name in names:
            register = frame.FindRegister(name)
            data = register.GetData()
            if not register.IsValid() or data.GetByteSize() != register.GetByteSize():
                raise RuntimeError('cannot preserve self-trap register ' + name)
            error = lldb.SBError()
            registers[name] = data.ReadRawData(error,0,data.GetByteSize())
            if error.Fail():
                raise RuntimeError('cannot preserve self-trap register ' + name)
        try:
            handler, mask, flags = self._action()
        finally:
            self._restore(thread,registers)
        if handler in (0, 1):
            return None
        if mask or flags & ~2:  # Only SA_RESTART is harmless for a BRK handler.
            raise RuntimeError('self-trap requires a simple handler without siginfo, signal masks, '
                               'alternate stacks or reset/reentrant flags; target remains stopped')
        error = lldb.SBError()
        stack = d.process.AllocateMemory(65536, lldb.ePermissionsReadable | lldb.ePermissionsWritable, error)
        if error.Fail():
            raise RuntimeError('cannot allocate self-trap handler stack')
        try:
            bp = d.create_hardware_breakpoint_by_address(pc + 4)
        except Exception:
            d.process.DeallocateMemory(stack)
            raise
        bp.SetThreadID(thread.GetThreadID())
        top = (stack + 65536 - 16) & ~15
        entry = dict(bp=bp.GetID(), pc=pc + 4, stack=stack, top=top, registers=registers)
        self.active[thread.GetThreadID()] = entry
        for name, value in [('sp', top), ('x0', 5), ('lr', pc + 4), ('pc', handler)]:
            if not frame.FindRegister(name).SetValueFromCString(hex(value)):
                self.error = 'could not enter self-trap handler; restart required'
                raise RuntimeError(self.error)
        d.cont()
        return 'self-trap: entered target SIGTRAP handler {:#x}; context saved'.format(handler)

    def complete(self):
        """Restore before either frontend inspects or dispatches a return stop."""
        d = self.debugger
        thread = d.process.GetSelectedThread()
        entry = self.active.get(thread.GetThreadID())
        if not entry or thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return False
        frame = thread.GetFrameAtIndex(0)
        ids = {thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)}
        if entry['bp'] not in ids or frame.GetPC() != entry['pc']:
            return False
        if frame.FindRegister('sp').GetValueAsUnsigned() != entry['top']:
            raise RuntimeError('self-trap handler did not restore its stack; target remains stopped')
        self._restore(thread,entry['registers'])
        d.delete_breakpoint(entry['bp'])
        d.process.DeallocateMemory(entry['stack'])
        del self.active[thread.GetThreadID()]
        return ids == {entry['bp']}

    def _restore(self, thread, registers):
        # Apple's SBValue.SetData can report success without writing SIMD
        # registers. Use the register interpreter for vectors and verify bytes.
        for name, data in registers.items():
            frame = thread.GetFrameAtIndex(0)
            if name.startswith('v'):
                result = lldb.SBCommandReturnObject()
                literal = '{' + ' '.join('0x{:02x}'.format(b) for b in data) + '}'
                self.debugger.ci.HandleCommand('register write {} "{}"'.format(name,literal), result, False)
                success = result.Succeeded()
            else:
                success = frame.FindRegister(name).SetValueFromCString(hex(int.from_bytes(data,'little')))
            error = lldb.SBError()
            observed = thread.GetFrameAtIndex(0).FindRegister(name).GetData().ReadRawData(error,0,len(data))
            if not success or error.Fail() or observed != data:
                self.error = 'cannot restore self-trap register {}; restart required'.format(name)
                raise RuntimeError(self.error)
