"""In-process OSA execution gates; inspection never calls the script engine."""
import lldb
from .script_payload import ScriptPayloadCapture
from .script_preview import readable_content, ScriptContent


# name: (second argument, flags register, output register, output kind)
OSA_CALLS = {
    "OSAExecute": ("script_id", "x3", "x4", "id"),
    "OSAExecuteEvent": ("event_descriptor", "x3", "x4", "id"),
    "OSALoadExecute": ("script_descriptor", "x3", "x4", "id"),
    "OSACompileExecute": ("source_descriptor", "x3", "x4", "id"),
    "OSADoScript": ("source_descriptor", "x4", "x5", "descriptor"),
    "OSADoEvent": ("event_descriptor", "x3", "x4", "descriptor"),
    "OSADoScriptFile": ("file_reference", "x4", "x5", "descriptor"),
}


class ScriptExec:
    def __init__(self, debugger):
        self.debugger = debugger
        self.payloads = ScriptPayloadCapture(debugger)
        self.reset()

    def reset(self, keep_hooks=False):
        self.payloads.reset(keep_hooks=keep_hooks)
        self.pending = None
        self.allowed = set()
        self.last_error = None

    def _key(self, thread):
        p = self.debugger.process
        return (p.GetProcessID(), p.GetStopID(), thread.GetThreadID(),
                thread.GetFrameAtIndex(0).GetPC())

    def breakpoint_ids(self):
        return {bid for bid, name in (self.debugger.exec_bp_ids or {}).items()
                if name in OSA_CALLS} | self.payloads.hidden_ids()

    def find_hit(self):
        d = self.debugger
        if not d.exec_bp_ids or not d.process or d.process.GetState() != lldb.eStateStopped:
            return None
        prefix = (d.process.GetProcessID(), d.process.GetStopID())
        self.allowed = {k for k in self.allowed if k[:2] == prefix}
        sites = {}
        for bid, name in d.exec_bp_ids.items():
            if name not in OSA_CALLS:
                continue
            bp = d.target.FindBreakpointByID(bid)
            if not bp.IsValid() or not bp.IsEnabled():
                raise RuntimeError('required OSA execution hook is missing or disabled')
            for location in bp:
                if location.IsEnabled() and location.IsResolved():
                    sites[location.GetLoadAddress()] = bid
        for thread in d.process:
            if thread.GetStopReason() not in (lldb.eStopReasonNone, lldb.eStopReasonInvalid,
                                              lldb.eStopReasonBreakpoint, lldb.eStopReasonPlanComplete):
                continue
            frame = thread.GetFrameAtIndex(0)
            if frame.IsValid() and frame.GetPC() in sites and self._key(thread) not in self.allowed:
                d.process.SetSelectedThread(thread)
                return sites[frame.GetPC()]
        return None

    @staticmethod
    def _reg(frame, name):
        value = frame.FindRegister(name)
        if not value.IsValid():
            raise RuntimeError('cannot read OSA argument register ' + name)
        return value.GetValueAsUnsigned()

    def capture(self, bid):
        d = self.debugger
        name = d.exec_bp_ids[bid]
        if self.pending is not None:
            self._validate_pending()
            return self.pending['capture']
        thread = d.process.GetSelectedThread()
        frame = thread.GetFrameAtIndex(0)
        argument, flags, output, kind = OSA_CALLS[name]
        info = {'component': hex(self._reg(frame, 'x0')),
                argument: hex(self._reg(frame, 'x1')),
                'context_id': hex(self._reg(frame, 'x2') & 0xffffffff),
                'mode_flags': hex(self._reg(frame, flags) & 0xffffffff),
                'result_pointer': hex(self._reg(frame, output)),
                'result_kind': kind}
        payload = self.payloads.for_execution(name, frame)
        if payload is not None:
            info['captured_payload'] = payload.summary()
            content = readable_content(payload)
        else:
            content = ScriptContent(note='Payload unavailable: ' + self.payloads.problem + '.')
        view = content.preview()
        description = view['note'] + ('\n\n' + view['text'] if view['text'] else '')
        if view['truncated']:
            description += '\n[Preview truncated; Dump saves the full captured content.]'
        cap = {'sym': name, 'path': None, 'cmd': description, 'argv': None, 'kind': 'osa',
               'script_content': view, 'metadata': info,
               'payload_bytes': len(payload.data) if payload is not None else None}
        self.pending = {'key': self._key(thread), 'capture': cap,
                        'content': content, 'dump': {},
                        'output': self._reg(frame, output), 'kind': kind, 'payload': payload,
                        'payload_error': self.payloads.problem if payload is None else None}
        return cap

    def prompt_details(self):
        self._validate_pending()
        return {'script_content': self.pending['capture']['script_content'],
                'metadata': self.pending['capture']['metadata'], **self.pending['dump']}

    def payload_for_dump(self):
        self._validate_pending()
        payload = self.pending['payload']
        if payload is None:
            raise RuntimeError('No captured script payload: ' + self.pending['payload_error']
                               + '. Only observed script inputs can be dumped; no metadata file was written.')
        return payload

    def _validate_pending(self):
        if not self.pending:
            raise RuntimeError('no pending OSA execution decision')
        d = self.debugger
        key = self.pending['key']
        thread = d.process.GetThreadByID(key[2])
        if not thread.IsValid() or self._key(thread) != key:
            raise RuntimeError('OSA execution context changed; restart or inspect the target')
        d.process.SetSelectedThread(thread)
        return thread.GetFrameAtIndex(0)

    def resolve(self, decision):
        frame = self._validate_pending()
        d = self.debugger
        thread = d.process.GetThreadByID(self.pending['key'][2])
        if decision == 'allow':
            self.allowed.add(self.pending['key'])
            self.pending = None
            return
        # Hooks stop at the first instruction, before any prologue executes.
        # Returning by PC avoids evaluating target-side expressions or unwinding
        # a frame that has not been established yet.
        pc, result = frame.GetPC(), self._reg(frame, 'x0')
        caller = self._reg(frame, 'lr')
        if not caller or caller % 4 or len(d.read_memory(caller, 4)) != 4:
            raise RuntimeError('cannot validate OSA return address')
        output, previous = self.pending['output'], None
        if decision == 'fake':
            # AEDesc uses mac68k packing: 4-byte type + 8-byte data handle.
            data = (bytes(4) if self.pending['kind'] == 'id'
                    else (0x6e756c6c).to_bytes(4, 'little') + bytes(8))
            previous = d.read_memory(output, len(data)) if output else b''
            if len(previous) != len(data):
                raise RuntimeError('cannot preserve OSA output; execution remains stopped')
            ok, error = d.write_memory(output, data, track=False)
            if not ok:
                restored, _ = d.write_memory(output, previous, track=False)
                self.last_error = 'cannot write OSA empty result: ' + error
                if not restored:
                    self.last_error += '; rollback failed'
                raise RuntimeError(self.last_error)
        value = 0 if decision == 'fake' else ((-128) & ((1 << 64) - 1))
        if (not thread.GetFrameAtIndex(0).FindRegister('x0').SetValueFromCString(hex(value))
                or self._reg(thread.GetFrameAtIndex(0), 'x0') != value
                or not thread.GetFrameAtIndex(0).SetPC(caller)
                or thread.GetFrameAtIndex(0).GetPC() != caller):
            rollback = thread.GetFrameAtIndex(0).FindRegister('x0').SetValueFromCString(hex(result))
            rollback = thread.GetFrameAtIndex(0).SetPC(pc) and rollback
            if previous is not None:
                rollback = d.write_memory(output, previous, track=False)[0] and rollback
            self.last_error = 'cannot return from OSA execution gate'
            if not rollback:
                self.last_error += '; rollback failed'
            raise RuntimeError(self.last_error)
        self.pending = None

    def require_ready(self):
        if self.last_error:
            raise RuntimeError(self.last_error)
        if self.pending or self.find_hit() is not None:
            raise RuntimeError('OSA execution requires an exec sandbox decision before resuming')
