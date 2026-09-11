"""Capture OSA input bytes through public API observations, without engine calls."""
from collections import OrderedDict
from dataclasses import dataclass
import hashlib

import lldb

from .breakpoints import remember_hardware_return


TYPES = {
    0x73637074: ('compiled OSA', '.scpt'),
    0x75746638: ('UTF-8 source', '.applescript.txt'),
    0x75747874: ('Unicode source', '.utf16.bin'),
    0x75743136: ('external UTF-16 source', '.utf16.bin'),
    0x54455854: ('legacy text source', '.text.bin'),
}
OBSERVERS = {
    **{name: 'AE' for name in ('AECreateDesc', 'AEReplaceDescData',
                              'AEDuplicateDesc', 'AEDisposeDesc')},
    **{name: 'OpenScripting' for name in ('OSALoad', 'OSACompile', 'OSACopyID',
                                        'OSACopyScript', 'OSADispose')},
    'CloseComponent': 'CarbonCore',
}


@dataclass(frozen=True)
class Payload:
    descriptor_type: int
    data: bytes
    origin: str

    @property
    def suffix(self):
        return TYPES[self.descriptor_type][1]

    def summary(self):
        return {'kind': TYPES[self.descriptor_type][0], 'bytes': len(self.data),
                'sha256': hashlib.sha256(self.data).hexdigest(), 'origin': self.origin}


class ScriptPayloadCapture:
    MAX_PAYLOAD = 4 * 1024 * 1024
    MAX_CACHE = 32 * 1024 * 1024
    MAX_ENTRIES = 128
    MAX_RETURNS = 8

    def __init__(self, debugger):
        self.debugger = debugger
        self.entries = {}
        self.returns = {}
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.epoch = 0
        self.seen = set()
        self.retired = set()
        self.stop_key = None
        self.problem = 'enable the sandbox before descriptor creation and script loading'

    def hidden_ids(self):
        return set(self.entries) | set(self.returns) | self.retired

    def _delete(self, bid):
        d = self.debugger
        if d.target:
            deleted = d.target.BreakpointDelete(bid)
            if not deleted and d.target.FindBreakpointByID(bid).IsValid():
                raise RuntimeError('cannot remove script payload observer')
        getattr(d, 'hardware_bp_ids', set()).discard(bid)

    def reset(self, keep_hooks=False):
        for bid in list(self.returns):
            self._delete(bid)
        self.returns.clear()
        if not keep_hooks:
            for bid in self.entries:
                self._delete(bid)
            self.entries.clear()
        self.cache.clear()
        self.cache_bytes = 0
        self.epoch += 1
        self.seen.clear()
        self.retired.clear()
        self.stop_key = None
        self.problem = 'no observed input for this script; enable the sandbox before loading it'

    def enable(self):
        if self.entries:
            return
        d = self.debugger
        try:
            for name, module in OBSERVERS.items():
                before = {bp.GetID() for bp in d.target.breakpoint_iter()}
                result = lldb.SBCommandReturnObject()
                d.ci.HandleCommand('breakpoint set --name {} --shlib {} --skip-prologue false'.format(name, module), result, False)
                created = [bp for bp in d.target.breakpoint_iter() if bp.GetID() not in before]
                if not result.Succeeded() or len(created) != 1 or not created[0].IsValid():
                    for bp in created:
                        self._delete(bp.GetID())
                    raise RuntimeError('cannot arm script payload observer ' + name)
                self.entries[created[0].GetID()] = name
        except Exception:
            self.reset()
            raise

    def _invalidate(self, reason):
        self.cache.clear()
        self.cache_bytes = 0
        self.epoch += 1
        self.problem = reason

    def _forget(self, key):
        old = self.cache.pop(key, None)
        if old is not None:
            self.cache_bytes -= len(old.data)

    def _store(self, key, payload):
        self._forget(key)
        if payload is None:
            return
        self.cache[key] = payload
        self.cache_bytes += len(payload.data)
        while len(self.cache) > self.MAX_ENTRIES or self.cache_bytes > self.MAX_CACHE:
            _, old = self.cache.popitem(last=False)
            self.cache_bytes -= len(old.data)
            self.problem = 'payload capture cache was exhausted; restart with fewer concurrent scripts'

    def _get(self, key):
        item = self.cache.get(key)
        if item is not None:
            self.cache.move_to_end(key)
        return item

    @staticmethod
    def _reg(frame, name):
        value = frame.FindRegister(name)
        if not value.IsValid():
            raise RuntimeError('cannot read payload capture register ' + name)
        return value.GetValueAsUnsigned()

    def _read(self, address, size):
        data = self.debugger.read_memory(address, size) if size else b''
        if len(data) != size:
            raise RuntimeError('script input memory is unreadable')
        return data

    def _descriptor(self, address):
        data = self._read(address, 12)
        kind = int.from_bytes(data[:4], 'little')
        handle = int.from_bytes(data[4:], 'little')
        return (kind, handle) if kind in TYPES else None

    def _forget_descriptor(self, address, all_aliases=False):
        identity = self._descriptor(address) if all_aliases and address else None
        for key in list(self.cache):
            if key[0] == 'desc' and (key[1] == address or
                                     (identity is not None and key[2:] == identity)):
                self._forget(key)

    def _desc_payload(self, address):
        identity = self._descriptor(address)
        if identity is None:
            return None
        key = ('desc', address) + identity
        payload = self._get(key)
        if payload is not None:
            return payload
        # Descriptor structs may be copied while their data handles are shared.
        # Only borrow from a tracked owner whose header is still live and equal.
        for owner in list(self.cache):
            if owner[0] != 'desc' or owner[2:] != identity:
                continue
            try:
                current = self._descriptor(owner[1])
            except RuntimeError:
                current = None
            if current != identity:
                self._forget(owner)
                continue
            payload = self._get(owner)
            self._store(key, payload)
            return payload
        return None

    def _valid(self):
        if not self.entries:
            return False
        for bid in self.entries:
            bp = self.debugger.target.FindBreakpointByID(bid)
            if not bp.IsValid() or not bp.IsEnabled():
                self.reset()
                self.problem = 'a payload observer was removed or disabled; restart and re-enable the sandbox'
                return False
        for bid in list(self.returns):
            bp = self.debugger.target.FindBreakpointByID(bid)
            if (not bp.IsValid() or not bp.IsEnabled()
                    or bp.GetNumLocations() == 0 or not all(loc.IsResolved() for loc in bp)):
                self._delete(bid)
                del self.returns[bid]
                self._invalidate('a script input return observer was lost')
        return True

    def for_execution(self, name, frame):
        if not self._valid():
            return None
        try:
            component = self._reg(frame, 'x0')
            if name == 'OSAExecute':
                return self._get(('script', component, self._reg(frame, 'x1') & 0xffffffff))
            if name in ('OSAExecuteEvent', 'OSADoEvent'):
                return self._get(('script', component, self._reg(frame, 'x2') & 0xffffffff))
            if name in ('OSALoadExecute', 'OSACompileExecute', 'OSADoScript'):
                return self._desc_payload(self._reg(frame, 'x1'))
            self.problem = 'file-reference-only script loading was not captured'
        except RuntimeError as error:
            self._invalidate(str(error))
        return None

    def _arm(self, thread, job):
        if len(self.returns) >= self.MAX_RETURNS:
            raise RuntimeError('too many concurrent script payload operations')
        d = self.debugger
        frame = thread.GetFrameAtIndex(0)
        address = self._reg(frame, 'lr')
        if not address:
            raise RuntimeError('script input operation has no return address')
        main = d.target.FindModule(d.target.GetExecutable())
        module = d.target.ResolveLoadAddress(address).GetModule()
        # Preserve executable text; system-library return sites can use software.
        bp = (d.create_hardware_breakpoint_by_address(address)
              if not module.IsValid() or module == main
              else d.target.BreakpointCreateByAddress(address))
        if (not bp.IsValid() or not bp.GetNumLocations()
                or not all(bp.GetLocationAtIndex(i).IsResolved() for i in range(bp.GetNumLocations()))):
            if bp.IsValid():
                self._delete(bp.GetID())
            raise RuntimeError('cannot arm script input return observer')
        bp.SetThreadID(thread.GetThreadID())
        job.update(thread=thread.GetThreadID(), address=address,
                   sp=self._reg(frame, 'sp'), epoch=self.epoch)
        self.returns[bp.GetID()] = job

    def _entry(self, thread, name):
        frame = thread.GetFrameAtIndex(0)
        reg = lambda n: self._reg(frame, 'x' + str(n))
        if name == 'AEDisposeDesc':
            self._forget_descriptor(reg(0))
            return
        if name == 'OSADispose':
            self._forget(('script', reg(0), reg(1) & 0xffffffff))
            return
        if name == 'CloseComponent':
            component = reg(0)
            for key in list(self.cache):
                if key[:2] == ('script', component):
                    self._forget(key)
            return
        if name in ('AECreateDesc', 'AEReplaceDescData'):
            output = reg(3)
            self._forget_descriptor(output, all_aliases=name == 'AEReplaceDescData')
            kind, size = reg(0) & 0xffffffff, reg(2)
            if kind not in TYPES:
                return
            if size > self.MAX_PAYLOAD:
                raise RuntimeError('script input exceeds the 4 MiB capture limit')
            payload = Payload(kind, self._read(reg(1), size), name)
            job = {'kind': 'desc', 'output': output, 'payload': payload,
                   'expected_type': kind}
        elif name == 'AEDuplicateDesc':
            key = self._descriptor(reg(0))
            if key is None:
                return
            payload = self._desc_payload(reg(0))
            self._forget_descriptor(reg(1))
            job = {'kind': 'desc', 'output': reg(1), 'payload': payload}
        elif name in ('OSALoad', 'OSACompile'):
            component, output = reg(0), reg(3)
            payload = self._desc_payload(reg(1))
            if name == 'OSACompile':
                previous = int.from_bytes(self._read(output, 4), 'little')
                self._forget(('script', component, previous))
                if reg(2) & 4:  # kOSAModeAugmentContext does not describe a complete script.
                    payload = None
                    self.problem = 'an augmented script context has no complete captured input'
            job = {'kind': 'script', 'component': component,
                   'output': output, 'payload': payload}
        elif name in ('OSACopyID', 'OSACopyScript'):
            component = reg(0)
            job = {'kind': 'script', 'component': component, 'output': reg(2),
                   'payload': self._get(('script', component, reg(1) & 0xffffffff))}
        else:
            return
        self._arm(thread, job)

    def _returned(self, job, result):
        if result & 0xffffffff or job['epoch'] != self.epoch:
            return
        if job['kind'] == 'desc':
            key = self._descriptor(job['output'])
            if key is not None and key[0] == job.get('expected_type', key[0]):
                self._store(('desc', job['output']) + key, job['payload'])
        else:
            value = int.from_bytes(self._read(job['output'], 4), 'little')
            if value:
                self._store(('script', job['component'], value), job['payload'])

    def apply_stop(self):
        d = self.debugger
        if not self.entries or not d.process or d.process.GetState() != lldb.eStateStopped:
            return False
        if not self._valid():
            return False
        key = (d.process.GetProcessID(), d.process.GetStopID())
        if key != self.stop_key:
            self.seen.clear()
            self.retired.clear()
            self.stop_key = key
        hidden = self.hidden_ids()
        matched, foreign = False, False
        for thread in d.process:
            reason = thread.GetStopReason()
            ids = ({thread.GetStopReasonDataAtIndex(i)
                    for i in range(0, thread.GetStopReasonDataCount(), 2)}
                   if reason == lldb.eStopReasonBreakpoint else set())
            foreign |= bool(ids - hidden) or reason not in (
                lldb.eStopReasonNone, lldb.eStopReasonInvalid, lldb.eStopReasonBreakpoint)
            if reason not in (lldb.eStopReasonNone, lldb.eStopReasonInvalid,
                              lldb.eStopReasonBreakpoint, lldb.eStopReasonPlanComplete):
                continue
            frame = thread.GetFrameAtIndex(0)
            if not frame.IsValid():
                continue
            pc, tid = frame.GetPC(), thread.GetThreadID()
            for bid, job in list(self.returns.items()):
                if job['thread'] != tid or job['address'] != pc:
                    continue
                matched = True
                if self._reg(frame, 'sp') != job['sp']:
                    continue
                result = self._reg(frame, 'x0')
                d.process.SetSelectedThread(thread)
                remember_hardware_return(d, bid)
                self._delete(bid)
                del self.returns[bid]
                self.retired.add(bid)
                try:
                    self._returned(job, result)
                except RuntimeError as error:
                    self._invalidate(str(error))
            for bid, name in self.entries.items():
                bp = d.target.FindBreakpointByID(bid)
                if not any(loc.IsEnabled() and loc.IsResolved() and loc.GetLoadAddress() == pc for loc in bp):
                    continue
                matched = True
                token = (tid, bid)
                if token in self.seen:
                    continue
                self.seen.add(token)
                try:
                    self._entry(thread, name)
                except RuntimeError as error:
                    self._invalidate(str(error))
        return matched and not foreign
