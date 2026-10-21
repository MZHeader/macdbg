"""Bounded memory snapshots, executable-map observations and execution guards."""
from collections import OrderedDict
import hashlib
import os
import re
import uuid

import lldb

from .return_hooks import ReturnHooks


def strings(data, base=0):
    return [{'addr':hex(base+m.start()), 'text':m.group().decode('ascii')}
            for m in re.finditer(rb'[\x20-\x7e]{5,}', data)][:4096]


class MemoryAnalysis:
    HOOKS = ('mprotect', 'mach_vm_protect', 'vm_protect', 'mmap', 'dlopen')
    SNAPSHOT_LIMIT = 1024 * 1024
    SCAN_LIMIT = 8 * 1024 * 1024

    def __init__(self, debugger):
        self.debugger = debugger
        self.enabled = False
        self.hooks = {}
        self.returns = ReturnHooks(debugger)
        self.snapshots = OrderedDict()
        self.sequence = 0
        self.epoch = uuid.uuid4().hex[:12]
        self.previous = {}
        self.guard = None
        self.guard_stop = None
        self.coverage = 'off'
        self._observed = None

    def hidden_ids(self):
        return set(self.hooks) | self.returns.ids() | self.returns.retired

    def regions(self):
        d = self.debugger
        if not d.process or d.process.GetState() != lldb.eStateStopped:
            raise ValueError('pause the target to inspect its memory map')
        regions = d.process.GetMemoryRegions()
        rows = []
        for index in range(min(regions.GetSize(), 16384)):
            info = lldb.SBMemoryRegionInfo()
            if not regions.GetMemoryRegionAtIndex(index, info) or not info.IsMapped():
                continue
            base, end = info.GetRegionBase(), info.GetRegionEnd()
            module = d.target.ResolveLoadAddress(base).GetModule()
            name = str(module.GetFileSpec()) if module.IsValid() else (info.GetName() or '')
            protection = (1 if info.IsReadable() else 0) | (2 if info.IsWritable() else 0) | (4 if info.IsExecutable() else 0)
            rows.append({'base':base, 'end':end, 'size':end-base, 'protection':protection,
                         'permissions':''.join(letter if protection & bit else '-' for bit,letter in [(1,'r'),(2,'w'),(4,'x')]),
                         'name':name})
        return rows

    def capture(self, address, size, label='snapshot'):
        if not 0 < size <= self.SNAPSHOT_LIMIT or address < 0 or address + size >= 1 << 64:
            raise ValueError('snapshot size must be between 1 byte and 1 MiB at a valid address')
        if not self.debugger.process or self.debugger.process.GetState() != lldb.eStateStopped:
            raise ValueError('pause the target before capturing memory')
        data = self.debugger.read_memory(address, size)
        if not data:
            raise ValueError('snapshot memory is unreadable')
        self.sequence += 1
        record = {'id':self.sequence, 'addr':address, 'size':len(data), 'requested':size,
                  'label':str(label)[:100], 'data':data, 'strings':strings(data,address)}
        self.snapshots[self.sequence] = record
        while len(self.snapshots) > 8:
            self.snapshots.popitem(last=False)
        return self.summary(record)

    @staticmethod
    def summary(record):
        return {key:value for key,value in record.items() if key != 'data'}

    def compare(self, snapshot_id):
        if not self.debugger.process or self.debugger.process.GetState() != lldb.eStateStopped:
            raise ValueError('pause the target before comparing memory')
        old = self.snapshots.get(snapshot_id)
        if old is None:
            raise ValueError('snapshot expired or does not exist')
        new = self.debugger.read_memory(old['addr'], old['size'])
        changes, changed = [], 0
        for offset in range(0, max(len(new),len(old['data'])), 16):
            before, after = old['data'][offset:offset+16], new[offset:offset+16]
            changed += sum(a != b for a,b in zip(before,after)) + abs(len(before)-len(after))
            if before != after and len(changes) < 512:
                changes.append({'addr':hex(old['addr']+offset), 'before':before.hex(' '), 'after':after.hex(' ')})
        before = {(s['addr'],s['text']) for s in old['strings']}
        after = {(s['addr'],s['text']) for s in strings(new,old['addr'])}
        return {'id':snapshot_id, 'changed_bytes':changed, 'changes':changes,
                'complete':len(new)==old['size'], 'display_limit':512,
                'strings_added':[{'addr':a,'text':t} for a,t in sorted(after-before)],
                'strings_removed':[{'addr':a,'text':t} for a,t in sorted(before-after)]}

    def enable(self):
        if self.enabled:
            return
        d = self.debugger
        self.observe(baseline=True)
        try:
            for name in self.HOOKS:
                before = {bp.GetID() for bp in d.target.breakpoint_iter()}
                result = lldb.SBCommandReturnObject()
                d.ci.HandleCommand('breakpoint set --skip-prologue false -F ' + name, result, False)
                created = [bp for bp in d.target.breakpoint_iter() if bp.GetID() not in before]
                for bp in created:
                    self.hooks[bp.GetID()] = name
                if not result.Succeeded() or len(created) != 1:
                    raise RuntimeError('cannot monitor ' + name)
            self.enabled = True
        except Exception:
            self.disable()
            raise

    def disable(self):
        self.disarm_guard()
        self.returns.clear()
        if self.debugger.target:
            for bid in self.hooks:
                self.debugger.delete_breakpoint(bid)
        self.hooks.clear()
        self.enabled = False

    def reset(self):
        self.disable()
        self.snapshots.clear()
        self.previous.clear()
        self.guard_stop = None
        self._observed = None

    def observe(self, baseline=False):
        d = self.debugger
        budget = self.SCAN_LIMIT
        current = {}
        for row in self.regions():
            if row['protection'] & 5 != 5 or row['name'].startswith(('/System/','/usr/lib/')):
                continue
            size = min(row['size'], 256*1024, budget)
            if size <= 0:
                break
            data = d.read_memory(row['base'],size)
            budget -= size
            digest = hashlib.sha256(data).hexdigest()
            old = self.previous.get(row['base'])
            current[row['base']] = (digest, row['protection'], data)
            complete = len(data) == size
            # A shorter debugger read is reduced visibility, not proof that
            # code changed. Keep the last baseline until comparable bytes return.
            if old is not None and not complete:
                current[row['base']] = (old[0],row['protection'],old[2])
            changed = old is not None and (old[1] != row['protection'] or
                (complete and len(old[2]) == size and old[0] != digest))
            if not baseline and (old is None or changed):
                kind = 'new executable region' if old is None else 'executable memory changed'
                snapshot = self.capture(row['base'],size,kind)
                directory = d._dumps_dir()
                os.makedirs(directory, exist_ok=True)
                path = os.path.join(directory,'code-{}-{}-{:x}.bin'.format(self.epoch,snapshot['id'],row['base']))
                with open(path,'wb') as file:
                    file.write(data)
                details = {'pc':row['base'], 'region':row, 'snapshot':snapshot['id'],
                           'path':path, 'captured_bytes':len(data), 'truncated':len(data)<row['size']}
                if old is not None:
                    previous_path = path + '.before'
                    with open(previous_path,'wb') as file:
                        file.write(old[2])
                    details['previous_path'] = previous_path
                d.record_event('MEMORY',kind,**details)
        self.previous = current
        self.coverage = ('readable executable regions outside system libraries; first 256 KiB per region, '
                         '8 MiB per scan; API returns and debugger stops; inline syscalls observed at next stop')

    def _protect(self, region, protection):
        result = lldb.SBCommandReturnObject()
        self.debugger.ci.HandleCommand('expression -l c++ --ignore-breakpoints true -- '
            '((int(*)(void*,unsigned long,int))mprotect)((void*){:#x}, {}, {})'.format(
                region['base'],region['size'],protection),result,False)
        if not result.Succeeded() or not (result.GetOutput() or '').strip().endswith('= 0'):
            raise RuntimeError('could not change execution-guard protection: ' + (result.GetError() or result.GetOutput() or ''))

    def arm_guard(self, address):
        if self.guard:
            raise ValueError('disarm the existing execution guard first')
        region = next((r for r in self.regions() if r['base'] <= address < r['end']), None)
        if not region or not region['protection'] & 4:
            raise ValueError('select an executable memory region')
        if region['size'] > 16*1024*1024:
            raise ValueError('execution guards are limited to regions of at most 16 MiB')
        for thread in self.debugger.process:
            if region['base'] <= thread.GetFrameAtIndex(0).GetPC() < region['end']:
                raise ValueError('cannot guard a region containing a stopped thread PC')
        self._protect(region, region['protection'] & ~4)
        self.guard = region
        self.debugger.record_event('MEMORY','execution guard armed; execute permission temporarily removed',pc=address,region=region)
        return dict(region)

    def disarm_guard(self):
        if self.guard and self.debugger.process:
            process = self.debugger.process
            if process.GetState() == lldb.eStateRunning:
                import time
                error = process.Stop()
                deadline = time.monotonic()+2
                while process.GetState() == lldb.eStateRunning and time.monotonic() < deadline:
                    time.sleep(.01)
                if error.Fail() or process.GetState() == lldb.eStateRunning:
                    raise RuntimeError('cannot restore execution guard while target is running')
            if process.GetState() == lldb.eStateStopped:
                self._protect(self.guard,self.guard['protection'])
        self.guard = None

    def apply_stop(self):
        d = self.debugger
        thread = d.process.GetSelectedThread()
        frame = thread.GetFrameAtIndex(0)
        pc = frame.GetPC()
        if (self.guard and thread.GetStopReason() == lldb.eStopReasonException
                and self.guard['base'] <= pc < self.guard['end']
                and (thread.GetStopDescription(256) or '').startswith('EXC_BAD_ACCESS')):
            current = lldb.SBMemoryRegionInfo()
            error = d.process.GetMemoryRegionInfo(pc,current)
            if error.Fail() or current.IsExecutable():
                # Someone changed the mapping after arming. Preserve the real
                # fault instead of attributing it to a guard that no longer owns it.
                self.guard = None
                d.record_event('MEMORY','execution guard invalidated by a mapping change',pc=pc)
                return 'visible'
            region = self.guard
            self.disarm_guard()
            self.guard_stop = (d.process.GetProcessID(),d.process.GetStopID(),pc)
            d.record_event('MEMORY','first execution in guarded region',pc=pc,region=region)
            return 'visible'
        if not self.enabled:
            return None
        key = (d.process.GetProcessID(), d.process.GetStopID())
        if key != self._observed:
            self._observed = key
            self.observe()
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
            return None
        ids = {thread.GetStopReasonDataAtIndex(i) for i in range(0,thread.GetStopReasonDataCount(),2)}
        owned = set(self.hooks) | self.returns.ids()
        completed = self.returns.consume(thread)
        for record in completed:
            d.record_event('MEMORY',record['payload']['name'] + ' returned',
                return_value=frame.FindRegister('x0').GetValue(), arguments=record['payload']['arguments'])
        bid = next((bid for bid in ids if bid in self.hooks),None)
        if bid is not None:
            arguments = {name:frame.FindRegister(name).GetValue() for name in ('x0','x1','x2','x3','x4')}
            try:
                self.returns.arm(frame, {'name':self.hooks[bid],'arguments':arguments})
            except RuntimeError as error:
                d.record_event('MEMORY','return observation unavailable: '+str(error),arguments=arguments)
                return 'visible'
        return 'internal' if ids and ids <= owned else None

    def status(self):
        return {'enabled':self.enabled, 'coverage':self.coverage, 'guard':self.guard,
                'snapshots':[{key:value for key,value in self.summary(s).items() if key != 'strings'} for s in self.snapshots.values()]}
