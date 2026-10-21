"""Read-only ARM64 instruction context and bounded code navigation."""
import re
import os

import lldb

from .disasm import DisasmRow, _branch_target, _evaluate_condition, _parse_adrp_imm, _first_hex_addr
from .code_flow import reference_candidates

INDIRECT = {'br', 'blr', 'braa', 'brab', 'braaz', 'brabz', 'blraa', 'blrab', 'blraaz', 'blrabz'}
CONDITIONAL = {'cbz', 'cbnz', 'tbz', 'tbnz'}


def branch_kind(mnemonic):
    if mnemonic in INDIRECT and mnemonic.startswith('bl'):
        return 'call'
    if mnemonic == 'b' or mnemonic in INDIRECT or mnemonic.startswith('ret'):
        return 'terminal'
    if mnemonic.startswith('b.') or mnemonic in CONDITIONAL:
        return 'conditional'
    return None


def blocks_for(rows, observed=()):
    """Build decoded basic blocks; unresolved indirect edges remain explicit."""
    if not rows:
        return [], []
    addresses = {r['addr'] for r in rows}
    leaders = {rows[0]['addr']}
    for row in rows:
        if branch_kind(row['mn']):
            target = _branch_target(row['ops'])
            if target in addresses:
                leaders.add(target)
            if row['addr'] + 4 in addresses:
                leaders.add(row['addr'] + 4)
    blocks, current = [], None
    for row in rows:
        if row['addr'] in leaders:
            current = {'addr':row['addr'], 'instructions':[]}
            blocks.append(current)
        current['instructions'].append(row)
    edges = []
    for block in blocks:
        last = block['instructions'][-1]
        kind, target = branch_kind(last['mn']), _branch_target(last['ops'])
        if last['mn'] == 'b' or kind == 'conditional':
            edges.append({'from':block['addr'], 'to':target, 'kind':'taken' if kind == 'conditional' else 'jump', 'source':'decoded'})
        elif last['mn'] in INDIRECT:
            targets = [dst for src,dst in observed if src == last['addr']]
            for dst in targets:
                edges.append({'from':block['addr'], 'to':dst, 'kind':'indirect', 'source':'observed single step'})
            if not targets:
                edges.append({'from':block['addr'], 'to':None, 'kind':'indirect', 'source':'unresolved'})
        if kind != 'terminal' and last['addr'] + 4 in addresses:
            edges.append({'from':block['addr'], 'to':last['addr']+4, 'kind':'fallthrough', 'source':'decoded'})
    return blocks, edges


class CodeNavigation:
    def __init__(self, debugger):
        self.dbg = debugger
        self.observed = set()
        self.observed_code = {}
        self._step = None
        self._pid = None

    def sync(self):
        pid = self.dbg.process.GetProcessID() if self.dbg.process else None
        if pid != self._pid:
            self._pid, self._step = pid, None
            self.observed.clear()
            self.observed_code.clear()

    def instructions(self, address, count):
        target = self.dbg.target
        instructions = target.ReadInstructions(lldb.SBAddress(address,target), min(count,16384))
        return [{'addr':i.GetAddress().GetLoadAddress(target), 'mn':i.GetMnemonic(target) or '',
                 'ops':i.GetOperands(target) or '', 'comment':i.GetComment(target) or ''} for i in instructions]

    def preview(self, address):
        symbol = self.dbg.target.ResolveLoadAddress(address).GetSymbol()
        if symbol.IsValid() and symbol.GetName():
            start = symbol.GetStartAddress().GetLoadAddress(self.dbg.target)
            return '{}+{:#x}'.format(symbol.GetName(),address-start)
        data = self.dbg.read_memory(address,64)
        text = data.split(b'\0',1)[0]
        return repr(text.decode('ascii')) if len(text) >= 4 and all(32 <= b < 127 for b in text) else ''

    def info(self, address):
        rows = self.instructions(address,1)
        if not rows:
            return {'addr':address, 'lines':['Instruction unavailable'], 'links':[]}
        row, d = rows[0], self.dbg
        frame = d.frame()
        live = bool(frame and frame.IsValid() and address == frame.GetPC() and d.process.GetState() == lldb.eStateStopped)
        lines, links = [], []
        target = _branch_target(row['ops']) if row['mn'] in ('b','bl') or branch_kind(row['mn']) == 'conditional' else None
        if target is not None:
            links.append({'addr':target,'label':self.preview(target) or hex(target)})
        if not live:
            return {**row, 'live':False, 'lines':['Static selection — register-dependent values are shown only at the current PC.'], 'links':links}
        def reg(name):
            if name in ('xzr','wzr'):
                return 0
            value = frame.FindRegister(name)
            return value.GetValueAsUnsigned() if value.IsValid() else None
        if branch_kind(row['mn']) == 'conditional':
            taken = _evaluate_condition(DisasmRow(address,b'',row['mn'],row['ops'],'',True),frame)
            lines.append('Branch: ' + ('taken' if taken else 'not taken') if taken is not None else 'Branch outcome unavailable')
            names = re.findall(r'\b[wx]\d+\b',row['ops']) or ['cpsr']
            lines += ['{} = {}'.format(name,hex(reg(name))) for name in names if reg(name) is not None]
        match = re.search(r'\[(x\d+|sp|fp|lr)([^\]]*)\]',row['ops'])
        if match and row['mn'].startswith(('ld','st')):
            base, rest = reg(match[1]), match[2].strip().lstrip(',').strip()
            offset = 0
            known = base is not None
            if rest:
                immediate = re.fullmatch(r'#?(-?(?:0x[\da-fA-F]+|\d+))',rest)
                index = re.fullmatch(r'([wx]\d+)(?:,\s*(lsl|uxtw|sxtw|sxtx)\s*#?(\d+))?',rest)
                if immediate:
                    offset = int(immediate[1],0)
                elif index and reg(index[1]) is not None:
                    offset = reg(index[1])
                    if index[2] in ('sxtw','sxtx'):
                        bits = 32 if index[2] == 'sxtw' else 64
                        offset = (offset & ((1 << bits)-1)) - ((1 << bits) if offset & (1 << (bits-1)) else 0)
                    offset <<= int(index[3] or 0)
                else:
                    known = False
            if known:
                effective = (base+offset) & ((1 << 64)-1)
                first = row['ops'].split(',')[0].strip()
                width = 16 if first.startswith('q') else 8 if first.startswith(('x','d')) else 4
                if row['mn'].endswith('b'): width = 1
                elif row['mn'].endswith('h'): width = 2
                elif row['mn'] in ('ldrsw','ldursw'): width = 4
                if row['mn'].startswith(('ldp','stp')): width *= 2
                data = d.read_memory(effective,width)
                lines.append('Effective address: {:#x} · {} bytes{}'.format(effective,width,' · before store' if row['mn'].startswith('st') else ''))
                lines.append('Memory: ' + (data.hex(' ') if data else 'unreadable'))
                if 0 < len(data) <= 8:
                    value = int.from_bytes(data,'little')
                    lines.append('Value: {:#x} {}'.format(value,self.preview(value)))
                links.append({'addr':effective,'label':'Effective address','pane':'memory'})
            else:
                lines.append('Addressing mode not decoded; raw operands shown.')
        if row['mn'] in INDIRECT:
            operand = row['ops'].split(',')[0].strip()
            value = reg(operand)
            if value is not None:
                lines.append('Live {} = {:#x} (register value; not an observed edge)'.format(operand,value))
                links.append({'addr':value,'label':'Indirect target register'})
        if row['mn'] in ('bl','blr','blraa','blrab','blraaz','blrabz'):
            name = row['comment'] or (self.preview(target) if target else '')
            lines.append('Call: '+(name or 'indirect / unknown signature'))
            signature = next((key for key in ('openat','open','read','write','mprotect','ptrace','strcmp','memcmp','memcpy','objc_msgSend') if re.search(r'\b'+key+r'\b',name)),None)
            labels = {'open':['path','flags'], 'openat':['dirfd','path','flags'], 'read':['fd','buffer','length'],
                      'write':['fd','buffer','length'], 'mprotect':['address','length','protection'],
                      'ptrace':['request','pid','address','data'], 'strcmp':['left','right'],
                      'memcmp':['left','right','length'], 'memcpy':['destination','source','length'],
                      'objc_msgSend':['receiver','selector']}.get(signature,['argument '+str(i) for i in range(8)])
            for index,label in enumerate(labels):
                value = reg('x'+str(index))
                if value is not None:
                    lines.append('{} (x{}) = {:#x} {}'.format(label,index,value,self.preview(value)))
                    if label=='flags' and signature in ('open','openat'):
                        access = {os.O_RDONLY:'O_RDONLY',os.O_WRONLY:'O_WRONLY',os.O_RDWR:'O_RDWR'}.get(value & os.O_ACCMODE,'unknown access')
                        names = [access]+[key for key in ('O_CREAT','O_TRUNC','O_APPEND','O_EXCL','O_NONBLOCK') if value & getattr(os,key)]
                        lines.append('Open flags: '+' | '.join(names))
            lines.append('Known API argument labels' if signature else 'Raw ARM64 argument registers; signature unknown')
        return {**row,'live':True,'lines':lines or ['No additional dynamic information for this instruction.'],'links':links}

    def arm_observation(self):
        self.sync()
        frame = self.dbg.frame()
        rows = self.instructions(frame.GetPC(),1) if frame else []
        if rows and rows[0]['mn'] in INDIRECT:
            self._step = (self.dbg.process.GetStopID(),frame.GetThread().GetThreadID(),frame.GetPC(), self.dbg.read_memory(frame.GetPC(),4))
        else:
            self._step = None

    def observe_stop(self):
        self.sync()
        previous, self._step = self._step, None
        if not previous: return
        thread = self.dbg.process.GetSelectedThread()
        if (self.dbg.process.GetStopID() == previous[0]+1 and thread.GetThreadID() == previous[1]
                and thread.GetStopReason() in (lldb.eStopReasonPlanComplete,lldb.eStopReasonTrace)):
            if len(self.observed) < 4096:
                self.observed.add((previous[2],thread.GetFrameAtIndex(0).GetPC()))
                self.observed_code[(previous[2],thread.GetFrameAtIndex(0).GetPC())] = previous[3]

    def graph(self,address,limit=1024,offset=0):
        self.sync()
        target = self.dbg.target
        resolved = target.ResolveLoadAddress(address)
        item = resolved.GetFunction()
        if not item.IsValid(): item = resolved.GetSymbol()
        start = item.GetStartAddress().GetLoadAddress(target) if item.IsValid() else address
        end = item.GetEndAddress().GetLoadAddress(target) if item.IsValid() else start+1024
        known = start <= address < end and end != lldb.LLDB_INVALID_ADDRESS
        if not known: start,end = address,address+1024
        limit, offset = int(limit), int(offset)
        if not 16 <= limit <= 16384 or offset < 0 or offset % 4: raise ValueError('Invalid graph range')
        if not known: end = start + limit*4
        if start+offset >= end: raise ValueError('Graph offset is outside the function')
        count = min((end-start-offset)//4,limit)
        rows = self.instructions(start+offset,count)
        recorder = getattr(self.dbg, 'instruction_trace', None)
        trace_edges = set()
        visited = {}
        row_addresses = {r['addr'] for r in rows}
        if recorder and not recorder.readonly and recorder._identity() == getattr(recorder, 'identity', None):
            trace_edges = {edge for edge in getattr(recorder, 'edges', set())
                           if edge[0] in row_addresses and self.dbg.read_memory(edge[0], 4).hex() == recorder.edge_code.get(edge)}
            visited = getattr(recorder, 'visited', {})
        observed = {edge for edge in self.observed if edge[0] in row_addresses and self.dbg.read_memory(edge[0],4) == self.observed_code.get(edge)}
        blocks,edges = blocks_for(rows,observed | trace_edges)
        inferred = {r['addr']: r for r in reference_candidates(rows, self.dbg.read_memory) if r['kind'].startswith('inferred indirect')}
        for block in blocks:
            last = block['instructions'][-1]
            block['visits'] = sum(visited.get(i['addr'], 0) for i in block['instructions'])
            if last['addr'] in inferred:
                ref = inferred[last['addr']]
                if not any(e['from'] == block['addr'] and e['to'] == ref['target'] for e in edges):
                    edges.append({'from': block['addr'], 'to': ref['target'], 'kind': 'indirect', 'source': ref['kind']})
        for block in blocks:
            last = block['instructions'][-1]
            if last['addr'] == self.dbg.pc() and branch_kind(last['mn']) == 'conditional':
                taken = _evaluate_condition(DisasmRow(last['addr'],b'',last['mn'],last['ops'],'',True),self.dbg.frame())
                for edge in edges:
                    if edge['from']==block['addr'] and taken is not None:
                        edge['active'] = (edge['kind']=='taken') == taken
        return {'name':item.GetName() if item.IsValid() else 'Unknown function', 'start':start,
                'blocks':blocks,'edges':edges,'pc':self.dbg.pc(), 'truncated':start+offset+len(rows)*4<end or not known,
                'next':offset+len(rows)*4 if len(rows)==count and start+offset+len(rows)*4<end else None,
                'coverage':'{} decoded instructions. Direct, inferred and observed edges are distinguished; unresolved edges remain explicit. {}'.format(len(rows), 'Unknown function boundary; selected window only.' if not known else '')}

    def module(self,name=None):
        if not self.dbg.target: raise ValueError('Open a target first')
        name = name or self.dbg.target.GetExecutable().GetFilename()
        for module in self.dbg.target.module_iter():
            if module.GetFileSpec().GetFilename() == name: return module
        raise ValueError('Module is not loaded')

    def symbols(self,query='',module=None,offset=0):
        mod = self.module(module)
        if offset<0 or offset>mod.GetNumSymbols() or len(query)>1024:
            raise ValueError('Invalid symbol query or offset')
        rows, scanned = [], 0
        end = min(mod.GetNumSymbols(),offset+50000)
        for index in range(offset,end):
            symbol = mod.GetSymbolAtIndex(index); scanned += 1
            name = symbol.GetName() or ''
            address = symbol.GetStartAddress().GetLoadAddress(self.dbg.target)
            if query.casefold() not in name.casefold() or address == lldb.LLDB_INVALID_ADDRESS: continue
            rows.append({'name':name,'addr':address,'module':mod.GetFileSpec().GetFilename(),
                         'kind':{lldb.eSymbolTypeCode:'code',lldb.eSymbolTypeData:'data',
                                 lldb.eSymbolTypeTrampoline:'import stub'}.get(symbol.GetType(),'other')})
            if len(rows) == 500: break
        return {'rows':rows,'next':offset+scanned,'complete':offset+scanned>=mod.GetNumSymbols(),'total':mod.GetNumSymbols()}

    def references(self,address,module=None,offset=0):
        mod = self.module(module)
        section = mod.FindSection('__TEXT').FindSubSection('__text')
        if not section.IsValid(): raise ValueError('Module has no __TEXT,__text section')
        base,size = section.GetLoadAddress(self.dbg.target),section.GetByteSize()
        if offset < 0 or offset % 4 or offset > size: raise ValueError('Invalid scan offset')
        scan_start = max(0,offset-1024)
        requested = min((size-scan_start)//4,16384)
        rows = self.instructions(base+scan_start,requested)
        refs = [r for r in reference_candidates(rows, self.dbg.read_memory)
                if r['target'] == address and r['addr'] >= base+offset]
        next_offset = scan_start+len(rows)*4
        short = len(rows) < requested
        return {'rows':refs,'next':next_offset,'complete':next_offset>=size or short,
                'coverage_complete':next_offset>=size,
                'coverage':'Selected module: direct branches and conservative basic-block address propagation, including current pointer contents. Inferences are labeled; constants are discarded at control boundaries. Pages overlap by 256 instructions.' +
                           (' Decode stopped early at {:#x}; remaining bytes were not examined.'.format(base+next_offset) if short else '')}
