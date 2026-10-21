"""Debugger workspace commands, preferences, and reversible UI edits."""
import copy
import json
import math
import os
from pathlib import Path
import re
import shlex
import struct
import tempfile

import lldb

from macdbg.core import state as state_store
from macdbg.core.address import resolve
from macdbg.core.breakpoints import validate_hardware_capacity, hardware_breakpoint_capacity, hardware_usage
from macdbg.core.code_navigation import CodeNavigation


DEFAULTS = {'font_size':13, 'left_percent':65, 'top_percent':60, 'console_height':180,
            'console_open':False, 'shortcuts':{}, 'columns':{},
            'pinned_registers':['pc','sp','lr','x16'], 'dump_formats':['hex']*4}


class Preferences:
    def __init__(self, directory=None):
        self.path = Path(directory or state_store.STATE_DIR)/'workspace.json'
        self.data = {'settings':copy.deepcopy(DEFAULTS),'recent':[],'launches':[]}
        try:
            if self.path.stat().st_size <= 256*1024:
                data = json.loads(self.path.read_text())
                self.data['settings'].update(self.validate(data.get('settings',{})))
                self.data['recent'] = [self.launch(p) for p in data.get('recent',[])][:20]
                self.data['launches'] = [self.launch(p) for p in data.get('launches',[])][:20]
        except (OSError,ValueError,TypeError,KeyError):
            pass

    @staticmethod
    def launch(item):
        path = str(item['path'])
        args = str(item.get('args_text',''))
        if not path or len(path)>4096 or len(args)>8192 or '\0' in path+args:
            raise ValueError('Invalid launch configuration')
        shlex.split(args)
        stop,profile = item.get('stop_at','loader'),item.get('profile','manual')
        if stop not in ('entry','loader') or profile not in ('manual','intercept'):
            raise ValueError('Invalid launch mode')
        return {'path':path,'args_text':args,'stop_at':stop,'profile':profile,'name':str(item.get('name',Path(path).name))[:100]}

    @staticmethod
    def validate(patch):
        if not isinstance(patch,dict) or set(patch)-set(DEFAULTS):
            raise ValueError('Unknown workspace preference')
        for key,value in patch.items():
            if key in ('font_size','left_percent','top_percent','console_height'):
                low,high = {'font_size':(10,22),'left_percent':(30,80),'top_percent':(30,80),'console_height':(90,600)}[key]
                if not isinstance(value,(int,float)) or not math.isfinite(value) or not low<=value<=high:
                    raise ValueError('Invalid '+key)
            elif key in ('shortcuts','columns'):
                if not isinstance(value,dict) or len(value)>200:
                    raise ValueError('Invalid '+key)
                for name,item in value.items():
                    if not re.fullmatch(r'[\w:.-]{1,100}',name): raise ValueError('Invalid preference key')
                    if key=='shortcuts' and (not isinstance(item,str) or len(item)>60): raise ValueError('Invalid shortcut')
                    if key=='columns' and (not isinstance(item,(int,float)) or not math.isfinite(item) or not 35<=item<=1000): raise ValueError('Invalid column width')
            elif key=='pinned_registers':
                if not isinstance(value,list) or len(value)>40 or any(not re.fullmatch(r'(?:[xw]\d+|pc|sp|lr|fp)',v) for v in value): raise ValueError('Invalid register pins')
            elif key=='dump_formats':
                if not isinstance(value,list) or len(value)!=4 or any(v not in ('hex','pointers','u32','u64','f32','f64','utf16') for v in value): raise ValueError('Invalid dump formats')
            elif not isinstance(value,bool):
                raise ValueError('Expected boolean preference')
        return patch

    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='workspace-',suffix='.tmp',dir=self.path.parent)
        try:
            with os.fdopen(descriptor,'w') as file: json.dump(self.data,file,indent=2)
            os.replace(temporary,self.path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def update(self,patch):
        self.data['settings'].update(self.validate(patch)); self.save()
        return copy.deepcopy(self.data)

    def remember(self,item,preset=False):
        item = self.launch(item)
        key = 'launches' if preset else 'recent'
        identity = 'name' if preset else 'path'
        self.data[key] = [item]+[p for p in self.data[key] if p[identity]!=item[identity]]
        self.data[key] = self.data[key][:20]
        self.save()


class Workspace:
    def __init__(self,debugger,hidden_ids):
        self.dbg, self.hidden_ids = debugger, hidden_ids
        self.preferences = Preferences()
        self.code = CodeNavigation(debugger)
        self.edits = []
        self._pid = None

    def sync(self):
        pid = self.dbg.process.GetProcessID() if self.dbg.process else None
        if pid != self._pid:
            self.edits.clear(); self._pid = pid
        self.code.sync()

    def stopped(self):
        self.sync()
        if not self.dbg.process or self.dbg.process.GetState()!=lldb.eStateStopped:
            raise ValueError('Pause the target first')

    def address(self,expression):
        found = resolve(self.dbg,expression)
        if len(found)!=1: raise ValueError('Ambiguous address; select a specific symbol or numeric address')
        return int(found[0]['addr'],16)

    def command(self,action,args):
        if action=='preferences':
            result = self.preferences.update(args) if args else copy.deepcopy(self.preferences.data)
            for collection in ('recent','launches'):
                for item in result[collection]:
                    item['available'] = os.path.isfile(item['path']) and os.access(item['path'],os.X_OK)
            return result
        if action=='save_launch':
            self.preferences.remember(args,preset=True)
            return copy.deepcopy(self.preferences.data)
        if action=='remove_launch':
            self.preferences.data['launches'] = [p for p in self.preferences.data['launches'] if p['name']!=args['name']]
            self.preferences.save(); return copy.deepcopy(self.preferences.data)
        self.stopped()
        if action=='instruction': return self.code.info(self.address(args['address']))
        if action=='graph': return self.code.graph(self.address(args['address']))
        if action=='symbols': return self.code.symbols(str(args.get('query','')),args.get('module'),int(args.get('offset',0)))
        if action=='references': return self.code.references(self.address(args['address']),args.get('module'),int(args.get('offset',0)))
        if action=='dump': return self.dump(self.address(args['address']),int(args.get('size',512)))
        if action=='breakpoints': return self.breakpoints()
        if action=='breakpoints_clear':
            for row in self.breakpoints()['rows']: self.dbg.delete_breakpoint(row['id'])
            self.save(); return self.breakpoints()
        if action=='breakpoint_save': return self.save_breakpoint(args)
        if action=='breakpoint_delete':
            bid = int(args['id']); self.user_breakpoint(bid)
            self.dbg.delete_breakpoint(bid); self.save(); return self.breakpoints()
        if action=='watchpoint_save': return self.save_watchpoint(args)
        if action=='watchpoint_delete':
            self.dbg.target.DeleteWatchpoint(int(args['id'])); return self.breakpoints()
        if action=='edit_memory': return self.edit_memory(self.address(args['address']),bytes.fromhex(args['hex']))
        if action=='edit_register': return self.edit_register(args['name'],str(args['value']))
        if action=='undo': return self.undo()
        if action=='edit_history': return self.history()
        raise ValueError('Unknown workspace action')

    def save(self):
        if self.dbg.state and self.dbg.save_state(self.hidden_ids()) is None:
            raise RuntimeError('Could not save breakpoint state')

    def dump(self,address,size):
        if not 1<=size<=4096 or address<0 or address+size>=1<<64: raise ValueError('Dump size must be 1–4096 bytes')
        data = self.dbg.read_memory(address,size)
        annotations = []
        for offset in range(0,len(data)-7,8):
            value = int.from_bytes(data[offset:offset+8],'little')
            annotations.append({'offset':offset,'value':hex(value),'text':self.code.preview(value) if value>=0x10000 else ''})
        return {'addr':address,'bytes':list(data),'annotations':annotations,'complete':len(data)==size}

    def user_breakpoint(self,bid):
        if bid in self.hidden_ids(): raise ValueError('This breakpoint belongs to a defense or tracer')
        bp = self.dbg.target.FindBreakpointByID(bid)
        if not bp.IsValid(): raise ValueError('Breakpoint no longer exists')
        return bp

    def breakpoints(self):
        target, rows = self.dbg.target, []
        if not target: return {'rows':[],'watchpoints':[]}
        for bp in target.breakpoint_iter():
            if bp.GetID() in self.hidden_ids(): continue
            locations = []
            for loc in bp:
                address = loc.GetLoadAddress()
                if address==lldb.LLDB_INVALID_ADDRESS: continue
                module = loc.GetAddress().GetModule()
                base = module.GetObjectFileHeaderAddress().GetLoadAddress(target) if module.IsValid() else address
                locations.append({'addr':address,'label':('{}+{:#x}'.format(module.GetFileSpec().GetFilename(),address-base) if module.IsValid() else hex(address))})
            rows.append({'id':bp.GetID(),'kind':'hardware' if bp.IsHardware() else 'software',
                'enabled':bp.IsEnabled(),'hits':bp.GetHitCount(),'ignore':bp.GetIgnoreCount(),
                'condition':bp.GetCondition() or '', 'commands':self.dbg.bp_commands(bp.GetID()),
                'one_shot':bp.IsOneShot(), 'locations':locations,'resolved':bp.GetNumResolvedLocations(),
                'expression':hex(locations[0]['addr']) if locations else ''})
        watches = []
        for i in range(target.GetNumWatchpoints()):
            wp = target.GetWatchpointAtIndex(i)
            watches.append({'id':wp.GetID(),'addr':wp.GetWatchAddress(),'size':wp.GetWatchSize(),
                'access':'access' if wp.IsWatchingReads() and wp.IsWatchingWrites() else 'read' if wp.IsWatchingReads() else 'write',
                'enabled':wp.IsEnabled(),'hits':wp.GetHitCount(),'condition':wp.GetCondition() or ''})
        try: budget = {'used':hardware_usage(target),'capacity':hardware_breakpoint_capacity()}
        except RuntimeError: budget = {}
        return {'rows':rows,'watchpoints':watches,'hardware':budget}

    def save_breakpoint(self,args):
        kind = args.get('kind','software')
        if kind not in ('software','hardware'): raise ValueError('Invalid breakpoint type')
        condition = str(args.get('condition',''))
        commands = args.get('commands',[])
        ignore = int(args.get('ignore',0))
        if ignore<0 or ignore>2**32-1 or not isinstance(commands,list) or len(commands)>100 or not all(isinstance(c,str) for c in commands): raise ValueError('Invalid breakpoint settings')
        existing = self.user_breakpoint(int(args['id'])) if args.get('id') else None
        if not existing and self.dbg.analysis_cloak.enabled:
            kind = 'hardware'
        previous_hardware = existing.IsHardware() if existing else None
        if existing:
            bp = existing
            if bp.IsHardware() != (kind=='hardware'):
                if kind=='software' and self.dbg.analysis_cloak.enabled:
                    raise ValueError('Disable Analysis cloak before converting a breakpoint to software')
                error = bp.SetIsHardware(kind=='hardware')
                if error.Fail():
                    bp.SetIsHardware(previous_hardware)
                    raise RuntimeError(error.GetCString())
        else:
            expression = str(args.get('expression','')).strip()
            if not expression or len(expression)>4096 or '\n' in expression: raise ValueError('Enter an address or symbol')
            try:
                address = self.address(expression)
            except ValueError:
                if not re.fullmatch(r'[\w.$:!+-]+',expression): raise
                module,separator,symbol = expression.partition('!')
                if not separator: symbol,module = expression,''
                before = {b.GetID() for b in self.dbg.target.breakpoint_iter()}
                result = lldb.SBCommandReturnObject()
                self.dbg.ci.HandleCommand('breakpoint set --skip-prologue false '+('-H ' if kind=='hardware' else '')+'-F '+shlex.quote(symbol)+(' -s '+shlex.quote(module) if module else ''),result,False)
                created = [b for b in self.dbg.target.breakpoint_iter() if b.GetID() not in before]
                if not result.Succeeded() or len(created)!=1:
                    for b in created: self.dbg.delete_breakpoint(b.GetID())
                    raise RuntimeError(result.GetError() or 'Could not create breakpoint')
                bp = created[0]
            else:
                if kind=='hardware' or self.dbg.analysis_cloak.enabled:
                    bp = self.dbg.create_hardware_breakpoint_by_address(address)
                else:
                    bp = self.dbg.target.BreakpointCreateByAddress(address)
        was_enabled = bp.IsEnabled()
        try:
            bp.SetEnabled(bool(args.get('enabled',True)))
            validate_hardware_capacity(self.dbg.target)
        except Exception:
            if existing:
                bp.SetEnabled(was_enabled)
                if previous_hardware != bp.IsHardware(): bp.SetIsHardware(previous_hardware)
            else: self.dbg.delete_breakpoint(bp.GetID())
            raise
        if bp.IsHardware(): self.dbg.hardware_bp_ids.add(bp.GetID())
        else: self.dbg.hardware_bp_ids.discard(bp.GetID())
        bp.SetCondition(condition or None); bp.SetIgnoreCount(ignore)
        bp.SetOneShot(bool(args.get('one_shot',False)))
        self.dbg.set_bp_commands(bp.GetID(),commands)
        self.save(); return self.breakpoints()

    def save_watchpoint(self,args):
        target = self.dbg.target
        address = self.address(args['address'])
        size,access = int(args.get('size',8)),args.get('access','write')
        if size not in (1,2,4,8) or address%size or access not in ('read','write','access'):
            raise ValueError('Use a naturally aligned 1, 2, 4 or 8 byte watchpoint')
        old = target.FindWatchpointByID(int(args['id'])) if args.get('id') else None
        if args.get('id') and not old.IsValid(): raise ValueError('Watchpoint no longer exists')
        restore = None
        if old and (old.GetWatchAddress()!=address or old.GetWatchSize()!=size or
                old.IsWatchingReads()!=(access in ('read','access')) or old.IsWatchingWrites()!=(access in ('write','access'))):
            restore = (old.GetWatchAddress(),old.GetWatchSize(),old.IsWatchingReads(),old.IsWatchingWrites(),old.IsEnabled(),old.GetCondition())
            target.DeleteWatchpoint(old.GetID())
            old = None
        if old and old.IsValid(): wp = old
        else:
            error = lldb.SBError(); wp = target.WatchAddress(address,size,access in ('read','access'),access in ('write','access'),error)
            if error.Fail() or not wp.IsValid():
                message = error.GetCString() or 'No hardware watchpoint slot available'
                if restore:
                    recovered_error = lldb.SBError()
                    recovered = target.WatchAddress(*restore[:4],recovered_error)
                    if recovered_error.Fail():
                        raise RuntimeError(message+'; original watchpoint could not be restored: '+str(recovered_error))
                    recovered.SetEnabled(restore[4]); recovered.SetCondition(restore[5])
                raise RuntimeError(message)
        wp.SetEnabled(bool(args.get('enabled',True))); wp.SetCondition(str(args.get('condition','')) or None)
        return self.breakpoints()

    def edit_memory(self,address,data):
        self.stopped()
        if not 1<=len(data)<=4096: raise ValueError('Edit 1–4096 bytes at a time')
        before = self.dbg.read_memory(address,len(data))
        if len(before)!=len(data): raise ValueError('Cannot read all original bytes; edit refused')
        ok,message = self.dbg.write_memory(address,data)
        if not ok:
            if self.dbg.read_memory(address,len(data)) != before:
                restored,reason = self.dbg.write_memory(address,before,track=False)
                if not restored: raise RuntimeError(message+'; rollback failed: '+reason)
            raise RuntimeError(message)
        self.edits.append({'kind':'memory','address':address,'before':before.hex(),'after':data.hex(),
                           'stop':self.dbg.process.GetStopID()})
        self.edits = self.edits[-100:]
        return self.history()

    def register_bytes(self,name):
        register = self.dbg.frame().FindRegister(name)
        if not register.IsValid() or not 1<=register.GetByteSize()<=16:
            raise ValueError('Unsupported register')
        error = lldb.SBError()
        data = register.GetData().ReadRawData(error,0,register.GetByteSize())
        if error.Fail(): raise RuntimeError('Cannot read register')
        return bytes(data)

    def write_register_bytes(self,name,data):
        alias = re.fullmatch(r'([wsdqhb])(\d+)',name)
        if alias and alias[1]=='w':
            return self.write_register_bytes('x'+alias[2],data+b'\0'*4)
        if alias and alias[1] in ('s','d','q','h','b'):
            parent = 'v'+alias[2]
            original = self.register_bytes(parent)
            return self.write_register_bytes(parent,data+original[len(data):])
        literal = ('"{'+' '.join('0x{:02x}'.format(b) for b in data)+'}"' if len(data)>8
                   else hex(int.from_bytes(data,'little')))
        result = lldb.SBCommandReturnObject()
        self.dbg.ci.HandleCommand('register write {} {}'.format(name,literal),result,False)
        if not result.Succeeded() or self.register_bytes(name)!=data:
            raise RuntimeError(result.GetError() or 'Register write verification failed')

    def edit_register(self,name,value):
        self.stopped()
        if not re.fullmatch(r'(?:[xwvsdqhb]\d+|pc|sp|fp|lr|cpsr|fpsr|fpcr)',name):
            raise ValueError('Unknown register')
        before = self.register_bytes(name)
        parent = ('x'+name[1:] if re.fullmatch(r'w\d+',name) else
                  'v'+name[1:] if re.fullmatch(r'[sdqhb]\d+',name) else name)
        parent_before = self.register_bytes(parent)
        if len(before)>8 or value.strip().startswith('{'):
            after = bytes.fromhex(value.strip().strip('{}').replace('0x',''))
        elif re.fullmatch(r'[sd]\d+',name) and not value.lower().startswith(('0x','-0x')):
            after = struct.pack('<f' if len(before)==4 else '<d',float(value))
        else:
            number = int(value,0); bits=len(before)*8
            if not -(1<<(bits-1))<=number<(1<<bits): raise ValueError('Value does not fit register width')
            after = (number & ((1<<bits)-1)).to_bytes(len(before),'little')
        if len(after)!=len(before): raise ValueError('Expected {} register bytes'.format(len(before)))
        try:
            self.write_register_bytes(name,after)
        except Exception:
            self.write_register_bytes(parent,parent_before)
            raise
        self.edits.append({'kind':'register','name':name,'register':parent,
                           'before':parent_before.hex(' '),'after':self.register_bytes(parent).hex(' '),
                           'thread':self.dbg.frame().GetThread().GetThreadID(),
                           'stop':self.dbg.process.GetStopID()})
        self.edits = self.edits[-100:]
        return self.history()

    def history(self):
        self.sync()
        stop = self.dbg.process.GetStopID() if self.dbg.process else None
        valid = bool(self.edits and self.edits[-1]['stop']==stop and self.dbg.process.GetState()==lldb.eStateStopped)
        if valid and self.edits[-1]['kind']=='register':
            valid = self.edits[-1]['thread']==self.dbg.process.GetSelectedThread().GetThreadID()
        return {'edits':list(self.edits),'can_undo':valid}

    def undo(self):
        self.stopped()
        if not self.history()['can_undo']: raise ValueError('Undo is available only before the target executes again')
        edit = self.edits[-1]
        if edit['kind']=='memory':
            current = self.dbg.read_memory(edit['address'],len(bytes.fromhex(edit['after']))).hex()
            if current!=edit['after']: raise ValueError('Memory changed since this edit; undo refused')
            ok,message = self.dbg.write_memory(edit['address'],bytes.fromhex(edit['before']))
        else:
            register = edit.get('register',edit['name'])
            current = self.register_bytes(register)
            if current!=bytes.fromhex(edit['after']): raise ValueError('Register changed since this edit; undo refused')
            self.write_register_bytes(register,bytes.fromhex(edit['before']))
            ok,message = True,''
        if not ok: raise RuntimeError(message)
        self.edits.pop(); return self.history()
