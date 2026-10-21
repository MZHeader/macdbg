/* CPU workspace and analysis tools. The small bridge keeps debugger commands
 * and existing dialogs in app.js; this module owns interaction state. */
(function () {
  'use strict';
  window.MacdbgWorkspace = {
    create(u) {
      const M=window.MacdbgWorkspaceModel, $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
      const esc=u.esc, hx=u.hx;
      const call=(action,args={})=>u.cmdSync('workspace',{action,...args});
      let settings={}, recent=[], launches=[], view='cpu', activeDump=0, state=null, infoRequest=0, stackRequest=0, symbolRequest=0;
      let selectedOperand=null, selection=null, anchor=null, dragging=false, lastFollow=null, refreshTimer=null, pendingSnapshot=null, comparisonId=null, comparisonRequest=0;
      let symbols=[], symbolNext=0, references=[], referenceNext=0, graph=null, overview=false;
      const dumps=Array.from({length:4},()=>({addr:null,history:[],index:-1,data:null,request:0,scroll:0}));
      const keys=()=>({...M.DEFAULT_KEYS,...(settings.shortcuts||{})});
      const paused=()=>state && state.process_state==='stopped';
      const advanced=window.MacdbgAdvanced.create({...u,showView,paused,address:()=>address(),toast:text=>toast(text),dialog,button});
      const address=()=>u.selected()==null ? (state && (state.disasm_center==null?state.pc:state.disasm_center)) : u.selected();
      function toast(text) {
        let node=$('.workspace-toast'); if (node) node.remove();
        node=document.createElement('div');node.className='workspace-toast';node.textContent=text;document.body.appendChild(node);
        setTimeout(()=>node.remove(),4500);
      }
      function dialog(title,html) {
        const content=document.createElement('div');content.innerHTML=html;
        const result=u.analysisDialog(title,content);
        const error=document.createElement('div');error.className='m-error';result.body.appendChild(error);
        result.error=message=>{error.textContent=message;};
        return result;
      }
      function button(parent,label,action,cls='btn') {
        const b=document.createElement('button');b.className=cls;b.textContent=label;b.onclick=action;parent.appendChild(b);return b;
      }
      async function saveSettings(patch) {
        const result=await call('preferences',patch);
        if (result) {settings=result.settings;recent=result.recent;launches=result.launches;applySettings();}
      }
      function applySettings() {
        const root=document.documentElement.style;
        root.setProperty('--workspace-font',(settings.font_size||13)+'px');
        root.setProperty('--cpu-left',(settings.left_percent||65)+'%');
        root.setProperty('--cpu-top',(settings.top_percent||60)+'%');
        root.setProperty('--console-height',(settings.console_height||180)+'px');
        $('.panel-console').classList.toggle('open',!!settings.console_open);
        $('#console-toggle').textContent=settings.console_open?'Hide console':'Show console';
        u.setPins(settings.pinned_registers||['pc','sp','lr','x16']);
        $('#dump-format').value=(settings.dump_formats||['hex','hex','hex','hex'])[activeDump];
        $$('.tb[data-act]').forEach(b=>{const key=keys()[b.dataset.act==='cont'?'run':b.dataset.act];if(key)b.title=b.title.replace(/\s*\([^)]*\)$/,'')+' ('+key.replace('Mod+','⌘/Ctrl+')+')';});
        const shortNames={step_in:'Step in',step_over:'Step over',step_out:'Step out',run:'Run',pause:'Pause',toggle_bp:'Breakpoint',run_to:'Run to',snap_pc:'PC',actions:'Actions',console:'Console',undo:'Undo'};
        const quick=['step_in','step_over','step_out','run','pause','toggle_bp','run_to','snap_pc','actions','console','undo'];
        $('#keybar').innerHTML=quick.map(name=>{const a=ACTIONS.find(a=>a[0]===name);return `<span class="kb" data-quick="${name}"><span class="kb-key">${esc((keys()[name]||'').replace('Mod+','⌘'))}</span>${esc(shortNames[name])}</span>`;}).join('');
        $$('[data-quick]').forEach(b=>b.onclick=()=>ACTIONS.find(a=>a[0]===b.dataset.quick)[2]());
        requestAnimationFrame(()=>u.recenter());
        decorateTables();
      }
      function showView(name) {
        view=name;
        $('#cpu-workspace').classList.toggle('hidden',name!=='cpu');
        $('#tool-workspace').classList.toggle('hidden',name==='cpu');
        $$('#bot-tabs .tab').forEach(t=>t.classList.toggle('active',t.dataset.bottab===name));
        $$('.tabbody > [id^="tb-"]').forEach(p=>p.classList.toggle('hidden',p.id!=='tb-'+name));
        if(name==='symbols') loadSymbols(false);
        if(name==='graph') loadGraph();
        if(name==='references' && !$('#reference-address').value) $('#reference-address').value=hx(address());
        if(name==='cpu') {renderDump();selectionInfo();}
        decorateTables();
        advanced.show(name);
      }
      function setConsole(open) {settings.console_open=open;applySettings();saveSettings({console_open:open});if(open)$('#cmd').focus();}
      function paneForMemory(which) {return which==='memory'?0:Math.max(0,Number(which.replace('watch','')));}
      function selectDump(which) {
        dumps[activeDump].scroll=$('#memory').scrollTop;
        activeDump=typeof which==='number'?which:paneForMemory(which);
        if(activeDump>3)activeDump=0;
        $$('#mem-tabs .tab').forEach((t,i)=>t.classList.toggle('active',i===activeDump));
        $('#memory').classList.remove('hidden');['watch1','watch2','watch3'].forEach(id=>$('#'+id).classList.add('hidden'));
        $('#mem-addrbar').classList.remove('hidden');
        selection=null;anchor=null;selectedOperand=null;
        $('#dump-format').value=(settings.dump_formats||['hex','hex','hex','hex'])[activeDump];
        if(dumps[activeDump].addr==null && state) M.historyPush(dumps[activeDump],state.pc);
        if(dumps[activeDump].addr!=null) {lastFollow=dumps[activeDump].addr;u.cmd('follow_mem',{addr:lastFollow});}
        refreshDump();
      }
      function followMemory(value,slot=activeDump) {
        if(!paused()){toast('Pause the target to follow live memory.');return;}
        if(!Number.isSafeInteger(Number(value))||Number(value)<0){toast('Tagged or noncanonical pointer — resolve its address before following it.');return;}
        activeDump=slot;showView('cpu');
        const model=dumps[slot];M.historyPush(model,Number(value));selection=null;anchor=null;
        lastFollow=Number(value);selectDump(slot);
      }
      async function refreshDump() {
        const index=activeDump, model=dumps[index];
        if(!paused() || model.addr==null)return;
        const request=++model.request,pid=state.process_id;
        const result=await call('dump',{address:hx(model.addr),size:512});
        if(!result || request!==model.request || !state || state.process_id!==pid)return;
        model.data=result;if(selection && (selection.addr<result.addr||selection.addr+selection.size>result.addr+result.bytes.length)){selection=null;anchor=null;}if(index===activeDump)renderDump();
      }
      function changedByte(addr) {
        return ((state.edit_history||{}).edits||[]).some(e=>e.kind==='memory' && addr>=e.address && addr<e.address+e.after.length/2);
      }
      function renderDump() {
        const model=dumps[activeDump],data=model.data;
        $('#dump-back').disabled=model.index<=0;$('#dump-forward').disabled=model.index>=model.history.length-1;
        if(!data){$('#memory').innerHTML='<div class="empty-note">Follow an address to inspect this dump.</div>';return;}
        $('#mem-addr').value=hx(model.addr);
        const format=$('#dump-format').value,width=+(state.memory_width||16);
        let html='';
        if(format==='hex') {
          for(let offset=0;offset<data.bytes.length;offset+=width) {
            const bytes=data.bytes.slice(offset,offset+width),addr=data.addr+offset;
            const hex=bytes.map((b,i)=>`<span class="byte-cell${changedByte(addr+i)?' modified':''}" data-byte="${addr+i}">${b.toString(16).padStart(2,'0')}</span>`).join(' ');
            const ascii=bytes.map((b,i)=>`<span class="ascii-cell" data-byte="${addr+i}" data-ascii-cell="1">${esc(b>=32&&b<127?String.fromCharCode(b):'.')}</span>`).join('');
            html+=`<div class="hrow" data-addr="${addr}" data-hex="${M.hex(bytes)}" data-ascii="${esc(bytes.map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join(''))}"><span class="h-addr">${hx(addr)}</span><span class="h-hex">${hex}</span><span class="h-ascii">${ascii}</span></div>`;
          }
        } else {
          html=M.typed(data.bytes,format).map(row=>{
            const annotation=data.annotations.find(a=>a.offset===row.offset);
            return `<div class="hrow typed-row" data-addr="${data.addr+row.offset}" data-hex="${M.hex(data.bytes.slice(row.offset,row.offset+row.size))}" data-byte="${data.addr+row.offset}" data-size="${row.size}"><span class="c-addr">${hx(data.addr+row.offset)}</span><span ${format==='pointers'?`data-pointer="${esc(row.value)}" class="operand-link"`:''}>${esc(row.value)}</span><span class="c-str">${esc(annotation&&format==='pointers'?annotation.text:'')}</span></div>`;
          }).join('');
        }
        $('#memory').innerHTML=html || '<div class="empty-note">Memory is unreadable.</div>';
        $('#memory').scrollTop=model.scroll;
        $('#mem-follow-info').textContent='Dump '+(activeDump+1)+' · '+data.bytes.length+' bytes'+(data.complete?'':' · partial read');
        selectionInfo();
      }
      function selectionInfo() {
        $$('#memory [data-byte]').forEach(cell=>cell.classList.toggle('selected',!!selection && +cell.dataset.byte>=selection.addr && +cell.dataset.byte<selection.addr+selection.size));
        $('#dump-selection').textContent=selection?`${hx(selection.addr)} · ${selection.size} byte${selection.size===1?'':'s'} selected · double-click or type hex to edit`:'Click a byte; Shift-click or drag to select a range.';
      }
      function chooseByte(addr,extend=false) {
        const data=dumps[activeDump].data;if(!data)return;
        if(!extend || anchor==null)anchor=addr;
        selection=M.range(anchor,addr,data.addr,data.bytes.length);selectionInfo();
      }
      function copySelection() {
        const data=dumps[activeDump].data;if(!selection||!data)return false;
        u.copy(M.hex(data.bytes.slice(selection.addr-data.addr,selection.addr-data.addr+selection.size)));return true;
      }
      async function editSelection(mode='hex') {
        const data=dumps[activeDump].data;if(!data)return;
        const range=selection||{addr:data.addr,size:1},bytes=data.bytes.slice(range.addr-data.addr,range.addr-data.addr+range.size);
        const binary=mode==='ascii'&&bytes.some(b=>b<32||b>126);if(binary)mode='hex';
        const value=mode==='hex'?M.hex(bytes):new TextDecoder(mode==='utf16'?'utf-16le':'utf-8').decode(Uint8Array.from(bytes));
        const text=await u.promptDialog({title:'Edit '+range.size+' selected byte(s) · '+hx(range.addr),value,hint:(binary?'Binary bytes selected; displaying hex. ':'')+'Writes from the selected address. Undo is available until the target executes again.'});
        if(text===null||text===value)return;
        try {
          let output;
          if(mode==='hex')output=M.parseHex(text);
          else if(mode==='utf16')output=M.encodeUtf16(text);
          else output=Array.from(new TextEncoder().encode(text));
          if(await call('edit_memory',{address:hx(range.addr),hex:M.hex(output)}))refreshDump();
        } catch(e){toast(e.message);}
      }
      function inlineByte(cell,firstKey) {
        if(cell.querySelector('input') || !paused())return;
        const addr=+cell.dataset.byte, ascii=!!cell.dataset.asciiCell;
        const input=document.createElement('input');input.className='inline-byte';input.maxLength=ascii?1:2;
        input.value=firstKey||cell.textContent;cell.textContent='';cell.appendChild(input);input.focus();if(!firstKey)input.select();
        let done=false;
        const commit=async()=>{if(done)return;done=true;try{
          const bytes=ascii?Array.from(new TextEncoder().encode(input.value)):M.parseHex(input.value);
          if(bytes.length!==1)throw new Error('Inline editing accepts one byte. Use Edit selection for longer text.');
          await call('edit_memory',{address:hx(addr),hex:M.hex(bytes)});refreshDump();
        }catch(e){toast(e.message);renderDump();}};
        input.onkeydown=e=>{e.stopPropagation();if(e.key==='Enter'){e.preventDefault();commit();}if(e.key==='Escape'){done=true;renderDump();}};
        input.onblur=()=>{if(!done){done=true;renderDump();}};
      }
      async function refreshStack() {
        if(!paused() || !state.sp)return;
        const request=++stackRequest,sp=state.sp,pid=state.process_id;
        const result=await call('dump',{address:hx(sp),size:256});
        if(!result || request!==stackRequest || state.process_id!==pid)return;
        $('#stack').innerHTML=result.annotations.map(r=>`<div class="stack-row${r.offset===0?' at-sp':''}"><span class="dim">SP+${r.offset.toString(16)}</span><span class="c-addr">${hx(sp+r.offset)}</span><span data-follow="${esc(r.value)}" class="c-addr">${esc(r.value)}</span><span class="stack-symbol c-str" title="${esc(r.text)}">${esc(r.text)}</span></div>`).join('')||'<div class="empty-note">Stack unreadable.</div>';
        $$('#stack [data-follow]').forEach(node=>node.ondblclick=()=>{showView('cpu');u.cmd('follow_disasm',{addr:node.dataset.follow});});
      }
      function renderInfo(info) {
        if(!info)return;
        $('#instruction-info').innerHTML=`<div class="info-heading">${info.live?'Live at PC':'Static selection'} · ${hx(info.addr)} ${esc((info.mn||'')+' '+(info.ops||''))}</div><div class="info-lines">${(info.lines||[]).map(line=>`<span title="${esc(line)}">${esc(line)}</span>`).join('')}</div><div class="info-links">${(info.links||[]).map((link,i)=>`<button class="mini" data-info-link="${i}">${esc(link.label)}</button>`).join('')}</div>`;
        $$('#instruction-info [data-info-link]').forEach(b=>b.onclick=()=>{const link=info.links[+b.dataset.infoLink];if(link.pane==='memory')followMemory(link.addr);else u.cmd('follow_disasm',{addr:link.addr});});
      }
      async function selected(addr) {
        selectedOperand=null;
        if(!paused())return;
        if(addr===state.pc){++infoRequest;renderInfo(state.instruction_info);return;}
        const request=++infoRequest,result=await call('instruction',{address:hx(addr)});
        if(request===infoRequest && result)renderInfo(result);
      }
      function operand(node) {selectedOperand=node.textContent.trim();$$('#disasm .operand-link').forEach(n=>n.classList.toggle('selected',n===node));}
      function followOperand() {
        if(!paused())return;
        let value=selectedOperand;
        const row=(state.disasm||[]).find(r=>r.addr===address());
        if(!value && row)value=(row.ops||[]).filter(o=>o[1]==='op-hex').map(o=>o[0]).pop();
        if(value && /^0x[\da-f]+$/i.test(value)){u.cmd('follow_disasm',{addr:value});return;}
        if(value && /^([wx]\d+|sp|lr|fp)$/.test(value)) {
          if(address()!==state.pc){toast('Register-dependent operands can be followed at the current PC.');return;}
          const r=state.registers.find(r=>r.name===value || (value[0]==='w' && r.name==='x'+value.slice(1)));
          if(r){u.cmd('follow_disasm',{addr:r.value});return;}
        }
        toast('Select a branch address or a live register operand to follow.');
      }
      function renderBreakpoints() {
        const details=state && state.breakpoint_details;if(!details)return;
        const h=details.hardware||{};$('#breakpoint-budget').textContent=h.capacity?`Instruction hardware slots: ${h.used}/${h.capacity} · data watchpoints have a separate pool`:'';
        $('#bp-table').innerHTML='<thead><tr><th>ID</th><th>Type</th><th>Enabled</th><th>Hits</th><th>Location</th><th>Condition</th><th>Actions</th></tr></thead><tbody>'+details.rows.map(r=>`<tr data-bpid="${r.id}" data-addr="${r.locations.length?r.locations[0].addr:''}"><td>${r.id}</td><td>${esc(r.kind)}</td><td>${r.enabled?'✓':'—'}</td><td>${r.hits}</td><td>${esc(r.locations.map(l=>l.label).join(', ')||'Pending symbol')}</td><td>${esc(r.condition)}</td><td>${r.commands.length} command(s)${r.one_shot?' · one-shot':''}</td></tr>`).join('')+'</tbody>';
        $('#wp-table').innerHTML='<thead><tr><th>ID</th><th>Address</th><th>Bytes</th><th>Access</th><th>Enabled</th><th>Hits</th><th>Condition</th></tr></thead><tbody>'+details.watchpoints.map(w=>`<tr data-wpid="${w.id}"><td>${w.id}</td><td>${hx(w.addr)}</td><td>${w.size}</td><td>${esc(w.access)}</td><td>${w.enabled?'✓':'—'}</td><td>${w.hits}</td><td>${esc(w.condition)}</td></tr>`).join('')+'</tbody>';
        $$('#bp-table [data-bpid]').forEach(row=>row.ondblclick=e=>{e.stopImmediatePropagation();editBreakpoint(details.rows.find(r=>r.id===+row.dataset.bpid));});
        $$('#wp-table [data-wpid]').forEach(row=>row.ondblclick=()=>editWatchpoint(details.watchpoints.find(w=>w.id===+row.dataset.wpid)));
      }
      function editBreakpoint(row=null) {
        const r=row||{expression:hx(address()||0),kind:state&&state.trace_status.defenses.analysis_cloak?'hardware':'software',enabled:true,ignore:0,condition:'',commands:[]};
        const dlg=dialog(row?'Edit breakpoint #'+row.id:'Add breakpoint',`<div class="form-grid"><label class="wide">Address or symbol<input class="m-input" id="bp-expression" value="${esc(r.expression)}" ${row?'readonly':''}/></label><label>Type<select class="m-input" id="bp-kind"><option value="software">Software</option><option value="hardware">Hardware</option></select></label><label>Ignore first N hits<input class="m-input" id="bp-ignore" type="number" min="0" value="${r.ignore}"/></label><label class="wide">Condition<input class="m-input" id="bp-condition" value="${esc(r.condition)}" placeholder="$x0 == 0"/></label><label class="wide">Commands when hit<textarea class="m-input" id="bp-commands" placeholder="One LLDB command per line">${esc(r.commands.join('\n'))}</textarea></label><label><input type="checkbox" id="bp-enabled" ${r.enabled?'checked':''}/> Enabled</label><label><input type="checkbox" id="bp-once" ${r.one_shot?'checked':''}/> One-shot</label></div><p class="m-hint">${row?`Hit count: ${r.hits} · ${r.resolved} resolved location(s)`:'Symbols may remain pending until their module loads.'}</p>`);
        $('#bp-kind').value=r.kind;
        button(dlg.foot,'Save',async()=>{const result=await call('breakpoint_save',{id:r.id,expression:$('#bp-expression').value,kind:$('#bp-kind').value,ignore:+$('#bp-ignore').value,condition:$('#bp-condition').value,commands:$('#bp-commands').value.split('\n').filter(s=>s.trim()),enabled:$('#bp-enabled').checked,one_shot:$('#bp-once').checked});if(result)u.closeModal();else dlg.error('The breakpoint was not saved. See the error message for details.');},'btn primary');
        if(row)button(dlg.foot,'Delete',async()=>{if(await call('breakpoint_delete',{id:r.id}))u.closeModal();},'btn danger');
      }
      function editWatchpoint(row=null) {
        const r=row||{addr:selection?selection.addr:(dumps[activeDump].addr||address()||0),size:8,access:'write',enabled:true,condition:''};
        const dlg=dialog(row&&row.id?'Edit watchpoint #'+row.id:'Break on memory access',`<div class="form-grid"><label class="wide">Address or symbol<input class="m-input" id="wp-address" value="${hx(r.addr)}"/></label><label>Size<select class="m-input" id="wp-size">${[1,2,4,8].map(n=>`<option>${n}</option>`).join('')}</select></label><label>Access<select class="m-input" id="wp-access"><option value="write">Write</option><option value="read">Read</option><option value="access">Read or write</option></select></label><label class="wide">Condition<input class="m-input" id="wp-condition" value="${esc(r.condition)}"/></label><label><input type="checkbox" id="wp-enabled" ${r.enabled?'checked':''}/> Enabled</label></div><p class="m-hint">Address must be aligned to the selected size. Allocation failures leave the target stopped.</p>`);
        $('#wp-size').value=String(r.size);$('#wp-access').value=r.access;
        button(dlg.foot,'Save',async()=>{if(await call('watchpoint_save',{id:r.id,address:$('#wp-address').value,size:+$('#wp-size').value,access:$('#wp-access').value,condition:$('#wp-condition').value,enabled:$('#wp-enabled').checked}))u.closeModal();else dlg.error('Watchpoint not saved. Check alignment, available slots, and the error message.');},'btn primary');
        if(row&&row.id)button(dlg.foot,'Delete',async()=>{if(await call('watchpoint_delete',{id:r.id}))u.closeModal();},'btn danger');
      }
      function renderHistory() {
        const history=(state.edit_history||{});$('#undo-edit').disabled=!history.can_undo;
        $('#edit-table').innerHTML='<thead><tr><th>Change</th><th>Before</th><th>After</th><th>Stop</th></tr></thead><tbody>'+(history.edits||[]).slice().reverse().map(e=>`<tr><td>${esc(e.kind==='memory'?hx(e.address):e.name)}</td><td>${esc(e.before)}</td><td>${esc(e.after)}</td><td>${e.stop}</td></tr>`).join('')+'</tbody>';
      }
      async function undo() {if(await call('undo'))refreshDump();}
      async function snapshot() {
        const model=dumps[activeDump];if(model.addr==null)return;
        const size=selection?selection.size:256,addr=selection?selection.addr:model.addr;
        const result=await u.analysis('memory_snapshot',{addr,size,label:'Dump '+(activeDump+1)});
        if(result){pendingSnapshot=result.id;$('#memory-baseline').value=String(result.id);toast('Captured '+result.size+' bytes and '+result.strings.length+' strings.');}
      }
      async function compare(result=null,navigate=true) {
        const request=++comparisonRequest;result=result||await u.analysis('memory_compare',{id:comparisonId&&!navigate?comparisonId:$('#memory-baseline').value});if(!result||request!==comparisonRequest)return;comparisonId=result.id;
        const panel=$('#dump-comparison');panel.classList.remove('hidden');panel.innerHTML='<button class="mini" id="close-comparison">Close comparison</button><p>'+result.changed_bytes+' changed bytes'+(result.complete?'':' · partial read')+'</p>'+result.changes.map(r=>`<div class="diff-row"><b>${esc(r.addr)}</b><div class="diff-before">Before ${esc(r.before)}</div><div class="diff-after">After  ${esc(r.after)}</div></div>`).join('')+'<b>New strings</b><pre>'+esc(result.strings_added.map(s=>s.addr+' '+s.text).join('\n')||'(none)')+'</pre>';
        $('#close-comparison').onclick=()=>{comparisonId=null;comparisonRequest++;panel.classList.add('hidden');};
        const baseline=(state.memory_analysis.snapshots||[]).find(s=>s.id===result.id);if(baseline&&navigate)followMemory(baseline.addr);
      }
      function populateModules() {
        const names=(state.modules||[]).map(m=>m[0]);
        ['#symbol-module','#reference-module'].forEach(id=>{const select=$(id),previous=select.value;if(select.dataset.modules===JSON.stringify(names))return;select.dataset.modules=JSON.stringify(names);select.innerHTML=names.map(n=>`<option>${esc(n)}</option>`).join('');if(names.includes(previous))select.value=previous;});
      }
      async function loadSymbols(more) {
        if(!paused())return;
        if(!more){symbols=[];symbolNext=0;}
        const request=++symbolRequest,pid=state.process_id;
        const result=await call('symbols',{query:$('#symbol-search').value,module:$('#symbol-module').value,offset:symbolNext});
        if(!result || request!==symbolRequest || pid!==state.process_id)return;
        symbols=symbols.concat(result.rows).slice(-2000);symbolNext=result.next;$('#symbol-more').disabled=result.complete;$('#symbol-count').textContent=symbols.length+' latest matches · scanned '+result.next+'/'+result.total;
        $('#symbol-table').innerHTML='<thead><tr><th>Symbol</th><th>Address</th><th>Kind</th><th>Actions</th></tr></thead><tbody>'+symbols.map((s,i)=>`<tr><td>${esc(s.name)}</td><td>${hx(s.addr)}</td><td>${esc(s.kind)}</td><td><button class="mini" data-symbol-follow="${i}">Follow</button><button class="mini" data-symbol-refs="${i}">References</button></td></tr>`).join('')+'</tbody>';
        $$('[data-symbol-follow]').forEach(b=>b.onclick=()=>{showView('cpu');const symbol=symbols[+b.dataset.symbolFollow];if(symbol.kind==='data')followMemory(symbol.addr);else u.cmd('follow_disasm',{addr:symbol.addr});});
        $$('[data-symbol-refs]').forEach(b=>b.onclick=()=>openReferences(symbols[+b.dataset.symbolRefs].addr));decorateTables();
      }
      function openReferences(addr=address()) {$('#reference-address').value=hx(addr);showView('references');loadReferences(false);}
      async function loadReferences(more) {
        if(!paused())return;if(!more){references=[];referenceNext=0;}
        $('#find-references').disabled=true;$('#reference-more').disabled=true;
        const result=await call('references',{address:$('#reference-address').value,module:$('#reference-module').value,offset:referenceNext});
        $('#find-references').disabled=false;if(!result)return;
        references=references.concat(result.rows).slice(-4096);referenceNext=result.next;$('#reference-more').disabled=result.complete;
        $('#reference-coverage').textContent=result.coverage+' · '+references.length+' latest matches · '+referenceNext+' bytes scanned'+(result.complete?(result.coverage_complete?' · complete':' · incomplete scan stopped'):' · more code remains');
        $('#reference-table').innerHTML='<thead><tr><th>Address</th><th>Instruction</th><th>Evidence</th></tr></thead><tbody>'+references.map(r=>`<tr data-ref="${r.addr}"><td>${hx(r.addr)}</td><td>${esc(r.mn+' '+r.ops)}</td><td>${esc(r.kind)}</td></tr>`).join('')+'</tbody>';
        $$('[data-ref]').forEach(r=>r.ondblclick=()=>{showView('cpu');u.cmd('follow_disasm',{addr:r.dataset.ref});});decorateTables();
      }
      async function loadGraph(more=false) {if(!paused())return;const result=await call('graph',{address:hx(address()),limit:+$('#graph-limit').value,offset:more===true&&graph?graph.next||0:0});if(result){graph=result;$('#graph-more').disabled=result.next==null;renderGraph();}}
      function renderGraph() {
        if(!graph)return;
        $('#graph-title').textContent=graph.name||'Function graph';$('#graph-coverage').textContent=graph.coverage+(graph.truncated?' · bounded / incomplete function range':'');
        const positions=new Map(),blocks=graph.blocks,known=new Set(blocks.map(b=>b.addr)),levels=new Map();let y=20,canvasWidth=800;
        if(blocks.length){levels.set(blocks[0].addr,0);const queue=[blocks[0].addr];while(queue.length){const from=queue.shift();for(const edge of graph.edges){if(edge.from===from&&known.has(edge.to)&&!levels.has(edge.to)){levels.set(edge.to,levels.get(from)+1);queue.push(edge.to);}}}}
        let lastLevel=Math.max(0,...levels.values());blocks.forEach(b=>{if(!levels.has(b.addr))levels.set(b.addr,++lastLevel);});
        for(let level=0;level<=lastLevel;level++){const group=blocks.filter(b=>levels.get(b.addr)===level);let rowHeight=0;group.forEach((block,index)=>{const height=overview?65:Math.min(320,60+block.instructions.length*20);positions.set(block.addr,{x:30+index*390,y,w:330,h:height});rowHeight=Math.max(rowHeight,height);canvasWidth=Math.max(canvasWidth,390*(index+1));});y+=rowHeight+55;}
        let paths='',html='';
        const pc=state.pc;
        blocks.forEach(block=>{const p=positions.get(block.addr),current=block.instructions.some(i=>i.addr===pc);const notes=graph.edges.filter(e=>e.from===block.addr && (!positions.has(e.to)||e.source!=='decoded')).map(e=>(e.to==null?'unknown target':hx(e.to))+' · '+e.source);
          html+=`<section class="graph-node${current?' current':''}" style="left:${p.x}px;top:${p.y}px;height:${p.h}px"><header data-graph-follow="${block.addr}">${hx(block.addr)}${current?' · PC':''}${block.visits?' · '+block.visits+' recorded instruction visits':''}</header>${overview?'':`<div class="graph-code">${block.instructions.map(i=>`<div data-graph-follow="${i.addr}" class="${i.addr===pc?'current':''}">${esc(i.mn.padEnd(7)+' '+i.ops)}</div>`).join('')}</div>`}<div class="graph-edge-note">${esc(notes.join(' · '))}</div></section>`;
        });
        graph.edges.forEach(edge=>{const a=positions.get(edge.from),b=positions.get(edge.to);if(!a||!b)return;const color=edge.source!=='decoded'?'#d9a4ff':edge.kind==='taken'?'#62d995':edge.kind==='fallthrough'?'#e0ab65':'#70b5ee';const x=a.x+a.w/2,ex=b.x+b.w/2,sy=a.y+a.h,ey=b.y;paths+=`<path d="M${x},${sy} C${x},${sy+25} ${ex},${ey-25} ${ex},${ey}" fill="none" stroke="${color}" stroke-width="${edge.active?4:2}" opacity="${edge.active===false ? 0.35 : 1}" ${edge.source!=='decoded'?'stroke-dasharray="5 4"':''} marker-end="url(#arrow)"/>`;});
        $('#graph-canvas').style.width=canvasWidth+'px';$('#graph-canvas').style.height=(y+20)+'px';$('#graph-canvas').innerHTML=`<svg width="${canvasWidth}" height="${y+20}"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#9eacbd"/></marker></defs>${paths}</svg>`+html;
        $$('[data-graph-follow]').forEach(n=>n.ondblclick=()=>{showView('cpu');u.cmd('follow_disasm',{addr:n.dataset.graphFollow});});
      }
      const ACTIONS=[
        ['time_machine','Time Machine / instruction history',()=>showView('history')],['record_instructions','Record instructions',()=>advanced.startRecording()],['assemble','Assemble at selection',()=>advanced.assemble()],['environment','Signals, child processes and offline connectivity',()=>showView('environment')],
        ['run','Run / continue',()=>u.doAct('cont')],['step_in','Step into',()=>u.doAct('step_in')],['step_over','Step over',()=>u.doAct('step_over')],['step_out','Step out',()=>u.doAct('step_out')],['pause','Pause target',()=>u.cmd('interrupt')],['restart','Restart target',()=>u.cmd('restart')],['open','Open target',()=>u.chooseTarget()],
        ['toggle_bp','Toggle breakpoint',()=>u.doAct('toggle_bp')],['run_to','Run to selection',()=>u.doAct('run_to')],['follow','Follow selected operand',followOperand],['snap_pc','Return to current PC',()=>u.cmd('snap_pc')],['back','Previous code location',()=>u.cmd('navigate_history',{direction:'back'})],['forward','Next code location',()=>u.cmd('navigate_history',{direction:'forward'})],['comment','Add / edit comment',()=>u.editComment(address())],
        ['find','Find text / bytes in memory',()=>u.findInMemory()],['goto','Go to address or symbol',()=>u.focusGoto()],['trace','Toggle API Trace',()=>u.cmd('trace_toggle')],['defenses','Configure defenses',()=>u.openDefenses()],['graph','Graph selected function',()=>showView('graph')],['references','Find references / callers',()=>openReferences()],['symbols','Search symbols',()=>{showView('symbols');$('#symbol-search').focus();}],
        ['watchpoint','Break on write / memory access',()=>editWatchpoint()],['breakpoint_editor','Add conditional breakpoint',()=>editBreakpoint()],['snapshot','Snapshot selected buffer and strings',snapshot],['compare','Compare memory with snapshot',()=>compare()],['undo','Undo last UI edit',undo],['console','Toggle LLDB console',()=>setConsole(!settings.console_open)],['lldb_palette','LLDB command palette',()=>u.rawPalette()],['recent','Recent targets and launch profiles',()=>openRecent()],['settings','Workspace and shortcut settings',()=>openSettings()],['actions','Search application actions',()=>openActions()]
      ];
      function openActions() {
        const dlg=dialog('Application actions','<input class="m-input" id="action-search" placeholder="Try: break on write, snapshot, callers…"/><div id="action-list"></div>');let items=Array.from(ACTIONS),index=0;
        const draw=()=>{$('#action-list').innerHTML=items.map((a,i)=>`<div class="action-row${i===index?' selected':''}" data-action-choice="${i}"><span>${esc(a[1])}</span><small>${esc(keys()[a[0]]||'')}</small></div>`).join('');$$('[data-action-choice]').forEach(n=>n.onclick=()=>{const a=items[+n.dataset.actionChoice];u.closeModal();a[2]();});};
        $('#action-search').oninput=()=>{const words=$('#action-search').value.toLowerCase().split(/\s+/);items=ACTIONS.filter(a=>words.every(w=>(a[0]+' '+a[1]).toLowerCase().includes(w)));index=0;draw();};
        $('#action-search').onkeydown=e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();index=Math.max(0,Math.min(items.length-1,index+(e.key==='ArrowDown'?1:-1)));draw();}if(e.key==='Enter'&&items[index]){e.preventDefault();u.closeModal();items[index][2]();}};
        draw();$('#action-search').focus();
      }
      function openSettings() {
        const dlg=dialog('Workspace settings',`<div class="form-grid"><label>Font size<input class="m-input" type="number" min="10" max="22" id="pref-font" value="${settings.font_size||13}"/></label><label>Console height<input class="m-input" id="pref-console-height" type="number" min="90" max="600" value="${settings.console_height||180}"/></label><label>Shortcut profile<select class="m-input" id="pref-profile"><option value="custom">Current/custom</option><option value="mac">Mac defaults</option><option value="x64">x64dbg-style</option></select></label></div><p class="m-hint">Click a shortcut field and press the desired key combination. Backspace clears a binding; Escape cancels the dialog. Layout and preferences survive app restarts.</p><div class="shortcut-grid">${ACTIONS.filter(a=>a[0] in M.DEFAULT_KEYS).map(a=>`<label>${esc(a[1])}</label><input class="m-input key-binding" readonly data-binding="${a[0]}" value="${esc(keys()[a[0]])}"/>`).join('')}</div>`);
        $$('.key-binding').forEach(input=>input.onkeydown=e=>{if(e.key==='Escape')return;e.preventDefault();e.stopPropagation();if(['Shift','Control','Meta','Alt'].includes(e.key))return;input.value=e.key==='Backspace'?'':M.keyName(e);});
        $('#pref-profile').onchange=()=>{const profile=$('#pref-profile').value==='x64'?M.X64_KEYS:M.DEFAULT_KEYS;$$('.key-binding').forEach(input=>input.value=profile[input.dataset.binding]);};
        button(dlg.foot,'Save',async()=>{const shortcuts={},used=new Set();for(const input of $$('.key-binding')){const expanded=input.value.includes('Mod+')?[input.value.replace('Mod+','Meta+'),input.value.replace('Mod+','Ctrl+')]:[input.value];if(input.value && expanded.some(k=>used.has(k))){dlg.error('Two actions use '+input.value+'. Choose distinct shortcuts.');return;}if(input.value)expanded.forEach(k=>used.add(k));shortcuts[input.dataset.binding]=input.value;}await saveSettings({font_size:+$('#pref-font').value,console_height:+$('#pref-console-height').value,shortcuts});u.closeModal();},'btn primary');
        button(dlg.foot,'Reset layout',()=>saveSettings({left_percent:65,top_percent:60,console_height:180,font_size:13,columns:{}}));
      }
      async function openRecent() {
        const data=await call('preferences');if(!data)return;recent=data.recent;launches=data.launches;
        const dlg=dialog('Recent targets and launch profiles','<h4>Saved profiles</h4><div id="launch-profiles"></div><h4>Recent targets</h4><div id="recent-targets"></div>');
        [['#launch-profiles',launches],['#recent-targets',recent]].forEach(([id,items])=>{const host=$(id);if(!items.length)host.textContent='None yet.';items.forEach(item=>{const row=document.createElement('div');row.className='recent-row';button(row,item.name+' · '+item.path+(item.available===false?' (missing)':''),()=>{u.closeModal();u.openLaunch(item.path,item);},'btn launch-choice');if(id==='#launch-profiles')button(row,'Remove',async()=>{await call('remove_launch',{name:item.name});openRecent();},'mini');host.appendChild(row);});});
        button(dlg.foot,'Open another target…',()=>{u.closeModal();u.chooseTarget();});
      }
      function decorateTables() {
        $$('.table-wrap[data-pane],#tb-breakpoints').forEach(wrap=>{
          if(!wrap.querySelector(':scope > .table-search')){const input=document.createElement('input');input.className='table-search';input.placeholder='Filter this view…';input.oninput=()=>filterTable(wrap,input.value);wrap.prepend(input);}
          filterTable(wrap,wrap.querySelector(':scope > .table-search').value);
        });
        $$('table.grid[id]').forEach(table=>table.querySelectorAll('thead th').forEach((th,index)=>{
          const column=table.id+':'+index,width=(settings.columns||{})[column];if(width)th.style.width=width+'px';
          if(th.querySelector('.column-resize'))return;
          th.onclick=()=>{const body=table.querySelector('tbody');if(!body)return;const ascending=th.dataset.order!=='asc';th.dataset.order=ascending?'asc':'desc';const rows=Array.from(body.rows);rows.sort((a,b)=>{const av=a.cells[index]?.textContent||'',bv=b.cells[index]?.textContent||'';return av.localeCompare(bv,undefined,{numeric:true})*(ascending?1:-1);});rows.forEach(r=>body.appendChild(r));};
          const handle=document.createElement('span');handle.className='column-resize';th.appendChild(handle);handle.onclick=e=>e.stopPropagation();
          handle.onmousedown=e=>{e.preventDefault();e.stopPropagation();const start=e.clientX,width=th.getBoundingClientRect().width;let next=width;const move=ev=>{next=Math.max(35,Math.min(1000,width+ev.clientX-start));th.style.width=next+'px';};const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);saveSettings({columns:{...(settings.columns||{}),[column]:next}});};document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);};
        }));
      }
      function filterTable(wrap,query) {wrap.querySelectorAll('tbody tr').forEach(row=>row.hidden=!row.textContent.toLowerCase().includes(query.toLowerCase()));}
      function handleKey(e) {
        const editable=e.target.matches('input,textarea,[contenteditable]');
        if(e.target.matches('button,select')&&['Enter',' '].includes(e.key))return false;
        if(view==='cpu' && !editable && e.target.closest('#disasm') && ['ArrowUp','ArrowDown'].includes(e.key)) {
          const rows=state.disasm||[],index=rows.findIndex(r=>r.addr===address()),next=rows[Math.max(0,Math.min(rows.length-1,index+(e.key==='ArrowDown'?1:-1)))];if(next){u.select(next.addr);$('#disasm .drow[data-addr="'+next.addr+'"]').scrollIntoView({block:'nearest'});}return true;
        }
        if(!editable && e.target.closest('#memory') && ['PageUp','PageDown'].includes(e.key)){followMemory(Math.max(0,(dumps[activeDump].addr||0)+(e.key==='PageDown'?512:-512)));return true;}
        if(!editable && e.target.closest('#memory') && selection && ['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)){const delta={ArrowLeft:-1,ArrowRight:1,ArrowUp:-(state.memory_width||16),ArrowDown:(state.memory_width||16)}[e.key];chooseByte((e.shiftKey?selection.addr+selection.size-1:selection.addr)+delta,e.shiftKey);return true;}
        if(!editable && e.target.closest('#memory') && /^[\da-f]$/i.test(e.key) && !e.metaKey && !e.ctrlKey && selection && selection.size===1){const cell=$('#memory .byte-cell[data-byte="'+selection.addr+'"]');if(cell)inlineByte(cell,e.key);return true;}
        for(const [name,binding] of Object.entries(keys()))if(M.matches(e,binding)){
          if(editable && !/^F\d+$/.test(e.key) && !['actions','pause','console'].includes(name))return false;
          if(!editable && name==='follow' && e.target.closest('#memory')){editSelection();return true;}
          const action=ACTIONS.find(a=>a[0]===name);if(action){action[2]();return true;}
        }
        return false;
      }
      function wire() {
        const graphLimit=document.createElement('select');graphLimit.id='graph-limit';graphLimit.setAttribute('aria-label','Graph instruction budget');graphLimit.innerHTML='<option value="1024">1,024 instructions</option><option value="4096">4,096 instructions</option><option value="16384">16,384 instructions</option>';$('#graph-refresh').after(graphLimit);graphLimit.onchange=()=>loadGraph();
        button($('#graph-refresh').parentElement,'Next graph range',()=>loadGraph(true),'mini').id='graph-more';
        $('#console-toggle').onclick=()=>setConsole(!settings.console_open);
        $('#actions-button').onclick=openActions;$('#recent-button').onclick=openRecent;$('#settings-button').onclick=openSettings;
        $('#dump-format').onchange=()=>{selection=null;anchor=null;const formats=(settings.dump_formats||['hex','hex','hex','hex']).slice();formats[activeDump]=$('#dump-format').value;saveSettings({dump_formats:formats});renderDump();};
        $('#dump-back').onclick=()=>dumpHistory(-1);$('#dump-forward').onclick=()=>dumpHistory(1);
        $('#dump-edit').onclick=()=>editSelection($('#dump-format').value==='utf16'?'utf16':'hex');$('#undo-edit').onclick=undo;
        $('#snapshot-memory').onclick=snapshot;$('#compare-memory').onclick=()=>compare();
        $('#new-breakpoint').onclick=()=>editBreakpoint();$('#new-watchpoint').onclick=()=>editWatchpoint();
        $('#memory').onmousedown=e=>{const cell=e.target.closest('[data-byte]');if(!cell||e.button!==0||e.target.matches('input'))return;e.preventDefault();$('#memory').focus();chooseByte(+cell.dataset.byte,e.shiftKey);if(!e.shiftKey && cell.dataset.size)chooseByte(+cell.dataset.byte+Number(cell.dataset.size)-1,true);dragging=true;};
        $('#memory').onmouseover=e=>{const cell=e.target.closest('[data-byte]');if(dragging&&cell)chooseByte(+cell.dataset.byte,true);};document.addEventListener('mouseup',()=>dragging=false);
        $('#memory').ondblclick=e=>{const pointer=e.target.closest('[data-pointer]');if(pointer){followMemory(pointer.dataset.pointer);return;}const cell=e.target.closest('.byte-cell,.ascii-cell');if(cell){e.preventDefault();inlineByte(cell);}};
        $('#memory').onscroll=()=>dumps[activeDump].scroll=$('#memory').scrollTop;
        $('#symbol-search').oninput=()=>{clearTimeout(refreshTimer);refreshTimer=setTimeout(()=>loadSymbols(false),180);};$('#symbol-module').onchange=()=>loadSymbols(false);$('#symbol-more').onclick=()=>loadSymbols(true);
        $('#find-references').onclick=()=>loadReferences(false);$('#reference-more').onclick=()=>loadReferences(true);
        $('#graph-refresh').onclick=loadGraph;$('#graph-overview').onclick=()=>{overview=!overview;renderGraph();};$('#graph-zoom').oninput=()=>$('#graph-canvas').style.transform='scale('+$('#graph-zoom').value/100+')';
        $$('.workspace-split').forEach(split=>split.onmousedown=e=>{e.preventDefault();const box=$('#cpu-workspace').getBoundingClientRect(),top=split.dataset.drag==='top';let value;const move=event=>{value=Math.max(30,Math.min(80,100*(top?event.clientY-box.top:event.clientX-box.left)/(top?box.height:box.width)));document.documentElement.style.setProperty(top?'--cpu-top':'--cpu-left',value+'%');};const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);if(value!=null)saveSettings({[top?'top_percent':'left_percent']:value});};document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);});
      }
      function dumpHistory(direction){const m=dumps[activeDump],next=m.index+direction;if(next<0||next>=m.history.length)return;m.index=next;m.addr=m.history[next];lastFollow=m.addr;u.cmd('follow_mem',{addr:m.addr});refreshDump();}
      function onState(next) {
        const changed=!state||state.process_id!==next.process_id;state=next;
        if(changed){dumps.forEach(m=>{m.addr=null;m.data=null;m.history=[];m.index=-1;m.request++;m.scroll=0;});selection=null;anchor=null;lastFollow=null;infoRequest++;symbolRequest++;graph=null;comparisonId=null;comparisonRequest++;$('#dump-comparison').classList.add('hidden');}
        if(next.memory && next.memory.follow!==lastFollow){lastFollow=next.memory.follow;M.historyPush(dumps[activeDump],lastFollow);}
        if(paused()) {
          if(dumps[activeDump].addr==null)M.historyPush(dumps[activeDump],state.pc);
          refreshDump();refreshStack();populateModules();
          if(address()===state.pc)renderInfo(state.instruction_info);else selected(address());
          renderBreakpoints();if(view==='graph')loadGraph();
          if(comparisonId){if((state.memory_analysis.snapshots||[]).some(s=>s.id===comparisonId))compare(null,false);else{comparisonId=null;$('#dump-comparison').classList.add('hidden');}}
        }
        if(pendingSnapshot && (state.memory_analysis.snapshots||[]).some(s=>s.id===pendingSnapshot)){$('#memory-baseline').value=String(pendingSnapshot);pendingSnapshot=null;}
        ['#dump-edit','#snapshot-memory'].forEach(id=>$(id).disabled=!paused());
        renderHistory();decorateTables();
        advanced.onState(next);
      }
      async function mount(){advanced.mount();wire();const data=await call('preferences');if(data){settings=data.settings;recent=data.recent;launches=data.launches;applySettings();}showView('cpu');if(u.state())onState(u.state());}
      return {copySelection,mount,onState,showView,selectDump,followMemory,selected,operand,followOperand,handleKey,openActions,openSettings,openRecent,editBreakpoint,editWatchpoint,editSelection,compare,toast,
        editRegisterValue:(name,value)=>call('edit_register',{name,value}),references:openReferences,editMemoryAt:(addr,kind)=>{if(!selection||addr<selection.addr||addr>=selection.addr+selection.size)chooseByte(addr);return editSelection(kind==='ascii'?'ascii':'hex');},
        pinChanged:pins=>saveSettings({pinned_registers:pins}),
        saveLaunch:async item=>{const name=await u.promptDialog({title:'Save launch profile',value:item.path.split('/').pop()});if(name){await call('save_launch',{...item,name});u.openLaunch(item.path,item);toast('Launch profile saved.');}},
        running:()=>{if(state)state={...state,process_state:'running'};advanced.running();['#dump-edit','#snapshot-memory','#undo-edit','#compare-memory'].forEach(id=>$(id).disabled=true);$('#dump-selection').textContent='Last captured bytes — target running';infoRequest++;stackRequest++;comparisonRequest++;dumps.forEach(d=>d.request++);},
        shortcut:name=>keys()[name]||''};
    }
  };
})();
