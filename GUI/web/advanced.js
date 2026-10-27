/* Historical inspection, assembly and controlled environment simulation. */
(function () {
  'use strict';
  window.MacdbgAdvanced = {create(u) {
    const $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
    const esc=u.esc, trace=(action,args={})=>u.cmdSync('instruction_trace',{action,...args});
    const work=(action,args={})=>u.cmdSync('workspace',{action,...args});
    let mounted=false, view='', state=null, page=0, next=0, cursor=0, total=0, request=0, selected=null;
    let historyPath=null,selectionRequest=0;
    function resultPath(result) {
      if(!result)return;
      const dlg=u.dialog('Saved file',`<p class="file-path">${esc(result.path)}</p>${result.note?`<p class="m-hint">${esc(result.note)}</p>`:''}`);
      u.button(dlg.foot,'Copy path',()=>u.copy(result.path));
      if(result.jsonl)u.button(dlg.foot,'Copy complete JSONL path',()=>u.copy(result.jsonl));
    }
    function status(result) {
      if(!result||!mounted)return;
      if(result.path!==historyPath){historyPath=result.path;page=0;next=0;cursor=0;selected=null;selectionRequest++;$('#history-detail').textContent='Select a record to inspect its historical state.';}
      total=result.total||0;
      $('#history-status').textContent=(result.recording?'Recording':'History')+' · '+total+' records'+(result.automatic?' · auto-stepping':'')+(result.error?' · '+result.error:'');
      $('#history-coverage').textContent=result.coverage||'';
      $('#history-file').textContent=result.path||'No recording yet';
      $('#history-position').max=Math.max(total,1);
      $('#history-stop').disabled=!result.recording;
      $('#history-export').disabled=!total;
    }
    async function loadHistory(offset=0) {
      if(!mounted)return;
      const token=++request;
      const result=await trace('query',{offset,limit:100,text:$('#history-search').value,address:$('#history-address').value||null,access:$('#history-access').value||null});
      if(!result||token!==request)return;
      status(result);page=offset;next=result.next;
      $('#history-more').disabled=result.complete;
      $('#history-page-back').disabled=offset===0;
      $('#history-table').innerHTML='<thead><tr><th>#</th><th>Thread</th><th>PC</th><th>Instruction / event</th><th>Result</th></tr></thead><tbody>'+result.rows.map(row=>`<tr data-record="${row.n}" class="${row.n===cursor?'selected':''}"><td>${row.n}</td><td>${row.thread||'—'}</td><td>${esc(row.pc||'—')}</td><td>${esc(row.type==='instruction'?row.mnemonic+' '+row.operands:row.category+' · '+row.message)}</td><td>${esc(row.outcome||'event')}</td></tr>`).join('')+'</tbody>';
      $$('#history-table [data-record]').forEach(row=>row.onclick=()=>selectRecord(+row.dataset.record));
      if(!cursor&&result.rows.length)selectRecord(result.rows[0].n);
    }
    async function selectRecord(index) {
      if(index<1||index>total)return;
      const token=++selectionRequest,path=historyPath;
      const result=await trace('read',{index});if(!result||token!==selectionRequest||path!==historyPath)return;
      cursor=index;selected=result;
      $('#history-position').value=index;$('#history-index').textContent=index+' / '+total;
      $('#history-prev').disabled=index<=1;$('#history-next').disabled=index>=total;
      $$('#history-table [data-record]').forEach(row=>row.classList.toggle('selected',+row.dataset.record===index));
      $('#history-live').disabled=!result.pc||!u.paused();
      const instruction=result.type==='instruction';
      const registers=Object.entries(result.registers||{});
      const registerTable=entries=>'<table class="grid"><thead><tr><th>Register</th><th>Before</th><th>After</th></tr></thead><tbody>'+entries.map(([name,value])=>`<tr class="${result.changes?.[name]?'trace-changed':''}"><td>${esc(name)}</td><td>${esc(value)}</td><td>${esc(result.changes?.[name]?.after||value)}</td></tr>`).join('')+'</tbody></table>';
      $('#history-detail').innerHTML=instruction?
        `<div class="historical-banner">RECORDED STATE · ${esc(result.outcome)} · ${esc(result.timestamp)}<br/>${esc(result.note||'Browsing this record does not change the live process.')}</div><h3>${esc(result.pc+'  '+result.mnemonic+' '+result.operands)}</h3><p>${esc(result.module||'')} · ${esc(result.symbol||'')}<br/>Next PC: ${esc(result.next_pc||'unverified')} · bytes: ${esc(result.bytes||'')}${result.branch?'<br/>Branch: '+(result.branch.taken==null?'unverified':result.branch.taken?'taken':'not taken'):''}</p><h4>Register changes</h4>${registerTable(registers.filter(([name])=>result.changes?.[name]))}<h4>Captured memory</h4><p class="m-hint">${esc(result.memory_coverage||'')}</p>${(result.memory||[]).map(m=>`<div class="history-memory"><b>${esc(m.access)} ${esc(m.address)} · ${m.size} bytes</b><pre>before: ${esc(m.before||'unreadable')}${m.complete_before?'':' (partial)'}\nafter:  ${esc(m.after||'unavailable')}${m.complete_after?'':' (partial/unverified)'}</pre></div>`).join('')}<details><summary>All ${registers.length} recorded registers before → after</summary>${registerTable(registers)}</details>`:
        `<div class="historical-banner">RECORDED EVENT · ${esc(result.timestamp)}</div><pre>${esc(JSON.stringify(result,null,2))}</pre>`;
    }
    async function startRecording() {
      if(!u.paused()){u.toast('Pause the target to start recording.');return;}
      const dlg=u.dialog('Record instructions',`<p>Manual single steps and Trace Run are recorded to a verbose JSONL file. Continue creates an explicit gap.</p><div class="form-grid"><label>Maximum records<input class="m-input" id="record-count" type="number" min="1" max="100000" value="100000"/></label><label><input type="checkbox" id="record-vectors" checked/> Capture SIMD registers</label><label>Additional buffer address<input class="m-input" id="record-range" placeholder="Optional numeric address"/></label><label>Buffer bytes<input class="m-input" id="record-size" type="number" min="1" max="4096" value="256"/></label></div><p class="m-hint">Existing recordings stay on disk. The new recording becomes the active history.</p>`);
      u.button(dlg.foot,'Start recording',async()=>{
        const address=$('#record-range').value.trim();
        const result=await trace('start',{max_records:+$('#record-count').value,vectors:$('#record-vectors').checked,ranges:address?[{address,size:+$('#record-size').value}]:[]});
        if(result){cursor=0;selected=null;status(result);u.closeModal();u.showView('history');}
        else dlg.error('Recording could not start. See the console error.');
      },'btn primary');
    }
    async function traceRun() {
      const until=$('#trace-until').value.trim();
      const result=await u.cmd('instruction_trace_run',{count:+$('#trace-count').value,seconds:+$('#trace-seconds').value,until:until||null});
      if(result)u.toast('Tracing until the limit, stop address, breakpoint or exception. Pause cancels.');
    }
    async function assemble() {
      if(!u.paused()){u.toast('Pause the target before assembling.');return;}
      let token=null;
      const dlg=u.dialog('Assemble ARM64',`<div class="form-grid"><label>Address or symbol<input class="m-input" id="assembly-address" value="${esc(u.hx(u.address()))}"/></label><label>Replacement span (optional NOP fill)<input class="m-input" id="assembly-size" type="number" min="4" max="4096" step="4" placeholder="Exact assembled length"/></label></div><textarea class="m-input assembly-source" id="assembly-source" spellcheck="false" placeholder="mov w0, #1&#10;ret"></textarea><p class="m-hint">Branch, ADR/ADRP and literal-load destinations are absolute addresses, symbols or local labels. Preview before applying.</p><pre id="assembly-preview"></pre>`);
      const apply=u.button(dlg.foot,'Apply preview',async()=>{if(await work('assemble_apply',{token})){u.closeModal();u.toast('Assembly applied. Undo is available until execution resumes.');}},'btn primary');apply.disabled=true;
      ['#assembly-source','#assembly-address','#assembly-size'].forEach(id=>$(id).oninput=()=>{token=null;apply.disabled=true;});
      u.button(dlg.foot,'Preview',async()=>{
        const result=await work('assemble_preview',{address:$('#assembly-address').value,source:$('#assembly-source').value,size:$('#assembly-size').value||null});
        if(!result){token=null;apply.disabled=true;dlg.error('Assembly failed. See the compiler diagnostic in the console.');return;}
        token=result.token;apply.disabled=false;dlg.error('');
        $('#assembly-preview').textContent='Original: '+result.original+'\nNew:      '+result.new+'\n\n'+result.instructions.map(i=>i.address+'  '+i.mnemonic+' '+i.operands).join('\n');
      });
      $('#assembly-source').focus();
    }
    async function exportPatches(manifestOnly) {
      const dlg=u.dialog(manifestOnly?'Export patch manifest':'Export patched binary',`<label>New output path (blank uses the sample dumps directory)<input class="m-input" id="patch-output" placeholder="Never overwrites an existing file"/></label>${manifestOnly?'':'<label><input type="checkbox" id="patch-sign" checked/> Ad-hoc sign the exported copy</label><p class="m-hint">Changes invalidate the vendor signature. Ad-hoc signing does not restore vendor trust or entitlements.</p>'}`);
      u.button(dlg.foot,'Export',async()=>{const result=await work('patch_export',{path:$('#patch-output').value||null,sign:manifestOnly?false:$('#patch-sign').checked,manifest_only:manifestOnly});if(result){u.closeModal();resultPath(result);}else dlg.error('Export refused. See the console for the conflicting patch or file.');},'btn primary');
    }
    async function importPatches() {
      const path=await u.promptDialog({title:'Import patch manifest',placeholder:'Absolute path to a saved patch JSON file'});if(!path)return;
      const preview=await work('patch_import',{path,apply:false});if(!preview)return;
      const dlg=u.dialog('Apply verified patch set',`<p>${preview.patches.length} patch ranges match this binary and its current bytes.</p><pre>${esc(JSON.stringify(preview.patches,null,2))}</pre>`);
      u.button(dlg.foot,'Apply patches',async()=>{if(await work('patch_import',{path,apply:true})){u.closeModal();u.toast('Patch set applied. Use Patches to revert it.');}},'btn primary');
    }
    async function environment() {
      if(!u.paused()){$('#environment-status').textContent='Pause the target to inspect signal policies and configure simulation.';return;}
      const token=++environmentRequest;
      const [signals,processes,network,monitor]=await Promise.all([
        u.analysis('signal_policy'),u.analysis('related_processes'),u.analysis('offline_network'),u.analysis('syscall_monitor')]);
      if(token!==environmentRequest)return;
      $('#environment-status').textContent='Policies affect this debug session. Simulation is opt-in.';
      if(signals){$('#signal-coverage').textContent=signals.coverage;$('#signal-table').innerHTML='<thead><tr><th>Signal</th><th>Stop</th><th>Deliver</th><th>Notify</th></tr></thead><tbody>'+signals.signals.map(row=>`<tr><td>${esc(row.name)}</td>${['stop','deliver','notify'].map(key=>`<td><input type="checkbox" data-signal="${row.number}" data-policy="${key}" ${row[key]?'checked':''} ${row.editable?'':'disabled'} aria-label="${esc(row.name+' '+key)}"/></td>`).join('')}</tr>`).join('')+'</tbody>';
        $$('#signal-table input').forEach(input=>input.onchange=async()=>{await u.analysis('signal_policy',{signal:+input.dataset.signal,[input.dataset.policy]:input.checked});environment();});}
      if(processes){$('#process-coverage').textContent=processes.coverage;$('#process-table').innerHTML='<thead><tr><th>PID</th><th>Parent</th><th>State</th><th>Executable</th><th></th></tr></thead><tbody>'+processes.processes.map(p=>`<tr><td>${p.pid}</td><td>${p.parent}</td><td>${esc(p.state)}</td><td>${esc(p.path)}</td><td>${p.pid!==processes.root?`<button class="mini" data-child="${p.pid}">Debug in new window</button>`:'Current target'}</td></tr>`).join('')+'</tbody>';$$('#process-table [data-child]').forEach(b=>b.onclick=async()=>{const result=await u.cmdSync('debug_child',{pid:+b.dataset.child});if(result)u.toast(result.note);});}
      if(network){$('#network-status').textContent=(network.enabled?'Enabled':'Disabled')+' · '+network.coverage;$('#network-disable').disabled=!network.enabled;$('#network-enable').disabled=network.enabled;if(network.enabled)$('#network-rules').textContent=network.rules.map(r=>r.host+':'+r.port+' → local '+(r.tls?'HTTPS':'HTTP')+' '+r.status).join('\n');else $('#network-rules').textContent='';}
      if(monitor){$('#syscall-status').textContent=(monitor.enabled?'Enabled · '+monitor.sites+' sites':'Disabled')+' · '+monitor.coverage;$('#syscall-toggle').textContent=monitor.enabled?'Disable automatic scan':'Monitor new executable code';$('#syscall-toggle').onclick=async()=>{await u.analysis('syscall_monitor',{enabled:!monitor.enabled});environment();};$('#syscall-regions').textContent=monitor.regions.map(r=>r.address+' · '+r.bytes+' bytes · '+r.omitted+' omitted'+(r.error?' · '+r.error:'')).join('\n');}
    }
    let environmentRequest=0;
    function mount() {
      mounted=true;
      $('#tb-history').innerHTML=`<div class="view-toolbar"><button class="mini" id="history-record">Record…</button><button class="mini" id="history-stop">Stop recording</button><button class="mini" id="history-open">Open saved trace…</button><button class="mini" id="history-export">Export LLM context…</button><span id="history-status">No recording</span></div><div class="view-toolbar"><label>Steps <input id="trace-count" type="number" min="1" max="100000" value="1000"/></label><label>Seconds <input id="trace-seconds" type="number" min="1" max="300" value="30"/></label><input id="trace-until" placeholder="Stop at address (optional)"/><button class="mini" id="history-run">Trace Run</button><button class="mini" id="history-pause">Pause</button></div><div class="m-hint" id="history-coverage"></div><div class="file-path" id="history-file"></div><div class="view-toolbar"><input id="history-search" placeholder="Search instructions, values, symbols…"/><input id="history-address" placeholder="PC or memory address"/><select id="history-access" aria-label="Memory access filter"><option value="">All records</option><option value="read">Memory reads</option><option value="write">Memory writes</option><option value="snapshot">Captured ranges</option></select><button class="mini" id="history-find">Find</button><button class="mini" id="history-writer">Previous observed write</button></div><div class="history-layout"><div class="history-list"><div class="scroll"><table class="grid" id="history-table"></table></div><div class="view-toolbar"><button class="mini" id="history-page-back">Previous page</button><button class="mini" id="history-more">Next scan/page</button></div></div><div class="history-inspector"><div class="view-toolbar"><button class="mini" id="history-prev">← Record</button><input type="range" min="1" max="1" value="1" id="history-position" aria-label="Historical record"/><button class="mini" id="history-next">Record →</button><span id="history-index"></span><button class="mini" id="history-live">Follow address in live CPU</button></div><div class="scroll" id="history-detail"><p>Record steps or open an existing JSONL trace. Historical registers and memory stay separate from the live CPU.</p></div></div></div>`;
      $('#tb-environment').innerHTML=`<div class="view-toolbar"><button class="mini" id="environment-refresh">Refresh</button><span id="environment-status"></span></div><div class="scroll environment-sections"><section><h3>Offline connectivity</h3><p id="network-status" class="m-hint"></p><div class="form-grid"><label>Domains (one per line)<textarea class="m-input" id="network-hosts" placeholder="connectivity.example.test"></textarea></label><label>Response body<textarea class="m-input" id="network-body">online</textarea></label><label>HTTP status<input class="m-input" id="network-code" type="number" value="200" min="200" max="599"/></label><label>Destination port<input class="m-input" id="network-port" type="number" value="80" min="1" max="65535"/></label></div><label><input id="network-tls" type="checkbox"/> HTTPS responder (target must trust its certificate)</label><div class="form-grid"><label>TLS certificate PEM path<input class="m-input" id="network-cert" placeholder="/path/to/server.crt"/></label><label>TLS private key PEM path<input class="m-input" id="network-key" placeholder="/path/to/server.key"/></label></div><label><input id="network-reachability" type="checkbox"/> Report connectivity through supported reachability APIs</label><div class="view-toolbar"><button class="mini" id="network-enable">Enable simulation</button><button class="mini" id="network-disable">Disable simulation</button></div><pre id="network-rules"></pre></section><section><h3>Executable-memory syscall coverage</h3><p id="syscall-status" class="m-hint"></p><button class="mini" id="syscall-toggle">Monitor new executable code</button><pre id="syscall-regions"></pre></section><section><h3>Related processes</h3><p id="process-coverage" class="m-hint"></p><table class="grid" id="process-table"></table></section><section><h3>Native signal delivery</h3><p id="signal-coverage" class="m-hint"></p><table class="grid" id="signal-table"></table></section></div>`;
      const patchTools=document.createElement('div');patchTools.className='view-toolbar';$('#tb-patches').prepend(patchTools);
      u.button(patchTools,'Assemble at selection…',assemble,'mini');u.button(patchTools,'Export patched binary…',()=>exportPatches(false),'mini');u.button(patchTools,'Export manifest…',()=>exportPatches(true),'mini');u.button(patchTools,'Import manifest…',importPatches,'mini');
      const assembleButton=document.createElement('button');assembleButton.className='mini';assembleButton.textContent='Assemble';assembleButton.onclick=assemble;$('#disasm-status').parentElement.appendChild(assembleButton);
      $('#history-record').onclick=startRecording;$('#history-run').onclick=traceRun;$('#history-pause').onclick=()=>u.cmd('interrupt');
      $('#history-stop').onclick=async()=>{const r=await trace('stop');status(r);loadHistory(page);};
      $('#history-find').onclick=()=>loadHistory(0);$('#history-search').onkeydown=e=>{if(e.key==='Enter')loadHistory(0);};
      $('#history-more').onclick=()=>loadHistory(next);$('#history-page-back').onclick=()=>loadHistory(Math.max(0,page-100));
      $('#history-prev').onclick=()=>selectRecord(cursor-1);$('#history-next').onclick=()=>selectRecord(cursor+1);$('#history-position').onchange=()=>selectRecord(+$('#history-position').value);
      $('#history-live').onclick=()=>{if(selected?.pc&&u.paused()){u.cmd('follow_disasm',{addr:selected.pc});u.showView('cpu');}};
      $('#history-writer').onclick=async()=>{const address=$('#history-address').value;if(!address){u.toast('Enter a memory address to find a previous observed write.');return;}const r=await trace('query',{address,access:'write',before:cursor||total+1,limit:1});if(r?.rows.length)selectRecord(r.rows[0].n);else u.toast(r?.complete?'No earlier observed write in this recording.':'No match in the previous 5,000 records; use paged memory-write search to scan further.');};
      $('#history-open').onclick=async()=>{const path=await u.promptDialog({title:'Open instruction recording',placeholder:'Absolute path to instructions-….jsonl'});if(path){const r=await trace('open',{path});if(r){cursor=0;status(r);loadHistory();}}};
      $('#history-export').onclick=()=>{const dlg=u.dialog('Export LLM context',`<p>The report includes binary/module provenance, full register snapshots, captured bytes and debugger interventions. The complete verbose JSONL is already saved.</p><div class="form-grid"><label>First record<input class="m-input" id="export-first" type="number" min="1" value="${cursor||1}"/></label><label>Record count<input class="m-input" id="export-count" type="number" min="1" max="10000" value="1000"/></label></div>`);u.button(dlg.foot,'Export context log',async()=>{const r=await trace('export',{start:+$('#export-first').value,count:+$('#export-count').value});if(r){u.closeModal();resultPath(r);}},'btn primary');};
      $('#environment-refresh').onclick=environment;
      $('#network-port').onchange=()=>{$('#network-tls').checked=+$('#network-port').value===443;};
      $('#network-enable').onclick=async()=>{const tls=$('#network-tls').checked;const rules=$('#network-hosts').value.split(/\s+/).filter(Boolean).map(host=>({host,status:+$('#network-code').value,port:+$('#network-port').value,body:$('#network-body').value,tls,...(tls?{tls_cert:$('#network-cert').value.trim(),tls_key:$('#network-key').value.trim()}:{})}));await u.analysis('offline_network',{enabled:true,rules,reachability:$('#network-reachability').checked});environment();};
      $('#network-disable').onclick=async()=>{await u.analysis('offline_network',{enabled:false});environment();};
    }
    return {mount,assemble,startRecording,show(name){view=name;if(!mounted)return;if(name==='history')loadHistory(page);if(name==='environment')environment();},
      onState(nextState){const changed=!state||state.process_id!==nextState.process_id;state=nextState;status(state.instruction_trace);if(view==='history')loadHistory(page);if(view==='environment'&&changed)environment();if(['exited','detached','invalid','crashed'].includes(state.process_state)){$('#network-status').textContent='Target ended. Offline connectivity simulation stopped.';$('#network-rules').textContent='';}['#history-record','#history-run','#network-enable','#syscall-toggle'].forEach(id=>$(id).disabled=!u.paused());},
      running(){if(!mounted)return;['#history-record','#history-run','#history-live','#network-enable','#network-disable','#syscall-toggle'].forEach(id=>$(id).disabled=true);}};
  }};
})();
