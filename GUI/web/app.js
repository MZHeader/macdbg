/* macdbg GUI front-end.
 *
 * Subscribes to the backend SSE stream (GET /events), renders every panel from
 * the `state` snapshot, and dispatches user actions as POST /cmd. Framework-free
 * and self-contained (WKWebView / offline). The backend contract is defined by
 * GUI/server/engine.py + snapshot.py — this file only consumes it.
 */
(function () {
  'use strict';

  // ---- tiny helpers --------------------------------------------------------
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const hx = n => (n == null ? '' : '0x' + Math.trunc(Number(n)).toString(16));
  const pad = (s, n) => { s = String(s == null ? '' : s); return s.length >= n ? s : s + ' '.repeat(n - s.length); };
  const near = el => el.scrollHeight - el.scrollTop - el.clientHeight < 40;

  async function cmd(name, args) {
    try {
      const r = await fetch('/cmd', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, args: args || {} })
      });
      return await r.json();
    } catch (e) { return { ok: false, error: String(e) }; }
  }
  async function cmdSync(name, args) { const r = await cmd(name, args); return r && r.ok ? r.result : null; }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { /* clipboard may be blocked in webview; ignore */ }
  }

  // ---- global state --------------------------------------------------------
  let lastState = null;
  let selDisasm = null;   // address of the single-clicked disassembly line
  let traceRows = [];
  const traceFilter = { FILE: true, NET: true, PROC: true };
  const cmdHistory = [];
  let histIdx = -1;
  const startTime = Date.now();

  // ===========================================================================
  //  SSE
  // ===========================================================================
  function connect() {
    const es = new EventSource('/events');
    es.onmessage = ev => { let m; try { m = JSON.parse(ev.data); } catch (e) { return; } dispatch(m); };
    es.onerror = () => { /* EventSource auto-reconnects */ };
  }

  function dispatch(m) {
    switch (m.t) {
      case 'state': onState(m); break;
      case 'console': appendConsole(m.text, m.error); break;
      case 'trace': addTrace(m); break;
      case 'trace_clear': clearTrace(); break;
      case 'running': onRunning(); break;
      case 'meta': onMeta(m); break;
      case 'prompt': onPrompt(m); break;
      case 'ui': handleUiAction(m.action); break;
    }
  }

  // ===========================================================================
  //  render: full state snapshot
  // ===========================================================================
  function onState(st) {
    lastState = st;
    renderDisasm(st);
    renderRegs(st);
    renderHex($('#memory'), st.memory);
    renderHex($('#stack'), st.stack);
    for (let i = 1; i <= 3; i++) renderWatch(i, (st.watches || [])[i - 1]);
    renderBreakpoints(st.breakpoints || []);
    renderCallstack(st.backtrace || []);
    renderThreads(st.threads || []);
    renderModules(st.modules || []);
    renderStrings(st.strings || []);
    renderPatches(st.patches || []);
    renderTraceStatus(st.trace_status);

    // follow / status
    const mem = st.memory;
    $('#mem-follow-info').textContent = mem ? (hx(mem.follow) + (mem.search ? '  · ' + mem.search : '')) : '';
    let kind = 'none';
    if (st.has_process) kind = st.running ? 'running' : 'paused';
    if (st.has_process && !st.pc && !st.running) kind = 'paused';
    setStatus(kind, st.pc, st.modules);
    // `meta` fires once before the webview connects; recover the target name
    // from the main module for subscribers that missed it.
    const mt = $('#menu-target');
    if ((mt.textContent === '—' || !mt.textContent) && st.modules && st.modules.length)
      mt.textContent = String(st.modules[0][0] || '').split('/').pop() || '—';
    if (defensesOpen) rebuildDefenses();
  }

  function onRunning() { setStatus('running', lastState && lastState.pc, lastState && lastState.modules); }
  function onMeta(m) { $('#menu-target').textContent = m.target ? m.target.split('/').pop() : (m.attach ? 'pid ' + m.attach : '—'); }

  function setStatus(kind, pc, modules) {
    const pill = $('#state-pill'), bar = $('.statusbar'), msg = $('#st-msg');
    pill.className = 'pill pill-' + kind;
    bar.className = 'statusbar s-' + kind;
    pill.textContent = { none: 'No process', paused: 'Paused', running: 'Running', exited: 'Exited' }[kind] || kind;
    msg.textContent = { none: 'no process — open a target or attach', paused: 'paused', running: 'running…', exited: 'process exited' }[kind] || kind;
    $('#st-addr').textContent = pc ? 'PC ' + hx(pc) : '';
    const triple = (modules && modules[0] && modules[0][3]) || '';
    $('#st-triple').textContent = triple;
  }

  // ---- disassembly ---------------------------------------------------------
  function renderDisasm(st) {
    const rows = st.disasm || [];
    let html = '';
    for (const r of rows) {
      if (r.func) html += `<div class="funchead">▼ ${esc(r.func)}:</div>`;
      const gut = (r.gutter || []).map(g => `<span class="${g[1]}">${esc(g[0])}</span>`).join('');
      const pcmk = r.pc ? '<span class="mk mk-pc">▶</span>' : '<span class="mk"> </span>';
      const bpmk = r.bp ? `<span class="mk ${r.bp_on ? 'mk-bp-on' : 'mk-bp-off'}">${r.bp_on ? '●' : '○'}</span>`
        : '<span class="mk"> </span>';
      const ops = (r.ops || []).map(o => `<span class="${o[1]}">${esc(o[0])}</span>`).join('');
      const opsRaw = (r.ops || []).map(o => o[0]).join('');
      let tail = '';
      if (r.comment) tail += ` <span class="d-comment">; ${esc(r.comment)}</span>`;
      if (r.hint) tail += ` <span class="d-hint">${esc(r.hint)}</span>`;
      if (r.note) tail += ` <span class="d-note">← ${esc(r.note)}</span>`;
      html += `<div class="drow${r.pc ? ' is-pc' : ''}${r.addr === selDisasm ? ' sel' : ''}" data-addr="${r.addr}" data-ops="${esc(opsRaw)}">`
        + `<span class="gutter">${gut}</span>${pcmk}${bpmk}`
        + `<span class="d-addr">${hx(r.addr)}</span>`
        + `<span class="d-bytes">${esc(pad(r.bytes, 11))}</span>`
        + `<span class="d-insn"><span class="${r.mn_cls}">${esc(pad(r.mn, 7))}</span> ${ops}${tail}</span>`
        + '</div>';
    }
    const el = $('#disasm');
    el.innerHTML = html || '<div class="empty-note">no code — launch or attach to a target</div>';
    // center: on browse-center if set, else on pc
    let target = st.disasm_center != null ? el.querySelector(`.drow[data-addr="${st.disasm_center}"]`) : null;
    if (!target) target = el.querySelector('.drow.is-pc');
    if (target) target.scrollIntoView({ block: 'center' });
    $('#disasm-status').textContent = st.disasm_center != null
      ? 'browsing ' + hx(st.disasm_center) + ' · F5 to snap to PC'
      : (selDisasm != null ? 'selected ' + hx(selDisasm) : '');
  }

  // ---- registers + flags ---------------------------------------------------
  function renderRegs(st) {
    const el = $('#regs');
    el.innerHTML = (st.registers || []).map(r => {
      const annot = r.annot ? ` <span class="r-annot">${esc(r.annot)}</span>` : '';
      return `<div class="rrow${r.changed ? ' changed' : ''}" data-reg="${esc(r.name)}" data-val="${esc(r.value)}">`
        + `<span class="r-name">${esc(r.name)}</span><span class="r-val">${esc(r.value)}</span>${annot}</div>`;
    }).join('') || '<div class="empty-note">no registers</div>';
    renderFlags(st);
  }

  // flag bit layouts (the engine doesn't ship a decode, so mirror the TUI's)
  const FLAGS = {
    cpsr: [['N', 31], ['Z', 30], ['C', 29], ['V', 28]],
    rflags: [['CF', 0], ['PF', 2], ['AF', 4], ['ZF', 6], ['SF', 7], ['TF', 8], ['IF', 9], ['DF', 10], ['OF', 11]]
  };
  function renderFlags(st) {
    const el = $('#flags');
    let reg = null, layout = null;
    for (const r of (st.registers || [])) {
      const n = r.name.toLowerCase();
      if (FLAGS[n]) { reg = r; layout = FLAGS[n]; break; }
    }
    if (!reg) { el.innerHTML = ''; return; }
    let val;
    try { val = parseInt(reg.value, 16); } catch (e) { val = 0; }
    if (isNaN(val)) val = 0;
    el.innerHTML = `<span class="dim mono">${esc(reg.name)}</span>` + layout.map(([name, bit]) => {
      const set = (val >> bit) & 1;
      return `<span class="flagbit${set ? ' set' : ''}" data-reg="${esc(reg.name)}" data-bit="${bit}" title="bit ${bit} — click to flip">${name} ${set}</span>`;
    }).join('');
  }

  // ---- hex views -----------------------------------------------------------
  function hexSpans(row, width, focus) {
    let out = '';
    const h = row.hex || '';
    for (let j = 0; j < width; j++) {
      const tok = h.substr(j * 3, 2);
      const sep = j < width - 1 ? ' ' : '';
      const a = row.addr + j;
      if (focus && tok.trim() && a >= focus.addr && a < focus.addr + focus.len) out += `<span class="foc">${tok}</span>` + sep;
      else out += tok + sep;
    }
    return out;
  }
  function asciiSpans(row, focus) {
    let out = '';
    const s = row.ascii || '';
    for (let j = 0; j < s.length; j++) {
      const a = row.addr + j, c = esc(s[j]);
      out += (focus && a >= focus.addr && a < focus.addr + focus.len) ? `<span class="foc">${c}</span>` : c;
    }
    return out;
  }
  function renderHex(el, block, header) {
    if (!block) { el.innerHTML = '<div class="empty-note">no data</div>'; return; }
    let html = header ? `<div class="hrow"><span class="dim">${esc(header)}</span></div>` : '';
    for (const row of block.rows || []) {
      html += `<div class="hrow" data-addr="${row.addr}" data-hex="${esc(row.hex)}">`
        + `<span class="h-addr">${hx(row.addr)}</span>`
        + `<span class="h-hex">${hexSpans(row, block.width, block.focus)}</span>`
        + `<span class="h-ascii">${asciiSpans(row, block.focus)}</span></div>`;
    }
    el.innerHTML = html;
  }
  function renderWatch(slot, w) {
    const el = $('#watch' + slot);
    if (!w) {
      el.innerHTML = `<div class="watch-empty">Watch ${slot} is empty.<br>`
        + `<button class="btn" data-watchpin="${slot}">Pin an address…</button></div>`;
      return;
    }
    const hdr = `Watch ${slot} @ ${hx(w.addr)} (${w.len}B)${w.label ? ' — ' + w.label : ''}`;
    renderHex(el, w, hdr);
  }

  // ---- tables --------------------------------------------------------------
  function tbl(id, head, body, empty) {
    const t = $('#' + id);
    if (!body) { t.innerHTML = `<tr><td class="empty-note">${esc(empty || 'nothing')}</td></tr>`; return; }
    t.innerHTML = `<thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${body}</tbody>`;
  }
  function renderBreakpoints(rows) {
    tbl('bp-table', ['#', 'address', 'symbol', 'cmds', 'condition', 'en'],
      rows.map(r => `<tr data-bpid="${r[0]}" data-addr="${esc(r[1])}"><td>${r[0]}</td>`
        + `<td class="c-addr">${esc(r[1])}</td><td class="c-sym">${esc(r[2])}</td>`
        + `<td class="c-cmds">${r[3] || ''}</td><td class="c-cond">${esc(r[4])}</td>`
        + `<td class="${r[5] ? 'c-en-on' : 'c-en-off'}">${r[5] ? '✓' : '×'}</td></tr>`).join(''),
      'no breakpoints — F2 at PC, or double-click a disasm line');
  }
  function renderCallstack(rows) {
    tbl('cs-table', ['#', 'pc', 'function', 'module'],
      rows.map(r => `<tr data-addr="${esc(r[1])}"><td class="c-dim">${r[0]}</td>`
        + `<td class="c-addr">${esc(r[1])}</td><td class="c-sym">${esc(r[2])}</td>`
        + `<td class="c-dim">${esc(r[3])}</td></tr>`).join(''), 'no frames');
  }
  function renderThreads(rows) {
    tbl('th-table', ['tid', '#', 'name', 'pc', 'function'],
      rows.map(r => {
        const sel = String(r[2]).startsWith('*');
        return `<tr class="${sel ? 'sel-thread' : ''}" data-tid="${esc(r[0])}" data-addr="${esc(r[3])}">`
          + `<td>${esc(r[0])}</td><td class="c-dim">${r[1]}</td><td>${esc(r[2])}</td>`
          + `<td class="c-addr">${esc(r[3])}</td><td class="c-sym">${esc(r[4])}</td></tr>`;
      }).join(''), 'no threads');
  }
  function renderModules(rows) {
    tbl('mod-table', ['name', 'base', 'size', 'triple'],
      rows.map(r => `<tr data-addr="${esc(r[1])}"><td class="c-sym">${esc(r[0])}</td>`
        + `<td class="c-addr">${esc(r[1])}</td><td class="c-dim">${esc(r[2])}</td>`
        + `<td class="c-dim">${esc(r[3])}</td></tr>`).join(''), 'no modules');
  }
  function renderStrings(rows) {
    tbl('str-table', ['src', 'address', 'len', 'string'],
      rows.map(r => `<tr data-addr="${esc(r[1])}" data-str="${esc(r[3])}"><td class="src-${r[0]}">${esc(r[0])}</td>`
        + `<td class="c-addr">${esc(r[1])}</td><td class="c-dim">${r[2]}</td>`
        + `<td class="c-str">${esc(r[3])}</td></tr>`).join(''),
      'no strings — right-click → Rescan, or run the target');
  }
  function renderPatches(rows) {
    tbl('patch-table', ['#', 'address', 'original', 'patched', 'size'],
      rows.map(r => `<tr data-patchidx="${r[0]}" data-addr="${esc(r[1])}" data-orig="${esc(r[2])}"><td class="c-dim">${r[0]}</td>`
        + `<td class="c-addr">${esc(r[1])}</td><td class="c-orig">${esc(r[2])}</td>`
        + `<td class="c-new">${esc(r[3])}</td><td class="c-dim">${r[4]}</td></tr>`).join(''), 'no patches');
  }

  // ---- trace ---------------------------------------------------------------
  function renderTraceStatus(ts) {
    if (!ts) return;
    $('#tracer-state').textContent = ts.on ? 'ON' : 'off';
    $('#tb-tracer').classList.toggle('active', !!ts.on);
    $('#scope-label').textContent = ts.scope || '';
    $('#trace-info').textContent = `tracer ${ts.on ? 'ON' : 'off'} · scope: ${ts.scope}`;
  }
  function addTrace(m) {
    traceRows.push(m);
    $('#trace-badge').textContent = String(m.n);
    if (traceFilter[m.cat] !== false) appendTraceRow(m, near($('#trace-scroll')));
  }
  function appendTraceRow(m, stick) {
    const tb = $('#trace-table');
    if (!tb.querySelector('thead')) tb.innerHTML = '<thead><tr><th>#</th><th>cat</th><th>call</th></tr></thead><tbody></tbody>';
    const body = tb.querySelector('tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="c-dim">${m.n}</td><td class="tcat-${esc(m.cat)}">${esc(m.cat)}</td><td>${esc(m.call)}</td>`;
    tr.dataset.call = m.call;
    body.appendChild(tr);
    if (stick) $('#trace-scroll').scrollTop = $('#trace-scroll').scrollHeight;
  }
  function rebuildTrace() {
    $('#trace-table').innerHTML = '';
    for (const m of traceRows) if (traceFilter[m.cat] !== false) appendTraceRow(m, false);
    $('#trace-scroll').scrollTop = $('#trace-scroll').scrollHeight;
  }
  function clearTrace() { traceRows = []; $('#trace-table').innerHTML = ''; $('#trace-badge').textContent = '0'; }

  // ---- console -------------------------------------------------------------
  function appendConsole(text, error) {
    const el = $('#console');
    const stick = near(el);
    const div = document.createElement('span');
    div.className = 'cl' + (error ? ' cl-err' : '');
    div.textContent = text.replace(/\n$/, '');
    el.appendChild(div);
    if (stick) el.scrollTop = el.scrollHeight;
  }
  function echoConsole(text) {
    const el = $('#console'), stick = near(el);
    const s = document.createElement('span');
    s.className = 'cl cl-echo'; s.textContent = 'lldb> ' + text;
    el.appendChild(s);
    if (stick) el.scrollTop = el.scrollHeight;
  }

  // ===========================================================================
  //  actions
  // ===========================================================================
  function doAct(act) {
    if (act === 'open') return cmd('pick_file');
    if (act === 'attach') return openAttach();
    if (act === 'stop') return cmd('run_cmd', { cmd: 'process kill' });
    if (act === 'defenses') return openDefenses();
    // breakpoint / origin actions honour the selected disasm line, else the PC
    if (act === 'toggle_bp') return cmd('toggle_bp', selDisasm != null ? { addr: selDisasm } : {});
    if (act === 'set_pc') { if (selDisasm != null) cmd('set_pc', { addr: selDisasm }); return; }
    if (act === 'run_to') { if (selDisasm != null) cmd('run_to', { addr: selDisasm }); return; }
    return cmd(act);
  }
  function selectDisasm(addr) {
    selDisasm = addr;
    $$('#disasm .drow').forEach(r => r.classList.toggle('sel', +r.dataset.addr === addr));
    if (!lastState || lastState.disasm_center == null) $('#disasm-status').textContent = 'selected ' + hx(addr);
  }
  function opAddr(rowEl, fallback) {
    const ops = rowEl.dataset.ops || '';
    const m = ops.match(/0x[0-9a-fA-F]+/);
    return m ? m[0] : fallback;
  }
  function focusGoto() { $('#goto').focus(); $('#goto').select(); }
  async function findInMemory() {
    const v = await promptDialog({ title: 'Find in Memory', placeholder: 'ASCII text, 0x… hex, or "all:" to scan libraries', hint: 'Empty + ⌘F cycles to the next hit.' });
    if (v !== null) cmd('search', { text: v });
  }

  // ===========================================================================
  //  toolbar / tabs / inputs wiring
  // ===========================================================================
  function wireChrome() {
    $$('.tb[data-act]').forEach(b => b.onclick = () => doAct(b.dataset.act));

    $$('#mem-tabs .tab').forEach(t => t.onclick = () => {
      $$('#mem-tabs .tab').forEach(x => x.classList.toggle('active', x === t));
      const which = t.dataset.memtab;
      ['memory', 'stack', 'watch1', 'watch2', 'watch3'].forEach(p => $('#' + p).classList.toggle('hidden', p !== which));
      $('#mem-addrbar').classList.toggle('hidden', which !== 'memory');
    });
    $$('#bot-tabs .tab').forEach(t => t.onclick = () => selectBottomTab(t.dataset.bottab));

    // goto (browse disasm) — numeric => follow_disasm, else lldb symbol lookup
    $('#goto').addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const v = e.target.value.trim(); if (!v) return;
      if (/^(0x[0-9a-f]+|\d+)$/i.test(v)) cmd('follow_disasm', { addr: v });
      else cmd('run_cmd', { cmd: 'image lookup -rn ' + v });
      e.target.blur();
    });
    // memory follow address bar
    $('#mem-addr').addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const v = e.target.value.trim(); if (!v) return;
      cmd('follow_mem', { addr: v }); e.target.value = '';
    });
    // trace category filters
    $$('.tt-filter input').forEach(cb => cb.onchange = () => {
      traceFilter[cb.closest('.tt-filter').dataset.cat] = cb.checked; rebuildTrace();
    });
    $$('.trace-toolbar .mini[data-act]').forEach(b => b.onclick = () => cmd(b.dataset.act));

    // watch pin buttons (delegated)
    document.addEventListener('click', e => {
      const p = e.target.closest('[data-watchpin]');
      if (p) pinWatch(+p.dataset.watchpin);
    });
    // flag flips (delegated)
    $('#flags').addEventListener('click', e => {
      const f = e.target.closest('.flagbit');
      if (f) cmd('flip_flag', { reg: f.dataset.reg, bit: +f.dataset.bit });
    });

    wireConsole();
    wireContextMenus();
    wireRowActivate();
    wireSplitters();
    renderKeybar();
  }

  function selectBottomTab(name) {
    $$('#bot-tabs .tab').forEach(x => x.classList.toggle('active', x.dataset.bottab === name));
    ['breakpoints', 'callstack', 'threads', 'modules', 'strings', 'patches', 'trace']
      .forEach(p => $('#tb-' + p).classList.toggle('hidden', p !== name));
  }

  // double-click a disasm line toggles a breakpoint; a table pc row follows it
  function wireRowActivate() {
    $('#disasm').addEventListener('click', e => {
      const row = e.target.closest('.drow'); if (!row) return;
      if (!window.getSelection().isCollapsed) return;   // don't steal a text drag-select
      selectDisasm(+row.dataset.addr);
    });
    $('#disasm').addEventListener('dblclick', e => {
      const row = e.target.closest('.drow'); if (row) { selectDisasm(+row.dataset.addr); cmd('toggle_bp', { addr: +row.dataset.addr }); }
    });
    ['#cs-table', '#th-table', '#mod-table'].forEach(sel => {
      $(sel).addEventListener('dblclick', e => {
        const tr = e.target.closest('tr'); if (tr && tr.dataset.addr) cmd('follow_disasm', { addr: tr.dataset.addr });
      });
    });
    $('#bp-table').addEventListener('dblclick', e => {
      const tr = e.target.closest('tr'); if (tr && tr.dataset.addr) cmd('follow_disasm', { addr: tr.dataset.addr });
    });
    $('#str-table').addEventListener('dblclick', e => {
      const tr = e.target.closest('tr'); if (tr && tr.dataset.addr) cmd('follow_mem', { addr: tr.dataset.addr });
    });
  }

  async function pinWatch(slot) {
    const addr = await promptDialog({ title: 'Pin Watch ' + slot, placeholder: 'address / expression' });
    if (addr === null || !addr.trim()) return;
    const label = await promptDialog({ title: 'Watch ' + slot + ' label (optional)', placeholder: 'label' });
    cmd('watch_set', { slot: slot, addr: addr.trim(), len: 32, label: label || '' });
  }

  // ---- console input: history + Tab completion -----------------------------
  function wireConsole() {
    const inp = $('#cmd'), comp = $('#completions');
    let items = [], sel = -1;
    const hideComp = () => { comp.classList.add('hidden'); items = []; sel = -1; };
    const drawComp = () => {
      comp.innerHTML = items.map((c, i) =>
        `<div class="citem${i === sel ? ' sel' : ''}" data-i="${i}"><span>${esc(c.match)}</span><span class="cdesc">${esc(c.desc || '')}</span></div>`).join('');
      comp.classList.toggle('hidden', !items.length);
    };
    comp.addEventListener('click', e => {
      const it = e.target.closest('.citem'); if (!it) return;
      inp.value = items[+it.dataset.i].cmd; hideComp(); inp.focus();
    });
    inp.addEventListener('keydown', async e => {
      if (!comp.classList.contains('hidden')) {
        if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, items.length - 1); drawComp(); return; }
        if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); drawComp(); return; }
        if (e.key === 'Escape') { e.preventDefault(); hideComp(); return; }
        if ((e.key === 'Enter' || e.key === 'Tab') && sel >= 0) { e.preventDefault(); inp.value = items[sel].cmd; hideComp(); return; }
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        const res = await cmdSync('complete', { text: inp.value });
        items = res || []; sel = items.length ? 0 : -1; drawComp(); return;
      }
      if (e.key === 'Enter') {
        const v = inp.value.trim(); if (!v) return;
        echoConsole(v); cmd('run_cmd', { cmd: v });
        cmdHistory.push(v); histIdx = cmdHistory.length; inp.value = ''; hideComp(); return;
      }
      if (e.key === 'ArrowUp') { if (histIdx > 0) { histIdx--; inp.value = cmdHistory[histIdx] || ''; } e.preventDefault(); return; }
      if (e.key === 'ArrowDown') { if (histIdx < cmdHistory.length) { histIdx++; inp.value = cmdHistory[histIdx] || ''; } e.preventDefault(); return; }
    });
    inp.addEventListener('blur', () => setTimeout(hideComp, 150));
  }

  // ===========================================================================
  //  context menus
  // ===========================================================================
  const ctx = $('#ctxmenu');
  function closeCtx() { ctx.classList.add('hidden'); ctx.innerHTML = ''; }
  function showCtx(x, y, items, header) {
    let html = header ? `<div class="cx-header">${esc(header)}</div>` : '';
    items.forEach((it, i) => {
      if (it.sep) html += '<div class="cx-sep"></div>';
      else if (it.section) html += `<div class="cx-section">${esc(it.section)}</div>`;
      else html += `<div class="cx-item${it.danger ? ' danger' : ''}" data-i="${i}">`
        + `<span class="cx-check">${it.check ? '✓' : ''}</span>${esc(it.label)}</div>`;
    });
    ctx.innerHTML = html;
    ctx.classList.remove('hidden');
    const w = ctx.offsetWidth, h = ctx.offsetHeight;
    ctx.style.left = Math.min(x, window.innerWidth - w - 6) + 'px';
    ctx.style.top = Math.min(y, window.innerHeight - h - 6) + 'px';
    ctx.querySelectorAll('.cx-item').forEach(el => el.onclick = () => {
      const it = items[+el.dataset.i]; closeCtx(); if (it && it.fn) it.fn();
    });
  }

  function wireContextMenus() {
    const on = (sel, builder) => $(sel).addEventListener('contextmenu', e => {
      e.preventDefault();
      const items = builder(e);
      if (items && items.length) showCtx(e.clientX, e.clientY, items, items._header);
    });

    on('#disasm', e => {
      const row = e.target.closest('.drow'); if (!row) return [];
      const addr = +row.dataset.addr, oa = opAddr(row, addr);
      selectDisasm(addr);
      return [
        { label: 'Follow operand in Disassembly', fn: () => cmd('follow_disasm', { addr: oa }) },
        { label: 'Follow operand in Memory', fn: () => cmd('follow_mem', { addr: oa }) },
        { sep: 1 },
        { label: 'Toggle breakpoint here', fn: () => cmd('toggle_bp', { addr: addr }) },
        { label: 'Set PC to here (jump execution)', fn: () => cmd('set_pc', { addr: addr }) },
        { label: 'Run to cursor', fn: () => cmd('run_to', { addr: addr }) },
        { sep: 1 },
        { label: 'Add / edit comment…', fn: () => editComment(addr) },
        { label: 'Copy address', fn: () => copy(hx(addr)) },
        { sep: 1 },
        { label: 'Pin to Watch 1', fn: () => cmd('watch_set', { slot: 1, addr: addr, len: 32 }) },
        { label: 'Pin to Watch 2', fn: () => cmd('watch_set', { slot: 2, addr: addr, len: 32 }) },
        { label: 'Pin to Watch 3', fn: () => cmd('watch_set', { slot: 3, addr: addr, len: 32 }) }
      ];
    });

    on('#regs', e => {
      const row = e.target.closest('.rrow'); if (!row) return [];
      const name = row.dataset.reg, val = row.dataset.val;
      return [
        { label: 'Follow value in Disassembly', fn: () => cmd('follow_disasm', { addr: val }) },
        { label: 'Follow value in Memory', fn: () => cmd('follow_mem', { addr: val }) },
        { label: 'Breakpoint at value', fn: () => cmd('toggle_bp', { addr: val }) },
        { sep: 1 },
        { label: 'Edit value…', fn: () => editReg(name, val) },
        { label: 'Copy value', fn: () => copy(val) },
        { sep: 1 },
        { label: 'Pin value to Watch 1', fn: () => cmd('watch_set', { slot: 1, addr: val, len: 32 }) },
        { label: 'Pin value to Watch 2', fn: () => cmd('watch_set', { slot: 2, addr: val, len: 32 }) },
        { label: 'Pin value to Watch 3', fn: () => cmd('watch_set', { slot: 3, addr: val, len: 32 }) }
      ];
    });

    const hexMenu = e => {
      const row = e.target.closest('.hrow'); if (!row || !row.dataset.addr) return [];
      const addr = +row.dataset.addr, qw = parseQword(row.dataset.hex);
      const items = [
        { label: 'Follow in Disassembly', fn: () => cmd('follow_disasm', { addr: addr }) }
      ];
      if (qw) items.push({ label: 'Follow pointer here (' + qw + ')', fn: () => cmd('follow_mem', { addr: qw }) });
      items.push(
        { label: 'Edit bytes here…', fn: () => editBytes(addr) },
        { sep: 1 },
        { label: 'Set watchpoint on this address…', fn: () => setWatchAt(addr) },
        { label: 'Pin to Watch 1', fn: () => cmd('watch_set', { slot: 1, addr: addr, len: 32 }) },
        { label: 'Pin to Watch 2', fn: () => cmd('watch_set', { slot: 2, addr: addr, len: 32 }) },
        { label: 'Pin to Watch 3', fn: () => cmd('watch_set', { slot: 3, addr: addr, len: 32 }) },
        { sep: 1 },
        { label: 'Copy address', fn: () => copy(hx(addr)) },
        { label: 'Copy row (hex)', fn: () => copy(row.dataset.hex) }
      );
      return items;
    };
    on('#memory', hexMenu); on('#stack', hexMenu);
    ['#watch1', '#watch2', '#watch3'].forEach(sel => $(sel).addEventListener('contextmenu', e => {
      e.preventDefault();
      const slot = +$(sel).dataset.slot;
      let items = hexMenu(e); if (!items.length) items = [];
      items.push({ sep: 1 }, { label: 'Change watch ' + slot + ' length…', fn: () => changeWatchLen(slot) },
        { label: 'Clear watch ' + slot, danger: true, fn: () => cmd('watch_clear', { slot: slot }) });
      showCtx(e.clientX, e.clientY, items);
    }));

    on('#bp-table', e => {
      const tr = e.target.closest('tr'); if (!tr || !tr.dataset.bpid) return [];
      const id = +tr.dataset.bpid;
      return [
        { label: 'Toggle enabled', fn: () => cmd('bp_enable', { id: id }) },
        { label: 'Set condition…', fn: () => editCondition(id) },
        { label: 'Edit commands…', fn: () => editBpCommands(id) },
        { sep: 1 },
        { label: 'Follow in Disassembly', fn: () => cmd('follow_disasm', { addr: tr.dataset.addr }) },
        { label: 'Delete breakpoint', danger: true, fn: () => cmd('bp_delete', { id: id }) }
      ];
    });

    on('#cs-table', e => {
      const tr = e.target.closest('tr'); if (!tr || !tr.dataset.addr) return [];
      return [{ label: 'Follow in Disassembly', fn: () => cmd('follow_disasm', { addr: tr.dataset.addr }) },
      { label: 'Follow in Memory', fn: () => cmd('follow_mem', { addr: tr.dataset.addr }) },
      { label: 'Copy address', fn: () => copy(tr.dataset.addr) }];
    });
    on('#th-table', e => {
      const tr = e.target.closest('tr'); if (!tr) return [];
      return [{ label: 'Follow PC in Disassembly', fn: () => cmd('follow_disasm', { addr: tr.dataset.addr }) },
      { label: 'Copy tid', fn: () => copy(tr.dataset.tid) }];
    });
    on('#mod-table', e => {
      const tr = e.target.closest('tr'); if (!tr) return [];
      return [{ label: 'Follow base in Memory', fn: () => cmd('follow_mem', { addr: tr.dataset.addr }) },
      { label: 'Copy base', fn: () => copy(tr.dataset.addr) }];
    });
    on('#str-table', e => {
      const tr = e.target.closest('tr'); if (!tr) return [
        { label: 'Rescan heap/stack for strings', fn: () => cmd('scan_strings') }];
      return [{ label: 'Follow in Memory', fn: () => cmd('follow_mem', { addr: tr.dataset.addr }) },
      { label: 'Follow in Disassembly', fn: () => cmd('follow_disasm', { addr: tr.dataset.addr }) },
      { label: 'Copy address', fn: () => copy(tr.dataset.addr) },
      { label: 'Copy string', fn: () => copy(tr.dataset.str) },
      { sep: 1 }, { label: 'Rescan heap/stack for strings', fn: () => cmd('scan_strings') }];
    });
    on('#patch-table', e => {
      const tr = e.target.closest('tr'); if (!tr || !tr.dataset.addr) return [];
      return [{ label: 'Follow in Memory', fn: () => cmd('follow_mem', { addr: tr.dataset.addr }) },
      { label: 'Revert (write original bytes)', fn: () => cmd('write_mem', { addr: tr.dataset.addr, bytes: tr.dataset.orig }) },
      { label: 'Copy address', fn: () => copy(tr.dataset.addr) }];
    });
    on('#trace-table', e => {
      const tr = e.target.closest('tr');
      return [
        tr && tr.dataset.call ? { label: 'Copy this call', fn: () => copy(tr.dataset.call) } : null,
        { label: 'Copy all trace rows', fn: () => copy(traceRows.map(r => `${r.n}\t${r.cat}\t${r.call}`).join('\n')) },
        { label: 'Clear trace', fn: () => cmd('trace_clear') }
      ].filter(Boolean);
    });

    document.addEventListener('click', closeCtx);
    document.addEventListener('scroll', closeCtx, true);
  }

  function parseQword(hexStr) {
    if (!hexStr) return null;
    const t = hexStr.trim().split(/\s+/).slice(0, 8);
    if (t.length < 8 || t.some(x => x.length !== 2)) return null;
    return '0x' + t.reverse().join('');
  }

  // context-menu action helpers (dialogs)
  async function editComment(addr) {
    const cur = commentAt(addr);
    const t = await promptDialog({ title: 'Comment @ ' + hx(addr), value: cur, placeholder: 'comment (empty to clear)' });
    if (t !== null) cmd('comment', { addr: addr, text: t });
  }
  function commentAt(addr) {
    const rows = (lastState && lastState.disasm) || [];
    const r = rows.find(x => x.addr === addr);
    return r ? (r.note || '') : '';
  }
  async function editReg(name, val) {
    const v = await promptDialog({ title: 'Set ' + name, value: val, placeholder: 'new value (0x… or decimal)' });
    if (v !== null && v.trim()) cmd('write_reg', { name: name, value: v.trim() });
  }
  async function editBytes(addr) {
    const v = await promptDialog({ title: 'Write bytes @ ' + hx(addr), placeholder: '90 90  or  0x9090' });
    if (v !== null && v.trim()) cmd('write_mem', { addr: addr, bytes: v.trim() });
  }
  async function setWatchAt(addr) {
    const s = await promptDialog({ title: 'Set watchpoint', value: hx(addr), placeholder: 'address', hint: 'Runs `watchpoint set expression`.' });
    if (s !== null && s.trim()) cmd('run_cmd', { cmd: 'watchpoint set expression -- ' + s.trim() });
  }
  async function changeWatchLen(slot) {
    const w = (lastState && lastState.watches || [])[slot - 1];
    if (!w) return;
    const v = await promptDialog({ title: 'Watch ' + slot + ' length', value: String(w.len), placeholder: 'bytes' });
    if (v !== null && v.trim()) cmd('watch_set', { slot: slot, addr: w.addr, len: +v.trim() || 32, label: w.label || '' });
  }
  async function editCondition(id) {
    const v = await promptDialog({ title: 'Breakpoint #' + id + ' condition', placeholder: 'e.g. $x0 == 0  (empty to clear)' });
    if (v !== null) cmd('bp_condition', { id: id, cond: v });
  }
  async function editBpCommands(id) {
    const v = await promptDialog({ title: 'Breakpoint #' + id + ' commands', multiline: true, placeholder: 'one lldb command per line', hint: 'Runs each line when the breakpoint hits.' });
    if (v !== null) cmd('bp_commands', { id: id, commands: v.split('\n').map(s => s).filter(s => s.trim().length) });
  }

  // ===========================================================================
  //  modal dialogs
  // ===========================================================================
  const backdrop = $('#modal-backdrop');
  let modalKeyHandler = null;
  function openModal(node, onKey) {
    backdrop.innerHTML = ''; backdrop.appendChild(node); backdrop.classList.remove('hidden');
    modalKeyHandler = onKey || null;
  }
  function closeModal() { backdrop.classList.add('hidden'); backdrop.innerHTML = ''; modalKeyHandler = null; }
  backdrop.addEventListener('mousedown', e => { if (e.target === backdrop) closeModal(); });

  function el(tag, cls, html) { const n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; }

  function promptDialog(opts) {
    return new Promise(resolve => {
      const m = el('div', 'modal');
      m.innerHTML = `<div class="m-head">${esc(opts.title || 'Input')}</div>`;
      const body = el('div', 'm-body');
      const input = opts.multiline ? el('textarea', 'm-input') : el('input', 'm-input');
      if (!opts.multiline) input.type = 'text';
      input.value = opts.value || '';
      input.placeholder = opts.placeholder || '';
      body.appendChild(input);
      if (opts.hint) body.appendChild(el('div', 'm-hint', esc(opts.hint)));
      m.appendChild(body);
      const foot = el('div', 'm-foot');
      const ok = el('button', 'btn primary', 'OK'), cancel = el('button', 'btn', 'Cancel');
      foot.appendChild(cancel); foot.appendChild(ok); m.appendChild(foot);
      const done = v => { closeModal(); resolve(v); };
      ok.onclick = () => done(input.value);
      cancel.onclick = () => done(null);
      openModal(m, e => {
        if (e.key === 'Escape') { e.preventDefault(); done(null); }
        else if (e.key === 'Enter' && (!opts.multiline || e.metaKey || e.ctrlKey)) { e.preventDefault(); done(input.value); }
      });
      setTimeout(() => { input.focus(); input.select && input.select(); }, 30);
    });
  }

  // ---- defenses toggle dialog ---------------------------------------------
  let defensesOpen = false;
  const DEF_SECTIONS = [
    ['Anti-debug', [
      ['all_anti', 'Enable ALL anti-debug bypasses', 'ptrace · sysctl · csops · mach · parent · sigtrap · timing · direct-syscall'],
      ['deny_attach', 'Defeat PT_DENY_ATTACH', 'libc ptrace hook + inline svc #0x80 scan'],
      ['mach', 'Cloak Mach exception ports', 'report none — look unattached'],
      ['flag_scrubs', 'Scrub debugger flags', 'P_TRACED (sysctl) + CS_DEBUGGED (csops)'],
      ['parent', 'Cloak parent identity', 'scrub debugger name from KERN_PROC'],
      ['sigtrap', 'Forward self-trap to SIGTRAP handler', 'brk #0 → target’s handler'],
      ['timing', 'Cloak timing', 'fake monotonic clocks (slower)']
    ]],
    ['Breakpoints', [
      ['hw_bps', 'Hardware breakpoints for your BPs', 'no __TEXT patch'],
      ['tracer_hw', 'Hardware breakpoints for the tracer', 'set before enabling the tracer']
    ]],
    ['Forks', [
      ['fork_identity', 'Fork intercept: fake fork/vfork→0 & setsid', 'run the child path in-process'],
      ['fork_interactive', 'Prompt on each fork', 'stay in parent vs enter child'],
      ['fork_trace', 'Trace the whole fork tree', 'DYLD interpose — relaunches the target']
    ]],
    ['Exec', [
      ['exec_sandbox', 'Sandbox exec/spawn', 'intercept system/popen/exec/posix_spawn'],
      ['exec_interactive', 'Prompt on each exec', 'Allow / Fake / Block / Dump']
    ]]
  ];
  function openDefenses() {
    defensesOpen = true;
    const m = el('div', 'modal');
    m.innerHTML = '<div class="m-head">Defenses <span class="m-sub">anti-anti-debug bypasses — click to toggle</span></div>';
    const body = el('div', 'm-body'); body.id = 'def-body'; m.appendChild(body);
    const foot = el('div', 'm-foot'); const close = el('button', 'btn', 'Close');
    close.onclick = () => { defensesOpen = false; closeModal(); }; foot.appendChild(close); m.appendChild(foot);
    openModal(m, e => { if (e.key === 'Escape') { defensesOpen = false; closeModal(); } });
    rebuildDefenses();
  }
  function rebuildDefenses() {
    const body = $('#def-body'); if (!body) return;
    const st = (lastState && lastState.trace_status && lastState.trace_status.defenses) || {};
    let html = '';
    for (const [title, rows] of DEF_SECTIONS) {
      html += `<div class="toggle-section">${esc(title)}</div><div class="toggle-list">`;
      for (const [key, label, sub] of rows) {
        const on = !!st[key];
        html += `<div class="toggle-row${on ? ' on' : ''}" data-key="${key}"><div class="tg-box"></div>`
          + `<div class="tg-text"><b>${esc(label)}</b><span>${esc(sub)}</span></div></div>`;
      }
      html += '</div>';
    }
    body.innerHTML = html;
    body.querySelectorAll('.toggle-row').forEach(r => r.onclick = () => {
      const key = r.dataset.key;
      if (key === 'fork_trace') cmd('fork_trace'); else cmd('defense', { key: key });
      // optimistic flip; the next state refresh corrects it
      r.classList.toggle('on');
    });
  }

  // ---- exec / fork decision dialogs (from `prompt` events) -----------------
  function onPrompt(m) {
    if (m.kind === 'exec') {
      const dlg = el('div', 'modal');
      dlg.innerHTML = `<div class="m-head">exec intercepted <span class="m-sub">${esc(m.name)}</span></div>`
        + `<div class="m-body"><div class="mono" style="white-space:pre-wrap;word-break:break-word">${esc(m.cmd || '')}</div>`
        + (m.caller ? `<div class="m-hint">caller @ ${hx(m.caller)}</div>` : '') + '</div>';
      const foot = el('div', 'm-foot');
      const mk = (lbl, dec, cls) => { const b = el('button', 'btn ' + (cls || ''), lbl); b.onclick = () => { cmd('decide_exec', { decision: dec }); if (dec !== 'dump') closeModal(); }; return b; };
      foot.appendChild(mk('Block', 'block', 'danger'));
      foot.appendChild(mk('Dump payload', 'dump'));
      foot.appendChild(mk('Fake success', 'fake'));
      foot.appendChild(mk('Allow (run)', 'allow', 'primary'));
      dlg.appendChild(foot);
      openModal(dlg, e => { if (e.key === 'Escape') { cmd('decide_exec', { decision: 'block' }); closeModal(); } });
    } else if (m.kind === 'fork') {
      const dlg = el('div', 'modal');
      dlg.innerHTML = `<div class="m-head">fork intercepted <span class="m-sub">${esc(m.name)}</span></div>`
        + `<div class="m-body">Follow the parent (real fork, child runs untraced) or enter the child path in-process?`
        + (m.caller ? `<div class="m-hint">caller @ ${hx(m.caller)}</div>` : '') + '</div>';
      const foot = el('div', 'm-foot');
      const mk = (lbl, dec, cls) => { const b = el('button', 'btn ' + (cls || ''), lbl); b.onclick = () => { cmd('decide_fork', { decision: dec }); closeModal(); }; return b; };
      foot.appendChild(mk('Stay in parent', 'parent'));
      foot.appendChild(mk('Enter child', 'child', 'primary'));
      dlg.appendChild(foot);
      openModal(dlg, e => { if (e.key === 'Escape') { cmd('decide_fork', { decision: 'parent' }); closeModal(); } });
    }
  }

  // ---- attach picker -------------------------------------------------------
  async function openAttach() {
    const procs = await cmdSync('list_processes') || [];
    const m = el('div', 'modal');
    m.innerHTML = '<div class="m-head">Attach to Process</div>';
    const body = el('div', 'm-body');
    const filter = el('input', 'm-input pick-filter'); filter.placeholder = 'filter by name or pid';
    const list = el('div', 'pick-list');
    body.appendChild(filter); body.appendChild(list); m.appendChild(body);
    const foot = el('div', 'm-foot'); const cancel = el('button', 'btn', 'Cancel'); cancel.onclick = closeModal; foot.appendChild(cancel); m.appendChild(foot);
    let sel = 0, shown = procs;
    const draw = () => {
      list.innerHTML = shown.slice(0, 400).map((p, i) =>
        `<div class="pick-row${i === sel ? ' sel' : ''}" data-i="${i}"><span class="pk-pid">${p.pid}</span><span>${esc(p.name)}</span></div>`).join('');
      list.querySelectorAll('.pick-row').forEach(r => r.onclick = () => { cmd('attach', { pid: shown[+r.dataset.i].pid }); closeModal(); });
    };
    filter.oninput = () => {
      const q = filter.value.toLowerCase();
      shown = procs.filter(p => String(p.pid).includes(q) || p.name.toLowerCase().includes(q)); sel = 0; draw();
    };
    openModal(m, e => {
      if (e.key === 'Escape') closeModal();
      else if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, shown.length - 1); draw(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
      else if (e.key === 'Enter' && shown[sel]) { cmd('attach', { pid: shown[sel].pid }); closeModal(); }
    });
    draw(); setTimeout(() => filter.focus(), 30);
  }

  // ---- command palette -----------------------------------------------------
  function openPalette() {
    const m = el('div', 'modal');
    m.innerHTML = '<div class="m-head">Command Palette <span class="m-sub">lldb — Enter to run</span></div>';
    const body = el('div', 'm-body');
    const input = el('input', 'm-input pick-filter'); input.placeholder = 'type an lldb command…';
    const list = el('div', 'pick-list'); body.appendChild(input); body.appendChild(list); m.appendChild(body);
    let items = [], sel = 0;
    const draw = () => {
      list.innerHTML = items.slice(0, 200).map((c, i) =>
        `<div class="pick-row${i === sel ? ' sel' : ''}" data-i="${i}"><span>${esc(c.match)}</span><span class="cdesc dim">${esc(c.desc || '')}</span></div>`).join('');
      list.querySelectorAll('.pick-row').forEach(r => r.onclick = () => { input.value = items[+r.dataset.i].cmd; input.focus(); });
    };
    let timer = null;
    input.oninput = () => {
      clearTimeout(timer);
      timer = setTimeout(async () => { items = await cmdSync('complete', { text: input.value }) || []; sel = 0; draw(); }, 120);
    };
    const run = () => { const v = (sel >= 0 && items[sel]) ? items[sel].cmd : input.value; if (v && v.trim()) { echoConsole(v.trim()); cmd('run_cmd', { cmd: v.trim() }); } closeModal(); };
    openModal(m, e => {
      if (e.key === 'Escape') closeModal();
      else if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, items.length - 1); draw(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
      else if (e.key === 'Enter') { run(); e.preventDefault(); }
    });
    setTimeout(() => input.focus(), 30);
  }

  // ===========================================================================
  //  resizable splitters
  // ===========================================================================
  function wireSplitters() {
    $$('.splitter').forEach(sp => {
      const horiz = sp.classList.contains('split-v');   // vertical bar → drag on X
      sp.addEventListener('mousedown', e => {
        const prev = sp.previousElementSibling; if (!prev) return;
        e.preventDefault();
        const rect = prev.getBoundingClientRect();
        const start = horiz ? e.clientX : e.clientY;
        const startSize = horiz ? rect.width : rect.height;
        sp.classList.add('dragging'); document.body.classList.add('resizing');
        const mv = ev => {
          const d = (horiz ? ev.clientX : ev.clientY) - start;
          prev.style.flex = '0 0 ' + Math.max(60, startSize + d) + 'px';
        };
        const up = () => {
          document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
          sp.classList.remove('dragging'); document.body.classList.remove('resizing');
        };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      });
    });
  }

  // ===========================================================================
  //  priority keyboard-shortcut bar (bottom, x64dbg / Textual style)
  // ===========================================================================
  const KEYBAR = [
    ['F7', 'Step In', () => cmd('step_in')], ['F8', 'Step Over', () => cmd('step_over')],
    ['F6', 'Step Out', () => cmd('step_out')], ['F9', 'Run', () => cmd('cont')],
    ['⌘B', 'Break', () => cmd('interrupt')], ['F2', 'Breakpoint', () => doAct('toggle_bp')],
    ['F5', 'Snap PC', () => cmd('snap_pc')], ['⌘G', 'Goto', focusGoto], ['⌘F', 'Find', findInMemory],
    ['⌘T', 'Tracer', () => cmd('trace_toggle')], ['⌘Y', 'Scope', () => cmd('trace_scope')],
    ['⌘D', 'Defenses', openDefenses], ['⌘P', 'Palette', openPalette], ['⌘R', 'Restart', () => cmd('restart')]
  ];
  function renderKeybar() {
    const bar = $('#keybar');
    bar.innerHTML = KEYBAR.map((k, i) => `<span class="kb" data-i="${i}"><span class="kb-key">${esc(k[0])}</span>${esc(k[1])}</span>`).join('');
    bar.querySelectorAll('.kb').forEach(elm => elm.onclick = () => KEYBAR[+elm.dataset.i][2]());
  }

  // ===========================================================================
  //  ui action relay (native menu → dialog)
  // ===========================================================================
  function handleUiAction(action) {
    ({ attach: openAttach, defenses: openDefenses, palette: openPalette, find: findInMemory,
      goto: focusGoto, trace_filter: () => selectBottomTab('trace') }[action] || (() => { }))();
  }

  // ===========================================================================
  //  global keys
  // ===========================================================================
  function closeTopLayer() {
    if (!backdrop.classList.contains('hidden')) { if (modalKeyHandler) return false; closeModal(); return true; }
    if (!ctx.classList.contains('hidden')) { closeCtx(); return true; }
    return false;
  }
  const FKEYS = { F2: 'toggle_bp', F5: 'snap_pc', F6: 'step_out', F7: 'step_in', F8: 'step_over', F9: 'cont', F3: 'open' };
  function wireKeys() {
    document.addEventListener('keydown', e => {
      // ⌘/Ctrl+C copies the current text selection (the native Edit menu is off)
      if ((e.metaKey || e.ctrlKey) && (e.key === 'c' || e.key === 'C')) {
        const sel = window.getSelection ? String(window.getSelection()) : '';
        if (sel) copy(sel);
        return;
      }
      if (modalKeyHandler) { modalKeyHandler(e); return; }
      if (e.key === 'Escape') { if (closeTopLayer()) { e.preventDefault(); return; } }
      if (FKEYS[e.key]) { e.preventDefault(); doAct(FKEYS[e.key]); return; }
      if (e.ctrlKey || e.metaKey) {
        const map = { g: focusGoto, f: findInMemory, t: () => cmd('trace_toggle'), y: () => cmd('trace_scope'), k: () => cmd('trace_clear'), d: openDefenses, b: () => cmd('interrupt'), r: () => cmd('restart'), p: openPalette };
        const fn = map[e.key.toLowerCase()];
        if (fn) { e.preventDefault(); fn(); }
      }
    });
  }

  // ---- clock ---------------------------------------------------------------
  function tick() {
    const s = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor(s / 60) % 60).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    $('#st-time').textContent = `${h}:${m}:${sec}`;
  }

  // ---- boot ----------------------------------------------------------------
  function boot() {
    wireChrome();
    wireKeys();
    setStatus('none', 0, null);
    setInterval(tick, 1000);
    connect();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
