(function (root) {
  'use strict';
  const DEFAULT_KEYS = {run:'F9',step_in:'F7',step_over:'F8',step_out:'F6',toggle_bp:'F2',run_to:'F4',snap_pc:'F5',open:'F3',follow:'Enter',comment:';',back:'Alt+Left',forward:'Alt+Right',actions:'Mod+P',find:'Mod+F',goto:'Mod+G',console:'Mod+`',trace:'Mod+T',restart:'Mod+R',pause:'Mod+B',graph:'G',references:'X',defenses:'Mod+D',undo:'Mod+Z'};
  const X64_KEYS = {...DEFAULT_KEYS,step_out:'Mod+F9'};
  function hex(bytes) { return bytes.map(b => b.toString(16).padStart(2,'0')).join(' '); }
  function parseHex(text) {
    const value = text.trim().replace(/^0x/i,'').replace(/\s/g,'');
    if (!value || value.length % 2 || !/^[\da-f]+$/i.test(value)) throw new Error('Enter complete hexadecimal bytes, for example 41 42 43.');
    return value.match(/../g).map(v => parseInt(v,16));
  }
  function range(anchor,focus,base,length) {
    if (!length) return null;
    const a = Math.max(base,Math.min(base+length-1,anchor));
    const b = Math.max(base,Math.min(base+length-1,focus));
    return {addr:Math.min(a,b),size:Math.abs(a-b)+1};
  }
  function historyPush(model,address) {
    if (model.history[model.index] !== address) {
      model.history = model.history.slice(0,model.index+1).concat(address).slice(-100);
      model.index = model.history.length-1;
    }
    model.addr = address;
  }
  function typed(bytes,format) {
    const data = Uint8Array.from(bytes), view = new DataView(data.buffer);
    const size = {pointers:8,u32:4,u64:8,f32:4,f64:8,utf16:2}[format] || 1;
    const rows = [];
    for (let offset=0; offset+size<=bytes.length; offset+=size) {
      let value;
      if (format==='pointers') value='0x'+view.getBigUint64(offset,true).toString(16).padStart(16,'0');
      else if (format==='u64') value=view.getBigUint64(offset,true).toString();
      else if (format==='u32') value=String(view.getUint32(offset,true));
      else if (format==='f64') value=String(view.getFloat64(offset,true));
      else if (format==='f32') value=String(view.getFloat32(offset,true));
      else if (format==='utf16') {
        const word=view.getUint16(offset,true),low=offset+4<=bytes.length?view.getUint16(offset+2,true):0;
        if(word>=0xd800&&word<=0xdbff&&low>=0xdc00&&low<=0xdfff){rows.push({offset,size:4,value:String.fromCodePoint(0x10000+(word-0xd800)*1024+low-0xdc00)});offset+=2;continue;}
        value=word===0?'␀':word<32?'·':word>=0xd800&&word<=0xdfff?'U+'+word.toString(16)+' (unpaired)':String.fromCharCode(word);
      }
      else value=bytes[offset].toString(16).padStart(2,'0');
      rows.push({offset,size,value});
    }
    return rows;
  }
  function keyName(e) {
    const aliases={ArrowLeft:'Left',ArrowRight:'Right',ArrowUp:'Up',ArrowDown:'Down',' ':'Space',Escape:'Esc'};
    let key=aliases[e.key] || e.key;
    if (key.length===1 && /[a-z]/i.test(key)) key=key.toUpperCase();
    return [e.ctrlKey?'Ctrl':'',e.metaKey?'Meta':'',e.altKey?'Alt':'',e.shiftKey && key!==';'?'Shift':'',key].filter(Boolean).join('+');
  }
  function encodeUtf16(text) {
    const bytes=[];for(let i=0;i<text.length;i++){const value=text.charCodeAt(i);bytes.push(value&255,value>>8);}return bytes;
  }
  function matches(e,binding) {
    const actual=keyName(e);
    return actual===binding || (binding.includes('Mod+') && (actual===binding.replace('Mod+','Meta+') || actual===binding.replace('Mod+','Ctrl+')));
  }
  const api={DEFAULT_KEYS,X64_KEYS,hex,parseHex,range,historyPush,typed,keyName,matches,encodeUtf16};
  if (typeof module!=='undefined' && module.exports) module.exports=api;
  else root.MacdbgWorkspaceModel=api;
})(typeof window!=='undefined'?window:globalThis);
