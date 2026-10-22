/* Lynkio UI library — toasts, loaders, skeletons, modals, prompts,
   file viewer, copy, download, formatting helpers.
   Exposed as window.__LYNK_UI__ for the shell and the toolkit.

   v18.2: unchanged. Used by toolkit's Cloner category (modal, confirm,
   toast, copy, prettySize) and by file viewer for source inspection. */
(function(){
if (window.__LYNK_UI__) return;

/* ---------------- escape / format ---------------- */
function esc(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function prettySize(n){
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(2) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}
function formatDate(ts){
  try { return new Date(ts).toLocaleString(); } catch(e){ return String(ts); }
}
function truncate(s, n){ s = String(s || ''); return s.length > n ? s.slice(0, n-1) + '…' : s; }

/* ---------------- inject keyframes once ---------------- */
(function ensureKf(){
  if (document.getElementById('__lynk_ui_kf')) return;
  var s = document.createElement('style');
  s.id = '__lynk_ui_kf';
  s.textContent =
    '@keyframes __lynk_skel{0%{background-position:-400px 0}100%{background-position:400px 0}}'
    + '@keyframes __lynk_spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}'
    + '@keyframes __lynk_fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}';
  document.head.appendChild(s);
})();

/* ---------------- toast (queue, capped) ---------------- */
var toasts = [];
var TOAST_MAX = 6;
var TSTYLE = {
  info: { bg:'rgba(56,189,248,.16)', bd:'rgba(56,189,248,.45)', fg:'#38bdf8', ic:'ℹ' },
  ok:   { bg:'rgba(16,185,129,.16)', bd:'rgba(16,185,129,.45)', fg:'#10b981', ic:'✓' },
  warn: { bg:'rgba(245,158,11,.16)', bd:'rgba(245,158,11,.45)', fg:'#f59e0b', ic:'⚠' },
  err:  { bg:'rgba(248,113,113,.16)',bd:'rgba(248,113,113,.45)',fg:'#f87171', ic:'✕' },
};
function layoutToasts(){
  for (var i = 0; i < toasts.length; i++){
    var el = toasts[i];
    el.style.bottom = 'calc(' + (24 + i * 56) + 'px + env(safe-area-inset-bottom,0px))';
  }
}
function toast(msg, kind, ms){
  kind = kind || 'info'; ms = ms || 3200;
  var c = TSTYLE[kind] || TSTYLE.info;
  var el = document.createElement('div');
  el.style.cssText =
    'position:fixed;'
    + 'bottom:calc(24px + env(safe-area-inset-bottom,0px));'
    + 'right:calc(16px + env(safe-area-inset-right,0px));'
    + 'background:'+c.bg+';border:1px solid '+c.bd+';color:'+c.fg+';'
    + 'padding:12px 18px;border-radius:12px;'
    + 'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif;'
    + 'font-size:13px;font-weight:600;'
    + 'backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);'
    + 'box-shadow:0 20px 40px -12px rgba(0,0,0,.55);'
    + 'z-index:2147483647;display:flex;align-items:center;gap:10px;'
    + 'min-width:220px;max-width:calc(100vw - 32px);box-sizing:border-box;'
    + 'transform:translateX(420px);'
    + 'transition:transform .26s cubic-bezier(.34,1.36,.64,1);';
  el.innerHTML = '<span style="font-size:14px">'+c.ic+'</span><span>'+esc(msg)+'</span>';
  document.body.appendChild(el);
  toasts.push(el);
  while (toasts.length > TOAST_MAX){
    var drop = toasts.shift();
    try { drop.remove(); } catch(e){}
  }
  layoutToasts();
  requestAnimationFrame(function(){ el.style.transform = 'translateX(0)'; });
  setTimeout(function(){
    el.style.transform = 'translateX(420px)';
    setTimeout(function(){
      try { el.remove(); } catch(e){}
      toasts = toasts.filter(function(x){ return x !== el; });
      layoutToasts();
    }, 280);
  }, ms);
}

/* ---------------- withLoader ---------------- */
function withLoader(btn, promise){
  if (!btn) return promise;
  var orig = btn.innerHTML;
  var w = btn.offsetWidth || 0;
  btn.disabled = true;
  btn.style.minWidth = w + 'px';
  btn.dataset.__lynk_loading = '1';
  btn.innerHTML = '<span style="opacity:.6">Working…</span>';
  return Promise.resolve(promise).finally(function(){
    btn.disabled = false;
    btn.innerHTML = orig;
    btn.style.minWidth = '';
    delete btn.dataset.__lynk_loading;
  });
}

/* ---------------- skeleton ---------------- */
function skeleton(rows){
  rows = rows || 4;
  var out = '';
  for (var i = 0; i < rows; i++){
    out += '<div style="height:14px;margin-bottom:10px;border-radius:6px;'
      + 'background:linear-gradient(90deg,rgba(148,163,184,.08),rgba(148,163,184,.2),rgba(148,163,184,.08));'
      + 'background-size:800px 100%;animation:__lynk_skel 1.6s infinite linear;'
      + 'width:'+(100 - i*8)+'%"></div>';
  }
  return '<div style="padding:8px 0">'+out+'</div>';
}

/* ---------------- modal (stackable) ---------------- */
var _modalZ = 2147483000;
function openModal(opts){
  opts = opts || {};
  var z = ++_modalZ;
  var overlay = document.createElement('div');
  overlay.style.cssText =
    'position:fixed;inset:0;z-index:' + z + ';display:flex;'
    + 'align-items:center;justify-content:center;padding:16px;'
    + 'background:rgba(2,6,23,.8);backdrop-filter:blur(6px);'
    + 'animation:__lynk_fade .18s ease;box-sizing:border-box;';
  overlay.innerHTML =
    '<div style="background:#0d1526;border:1px solid rgba(148,163,184,.2);'
    + 'border-radius:16px;width:100%;max-width:'+(opts.width || 520)+'px;'
    + 'max-height:92vh;display:flex;flex-direction:column;overflow:hidden;'
    + 'font-family:Inter,-apple-system,sans-serif;color:#e2e8f0;'
    + 'box-shadow:0 40px 80px -20px rgba(0,0,0,.8);box-sizing:border-box;">'
    + (opts.title ? '<div style="padding:14px 18px;border-bottom:1px solid rgba(148,163,184,.16);'
        + 'display:flex;justify-content:space-between;align-items:center;flex-shrink:0;">'
        + '<div style="font-weight:700;font-size:14px;min-width:0;overflow:hidden;'
        + 'text-overflow:ellipsis;white-space:nowrap;">'+esc(opts.title)+'</div>'
        + '<button class="__lynk_modal_x" style="background:rgba(148,163,184,.08);'
        + 'border:none;color:#94a3b8;width:32px;height:32px;border-radius:8px;'
        + 'font-size:15px;cursor:pointer;padding:0;">✕</button></div>' : '')
    + '<div class="__lynk_modal_body" style="padding:16px;overflow:auto;flex:1;'
    + 'font-size:13px;box-sizing:border-box;"></div>'
    + '</div>';
  document.body.appendChild(overlay);
  var body = overlay.querySelector('.__lynk_modal_body');
  function close(){
    overlay.style.opacity = '0';
    setTimeout(function(){ overlay.remove(); }, 180);
    document.removeEventListener('keydown', keyH);
    if (opts.onClose) opts.onClose();
  }
  var x = overlay.querySelector('.__lynk_modal_x');
  if (x) x.onclick = close;
  overlay.onclick = function(e){ if (e.target === overlay && !opts.persistent) close(); };
  var keyH = function(e){
    if (e.key === 'Escape'){ close(); }
  };
  document.addEventListener('keydown', keyH);
  return { overlay: overlay, body: body, close: close };
}

/* ---------------- confirm ---------------- */
function confirmDialog(opts){
  if (typeof opts === 'string') opts = { message: opts };
  opts = opts || {};
  return new Promise(function(resolve){
    var m = openModal({ title: opts.title || 'Confirm', width: opts.width || 440 });
    m.body.innerHTML = '<div style="font-size:13.5px;line-height:1.6;">'
      + esc(opts.message || 'Are you sure?') + '</div>';
    var wrap = m.overlay.querySelector('.__lynk_modal_body').parentNode;
    var f = document.createElement('div');
    f.style.cssText = 'padding:12px 18px;border-top:1px solid rgba(148,163,184,.14);'
      + 'display:flex;justify-content:flex-end;gap:8px;flex-shrink:0;';
    var cancel = document.createElement('button');
    cancel.textContent = opts.cancelText || 'Cancel';
    cancel.style.cssText = 'padding:9px 18px;border-radius:9px;'
      + 'border:1px solid rgba(148,163,184,.25);background:transparent;color:#e2e8f0;'
      + 'cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:600;';
    cancel.onclick = function(){ m.close(); resolve(false); };
    var ok = document.createElement('button');
    ok.textContent = opts.okText || 'OK';
    ok.style.cssText = 'padding:9px 18px;border-radius:9px;border:none;'
      + 'background:' + (opts.danger ? '#f87171' : 'linear-gradient(135deg,#38bdf8,#818cf8)')
      + ';color:' + (opts.danger ? '#fff' : '#0b1220')
      + ';cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:700;';
    ok.onclick = function(){ m.close(); resolve(true); };
    f.appendChild(cancel); f.appendChild(ok);
    wrap.appendChild(f);
  });
}

/* ---------------- prompt ---------------- */
function promptDialog(opts){
  if (typeof opts === 'string') opts = { message: opts };
  opts = opts || {};
  return new Promise(function(resolve){
    var m = openModal({ title: opts.title || 'Input', width: opts.width || 440 });
    var inputId = '__lynk_prompt_' + Math.random().toString(36).slice(2,8);
    m.body.innerHTML =
      (opts.message ? '<div style="font-size:13.5px;line-height:1.6;margin-bottom:10px;">'
        + esc(opts.message) + '</div>' : '')
      + (opts.multiline
        ? '<textarea id="'+inputId+'" style="width:100%;height:120px;background:#0b1220;'
          + 'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:8px;'
          + 'padding:10px;font-family:ui-monospace,monospace;font-size:12.5px;outline:none;'
          + 'box-sizing:border-box;resize:vertical;">'+esc(opts.defaultValue || '')+'</textarea>'
        : '<input id="'+inputId+'" value="'+esc(opts.defaultValue || '')+'" '
          + 'placeholder="'+esc(opts.placeholder || '')+'" '
          + 'style="width:100%;padding:11px 12px;background:#0b1220;color:#e2e8f0;'
          + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;font-family:inherit;'
          + 'font-size:13px;outline:none;box-sizing:border-box;"/>');
    var wrap = m.overlay.querySelector('.__lynk_modal_body').parentNode;
    var f = document.createElement('div');
    f.style.cssText = 'padding:12px 18px;border-top:1px solid rgba(148,163,184,.14);'
      + 'display:flex;justify-content:flex-end;gap:8px;flex-shrink:0;';
    var cancel = document.createElement('button');
    cancel.textContent = 'Cancel';
    cancel.style.cssText = 'padding:9px 18px;border-radius:9px;'
      + 'border:1px solid rgba(148,163,184,.25);background:transparent;color:#e2e8f0;'
      + 'cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:600;';
    cancel.onclick = function(){ m.close(); resolve(null); };
    var ok = document.createElement('button');
    ok.textContent = opts.okText || 'OK';
    ok.style.cssText = 'padding:9px 18px;border-radius:9px;border:none;'
      + 'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;cursor:pointer;'
      + 'font-family:inherit;font-size:12.5px;font-weight:700;';
    ok.onclick = function(){
      var el = m.body.querySelector('#' + inputId);
      var v = el ? el.value : '';
      m.close(); resolve(v);
    };
    f.appendChild(cancel); f.appendChild(ok);
    wrap.appendChild(f);
    setTimeout(function(){
      var el = m.body.querySelector('#' + inputId);
      if (el){ el.focus(); if (!opts.multiline) el.select(); }
    }, 40);
  });
}

/* ---------------- copy ---------------- */
function copy(text){
  try {
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text);
      toast('Copied', 'ok', 1400);
      return true;
    }
  } catch(e){}
  try {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
    toast('Copied', 'ok', 1400);
    return true;
  } catch(e){ toast('Copy failed', 'err'); return false; }
}

/* ---------------- download ---------------- */
function download(name, content, mime){
  try {
    var blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    return true;
  } catch(e){ toast('Download failed', 'err'); return false; }
}

/* ---------------- msg helper ---------------- */
function msg(kind, text){
  return '<div class="result-msg ' + kind + '">' + esc(text) + '</div>';
}

/* ---------------- file viewer ---------------- */
async function fileViewer(url, title){
  var m = openModal({ title: title || url, width: 960 });
  m.body.innerHTML = skeleton(5);
  var aborted = false;
  var abortCtrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  var origClose = m.close;
  m.close = function(){ aborted = true;
    try { if (abortCtrl) abortCtrl.abort(); } catch(e){}
    origClose(); };

  try {
    var opts = { credentials: 'same-origin' };
    if (abortCtrl) opts.signal = abortCtrl.signal;
    var r = await fetch('/tool/file/view?url=' + encodeURIComponent(url), opts);
    if (aborted) return;
    var d = await r.json();
    if (aborted) return;
    if (d.error){ m.body.innerHTML = msg('err', d.error); return; }
    var head = '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;'
      + 'font-size:11px;color:#94a3b8;">'
      + '<span><b style="color:#38bdf8;">Status</b> ' + d.status + '</span>'
      + '<span><b style="color:#38bdf8;">Size</b> ' + prettySize(d.size) + '</span>'
      + '<span><b style="color:#38bdf8;">Type</b> ' + esc(d.content_type) + '</span>'
      + '<span style="margin-left:auto;">'
      + '<button data-act="copy" style="padding:4px 10px;border-radius:6px;'
      + 'border:1px solid rgba(148,163,184,.3);background:transparent;color:#e2e8f0;'
      + 'cursor:pointer;font-family:inherit;font-size:11px;font-weight:600;'
      + 'margin-right:4px;">⧉ Copy</button>'
      + '<button data-act="dl" style="padding:4px 10px;border-radius:6px;'
      + 'border:1px solid rgba(148,163,184,.3);background:transparent;color:#e2e8f0;'
      + 'cursor:pointer;font-family:inherit;font-size:11px;font-weight:600;">⬇</button>'
      + '</span></div>';
    if (d.kind === 'text'){
      m.body.innerHTML = head
        + '<pre style="background:#050a14;padding:12px;border-radius:8px;'
        + 'font-size:11.5px;line-height:1.6;white-space:pre-wrap;word-break:break-word;'
        + 'border:1px solid rgba(148,163,184,.1);overflow:auto;margin:0;">'
        + esc(d.body || '(empty)') + '</pre>'
        + (d.truncated ? msg('warn', 'File truncated to first 200 KB') : '');
    } else if (d.kind === 'media'){
      var src = '/proxy?url=' + encodeURIComponent(url);
      var ct = (d.content_type || '').toLowerCase();
      if (ct.indexOf('image/') === 0){
        m.body.innerHTML = head + '<div style="text-align:center;padding:12px;">'
          + '<img src="' + src + '" style="max-width:100%;max-height:60vh;'
          + 'border-radius:8px;" /></div>';
      } else if (ct.indexOf('video/') === 0){
        m.body.innerHTML = head + '<video src="' + src + '" controls '
          + 'style="width:100%;max-height:60vh;border-radius:8px;"></video>';
      } else if (ct.indexOf('audio/') === 0){
        m.body.innerHTML = head + '<audio src="' + src + '" controls style="width:100%;"></audio>';
      } else {
        m.body.innerHTML = head + msg('info', 'Media preview unavailable');
      }
    } else if (d.kind === 'pdf'){
      m.body.innerHTML = head + '<iframe src="/proxy?url='
        + encodeURIComponent(url) + '" style="width:100%;height:60vh;'
        + 'border:1px solid rgba(148,163,184,.15);border-radius:8px;background:#fff;"></iframe>';
    } else {
      m.body.innerHTML = head + msg('info', 'Binary file — use download.');
    }
    m.body.querySelectorAll('[data-act="copy"]').forEach(function(b){
      b.onclick = function(){ copy(d.body || ''); };
    });
    m.body.querySelectorAll('[data-act="dl"]').forEach(function(b){
      b.onclick = function(){
        var a = document.createElement('a');
        a.href = '/tool/fetch?dl=1&url=' + encodeURIComponent(url);
        a.download = url.split('/').pop().split('?')[0] || 'file';
        document.body.appendChild(a); a.click(); a.remove();
      };
    });
  } catch(e){
    if (aborted) return;
    m.body.innerHTML = msg('err', e.message);
  }
}

/* ---------------- public API ---------------- */
window.__LYNK_UI__ = {
  esc: esc,
  toast: toast,
  withLoader: withLoader,
  skeleton: skeleton,
  confirm: confirmDialog,
  prompt: promptDialog,
  modal: openModal,
  copy: copy,
  download: download,
  fileViewer: fileViewer,
  prettySize: prettySize,
  formatDate: formatDate,
  truncate: truncate,
  msg: msg,
};
})();
