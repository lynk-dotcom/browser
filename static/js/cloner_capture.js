/* cloner_capture.js
 * ─────────────────────────────────────────────────────────────────
 * Two responsibilities:
 *   1. Capture full page state and send it to the server (clone).
 *   2. Provide a live editor for clone pages: click any element,
 *      edit its HTML in the sidebar (or Ctrl+Shift+E to toggle),
 *      changes persist to the exact clone source immediately and
 *      broadcast to any other open view of that clone.
 * ─────────────────────────────────────────────────────────────────
 */
(function () {
  'use strict';

  if (window.__LYNK_CAPTURE__) return;
  window.__LYNK_CAPTURE__ = true;

  /* ================= CONFIG ================= */
  var PATH = location.pathname || '/';
  var IS_CLONE = PATH.indexOf('/clone/') === 0;
  var CLONE_ID = null;
  if (IS_CLONE) {
    var _parts = PATH.split('/').filter(Boolean);
    CLONE_ID = _parts[1] || null;
  }
  var EDIT_ENDPOINT = '/clone/{id}/edit';
  var SOURCE_ENDPOINT = '/clone/{id}/source';
  var CAPTURE_ENDPOINT = '/cloner/capture';

  var UPSTREAM = (function () {
    if (window.__LYNK_CTX__ && window.__LYNK_CTX__.upstream) return window.__LYNK_CTX__.upstream;
    if (window.__LYNK_CLONE_STATE__ && window.__LYNK_CLONE_STATE__.source_url) {
      try { return new URL(window.__LYNK_CLONE_STATE__.source_url).origin; } catch (e) {}
    }
    return location.origin;
  })();

  function ep(tpl) {
    return tpl.replace('{id}', encodeURIComponent(CLONE_ID || ''));
  }

  /* ================= CAPTURE ================= */

  function markInlineScripts() {
    try {
      document.querySelectorAll('script').forEach(function (s) {
        if (s.src) return;
        if (!s.textContent || !s.textContent.trim()) return;
        if (s.type && !/javascript|module|text\/lynk-js/.test(s.type)) return;
        if (s.hasAttribute('data-lynk-exec')) return;
        s.setAttribute('data-lynk-exec', '1');
        if (!s.type) s.setAttribute('type', 'text/javascript');
      });
    } catch (e) {}
  }

  function getDoctype() {
    try {
      if (document.doctype) {
        return '<!DOCTYPE ' + document.doctype.name +
          (document.doctype.publicId ? ' PUBLIC "' + document.doctype.publicId + '"' : '') +
          (document.doctype.systemId ? ' "' + document.doctype.systemId + '"' : '') +
          '>';
      }
    } catch (e) {}
    return '<!DOCTYPE html>';
  }

  function collectDOM() {
    try {
      return '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
    } catch (e) {
      return '';
    }
  }

  function collectStorage() {
    var ls = {}, ss = {};
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        ls[k] = localStorage.getItem(k);
      }
    } catch (e) {}
    try {
      for (var j = 0; j < sessionStorage.length; j++) {
        var k2 = sessionStorage.key(j);
        ss[k2] = sessionStorage.getItem(k2);
      }
    } catch (e) {}
    return { localStorage: ls, sessionStorage: ss };
  }

  function collectCookies() {
    try {
      return document.cookie.split(';').map(function (c) {
        var idx = c.indexOf('=');
        if (idx < 0) return null;
        return { name: c.slice(0, idx).trim(), value: c.slice(idx + 1).trim() };
      }).filter(Boolean);
    } catch (e) { return []; }
  }

  function collectFormValues() {
    var out = [];
    try {
      document.querySelectorAll('form').forEach(function (f, idx) {
        var fields = [];
        f.querySelectorAll('input,select,textarea').forEach(function (field) {
          fields.push({
            name: field.name || '',
            type: field.type || field.tagName.toLowerCase(),
            value: field.value,
            checked: !!field.checked
          });
        });
        out.push({ index: idx, id: f.id || '', action: f.action || '', fields: fields });
      });
    } catch (e) {}
    return out;
  }

  function readOneIDB(name) {
    return new Promise(function (resolve) {
      try {
        var req = indexedDB.open(name);
        req.onsuccess = function () {
          var db = req.result;
          var names = Array.from(db.objectStoreNames);
          if (names.length === 0) { db.close(); resolve({}); return; }
          var result = {}, pending = names.length;
          names.forEach(function (sn) {
            try {
              var tx = db.transaction(sn, 'readonly');
              var all = tx.objectStore(sn).getAll();
              all.onsuccess = function () {
                result[sn] = all.result;
                if (--pending === 0) { db.close(); resolve(result); }
              };
              all.onerror = function () {
                result[sn] = [];
                if (--pending === 0) { db.close(); resolve(result); }
              };
            } catch (e) {
              result[sn] = [];
              if (--pending === 0) { db.close(); resolve(result); }
            }
          });
        };
        req.onerror = function () { resolve({}); };
      } catch (e) { resolve({}); }
    });
  }

  async function collectIDB() {
    if (!window.indexedDB || !indexedDB.databases) return [];
    try {
      var dbs = await indexedDB.databases();
      var out = [];
      for (var i = 0; i < dbs.length; i++) {
        var data = await readOneIDB(dbs[i].name);
        out.push({ name: dbs[i].name, version: dbs[i].version || 1, stores: data });
      }
      return out;
    } catch (e) { return []; }
  }

  async function collectCaches() {
    if (!window.caches) return [];
    try {
      var names = await caches.keys();
      var out = [];
      for (var i = 0; i < names.length; i++) {
        var cache = await caches.open(names[i]);
        var reqs = await cache.keys();
        var entries = [];
        for (var j = 0; j < reqs.length && j < 200; j++) {
          try {
            var resp = await cache.match(reqs[j]);
            if (!resp) continue;
            var body = await resp.clone().text();
            entries.push({
              url: reqs[j].url,
              body: body.length > 512000 ? body.slice(0, 512000) : body,
              status: resp.status,
              headers: Object.fromEntries(resp.headers)
            });
          } catch (e) {}
        }
        out.push({ name: names[i], entries: entries });
      }
      return out;
    } catch (e) { return []; }
  }

  function collectAssets() {
    var urls = new Set();
    try {
      document.querySelectorAll(
        'script[src],link[href],img[src],source[src],source[srcset],' +
        'video[src],video[poster],audio[src],iframe[src],embed[src],object[data]'
      ).forEach(function (el) {
        var u = el.src || el.href || el.getAttribute('data');
        if (u) urls.add(u);
        var ss = el.getAttribute && el.getAttribute('srcset');
        if (ss) ss.split(',').forEach(function (part) {
          var u2 = part.trim().split(/\s+/)[0];
          if (u2) urls.add(u2);
        });
      });
    } catch (e) {}
    return Array.from(urls);
  }

  async function captureAll() {
    markInlineScripts();
    var payload = {
      url: location.href,
      upstream: UPSTREAM,
      title: document.title,
      doctype: getDoctype(),
      html: collectDOM(),
      storage: collectStorage(),
      cookies: collectCookies(),
      forms: collectFormValues(),
      indexedDB: await collectIDB(),
      caches: await collectCaches(),
      assets: collectAssets(),
      staged_edits: window.__LYNK_STAGED_EDITS__ || [],
      cloned_at: Date.now()
    };
    return payload;
  }

  async function sendCapture(payload) {
    try {
      var resp = await fetch(CAPTURE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!resp.ok) throw new Error('capture failed: ' + resp.status);
      return await resp.json().catch(function () { return {}; });
    } catch (err) {
      // fall back to shell: shell may own the capture pipeline
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'lynk:capture', payload: payload }, '*');
        return { ok: true, delegated: true };
      }
      throw err;
    }
  }

  function bindCloneButton() {
    document.addEventListener('click', async function (e) {
      var btn = e.target && e.target.closest &&
        e.target.closest('[data-lynk-clone], [data-action="clone"], #lynk-clone-btn');
      if (!btn) return;
      e.preventDefault();
      var prev = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Cloning…';
      try {
        var payload = await captureAll();
        var result = await sendCapture(payload);
        btn.textContent = 'Cloned ✓';
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: 'lynk:capture-done', result: result }, '*');
        }
      } catch (err) {
        btn.textContent = 'Error';
        console.error('[Lynk capture]', err);
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({
            type: 'lynk:capture-error',
            error: String(err)
          }, '*');
        }
      } finally {
        setTimeout(function () {
          btn.disabled = false;
          btn.textContent = prev;
        }, 1800);
      }
    }, true);
  }

  /* ================= LIVE EDITOR ================= */
  /*
   * Features
   *   • Ctrl+Shift+E            → toggle edit mode
   *   • Ctrl+S                  → flush pending changes now
   *   • Ctrl+Z / Ctrl+Shift+Z   → undo / redo
   *   • Hover element           → blue outline
   *   • Click element           → select + sidebar with HTML
   *   • Double‑click element    → contenteditable (edit in place)
   *   • Toolbar "HTML Source"   → full‑page source editor
   *   • Every change debounced → POST /clone/<id>/edit or /source
   *   • Broadcasts to parent    → other views of same clone update live
   */
  var Editor = (function () {
    var state = {
      active: false,
      toolbar: null,
      sidebar: null,
      selected: null,
      selectedSelector: null,
      pending: new Map(),
      saveTimer: null,
      applyTimer: null,
      undoStack: [],
      redoStack: []
    };

    /* ---- selectors ---- */
    function getSelector(el) {
      if (!el || el.nodeType !== 1) return null;
      try {
        if (el.id) return '#' + CSS.escape(el.id);
      } catch (e) {}
      var path = [];
      var cur = el;
      while (cur && cur.nodeType === 1 && cur !== document.documentElement) {
        var sel = cur.tagName.toLowerCase();
        if (cur.id) {
          try { sel = '#' + CSS.escape(cur.id); } catch (e) { sel = cur.tagName.toLowerCase(); }
          path.unshift(sel);
          break;
        }
        if (typeof cur.className === 'string' && cur.className.trim()) {
          cur.className.trim().split(/\s+/).slice(0, 2).forEach(function (c) {
            if (c && /^[a-zA-Z_-]/.test(c)) {
              try { sel += '.' + CSS.escape(c); } catch (e) {}
            }
          });
        }
        var parent = cur.parentNode;
        if (parent && parent.children) {
          var siblings = Array.prototype.filter.call(parent.children, function (s) {
            return s.tagName === cur.tagName;
          });
          if (siblings.length > 1) {
            sel += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
          }
        }
        path.unshift(sel);
        cur = cur.parentNode;
      }
      return path.join(' > ');
    }

    /* ---- toolbar / sidebar / modal ---- */
    function createUI() {
      var host = document.createElement('div');
      host.id = '__lynk_editor_host__';
      host.style.cssText =
        'position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
      document.documentElement.appendChild(host);

      var shadow = host.attachShadow({ mode: 'closed' });
      shadow.innerHTML = '\
        <style>\
          *{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}\
          .bar{display:flex;align-items:center;gap:8px;padding:8px 12px;\
               background:rgba(15,23,42,.97);color:#e2e8f0;\
               border-bottom:1px solid #334155;pointer-events:auto;font-size:13px}\
          .bar .title{font-weight:600;color:#38bdf8;margin-right:auto}\
          .bar button{padding:5px 10px;border:1px solid #475569;border-radius:5px;\
                      background:#1e293b;color:#e2e8f0;cursor:pointer;font-size:12px}\
          .bar button:hover{background:#334155}\
          .status{color:#94a3b8;font-size:11px;min-width:90px}\
          .status.saving{color:#fbbf24}\
          .status.saved{color:#4ade80}\
          .status.error{color:#f87171}\
          .sidebar{position:fixed;top:40px;right:0;bottom:0;width:420px;\
                   background:rgba(15,23,42,.98);color:#e2e8f0;\
                   border-left:1px solid #334155;padding:14px;\
                   display:none;flex-direction:column;gap:10px;\
                   pointer-events:auto;font-size:12px;overflow:auto}\
          .sidebar.open{display:flex}\
          .sidebar .label{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.05em}\
          .sidebar .sel{color:#38bdf8;font-family:monospace;font-size:11px;word-break:break-all;\
                        background:#0f172a;padding:6px;border-radius:4px}\
          .sidebar textarea{flex:1;min-height:240px;background:#0f172a;color:#e2e8f0;\
                            border:1px solid #334155;border-radius:4px;padding:10px;\
                            font-family:monospace;font-size:12px;resize:vertical}\
          .sidebar .row{display:flex;gap:8px}\
          .sidebar .row button{flex:1;padding:6px 10px;border:1px solid #475569;\
                                border-radius:5px;background:#1e293b;color:#e2e8f0;\
                                cursor:pointer;font-size:12px}\
          .sidebar .row button.primary{background:#0284c7;border-color:#0284c7}\
          .modal{position:fixed;inset:40px 0 0 0;background:rgba(0,0,0,.85);\
                 display:none;padding:20px;pointer-events:auto;\
                 flex-direction:column;gap:12px}\
          .modal.open{display:flex}\
          .modal h3{margin:0;color:#e2e8f0;font-size:14px}\
          .modal textarea{flex:1;background:#0f172a;color:#e2e8f0;\
                          border:1px solid #334155;border-radius:4px;padding:12px;\
                          font-family:monospace;font-size:12px;resize:none}\
          .modal .row{display:flex;gap:8px;justify-content:flex-end}\
          .modal .row button{padding:6px 14px;border:1px solid #475569;\
                              border-radius:5px;background:#1e293b;color:#e2e8f0;\
                              cursor:pointer}\
          .modal .row button.primary{background:#0284c7;border-color:#0284c7}\
          .outline{position:fixed;pointer-events:none;z-index:2147483646;\
                   border:2px solid #38bdf8;background:rgba(56,189,248,.08);\
                   border-radius:2px;display:none}\
          [data-lynk-edit="active"]{outline:2px dashed #38bdf8!important;\
                                     outline-offset:2px!important}\
        </style>\
        <div class="bar">\
          <span class="title">Lynk Editor</span>\
          <button data-act="save">Save</button>\
          <button data-act="undo">↶ Undo</button>\
          <button data-act="redo">↷ Redo</button>\
          <button data-act="source">HTML Source</button>\
          <span class="status" data-status>Ready</span>\
          <button data-act="exit">Exit</button>\
        </div>\
        <div class="sidebar" data-sidebar>\
          <div class="label">Selected element</div>\
          <div class="sel" data-selector>—</div>\
          <div class="label">HTML</div>\
          <textarea data-editor spellcheck="false"></textarea>\
          <div class="row">\
            <button data-act="el-revert">Revert</button>\
            <button class="primary" data-act="el-save">Apply &amp; Save</button>\
          </div>\
        </div>\
        <div class="modal" data-modal>\
          <h3>Clone Source (HTML)</h3>\
          <textarea data-source spellcheck="false"></textarea>\
          <div class="row">\
            <button data-act="source-cancel">Cancel</button>\
            <button class="primary" data-act="source-save">Save Source</button>\
          </div>\
        </div>\
        <div class="outline" data-outline></div>\
      ';

      state.toolbar = { host: host, shadow: shadow };
      state.sidebar = shadow.querySelector('[data-sidebar]');

      /* toolbar wiring */
      shadow.querySelectorAll('[data-act]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var a = btn.getAttribute('data-act');
          if (a === 'save') flush(true);
          else if (a === 'undo') undo();
          else if (a === 'redo') redo();
          else if (a === 'source') openSource();
          else if (a === 'exit') exit();
          else if (a === 'el-revert') revertSelected();
          else if (a === 'el-save') commitSelected();
          else if (a === 'source-cancel') closeSource();
          else if (a === 'source-save') saveSource();
        });
      });

      /* sidebar textarea — debounced apply to selected element */
      var editorTa = shadow.querySelector('[data-editor]');
      editorTa.addEventListener('input', function () {
        if (!state.selected || !state.selectedSelector) return;
        clearTimeout(state.applyTimer);
        state.applyTimer = setTimeout(function () {
          applyFromSidebar();
        }, 280);
      });

      return state.toolbar;
    }

    function status(cls, text) {
      if (!state.toolbar) return;
      var s = state.toolbar.shadow.querySelector('[data-status]');
      if (!s) return;
      s.className = 'status ' + cls;
      s.textContent = text;
      if (cls === 'saved') {
        setTimeout(function () {
          if (s.classList.contains('saved')) {
            s.className = 'status';
            s.textContent = 'Ready';
          }
        }, 1500);
      }
    }

    /* ---- apply textarea content to selected element ---- */
    function applyFromSidebar() {
      if (!state.selected || !state.selectedSelector) return;
      var newHtml = state.toolbar.shadow.querySelector('[data-editor]').value;
      var target;
      try { target = document.querySelector(state.selectedSelector); } catch (e) { return; }
      if (!target) return;
      try {
        var temp = document.createElement('div');
        temp.innerHTML = newHtml;
        var newEl = temp.firstElementChild;
        if (!newEl) return;
        state.undoStack.push({ selector: state.selectedSelector, html: target.outerHTML });
        state.redoStack.length = 0;
        target.replaceWith(newEl);
        state.selected = newEl;
        state.pending.set(state.selectedSelector, newHtml);
        scheduleFlush();
      } catch (err) {
        console.warn('[Lynk editor] apply failed:', err);
      }
    }

    /* ---- commit from Apply & Save button ---- */
    function commitSelected() {
      applyFromSidebar();
      flush(true);
    }

    /* ---- revert to last saved value ---- */
    function revertSelected() {
      if (!state.selected || !state.selectedSelector) return;
      var entry = state.undoStack.pop();
      if (!entry) return;
      var target;
      try { target = document.querySelector(entry.selector); } catch (e) { return; }
      if (!target) return;
      try {
        var temp = document.createElement('div');
        temp.innerHTML = entry.html;
        var prev = temp.firstElementChild;
        if (prev) target.replaceWith(prev);
        state.selected = prev;
        state.toolbar.shadow.querySelector('[data-editor]').value =
          prev ? prev.outerHTML : '';
        state.pending.set(entry.selector, entry.html);
        scheduleFlush();
      } catch (e) {}
    }

    /* ---- pending change tracking ---- */
    function scheduleFlush() {
      status('saving', 'Saving…');
      clearTimeout(state.saveTimer);
      state.saveTimer = setTimeout(function () { flush(false); }, 400);
    }

    async function flush(immediate) {
      if (state.pending.size === 0) {
        if (immediate) status('saved', 'Saved');
        return;
      }
      var edits = [];
      state.pending.forEach(function (html, selector) {
        edits.push({ selector: selector, html: html });
      });
      state.pending.clear();

      if (IS_CLONE && CLONE_ID) {
        try {
          var resp = await fetch(ep(EDIT_ENDPOINT), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ edits: edits })
          });
          if (resp.ok) {
            status('saved', 'Saved');
            broadcast(edits);
          } else {
            status('error', 'Server ' + resp.status);
          }
        } catch (err) {
          status('error', 'Save failed');
        }
      } else {
        /* non‑clone page: stage changes for the next capture */
        if (!window.__LYNK_STAGED_EDITS__) window.__LYNK_STAGED_EDITS__ = [];
        window.__LYNK_STAGED_EDITS__.push.apply(window.__LYNK_STAGED_EDITS__, edits);
        status('saved', 'Staged');
        broadcast(edits);
      }
    }

    function broadcast(edits) {
      if (window.parent && window.parent !== window) {
        try {
          window.parent.postMessage({
            type: 'lynk:clone-edit',
            clone_id: CLONE_ID,
            edits: edits
          }, '*');
        } catch (e) {}
      }
    }

    /* ---- full source view ---- */
    function openSource() {
      if (!state.toolbar) return;
      var modal = state.toolbar.shadow.querySelector('[data-modal]');
      var ta = modal.querySelector('[data-source]');
      ta.value = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
      modal.classList.add('open');
    }

    function closeSource() {
      if (!state.toolbar) return;
      state.toolbar.shadow.querySelector('[data-modal]').classList.remove('open');
    }

    async function saveSource() {
      if (!state.toolbar) return;
      var html = state.toolbar.shadow.querySelector('[data-source]').value;
      html = html.replace(/^<!DOCTYPE[^>]*>\s*/i, '');

      if (IS_CLONE && CLONE_ID) {
        try {
          var resp = await fetch(ep(SOURCE_ENDPOINT), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ html: html })
          });
          if (resp.ok) {
            status('saved', 'Source saved');
            closeSource();
            /* soft reload so the new source renders */
            setTimeout(function () { location.reload(); }, 400);
          } else {
            status('error', 'Server ' + resp.status);
          }
        } catch (err) {
          status('error', 'Save failed');
        }
      } else {
        try {
          var parser = new DOMParser();
          var doc = parser.parseFromString(html, 'text/html');
          document.documentElement.innerHTML = doc.documentElement.innerHTML;
          closeSource();
          status('saved', 'Source applied');
        } catch (err) {
          status('error', 'Parse failed');
        }
      }
    }

    /* ---- undo / redo ---- */
    function undo() {
      var snap = state.undoStack.pop();
      if (!snap) return;
      var target;
      try { target = document.querySelector(snap.selector); } catch (e) { return; }
      if (!target) return;
      state.redoStack.push({ selector: snap.selector, html: target.outerHTML });
      /* we can't restore exact previous html here without a before stack;
         use the pending value if present, else skip */
      if (state.pending.has(snap.selector)) {
        var prev = state.pending.get(snap.selector);
        try {
          var temp = document.createElement('div');
          temp.innerHTML = prev;
          var prevEl = temp.firstElementChild;
          if (prevEl) target.replaceWith(prevEl);
        } catch (e) {}
      }
      status('', 'Undo');
    }

    function redo() {
      var snap = state.redoStack.pop();
      if (!snap) return;
      var target;
      try { target = document.querySelector(snap.selector); } catch (e) { return; }
      if (!target) return;
      state.undoStack.push({ selector: snap.selector, html: target.outerHTML });
      try {
        var temp = document.createElement('div');
        temp.innerHTML = snap.html;
        var nextEl = temp.firstElementChild;
        if (nextEl) target.replaceWith(nextEl);
        state.pending.set(snap.selector, snap.html);
        scheduleFlush();
      } catch (e) {}
    }

    /* ---- mouse handlers ---- */
    function onMouseOver(e) {
      if (!state.active) return;
      if (state.toolbar && state.toolbar.host.contains(e.target)) return;
      var outline = state.toolbar.shadow.querySelector('[data-outline]');
      if (!outline) return;
      var rect = e.target.getBoundingClientRect();
      outline.style.cssText =
        'position:fixed;left:' + rect.left + 'px;top:' + rect.top + 'px;' +
        'width:' + rect.width + 'px;height:' + rect.height + 'px;display:block;' +
        'pointer-events:none;z-index:2147483646;border:2px solid #38bdf8;' +
        'background:rgba(56,189,248,.08);border-radius:2px;';
    }

    function onClick(e) {
      if (!state.active) return;
      if (state.toolbar && state.toolbar.host.contains(e.target)) return;
      var t = e.target;
      if (!t || t.nodeType !== 1) return;
      if (t.tagName === 'A') e.preventDefault();
      e.stopPropagation();

      document.querySelectorAll('[data-lynk-edit="active"]').forEach(function (el) {
        el.removeAttribute('data-lynk-edit');
      });
      t.setAttribute('data-lynk-edit', 'active');

      state.selected = t;
      state.selectedSelector = getSelector(t);

      var s = state.toolbar.shadow;
      s.querySelector('[data-sidebar]').classList.add('open');
      s.querySelector('[data-selector]').textContent = state.selectedSelector || '—';
      s.querySelector('[data-editor]').value = t.outerHTML;
    }

    function onDblClick(e) {
      if (!state.active) return;
      if (state.toolbar && state.toolbar.host.contains(e.target)) return;
      var t = e.target;
      if (!t || t.nodeType !== 1) return;
      e.preventDefault();
      try {
        t.setAttribute('contenteditable', 'true');
        t.focus();
        t.__lynkEditing = true;
        t.addEventListener('blur', function onBlur() {
          if (!t.__lynkEditing) return;
          t.__lynkEditing = false;
          t.removeAttribute('contenteditable');
          var sel = getSelector(t);
          if (sel) {
            state.undoStack.push({ selector: sel, html: t.outerHTML });
            state.redoStack.length = 0;
            state.pending.set(sel, t.outerHTML);
            scheduleFlush();
          }
          t.removeEventListener('blur', onBlur);
        });
      } catch (err) {}
    }

    function onKeyDown(e) {
      if (!state.active) return;
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        flush(true);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        exit();
      } else if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
        e.preventDefault();
        if (e.shiftKey) redo(); else undo();
      }
    }

    /* ---- enter / exit / toggle ---- */
    function enter() {
      if (state.active) return;
      if (!state.toolbar) createUI();
      else state.toolbar.host.style.display = '';
      state.active = true;
      document.body.style.paddingTop = '40px';

      document.addEventListener('mouseover', onMouseOver, true);
      document.addEventListener('click', onClick, true);
      document.addEventListener('dblclick', onDblClick, true);
      document.addEventListener('keydown', onKeyDown, true);

      status('', 'Editing');
    }

    function exit() {
      if (!state.active) return;
      flush(true);
      state.active = false;
      if (state.toolbar) {
        state.toolbar.host.style.display = 'none';
        var outline = state.toolbar.shadow.querySelector('[data-outline]');
        if (outline) outline.style.display = 'none';
      }
      document.body.style.paddingTop = '';
      document.removeEventListener('mouseover', onMouseOver, true);
      document.removeEventListener('click', onClick, true);
      document.removeEventListener('dblclick', onDblClick, true);
      document.removeEventListener('keydown', onKeyDown, true);
      document.querySelectorAll('[data-lynk-edit="active"]').forEach(function (el) {
        el.removeAttribute('data-lynk-edit');
      });
    }

    function toggle() { if (state.active) exit(); else enter(); }

    /* ---- incoming remote edits ---- */
    function applyIncoming(edits) {
      if (!Array.isArray(edits)) return;
      edits.forEach(function (edit) {
        try {
          if (state.selected && state.selectedSelector === edit.selector) return;
          var el = document.querySelector(edit.selector);
          if (!el) return;
          var temp = document.createElement('div');
          temp.innerHTML = edit.html;
          var newEl = temp.firstElementChild;
          if (newEl) el.replaceWith(newEl);
        } catch (e) {}
      });
    }

    return {
      toggle: toggle,
      enter: enter,
      exit: exit,
      openSource: openSource,
      applyIncoming: applyIncoming,
      isActive: function () { return state.active; }
    };
  })();

  /* ================= BOOT ================= */

  /* keyboard shortcut: Ctrl+Shift+E */
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'E' || e.key === 'e')) {
      e.preventDefault();
      Editor.toggle();
    }
  });

  /* expose for shell */
  window.LynkEditor = Editor;
  window.LynkCapture = { capture: captureAll, send: sendCapture };

  /* shell ↔ page messages */
  window.addEventListener('message', function (e) {
    var d = e.data;
    if (!d || !d.type) return;
    switch (d.type) {
      case 'lynk:editor-enter': Editor.enter(); break;
      case 'lynk:editor-exit': Editor.exit(); break;
      case 'lynk:editor-toggle': Editor.toggle(); break;
      case 'lynk:editor-source': Editor.openSource(); break;
      case 'lynk:clone-edit':
        if (IS_CLONE && d.clone_id === CLONE_ID) {
          Editor.applyIncoming(d.edits || []);
        }
        break;
    }
  });

  /* capture button binding */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindCloneButton, { once: true });
  } else {
    bindCloneButton();
  }
})();
