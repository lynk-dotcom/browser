#!/usr/bin/env python3
"""
Lynkio Cloner — full page/session/DOM/storage capture + rehydrate.

v4 changes:
  • _json_for_script() escapes `</` in every JSON dumped inside a <script>
    tag. Without this, JSON containing `</script>` (common in Facebook /
    Instagram error payloads) closes the tag early and the rest of the
    JSON is rendered as visible page text on the clone.
  • State is now embedded in <script type="application/json"> and read
    via JSON.parse in cloner_hydrate.js — never as inline JS assignment.
"""

import base64
import copy
import gzip
import hashlib
import html as _html_mod
import json
import logging
import os
import time
import uuid as _uuid
from collections import deque
from urllib.parse import urlparse

log = logging.getLogger("lynk.cloner")

HERE       = os.path.dirname(os.path.abspath(__file__))
CLONES_DIR = os.path.join(HERE, "clones")
os.makedirs(CLONES_DIR, exist_ok=True)

MAX_CLONES             = 2000
MAX_RAW_BYTES          = 64 * 1024 * 1024
MAX_STORED_BYTES       = 512 * 1024 * 1024
INLINE_STATE_THRESHOLD = 8 * 1024 * 1024

CLONE_VISITOR_COOKIE = "__lynk_clone_vid"


# ======================================================================
# Safe JSON for <script> tags
# ======================================================================

def _json_for_script(obj):
    """
    Return obj as a JSON string safe to embed inside <script>...</script>.

    Escapes `</` → `<\\/` so the browser parser doesn't see a closing tag
    mid-JSON. `\\/` is a valid JSON (and JS) escape for `/`, so parsing
    restores the original value exactly.
    Also escapes U+2028 / U+2029 (line separators) which break inline JS.
    """
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    s = s.replace("</", "<\\/")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s


# ======================================================================
# Storage
# ======================================================================

def _clone_path(cid):
    return os.path.join(CLONES_DIR, f"{cid}.json.gz")


def _list_files():
    try:
        return [f for f in os.listdir(CLONES_DIR) if f.endswith(".json.gz")]
    except FileNotFoundError:
        return []


def _enforce_capacity():
    files = _list_files()
    if len(files) < MAX_CLONES:
        return
    entries = []
    for f in files:
        full = os.path.join(CLONES_DIR, f)
        try:
            entries.append((os.path.getmtime(full), full))
        except OSError:
            pass
    entries.sort()
    excess = len(entries) - MAX_CLONES + 1
    for _, path in entries[:max(0, excess)]:
        try:
            os.remove(path)
            log.info("cloner: evicted %s", os.path.basename(path))
        except OSError:
            pass


def save_clone(clone):
    _enforce_capacity()
    blob = json.dumps(clone, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(blob, compresslevel=6)
    if len(compressed) > MAX_STORED_BYTES:
        raise ValueError(
            f"clone too large: {len(compressed)} compressed bytes "
            f"(limit {MAX_STORED_BYTES})"
        )
    path = _clone_path(clone["uuid"])
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(compressed)
    os.replace(tmp, path)
    log.info("cloner: saved %s (%d → %d)",
             clone["uuid"], len(blob), len(compressed))


def load_clone(cid):
    path = _clone_path(cid)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            blob = gzip.decompress(f.read())
        return json.loads(blob.decode("utf-8"))
    except Exception as e:
        log.warning("cloner: load %s failed: %s", cid, e)
        return None


def delete_clone(cid):
    try:
        os.remove(_clone_path(cid))
        return True
    except FileNotFoundError:
        return False


def list_clones():
    out = []
    for f in _list_files():
        cid = f[:-len(".json.gz")]
        full = os.path.join(CLONES_DIR, f)
        try:
            size = os.path.getsize(full)
            with open(full, "rb") as fh:
                blob = gzip.decompress(fh.read())
            c = json.loads(blob.decode("utf-8"))
            dom = c.get("dom_state") or {}
            out.append({
                "uuid": cid,
                "source_url": c.get("source_url", ""),
                "page_origin": c.get("page_origin", ""),
                "created_at": c.get("created_at", 0),
                "edit_count": c.get("edit_count", 0),
                "size": size,
                "has_indexeddb": bool(c.get("indexeddb")),
                "has_caches": bool(c.get("caches")),
                "has_opfs": bool(c.get("opfs")),
                "dom_counts": {
                    "forms": len(dom.get("forms") or []),
                    "scrolls": len(dom.get("scrolls") or []),
                    "canvases": len(dom.get("canvases") or []),
                    "media": len(dom.get("media") or []),
                    "shadows": len(dom.get("shadows") or []),
                },
                "globals_count": len(c.get("globals") or {}),
            })
        except Exception as e:
            log.debug("cloner: skip %s (%s)", f, e)
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out


# ======================================================================
# Capture / hydrate
# ======================================================================

def capture_from_client(sess, payload):
    target_url = (payload.get("target_url") or sess.last_origin or "").strip()
    outer_html = payload.get("outer_html") or ""
    if not outer_html:
        raise ValueError("outer_html is required")

    parsed = urlparse(target_url)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        page_origin = f"{parsed.scheme}://{parsed.netloc}"
    else:
        page_origin = sess.page_origin or ""

    now = time.time()
    clone = {
        "uuid": _uuid.uuid4().hex[:16],
        "created_at": now,
        "source_url": target_url,
        "page_origin": page_origin,
        "final_path": parsed.path or "/",

        "server_cookies": {k: dict(v) for k, v in sess.cookies.by_origin.items()},
        "injected": [
            {"id": s["id"], "name": s["name"],
             "code": s["code"], "enabled": s["enabled"]}
            for s in sess.injected
        ],
        "history": list(sess.history)[-300:],
        "recent_origins": [[o, t] for o, t in sess.recent_origins],

        "outer_html": outer_html,
        "local_storage": payload.get("local_storage") or {},
        "session_storage": payload.get("session_storage") or {},
        "document_cookies": payload.get("document_cookies") or "",
        "indexeddb": payload.get("indexeddb") or {},
        "caches": payload.get("caches") or {},
        "opfs": payload.get("opfs"),
        "dom_state": payload.get("dom_state") or {},
        "globals": payload.get("globals") or {},

        "user_agent": payload.get("user_agent") or "",
        "viewport": payload.get("viewport") or {},
        "edit_count": 0,
        "last_edit_ts": 0,
    }
    save_clone(clone)
    return clone


def hydrate_session_from_clone(sess, clone):
    sess.cookies.by_origin = copy.deepcopy(clone.get("server_cookies") or {})
    sess.page_origin = clone.get("page_origin", "")
    sess.last_origin = sess.page_origin
    sess.injected = [dict(s) for s in (clone.get("injected") or [])]
    sess.history = deque(clone.get("history") or [], maxlen=1000)
    sess.recent_origins = deque(
        [(o, t) for o, t in (clone.get("recent_origins") or [])], maxlen=24,
    )


def clone_session_id(clone_uuid, visitor_id):
    return hashlib.sha256(
        f"{clone_uuid}|{visitor_id}".encode()).hexdigest()[:32]


def state_payload(clone):
    return {
        "uuid": clone["uuid"],
        "source_url": clone.get("source_url", ""),
        "page_origin": clone.get("page_origin", ""),
        "local_storage": clone.get("local_storage") or {},
        "session_storage": clone.get("session_storage") or {},
        "document_cookies": clone.get("document_cookies") or "",
        "indexeddb": clone.get("indexeddb") or {},
        "caches": clone.get("caches") or {},
        "opfs": clone.get("opfs"),
        "dom_state": clone.get("dom_state") or {},
        "globals": clone.get("globals") or {},
        "injected": clone.get("injected") or [],
    }


def build_clone_html(clone, sid=None):
    """Insert hydrate bootstrap at the top of <head>."""
    html = clone["outer_html"]
    state = state_payload(clone)
    # Size check uses json.dumps default (no escaping) — close enough.
    blob = json.dumps(state, separators=(",", ":")).encode("utf-8")

    ctx = {
        "upstream": clone.get("source_url", ""),
        "_injected": [
            s["code"] for s in (clone.get("injected") or [])
            if s.get("enabled")
        ],
    }
    if sid:
        ctx["sid"] = sid

    # Escape </ in both JSON blobs so the browser parser can't see a
    # premature closing tag inside them.
    ctx_script = (
        '<script>'
        f'window.__LYNK_CTX__={_json_for_script(ctx)};'
        'window.__LYNK_SW__=1;'
        '</script>'
    )

    if len(blob) <= INLINE_STATE_THRESHOLD:
        state_json = _json_for_script(state)
        bootstrap = (
            '<script type="application/json" id="__lynk_clone_state">'
            + state_json
            + '</script>'
            + ctx_script
            + '<script src="/static/js/cloner_hydrate.js"></script>'
        )
    else:
        bootstrap = (
            '<script>'
            f'window.__LYNK_CLONE_STATE_URL__="/clone/{clone["uuid"]}/state.json";'
            '</script>'
            + ctx_script
            + '<script src="/static/js/cloner_hydrate.js"></script>'
        )

    lower = html.lower()
    idx = lower.find("<head")
    if idx != -1:
        close = lower.find(">", idx)
        if close != -1:
            return html[:close + 1] + bootstrap + html[close + 1:]
    idx = lower.find("<html")
    if idx != -1:
        close = lower.find(">", idx)
        if close != -1:
            return html[:close + 1] + "<head>" + bootstrap + "</head>" + html[close + 1:]
    return ("<!DOCTYPE html><html><head>" + bootstrap
            + "</head><body>" + html + "</body></html>")


# ======================================================================
# Editor page
# ======================================================================

_EDITOR_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clone Editor · Lynkio</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/lib/codemirror.css">
<style>
:root{--bg:#070b16;--bg-2:#0d1526;--bg-3:#131d33;--fg:#e2e8f0;--fg-muted:#94a3b8;
--fg-dim:#64748b;--line:rgba(148,163,184,.16);--accent:#38bdf8;
--ok:#10b981;--warn:#f59e0b;--danger:#f87171;--grad:linear-gradient(135deg,#38bdf8,#818cf8)}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden;font-family:'Inter',system-ui,-apple-system,sans-serif;
background:var(--bg);color:var(--fg)}
body{display:flex;flex-direction:column}
.header{display:flex;align-items:center;gap:14px;padding:12px 18px;background:var(--bg-2);
border-bottom:1px solid var(--line);flex-shrink:0}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.mark{width:30px;height:30px;border-radius:8px;background:var(--grad);display:grid;
place-items:center;color:#0b1220;font-size:14px;font-weight:800;flex-shrink:0}
.title{font-weight:700;font-size:13.5px;line-height:1.2}
.subtitle{font-size:11px;color:var(--fg-dim);font-family:'JetBrains Mono',monospace;
max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.spacer{flex:1}
.status{font-family:'JetBrains Mono',monospace;font-size:11px;padding:4px 10px;
border-radius:6px;background:rgba(148,163,184,.08);color:var(--fg-muted);white-space:nowrap}
.status.saving{color:var(--warn)}
.status.saved{color:var(--ok)}
.status.error{color:var(--danger)}
.btn{padding:6px 12px;border-radius:7px;border:1px solid rgba(148,163,184,.25);
background:transparent;color:var(--fg);font-family:inherit;font-size:12px;font-weight:600;
cursor:pointer;transition:.15s}
.btn:hover{background:rgba(56,189,248,.1);border-color:rgba(56,189,248,.45);color:var(--accent)}
.btn.primary{background:var(--grad);color:#0b1220;border:none}
.main{flex:1;display:grid;grid-template-columns:1fr 1fr;min-height:0}
.editor-pane,.preview-pane{display:flex;flex-direction:column;min-height:0;overflow:hidden}
.editor-pane{border-right:1px solid var(--line);background:var(--bg-2)}
.tabs{display:flex;gap:2px;padding:6px 8px 0;background:var(--bg-2);
border-bottom:1px solid var(--line);flex-shrink:0}
.tab-btn{padding:7px 14px;border-radius:6px 6px 0 0;border:none;background:transparent;
color:var(--fg-muted);font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;
border-bottom:2px solid transparent}
.tab-btn:hover{color:var(--fg);background:rgba(148,163,184,.06)}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);
background:rgba(56,189,248,.08)}
.editor-host{flex:1;min-height:0;overflow:auto;background:#050a14}
.editor-host.hidden{display:none}
.CodeMirror{height:100% !important;background:#050a14 !important;color:var(--fg) !important;
font-family:'JetBrains Mono',ui-monospace,monospace !important;font-size:12px !important;
line-height:1.55 !important}
.CodeMirror-gutters{background:#070b16 !important;border-right:1px solid var(--line) !important}
.CodeMirror-linenumber{color:var(--fg-dim) !important}
.CodeMirror-cursor{border-left-color:var(--accent) !important}
.cm-tag{color:#f472b6 !important}
.cm-attribute{color:#a78bfa !important}
.cm-string{color:#34d399 !important}
.cm-comment{color:#64748b !important;font-style:italic}
.cm-number{color:#f59e0b !important}
.cm-keyword{color:#38bdf8 !important}
.state-textarea{width:100%;height:100%;min-height:200px;background:#050a14;color:var(--fg);
border:none;padding:14px;font-family:'JetBrains Mono',ui-monospace,monospace;
font-size:12px;line-height:1.55;outline:none;resize:none;box-sizing:border-box}
.preview-toolbar{display:flex;align-items:center;gap:10px;padding:8px 14px;
background:var(--bg-2);border-bottom:1px solid var(--line);flex-shrink:0}
.preview-toolbar .label{font-size:11px;color:var(--fg-dim);font-weight:600;
text-transform:uppercase;letter-spacing:.06em}
.preview-toolbar .btn{padding:4px 10px;font-size:11px}
.preview-toolbar .preview-url{font-family:'JetBrains Mono',monospace;font-size:11px;
color:var(--fg-dim);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#previewFrame{flex:1;width:100%;border:none;background:#fff;min-height:0}
.footer{padding:4px 14px;background:var(--bg-2);border-top:1px solid var(--line);
font-size:11px;color:var(--fg-dim);font-family:'JetBrains Mono',monospace;
display:flex;gap:14px;flex-shrink:0}
.toast{position:fixed;bottom:24px;right:24px;padding:10px 16px;border-radius:8px;
background:var(--bg-3);border:1px solid var(--line);color:var(--fg);
font-size:12.5px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,.4);
transform:translateY(80px);opacity:0;transition:.25s cubic-bezier(.34,1.36,.64,1);
pointer-events:none;z-index:1000}
.toast.show{transform:translateY(0);opacity:1}
.toast.error{border-color:rgba(248,113,113,.4);color:var(--danger)}
.toast.ok{border-color:rgba(16,185,129,.4);color:var(--ok)}
.spin{display:inline-block;width:10px;height:10px;border:2px solid currentColor;
border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;
vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:900px){
.main{grid-template-columns:1fr}
.editor-pane{border-right:none;border-bottom:1px solid var(--line);max-height:50vh}
.preview-pane{min-height:50vh}
.subtitle{max-width:180px}}
</style></head><body>

<header class="header">
  <div class="brand">
    <div class="mark">L</div>
    <div>
      <div class="title">Clone Editor</div>
      <div class="subtitle" id="subtitle">{{UUID}} · {{SOURCE_URL}}</div>
    </div>
  </div>
  <div class="spacer"></div>
  <div class="status" id="saveStatus">Ready</div>
  <button class="btn" id="btnSaveNow" title="Force save">Save now</button>
  <button class="btn" id="btnPreview" title="Reload preview">↻ Reload preview</button>
  <button class="btn" id="btnBack" title="Back to browser">← Back</button>
</header>

<main class="main">
  <section class="editor-pane">
    <div class="tabs">
      <button class="tab-btn active" data-tab="html">HTML</button>
      <button class="tab-btn" data-tab="localStorage">localStorage</button>
      <button class="tab-btn" data-tab="sessionStorage">sessionStorage</button>
    </div>
    <div class="editor-host" id="htmlEditor"></div>
    <div class="editor-host hidden" id="lsEditor">
      <textarea class="state-textarea" id="lsTextarea" spellcheck="false"></textarea>
    </div>
    <div class="editor-host hidden" id="ssEditor">
      <textarea class="state-textarea" id="ssTextarea" spellcheck="false"></textarea>
    </div>
  </section>
  <section class="preview-pane">
    <div class="preview-toolbar">
      <span class="label">Preview</span>
      <span class="preview-url" id="previewUrl">/clone/{{UUID}}</span>
      <button class="btn" id="btnOpenPreview" title="Open in new tab">Open ↗</button>
    </div>
    <iframe id="previewFrame" src="/clone/{{UUID}}"></iframe>
  </section>
</main>

<div class="footer">
  <span>UUID: {{UUID}}</span>
  <span id="ftEditCount">Edits: 0</span>
  <span id="ftLastEdit">Last edit: —</span>
  <span>Auto-save: 600ms</span>
</div>

<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/lib/codemirror.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/xml/xml.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/javascript/javascript.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/css/css.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/htmlmixed/htmlmixed.js"></script>
<script>
(function() {
  'use strict';
  var UUID = '{{UUID}}';
  var SAVE_DEBOUNCE_MS = 600;

  var elStatus = document.getElementById('saveStatus');
  var elToast = document.getElementById('toast');
  var elPreviewFrame = document.getElementById('previewFrame');
  var elHtmlHost = document.getElementById('htmlEditor');
  var elHtmlHostLs = document.getElementById('lsEditor');
  var elHtmlHostSs = document.getElementById('ssEditor');
  var elLsTextarea = document.getElementById('lsTextarea');
  var elSsTextarea = document.getElementById('ssTextarea');
  var elFtEditCount = document.getElementById('ftEditCount');
  var elFtLastEdit = document.getElementById('ftLastEdit');

  var cm = null;
  var activeTab = 'html';
  var saveTimer = null;
  var isSaving = false;
  var needsResave = false;
  var dirty = false;

  var toastTimer = null;
  function toast(msg, kind) {
    elToast.textContent = msg;
    elToast.className = 'toast show' + (kind ? ' ' + kind : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ elToast.classList.remove('show'); }, 2400);
  }
  function setStatus(kind, text) {
    elStatus.className = 'status' + (kind ? ' ' + kind : '');
    elStatus.textContent = text || 'Ready';
    if (kind === 'saving') {
      var sp = document.createElement('span');
      sp.className = 'spin';
      elStatus.insertBefore(sp, elStatus.firstChild);
    }
  }
  async function loadSource() {
    var r = await fetch('/clone/' + UUID + '/source', { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }
  async function loadMeta() {
    try {
      var r = await fetch('/clone/' + UUID + '/meta', { credentials: 'same-origin' });
      return r.ok ? r.json() : {};
    } catch(e) { return {}; }
  }
  async function loadState() {
    try {
      var r = await fetch('/clone/' + UUID + '/state.json', { credentials: 'same-origin' });
      return r.ok ? r.json() : {};
    } catch(e) { return {}; }
  }
  function initEditor(initialHtml) {
    if (typeof CodeMirror === 'undefined') {
      var ta = document.createElement('textarea');
      ta.className = 'state-textarea';
      ta.value = initialHtml;
      ta.spellcheck = false;
      ta.addEventListener('input', onHtmlChange);
      elHtmlHost.appendChild(ta);
      cm = { getValue: function(){ return ta.value; }, refresh: function(){} };
      return;
    }
    cm = CodeMirror(elHtmlHost, {
      value: initialHtml, mode: 'htmlmixed', lineNumbers: true,
      lineWrapping: true, matchBrackets: true, autoCloseBrackets: true,
      autoCloseTags: true, indentUnit: 2, tabSize: 2, indentWithTabs: false,
    });
    cm.on('change', onHtmlChange);
  }
  function onHtmlChange(){ dirty = true; scheduleSave(); }
  function onStateChange(){ dirty = true; scheduleSave(); }
  function scheduleSave(){
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, SAVE_DEBOUNCE_MS);
    setStatus('saving', 'Saving…');
  }
  async function saveNow(){
    if (isSaving) { needsResave = true; return; }
    isSaving = true; needsResave = false;
    try {
      if (activeTab === 'html') {
        var html = cm.getValue();
        var r = await fetch('/clone/' + UUID + '/source', {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ outer_html: html }),
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        var j = await r.json();
        if (!j.ok) throw new Error(j.error || 'Save failed');
        updateEditMeta(j.edit_count);
      } else if (activeTab === 'localStorage') {
        var raw = elLsTextarea.value, obj;
        try { obj = JSON.parse(raw || '{}'); }
        catch(e) { throw new Error('Invalid JSON: ' + e.message); }
        var r2 = await fetch('/clone/' + UUID + '/state', {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ local_storage: obj }),
        });
        if (!r2.ok) throw new Error('HTTP ' + r2.status);
        var j2 = await r2.json();
        if (!j2.ok) throw new Error(j2.error || 'Save failed');
        updateEditMeta(j2.edit_count);
      } else if (activeTab === 'sessionStorage') {
        var raw2 = elSsTextarea.value, obj2;
        try { obj2 = JSON.parse(raw2 || '{}'); }
        catch(e) { throw new Error('Invalid JSON: ' + e.message); }
        var r3 = await fetch('/clone/' + UUID + '/state', {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_storage: obj2 }),
        });
        if (!r3.ok) throw new Error('HTTP ' + r3.status);
        var j3 = await r3.json();
        if (!j3.ok) throw new Error(j3.error || 'Save failed');
        updateEditMeta(j3.edit_count);
      }
      dirty = false;
      setStatus('saved', 'Saved');
      refreshPreview();
    } catch(e){
      setStatus('error', 'Error');
      toast(e.message || 'Save failed', 'error');
    } finally {
      isSaving = false;
      if (needsResave) { needsResave = false; scheduleSave(); }
    }
  }
  function updateEditMeta(count){
    if (typeof count === 'number') elFtEditCount.textContent = 'Edits: ' + count;
    elFtLastEdit.textContent = 'Last edit: ' + new Date().toLocaleTimeString();
  }
  function refreshPreview(){
    elPreviewFrame.src = '/clone/' + UUID + '?t=' + Date.now();
  }
  document.querySelectorAll('.tab-btn').forEach(function(btn){
    btn.addEventListener('click', async function(){
      if (dirty) await saveNow();
      var tab = btn.getAttribute('data-tab');
      if (tab === activeTab) return;
      activeTab = tab;
      document.querySelectorAll('.tab-btn').forEach(function(b){
        b.classList.toggle('active', b === btn);
      });
      elHtmlHost.classList.toggle('hidden', tab !== 'html');
      elHtmlHostLs.classList.toggle('hidden', tab !== 'localStorage');
      elHtmlHostSs.classList.toggle('hidden', tab !== 'sessionStorage');
      if (cm && cm.refresh) setTimeout(function(){ cm.refresh(); }, 30);
    });
  });
  document.getElementById('btnSaveNow').addEventListener('click', function(){
    clearTimeout(saveTimer); saveNow();
  });
  document.getElementById('btnPreview').addEventListener('click', refreshPreview);
  document.getElementById('btnOpenPreview').addEventListener('click', function(){
    window.open('/clone/' + UUID, '_blank');
  });
  document.getElementById('btnBack').addEventListener('click', function(){
    if (window.history.length > 1) window.history.back();
    else window.location.href = '/tabs';
  });
  window.addEventListener('beforeunload', function(e){
    if (dirty || isSaving) { e.preventDefault(); e.returnValue = ''; }
  });
  (async function boot(){
    setStatus('saving', 'Loading…');
    try {
      var source = await loadSource();
      var state = await loadState();
      var meta = await loadMeta();
      updateEditMeta(meta.edit_count || 0);
      if (meta.last_edit_ts) {
        elFtLastEdit.textContent = 'Last edit: ' + new Date(meta.last_edit_ts * 1000).toLocaleString();
      }
      initEditor(source.outer_html || '');
      elLsTextarea.value = JSON.stringify(state.local_storage || {}, null, 2);
      elLsTextarea.addEventListener('input', onStateChange);
      elSsTextarea.value = JSON.stringify(state.session_storage || {}, null, 2);
      elSsTextarea.addEventListener('input', onStateChange);
      setStatus('', 'Ready');
    } catch(e){
      setStatus('error', 'Load failed');
      toast('Load failed: ' + e.message, 'error');
    }
  })();
})();
</script>
</body></html>
"""


def _build_editor_html(clone):
    uuid_safe = _html_mod.escape(clone.get("uuid", ""), quote=True)
    src_safe  = _html_mod.escape(clone.get("source_url", ""), quote=True)
    return _EDITOR_HTML.replace("{{UUID}}", uuid_safe).replace("{{SOURCE_URL}}", src_safe)


# ======================================================================
# Route installer
# ======================================================================

def install(app, ctx):
    get_session      = ctx["get_session"]
    Session          = ctx["Session"]
    RawResponse      = ctx["RawResponse"]
    json_response    = ctx["json_response"]
    error_page       = ctx["error_page"]
    SESSION_COOKIE   = ctx["SESSION_COOKIE"]
    session_from_req = ctx["session_from_req"]
    SESSIONS         = ctx["SESSIONS"]

    def _visitor(req):
        vid = req.cookies.get(CLONE_VISITOR_COOKIE, "")
        new = False
        if not vid or len(vid) < 8:
            vid = _uuid.uuid4().hex[:16]
            new = True
        return vid, new

    @app.route("/clone/capture-client", methods=["POST"])
    async def clone_capture_client(req):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        body = req.body or b""
        if len(body) > MAX_RAW_BYTES:
            return json_response(
                {"error": f"payload too large ({len(body)} > {MAX_RAW_BYTES})"},
                status=413,
            )
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError as e:
            return json_response({"error": f"invalid JSON: {e}"}, status=400)
        try:
            clone = capture_from_client(sess, payload)
        except ValueError as e:
            return json_response({"error": str(e)}, status=400)
        except Exception as e:
            log.exception("cloner: capture failed")
            return json_response({"error": f"capture failed: {e}"}, status=500)
        return json_response({
            "uuid": clone["uuid"],
            "url": f"/clone/{clone['uuid']}",
            "source_url": clone["source_url"],
        })

    @app.route("/clone/import", methods=["POST"])
    async def clone_import(req):
        body = req.body or b""
        if len(body) > MAX_RAW_BYTES:
            return json_response({"error": "too large"}, status=413)
        try:
            c = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError as e:
            return json_response({"error": f"invalid JSON: {e}"}, status=400)
        if "uuid" not in c or "outer_html" not in c:
            return json_response({"error": "not a clone file"}, status=400)
        c["uuid"] = _uuid.uuid4().hex[:16]
        c.setdefault("created_at", time.time())
        c.setdefault("edit_count", 0)
        c.setdefault("last_edit_ts", 0)
        try:
            save_clone(c)
        except ValueError as e:
            return json_response({"error": str(e)}, status=413)
        return json_response({"uuid": c["uuid"], "url": f"/clone/{c['uuid']}"})

    @app.get("/clones")
    async def clones_index(req):
        return json_response({"clones": list_clones()})

    @app.get("/clone/*/state.json")
    async def clone_state_json(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        return json_response(state_payload(c))

    @app.route("/clone/*/state", methods=["PUT"])
    async def clone_state_put(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        try:
            payload = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return json_response({"error": "invalid JSON"}, status=400)
        if "local_storage" in payload:
            c["local_storage"] = payload["local_storage"] if isinstance(payload["local_storage"], dict) else {}
        if "session_storage" in payload:
            c["session_storage"] = payload["session_storage"] if isinstance(payload["session_storage"], dict) else {}
        if "document_cookies" in payload:
            c["document_cookies"] = str(payload["document_cookies"] or "")
        c["edit_count"] = int(c.get("edit_count", 0)) + 1
        c["last_edit_ts"] = time.time()
        try:
            save_clone(c)
        except ValueError as e:
            return json_response({"error": str(e)}, status=413)
        return json_response({"ok": True, "edit_count": c["edit_count"]})

    @app.get("/clone/*/source")
    async def clone_source_get(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        return json_response({
            "uuid": cid,
            "source_url": c["source_url"],
            "outer_html": c["outer_html"],
            "edit_count": c["edit_count"],
        })

    @app.route("/clone/*/source", methods=["PUT"])
    async def clone_source_put(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        try:
            payload = json.loads(
                (req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return json_response({"error": "invalid JSON"}, status=400)
        new_html = payload.get("outer_html")
        if not isinstance(new_html, str):
            return json_response({"error": "outer_html required"}, status=400)
        c["outer_html"] = new_html
        c["edit_count"] = int(c.get("edit_count", 0)) + 1
        c["last_edit_ts"] = time.time()
        try:
            save_clone(c)
        except ValueError as e:
            return json_response({"error": str(e)}, status=413)
        return json_response({"ok": True, "edit_count": c["edit_count"]})

    @app.get("/clone/*/meta")
    async def clone_meta(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        dom = c.get("dom_state") or {}
        return json_response({
            "uuid": cid,
            "source_url": c["source_url"],
            "page_origin": c["page_origin"],
            "created_at": c["created_at"],
            "edit_count": c["edit_count"],
            "last_edit_ts": c["last_edit_ts"],
            "cookie_origins": list((c.get("server_cookies") or {}).keys()),
            "injected_count": len(c.get("injected") or []),
            "history_count": len(c.get("history") or []),
            "local_storage_keys": list((c.get("local_storage") or {}).keys()),
            "session_storage_keys": list((c.get("session_storage") or {}).keys()),
            "indexeddb_dbs": list((c.get("indexeddb") or {}).keys()),
            "cache_names": list((c.get("caches") or {}).keys()),
            "opfs_present": bool(c.get("opfs")),
            "dom_counts": {
                "forms": len(dom.get("forms") or []),
                "scrolls": len(dom.get("scrolls") or []),
                "canvases": len(dom.get("canvases") or []),
                "media": len(dom.get("media") or []),
                "shadows": len(dom.get("shadows") or []),
            },
            "globals_count": len(c.get("globals") or {}),
        })

    @app.get("/clone/*/export")
    async def clone_export(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        blob = json.dumps(c, ensure_ascii=False).encode("utf-8")
        resp = RawResponse(blob, content_type="application/json")
        resp.add_header("Content-Disposition",
                        f'attachment; filename="{cid}.lynkclone"')
        return resp

    @app.get("/clone/*/edit")
    async def clone_edit(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return error_page("Clone not found", f"No clone <code>{cid}</code>.", 404)
        html = _build_editor_html(c)
        return RawResponse(html.encode("utf-8"),
                           content_type="text/html; charset=utf-8")

    @app.route("/clone/*", methods=["GET", "DELETE"])
    async def clone_route(req, wildcard=""):
        raw = (wildcard or "").split("?", 1)[0]
        cid = raw.split("/", 1)[0].strip()
        if not cid:
            return error_page("Clone not found", "Missing clone id.", 404)

        if req.method == "DELETE":
            ok = delete_clone(cid)
            return json_response({"ok": ok}, status=200 if ok else 404)

        clone = load_clone(cid)
        if not clone:
            return error_page(
                "Clone not found",
                f"No clone with id <code>{cid}</code>.", 404,
            )

        vid, is_new = _visitor(req)
        sid = clone_session_id(cid, vid)
        if sid not in SESSIONS:
            sess = Session()
            hydrate_session_from_clone(sess, clone)
            sess.clone_uuid = cid
            sess.clone_visitor = vid
            SESSIONS[sid] = sess
        SESSIONS[sid].touch()

        html = build_clone_html(clone, sid)
        resp = RawResponse(html.encode("utf-8"),
                           content_type="text/html; charset=utf-8")
        resp.add_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax",
        )
        if is_new:
            resp.add_header(
                "Set-Cookie",
                f"{CLONE_VISITOR_COOKIE}={vid}; Path=/; Max-Age=86400; SameSite=Lax",
            )
        resp.add_header("Cache-Control", "no-store")
        return resp

    log.info("cloner: routes installed")
