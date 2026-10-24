/* Lynkio shell — v20.0
   Adds: real Chrome tab strip via CDP, one-click capture, graceful fallback
   when Chrome isn't available.

   Changes in this revision (all marked "FIX" in the code):
     1. LOAD_WATCHDOG raised 45000 → 180000 (45s → 180s). 45s is far too short
        for a proxied page whose every sub-resource round-trips through
        /proxy; DDG, Coinbase, Facebook routinely take 60–120 s to reach the
        iframe 'load' event.
     2. markTabBusy no longer uses a fixed 45 s setTimeout. It polls the
        iframe's contentDocument.readyState every 2 s and releases the tab
        the moment the DOM reaches 'interactive' or 'complete'. Only a
        genuinely hung navigation waits the full 180 s. This is why the
        "navigation watchdog fired (45s)" warning no longer appears before
        the page has actually loaded.
     3. markTabIdle and closeTab now also clear the new polling interval
        (tab._watchdogInterval) in addition to the legacy tab._watchdog.
     4. Initial tab, new-tab button, Ctrl+T, and the ctx-menu "New tab" all
        open https://duckduckgo.com/html/ (the JS-free endpoint) instead of
        https://duckduckgo.com/. This makes the default tab fully functional
        even if DDG's homepage.js is stubbed by Cloudflare.
*/
(function(){
"use strict";
if (window.__LYNK_SHELL__) return;
try { Object.defineProperty(window, '__LYNK_SHELL__', { value: true, enumerable: false }); }
catch(e) { window.__LYNK_SHELL__ = true; }

/* FIX: was 45000. 3 minutes lets a heavy proxied page finish loading its
   sub-resources without a spurious watchdog fire. Real hangs are rare and
   180 s is a reasonable upper bound before we force-release the tab. */
var LOAD_WATCHDOG   = 180000;
var BOOKMARK_KEY    = '__lynk_bookmarks_v4';
var ZOOM_KEY        = '__lynk_zoom_v4';
var DESKTOP_KEY     = '__lynk_desktop_mode_v1';
var TABS_KEY        = '__lynk_tabs_v1';
var CONSOLE_MAX     = 2000;
var CONSOLE_TOTAL   = 20000;
var DESKTOP_VP_W    = 1280;

/* FIX: JS-free DDG endpoint. Functional even when homepage.js is stubbed. */
var DEFAULT_TAB_URL = 'https://duckduckgo.com/html/';

var tabs        = [];
var activeId    = null;
var lastClosed  = null;
var loadingCount= 0;
var progressTrickle = null;
var progressDoneTimer = null;

var consoleBuffers    = Object.create(null);
var consoleTotalCount = 0;
var consoleFilter     = 'all';
var consoleOnlyActive = false;
var consoleSeq        = 0;
var consoleAutoScroll = true;

var _layoutTimer = null;

var stack          = document.getElementById('stack');
var tabList        = document.getElementById('tabs');
var urlInput       = document.getElementById('urlInput');
var urlLock        = document.getElementById('urlLock');
var urlStar        = document.getElementById('urlStar');
var urlCopy        = document.getElementById('urlCopy');
var btnBack        = document.getElementById('btnBack');
var btnFwd         = document.getElementById('btnFwd');
var btnReload      = document.getElementById('btnReload');
var btnGo          = document.getElementById('btnGo');
var progressEl     = document.getElementById('progress');
var statusDot      = document.getElementById('statusDot');
var statusText     = document.getElementById('statusText');
var wsBadge        = document.getElementById('wsBadge');
var stTabs         = document.getElementById('stTabs');
var stLink         = document.getElementById('stLink');
var stMeta         = document.getElementById('stMeta');
var ctxMenu        = document.getElementById('ctxMenu');
var toastEl        = document.getElementById('toast');
var emptyEl        = document.getElementById('empty');
var drawerConsole  = document.getElementById('drawerConsole');
var drawerKit      = document.getElementById('drawerKit');
var consoleList    = document.getElementById('consoleList');
var consoleTotal   = document.getElementById('consoleTotal');
var zoomLevelEl    = document.getElementById('zoomLevel');
var desktopToggleEl= document.getElementById('desktopToggle');
var cdpStrip       = document.getElementById('cdpStrip');
var cdpStatus      = document.getElementById('cdpStatus');
var cdpLaunch      = document.getElementById('cdpLaunch');

function escHtml(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function dl(name, text){
  try {
    var blob = new Blob([text], {type:'text/plain;charset=utf-8'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 500);
  } catch(e){}
}
var toastTimer = null;
function showToast(msg){
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function(){ toastEl.classList.remove('show'); }, 2600);
}
function newId(){ return 't_' + Math.random().toString(36).slice(2,10); }
function proxyURL(u){ return '/proxy?url=' + encodeURIComponent(u); }
function isSecure(url){ return /^https:/i.test(url); }

function isLocalURL(url){
  if (!url) return false;
  try {
    var u = new URL(url, location.origin);
    if (u.origin !== location.origin) return false;
    var p = u.pathname;
    return p === '/' || p === '/tabs' || p === '/clones' || p === '/healthz'
        || p.indexOf('/clone/') === 0
        || p.indexOf('/clones/') === 0
        || p.indexOf('/static/') === 0
        || p.indexOf('/tool/') === 0
        || p.indexOf('/lynkio/') === 0
        || p.indexOf('__lynk_') === 0
        || p.indexOf('/search') === 0
        || p.indexOf('/cdp/') === 0;
  } catch(e){ return false; }
}
function fullURL(url){
  if (!url) return '';
  if (/^https?:\/\//i.test(url)) return url;
  if (url.charAt(0) === '/') return location.origin + url;
  return url;
}
function copyToClipboard(text, label){
  if (!text) { showToast('Nothing to copy'); return; }
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){
      showToast(label || 'Copied');
    }).catch(function(){ _copyFallback(text, label); });
    return;
  }
  _copyFallback(text, label);
}
function _copyFallback(text, label){
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
    showToast(label || 'Copied');
  } catch(e){ showToast('Copy failed'); }
}
function realURLFromProxied(href){
  try {
    var u = new URL(href, location.origin);
    if (u.pathname === '/proxy')  return u.searchParams.get('url') || '';
    if (u.pathname === '/search'){
      var q = u.searchParams.get('q') || '';
      var e = u.searchParams.get('engine') || 'google';
      return '/search?q=' + encodeURIComponent(q) + '&engine=' + encodeURIComponent(e);
    }
  } catch(e){}
  return '';
}
function clamp(v, lo, hi){ return v < lo ? lo : v > hi ? hi : v; }

function progressStart(){
  clearTimeout(progressDoneTimer); clearInterval(progressTrickle);
  progressEl.classList.remove('done','complete');
  progressEl.classList.add('active');
  progressEl.style.width = '5%';
  requestAnimationFrame(function(){
    setTimeout(function(){ progressEl.style.width = '22%'; }, 80);
    setTimeout(function(){ progressEl.style.width = '48%'; }, 220);
    setTimeout(function(){ progressEl.style.width = '68%'; }, 600);
  });
  progressTrickle = setInterval(function(){
    var w = parseFloat(progressEl.style.width) || 0;
    if (w < 92) progressEl.style.width = Math.min(92, w + Math.random() * 2.5) + '%';
  }, 420);
}
function progressComplete(){
  clearInterval(progressTrickle);
  if (!progressEl.classList.contains('active') &&
      !progressEl.classList.contains('complete')) return;
  progressEl.classList.remove('active');
  progressEl.classList.add('complete');
  progressDoneTimer = setTimeout(function(){
    progressEl.classList.add('done');
    setTimeout(function(){
      progressEl.style.width = '0';
      progressEl.classList.remove('complete','done');
    }, 340);
  }, 240);
}
function setStatus(mode, text){
  statusDot.className = 'dot' + (mode ? ' ' + mode : '');
  statusText.textContent = text || 'Ready';
}

function activeTab(){
  for (var i = 0; i < tabs.length; i++) if (tabs[i].id === activeId) return tabs[i];
  return null;
}
function tabById(id){
  for (var i = 0; i < tabs.length; i++) if (tabs[i].id === id) return tabs[i];
  return null;
}
function findTabByWindow(w){
  for (var i = 0; i < tabs.length; i++){
    try { if (tabs[i].frame && tabs[i].frame.contentWindow === w) return tabs[i]; } catch(e){}
  }
  return null;
}
function activeTabURL(){ var t = activeTab(); return t ? t.url : ''; }
function activeTabHost(){
  try { return new URL(activeTabURL()).hostname; } catch(e){ return ''; }
}
function activeTabOrigin(){
  try { var x = new URL(activeTabURL()); return x.protocol + '//' + x.host; } catch(e){ return ''; }
}
function getIframeDoc(t){
  try {
    var f = t && t.frame; if (!f) return null;
    var d = f.contentDocument; if (!d || !d.body) return null;
    return d;
  } catch(e){ return null; }
}

/* FIX: markTabBusy now polls the iframe's contentDocument.readyState
   every 2 s instead of arming a fixed 45 s setTimeout. The tab is released
   the moment the DOM reaches 'interactive' or 'complete' — which happens
   long before the iframe 'load' event fires for a page with many proxied
   sub-resources. Only a genuine hang waits the full LOAD_WATCHDOG (180 s). */
function markTabBusy(tab){
  if (!tab) return;
  tab._navStart = Date.now();
  if (!tab.busy){
    tab.busy = true; loadingCount++;
    if (loadingCount === 1){ progressStart(); setStatus('busy', 'Loading…'); }
  }
  clearInterval(tab._watchdogInterval);
  tab._watchdogInterval = setInterval(function(){
    if (!tab.busy){ clearInterval(tab._watchdogInterval); return; }
    var elapsed = Date.now() - (tab._navStart || Date.now());
    try {
      var doc = tab.frame && tab.frame.contentDocument;
      /* 800ms guard: the OLD document is briefly still 'complete' right
         after src is reassigned; don't release on that stale state. */
      if (elapsed > 800 && doc &&
          (doc.readyState === 'interactive' || doc.readyState === 'complete')){
        markTabIdle(tab);
        return;
      }
    } catch(e){}
    if (elapsed >= LOAD_WATCHDOG){
      addConsole(tab.id, 'warn',
        'navigation did not finish within ' + Math.round(elapsed / 1000) + 's — releasing tab', '');
      markTabIdle(tab);
    }
  }, 2000);
  renderTabs(); updateNavState();
}
function markTabIdle(tab){
  if (tab){
    clearInterval(tab._watchdogInterval);
    clearTimeout(tab._watchdog);
    if (tab.busy){
      tab.busy = false;
      loadingCount = Math.max(0, loadingCount - 1);
    }
  }
  if (loadingCount === 0){
    progressComplete();
    var t = activeTab();
    setStatus(t && t.error ? 'err' : '', t && t.error ? 'Error' : 'Ready');
  }
  renderTabs(); updateNavState();
}
function updateNavState(){
  var t = activeTab();
  var busy = !!(t && t.busy);
  btnGo.disabled = busy;
  if (busy){ btnReload.textContent = '×'; btnReload.title = 'Stop (Esc)'; }
  else     { btnReload.textContent = '⟳'; btnReload.title = 'Reload (Ctrl+R)'; }
  btnBack.disabled = !t || t.hpos <= 0;
  btnFwd.disabled  = !t || t.hpos >= t.history.length - 1;
}

function getZoom(){
  var v = parseFloat(localStorage.getItem(ZOOM_KEY) || '1');
  return isFinite(v) && v > 0 ? v : 1;
}
function getDesktopMode(){
  try { return localStorage.getItem(DESKTOP_KEY) === '1'; } catch(e){ return false; }
}
function setDesktopModeRaw(on){
  try { localStorage.setItem(DESKTOP_KEY, on ? '1' : '0'); } catch(e){}
  if (desktopToggleEl){
    desktopToggleEl.classList.toggle('active', !!on);
    desktopToggleEl.setAttribute('aria-pressed', on ? 'true' : 'false');
    desktopToggleEl.title = on ? 'Switch to mobile view' : 'Switch to desktop view';
  }
}
function updateZoomDisplay(){
  if (zoomLevelEl){
    zoomLevelEl.textContent = Math.round(getZoom() * 100) + '%';
  }
}
function isMobileOnlyViewport(){
  try {
    if (window.matchMedia && window.matchMedia('(max-width: 640px)').matches) return true;
  } catch(e){}
  return (('ontouchstart' in window) && window.innerWidth < 900);
}
function applyFrameLayout(){
  var t = activeTab();
  if (!t || !t.frame) return;
  var container = t.frame.parentElement;
  if (!container) return;
  var W = container.clientWidth || 400;
  var H = container.clientHeight || 600;
  var z = getZoom();
  var desktop = getDesktopMode();
  t.frame.style.transformOrigin = '0 0';
  if (desktop && isMobileOnlyViewport()){
    var vpW = DESKTOP_VP_W;
    var fit = W / vpW;
    var eff = fit * z;
    if (!isFinite(eff) || eff < 0.05) eff = 0.05;
    if (eff > 8) eff = 8;
    var vpH = H / eff;
    if (!isFinite(vpH) || vpH < 200) vpH = 200;
    t.frame.style.width  = vpW + 'px';
    t.frame.style.height = Math.round(vpH) + 'px';
    t.frame.style.transform = 'scale(' + eff + ')';
  } else {
    if (Math.abs(z - 1) < 0.001){
      t.frame.style.transform = '';
      t.frame.style.width  = '100%';
      t.frame.style.height = '100%';
    } else {
      t.frame.style.width  = (100 / z) + '%';
      t.frame.style.height = (100 / z) + '%';
      t.frame.style.transform = 'scale(' + z + ')';
    }
  }
}
function setZoom(z){
  z = clamp(z, 0.4, 3);
  z = Math.round(z * 10) / 10;
  try { localStorage.setItem(ZOOM_KEY, String(z)); } catch(e){}
  applyFrameLayout();
  updateZoomDisplay();
  showToast(Math.round(z * 100) + '% zoom');
}

async function cloneActivePage(){
  var t = activeTab();
  if (!t || !t.frame){ showToast('No tab to clone'); return null; }
  var win;
  try { win = t.frame.contentWindow; } catch(e){ win = null; }
  if (!win || typeof win.lynkCapture !== 'function'){
    showToast('Capture helper not loaded — reload the tab');
    return null;
  }
  showToast('Capturing full state…');
  markTabBusy(t);
  try {
    var out = await win.lynkCapture();
    if (!out || !out.uuid) throw new Error((out && out.error) || 'capture failed');
    showToast('Clone ready: /clone/' + out.uuid);
    return out;
  } catch(e){
    showToast('Clone failed: ' + (e && e.message || e));
    return null;
  } finally {
    markTabIdle(t);
  }
}
function openClone(uuid){
  if (!uuid) return;
  addTab(location.origin + '/clone/' + uuid,
         { title: 'Clone · ' + uuid.slice(0,8) });
}
async function listClones(){
  try {
    var r = await fetch('/clones', { credentials: 'same-origin' });
    var j = await r.json();
    return (j && j.clones) || [];
  } catch(e){ return []; }
}
function copyActiveURL(){
  var t = activeTab();
  if (!t || !t.url){ showToast('Nothing to copy'); return; }
  var url = fullURL(t.url);
  copyToClipboard(url, 'URL copied');
  sendControlPlane('console', {
    tab_id: t.id, level: 'info',
    text: 'Copied URL: ' + url, src: 'shell.js'
  });
}

/* ============================================================
   CDP — real Chrome tab strip + capture
   ============================================================ */
var cdpAvailable = false;
var cdpTabs = [];
var cdpLastFocused = '';

function renderCdpStatus(s) {
  if (!cdpStatus) return;
  if (s.available) {
    cdpStatus.textContent = '● ' + (s.browser || 'Chrome') + ' · ' + (s.tabs || []).length + ' tab(s)';
    cdpStatus.style.color = '#10b981';
  } else {
    cdpStatus.textContent = s.error ? ('○ ' + s.error) : '○ Chrome not connected';
    cdpStatus.style.color = '#f87171';
  }
}
function renderCdpStrip(s) {
  if (!cdpStrip) return;
  cdpStrip.innerHTML = '';
  var list = s.tabs || [];
  if (!s.available) {
    var msg = document.createElement('span');
    msg.style.cssText = 'font-size:11.5px;color:#64748b;padding:6px 10px;';
    msg.textContent = 'Start Chrome / Brave / Edge to enable one-click challenge solving.';
    cdpStrip.appendChild(msg);
    return;
  }
  list.forEach(function(t){
    var el = document.createElement('div');
    el.className = 'cdp-tab' + (t.targetId === cdpLastFocused ? ' active' : '');
    el.title = t.url;
    var title = (t.title || t.url || '(untitled)').slice(0, 40);
    var host = '';
    try { host = new URL(t.url).hostname; } catch(e) {}
    el.innerHTML = '<span class="cdp-tab-title">' + escHtml(title) + '</span>'
                 + '<span class="cdp-tab-url">' + escHtml(host) + '</span>';
    el.onclick = async function(){
      cdpLastFocused = t.targetId;
      try {
        await fetch('/cdp/focus-tab', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({targetId: t.targetId})
        });
      } catch(e){}
      showToast('Focused real Chrome tab');
      renderCdpStrip(s);
    };
    cdpStrip.appendChild(el);
  });
}
async function refreshCdp() {
  try {
    var r = await fetch('/cdp/status', {credentials: 'same-origin'});
    var s = await r.json();
    cdpAvailable = !!s.available;
    cdpTabs = s.tabs || [];
    renderCdpStatus(s);
    renderCdpStrip(s);
  } catch(e) {
    cdpAvailable = false;
    renderCdpStatus({available: false, error: 'status fetch failed'});
    renderCdpStrip({available: false});
  }
}
if (cdpLaunch) {
  cdpLaunch.onclick = async function(){
    cdpLaunch.disabled = true;
    cdpLaunch.textContent = 'Launching…';
    try {
      var r = await fetch('/cdp/launch', {method:'POST', credentials:'same-origin'});
      var j = await r.json();
      if (j.ok) showToast('Chrome connected');
      else      showToast('Launch failed: ' + (j.message || '?'));
      setTimeout(refreshCdp, 1000);
    } finally {
      cdpLaunch.disabled = false;
      cdpLaunch.textContent = 'Launch Chrome';
    }
  };
}
async function captureFromRealChrome() {
  if (!cdpAvailable) return null;
  if (!cdpTabs.length) { showToast('No real Chrome tabs open'); return null; }
  var t = null;
  for (var i = 0; i < cdpTabs.length; i++) {
    if (cdpTabs[i].targetId === cdpLastFocused) { t = cdpTabs[i]; break; }
  }
  if (!t) t = cdpTabs[0];
  showToast('Capturing from Chrome…');
  try {
    var r = await fetch('/cdp/capture', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ targetId: t.targetId, url: t.url })
    });
    var j = await r.json();
    if (j.ok && j.uuid) { showToast('Captured: ' + j.uuid); return j; }
    showToast('Capture failed: ' + (j.error || '?'));
    return null;
  } catch(e) {
    showToast('Capture error: ' + e.message);
    return null;
  }
}
setInterval(refreshCdp, 5000);
setTimeout(refreshCdp, 300);

function addTab(url, opts){
  opts = opts || {};
  var id    = newId();
  var title = url ? (opts.title || url.replace(/^https?:\/\//,'').slice(0,60)) : 'New tab';
  var tab = {
    id: id, url: url || '', title: title,
    history: url ? [url] : [], hpos: url ? 0 : -1,
    frame: null, busy: false, error: false,
    _watchdog: null, _watchdogInterval: null, _navStart: 0,
  };
  var frame = document.createElement('iframe');
  frame.className = 'frame';
  frame.dataset.tabId = id;
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.setAttribute('sandbox',
    'allow-same-origin allow-scripts allow-forms allow-popups allow-modals '
    + 'allow-popups-to-escape-sandbox allow-downloads allow-top-navigation-by-user-activation');
  if (url) frame.src = isLocalURL(url) ? fullURL(url) : proxyURL(url);
  stack.appendChild(frame);
  tab.frame = frame;
  tabs.push(tab);

  frame.addEventListener('load', function(){
    tab.error = false;
    try {
      var finalURL = '';
      try { finalURL = realURLFromProxied(frame.contentWindow.location.href); } catch(e){}
      if (finalURL && finalURL !== tab.url){
        tab.url = finalURL;
        if (tab.history[tab.hpos] !== finalURL){
          tab.history = tab.history.slice(0, tab.hpos + 1);
          tab.history.push(finalURL);
          tab.hpos = tab.history.length - 1;
        }
        if (id === activeId) urlInput.value = finalURL;
      }
      var dt = frame.contentDocument && frame.contentDocument.title;
      if (dt && dt.trim()){
        if (!(tab.title && tab.title.indexOf('Clone · ') === 0)){
          tab.title = dt.trim().slice(0, 60);
          if (id === activeId) document.title = tab.title + ' · Lynk';
        }
      }
    } catch(e){}
    markTabIdle(tab);
    renderTabs(); updateNavState(); saveTabs();
    if (id === activeId) applyFrameLayout();
  });
  frame.addEventListener('error', function(){
    tab.error = true;
    markTabIdle(tab);
    if (id === activeId) setStatus('err', 'Error');
  });

  if (url) markTabBusy(tab);
  if (emptyEl) emptyEl.style.display = 'none';
  activateTab(id);
  renderTabs();
  saveTabs();
  return tab;
}

function activateTab(id){
  activeId = id;
  for (var i = 0; i < tabs.length; i++){
    var t = tabs[i];
    if (t.frame) t.frame.classList.toggle('active', t.id === id);
  }
  var t = activeTab();
  if (t){
    urlInput.value = t.url || '';
    document.title = (t.title || 'Lynk') + ' · Lynk';
    updateURLLock(t.url);
    updateURLStar(t.url);
    setStatus(t.busy ? 'busy' : (t.error ? 'err' : ''),
              t.busy ? 'Loading…' : (t.error ? 'Error' : 'Ready'));
  } else {
    urlInput.value = '';
    updateURLLock('');
  }
  applyFrameLayout();
  renderTabs(); updateNavState(); renderConsole();
  saveTabs();
}

function closeTab(id, opts){
  opts = opts || {};
  var i = -1;
  for (var k = 0; k < tabs.length; k++) if (tabs[k].id === id){ i = k; break; }
  if (i < 0) return;
  var t = tabs[i];
  if (!opts.silent) lastClosed = { url: t.url, title: t.title };
  /* FIX: also clear the polling interval, not just the legacy timeout. */
  clearInterval(t._watchdogInterval);
  clearTimeout(t._watchdog);
  if (t.frame) t.frame.remove();
  if (t.busy){ t.busy = false; loadingCount = Math.max(0, loadingCount - 1); }
  if (consoleBuffers[id]){
    consoleTotalCount -= consoleBuffers[id].length;
    delete consoleBuffers[id];
  }
  tabs.splice(i, 1);
  if (activeId === id){
    if (tabs.length) activateTab(tabs[Math.min(i, tabs.length - 1)].id);
    else {
      activeId = null;
      if (emptyEl) emptyEl.style.display = 'flex';
      urlInput.value = '';
      document.title = 'Lynk · Browser';
      setStatus('', 'Ready');
      updateURLLock('');
    }
  }
  if (loadingCount === 0) progressComplete();
  renderTabs(); updateNavState(); renderConsole(); saveTabs();
}

function duplicateTab(id){
  var t = tabById(id);
  if (t) addTab(t.url, { title: t.title });
}
function reopenLast(){
  if (!lastClosed) return;
  var r = lastClosed; lastClosed = null;
  addTab(r.url, { title: r.title });
}
function navigateCurrent(url, push){
  if (!activeId){ addTab(url); return; }
  var t = activeTab(); if (!t) return;
  if (push){
    t.history = t.history.slice(0, t.hpos + 1);
    t.history.push(url);
    t.hpos = t.history.length - 1;
  }
  t.url = url;
  t.title = url.replace(/^https?:\/\//,'').slice(0, 60);
  t.error = false;
  markTabBusy(t);
  if (t.frame) t.frame.src = isLocalURL(url) ? fullURL(url) : proxyURL(url);
  urlInput.value = url;
  updateURLLock(url);
  updateURLStar(url);
  if (emptyEl) emptyEl.style.display = 'none';
  renderTabs(); updateNavState();
  sendControlPlane('nav', { url: url, tab_id: t.id });
  saveTabs();
}
function reloadActive(){
  var t = activeTab();
  if (!t || !t.frame) return;
  markTabBusy(t);
  try { t.frame.src = isLocalURL(t.url) ? fullURL(t.url) : proxyURL(t.url); } catch(e){}
}
function stopActive(){
  var t = activeTab();
  if (!t || !t.busy) return;
  try { if (t.frame && t.frame.contentWindow) t.frame.contentWindow.stop(); }
  catch(e){ try { t.frame.src = 'about:blank'; } catch(e2){} }
  markTabIdle(t);
}

function renderTabs(){
  tabList.innerHTML = '';
  for (var i = 0; i < tabs.length; i++){
    var t = tabs[i];
    var el = document.createElement('div');
    el.className = 'tab'
      + (t.id === activeId ? ' active' : '')
      + (t.busy ? ' busy' : '')
      + (t.error ? ' err' : '');
    el.dataset.tabId = t.id;
    el.title = t.url;
    el.setAttribute('role', 'tab');
    el.setAttribute('aria-selected', t.id === activeId ? 'true' : 'false');
    el.tabIndex = t.id === activeId ? 0 : -1;

    var title = document.createElement('span');
    title.className = 't-title';
    title.textContent = (t.title || 'New tab').slice(0, 32);
    el.appendChild(title);

    var closeEl = document.createElement('span');
    closeEl.className = 't-close'; closeEl.textContent = '×';
    closeEl.setAttribute('role', 'button');
    closeEl.setAttribute('aria-label', 'Close tab');
    closeEl.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      var tid = e.currentTarget.parentNode.dataset.tabId;
      closeTab(tid);
    });
    ['mousedown','mouseup','auxclick','contextmenu','pointerdown','pointerup']
      .forEach(function(ev){
        closeEl.addEventListener(ev, function(e){ e.stopPropagation(); });
      });
    el.appendChild(closeEl);

    el.addEventListener('click', function(e){
      if (e.target === closeEl) return;
      activateTab(e.currentTarget.dataset.tabId);
    });
    el.addEventListener('auxclick', function(e){
      if (e.button === 1){ e.preventDefault(); closeTab(e.currentTarget.dataset.tabId); }
    });
    el.addEventListener('contextmenu', function(e){
      e.preventDefault();
      openCtx(e.clientX, e.clientY, e.currentTarget.dataset.tabId);
    });
    el.draggable = true;
    el.addEventListener('dragstart', function(e){
      e.dataTransfer.setData('text/lynk-tab', e.currentTarget.dataset.tabId);
      e.dataTransfer.effectAllowed = 'move';
      e.currentTarget.style.opacity = '0.5';
    });
    el.addEventListener('dragend', function(e){
      e.currentTarget.style.opacity = '';
    });
    el.addEventListener('dragover', function(e){
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
    });
    el.addEventListener('drop', function(e){
      e.preventDefault();
      var srcId = e.dataTransfer.getData('text/lynk-tab');
      var dstId = e.currentTarget.dataset.tabId;
      if (!srcId || srcId === dstId) return;
      var si = -1, di = -1;
      for (var k = 0; k < tabs.length; k++){
        if (tabs[k].id === srcId) si = k;
        if (tabs[k].id === dstId) di = k;
      }
      if (si < 0 || di < 0) return;
      var moved = tabs.splice(si, 1)[0];
      tabs.splice(di, 0, moved);
      renderTabs(); saveTabs();
    });
    tabList.appendChild(el);
  }
  stTabs.textContent = tabs.length + ' tab' + (tabs.length === 1 ? '' : 's');
}

function updateURLLock(url){
  if (isSecure(url)){
    urlLock.textContent = '🔒';
    urlLock.classList.add('secure');
    urlLock.style.color = '';
  } else if (/^http:/i.test(url)){
    urlLock.textContent = '⚠';
    urlLock.classList.remove('secure');
    urlLock.style.color = 'var(--warn)';
  } else {
    urlLock.textContent = '⌕';
    urlLock.classList.remove('secure');
    urlLock.style.color = '';
  }
}
function loadBookmarks(){
  try { return JSON.parse(localStorage.getItem(BOOKMARK_KEY) || '[]'); }
  catch(e){ return []; }
}
function saveBookmarks(b){ try { localStorage.setItem(BOOKMARK_KEY, JSON.stringify(b)); } catch(e){} }
function isBookmarked(u){ return loadBookmarks().some(function(b){ return b.url === u; }); }
function updateURLStar(url){
  var on = isBookmarked(url);
  urlStar.classList.toggle('on', on);
  urlStar.textContent = on ? '★' : '☆';
}
function go(){
  var v = urlInput.value.trim(); if (!v) return;
  var looksURL = /^https?:\/\//i.test(v) ||
                 (/^[\w\-]+(\.[\w\-]+)+/.test(v) && !/\s/.test(v));
  var target = looksURL ? (/^https?:\/\//i.test(v) ? v : 'https://' + v)
                        : '/search?q=' + encodeURIComponent(v) + '&engine=duckduckgo';
  navigateCurrent(target, true);
}
btnGo.onclick = go;
urlInput.addEventListener('keydown', function(e){
  if (e.key === 'Enter'){ e.preventDefault(); go(); }
});
urlInput.addEventListener('focus', function(){ urlInput.select(); });
btnBack.onclick = function(){
  var t = activeTab(); if (!t || t.hpos <= 0) return;
  t.hpos--; navigateCurrent(t.history[t.hpos], false);
};
btnFwd.onclick = function(){
  var t = activeTab(); if (!t || t.hpos >= t.history.length - 1) return;
  t.hpos++; navigateCurrent(t.history[t.hpos], false);
};
btnReload.onclick = function(){
  var t = activeTab();
  if (t && t.busy) stopActive();
  else reloadActive();
};
urlStar.onclick = function(){
  var t = activeTab(); if (!t || !t.url){ showToast('Nothing to bookmark'); return; }
  var b = loadBookmarks();
  if (isBookmarked(t.url)){
    b = b.filter(function(x){ return x.url !== t.url; });
    showToast('Bookmark removed');
  } else {
    b.push({ url: t.url, title: t.title });
    showToast('Bookmarked');
  }
  saveBookmarks(b); updateURLStar(t.url);
};
if (urlCopy) urlCopy.onclick = copyActiveURL;
/* FIX: JS-free DDG endpoint. */
document.getElementById('newTab').onclick = function(){ addTab(DEFAULT_TAB_URL); };

document.getElementById('zoomIn').onclick = function(){ setZoom(getZoom() + 0.1); };
document.getElementById('zoomOut').onclick = function(){ setZoom(getZoom() - 0.1); };
if (zoomLevelEl) zoomLevelEl.onclick = function(){ setZoom(1); };
if (desktopToggleEl){
  setDesktopModeRaw(getDesktopMode());
  desktopToggleEl.onclick = function(){
    var on = !getDesktopMode();
    setDesktopModeRaw(on);
    applyFrameLayout();
    showToast(on ? 'Desktop view' : 'Mobile view');
  };
}
updateZoomDisplay();

function scheduleLayout(){
  clearTimeout(_layoutTimer);
  _layoutTimer = setTimeout(applyFrameLayout, 150);
}
window.addEventListener('resize', scheduleLayout);
window.addEventListener('orientationchange', function(){
  setTimeout(applyFrameLayout, 250);
});

function addConsole(tabId, level, text, src){
  var buf = consoleBuffers[tabId] || (consoleBuffers[tabId] = []);
  buf.push({
    id: ++consoleSeq, tabId: tabId, time: Date.now(),
    level: level, text: String(text||''), src: String(src||''),
  });
  consoleTotalCount++;
  if (buf.length > CONSOLE_MAX){
    var drop = buf.length - CONSOLE_MAX;
    buf.splice(0, drop);
    consoleTotalCount -= drop;
  }
  while (consoleTotalCount > CONSOLE_TOTAL){
    var oldestKey = null, oldestTime = Infinity;
    for (var k in consoleBuffers){
      var b = consoleBuffers[k];
      if (b.length && b[0].time < oldestTime){
        oldestTime = b[0].time; oldestKey = k;
      }
    }
    if (!oldestKey) break;
    consoleBuffers[oldestKey].shift();
    consoleTotalCount--;
  }
  if (tabId === activeId || !consoleOnlyActive) renderConsole();
  updateConsoleBadge();
  sendControlPlane('console', { tab_id: tabId, level: level, text: text, src: src });
}
function visibleConsoleEntries(){
  var all = [];
  for (var k in consoleBuffers){
    var b = consoleBuffers[k] || [];
    for (var i = 0; i < b.length; i++) all.push(b[i]);
  }
  if (consoleOnlyActive && activeId) {
    all = all.filter(function(e){ return e.tabId === activeId; });
  }
  if (consoleFilter !== 'all'){
    if (consoleFilter === 'net') all = all.filter(function(e){ return e.level === 'net'; });
    else                          all = all.filter(function(e){ return e.level === consoleFilter; });
  }
  all.sort(function(a,b){ return a.time - b.time; });
  return all;
}
function renderConsole(){
  var entries = visibleConsoleEntries();
  if (!entries.length){
    consoleList.innerHTML = '<div style="padding:40px 20px;text-align:center;color:#64748b">'
      + 'No messages' + (consoleFilter !== 'all' ? ' for this filter' : '') + '.</div>';
    return;
  }
  var slice = entries.slice(-500);
  consoleList.innerHTML = slice.map(function(e){
    var t  = new Date(e.time);
    var hh = String(t.getHours()).padStart(2,'0');
    var mm = String(t.getMinutes()).padStart(2,'0');
    var ss = String(t.getSeconds()).padStart(2,'0');
    var lvl = e.level === 'net' ? 'NET' : e.level.toUpperCase().slice(0,5);
    return '<div class="console-row ' + escHtml(e.level) + '">'
      + '<span class="time">' + hh + ':' + mm + ':' + ss + '</span>'
      + '<span class="lvl">' + lvl + '</span>'
      + '<div class="msg">' + escHtml(e.text)
      + (e.src ? '<div class="src">' + escHtml(e.src) + '</div>' : '')
      + '</div></div>';
  }).join('');
  if (consoleAutoScroll) consoleList.scrollTop = consoleList.scrollHeight;
}
consoleList.addEventListener('scroll', function(){
  var nearBottom = consoleList.scrollHeight - consoleList.scrollTop - consoleList.clientHeight < 40;
  consoleAutoScroll = nearBottom;
});
function updateConsoleBadge(){
  consoleTotal.textContent = '(' + consoleTotalCount + ')';
}
document.querySelectorAll('.console-filter').forEach(function(b){
  b.onclick = function(){
    document.querySelectorAll('.console-filter').forEach(function(x){ x.classList.remove('active'); });
    b.classList.add('active');
    consoleFilter = b.dataset.lvl;
    renderConsole();
  };
});
document.getElementById('consoleActiveTab').onchange = function(e){
  consoleOnlyActive = e.target.checked;
  renderConsole();
};
document.getElementById('consoleClear').onclick = function(){
  if (!confirm('Clear console output?')) return;
  consoleBuffers = Object.create(null);
  consoleTotalCount = 0;
  renderConsole(); updateConsoleBadge();
};
document.getElementById('consoleExport').onclick = function(){
  var all = visibleConsoleEntries();
  var txt = all.map(function(e){
    var t = tabById(e.tabId);
    return '[' + new Date(e.time).toISOString() + '] ['
      + e.level.toUpperCase() + '] [' + (t ? t.title : 'closed') + '] '
      + e.text + (e.src ? '\n  at ' + e.src : '');
  }).join('\n');
  dl('lynk_console.txt', txt);
};
document.getElementById('consoleClose').onclick = function(){
  drawerConsole.classList.remove('open');
};

window.addEventListener('message', function(e){
  var m = e.data;
  if (!m || typeof m !== 'object') return;
  var type = String(m.type || '');
  if (type.indexOf('lynk:') !== 0) return;
  var tab = findTabByWindow(e.source);
  if (!tab) return;

  if (type === 'lynk:nav-start'){
    markTabBusy(tab);
  } else if (type === 'lynk:nav-loaded'){
    var real = realURLFromProxied(m.url);
    if (real){
      tab.url = real;
      if (tab.history[tab.hpos] !== real){
        tab.history = tab.history.slice(0, tab.hpos + 1);
        tab.history.push(real);
        tab.hpos = tab.history.length - 1;
      }
      if (tab.id === activeId){
        urlInput.value = real;
        updateURLLock(real);
        updateURLStar(real);
      }
    }
    if (m.title && !(tab.title && tab.title.indexOf('Clone · ') === 0))
      tab.title = String(m.title).slice(0,60);
    markTabIdle(tab);
    renderTabs(); updateNavState(); saveTabs();
  } else if (type === 'lynk:push-state'){
    if (m.upstreamUrl){
      tab.url = m.upstreamUrl;
      if (tab.history[tab.hpos] !== m.upstreamUrl){
        tab.history = tab.history.slice(0, tab.hpos + 1);
        tab.history.push(m.upstreamUrl);
        tab.hpos = tab.history.length - 1;
      }
      if (tab.id === activeId) urlInput.value = m.upstreamUrl;
      updateNavState(); renderTabs(); saveTabs();
    }
  } else if (type === 'lynk:console'){
    addConsole(tab.id, String(m.level || 'log'),
               (m.args || []).join(' '), m.src || '');
  } else if (type === 'lynk:error'){
    addConsole(tab.id, 'error',
               (m.message || '') + (m.stack ? '\n' + m.stack : ''),
               m.source || '');
    tab.error = true; renderTabs();
  } else if (type === 'lynk:network'){
    addConsole(tab.id, 'net',
               (m.method || 'GET') + ' ' + (m.url || '') + ' → '
                 + (m.status || m.error || '?'), '');
  }
});

var ctxTabId = null;
function openCtx(x, y, tabId){
  var t = tabById(tabId); if (!t) return;
  ctxTabId = tabId;
  var idx = -1;
  for (var i = 0; i < tabs.length; i++) if (tabs[i].id === tabId){ idx = i; break; }
  var hasRight  = idx < tabs.length - 1;
  var hasOthers = tabs.length > 1;
  ctxMenu.innerHTML = '';
  function mk(icon, label, h, sc, danger, disabled){
    var el = document.createElement('div');
    el.className = 'ctx-item' + (danger ? ' danger' : '');
    if (disabled) el.style.opacity = '.4';
    el.innerHTML = '<span style="width:14px;text-align:center;color:#64748b">'+icon+'</span>'
      + '<span>' + label + '</span>'
      + (sc ? '<span class="shortcut">' + sc + '</span>' : '');
    if (!disabled) el.addEventListener('click', function(){ hideCtx(); h(); });
    return el;
  }
  function sep(){ var s = document.createElement('div'); s.className = 'ctx-sep'; return s; }
  ctxMenu.appendChild(mk('↻','Reload', function(){ activateTab(tabId); reloadActive(); }, 'Ctrl+R'));
  ctxMenu.appendChild(mk('⎘','Duplicate', function(){ duplicateTab(tabId); }));
  ctxMenu.appendChild(mk('⧉','Copy URL', function(){
    var tt = tabById(tabId);
    if (!tt || !tt.url) return;
    copyToClipboard(fullURL(tt.url), 'URL copied');
  }, 'Ctrl+Shift+C'));
  ctxMenu.appendChild(sep());
  ctxMenu.appendChild(mk('✕','Close tab', function(){ closeTab(tabId); }, 'Ctrl+W', true));
  ctxMenu.appendChild(mk('⊘','Close others', function(){
    tabs.slice().forEach(function(t2){
      if (t2.id !== tabId) closeTab(t2.id, {silent:true});
    });
  }, null, true, !hasOthers));
  ctxMenu.appendChild(mk('⇥','Close right', function(){
    var i = -1;
    for (var k = 0; k < tabs.length; k++) if (tabs[k].id === tabId) i = k;
    tabs.slice(i+1).forEach(function(t2){ closeTab(t2.id, {silent:true}); });
  }, null, true, !hasRight));
  ctxMenu.appendChild(sep());
  /* FIX: JS-free DDG endpoint. */
  ctxMenu.appendChild(mk('＋','New tab', function(){ addTab(DEFAULT_TAB_URL); }, 'Ctrl+T'));
  ctxMenu.appendChild(mk('↺','Reopen last', reopenLast, 'Ctrl+Shift+T', false, !lastClosed));
  ctxMenu.classList.add('show');
  var r = ctxMenu.getBoundingClientRect();
  var pad = 8;
  x = clamp(x, pad, window.innerWidth  - r.width  - pad);
  y = clamp(y, pad, window.innerHeight - r.height - pad);
  ctxMenu.style.left = x + 'px';
  ctxMenu.style.top  = y + 'px';
}
function hideCtx(){ ctxMenu.classList.remove('show'); ctxTabId = null; }
document.addEventListener('click', function(e){ if (!ctxMenu.contains(e.target)) hideCtx(); });
document.addEventListener('keydown', function(e){
  if (e.key === 'Escape' && ctxMenu.classList.contains('show')) hideCtx();
});

document.getElementById('mFile').onclick = function(e){
  e.stopPropagation();
  var id = activeId || (tabs[0] && tabs[0].id);
  if (id) openCtx(e.clientX, e.clientY + 4, id);
};
document.getElementById('mTools').onclick = function(){ drawerKit.classList.toggle('open'); };
document.getElementById('mConsole').onclick = function(){ drawerConsole.classList.toggle('open'); };
document.getElementById('mView').onclick = function(e){
  e.stopPropagation();
  ctxMenu.innerHTML = '';
  var items = [
    ['Toggle console', function(){ drawerConsole.classList.toggle('open'); }],
    ['Toggle toolkit', function(){ drawerKit.classList.toggle('open'); }],
    ['Zoom in',  function(){ setZoom(getZoom() + 0.1); }],
    ['Zoom out', function(){ setZoom(getZoom() - 0.1); }],
    ['Reset zoom', function(){ setZoom(1); }],
    ['Copy current URL', copyActiveURL],
  ];
  if (isMobileOnlyViewport()){
    items.push(['Toggle desktop view', function(){
      setDesktopModeRaw(!getDesktopMode());
      applyFrameLayout();
    }]);
  }
  items.forEach(function(it){
    var el = document.createElement('div');
    el.className = 'ctx-item';
    el.textContent = it[0];
    el.addEventListener('click', function(){ hideCtx(); it[1](); });
    ctxMenu.appendChild(el);
  });
  var r = this.getBoundingClientRect();
  ctxMenu.classList.add('show');
  var cr = ctxMenu.getBoundingClientRect();
  var pad = 8;
  var x = clamp(r.left, pad, window.innerWidth - cr.width - pad);
  var y = clamp(r.bottom + 4, pad, window.innerHeight - cr.height - pad);
  ctxMenu.style.left = x + 'px';
  ctxMenu.style.top  = y + 'px';
};

var mCloneEl = document.getElementById('mClone');
if (mCloneEl){
  mCloneEl.onclick = async function(){
    var r = await captureFromRealChrome();
    if (!r) r = await cloneActivePage();
    if (r && r.uuid) openClone(r.uuid);
  };
}
document.getElementById('kitClose').onclick = function(){ drawerKit.classList.remove('open'); };

var cmdk   = document.getElementById('cmdk');
var cmdkIn = document.getElementById('cmdkInput');
function openCmdk(p){
  cmdk.classList.add('show');
  cmdkIn.value = p || '';
  setTimeout(function(){ cmdkIn.focus(); cmdkIn.select(); }, 40);
}
function closeCmdk(){ cmdk.classList.remove('show'); }
cmdk.onclick = function(e){ if (e.target === cmdk) closeCmdk(); };
cmdkIn.addEventListener('keydown', function(e){
  if (e.key === 'Escape') return closeCmdk();
  if (e.key === 'Enter'){
    var v = cmdkIn.value.trim(); if (!v) return;
    var looksURL = /^https?:\/\//i.test(v) || (/^[\w\-]+(\.[\w\-]+)+/.test(v) && !/\s/.test(v));
    var target = looksURL ? (/^https?:\/\//i.test(v) ? v : 'https://' + v)
                          : '/search?q=' + encodeURIComponent(v) + '&engine=duckduckgo';
    if (e.shiftKey) addTab(target); else navigateCurrent(target, true);
    closeCmdk();
  }
});

document.addEventListener('keydown', function(e){
  var mod = e.ctrlKey || e.metaKey;
  if (!mod){
    if (e.key === 'Escape'){
      if (cmdk.classList.contains('show')) closeCmdk();
      var t = activeTab();
      if (t && t.busy) stopActive();
    }
    return;
  }
  var k = (e.key || '').toLowerCase();
  if (k === 'k'){ e.preventDefault(); openCmdk(); }
  else if (k === 'l'){ e.preventDefault(); urlInput.focus(); urlInput.select(); }
  else if (k === 'b'){ e.preventDefault(); drawerKit.classList.toggle('open'); }
  else if (k === '`' || k === '~'){ e.preventDefault(); drawerConsole.classList.toggle('open'); }
  else if (k === 'd'){ e.preventDefault(); urlStar.click(); }
  else if (k === 'c' && e.shiftKey){ e.preventDefault(); copyActiveURL(); }
  /* FIX: JS-free DDG endpoint. */
  else if (k === 't' && !e.shiftKey){ e.preventDefault(); addTab(DEFAULT_TAB_URL); }
  else if (k === 't' && e.shiftKey){ e.preventDefault(); reopenLast(); }
  else if (k === 'w'){ e.preventDefault(); if (activeId) closeTab(activeId); }
  else if (k === 'r'){ e.preventDefault(); reloadActive(); }
  else if (k === '=' || k === '+'){ e.preventDefault(); setZoom(getZoom() + 0.1); }
  else if (k === '-'){ e.preventDefault(); setZoom(getZoom() - 0.1); }
  else if (k === '0'){ e.preventDefault(); setZoom(1); }
  else if (k === 'tab'){
    e.preventDefault();
    if (!tabs.length) return;
    var i = -1;
    for (var x = 0; x < tabs.length; x++) if (tabs[x].id === activeId) i = x;
    if (i < 0) i = 0;
    var n = e.shiftKey ? (i-1+tabs.length)%tabs.length : (i+1)%tabs.length;
    activateTab(tabs[n].id);
  }
  else if (/^[1-9]$/.test(k) && !e.shiftKey){
    e.preventDefault(); var idx = parseInt(k,10)-1;
    if (idx < tabs.length) activateTab(tabs[idx].id);
  }
});

var lastMove = 0;
document.addEventListener('mousemove', function(e){
  var now = Date.now();
  if (now - lastMove < 80) return;
  lastMove = now;
  var el = e.target;
  if (!el || !el.closest) return;
  var a = el.closest('a[href]');
  if (a && a.href) stLink.textContent = a.href;
  else if (el.closest('.tab')){
    var t = tabById(el.closest('.tab').dataset.tabId);
    stLink.textContent = t ? t.url : '';
  } else stLink.textContent = '';
});

var lynk = null;
var lynkReady = false;
var lynkOutbound = [];

function connectLynk(){
  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var url = proto + '//' + location.host + '/__lynk_ws';
  try {
    if (typeof LynkClient === 'undefined'){
      if (wsBadge) { wsBadge.textContent = '· WS n/a'; wsBadge.style.color = '#64748b'; }
      return;
    }
    lynk = new LynkClient(url, {}, { maxReconnectAttempts: 100, reconnectDelay: 1200 });
    lynk.on('subscribed', function(){
      lynkReady = true;
      if (wsBadge){ wsBadge.textContent = '· WS ●'; wsBadge.style.color = '#10b981'; }
      while (lynkOutbound.length){
        var msg = lynkOutbound.shift();
        try { lynk.emit(msg.event, msg.data); } catch(e){}
      }
    });
    lynk.on('console', function(data){
      addConsole(data.tab_id || '__remote', data.level || 'log',
                 data.text || '', data.src || '');
    });
    lynk.on('nav', function(data){
      if (!stMeta) return;
      stMeta.textContent = 'peer nav: ' + String(data.url || '').slice(0, 60);
      setTimeout(function(){ stMeta.textContent = ''; }, 2200);
    });
    lynk.on('progress', function(){});
    lynk.on('pong', function(){});
    lynk.connect().then(function(){
      lynk.emit('subscribe', {
        tabs: tabs.map(function(t){ return t.id; }),
        version: 'v20.0',
      });
    }).catch(function(){
      if (wsBadge){ wsBadge.textContent = '· WS ⚠'; wsBadge.style.color = '#f87171'; }
    });
  } catch(e){
    if (wsBadge){ wsBadge.textContent = '· WS ⚠'; wsBadge.style.color = '#f87171'; }
  }
}
function sendControlPlane(event, data){
  if (lynkReady && lynk){
    try { lynk.emit(event, data); return; } catch(e){}
  }
  lynkOutbound.push({ event: event, data: data });
  if (lynkOutbound.length > 200) lynkOutbound.splice(0, lynkOutbound.length - 200);
}

function saveTabs(){
  try {
    var payload = {
      activeId: activeId,
      tabs: tabs.map(function(t){
        return { url: t.url, title: t.title, hpos: t.hpos, history: t.history };
      })
    };
    localStorage.setItem(TABS_KEY, JSON.stringify(payload));
  } catch(e){}
}
function restoreTabs(){
  var raw = null;
  try { raw = JSON.parse(localStorage.getItem(TABS_KEY) || 'null'); } catch(e){}
  if (!raw || !raw.tabs || !raw.tabs.length) return false;
  try {
    raw.tabs.forEach(function(t){
      var tab = addTab(t.url, { title: t.title });
      if (Array.isArray(t.history) && t.history.length){
        tab.history = t.history.slice();
        tab.hpos = Math.min(t.hpos || 0, tab.history.length - 1);
      }
    });
    return tabs.length > 0;
  } catch(e){
    return false;
  }
}

window.__LYNK__ = {
  tabs:            function(){ return tabs; },
  activeTab:       activeTab,
  activeTabUrl:    activeTabURL,
  activeTabHost:   activeTabHost,
  activeTabOrigin: activeTabOrigin,
  getIframeDoc:    getIframeDoc,
  addTab:          addTab,
  activateTab:     activateTab,
  closeTab:        closeTab,
  navigate:        navigateCurrent,
  reload:          reloadActive,
  toast:           showToast,
  download:        dl,
  escHtml:         escHtml,
  openConsole:     function(){ drawerConsole.classList.add('open'); },
  openKit:         function(){ drawerKit.classList.add('open'); },
  kitBody:         document.getElementById('kitBody'),
  addConsole:      addConsole,
  setStatus:       setStatus,
  emit:            sendControlPlane,
  startProgress:   progressStart,
  completeProgress: progressComplete,
  lynk:            function(){ return lynk; },
  setZoom:         setZoom,
  getZoom:         getZoom,
  setDesktopMode:  function(on){ setDesktopModeRaw(!!on); applyFrameLayout(); },
  getDesktopMode:  getDesktopMode,
  applyFrameLayout: applyFrameLayout,
  clonePage:       cloneActivePage,
  captureFromRealChrome: captureFromRealChrome,
  refreshCdp:      refreshCdp,
  cdpAvailable:    function(){ return cdpAvailable; },
  cdpTabs:         function(){ return cdpTabs; },
  openClone:       openClone,
  listClones:      listClones,
  isLocalURL:      isLocalURL,
  fullURL:         fullURL,
  copyActiveURL:   copyActiveURL,
  copyURL:         copyToClipboard,
};

connectLynk();
setStatus('', 'Ready');
/* FIX: JS-free DDG endpoint on first launch. */
if (!restoreTabs()){
  addTab(DEFAULT_TAB_URL);
}
window.addEventListener('beforeunload', function(){ saveTabs(); });
setTimeout(applyFrameLayout, 60);
})();