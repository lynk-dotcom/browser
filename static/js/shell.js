/* shell.js — Lynk shell bootstrap.
 * Owns the tab strip, the address bar, iframe lifecycle, the interceptor
 * message bridge, the service WebSocket, and dynamic chunk loading.
 *
 * This revision fixes the "[lynk] chunk not available: https://<upstream>/static/js/<file>"
 * warnings caused by the chunk loader resolving chunk URLs against the active
 * tab's upstream origin instead of the Lynk origin.
 */
(function () {
  'use strict';
  if (window.__LYNK_SHELL__) return;
  window.__LYNK_SHELL__ = true;

  /* =================== CONSTANTS =================== */

  const ORIGIN       = location.origin;                 /* FIX-0: never changed by tab state */
  const CHUNK_BASE   = ORIGIN + '/static/js/';          /* FIX-1: chunks ALWAYS come from Lynk origin */
  const SERVICE_WS   = ORIGIN.replace(/^http/, 'ws') + '/__lynk_ws';
  const VERSION      = window.__LYNK_VERSION__ || 'v1';

  /* Explicit allowlist of chunks the shell is allowed to load.
     Anything not in this map is refused — prevents a typo or a stale
     reference from ever being resolved against an upstream origin. */
  const KNOWN_CHUNKS = Object.freeze({
    'ui.js':               'ui',
    'toolkit.js':          'toolkit',
    'cloner_capture.js':   'clonerCapture',
    /* add future chunks here as you ship them */
  });

  /* =================== CHUNK LOADER =================== */

  const chunkCache  = Object.create(null);   /* name -> module / null */
  const chunkFailed = Object.create(null);   /* name -> true */

  /**
   * Load a Lynk shell chunk by basename.
   * Guarantees:
   *  - The URL is built from CHUNK_BASE (Lynk origin), never from upstream.
   *  - A file that is already in the DOM (server-injected) is reused, not refetched.
   *  - A non-JS content-type is rejected before the browser tries to execute it,
   *    which is what turns "facebook 404 HTML" into a clean warning instead of
   *    a SyntaxError: Unexpected token '<'.
   *  - Failures are cached so we don't retry every render.
   */
  function loadChunk(name, opts) {
    if (chunkCache[name] !== undefined)  return Promise.resolve(chunkCache[name]);
    if (chunkFailed[name])               return Promise.resolve(null);

    if (!KNOWN_CHUNKS[name]) {
      chunkFailed[name] = true;
      return Promise.resolve(null);
    }

    /* Reuse a server-injected script if it's already on the page. */
    const existing = document.querySelector(
      'script[src$="/static/js/' + name.replace(/\./g, '\\.') + '"]'
    );
    if (existing && existing.dataset.lynkLoaded === '1') {
      chunkCache[name] = window[KNOWN_CHUNKS[name]] || null;
      return Promise.resolve(chunkCache[name]);
    }

    /* FIX-2: URL is built from the shell's own origin. */
    const url = CHUNK_BASE + name + '?v=' + encodeURIComponent(VERSION);

    return fetch(url, { credentials: 'same-origin', cache: 'no-cache' })
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const ct = resp.headers.get('content-type') || '';
        if (!/javascript|ecmascript/i.test(ct)) {
          throw new Error('bad content-type: ' + ct);
        }
        return resp.text();
      })
      .then(function (src) {
        /* Execute the chunk exactly as a <script> would, but tagged so
           we know it has already been loaded. */
        const el = document.createElement('script');
        el.type = 'text/javascript';
        el.dataset.lynkLoaded = '1';
        el.textContent = src;
        document.head.appendChild(el);

        const mod = window[KNOWN_CHUNKS[name]] || null;
        chunkCache[name] = mod;
        return mod;
      })
      .catch(function (err) {
        chunkFailed[name] = true;
        /* Only warn once — this is the line that used to spam the console. */
        console.warn('[lynk] chunk not available:', url, err && err.message);
        return null;
      });
  }

  function preloadChunks(names) {
    return Promise.all((names || []).map(function (n) { return loadChunk(n); }));
  }

  /* =================== TAB STATE =================== */

  const tabs = [];              /* { id, title, url, upstream, iframe, active } */
  let activeTabId = null;
  let nextTabId   = 1;

  function newTabId() { return 'tab-' + (nextTabId++); }

  function findTab(id) {
    for (let i = 0; i < tabs.length; i++) if (tabs[i].id === id) return tabs[i];
    return null;
  }

  function activeTab() { return findTab(activeTabId); }

  /* =================== DOM (built lazily) =================== */

  const ui = {
    root:       null,
    tabStrip:   null,
    tabList:    null,
    urlBar:     null,
    back:       null,
    forward:    null,
    reload:     null,
    newTabBtn:  null,
    container:  null,
  };

  function ensureUI() {
    if (ui.root) return;
    ui.root = document.createElement('div');
    ui.root.id = 'lynk-shell';
    ui.root.innerHTML = '\
      <div class="lynk-tabstrip" data-tabstrip>\
        <div class="lynk-tabs" data-tabs></div>\
        <button class="lynk-newtab" data-newtab title="New tab">+</button>\
      </div>\
      <div class="lynk-urlbar">\
        <button data-back    title="Back">‹</button>\
        <button data-forward title="Forward">›</button>\
        <button data-reload  title="Reload">⟳</button>\
        <input  data-url type="text" spellcheck="false" placeholder="Enter URL"/>\
      </div>\
      <div class="lynk-viewport" data-container></div>\
    ';
    document.body.appendChild(ui.root);

    ui.tabStrip  = ui.root.querySelector('[data-tabstrip]');
    ui.tabList   = ui.root.querySelector('[data-tabs]');
    ui.urlBar    = ui.root.querySelector('[data-url]');
    ui.back      = ui.root.querySelector('[data-back]');
    ui.forward   = ui.root.querySelector('[data-forward]');
    ui.reload    = ui.root.querySelector('[data-reload]');
    ui.newTabBtn = ui.root.querySelector('[data-newtab]');
    ui.container = ui.root.querySelector('[data-container]');

    ui.newTabBtn.addEventListener('click', function () { createTab('about:blank'); });
    ui.urlBar.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      const v = ui.urlBar.value.trim();
      if (!v) return;
      navigateActive(normalizeUserUrl(v));
    });
    ui.back.addEventListener('click',    function () { historyBack(); });
    ui.forward.addEventListener('click', function () { historyForward(); });
    ui.reload.addEventListener('click',  function () { reloadActive(); });
  }

  /* =================== URL HELPERS =================== */

  function normalizeUserUrl(raw) {
    if (!raw) return 'about:blank';
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return raw;
    if (/^[\w-]+(\.[\w-]+)+/.test(raw)) return 'https://' + raw;
    /* search query */
    return 'https://duckduckgo.com/?q=' + encodeURIComponent(raw);
  }

  function proxyUrlFor(upstreamUrl) {
    if (!upstreamUrl || upstreamUrl === 'about:blank') return upstreamUrl;
    return ORIGIN + '/proxy?url=' + encodeURIComponent(upstreamUrl);
  }

  /* =================== TAB LIFECYCLE =================== */

  function createTab(url) {
    ensureUI();
    const id = newTabId();
    const upstream = (function () {
      try { return new URL(url).origin; } catch (e) { return null; }
    })();

    const iframe = document.createElement('iframe');
    iframe.className = 'lynk-frame';
    iframe.setAttribute('allow', 'clipboard-read; clipboard-write; fullscreen; camera; microphone');
    iframe.setAttribute('sandbox', 'allow-forms allow-scripts allow-same-origin allow-popups allow-modals allow-downloads allow-storage-access-by-user-activation allow-popups-to-escape-sandbox');

    const record = {
      id, url, upstream, iframe, title: '', active: false,
      history: [url], historyIndex: 0,
    };
    tabs.push(record);
    ui.container.appendChild(iframe);

    /* Ensure ui.js and toolkit.js are available on first tab. */
    preloadChunks(['ui.js', 'toolkit.js']).catch(function () {});

    iframe.src = proxyUrlFor(url);
    iframe.addEventListener('load', function () {
      try {
        record.title = iframe.contentDocument.title || record.title;
      } catch (e) {}
      renderTabs();
    });

    setActiveTab(id);
    return record;
  }

  function setActiveTab(id) {
    const target = findTab(id);
    if (!target) return;
    activeTabId = id;
    tabs.forEach(function (t) {
      t.active = t.id === id;
      t.iframe.style.display = t.active ? 'block' : 'none';
    });
    ui.urlBar.value = target.url;
    renderTabs();
  }

  function closeTab(id) {
    const idx = tabs.findIndex(function (t) { return t.id === id; });
    if (idx < 0) return;
    const t = tabs[idx];
    try { t.iframe.remove(); } catch (e) {}
    tabs.splice(idx, 1);
    if (activeTabId === id) {
      const next = tabs[idx] || tabs[idx - 1];
      if (next) setActiveTab(next.id);
      else { activeTabId = null; createTab('about:blank'); }
    }
    renderTabs();
  }

  function navigateActive(upstreamUrl, opts) {
    const t = activeTab();
    if (!t) { createTab(upstreamUrl); return; }
    const push = !(opts && opts.replace);
    if (push) {
      t.history = t.history.slice(0, t.historyIndex + 1);
      t.history.push(upstreamUrl);
      t.historyIndex = t.history.length - 1;
    } else {
      t.history[t.historyIndex] = upstreamUrl;
    }
    t.url = upstreamUrl;
    try { t.upstream = new URL(upstreamUrl).origin; } catch (e) {}
    t.iframe.src = proxyUrlFor(upstreamUrl);
    ui.urlBar.value = upstreamUrl;
    renderTabs();
  }

  function historyBack() {
    const t = activeTab(); if (!t) return;
    if (t.historyIndex <= 0) return;
    t.historyIndex--;
    t.url = t.history[t.historyIndex];
    t.iframe.src = proxyUrlFor(t.url);
    ui.urlBar.value = t.url;
  }
  function historyForward() {
    const t = activeTab(); if (!t) return;
    if (t.historyIndex >= t.history.length - 1) return;
    t.historyIndex++;
    t.url = t.history[t.historyIndex];
    t.iframe.src = proxyUrlFor(t.url);
    ui.urlBar.value = t.url;
  }
  function reloadActive() {
    const t = activeTab(); if (!t) return;
    t.iframe.src = proxyUrlFor(t.url);
  }

  /* =================== TAB STRIP RENDERING =================== */

  function renderTabs() {
    if (!ui.tabList) return;
    ui.tabList.innerHTML = '';
    tabs.forEach(function (t) {
      const el = document.createElement('div');
      el.className = 'lynk-tab' + (t.active ? ' active' : '');
      el.dataset.tabId = t.id;
      const label = document.createElement('span');
      label.className = 'lynk-tab-title';
      label.textContent = (t.title || t.url || 'New tab').slice(0, 40);
      const close = document.createElement('button');
      close.className = 'lynk-tab-close';
      close.textContent = '×';
      close.addEventListener('click', function (e) {
        e.stopPropagation();
        closeTab(t.id);
      });
      el.addEventListener('click', function () { setActiveTab(t.id); });
      el.appendChild(label);
      el.appendChild(close);
      ui.tabList.appendChild(el);
    });
  }

  /* =================== INTERCEPTOR BRIDGE =================== */

  window.addEventListener('message', function (e) {
    const d = e.data;
    if (!d || typeof d.type !== 'string') return;
    if (d.type.indexOf('lynk:') !== 0) return;

    const t = tabs.find(function (x) { return x.iframe && x.iframe.contentWindow === e.source; });
    switch (d.type) {
      case 'lynk:nav-start':
        if (t) {
          if (d.target) {
            t.url = d.target;
            t.history = t.history.slice(0, t.historyIndex + 1);
            t.history.push(d.target);
            t.historyIndex = t.history.length - 1;
            ui.urlBar.value = d.target;
          }
        }
        break;
      case 'lynk:nav-loaded':
        if (t) {
          if (d.title) t.title = d.title;
          if (d.url) t.url = d.url;
          renderTabs();
        }
        break;
      case 'lynk:push-state':
        if (t && d.upstreamUrl) {
          t.url = d.upstreamUrl;
          t.history = t.history.slice(0, t.historyIndex + 1);
          t.history.push(d.upstreamUrl);
          t.historyIndex = t.history.length - 1;
          ui.urlBar.value = d.upstreamUrl;
        }
        break;
      case 'lynk:console':
      case 'lynk:error':
      case 'lynk:network':
        /* forward to devtools-style log sink */
        try { console.debug('[lynk-bridge]', d.type, d); } catch (err) {}
        break;
      case 'lynk:capture':
        handleCaptureRequest(d, t);
        break;
      case 'lynk:clone-edit':
        broadcastCloneEdit(d);
        break;
      case 'lynk:clone-edit-done':
        /* broadcast to other shells via WS */
        serviceSend({ type: 'clone-edit-done', payload: d });
        break;
    }
  });

  /* =================== CAPTURE / CLONE =================== */

  function handleCaptureRequest(d, tab) {
    /* The interceptor already collected the payload; just forward it
       to the server-side cloner. */
    fetch('/cloner/capture', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(d.payload || {}),
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (tab && tab.iframe && tab.iframe.contentWindow) {
          tab.iframe.contentWindow.postMessage({
            type: 'lynk:capture-done', result: res,
          }, '*');
        }
      })
      .catch(function (err) {
        if (tab && tab.iframe && tab.iframe.contentWindow) {
          tab.iframe.contentWindow.postMessage({
            type: 'lynk:capture-error', error: String(err),
          }, '*');
        }
      });
  }

  function broadcastCloneEdit(d) {
    tabs.forEach(function (t) {
      if (t.id === d.clone_id || t.iframe.src.indexOf('/clone/' + d.clone_id) !== -1) {
        try {
          t.iframe.contentWindow.postMessage(d, '*');
        } catch (e) {}
      }
    });
    serviceSend({ type: 'clone-edit', payload: d });
  }

  /* =================== SERVICE WEBSOCKET =================== */

  let serviceWs = null;
  let serviceReady = false;

  function serviceConnect() {
    try {
      serviceWs = new WebSocket(SERVICE_WS);
    } catch (e) {
      setTimeout(serviceConnect, 3000);
      return;
    }
    serviceWs.addEventListener('open',  function () { serviceReady = true; });
    serviceWs.addEventListener('close', function () {
      serviceReady = false;
      setTimeout(serviceConnect, 3000);
    });
    serviceWs.addEventListener('message', function (ev) {
      let msg = null;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (!msg || !msg.type) return;
      if (msg.type === 'clone-edit') {
        broadcastCloneEdit(msg.payload);
      }
    });
  }

  function serviceSend(obj) {
    if (!serviceReady) return;
    try { serviceWs.send(JSON.stringify(obj)); } catch (e) {}
  }

  /* =================== KEYBOARD =================== */

  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 't') {
      e.preventDefault(); createTab('about:blank');
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'w') {
      e.preventDefault();
      if (activeTabId) closeTab(activeTabId);
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      if (ui.urlBar) { ui.urlBar.focus(); ui.urlBar.select(); }
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'r') {
      e.preventDefault(); reloadActive();
    } else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'e') {
      e.preventDefault();
      const t = activeTab(); if (!t) return;
      try { t.iframe.contentWindow.postMessage({ type: 'lynk:editor-toggle' }, '*'); } catch (er) {}
    }
  });

  /* =================== BOOT =================== */

  function boot() {
    ensureUI();
    preloadChunks(['ui.js', 'toolkit.js']).catch(function () {});
    serviceConnect();
    if (tabs.length === 0) createTab('about:blank');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }

  /* Public API */
  window.LynkShell = {
    createTab:    createTab,
    setActiveTab: setActiveTab,
    closeTab:     closeTab,
    navigate:     navigateActive,
    loadChunk:    loadChunk,
    preload:      preloadChunks,
    tabs:         function () { return tabs.slice(); },
    active:       activeTab,
  };
})();
