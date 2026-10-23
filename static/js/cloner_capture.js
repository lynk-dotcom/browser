/* Lynkio Cloner — capture. Injected into every proxied page. */
(function () {
  'use strict';
  if (window.__LYNK_CAPTURE_READY__) return;
  window.__LYNK_CAPTURE_READY__ = true;

  var MAX_PAYLOAD = 48 * 1024 * 1024;

  function abToB64(buf) {
    var bytes = new Uint8Array(buf);
    var chunk = 0x8000;
    var out = '';
    for (var i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(out);
  }

  function serializeValue(v) {
    return Promise.resolve().then(function () {
      if (v === null || v === undefined) return v;
      var t = typeof v;
      if (t === 'number' || t === 'string' || t === 'boolean') return v;
      if (t === 'bigint') return { __type: 'BigInt', data: String(v) };
      if (v instanceof ArrayBuffer) return { __type: 'ArrayBuffer', data: abToB64(v) };
      if (ArrayBuffer.isView && ArrayBuffer.isView(v))
        return { __type: 'ArrayBuffer', data: abToB64(v.buffer), view: v.constructor.name };
      if (typeof Blob !== 'undefined' && v instanceof Blob) {
        return v.arrayBuffer().then(function (buf) {
          return { __type: 'Blob', type: v.type || '', data: abToB64(buf) };
        });
      }
      if (v instanceof Date) return { __type: 'Date', data: v.toISOString() };
      if (Array.isArray(v)) return Promise.all(v.map(serializeValue));
      if (t === 'object') {
        var out = {};
        var keys = Object.keys(v);
        return Promise.all(keys.map(function (k) {
          return serializeValue(v[k]).then(function (val) { out[k] = val; });
        })).then(function () { return out; });
      }
      return null;
    });
  }

  function snapshotStorage(store) {
    var out = {};
    try {
      for (var i = 0; i < store.length; i++) {
        var k = store.key(i);
        out[k] = store.getItem(k);
      }
    } catch (e) {}
    return out;
  }

  /* ---- KEY: sanitize <script> textContent in outer_html ----
     If a script's textContent contains `</script` (unescaped), the
     re-parsed clone will close the tag early and dump the rest as
     visible text. Escaping `</script` to `<\/script` preserves the
     exact JS string value (since \/ is a valid escape for /) while
     preventing the closing-tag match. `a </ b` (unusual JS) is not
     affected because only the literal sequence `</script` matches. */
  function safeOuterHTML() {
    try {
      var clone = document.documentElement.cloneNode(true);
      var scripts = clone.querySelectorAll('script');
      for (var i = 0; i < scripts.length; i++) {
        var sc = scripts[i];
        var txt = sc.textContent || '';
        if (txt.indexOf('</') === -1) continue;
        sc.textContent = txt.replace(/<\/(script)/gi, '<\\/$1');
      }
      return '<!DOCTYPE html>\n' + clone.outerHTML;
    } catch (e) {
      try {
        return '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
      } catch (e2) {
        return '<!DOCTYPE html><html><head></head><body></body></html>';
      }
    }
  }

  function stablePath(el) {
    if (!el || el.nodeType !== 1) return '';
    var parts = [];
    var cur = el;
    var safety = 0;
    while (cur && cur !== document.documentElement && safety < 40) {
      safety++;
      if (cur.id) {
        parts.unshift('#' + CSS.escape(cur.id));
        return parts.join(' > ');
      }
      var nth = 1;
      var sib = cur;
      while ((sib = sib.previousElementSibling)) {
        if (sib.nodeType === 1) nth++;
      }
      parts.unshift(cur.tagName.toLowerCase() + ':nth-child(' + nth + ')');
      cur = cur.parentElement;
    }
    if (cur === document.documentElement) parts.unshift('html');
    return parts.join(' > ');
  }

  function captureDOMState() {
    var state = { forms: [], scrolls: [], canvases: [], media: [], shadows: [] };

    var formEls = document.querySelectorAll(
      'input, textarea, select, [contenteditable=""], [contenteditable="true"]'
    );
    for (var i = 0; i < formEls.length; i++) {
      var el = formEls[i];
      var path = stablePath(el);
      if (!path) continue;
      var entry = { path: path };
      try {
        if (el.tagName === 'INPUT') {
          if (el.type === 'checkbox' || el.type === 'radio') entry.checked = el.checked;
          else if (el.type === 'file') { }
          else entry.value = el.value;
        } else if (el.tagName === 'TEXTAREA') entry.value = el.value;
        else if (el.tagName === 'SELECT') {
          entry.value = el.value;
          entry.selectedIndex = el.selectedIndex;
        } else if (el.isContentEditable) entry.html = el.innerHTML;
      } catch (e) {}
      if (entry.value !== undefined || entry.checked !== undefined
          || entry.html !== undefined) {
        state.forms.push(entry);
      }
    }

    try {
      var sY = window.scrollY || document.documentElement.scrollTop || 0;
      var sX = window.scrollX || document.documentElement.scrollLeft || 0;
      if (sY || sX) state.scrolls.push({ path: '', scrollTop: sY, scrollLeft: sX });
    } catch (e) {}

    var all = document.querySelectorAll('*');
    for (var j = 0; j < all.length; j++) {
      var e2 = all[j];
      try {
        if ((e2.scrollTop > 0 || e2.scrollLeft > 0) &&
            (e2.scrollHeight > e2.clientHeight || e2.scrollWidth > e2.clientWidth)) {
          var sp = stablePath(e2);
          if (sp) state.scrolls.push({
            path: sp, scrollTop: e2.scrollTop, scrollLeft: e2.scrollLeft,
          });
        }
      } catch (e) {}
    }

    var canvases = document.querySelectorAll('canvas');
    for (var k = 0; k < canvases.length; k++) {
      var cv = canvases[k];
      var cp = stablePath(cv);
      if (!cp) continue;
      try {
        var dataUrl = cv.toDataURL('image/png');
        if (dataUrl && dataUrl.length > 400)
          state.canvases.push({ path: cp, dataUrl: dataUrl });
      } catch (e) {}
    }

    var media = document.querySelectorAll('video, audio');
    for (var m = 0; m < media.length; m++) {
      var mv = media[m];
      var mp = stablePath(mv);
      if (!mp) continue;
      try {
        state.media.push({
          path: mp,
          currentTime: mv.currentTime || 0,
          paused: !!mv.paused,
          volume: typeof mv.volume === 'number' ? mv.volume : 1,
          muted: !!mv.muted,
        });
      } catch (e) {}
    }

    function walkShadow(root, prefix) {
      try {
        var walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
        var node;
        while ((node = walker.nextNode())) {
          if (node.shadowRoot) {
            var hostPath = (prefix ? prefix + ' >> ' : '') + stablePath(node);
            var html = '';
            try {
              if (node.shadowRoot.getHTML) {
                html = node.shadowRoot.getHTML({ serializableShadowRoots: true });
              } else {
                html = node.shadowRoot.innerHTML;
              }
            } catch (e) { html = node.shadowRoot.innerHTML; }
            state.shadows.push({ hostPath: hostPath, html: html });
            walkShadow(node.shadowRoot, hostPath);
          }
        }
      } catch (e) {}
    }
    walkShadow(document, '');
    return state;
  }

  function dumpDB(name) {
    return new Promise(function (resolve, reject) {
      var req;
      try { req = indexedDB.open(name); } catch (e) { reject(e); return; }
      req.onsuccess = function () {
        var db = req.result;
        var dump = { version: db.version, stores: {} };
        var names = Array.from(db.objectStoreNames);
        var chain = Promise.resolve();
        names.forEach(function (storeName) {
          chain = chain.then(function () {
            return dumpStore(db, storeName).then(function (s) {
              dump.stores[storeName] = s;
            });
          });
        });
        chain.then(function () {
          try { db.close(); } catch (e) {}
          resolve(dump);
        }).catch(function (e) {
          try { db.close(); } catch (_) {}
          dump.error = String(e);
          resolve(dump);
        });
      };
      req.onerror = function () { reject(req.error); };
    });
  }

  function dumpStore(db, storeName) {
    return new Promise(function (resolve, reject) {
      var tx, store;
      try {
        tx = db.transaction(storeName, 'readonly');
        store = tx.objectStore(storeName);
      } catch (e) { reject(e); return; }
      var meta = {
        keyPath: store.keyPath,
        autoIncrement: store.autoIncrement,
        indexes: Array.from(store.indexNames).map(function (n) {
          var idx = store.index(n);
          return { name: n, keyPath: idx.keyPath,
                   unique: idx.unique, multiEntry: idx.multiEntry };
        }),
      };
      var req = store.getAll();
      req.onsuccess = function () {
        var records = [];
        var chain = Promise.resolve();
        req.result.forEach(function (rec) {
          chain = chain.then(function () {
            return serializeValue(rec).then(function (s) { records.push(s); })
              .catch(function () {});
          });
        });
        chain.then(function () { meta.records = records; resolve(meta); });
      };
      req.onerror = function () { reject(req.error); };
    });
  }

  function captureIndexedDB() {
    if (typeof indexedDB === 'undefined') return Promise.resolve({});
    if (!indexedDB.databases) return Promise.resolve({ __unsupported: true });
    return indexedDB.databases().then(function (dbs) {
      var out = {};
      var chain = Promise.resolve();
      dbs.forEach(function (info) {
        if (!info.name) return;
        chain = chain.then(function () {
          return dumpDB(info.name).then(function (d) { out[info.name] = d; })
            .catch(function (e) { out[info.name] = { error: String(e) }; });
        });
      });
      return chain.then(function () { return out; });
    }).catch(function (e) { return { __error: String(e) }; });
  }

  function captureCaches() {
    if (typeof caches === 'undefined') return Promise.resolve({});
    return caches.keys().then(function (names) {
      var out = {};
      var chain = Promise.resolve();
      names.forEach(function (name) {
        chain = chain.then(function () {
          return caches.open(name).then(function (cache) {
            return cache.keys().then(function (requests) {
              var entries = [];
              var sub = Promise.resolve();
              requests.forEach(function (request) {
                sub = sub.then(function () {
                  return cache.match(request).then(function (resp) {
                    if (!resp) return;
                    return resp.clone().arrayBuffer().then(function (buf) {
                      entries.push({
                        url: request.url,
                        method: request.method,
                        status: resp.status,
                        headers: Array.from(resp.headers.entries()),
                        body_b64: abToB64(buf),
                      });
                    }).catch(function () {});
                  }).catch(function () {});
                });
              });
              return sub.then(function () { out[name] = entries; });
            });
          }).catch(function (e) { out[name] = { error: String(e) }; });
        });
      });
      return chain.then(function () { return out; });
    }).catch(function (e) { return { __error: String(e) }; });
  }

  function walkOPFS(dir) {
    var result = { type: 'dir', entries: {} };
    if (!dir || !dir.entries) return Promise.resolve(result);
    var iter = dir.entries();
    function next() {
      return iter.next().then(function (r) {
        if (r.done) return result;
        var name = r.value[0];
        var handle = r.value[1];
        if (handle.kind === 'file') {
          return handle.getFile().then(function (file) {
            return file.arrayBuffer().then(function (buf) {
              result.entries[name] = {
                type: 'file',
                body_b64: abToB64(buf),
                mimeType: file.type || '',
                lastModified: file.lastModified || 0,
              };
              return next();
            });
          }).catch(function () { return next(); });
        }
        return walkOPFS(handle).then(function (sub) {
          result.entries[name] = sub;
          return next();
        }).catch(function () { return next(); });
      });
    }
    return next().catch(function (e) {
      result.error = String(e);
      return result;
    });
  }

  function captureOPFS() {
    if (!navigator.storage || !navigator.storage.getDirectory)
      return Promise.resolve(null);
    return navigator.storage.getDirectory().then(walkOPFS).catch(function (e) {
      return { error: String(e) };
    });
  }

  var GLOBAL_SKIP = {
    window: 1, self: 1, document: 1, location: 1, navigator: 1, history: 1,
    localStorage: 1, sessionStorage: 1, indexedDB: 1, caches: 1, console: 1,
    frames: 1, parent: 1, top: 1, opener: 1, closed: 1, length: 1, name: 1,
    screen: 1, performance: 1, crypto: 1, fetch: 1, XMLHttpRequest: 1,
    setTimeout: 1, setInterval: 1, clearTimeout: 1, clearInterval: 1,
    requestAnimationFrame: 1, cancelAnimationFrame: 1, atob: 1, btoa: 1,
    postMessage: 1, addEventListener: 1, removeEventListener: 1,
    dispatchEvent: 1, getComputedStyle: 1, matchMedia: 1, alert: 1,
    confirm: 1, prompt: 1, open: 1, close: 1, focus: 1, blur: 1, print: 1,
    scroll: 1, scrollTo: 1, scrollBy: 1,
    innerWidth: 1, innerHeight: 1, outerWidth: 1, outerHeight: 1,
    scrollX: 1, scrollY: 1, pageXOffset: 1, pageYOffset: 1,
    devicePixelRatio: 1, event: 1, CustomEvent: 1, Event: 1,
    MessageChannel: 1, MessagePort: 1, Worker: 1, SharedWorker: 1,
    ServiceWorker: 1, Blob: 1, File: 1, URL: 1, URLSearchParams: 1,
    FormData: 1, Headers: 1, Request: 1, Response: 1, AbortController: 1,
    TextEncoder: 1, TextDecoder: 1, ArrayBuffer: 1, Uint8Array: 1,
    Int8Array: 1, Uint16Array: 1, Int16Array: 1, Uint32Array: 1,
    Int32Array: 1, Float32Array: 1, Float64Array: 1, DataView: 1,
    Promise: 1, Symbol: 1, WeakMap: 1, WeakSet: 1, Map: 1, Set: 1,
    Date: 1, RegExp: 1, Error: 1, Proxy: 1, Reflect: 1, BigInt: 1,
  };

  function isPlainData(v) {
    if (v === null) return false;
    var t = typeof v;
    if (t === 'string' || t === 'number' || t === 'boolean') return true;
    if (t !== 'object') return false;
    try {
      var ctor = v.constructor;
      return ctor === Object || ctor === Array;
    } catch (e) { return false; }
  }

  function captureGlobals() {
    var out = {};
    try {
      var keys = Object.keys(window);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (GLOBAL_SKIP[k]) continue;
        if (!k) continue;
        if (k.indexOf('__lynk') === 0) continue;
        if (k.indexOf('webkit') === 0) continue;
        if (k.indexOf('moz') === 0) continue;
        if (k.indexOf('ms') === 0 && k.charAt(2) === k.charAt(2).toUpperCase()) continue;
        if (k.charAt(0) === 'o' && k.charAt(1) === 'n') continue;
        try {
          var v = window[k];
          if (!isPlainData(v)) continue;
          var s = JSON.stringify(v);
          if (!s || s.length > 500000) continue;
          out[k] = JSON.parse(s);
        } catch (e) {}
      }
    } catch (e) {}
    return out;
  }

  window.lynkCapture = function (options) {
    options = options || {};
    var target = (window.__LYNK_CTX__ && window.__LYNK_CTX__.upstream) || location.href;

    var payload = {
      target_url: target,
      outer_html: safeOuterHTML(),
      local_storage: snapshotStorage(localStorage),
      session_storage: snapshotStorage(sessionStorage),
      document_cookies: document.cookie,
      user_agent: navigator.userAgent,
      viewport: { w: window.innerWidth, h: window.innerHeight },
      dom_state: captureDOMState(),
      globals: captureGlobals(),
    };

    return Promise.all([
      captureIndexedDB(),
      captureCaches(),
      captureOPFS(),
    ]).then(function (res) {
      payload.indexeddb = res[0] || {};
      payload.caches = res[1] || {};
      payload.opfs = res[2];

      var json = JSON.stringify(payload);
      if (json.length > MAX_PAYLOAD) {
        delete payload.opfs;
        json = JSON.stringify(payload);
        if (json.length > MAX_PAYLOAD) {
          delete payload.caches;
          json = JSON.stringify(payload);
        }
        if (json.length > MAX_PAYLOAD) {
          delete payload.indexeddb;
          json = JSON.stringify(payload);
        }
      }

      return fetch('/clone/capture-client', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: json,
        credentials: 'same-origin',
      }).then(function (r) { return r.json(); });
    });
  };
})();
