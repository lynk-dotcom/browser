/* Lynkio Cloner — hydrate. Runs in the clone page BEFORE app scripts. */
(function () {
  'use strict';
  if (window.__LYNK_HYDRATE_READY__) return;
  window.__LYNK_HYDRATE_READY__ = true;

  function b64ToArrayBuffer(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function deserializeValue(v) {
    return Promise.resolve().then(function () {
      if (v === null || v === undefined) return v;
      var t = typeof v;
      if (t === 'number' || t === 'string' || t === 'boolean') return v;
      if (t === 'object' && v.__type) {
        if (v.__type === 'ArrayBuffer') return b64ToArrayBuffer(v.data);
        if (v.__type === 'Blob') return new Blob([b64ToArrayBuffer(v.data)], { type: v.type || '' });
        if (v.__type === 'Date') return new Date(v.data);
        if (v.__type === 'BigInt') { try { return BigInt(v.data); } catch (e) { return 0; } }
      }
      if (Array.isArray(v)) return Promise.all(v.map(deserializeValue));
      if (t === 'object') {
        var keys = Object.keys(v);
        var out = {};
        return Promise.all(keys.map(function (k) {
          return deserializeValue(v[k]).then(function (val) { out[k] = val; });
        })).then(function () { return out; });
      }
      return v;
    });
  }

  /* ---- 1. Read state ---- */
  var S = null;
  var stateEl = document.getElementById('__lynk_clone_state');
  if (stateEl) {
    try {
      S = JSON.parse(stateEl.textContent || '{}');
    } catch (e) {
      console.error('[lynk] failed to parse inline state:', e && e.message);
    }
  }
  if (!S && window.__LYNK_CLONE_STATE_URL__) {
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', window.__LYNK_CLONE_STATE_URL__, false);
      xhr.send(null);
      if (xhr.status === 200) S = JSON.parse(xhr.responseText);
    } catch (e) {
      console.error('[lynk] state fetch failed:', e && e.message);
    }
  }
  if (!S) {
    console.warn('[lynk] no clone state — running without hydration');
    return;
  }

  /* ---- 2. Sync restores ---- */
  if (S.globals) {
    for (var gk in S.globals) {
      try { window[gk] = S.globals[gk]; } catch (e) {}
    }
  }
  if (S.local_storage) {
    for (var lk in S.local_storage) {
      try { localStorage.setItem(lk, S.local_storage[lk]); } catch (e) {}
    }
  }
  if (S.session_storage) {
    for (var sk in S.session_storage) {
      try { sessionStorage.setItem(sk, S.session_storage[sk]); } catch (e) {}
    }
  }
  if (S.document_cookies) {
    var pairs = S.document_cookies.split(';');
    for (var ci = 0; ci < pairs.length; ci++) {
      var p = pairs[ci].trim();
      if (!p) continue;
      try { document.cookie = p + '; path=/'; } catch (e) {}
    }
  }

  /* ---- 3. IndexedDB barrier ---- */
  var IDB_OPEN = IDBFactory.prototype.open;
  var HYDRATION = hydrateAsync(S);
  window.__LYNK_HYDRATED__ = HYDRATION;

  IDBFactory.prototype.open = function (name, version) {
    var factory = this;
    var args = version !== undefined ? [name, version] : [name];
    var realReq = null;
    var pending = { success: [], error: [], upgradeneeded: [], blocked: [] };
    var proxy = {
      readyState: 'pending',
      get result() { return realReq ? realReq.result : undefined; },
      get error() { return realReq ? realReq.error : null; },
      get source() { return realReq ? realReq.source : null; },
      get transaction() { return realReq ? realReq.transaction : null; },
      addEventListener: function (t, fn) { if (pending[t]) pending[t].push(fn); },
      removeEventListener: function (t, fn) {
        var l = pending[t]; if (!l) return;
        var i = l.indexOf(fn); if (i >= 0) l.splice(i, 1);
      },
      dispatchEvent: function () { return false; },
    };
    ['onsuccess', 'onerror', 'onupgradeneeded', 'onblocked'].forEach(function (prop) {
      var val = null;
      Object.defineProperty(proxy, prop, {
        get: function () { return val; },
        set: function (fn) { val = fn; if (realReq) realReq[prop] = fn; },
        configurable: true,
      });
    });
    HYDRATION.then(function () {
      realReq = IDB_OPEN.apply(factory, args);
      ['success', 'error', 'upgradeneeded', 'blocked'].forEach(function (type) {
        var existing = realReq['on' + type];
        realReq['on' + type] = function (e) {
          if (typeof existing === 'function') { try { existing.call(realReq, e); } catch (_) {} }
          var custom = proxy['on' + type];
          if (typeof custom === 'function') { try { custom.call(realReq, e); } catch (_) {} }
          (pending[type] || []).forEach(function (fn) {
            try { fn.call(realReq, e); } catch (_) {}
          });
        };
      });
    });
    return proxy;
  };

  function hydrateAsync(state) {
    var p = Promise.resolve();
    p = p.then(function () {
      if (!state.indexeddb || state.indexeddb.__unsupported) return;
      var names = Object.keys(state.indexeddb);
      var chain = Promise.resolve();
      names.forEach(function (name) {
        if (name.charAt(0) === '_') return;
        var dump = state.indexeddb[name];
        if (!dump || dump.error || !dump.stores) return;
        chain = chain.then(function () {
          return restoreIDB(name, dump).catch(function (e) {
            console.warn('[lynk] IDB restore failed:', name, e);
          });
        });
      });
      return chain;
    });
    p = p.then(function () {
      if (!state.caches || typeof caches === 'undefined') return;
      var names = Object.keys(state.caches);
      var chain = Promise.resolve();
      names.forEach(function (name) {
        if (name.charAt(0) === '_') return;
        var entries = state.caches[name];
        if (!Array.isArray(entries)) return;
        chain = chain.then(function () {
          return caches.open(name).then(function (cache) {
            var sub = Promise.resolve();
            entries.forEach(function (entry) {
              sub = sub.then(function () {
                try {
                  var body = entry.body_b64 ? b64ToArrayBuffer(entry.body_b64) : null;
                  var headers = new Headers();
                  (entry.headers || []).forEach(function (kv) {
                    try { headers.append(kv[0], kv[1]); } catch (e) {}
                  });
                  var response = new Response(body, {
                    status: entry.status || 200, headers: headers,
                  });
                  return cache.put(entry.url, response);
                } catch (e) {}
              });
            });
            return sub;
          }).catch(function (e) {
            console.warn('[lynk] cache restore failed:', name, e);
          });
        });
      });
      return chain;
    });
    p = p.then(function () {
      if (!state.opfs || !navigator.storage || !navigator.storage.getDirectory) return;
      return navigator.storage.getDirectory().then(function (root) {
        return restoreOPFS(root, state.opfs);
      }).catch(function (e) { console.warn('[lynk] OPFS restore failed:', e); });
    });
    return p;
  }

  function restoreIDB(name, dump) {
    return new Promise(function (resolve, reject) {
      var openReq;
      try { openReq = IDB_OPEN.call(indexedDB, name, dump.version); }
      catch (e) { reject(e); return; }
      openReq.onupgradeneeded = function (ev) {
        var db = ev.target.result;
        Object.keys(dump.stores || {}).forEach(function (storeName) {
          var meta = dump.stores[storeName];
          var store;
          if (!db.objectStoreNames.contains(storeName)) {
            store = db.createObjectStore(storeName, {
              keyPath: meta.keyPath !== null ? meta.keyPath : undefined,
              autoIncrement: !!meta.autoIncrement,
            });
          } else {
            store = ev.target.transaction.objectStore(storeName);
          }
          (meta.indexes || []).forEach(function (idx) {
            try {
              if (!store.indexNames.contains(idx.name)) {
                store.createIndex(idx.name, idx.keyPath, {
                  unique: !!idx.unique, multiEntry: !!idx.multiEntry,
                });
              }
            } catch (e) {}
          });
        });
      };
      openReq.onsuccess = function () {
        var db = openReq.result;
        var stores = Object.keys(dump.stores || {});
        if (!stores.length) { try { db.close(); } catch (e) {} resolve(); return; }
        var tx;
        try { tx = db.transaction(stores, 'readwrite'); }
        catch (e) { try { db.close(); } catch (_) {} reject(e); return; }
        var pending = [];
        stores.forEach(function (storeName) {
          var meta = dump.stores[storeName];
          var store = tx.objectStore(storeName);
          (meta.records || []).forEach(function (rec) {
            pending.push(deserializeValue(rec).then(function (r) {
              try { store.put(r); } catch (e) {}
            }).catch(function () {}));
          });
        });
        Promise.all(pending).then(function () {
          tx.oncomplete = function () {
            try { db.close(); } catch (e) {}
            resolve();
          };
          tx.onerror = function () {
            try { db.close(); } catch (e) {}
            resolve();
          };
        });
      };
      openReq.onerror = function () { reject(openReq.error); };
    });
  }

  function restoreOPFS(dir, node) {
    if (!node || node.type !== 'dir' || !node.entries) return Promise.resolve();
    var keys = Object.keys(node.entries);
    var chain = Promise.resolve();
    keys.forEach(function (name) {
      var child = node.entries[name];
      chain = chain.then(function () {
        if (child.type === 'file') {
          return dir.getFileHandle(name, { create: true }).then(function (fh) {
            return fh.createWritable().then(function (w) {
              return w.write(b64ToArrayBuffer(child.body_b64 || '')).then(function () {
                return w.close();
              });
            });
          }).catch(function () {});
        }
        return dir.getDirectoryHandle(name, { create: true }).then(function (sub) {
          return restoreOPFS(sub, child);
        }).catch(function () {});
      });
    });
    return chain;
  }

  function applyDOMState() {
    var dom = S.dom_state || {};
    (dom.forms || []).forEach(function (f) {
      try {
        var el = f.path ? document.querySelector(f.path) : null;
        if (!el) return;
        if (el.tagName === 'INPUT') {
          if ((el.type === 'checkbox' || el.type === 'radio')
              && f.checked !== undefined) {
            el.checked = !!f.checked;
            el.dispatchEvent(new Event('change', { bubbles: true }));
          } else if (f.value !== undefined) {
            el.value = f.value;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
          }
        } else if (el.tagName === 'TEXTAREA' && f.value !== undefined) {
          el.value = f.value;
          el.dispatchEvent(new Event('input', { bubbles: true }));
        } else if (el.tagName === 'SELECT' && f.value !== undefined) {
          el.value = f.value;
          el.dispatchEvent(new Event('change', { bubbles: true }));
        } else if (el.isContentEditable && f.html !== undefined) {
          el.innerHTML = f.html;
        }
      } catch (e) {}
    });
    (dom.scrolls || []).forEach(function (s) {
      try {
        var el = s.path ? document.querySelector(s.path)
                        : (document.scrollingElement || document.documentElement);
        if (!el) return;
        el.scrollTop = s.scrollTop || 0;
        el.scrollLeft = s.scrollLeft || 0;
      } catch (e) {}
    });
    (dom.canvases || []).forEach(function (c) {
      try {
        var el = c.path ? document.querySelector(c.path) : null;
        if (!el || el.tagName !== 'CANVAS') return;
        var ctx = el.getContext('2d');
        if (!ctx) return;
        var img = new Image();
        img.onload = function () {
          try {
            el.width = img.width; el.height = img.height;
            ctx.drawImage(img, 0, 0);
          } catch (e) {}
        };
        img.src = c.dataUrl;
      } catch (e) {}
    });
    (dom.media || []).forEach(function (m) {
      try {
        var el = m.path ? document.querySelector(m.path) : null;
        if (!el) return;
        if (typeof m.volume === 'number') el.volume = m.volume;
        el.muted = !!m.muted;
        if (typeof m.currentTime === 'number') {
          try { el.currentTime = m.currentTime; } catch (e) {}
        }
        if (!m.paused) {
          var pp = el.play(); if (pp && pp.catch) pp.catch(function () {});
        } else { try { el.pause(); } catch (e) {} }
      } catch (e) {}
    });
    (dom.shadows || []).forEach(function (sh) {
      try {
        var parts = (sh.hostPath || '').split(' >> ');
        var host = null;
        if (parts.length === 1 && parts[0]) {
          host = document.querySelector(parts[0]);
        } else if (parts.length > 1) {
          host = document.querySelector(parts[0]);
          for (var i = 1; i < parts.length && host; i++) {
            host = host.shadowRoot ? host.shadowRoot.querySelector(parts[i]) : null;
          }
        }
        if (!host) return;
        var root = host.shadowRoot || host.attachShadow({ mode: 'open' });
        root.innerHTML = sh.html || '';
      } catch (e) {}
    });
  }
  function scheduleDOMRestore() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', applyDOMState, { once: true });
    } else {
      applyDOMState();
    }
    window.addEventListener('load', function () { applyDOMState(); }, { once: true });
    try {
      var pending = false;
      var obs = new MutationObserver(function () {
        if (pending) return;
        pending = true;
        setTimeout(function () { pending = false; applyDOMState(); }, 60);
      });
      obs.observe(document.documentElement, { subtree: true, childList: true });
    } catch (e) {}
  }
  scheduleDOMRestore();
})();
