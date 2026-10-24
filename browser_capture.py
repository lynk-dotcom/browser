"""CDP-based capture pipeline — produces clones from real Chrome tabs."""
import asyncio
import logging
import time
import uuid
from urllib.parse import urlparse

import cdp_client
import cloner

log = logging.getLogger("lynk.capture")

DUMP_INDEXEDDB_JS = r"""
(async function(){
  if (typeof indexedDB === 'undefined') return {};
  if (!indexedDB.databases) return {__unsupported: true};
  function abToB64(buf){
    var bytes = new Uint8Array(buf), chunk = 0x8000, out = '';
    for (var i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(out);
  }
  function serialize(v){
    return Promise.resolve().then(function(){
      if (v === null || v === undefined) return v;
      var t = typeof v;
      if (t === 'number' || t === 'string' || t === 'boolean') return v;
      if (t === 'bigint') return {__type:'BigInt', data:String(v)};
      if (v instanceof ArrayBuffer) return {__type:'ArrayBuffer', data:abToB64(v)};
      if (ArrayBuffer.isView(v)) return {__type:'ArrayBuffer', data:abToB64(v.buffer), view:v.constructor.name};
      if (typeof Blob !== 'undefined' && v instanceof Blob){
        return v.arrayBuffer().then(function(b){ return {__type:'Blob', type:v.type||'', data:abToB64(b)}; });
      }
      if (v instanceof Date) return {__type:'Date', data:v.toISOString()};
      if (Array.isArray(v)) return Promise.all(v.map(serialize));
      if (t === 'object'){
        var keys = Object.keys(v), out = {};
        return Promise.all(keys.map(function(k){
          return serialize(v[k]).then(function(val){ out[k] = val; });
        })).then(function(){ return out; });
      }
      return null;
    });
  }
  function dumpDB(name){
    return new Promise(function(resolve){
      var req = indexedDB.open(name);
      req.onsuccess = function(){
        var db = req.result, dump = {version: db.version, stores: {}};
        var names = Array.from(db.objectStoreNames);
        var chain = Promise.resolve();
        names.forEach(function(storeName){
          chain = chain.then(function(){
            return new Promise(function(res){
              var tx = db.transaction(storeName, 'readonly');
              var store = tx.objectStore(storeName);
              var meta = {keyPath: store.keyPath, autoIncrement: store.autoIncrement, indexes: []};
              Array.from(store.indexNames).forEach(function(n){
                var idx = store.index(n);
                meta.indexes.push({name:n, keyPath:idx.keyPath, unique:idx.unique, multiEntry:idx.multiEntry});
              });
              var r = store.getAll();
              r.onsuccess = function(){
                var recs = [], sub = Promise.resolve();
                r.result.forEach(function(rec){
                  sub = sub.then(function(){ return serialize(rec).then(function(s){ recs.push(s); }); });
                });
                sub.then(function(){ meta.records = recs; dump.stores[storeName] = meta; res(); });
              };
              r.onerror = function(){ res(); };
            });
          });
        });
        chain.then(function(){ try{ db.close(); }catch(e){} resolve(dump); });
      };
      req.onerror = function(){ resolve({error:'open failed'}); };
    });
  }
  var dbs = await indexedDB.databases();
  var out = {};
  for (var i = 0; i < dbs.length; i++){
    if (!dbs[i].name) continue;
    try { out[dbs[i].name] = await dumpDB(dbs[i].name); }
    catch(e) { out[dbs[i].name] = {error: String(e)}; }
  }
  return out;
})()
"""

DUMP_CACHES_JS = r"""
(async function(){
  if (typeof caches === 'undefined') return {};
  function abToB64(buf){
    var bytes = new Uint8Array(buf), chunk = 0x8000, out = '';
    for (var i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(out);
  }
  var names = await caches.keys();
  var out = {};
  for (var i = 0; i < names.length; i++){
    var entries = [], cache = await caches.open(names[i]);
    var reqs = await cache.keys();
    for (var j = 0; j < reqs.length; j++){
      var resp = await cache.match(reqs[j]);
      if (!resp) continue;
      try {
        var buf = await resp.clone().arrayBuffer();
        entries.push({
          url: reqs[j].url,
          method: reqs[j].method,
          status: resp.status,
          headers: Array.from(resp.headers.entries()),
          body_b64: abToB64(buf)
        });
      } catch(e) {}
    }
    out[names[i]] = entries;
  }
  return out;
})()
"""

DUMP_OPFS_JS = r"""
(async function(){
  if (!navigator.storage || !navigator.storage.getDirectory) return null;
  function abToB64(buf){
    var bytes = new Uint8Array(buf), chunk = 0x8000, out = '';
    for (var i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(out);
  }
  async function walk(dir){
    var result = {type:'dir', entries:{}};
    for await (var pair of dir.entries()){
      var name = pair[0], handle = pair[1];
      if (handle.kind === 'file'){
        try {
          var file = await handle.getFile(), buf = await file.arrayBuffer();
          result.entries[name] = {type:'file', body_b64: abToB64(buf), mimeType: file.type||'', lastModified: file.lastModified||0};
        } catch(e) {}
      } else {
        try { result.entries[name] = await walk(handle); } catch(e) {}
      }
    }
    return result;
  }
  try { return await walk(await navigator.storage.getDirectory()); }
  catch(e) { return {error: String(e)}; }
})()
"""

DUMP_GLOBALS_JS = r"""
(function(){
  var SKIP = {window:1,self:1,document:1,location:1,navigator:1,history:1,
    localStorage:1,sessionStorage:1,indexedDB:1,caches:1,console:1,frames:1,
    parent:1,top:1,opener:1,closed:1,length:1,name:1,screen:1,performance:1,
    crypto:1,fetch:1,XMLHttpRequest:1,setTimeout:1,setInterval:1,
    clearTimeout:1,clearInterval:1,requestAnimationFrame:1,cancelAnimationFrame:1,
    atob:1,btoa:1,postMessage:1,addEventListener:1,removeEventListener:1,
    dispatchEvent:1,getComputedStyle:1,matchMedia:1,alert:1,confirm:1,prompt:1,
    open:1,close:1,focus:1,blur:1,print:1,scroll:1,scrollTo:1,scrollBy:1,
    innerWidth:1,innerHeight:1,outerWidth:1,outerHeight:1,scrollX:1,scrollY:1,
    pageXOffset:1,pageYOffset:1,devicePixelRatio:1,event:1,CustomEvent:1,Event:1,
    MessageChannel:1,MessagePort:1,Worker:1,SharedWorker:1,ServiceWorker:1,
    Blob:1,File:1,URL:1,URLSearchParams:1,FormData:1,Headers:1,Request:1,
    Response:1,AbortController:1,TextEncoder:1,TextDecoder:1,ArrayBuffer:1,
    Uint8Array:1,Int8Array:1,Uint16Array:1,Int16Array:1,Uint32Array:1,
    Int32Array:1,Float32Array:1,Float64Array:1,DataView:1,Promise:1,Symbol:1,
    WeakMap:1,WeakSet:1,Map:1,Set:1,Date:1,RegExp:1,Error:1,Proxy:1,Reflect:1,BigInt:1};
  var out = {}, keys = Object.keys(window);
  for (var i = 0; i < keys.length; i++){
    var k = keys[i];
    if (SKIP[k] || !k) continue;
    if (k.indexOf('__lynk') === 0 || k.indexOf('webkit') === 0 || k.indexOf('moz') === 0) continue;
    if (k.charAt(0) === 'o' && k.charAt(1) === 'n') continue;
    try {
      var v = window[k];
      if (v === null || typeof v === 'function') continue;
      if (typeof v === 'object' && (v.nodeType || v === window)) continue;
      var s = JSON.stringify(v);
      if (!s || s.length > 500000) continue;
      out[k] = JSON.parse(s);
    } catch(e) {}
  }
  return out;
})()
"""


def _host(origin):
    try:
        return urlparse(origin).hostname or ""
    except Exception:
        return ""


def _scheme(origin):
    try:
        return urlparse(origin).scheme or "https"
    except Exception:
        return "https"


async def wait_challenge_cleared(client, session, origin, timeout=90.0):
    """FIX: default raised from 30s to 90s and checks body length as a fallback."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            cookies = await cdp_client.get_cookies(client, session)
            if any(c.get("name") == "cf_clearance" for c in cookies):
                await asyncio.sleep(1.0)
                return True
        except Exception:
            pass

        try:
            body_len = await cdp_client.evaluate(
                client, session, "document.body ? document.body.innerText.length : 0", await_promise=False
            )
            if body_len and body_len > 200:
                return True
        except Exception:
            pass

        await asyncio.sleep(0.8)
    return False


async def capture(client, session, url, origin, sess=None):
    try:
        cur = await cdp_client.evaluate(client, session, "location.href", await_promise=False)
    except Exception:
        cur = ""

    if cur != url:
        await cdp_client.navigate(client, session, url)

    # FIX: wait for network idle (resource count stable for 2s), not just readyState.
    await cdp_client.wait_ready(client, session, timeout=90.0)

    # FIX: give challenge JS / iframe loaders more time (was 2.5s).
    await asyncio.sleep(5.0)
    await wait_challenge_cleared(client, session, origin, timeout=90.0)

    html = await cdp_client.get_html(client, session)
    raw_cookies = await cdp_client.get_cookies(client, session)

    ls = ss = {}
    idb = caches_dump = {}
    opfs = None
    globals_dump = {}
    ua = ""

    try:
        ls = await cdp_client.get_storage(client, session, origin, "localStorage")
    except Exception as e:
        log.debug("localStorage: %s", e)
    try:
        ss = await cdp_client.get_storage(client, session, origin, "sessionStorage")
    except Exception as e:
        log.debug("sessionStorage: %s", e)
    try:
        idb = await cdp_client.evaluate(client, session, DUMP_INDEXEDDB_JS, timeout=90.0)
    except Exception as e:
        log.debug("IDB: %s", e)
    try:
        caches_dump = await cdp_client.evaluate(client, session, DUMP_CACHES_JS, timeout=90.0)
    except Exception as e:
        log.debug("caches: %s", e)
    try:
        opfs = await cdp_client.evaluate(client, session, DUMP_OPFS_JS, timeout=90.0)
    except Exception as e:
        log.debug("OPFS: %s", e)
    try:
        globals_dump = await cdp_client.evaluate(client, session, DUMP_GLOBALS_JS, await_promise=False)
    except Exception as e:
        log.debug("globals: %s", e)
    try:
        ua = await cdp_client.evaluate(client, session, "navigator.userAgent", await_promise=False)
    except Exception:
        pass

    host = _host(origin)
    scheme = _scheme(origin)
    server_cookies = {}
    for c in raw_cookies:
        domain = (c.get("domain") or "").lstrip(".").lower()
        if not domain:
            continue
        if host == domain or host.endswith("." + domain):
            origin_key = f"{scheme}://{domain}"
            server_cookies.setdefault(origin_key, {})[c["name"]] = {
                "value": c.get("value", ""),
                "path": c.get("path", "/"),
                "domain": c.get("domain", ""),
                "secure": c.get("secure", False),
                "httponly": c.get("httpOnly", False),
                "samesite": c.get("sameSite", ""),
                "expires": c.get("expires", 0),
            }

    parsed = urlparse(url)
    clone = {
        "uuid": uuid.uuid4().hex[:16],
        "created_at": time.time(),
        "source_url": url,
        "page_origin": origin,
        "final_path": parsed.path or "/",
        "server_cookies": server_cookies,
        "injected": [
            {"id": s["id"], "name": s["name"], "code": s["code"], "enabled": s["enabled"]}
            for s in (sess.injected if sess else [])
        ],
        "history": list(sess.history)[-300:] if sess else [],
        "recent_origins": [[o, t] for o, t in (sess.recent_origins if sess else [])],
        "outer_html": html,
        "local_storage": ls,
        "session_storage": ss,
        "document_cookies": "",
        "indexeddb": idb,
        "caches": caches_dump,
        "opfs": opfs,
        "dom_state": {},
        "globals": globals_dump,
        "user_agent": ua,
        "viewport": {},
        "turnstile_token": "",
        "edit_count": 0,
        "last_edit_ts": 0,
    }

    cloner.save_clone(clone)

    if sess is not None:
        for origin_key, jar in server_cookies.items():
            for name, attrs in jar.items():
                try:
                    sess.cookies.set(
                        origin_key,
                        name,
                        attrs["value"],
                        path=attrs.get("path", "/"),
                        secure=attrs.get("secure", False),
                        httponly=attrs.get("httponly", False),
                        samesite=attrs.get("samesite", ""),
                    )
                except Exception:
                    pass

    return clone