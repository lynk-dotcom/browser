/* Lynkio interceptor — proxied pages AND clone pages.
   Fixes in this revision:
   1. Raw-string check for /proxy, /static, /lynkio, /__lynk_, /clone, /clones, /tabs, /tool
      BEFORE any URL resolution — kills the double-proxy bug.
   2. Unwrap URLs that were badly resolved against UPSTREAM
      (https://UPSTREAM/proxy?url=X  →  /proxy?url=X).
   3. Defensive shim: https://UPSTREAM/static/js/<lynk-file>  →  /static/js/<lynk-file>
      so a chunk loader that used __LYNK_CTX__.upstream as base still finds the file.
   4. Neutralise <base href> so relative chunk URLs resolve to location.origin.
   5. Clone-aware: leaves same-origin URLs alone on /clone/* (server catch-all handles them).
*/
(function () {
  'use strict';
  if (window.__LYNK_ICPT__) return;
  window.__LYNK_ICPT__ = true;

  var path  = location.pathname || '/';
  var isClone =
    path.indexOf('/clone/') === 0 ||
    !!window.__LYNK_CLONE_STATE__ ||
    !!window.__LYNK_CLONE_STATE_URL__;

  /* ---------- upstream ---------- */
  function resolveUpstream() {
    if (window.__LYNK_CTX__ && window.__LYNK_CTX__.upstream) return window.__LYNK_CTX__.upstream;
    if (window.__LYNK_CLONE_STATE__ && window.__LYNK_CLONE_STATE__.source_url) {
      try { return new URL(window.__LYNK_CLONE_STATE__.source_url).origin; } catch (e) {}
    }
    if (window.__LYNK_CLONE_STATE__ && window.__LYNK_CLONE_STATE__.page_origin) {
      return window.__LYNK_CLONE_STATE__.page_origin;
    }
    if (window.__LYNK_CLONE_STATE_URL__) {
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', window.__LYNK_CLONE_STATE_URL__, false);
        xhr.send(null);
        if (xhr.status === 200) {
          var s = JSON.parse(xhr.responseText);
          if (s.source_url)  return new URL(s.source_url).origin;
          if (s.page_origin) return s.page_origin;
        }
      } catch (e) {}
    }
    try {
      var q = new URL(location.href).searchParams.get('url');
      if (q) return new URL(q).origin;
    } catch (e) {}
    return null;
  }

  var UP_STR = resolveUpstream();
  var UP = (function () { try { return UP_STR ? new URL(UP_STR) : null; } catch (e) { return null; } })();
  if (!UP) return;

  var ORIGIN  = location.origin;
  var PROXY   = ORIGIN + '/proxy';
  var WS_TUN  = ORIGIN.replace(/^http/, 'ws') + '/__lynk_ws';

  /* ---------- known Lynk static files (for the chunk-loader shim) ---------- */
  var LYNK_STATIC = {
    'ui.js': 1, 'shell.js': 1, 'toolkit.js': 1, 'interceptor.js': 1,
    'cloner_capture.js': 1, 'cloner_hydrate.js': 1
  };

  /* ---------- captcha hosts ---------- */
  var CAPTCHA_HOSTS = [
    'google.com/recaptcha/', 'recaptcha.net/recaptcha/', 'gstatic.com/recaptcha/',
    'hcaptcha.com/', 'newassets.hcaptcha.com/', 'challenges.cloudflare.com/',
    'turnstile.com/', 'cloudflare.com/cdn-cgi/challenge-platform/',
    'arkoselabs.com/', 'funcaptcha.com/', 'captcha.awswaf.com/', 'awswaf.com/captcha/'
  ];
  function isCaptchaURL(u) {
    var s = String(u).toLowerCase();
    for (var i = 0; i < CAPTCHA_HOSTS.length; i++) if (s.indexOf(CAPTCHA_HOSTS[i]) !== -1) return true;
    return false;
  }

  /* ---------- shell bridge ---------- */
  function post(type, payload) {
    try {
      if (!window.parent || window.parent === window) return;
      window.parent.postMessage(Object.assign({ type: 'lynk:' + type, url: location.href }, payload || {}), '*');
    } catch (e) {}
  }
  window.addEventListener('beforeunload', function () { post('nav-start'); });
  window.addEventListener('pagehide',     function () { post('nav-start'); });
  window.addEventListener('load',         function () { post('nav-loaded', { title: document.title }); });
  if (document.readyState === 'complete') post('nav-loaded', { title: document.title });

  document.addEventListener('click', function (e) {
    try {
      var a = e.target && e.target.closest && e.target.closest('a[href]');
      if (!a) return;
      if (a.target && a.target !== '' && a.target !== '_self') return;
      var h = a.getAttribute('href');
      if (!h || h.charAt(0) === '#' || /^javascript:/i.test(h)) return;
      post('nav-start', { target: rw(h) });
    } catch (err) {}
  }, true);
  document.addEventListener('submit', function () { post('nav-start'); }, true);

  /* ---------- console / error bridge ---------- */
  ['log','info','warn','error','debug'].forEach(function (lvl) {
    var orig = console[lvl];
    if (!orig) return;
    console[lvl] = function () {
      try {
        var args = Array.prototype.slice.call(arguments).map(function (a) {
          if (typeof a === 'string') return a;
          if (a instanceof Error)   return a.message + (a.stack ? '\n' + a.stack : '');
          try { return JSON.stringify(a); } catch (e) { return String(a); }
        });
        post('console', { level: lvl, args: args });
      } catch (e) {}
      try { return orig.apply(console, arguments); } catch (e) {}
    };
  });
  window.addEventListener('error', function (e) {
    post('error', {
      message: e.message || String(e.error || 'Error'),
      source: e.filename, line: e.lineno, col: e.colno,
      stack: e.error && e.error.stack
    });
  });
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason || {};
    post('error', { message: 'Unhandled rejection: ' + (r.message || String(r)), stack: r.stack });
  });

  /* ---------- Lynk path detection ---------- */
  function isLynkPath(p) {
    if (!p) return false;
    if (p === '/' || p === '') return true;
    return p.indexOf('/proxy') === 0 ||
           p.indexOf('/__lynk_') === 0 ||
           p.indexOf('/lynkio/') === 0 ||
           p.indexOf('/static/') === 0 ||
           p.indexOf('/tool/') === 0 ||
           p.indexOf('/tabs') === 0 ||
           p.indexOf('/clone/') === 0 ||
           p.indexOf('/clones') === 0;
  }

  /* ---------- URL rewriting policy ---------- */

  function shouldProxy(u) {
    if (u == null || u === '') return false;
    var s = String(u);
    if (s.charAt(0) === '#') return false;
    if (/^(data|blob|javascript|about|mailto|tel|chrome|chrome-extension|file|ws:|wss:)/i.test(s)) return false;
    if (s.length > 16384) return false;
    if (isCaptchaURL(s)) return false;

    /* RAW Lynk-path check — BEFORE resolution. This is the fix for the
       double-proxy bug:  /proxy?url=… must never be re-wrapped. */
    if (s.charAt(0) === '/' && s.charAt(1) !== '/' && isLynkPath(s)) return false;

    /* Absolute on OUR origin and a Lynk path → leave alone */
    if (s.indexOf(ORIGIN) === 0) {
      var p0 = s.slice(ORIGIN.length);
      if (isLynkPath(p0)) return false;
    }

    try {
      var abs = new URL(s, UP.href);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return false;

      /* Clone pages: server catch-all handles same-origin */
      if (isClone && abs.origin === ORIGIN) return false;

      /* Absolute on OUR origin, non-Lynk path → leave alone */
      if (abs.origin === ORIGIN) return false;

      return true;
    } catch (e) {
      return false;
    }
  }

  function rw(u) {
    try {
      if (u == null) return u;
      var s = String(u);

      /* (a) Raw Lynk relative path → leave untouched */
      if (s.charAt(0) === '/' && s.charAt(1) !== '/' && isLynkPath(s)) return s;

      /* (b) Absolute on our origin, Lynk path → strip origin */
      if (s.indexOf(ORIGIN) === 0) {
        var pB = s.slice(ORIGIN.length);
        if (isLynkPath(pB)) return pB;
      }

      /* (c) Already-proxied but resolved against UPSTREAM → unwrap
             https://instagram.com/proxy?url=X  →  /proxy?url=X */
      if (s.indexOf(UP.origin + '/proxy') === 0) {
        return s.slice(UP.origin.length);
      }

      /* (d) Lynk static assets that somehow got an UPSTREAM origin
             (defensive for chunk loaders that used __LYNK_CTX__.upstream) */
      if (s.indexOf(UP.origin + '/static/js/') === 0) {
        var fname = s.slice((UP.origin + '/static/js/').length).split('?')[0].split('#')[0];
        if (LYNK_STATIC[fname]) return '/static/js/' + fname;
      }

      /* (e) Protocol-relative handled explicitly */
      if (s.indexOf('//') === 0) {
        var absPR = 'https:' + s;
        if (absPR.indexOf(ORIGIN) === 0) {
          var pC = absPR.slice(ORIGIN.length);
          if (isLynkPath(pC)) return pC;
        }
        if (absPR.indexOf(UP.origin + '/proxy') === 0) {
          return absPR.slice(UP.origin.length);
        }
      }

      /* (f) Standard proxy */
      if (!shouldProxy(s)) return s;
      var abs = new URL(s, UP.href).href;
      return PROXY + '?url=' + encodeURIComponent(abs);
    } catch (e) {
      return u;
    }
  }
  window.__LYNK_RW__ = rw;

  function rwSrcset(s) {
    if (!s || typeof s !== 'string') return s;
    try {
      return s.split(',').map(function (entry) {
        var t = entry.trim();
        if (!t) return entry;
        var parts = t.split(/\s+/);
        if (parts[0]) parts[0] = rw(parts[0]);
        return parts.join(' ');
      }).join(', ');
    } catch (e) { return s; }
  }

  /* ---------- fetch / XHR ---------- */
  var _fetch = window.fetch;
  if (_fetch) {
    window.fetch = function (input, init) {
      var urlForLog;
      try { urlForLog = typeof input === 'string' ? input : (input && input.url); } catch (e) {}
      try {
        if (typeof input === 'string') input = rw(input);
        else if (input instanceof URL) input = rw(input.href);
        else if (input instanceof Request) {
          if (input.body === null) {
            var nu = rw(input.url);
            if (nu !== input.url) input = new Request(nu, input);
          }
        }
      } catch (e) {}
      var p = _fetch.apply(this, arguments);
      return p.then(function (r) {
        try { if (!r.ok) post('network', { method: (init && init.method) || 'GET', url: urlForLog, status: r.status }); } catch (e) {}
        return r;
      }).catch(function (err) {
        try { post('network', { method: (init && init.method) || 'GET', url: urlForLog, error: (err && err.message) || String(err) }); } catch (e) {}
        throw err;
      });
    };
  }

  var _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    try {
      var self = this;
      self.addEventListener('error',  function () { post('network', { method: m, url: u, error: 'XHR error' }); });
      self.addEventListener('load',   function () { if (self.status >= 400) post('network', { method: m, url: u, status: self.status }); });
    } catch (e) {}
    try { arguments[1] = rw(u); } catch (e) {}
    return _xhrOpen.apply(this, arguments);
  };

  /* ---------- WebSocket ---------- */
  var _WS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    try {
      if (typeof url === 'string' && !isLynkPath(url)) {
        var abs = new URL(url, UP.href);
        var sch = abs.protocol === 'wss:' ? 'wss:' : 'ws:';
        var tun = WS_TUN + '?__lynk_ws=' + encodeURIComponent(sch + '//' + abs.host + abs.pathname + abs.search);
        return protocols ? new _WS(tun, protocols) : new _WS(tun);
      }
    } catch (e) {}
    return protocols ? new _WS(url, protocols) : new _WS(url);
  };
  window.WebSocket.prototype = _WS.prototype;
  ['CONNECTING','OPEN','CLOSING','CLOSED'].forEach(function (k) { window.WebSocket[k] = _WS[k]; });

  /* ---------- EventSource ---------- */
  var _ES = window.EventSource;
  if (_ES) {
    window.EventSource = function (url, opts) { try { url = rw(url); } catch (e) {} return opts ? new _ES(url, opts) : new _ES(url); };
    window.EventSource.prototype = _ES.prototype;
  }

  /* ---------- sendBeacon ---------- */
  if (navigator.sendBeacon) {
    var _sb = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { try { u = rw(u); } catch (e) {} return _sb(u, d); };
  }

  /* ---------- DOM property hooks ---------- */
  function hook(proto, prop, xform) {
    if (!proto) return;
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || d.__lynkPatched) return;
      var nd = {
        get: d.get,
        set: function (v) { try { v = xform.call(this, v); } catch (e) {} return d.set.call(this, v); },
        configurable: true, enumerable: d.enumerable
      };
      nd.__lynkPatched = true;
      Object.defineProperty(proto, prop, nd);
    } catch (e) {}
  }
  hook(window.HTMLAnchorElement && HTMLAnchorElement.prototype, 'href', rw);
  hook(window.HTMLAreaElement   && HTMLAreaElement.prototype,   'href', rw);
  hook(window.HTMLLinkElement   && HTMLLinkElement.prototype,   'href', rw);
  hook(window.HTMLImageElement  && HTMLImageElement.prototype,  'src',  rw);
  hook(window.HTMLImageElement  && HTMLImageElement.prototype,  'srcset', rwSrcset);
  hook(window.HTMLScriptElement && HTMLScriptElement.prototype, 'src',  rw);
  hook(window.HTMLIFrameElement && HTMLIFrameElement.prototype, 'src',  rw);
  hook(window.HTMLEmbedElement  && HTMLEmbedElement.prototype,  'src',  rw);
  hook(window.HTMLSourceElement && HTMLSourceElement.prototype, 'src',  rw);
  hook(window.HTMLSourceElement && HTMLSourceElement.prototype, 'srcset', rwSrcset);
  hook(window.HTMLVideoElement  && HTMLVideoElement.prototype,  'src',  rw);
  hook(window.HTMLVideoElement  && HTMLVideoElement.prototype,  'poster', rw);
  hook(window.HTMLAudioElement  && HTMLAudioElement.prototype,  'src',  rw);
  hook(window.HTMLTrackElement  && HTMLTrackElement.prototype,  'src',  rw);
  hook(window.HTMLObjectElement && HTMLObjectElement.prototype,'data', rw);
  hook(window.HTMLFormElement   && HTMLFormElement.prototype,  'action', rw);

  var ATTRS = {
    SCRIPT: ['src'], IMG: ['src','srcset'], IFRAME: ['src'], EMBED: ['src'],
    SOURCE: ['src','srcset'], VIDEO: ['src','poster'], AUDIO: ['src'],
    TRACK: ['src'], LINK: ['href'], A: ['href'], AREA: ['href'],
    OBJECT: ['data'], FORM: ['action']
  };

  var _setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      var a = ATTRS[this.tagName];
      var ln = String(name).toLowerCase();
      if (a && a.indexOf(ln) !== -1) value = (ln === 'srcset') ? rwSrcset(value) : rw(value);
    } catch (e) {}
    return _setAttr.call(this, name, value);
  };

  function fixNode(node) {
    try {
      if (!node || node.nodeType !== 1) return;
      var a = ATTRS[node.tagName];
      if (a) {
        for (var i = 0; i < a.length; i++) {
          var attr = a[i];
          var v = node.getAttribute && node.getAttribute(attr);
          if (!v) continue;
          var nv = (attr === 'srcset') ? rwSrcset(v) : rw(v);
          if (nv !== v) _setAttr.call(node, attr, nv);
        }
      }
      var kids = node.children;
      if (kids) for (var j = 0; j < kids.length; j++) fixNode(kids[j]);
    } catch (e) {}
  }

  var _ac = Node.prototype.appendChild;
  Node.prototype.appendChild = function (c) { try { fixNode(c); } catch (e) {} return _ac.call(this, c); };
  var _ib = Node.prototype.insertBefore;
  Node.prototype.insertBefore = function (c, r) { try { fixNode(c); } catch (e) {} return _ib.call(this, c, r); };

  function rewriteFragment(html) {
    if (!html || typeof html !== 'string' || html.length > 500000) return html;
    try {
      return html
        .replace(/\b(src|href|action|poster|data)\s*=\s*(["'])([^"']+)\2/gi, function (m, at, q, u) {
          if (/^(data:|javascript:|mailto:|tel:|blob:|about:|#)/i.test(u)) return m;
          return at + '=' + q + rw(u) + q;
        })
        .replace(/\b(srcset|data-srcset)\s*=\s*(["'])([^"']+)\2/gi, function (m, at, q, ss) {
          return at + '=' + q + rwSrcset(ss) + q;
        });
    } catch (e) { return html; }
  }

  var _iah = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (pos, html) {
    try { html = rewriteFragment(html); } catch (e) {}
    return _iah.call(this, pos, html);
  };

  try {
    var _inner = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (_inner && _inner.set) Object.defineProperty(Element.prototype, 'innerHTML', {
      get: _inner.get,
      set: function (h) { try { h = rewriteFragment(h); } catch (e) {} return _inner.set.call(this, h); },
      configurable: true, enumerable: _inner.enumerable
    });
  } catch (e) {}

  try {
    var _outer = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (_outer && _outer.set) Object.defineProperty(Element.prototype, 'outerHTML', {
      get: _outer.get,
      set: function (h) { try { h = rewriteFragment(h); } catch (e) {} return _outer.set.call(this, h); },
      configurable: true, enumerable: _outer.enumerable
    });
  } catch (e) {}

  try {
    var _dw = document.write, _dwl = document.writeln;
    document.write = function (h) { try { h = rewriteFragment(h); } catch (e) {} return _dw.call(document, h); };
    document.writeln = function (h) { try { h = rewriteFragment(h); } catch (e) {} return _dwl.call(document, h); };
  } catch (e) {}

  try {
    var _ccf = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function (html) {
      try { html = rewriteFragment(html); } catch (e) {}
      return _ccf.call(this, html);
    };
  } catch (e) {}

  try {
    var _create = Document.prototype.createElement;
    Document.prototype.createElement = function (tag, opts) {
      var el = _create.call(this, tag, opts);
      try { fixNode(el); } catch (e) {}
      return el;
    };
    var _createNS = Document.prototype.createElementNS;
    Document.prototype.createElementNS = function (ns, tag, opts) {
      var el = _createNS.call(this, ns, tag, opts);
      try { fixNode(el); } catch (e) {}
      return el;
    };
  } catch (e) {}

  /* ---------- base tag neutralisation ---------- */
  function neutralizeBase() {
    try {
      var bases = document.querySelectorAll('base[href]');
      for (var i = 0; i < bases.length; i++) {
        var b = bases[i];
        var orig = b.getAttribute('href');
        if (orig && !b.hasAttribute('data-lynk-base-href')) b.setAttribute('data-lynk-base-href', orig);
        b.setAttribute('href', ORIGIN + '/');
      }
    } catch (e) {}
  }

  /* ---------- MutationObserver ---------- */
  try {
    var _obs = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'attributes') {
          try {
            var lname = String(m.attributeName).toLowerCase();
            if (m.target.tagName === 'BASE') { neutralizeBase(); continue; }
            var a = ATTRS[m.target.tagName];
            if (a && a.indexOf(lname) !== -1) {
              var v = m.target.getAttribute(m.attributeName);
              if (!v) continue;
              var nv = (lname === 'srcset') ? rwSrcset(v) : rw(v);
              if (nv !== v) _setAttr.call(m.target, m.attributeName, nv);
            }
          } catch (e) {}
        } else if (m.type === 'childList') {
          for (var j = 0; j < m.addedNodes.length; j++) {
            var nd = m.addedNodes[j];
            if (nd && nd.nodeType === 1 && nd.tagName === 'BASE') { neutralizeBase(); continue; }
            fixNode(nd);
          }
        }
      }
    });
    _obs.observe(document.documentElement, {
      subtree: true, childList: true, attributes: true,
      attributeFilter: ['src','href','srcset','data-src','data-srcset','action','poster','data']
    });
  } catch (e) {}

  /* ---------- history ---------- */
  try {
    var _ps = history.pushState;
    history.pushState = function (s, t, url) {
      try { if (url != null) post('push-state', { upstreamUrl: new URL(url, UP.href).href }); } catch (e) {}
      return _ps.apply(this, arguments);
    };
    var _rs = history.replaceState;
    history.replaceState = function (s, t, url) {
      try { if (url != null) post('push-state', { upstreamUrl: new URL(url, UP.href).href }); } catch (e) {}
      return _rs.apply(this, arguments);
    };
  } catch (e) {}

  try {
    var _wo = window.open;
    window.open = function (url, name, features) {
      try { if (typeof url === 'string' && url) url = rw(url); } catch (e) {}
      return _wo.call(this, url, name, features);
    };
  } catch (e) {}

  /* ---------- clone: re-execute captured inline scripts ---------- */
  function reexecInlineScripts() {
    var nodes = document.querySelectorAll('script[data-lynk-exec]');
    for (var i = 0; i < nodes.length; i++) {
      var s = nodes[i];
      if (s.__lynkRan) continue;
      s.__lynkRan = true;
      try {
        var el = document.createElement('script');
        for (var k = 0; k < s.attributes.length; k++) {
          var at = s.attributes[k];
          if (at.name === 'data-lynk-exec') continue;
          el.setAttribute(at.name, at.value);
        }
        if (!el.type) el.type = 'text/javascript';
        el.textContent = s.textContent || '';
        (s.parentNode || document.head).appendChild(el);
      } catch (e) {}
    }
  }

  /* ---------- boot ---------- */
  function scanAll() {
    neutralizeBase();
    fixNode(document.documentElement);
    reexecInlineScripts();
  }

  function boot() {
    scanAll();
    if (isClone && window.__LYNK_HYDRATED__ && typeof window.__LYNK_HYDRATED__.then === 'function') {
      window.__LYNK_HYDRATED__.then(scanAll).catch(function () {});
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }

  window.__LYNK_REWRITE__ = {
    isClone: isClone,
    upstream: UP_STR,
    rw: rw,
    shouldProxy: shouldProxy,
    scanAll: scanAll,
    reexecInlineScripts: reexecInlineScripts
  };
})();
