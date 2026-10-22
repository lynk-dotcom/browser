/* Lynkio interceptor — injected into every proxied page.
   Rewrites URLs at the property level, bridges console / errors / network
   to the shell, tunnels WebSocket and EventSource through the proxy.
   Never touches captcha / challenge hosts (they verify origin).

   v18.2: unchanged. The cloner captures this script tag as part of the
   DOM snapshot, so clones inherit URL rewriting automatically. */
(function(){
if (window.__LYNK_ICPT__) return;
window.__LYNK_ICPT__ = true;

var ctx = window.__LYNK_CTX__ || {};
if (!ctx.upstream) return;
var UP = (function(){ try { return new URL(ctx.upstream); } catch(e){ return null; } })();
if (!UP) return;

var ORIGIN = location.origin;
var PROXY  = ORIGIN + '/proxy';
var WS_TUN = ORIGIN.replace(/^http/, 'ws') + '/__lynk_ws';

var CAPTCHA_HOSTS = [
  'google.com/recaptcha/',
  'recaptcha.net/recaptcha/',
  'gstatic.com/recaptcha/',
  'hcaptcha.com/',
  'newassets.hcaptcha.com/',
  'challenges.cloudflare.com/',
  'turnstile.com/',
  'cloudflare.com/cdn-cgi/challenge-platform/',
  'arkoselabs.com/',
  'funcaptcha.com/',
  'captcha.awswaf.com/',
  'awswaf.com/captcha/',
];
function isCaptchaURL(u){
  try {
    var s = String(u).toLowerCase();
    for (var i = 0; i < CAPTCHA_HOSTS.length; i++){
      if (s.indexOf(CAPTCHA_HOSTS[i]) !== -1) return true;
    }
  } catch(e){}
  return false;
}

function post(type, payload){
  try {
    if (!window.parent || window.parent === window) return;
    var msg = Object.assign({ type: 'lynk:' + type, url: location.href }, payload || {});
    window.parent.postMessage(msg, '*');
  } catch(e){}
}
window.addEventListener('beforeunload', function(){ post('nav-start'); });
window.addEventListener('pagehide',     function(){ post('nav-start'); });
window.addEventListener('load',         function(){ post('nav-loaded', { title: document.title }); });
if (document.readyState === 'complete') post('nav-loaded', { title: document.title });

document.addEventListener('click', function(e){
  try {
    var a = e.target && e.target.closest && e.target.closest('a[href]');
    if (!a) return;
    if (a.target && a.target !== '' && a.target !== '_self') return;
    var h = a.getAttribute('href');
    if (!h || h.charAt(0) === '#' || /^javascript:/i.test(h)) return;
    post('nav-start', { target: rw(h) });
  } catch(err){}
}, true);
document.addEventListener('submit', function(){ post('nav-start'); }, true);

['log','info','warn','error','debug'].forEach(function(level){
  var orig = console[level];
  if (!orig) return;
  console[level] = function(){
    try {
      var args = Array.prototype.slice.call(arguments).map(function(a){
        if (typeof a === 'string') return a;
        if (a instanceof Error)    return a.message + (a.stack ? '\n' + a.stack : '');
        try { return JSON.stringify(a); } catch(e){ return String(a); }
      });
      post('console', { level: level, args: args });
    } catch(e){}
    try { return orig.apply(console, arguments); } catch(e){}
  };
});
window.addEventListener('error', function(e){
  post('error', {
    message: e.message || String(e.error || 'Error'),
    source:  e.filename,
    line:    e.lineno,
    col:     e.colno,
    stack:   e.error && e.error.stack,
  });
});
window.addEventListener('unhandledrejection', function(e){
  var r = e.reason || {};
  post('error', {
    message: 'Unhandled rejection: ' + (r.message || String(r)),
    stack:   r.stack,
  });
});

function isLocal(s){
  if (!s) return false;
  if (s.indexOf(ORIGIN) === 0){
    var r = s.slice(ORIGIN.length);
    return r.indexOf('/proxy') === 0 || r.indexOf('/__lynk_') === 0
        || r.indexOf('/lynkio/') === 0 || r.indexOf('/static/') === 0
        || r.indexOf('/tool/') === 0 || r.indexOf('/tabs') === 0
        || r.indexOf('/clone/') === 0 || r.indexOf('/clones') === 0
        || r === '/' || r === '';
  }
  if (s.charAt(0) === '/'){
    return s.indexOf('/proxy') === 0 || s.indexOf('/__lynk_') === 0
        || s.indexOf('/lynkio/') === 0 || s.indexOf('/static/') === 0
        || s.indexOf('/tool/') === 0 || s.indexOf('/tabs') === 0
        || s.indexOf('/clone/') === 0 || s.indexOf('/clones') === 0;
  }
  return false;
}
function rw(u){
  try {
    if (u == null || u === '') return u;
    var s = String(u);
    if (s.charAt(0) === '#') return u;
    if (/^(data|blob|javascript|about|mailto|tel|chrome|chrome-extension|file|ws:|wss:)/i.test(s)) return u;
    if (s.length > 16384) return u;
    if (isCaptchaURL(s)) return s;
    if (isLocal(s)) return u;
    if (s.indexOf('//') === 0) return PROXY + '?url=' + encodeURIComponent(UP.protocol + s);
    if (/^https?:\/\//i.test(s)) return PROXY + '?url=' + encodeURIComponent(s);
    if (s.indexOf(ORIGIN) === 0){
      var rest = s.slice(ORIGIN.length);
      if (rest.charAt(0) !== '/') return u;
      if (rest === '/' || rest === '') return u;
      try {
        var u2 = new URL(rest, UP.href);
        if (isCaptchaURL(u2.href)) return u2.href;
        return PROXY + '?url=' + encodeURIComponent(u2.href);
      } catch(e){ return u; }
    }
    try {
      var abs = new URL(s, UP.href);
      if (isCaptchaURL(abs.href)) return abs.href;
      if (abs.protocol === 'http:' || abs.protocol === 'https:')
        return PROXY + '?url=' + encodeURIComponent(abs.href);
    } catch(e){}
    return u;
  } catch(e){ return u; }
}
window.__LYNK_RW__ = rw;

function rwSrcset(s){
  if (!s || typeof s !== 'string') return s;
  try {
    return s.split(',').map(function(entry){
      var t = entry.trim(); if (!t) return entry;
      var parts = t.split(/\s+/); if (!parts[0]) return entry;
      parts[0] = rw(parts[0]);
      return parts.join(' ');
    }).join(', ');
  } catch(e){ return s; }
}

/* ---------- fetch / XHR ----------
   IMPORTANT: do not attempt to clone Requests that have a stream body —
   `new Request(url, originalRequest)` throws "ReadableStream uploading is
   not supported" in Chrome.  Only rewrite the URL for requests without a
   body, or for string/URL inputs. */
var _fetch = window.fetch;
if (_fetch){
  window.fetch = function(input, init){
    var urlForLog;
    try { urlForLog = typeof input === 'string' ? input : (input && input.url); } catch(e){}
    try {
      if (typeof input === 'string'){
        input = rw(input);
      } else if (input instanceof URL){
        input = rw(input.href);
      } else if (input instanceof Request){
        // Only safe to rewrap when the body is null (GET/HEAD or empty POST).
        if (input.body === null){
          var nu = rw(input.url);
          if (nu !== input.url) input = new Request(nu, input);
        }
      }
    } catch(e){}
    var p = _fetch.apply(this, arguments);
    return p.then(function(r){
      try {
        if (!r.ok) post('network', {
          method: (init && init.method) || 'GET',
          url: urlForLog, status: r.status
        });
      } catch(e){}
      return r;
    }).catch(function(err){
      try { post('network', {
        method: (init && init.method) || 'GET',
        url: urlForLog, error: (err && err.message) || String(err)
      }); } catch(e){}
      throw err;
    });
  };
}
var _xhrOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(m, u){
  try {
    var self = this;
    self.addEventListener('error', function(){
      post('network', { method: m, url: u, error: 'XHR error' });
    });
    self.addEventListener('load', function(){
      if (self.status >= 400) post('network', { method: m, url: u, status: self.status });
    });
  } catch(e){}
  try { arguments[1] = rw(u); } catch(e){}
  return _xhrOpen.apply(this, arguments);
};

var _WS = window.WebSocket;
window.WebSocket = function(url, protocols){
  try {
    if (typeof url === 'string' && !isLocal(url)){
      var abs = new URL(url, UP.href);
      var scheme = abs.protocol === 'wss:' ? 'wss:' : 'ws:';
      var upstream = scheme + '//' + abs.host + abs.pathname + abs.search;
      var tun = WS_TUN + '?__lynk_ws=' + encodeURIComponent(upstream);
      return protocols ? new _WS(tun, protocols) : new _WS(tun);
    }
  } catch(e){}
  return protocols ? new _WS(url, protocols) : new _WS(url);
};
window.WebSocket.prototype = _WS.prototype;
['CONNECTING','OPEN','CLOSING','CLOSED'].forEach(function(k){
  window.WebSocket[k] = _WS[k];
});

var _ES = window.EventSource;
if (_ES){
  window.EventSource = function(url, opts){
    try { url = rw(url); } catch(e){}
    return opts ? new _ES(url, opts) : new _ES(url);
  };
  window.EventSource.prototype = _ES.prototype;
}

if (navigator.sendBeacon){
  var _sb = navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon = function(u, d){
    try { u = rw(u); } catch(e){}
    return _sb(u, d);
  };
}

function hook(proto, prop, xform){
  if (!proto) return;
  try {
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set || d.__lynkPatched) return;
    var nd = {
      get: d.get,
      set: function(v){ try { v = xform.call(this, v); } catch(e){} return d.set.call(this, v); },
      configurable: true, enumerable: d.enumerable,
    };
    nd.__lynkPatched = true;
    Object.defineProperty(proto, prop, nd);
  } catch(e){}
}
hook(window.HTMLAnchorElement  && HTMLAnchorElement.prototype,  'href',   rw);
hook(window.HTMLAreaElement    && HTMLAreaElement.prototype,    'href',   rw);
hook(window.HTMLLinkElement    && HTMLLinkElement.prototype,    'href',   rw);
hook(window.HTMLImageElement   && HTMLImageElement.prototype,   'src',    rw);
hook(window.HTMLImageElement   && HTMLImageElement.prototype,   'srcset', rwSrcset);
hook(window.HTMLScriptElement  && HTMLScriptElement.prototype,  'src',    rw);
hook(window.HTMLIFrameElement  && HTMLIFrameElement.prototype,  'src',    rw);
hook(window.HTMLEmbedElement   && HTMLEmbedElement.prototype,   'src',    rw);
hook(window.HTMLSourceElement  && HTMLSourceElement.prototype,  'src',    rw);
hook(window.HTMLSourceElement  && HTMLSourceElement.prototype,  'srcset', rwSrcset);
hook(window.HTMLVideoElement   && HTMLVideoElement.prototype,   'src',    rw);
hook(window.HTMLVideoElement   && HTMLVideoElement.prototype,   'poster', rw);
hook(window.HTMLAudioElement   && HTMLAudioElement.prototype,   'src',    rw);
hook(window.HTMLTrackElement   && HTMLTrackElement.prototype,   'src',    rw);
hook(window.HTMLObjectElement  && HTMLObjectElement.prototype,  'data',   rw);
hook(window.HTMLFormElement    && HTMLFormElement.prototype,    'action', rw);

var ATTRS = {
  SCRIPT:['src'], IMG:['src','srcset'], IFRAME:['src'], EMBED:['src'],
  SOURCE:['src','srcset'], VIDEO:['src','poster'], AUDIO:['src'],
  TRACK:['src'], LINK:['href'], A:['href'], AREA:['href'],
  OBJECT:['data'], FORM:['action'],
};
var _setAttr = Element.prototype.setAttribute;
Element.prototype.setAttribute = function(name, value){
  try {
    var a = ATTRS[this.tagName];
    var ln = String(name).toLowerCase();
    if (a && a.indexOf(ln) !== -1){
      value = (ln === 'srcset') ? rwSrcset(value) : rw(value);
    }
  } catch(e){}
  return _setAttr.call(this, name, value);
};

function fixNode(node){
  try {
    if (!node || node.nodeType !== 1) return;
    var a = ATTRS[node.tagName];
    if (a){
      for (var i = 0; i < a.length; i++){
        var attr = a[i];
        var v = node.getAttribute && node.getAttribute(attr);
        if (!v) continue;
        var nv = (attr === 'srcset') ? rwSrcset(v) : rw(v);
        if (nv !== v) _setAttr.call(node, attr, nv);
      }
    }
    var kids = node.children;
    if (kids) for (var j = 0; j < kids.length; j++) fixNode(kids[j]);
  } catch(e){}
}
var _ac = Node.prototype.appendChild;
Node.prototype.appendChild = function(c){ try { fixNode(c); } catch(e){} return _ac.call(this, c); };
var _ib = Node.prototype.insertBefore;
Node.prototype.insertBefore = function(c, r){ try { fixNode(c); } catch(e){} return _ib.call(this, c, r); };

function rewriteFragment(html){
  if (!html || typeof html !== 'string' || html.length > 500000) return html;
  try {
    return html
      .replace(/\b(src|href|action|poster|data)\s*=\s*(["'])([^"']+)\2/gi,
        function(m, at, q, u){
          if (/^(data:|javascript:|mailto:|tel:|blob:|about:|#)/i.test(u)) return m;
          return at + '=' + q + rw(u) + q;
        })
      .replace(/\b(srcset|data-srcset)\s*=\s*(["'])([^"']+)\2/gi,
        function(m, at, q, ss){ return at + '=' + q + rwSrcset(ss) + q; });
  } catch(e){ return html; }
}
var _iah = Element.prototype.insertAdjacentHTML;
Element.prototype.insertAdjacentHTML = function(pos, html){
  try { html = rewriteFragment(html); } catch(e){}
  return _iah.call(this, pos, html);
};
try {
  var _inner = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (_inner && _inner.set){
    Object.defineProperty(Element.prototype, 'innerHTML', {
      get: _inner.get,
      set: function(h){ try { h = rewriteFragment(h); } catch(e){} return _inner.set.call(this, h); },
      configurable: true, enumerable: _inner.enumerable,
    });
  }
} catch(e){}
try {
  var _outer = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (_outer && _outer.set){
    Object.defineProperty(Element.prototype, 'outerHTML', {
      get: _outer.get,
      set: function(h){ try { h = rewriteFragment(h); } catch(e){} return _outer.set.call(this, h); },
      configurable: true, enumerable: _outer.enumerable,
    });
  }
} catch(e){}
try {
  var _dw  = document.write;
  var _dwl = document.writeln;
  document.write   = function(h){ try { h = rewriteFragment(h); } catch(e){} return _dw.call(document, h); };
  document.writeln = function(h){ try { h = rewriteFragment(h); } catch(e){} return _dwl.call(document, h); };
} catch(e){}
try {
  var _ccf = Range.prototype.createContextualFragment;
  Range.prototype.createContextualFragment = function(html){
    try { html = rewriteFragment(html); } catch(e){}
    return _ccf.call(this, html);
  };
} catch(e){}

try {
  var _create = Document.prototype.createElement;
  Document.prototype.createElement = function(tag, opts){
    var el = _create.call(this, tag, opts);
    try { fixNode(el); } catch(e){}
    return el;
  };
  var _createNS = Document.prototype.createElementNS;
  Document.prototype.createElementNS = function(ns, tag, opts){
    var el = _createNS.call(this, ns, tag, opts);
    try { fixNode(el); } catch(e){}
    return el;
  };
} catch(e){}

try {
  var _obs = new MutationObserver(function(muts){
    for (var i = 0; i < muts.length; i++){
      var m = muts[i];
      if (m.type === 'attributes'){
        try {
          var lname = String(m.attributeName).toLowerCase();
          var a = ATTRS[m.target.tagName];
          if (a && a.indexOf(lname) !== -1){
            var v = m.target.getAttribute(m.attributeName);
            if (!v) continue;
            var nv = (lname === 'srcset') ? rwSrcset(v) : rw(v);
            if (nv !== v) _setAttr.call(m.target, m.attributeName, nv);
          }
        } catch(e){}
      } else if (m.type === 'childList'){
        for (var j = 0; j < m.addedNodes.length; j++) fixNode(m.addedNodes[j]);
      }
    }
  });
  _obs.observe(document.documentElement, {
    subtree: true, childList: true, attributes: true,
    attributeFilter: ['src','href','srcset','data-src','data-srcset',
                      'action','poster','data'],
  });
} catch(e){}

try {
  var _ps = history.pushState;
  history.pushState = function(s, t, url){
    try { if (url != null) post('push-state', { upstreamUrl: new URL(url, UP.href).href }); } catch(e){}
    return _ps.apply(this, arguments);
  };
  var _rs = history.replaceState;
  history.replaceState = function(s, t, url){
    try { if (url != null) post('push-state', { upstreamUrl: new URL(url, UP.href).href }); } catch(e){}
    return _rs.apply(this, arguments);
  };
} catch(e){}
try {
  var _wo = window.open;
  window.open = function(url, name, features){
    try { if (typeof url === 'string' && url) url = rw(url); } catch(e){}
    return _wo.call(this, url, name, features);
  };
} catch(e){}
})();
