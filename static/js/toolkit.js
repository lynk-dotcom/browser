/* Lynkio toolkit — all tools (vulnerability scanner, agent, recon, osint,
   web, injection, http, cms, auth & cookies, enumeration, shell & takeover,
   captcha, encode, payloads, cloner, customize). Mobile-first.

   v18.3: My Clones adds a "Copy URL" button so a clone can be shared to any
   browser. */
(function(){
"use strict";
if (window.__LYNK_TOOLKIT__) return;
window.__LYNK_TOOLKIT__ = true;
var L = window.__LYNK__; if (!L) return;
var UI = window.__LYNK_UI__;
if (!UI) return;
var esc = UI.esc;
var $ = L.kitBody;

/* ============================================================
   Helpers
   ============================================================ */
function row(k, v){
  return '<div class="result-kv"><span class="k">'+esc(k)+'</span>'
    + '<span class="v">'+esc(v)+'</span></div>';
}
function msg(k, t){ return UI.msg(k, t); }
function prettySize(n){ return UI.prettySize(n); }
function extOf(name){
  var m = String(name||'').match(/\.([A-Za-z0-9]+)$/);
  return m ? m[1].toLowerCase() : '';
}
function iconFor(name, kind){
  if (kind === 'dir') return '📁';
  var e = extOf(name);
  if (['html','htm'].indexOf(e) > -1) return '🌐';
  if (['js','mjs','ts'].indexOf(e) > -1) return '📜';
  if (['css','scss','sass'].indexOf(e) > -1) return '🎨';
  if (['json','map'].indexOf(e) > -1) return '🧩';
  if (['xml','rss','atom'].indexOf(e) > -1) return '📰';
  if (['jpg','jpeg','png','gif','webp','svg','ico','bmp'].indexOf(e) > -1) return '🖼';
  if (['mp4','webm','mov','avi','mkv'].indexOf(e) > -1) return '🎬';
  if (['mp3','wav','ogg','flac','m4a'].indexOf(e) > -1) return '🎵';
  if (['zip','tar','gz','rar','7z','bz2'].indexOf(e) > -1) return '🗜';
  if (e === 'pdf') return '📕';
  if (['doc','docx'].indexOf(e) > -1) return '📘';
  if (['xls','xlsx','csv'].indexOf(e) > -1) return '📗';
  if (['sh','bash','zsh','fish'].indexOf(e) > -1) return '⚙️';
  if (['env','ini','conf','cfg','toml','yml','yaml'].indexOf(e) > -1) return '⚙️';
  return '🔗';
}
async function api(p, o){
  return fetch(p, Object.assign({credentials:'same-origin'}, o||{}));
}
async function apiJ(p){
  var r = await api(p);
  var t = await r.text();
  try { return JSON.parse(t); } catch(e){ return { error: t || ('HTTP ' + r.status) }; }
}
async function post(p, d){
  var r = await api(p, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(d || {}),
  });
  var t = await r.text();
  try { return JSON.parse(t); } catch(e){ return { error: t || ('HTTP ' + r.status) }; }
}

/* ============================================================
   Registry
   ============================================================ */
var CATEGORIES = [
  {id:'vuln',      name:'🛡️ Vulnerability Scanner'},
  {id:'agent',     name:'🤖 Agent'},
  {id:'recon',     name:'🔎 Recon'},
  {id:'osint',     name:'🕵️ OSINT'},
  {id:'web',       name:'🌍 Web Security'},
  {id:'inject',    name:'💥 Injection'},
  {id:'http',      name:'🚢 HTTP Deep'},
  {id:'cms',       name:'📦 CMS'},
  {id:'auth',      name:'🔐 Auth & Cookies'},
  {id:'enum',      name:'🔬 Enumeration'},
  {id:'shell',     name:'🐚 Shell & Takeover'},
  {id:'captcha',   name:'🤖 Captcha'},
  {id:'encode',    name:'🔤 Encode'},
  {id:'payloads',  name:'📜 Payloads'},
  {id:'cloner',    name:'⎘ Cloner'},
  {id:'customize', name:'🎨 Customize'},
];
var TOOLS = {};
function reg(cat, t){ t.category = cat; TOOLS[t.id] = t; }

/* ============================================================
   VULN
   ============================================================ */
reg('vuln', {
  id:'vulnscan', icon:'🛡️', name:'Full Vulnerability Scan',
  description:'400+ checks: headers, cookies, HTML, JS libs, sensitive paths, HTTP methods, CORS.',
  fields: [
    {name:'url', label:'URL', default:''},
    {name:'active', label:'Active probes', type:'select', options:['1','0'], default:'1'},
  ],
  run: async function(i){
    var url = i.url || L.activeTabUrl();
    if (!url) throw new Error('no URL');
    var data = await post('/tool/vulnscan', {url: url, active: i.active||'1'});
    if (data.error) throw new Error(data.error);
    var f = data.findings || [];
    var counts = {critical:0, high:0, medium:0, low:0, info:0};
    f.forEach(function(x){ counts[x.severity] = (counts[x.severity]||0)+1; });
    var SC = {critical:'#dc2626', high:'#f87171', medium:'#f59e0b', low:'#38bdf8', info:'#64748b'};
    var SB = {critical:'rgba(220,38,38,.12)', high:'rgba(248,113,113,.12)',
              medium:'rgba(245,158,11,.12)', low:'rgba(56,189,248,.12)',
              info:'rgba(100,116,139,.12)'};
    var summary = Object.keys(counts).map(function(k){
      if (!counts[k]) return '';
      return '<div style="padding:12px 16px;background:'+SB[k]+';border-radius:11px;'
        + 'min-width:76px;text-align:center;flex:1 1 auto;">'
        + '<div style="font-size:22px;font-weight:800;color:'+SC[k]+';">'+counts[k]+'</div>'
        + '<div style="font-size:10.5px;color:#94a3b8;text-transform:uppercase;'
        + 'letter-spacing:.08em;font-weight:700;">'+k+'</div></div>';
    }).join('');
    var detail = f.map(function(x){
      return '<div style="padding:14px 16px;border-radius:11px;margin-bottom:8px;'
        + 'background:#070b16;border-left:3px solid '+SC[x.severity]+';">'
        + '<div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:6px;flex-wrap:wrap;">'
        + '<span style="font-size:10px;font-weight:700;padding:3px 9px;border-radius:5px;'
        + 'background:'+SB[x.severity]+';color:'+SC[x.severity]+';text-transform:uppercase;">'+x.severity+'</span>'
        + '<span style="flex:1;font-weight:600;font-size:13.5px;min-width:0;word-break:break-word;">'+esc(x.name)+'</span>'
        + '<span style="font-family:ui-monospace,monospace;font-size:10.5px;color:#64748b;">'+esc(x.id||'')+'</span>'
        + '</div>'
        + '<div style="color:#94a3b8;font-size:12.5px;line-height:1.6;margin-bottom:8px;">'+esc(x.description||'')+'</div>'
        + (x.evidence ? '<pre style="padding:10px 12px;background:rgba(2,6,23,.6);border-radius:7px;'
            + 'font-family:ui-monospace,monospace;font-size:11px;color:#94a3b8;'
            + 'white-space:pre-wrap;word-break:break-word;overflow:auto;margin:0 0 8px;">'
            + esc(x.evidence)+'</pre>' : '')
        + (x.remediation ? '<div style="font-size:12px;color:#38bdf8;line-height:1.55;'
            + 'padding-top:6px;border-top:1px dashed rgba(148,163,184,.15);">'
            + '<b>Fix:</b> '+esc(x.remediation)+'</div>' : '')
        + '</div>';
    }).join('');
    return {
      html: '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">'+summary+'</div>'
        + msg('info', 'Checks: '+(data.check_count||'?')+' · Target: '+esc(data.url||url))
        + (detail || msg('ok','No findings.')),
      raw: data,
      findings: f.map(function(x){
        return {severity:x.severity, cwe:x.cwe, title:x.name,
                desc:x.description, evidence:x.evidence,
                remediation:x.remediation, tabUrl: url};
      }),
    };
  }
});

/* ============================================================
   AGENT
   ============================================================ */
reg('agent', {
  id:'agent', icon:'🤖', name:'Run Agent',
  description:'Execute Python on the server (sandboxed) or JavaScript in the current page.',
  fields: [
    {name:'mode', label:'Mode', type:'select',
     options:['Python (server)','JavaScript (page)'], default:'Python (server)'},
    {name:'code', label:'Code', type:'textarea',
     default:'result = {"hello": "world"}'},
  ],
  run: async function(i){
    var code = i.code || '';
    if (!code.trim()) throw new Error('code required');
    var mode = i.mode || 'Python (server)';
    if (mode === 'JavaScript (page)'){
      try {
        var fn = new Function('LYNK', 'return (async () => { ' + code + ' })()');
        var res = await fn(L);
        var out = (typeof res === 'string') ? res : JSON.stringify(res, null, 2);
        return { html: '<pre class="result-pre">' + esc(out) + '</pre>',
                 raw: { ok: true, result: res } };
      } catch(e){
        return { html: msg('err', 'Error: ' + e.message),
                 raw: { ok: false, error: e.message } };
      }
    }
    var d = await post('/tool/agent-run', {code: code, url: L.activeTabUrl()});
    if (!d.ok){
      return { html: msg('err', d.error || 'failed'), raw: d };
    }
    var rendered;
    if (typeof d.result === 'string') rendered = d.result;
    else { try { rendered = JSON.stringify(d.result, null, 2); } catch(e){ rendered = String(d.result); } }
    return { html: '<pre class="result-pre">' + esc(rendered) + '</pre>', raw: d };
  }
});

/* ============================================================
   RECON
   ============================================================ */
reg('recon', {id:'headers', icon:'📡', name:'Response Headers',
  description:'Full header dump', fields:[],
  run: async function(){
    var d = await apiJ('/tool/headers?url=' + encodeURIComponent(L.activeTabUrl()));
    if (d.status === 0) throw new Error((d.headers||{}).error || 'failed');
    var h = row('Status', d.status);
    Object.keys(d.headers).forEach(function(k){ h += row(k, d.headers[k]); });
    return { html: h, raw: d };
  }});

reg('recon', {id:'source', icon:'📄', name:'Page Source',
  description:'Raw HTML of current tab', fields:[],
  run: async function(){
    var url = L.activeTabUrl();
    UI.fileViewer(url, 'Source · ' + url);
    return { html: msg('info','Viewer opened'), raw: {} };
  }});

reg('recon', {id:'dns', icon:'🌍', name:'DNS / IP',
  description:'Resolve current host', fields:[],
  run: async function(){
    var d = await apiJ('/tool/dns?url=' + encodeURIComponent(L.activeTabUrl()));
    var h = row('Host', d.host);
    if (!d.addresses.length) return { html: h + msg('warn','No addresses'), raw: d };
    d.addresses.forEach(function(a){ h += row('→', a); });
    return { html: h, raw: d };
  }});

reg('recon', {id:'diag', icon:'🩺', name:'Diagnose',
  description:'DNS + TCP + TLS breakdown', fields:[],
  run: async function(){
    var d = await apiJ('/tool/diag?url=' + encodeURIComponent(L.activeTabUrl()));
    var out = row('Host', (d.host||'') + ':' + (d.port||''));
    function arr(l, a){ if (!a || !a.length) return; out += row(l, a.join(', ')); }
    arr('System v4', d.system_dns_v4); arr('System v6', d.system_dns_v6);
    arr('DoH v4', d.doh_ipv4);
    (d.connect_tests||[]).forEach(function(t){
      out += row((t.ok?'OK ':'FAIL ') + t.ip, t.ok ? (t.latency_ms+'ms') : (t.error||''));
    });
    return { html: out, raw: d };
  }});

reg('recon', {id:'history', icon:'🕘', name:'History',
  description:'Recent requests', fields:[],
  run: async function(){
    var d = await apiJ('/tool/history');
    if (!d.entries || !d.entries.length) return { html: msg('info','No history yet.'), raw: d };
    return { html: d.entries.map(function(x){
      return '<div class="result-list-item" data-open-url="'+esc(x.url)+'">'
        + '<span style="color:#64748b;min-width:36px;">'+x.status+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(x.url)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('recon', {id:'subdomains', icon:'🌐', name:'Subdomain Enum',
  description:'Certificate Transparency', fields:[
    {name:'domain', label:'Domain', default:''}],
  run: async function(i){
    var d = await post('/tool/subdomains', {domain: i.domain || L.activeTabHost()});
    if (d.error) throw new Error(d.error);
    var list = (d.subdomains || []);
    if (!list.length) return { html: msg('info','No subdomains.'), raw: d };
    return { html: row('Count', list.length) + list.map(function(s){
      return '<div class="result-list-item" data-open-url="https://'+esc(s)+'">'
        + '<span style="flex:1;word-break:break-all;">'+esc(s)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('recon', {id:'portscan', icon:'📡', name:'Port Scan',
  description:'Common TCP ports', fields:[
    {name:'host', label:'Host', default:''}],
  run: async function(i){
    var d = await post('/tool/portscan', {host: i.host || L.activeTabHost()});
    if (d.error) throw new Error(d.error);
    var open = d.open || [];
    if (!open.length) return { html: msg('info','No open ports.'), raw: d };
    return { html: msg('info', open.length + ' open') + open.map(function(p){
      return row('OPEN', (d.host||'') + ':' + p.port + ' · ' + (p.service||''));
    }).join(''), raw: d };
  }});

reg('recon', {id:'ssltls', icon:'🔐', name:'SSL / TLS Info',
  description:'Certificate, cipher, ALPN, SANs', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/ssltls', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var html = '';
    Object.keys(d).forEach(function(k){
      var v = d[k];
      html += row(k, (typeof v === 'object') ? JSON.stringify(v) : String(v));
    });
    return { html: html, raw: d };
  }});

reg('recon', {id:'tlsaudit', icon:'🧪', name:'TLS Audit',
  description:'Protocol downgrade + weak ciphers', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/tls-audit', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var versions = (d.versions || []).map(function(v){
      return row(v.version, v.supported ? ('supported · ' + (v.cipher||'')) : (v.error||'no'));
    }).join('');
    var findings = (d.findings||[]).map(function(f){
      return '<div class="finding '+f.severity+'"><div class="finding-head">'
        + '<span class="sev '+f.severity+'">'+f.severity+'</span>'
        + '<span class="title">'+esc(f.name)+'</span></div>'
        + '<div class="finding-desc">'+esc(f.description)+'</div></div>';
    }).join('');
    return { html: versions + (findings || msg('ok','No weak protocols.')), raw: d,
             findings: (d.findings||[]).map(function(f){
               return {severity:f.severity, title:f.name, desc:f.description,
                       evidence:f.evidence, remediation:f.remediation,
                       tabUrl: i.url || L.activeTabUrl()};
             }) };
  }});

reg('recon', {id:'waf', icon:'🔥', name:'WAF Detect',
  description:'Signature probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/waf', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var det = (d.detected || []);
    var html = det.length ? msg('warn', 'Detected: ' + det.join(', ')) : msg('info', 'No WAF.');
    (d.probes||[]).forEach(function(p){
      html += row(p.label, p.error ? p.error : (p.status + (p.blocked ? ' · blocked' : '')));
    });
    return { html: html, raw: d };
  }});

reg('recon', {id:'wayback', icon:'🕰️', name:'Wayback Machine',
  description:'Archived snapshots', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/wayback', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var snaps = (d.snapshots || []);
    if (!snaps.length) return { html: msg('info','No snapshots.'), raw: d };
    return { html: snaps.map(function(s){
      return '<div class="result-list-item" data-open-url="'+esc(s.url)+'">'
        + '<span style="color:#64748b;font-family:ui-monospace,monospace;">'+esc(s.timestamp)+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(s.url)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('recon', {id:'favicon', icon:'🎨', name:'Favicon Hash',
  description:'Favicon fingerprint', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/favicon', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    return { html: Object.keys(d).map(function(k){ return row(k, d[k]); }).join(''), raw: d };
  }});

reg('recon', {id:'wellknown', icon:'📜', name:'Well-Known Probe',
  description:'.well-known URIs', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/well-known', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results || []).filter(function(x){ return x.status === 200; });
    if (!hits.length) return { html: msg('info','Nothing found.'), raw: d };
    return { html: hits.map(function(x){
      return '<div class="result-list-item" data-open-url="'+esc(x.url)+'">'
        + '<span class="badge">'+x.status+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(x.path)+'</span>'
        + '<span style="color:#64748b;">'+x.length+'B</span></div>';
    }).join(''), raw: d };
  }});

/* ============================================================
   OSINT
   ============================================================ */
reg('osint', {id:'harvester', icon:'🌾', name:'Harvester',
  description:'Emails + subdomains from page', fields:[],
  run: async function(){
    var url = L.activeTabUrl();
    var r = await api('/proxy?url=' + encodeURIComponent(url));
    var txt = await r.text();
    var emails = Array.from(new Set((txt.match(/[\w.+\-]+@[\w\-]+\.[\w.\-]+/g)||[])
      .filter(function(e){ return !/\.(png|jpg|gif|svg|css|js)$/i.test(e); })));
    var host = ''; try { host = new URL(url).hostname; } catch(e){}
    var subs = Array.from(new Set((txt.match(/https?:\/\/([\w\-]+\.)+[\w\-]+/g)||[])
      .map(function(u){ try { return new URL(u).hostname; } catch(e){ return null; } })
      .filter(function(h){ return h && host && h.endsWith(host); })));
    return { html: row('Emails', emails.slice(0,100).join(', ') || '(none)')
      + row('Subdomains', subs.slice(0,100).join(', ') || '(none)'),
      raw: { emails: emails, subdomains: subs } };
  }});

reg('osint', {id:'dork', icon:'🔍', name:'Dork Builder',
  description:'Google dorks', fields:[
    {name:'host', label:'Host', default:''}],
  run: async function(i){
    var h = i.host || L.activeTabHost();
    if (!h) throw new Error('host required');
    var dorks = [
      ['Login',       'site:' + h + ' inurl:login OR inurl:signin'],
      ['Config',      'site:' + h + ' ext:xml OR ext:conf OR ext:ini'],
      ['Backups',     'site:' + h + ' ext:bak OR ext:old OR ext:backup'],
      ['Dir listing', 'site:' + h + ' intitle:"index of"'],
      ['Swagger',     'site:' + h + ' inurl:swagger OR inurl:api-docs'],
      ['phpMyAdmin',  'site:' + h + ' inurl:phpmyadmin'],
      ['env',         'site:' + h + ' ext:env'],
      ['GitHub leaks','site:github.com "' + h + '" password OR secret'],
    ];
    return { html: dorks.map(function(d){
      var u = 'https://www.google.com/search?q=' + encodeURIComponent(d[1]);
      return '<div class="result-list-item" data-open-url="'+esc(u)+'">'
        + '<b style="color:#38bdf8;">'+esc(d[0])+'</b>'
        + '<span style="flex:1;color:#94a3b8;word-break:break-all;">'+esc(d[1])+'</span></div>';
    }).join(''), raw: { host: h, dorks: dorks } };
  }});

reg('osint', {id:'reverse_ip', icon:'🔁', name:'Reverse IP',
  description:'Domains sharing an IP', fields:[
    {name:'ip', label:'IP or host', default:''}],
  run: async function(i){
    var d = await post('/tool/reverse-ip', {ip: i.ip || L.activeTabHost()});
    if (d.error) throw new Error(d.error);
    var list = (d.domains || []);
    if (!list.length) return { html: msg('info','None for ' + d.ip), raw: d };
    return { html: msg('info', list.length + ' domains share ' + d.ip) + list.map(function(x){
      return '<div class="result-list-item"><span style="word-break:break-all;">'+esc(x)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('osint', {id:'email_verify', icon:'✉️', name:'Email Verifier',
  description:'Syntax + MX', fields:[{name:'email', label:'Email'}],
  run: async function(i){
    if (!i.email) throw new Error('email required');
    var ok = /^[\w.+\-]+@([\w\-]+\.)+[A-Za-z]{2,}$/.test(i.email);
    return { html: row('Syntax', ok ? 'valid' : 'invalid'), raw: { ok: ok } };
  }});

/* ============================================================
   WEB SECURITY
   ============================================================ */
reg('web', {id:'sec_headers', icon:'🛡️', name:'Security Headers',
  description:'Audit header presence', fields:[],
  run: async function(){
    var d = await apiJ('/tool/headers?url=' + encodeURIComponent(L.activeTabUrl()));
    var H = {}; Object.keys(d.headers||{}).forEach(function(k){ H[k.toLowerCase()] = d.headers[k]; });
    var checks = [
      ['strict-transport-security','HSTS'],
      ['content-security-policy','CSP'],
      ['x-frame-options','X-Frame-Options'],
      ['x-content-type-options','X-Content-Type-Options'],
      ['referrer-policy','Referrer-Policy'],
      ['permissions-policy','Permissions-Policy'],
    ];
    var out = '', findings = [];
    checks.forEach(function(c){
      var present = !!H[c[0]];
      out += '<div class="result-kv"><span class="k">'+esc(c[1])+'</span>'
        + '<span class="v" style="color:'+(present?'#10b981':'#f87171')+';">'
        + (present ? esc(String(H[c[0]]).slice(0,120)) : 'missing') + '</span></div>';
      if (!present) findings.push({severity:'medium', cwe:'CWE-693',
        title:'Missing ' + c[1], desc:c[1] + ' absent',
        evidence:c[0], tabUrl:L.activeTabUrl()});
    });
    return { html: out, findings: findings, raw: H };
  }});

reg('web', {id:'csp_analyzer', icon:'🔐', name:'CSP Analyzer',
  description:'Content-Security-Policy check', fields:[],
  run: async function(){
    var d = await apiJ('/tool/headers?url=' + encodeURIComponent(L.activeTabUrl()));
    var H = {}; Object.keys(d.headers||{}).forEach(function(k){ H[k.toLowerCase()] = d.headers[k]; });
    var csp = H['content-security-policy'] || '';
    if (!csp) return { html: msg('warn','No CSP header.'), raw: { csp: '' } };
    var findings = [];
    if (/'unsafe-inline'/.test(csp)){
      findings.push({severity:'high', cwe:'CWE-79', title:"CSP allows 'unsafe-inline'",
        desc:'Inline scripts run without nonce/hash.', evidence:csp.slice(0,300),
        remediation:'Use nonces or hashes.', tabUrl:L.activeTabUrl()});
    }
    if (/'unsafe-eval'/.test(csp)){
      findings.push({severity:'high', cwe:'CWE-95', title:"CSP allows 'unsafe-eval'",
        desc:'eval() and Function() are allowed.', evidence:csp.slice(0,300),
        remediation:'Remove unsafe-eval.', tabUrl:L.activeTabUrl()});
    }
    return { html: '<pre class="result-pre">' + esc(csp) + '</pre>',
             findings: findings, raw: { csp: csp } };
  }});

reg('web', {id:'cors', icon:'🌍', name:'CORS Audit',
  description:'Origin reflection probes', fields:[],
  run: async function(){
    var url = L.activeTabUrl();
    var out = '', findings = [];
    var origins = ['https://evil.example','null'];
    for (var i = 0; i < origins.length; i++){
      var o = origins[i];
      try {
        var r = await api('/proxy?url=' + encodeURIComponent(url),
                          {headers:{'Origin': o}});
        var acao = r.headers.get('access-control-allow-origin') || '';
        var acac = (r.headers.get('access-control-allow-credentials')||'').toLowerCase();
        out += row(o, 'ACAO: ' + (acao||'(none)') + ' · ACAC: ' + (acac||'(none)'));
        if ((acao === o || acao === '*') && acac === 'true'){
          findings.push({severity:'high', cwe:'CWE-942',
            title:'CORS misconfiguration: ' + o,
            desc:'Origin reflected with credentials.',
            evidence:'ACAO: '+acao+' / ACAC: '+acac, tabUrl: url});
        }
      } catch(e){}
    }
    return { html: out, findings: findings, raw: {} };
  }});

reg('web', {id:'cors_deep', icon:'🔓', name:'CORS Deep',
  description:'Multi-origin probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/cors-deep', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var probes = (d.probes || []).map(function(p){
      return row(p.origin, 'ACAO: ' + (p.acao||'(none)') + ' · ACAC: ' + (p.acac||'(none)'));
    }).join('');
    var findings = (d.findings||[]).map(function(f){
      return {severity:f.severity, cwe:'CWE-942', title:f.name,
              desc:'CORS misconfiguration', evidence:f.evidence,
              tabUrl: i.url || L.activeTabUrl()};
    });
    return { html: probes + (findings.length ? msg('warn', findings.length + ' findings') : msg('ok','None.')),
             findings: findings, raw: d };
  }});

reg('web', {id:'clickjack', icon:'🖱️', name:'Clickjacking',
  description:'Framing headers', fields:[],
  run: async function(){
    var d = await apiJ('/tool/headers?url=' + encodeURIComponent(L.activeTabUrl()));
    var H = {}; Object.keys(d.headers||{}).forEach(function(k){ H[k.toLowerCase()] = d.headers[k]; });
    var xfo = H['x-frame-options'] || '';
    var csp = H['content-security-policy'] || '';
    var fa = /frame-ancestors/i.test(csp);
    var safe = !!xfo || fa;
    return { html: row('X-Frame-Options', xfo||'(none)')
      + row('frame-ancestors', fa ? 'present' : 'absent'),
      findings: safe ? [] : [{severity:'medium', cwe:'CWE-1021',
        title:'Clickjacking possible',
        desc:'No framing protection.', evidence:'XFO: '+(xfo||'none'),
        remediation:'Add X-Frame-Options: DENY.',
        tabUrl:L.activeTabUrl()}],
      raw: H };
  }});

reg('web', {id:'hsts_audit', icon:'📮', name:'HSTS Audit',
  description:'HSTS strength + preload', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/hsts-audit', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    return { html: row('HSTS header', d.hsts_header || '(none)')
      + row('Present', d.present ? 'yes' : 'no')
      + row('includeSubDomains', d.has_include_subdomains ? 'yes' : 'no')
      + row('preload', d.has_preload ? 'yes' : 'no')
      + row('max-age', d.max_age || '(none)'), raw: d };
  }});

/* ============================================================
   INJECTION
   ============================================================ */
var PAYLOADS = {
  sqli:["'","''","' OR '1'='1","' OR 1=1--","1' AND 1=1--","') OR ('1'='1","' UNION SELECT NULL--"],
  nosqli:["' || '1'=='1",'{"$ne": null}','{"$gt": ""}','{"$where": "1==1"}'],
  xss:["<script>alert(1)</script>","<img src=x onerror=alert(1)>","'><svg onload=alert(1)>","\"><script>alert(1)</script>"],
  lfi:["../../../../etc/passwd","....//....//....//etc/passwd","/proc/self/environ"],
  rfi:["https://example.com/x.txt","//example.com/x.txt"],
  ssti:["{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","*{7*7}"],
  cmdi:[";id","|id","&&id","`id`","$(id)",";whoami"],
  xxe:['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
  ssrf:["http://127.0.0.1","http://169.254.169.254/","file:///etc/passwd"],
  crlf:["%0d%0aX-Injected:lynk","%0aX-Injected:lynk"],
  open_redirect:["//evil.example","https://evil.example","/\\evil.example"],
  host_header:["evil.example","127.0.0.1"],
  path_traversal:["..;/","..%2f","..%5c","%2e%2e/"],
  http_smuggling:["Transfer-Encoding: chunked","Transfer-Encoding : chunked"],
};
async function probeOnce(url, param, payload){
  try {
    var u = url;
    if (param && payload){
      u = url + (url.indexOf('?') === -1 ? '?' : '&')
        + encodeURIComponent(param) + '=' + encodeURIComponent(payload);
    }
    var r = await api('/proxy?url=' + encodeURIComponent(u));
    var t = await r.text();
    var h = 0; for (var k = 0; k < t.length; k++) h = ((h<<5)-h + t.charCodeAt(k))|0;
    return { status: r.status, length: t.length, hash: h };
  } catch(e){ return { status: 0, length: 0, hash: 0, error: String(e) }; }
}
function injectTool(kind, label){
  reg('inject', {
    id: 'inj_'+kind, icon:'💥', name: label,
    description: 'Non-destructive ' + kind + ' probe',
    fields: [
      {name:'url', label:'URL (default: current)'},
      {name:'param', label:'Parameter (blank = auto)'},
    ],
    run: async function(i){
      var url = i.url || L.activeTabUrl();
      var pls = PAYLOADS[kind] || [];
      if (!pls.length) throw new Error('no payloads');
      var baseline = await probeOnce(url, i.param, '');
      var hits = [];
      for (var k = 0; k < pls.length; k++){
        var res = await probeOnce(url, i.param, pls[k]);
        if (res.hash !== baseline.hash || res.status !== baseline.status
            || Math.abs(res.length - baseline.length) > 64){
          hits.push({payload:pls[k], status:res.status, length:res.length});
        }
      }
      if (!hits.length){
        return { html: msg('ok','No anomalies ('+pls.length+' probes).'),
                 raw: { baseline: baseline, results: [] } };
      }
      var html = msg('err', hits.length + ' anomalous of ' + pls.length);
      hits.forEach(function(h){
        html += '<div class="finding high"><div class="finding-head">'
          + '<span class="sev high">ANOMALY</span>'
          + '<span class="title" style="font-family:ui-monospace,monospace;font-size:11.5px;">'
          + esc(h.payload) + '</span></div>'
          + '<div class="finding-meta"><span>status '+h.status+'</span>'
          + '<span>len '+h.length+'</span></div></div>';
      });
      return { html: html, findings: hits.map(function(h){
        return {severity:'medium', cwe:'CWE-20',
          title:'Injection anomaly (' + kind + ')',
          desc:'Payload altered response.', evidence:'Payload: '+h.payload,
          tabUrl: url};
      }), raw: { baseline: baseline, results: hits } };
    }
  });
}
injectTool('sqli','SQL Injection');
injectTool('nosqli','NoSQL Injection');
injectTool('xss','XSS');
injectTool('lfi','LFI');
injectTool('rfi','RFI');
injectTool('ssti','SSTI');
injectTool('cmdi','Command Injection');
injectTool('xxe','XXE');
injectTool('ssrf','SSRF');
injectTool('crlf','CRLF');
injectTool('open_redirect','Open Redirect');
injectTool('host_header','Host Header');
injectTool('path_traversal','Path Traversal');
injectTool('http_smuggling','HTTP Smuggling');

reg('inject', {id:'xss_scan', icon:'⚡', name:'XSS Scanner',
  description:'Active reflected-XSS on every param', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/xss-scan', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.verified; });
    if (!hits.length) return { html: msg('ok','No unencoded reflections.'), raw: d };
    var html = msg('err', hits.length + ' confirmed');
    hits.forEach(function(x){
      html += '<div class="finding high"><div class="finding-head">'
        + '<span class="sev high">XSS</span>'
        + '<span class="title">param '+esc(x.param)+' · '+esc(x.payload)+'</span></div>'
        + '<pre class="finding-evidence">'+esc(x.tag)+'</pre></div>';
    });
    return { html: html, findings: hits.map(function(x){
      return {severity:'high', cwe:'CWE-79',
        title:'Reflected XSS in ' + x.param,
        desc:'Payload reflected unencoded.',
        evidence:x.tag, remediation:'Contextual output encoding + CSP.',
        tabUrl: d.url || i.url || L.activeTabUrl()};
    }), raw: d };
  }});

reg('inject', {id:'open_redirect_scan', icon:'➡️', name:'Open Redirect Scan',
  description:'Bypass payloads', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/open-redirect-scan', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.vulnerable; });
    if (!hits.length) return { html: msg('ok','No redirect to attacker.'), raw: d };
    return { html: msg('err', hits.length + ' vulnerable') + hits.map(function(x){
      return row(x.param, x.payload + ' → ' + x.location);
    }).join(''), findings: hits.map(function(x){
      return {severity:'medium', cwe:'CWE-601',
        title:'Open redirect via '+x.param,
        desc:'Location header redirects to attacker.',
        evidence:'payload='+x.payload+'\nLocation: '+x.location,
        remediation:'Allowlist redirect targets.',
        tabUrl: d.url || i.url || L.activeTabUrl()};
    }), raw: d };
  }});

reg('inject', {id:'subdomain_takeover', icon:'🎯', name:'Subdomain Takeover',
  description:'CNAME fingerprints', fields:[
    {name:'domain', label:'Domain(s) — one per line', type:'textarea', default:''}],
  run: async function(i){
    var d = await post('/tool/subdomain-takeover', {domain: i.domain || L.activeTabHost()});
    if (d.error) throw new Error(d.error);
    var r = (d.results || []);
    if (!r.length) return { html: msg('info','No results.'), raw: d };
    var html = r.map(function(x){
      var col = x.confirmed ? '#f87171' : x.matched ? '#f59e0b' : '#10b981';
      return '<div style="padding:10px 12px;background:#070b16;border-radius:8px;'
        + 'margin-bottom:5px;border-left:3px solid '+col+';">'
        + '<b style="color:'+col+';">'
        + (x.confirmed ? 'CONFIRMED' : x.matched ? 'CANDIDATE' : 'clean') + '</b> '
        + esc(x.subdomain)
        + (x.cname ? '<br><span style="font-size:11px;color:#94a3b8;">CNAME: '+esc(x.cname)+'</span>' : '')
        + (x.matched ? '<br><span style="font-size:11px;color:'+col+';">→ '+esc(x.matched)+'</span>' : '')
        + '</div>';
    }).join('');
    return { html: html, findings: (d.findings||[]).map(function(f){
      return {severity:f.severity, cwe:f.cwe, title:f.title,
              desc:f.desc, evidence:f.evidence,
              remediation:f.remediation, tabUrl:f.tabUrl};
    }), raw: d };
  }});

reg('inject', {id:'mass_assign', icon:'🏷️', name:'Mass Assignment',
  description:'POST extra fields and diff responses', fields:[
    {name:'url', label:'URL', default:''},
    {name:'fields', label:'Baseline fields (a=b&c=d)', default:'username=test&email=test@test.com'}],
  run: async function(i){
    var d = await post('/tool/mass-assign', {url: i.url || L.activeTabUrl(), fields: i.fields||''});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.differs; });
    if (!hits.length) return { html: msg('info','No differences.'), raw: d };
    return { html: msg('warn', hits.length + ' field(s) triggered a change') + hits.map(function(x){
      return row(x.field, 'status ' + x.status + ' · len ' + x.length + ' · ' + (x.diff||''));
    }).join(''), raw: d };
  }});

reg('inject', {id:'host_header_srv', icon:'🏠', name:'Host Header (server)',
  description:'Host override reflection', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/host-header', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.reflected; });
    if (!hits.length) return { html: msg('ok','No reflection.'), raw: d };
    return { html: msg('warn', hits.length + ' reflections') + hits.map(function(x){
      return row(x.header, x.value + ' → status ' + x.status);
    }).join(''), raw: d };
  }});

reg('inject', {id:'crlf_scan', icon:'↩️', name:'CRLF Injection',
  description:'Encoded CRLF header probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/crlf-scan', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.injected; });
    if (!hits.length) return { html: msg('ok','No injection.'), raw: d };
    return { html: msg('err', hits.length + ' injections') + hits.map(function(x){
      return row(x.payload, 'status ' + x.status);
    }).join(''), raw: d };
  }});

/* ============================================================
   HTTP DEEP
   ============================================================ */
reg('http', {id:'method_override', icon:'🔀', name:'Method Override',
  description:'X-HTTP-Method-Override probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var url = i.url || L.activeTabUrl();
    var r = await api('/proxy?url=' + encodeURIComponent(url), {
      method: 'POST', headers: {'X-HTTP-Method-Override':'PUT'}
    });
    var t = await r.text();
    return { html: row('POST + X-HTTP-Method-Override: PUT',
                       r.status + ' · ' + t.length + 'B'),
             raw: { url: url, status: r.status } };
  }});

reg('http', {id:'ratelimit', icon:'⏱️', name:'Rate Limit',
  description:'20-request burst', fields:[],
  run: async function(){
    var url = L.activeTabUrl();
    var codes = {};
    for (var i = 0; i < 20; i++){
      try {
        var r = await api('/proxy?url=' + encodeURIComponent(url));
        codes[r.status] = (codes[r.status]||0)+1;
      } catch(e){ codes['err'] = (codes['err']||0)+1; }
    }
    var html = '';
    Object.keys(codes).forEach(function(c){ html += row('HTTP '+c, codes[c]); });
    return { html: html, raw: { statuses: codes } };
  }});

reg('http', {id:'smuggling', icon:'🚢', name:'HTTP Smuggling',
  description:'TE/CL desync probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/smuggling', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    return { html: (d.results||[]).map(function(x){
      return row(x.label, x.error || ('status '+x.status+' · '+x.time+'ms'));
    }).join(''), raw: d };
  }});

reg('http', {id:'cache_poison', icon:'🧊', name:'Cache Poison',
  description:'Unkeyed header reflection', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/cache-poison', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.reflected; });
    if (!hits.length) return { html: msg('ok','No reflection.'), raw: d };
    return { html: msg('warn', hits.length + ' reflections') + hits.map(function(x){
      return row(x.header, 'reflected · status ' + x.status);
    }).join(''), raw: d };
  }});

reg('http', {id:'cache_deception', icon:'🎭', name:'Cache Deception',
  description:'Extension-trick probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/cache-deception', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    return { html: (d.results||[]).map(function(x){
      return row(x.url, x.differs + ' · cc: ' + (x.cc||'') + ' · xc: ' + (x.xc||''));
    }).join(''), raw: d };
  }});

/* ============================================================
   AUTH & COOKIES
   ============================================================ */
reg('auth', {id:'cookie_editor', icon:'🍪', name:'Cookie Editor',
  description:'View, add, edit, delete cookies for the current origin',
  fields: [],
  run: async function(){
    var url = L.activeTabUrl() || L.activeTabOrigin();
    var data = await apiJ('/tool/cookies/list?url=' + encodeURIComponent(url));
    var origin = data.origin || '';
    var cookies = data.cookies || {};
    var names = Object.keys(cookies);

    var listHTML = '';
    if (!names.length){
      listHTML = '<div style="padding:14px;background:#070b16;border-radius:9px;'
        + 'text-align:center;color:#64748b;font-size:12px;margin-bottom:12px;">'
        + 'No stored cookies for <b>' + esc(origin || 'this origin') + '</b>.</div>';
    } else {
      listHTML = '<div style="margin-bottom:14px;">'
        + '<div style="font-size:11px;color:#64748b;margin-bottom:8px;'
        + 'font-family:ui-monospace,monospace;">' + esc(origin) + '</div>'
        + names.map(function(n){
            var c = cookies[n] || {};
            var flags = [];
            if (c.secure) flags.push('Secure');
            if (c.httponly) flags.push('HttpOnly');
            if (c.samesite) flags.push('SameSite=' + c.samesite);
            if (c.path) flags.push('Path=' + c.path);
            return '<div class="result-list-item" data-cookie="'+esc(n)+'" '
              + 'style="flex-wrap:wrap;cursor:pointer;">'
              + '<b style="color:#38bdf8;min-width:100px;">' + esc(n) + '</b>'
              + '<span style="flex:1;word-break:break-all;font-size:11px;color:#94a3b8;">'
              + esc(String(c.value||'').slice(0, 60)) + '</span>'
              + '<span style="color:#64748b;font-size:10px;">'
              + esc(flags.join(' · ') || 'no flags') + '</span></div>';
        }).join('') + '</div>';
    }

    var editorHTML = ''
      + '<div style="padding:14px;background:#070b16;border-radius:10px;'
      + 'border:1px solid rgba(148,163,184,.1);">'
      + '<div style="font-weight:700;margin-bottom:10px;">Add / Edit cookie</div>'
      + '<label style="display:block;font-size:11px;color:#94a3b8;margin-bottom:4px;">Name</label>'
      + '<input id="__ck_name" placeholder="session" '
      + 'style="width:100%;padding:10px;background:#0b1220;color:#e2e8f0;'
      + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;'
      + 'font-family:ui-monospace,monospace;font-size:12.5px;outline:none;'
      + 'box-sizing:border-box;min-height:40px;margin-bottom:8px;"/>'
      + '<label style="display:block;font-size:11px;color:#94a3b8;margin-bottom:4px;">Value</label>'
      + '<input id="__ck_value" placeholder="abc123" '
      + 'style="width:100%;padding:10px;background:#0b1220;color:#e2e8f0;'
      + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;'
      + 'font-family:ui-monospace,monospace;font-size:12.5px;outline:none;'
      + 'box-sizing:border-box;min-height:40px;margin-bottom:8px;"/>'
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">'
      + '<label style="display:flex;flex-direction:column;font-size:11px;color:#94a3b8;">Path'
      + '<input id="__ck_path" value="/" style="padding:8px;background:#0b1220;'
      + 'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:6px;'
      + 'font-family:inherit;font-size:12px;outline:none;margin-top:2px;"/></label>'
      + '<label style="display:flex;flex-direction:column;font-size:11px;color:#94a3b8;">SameSite'
      + '<select id="__ck_samesite" style="padding:8px;background:#0b1220;color:#e2e8f0;'
      + 'border:1px solid rgba(148,163,184,.2);border-radius:6px;font-family:inherit;'
      + 'font-size:12px;outline:none;margin-top:2px;">'
      + '<option value="">—</option><option value="Lax">Lax</option>'
      + '<option value="Strict">Strict</option><option value="None">None</option>'
      + '</select></label></div>'
      + '<div style="display:flex;gap:12px;font-size:12px;color:#94a3b8;margin-bottom:12px;">'
      + '<label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="__ck_secure" style="accent-color:#38bdf8;"> Secure</label>'
      + '<label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="__ck_httponly" style="accent-color:#38bdf8;"> HttpOnly</label>'
      + '</div>'
      + '<button id="__ck_save" style="width:100%;padding:12px;border-radius:9px;border:none;'
      + 'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
      + 'cursor:pointer;font-family:inherit;font-size:13px;">Save cookie</button>'
      + '</div>';

    var actionsHTML = ''
      + '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">'
      + '<button id="__ck_clear" style="flex:1;padding:10px 14px;border-radius:9px;'
      + 'border:1px solid rgba(248,113,113,.35);background:transparent;color:#f87171;'
      + 'font-weight:600;cursor:pointer;font-family:inherit;font-size:12px;min-height:40px;">'
      + 'Clear all for origin</button></div>';

    setTimeout(function(){
      var host = $;
      host.querySelectorAll('[data-cookie]').forEach(function(el){
        el.onclick = function(){
          var n = el.getAttribute('data-cookie');
          var c = cookies[n] || {};
          host.querySelector('#__ck_name').value = n;
          host.querySelector('#__ck_value').value = c.value || '';
          host.querySelector('#__ck_path').value = c.path || '/';
          host.querySelector('#__ck_samesite').value = c.samesite || '';
          host.querySelector('#__ck_secure').checked = !!c.secure;
          host.querySelector('#__ck_httponly').checked = !!c.httponly;
          if (!host.querySelector('#__ck_delete')){
            var delBtn = document.createElement('button');
            delBtn.id = '__ck_delete';
            delBtn.textContent = 'Delete';
            delBtn.style.cssText = 'width:100%;padding:10px;margin-top:8px;'
              + 'border-radius:9px;border:1px solid rgba(248,113,113,.35);'
              + 'background:transparent;color:#f87171;font-weight:600;cursor:pointer;'
              + 'font-family:inherit;font-size:12px;';
            delBtn.onclick = async function(){
              await post('/tool/cookies/delete', {origin: origin, name: n});
              UI.toast('Deleted ' + n, 'ok');
              activeToolId = 'cookie_editor';
              render();
            };
            host.querySelector('#__ck_save').parentNode.appendChild(delBtn);
          }
        };
      });
      host.querySelector('#__ck_save').onclick = async function(){
        var name = host.querySelector('#__ck_name').value.trim();
        var value = host.querySelector('#__ck_value').value;
        if (!name){ UI.toast('Name required', 'err'); return; }
        await post('/tool/cookies/set', {
          origin: origin, name: name, value: value,
          path: host.querySelector('#__ck_path').value || '/',
          samesite: host.querySelector('#__ck_samesite').value,
          secure: host.querySelector('#__ck_secure').checked ? '1' : '',
          httponly: host.querySelector('#__ck_httponly').checked ? '1' : '',
        });
        UI.toast('Saved ' + name, 'ok');
        activeToolId = 'cookie_editor'; render();
      };
      var clr = host.querySelector('#__ck_clear');
      if (clr) clr.onclick = async function(){
        if (!(await UI.confirm('Clear all session cookies for ' + origin + '?'))) return;
        await post('/tool/cookies/clear', {origin: origin});
        UI.toast('Cleared', 'ok');
        activeToolId = 'cookie_editor'; render();
      };
    }, 0);

    return { html: listHTML + editorHTML + actionsHTML,
             raw: { origin: origin, cookies: cookies } };
  }});

reg('auth', {id:'session', icon:'🎟️', name:'Session Probe',
  description:'Visible cookies + storage', fields:[],
  run: async function(){
    var doc = L.getIframeDoc(L.activeTab()); if (!doc) throw new Error('tab not ready');
    var cookies = doc.cookie.split(';').map(function(c){return c.trim();}).filter(Boolean);
    var ls = doc.defaultView.localStorage, ss = doc.defaultView.sessionStorage;
    var html = row('Cookies', cookies.length + ' visible');
    cookies.forEach(function(c){
      html += row(c.split('=')[0], c.slice(c.indexOf('=')+1).slice(0,80));
    });
    html += row('localStorage', ls ? Object.keys(ls).length : 0);
    html += row('sessionStorage', ss ? Object.keys(ss).length : 0);
    return { html: html, raw: { cookies: cookies } };
  }});

reg('auth', {id:'jwt', icon:'🎫', name:'JWT Analyzer',
  description:'Decode header + payload', fields:[
    {name:'token', label:'JWT', type:'textarea'}],
  run: async function(i){
    if (!i.token) throw new Error('token required');
    var parts = i.token.split('.');
    if (parts.length < 2) throw new Error('not a JWT');
    function b64(s){ try {
      var t = s.replace(/-/g,'+').replace(/_/g,'/');
      return JSON.parse(decodeURIComponent(escape(atob(t))));
    } catch(e){ return null; } }
    var header = b64(parts[0]), payload = b64(parts[1]);
    return { html: row('Header', JSON.stringify(header))
      + row('Payload', JSON.stringify(payload)),
      raw: { header: header, payload: payload } };
  }});

reg('auth', {id:'oauth', icon:'🔑', name:'OAuth Probe',
  description:'Inspect current OAuth parameters', fields:[],
  run: async function(){
    var doc = L.getIframeDoc(L.activeTab()); if (!doc) throw new Error('tab not ready');
    var anchors = Array.from(doc.querySelectorAll('a[href]'))
      .map(function(a){ return a.href; })
      .filter(function(h){ return /oauth|authorize|openid|sso|redirect_uri/i.test(h); });
    var params = {};
    try {
      var sp = new doc.defaultView.URLSearchParams(doc.location.search);
      ['redirect_uri','state','nonce','response_type','client_id','scope'].forEach(function(k){
        if (sp.has(k)) params[k] = sp.get(k);
      });
    } catch(e){}
    var html = row('OAuth links', anchors.length);
    Object.keys(params).forEach(function(k){ html += row(k, params[k]); });
    if (params.redirect_uri && !/^https:/i.test(params.redirect_uri)){
      html += msg('warn', 'redirect_uri is not HTTPS');
    }
    return { html: html, raw: { anchors: anchors, params: params } };
  }});

reg('auth', {id:'tabnabbing', icon:'🔙', name:'Reverse Tabnabbing',
  description:'Unsafe target=_blank anchors', fields:[],
  run: async function(){
    var doc = L.getIframeDoc(L.activeTab()); if (!doc) throw new Error('tab not ready');
    var anchors = Array.from(doc.querySelectorAll('a[target="_blank"]'));
    var unsafe = anchors.filter(function(a){
      var rel = (a.getAttribute('rel')||'').toLowerCase();
      return !(rel.indexOf('noopener') !== -1 || rel.indexOf('noreferrer') !== -1);
    });
    if (!unsafe.length) return { html: msg('ok','None (' + anchors.length + ').'), raw: {} };
    return { html: msg('err', unsafe.length + ' unsafe / ' + anchors.length)
      + unsafe.slice(0,30).map(function(a){
        return '<div class="result-list-item" style="border-left:3px solid #f87171;word-break:break-all;">'
          + esc(a.href.slice(0,140)) + '</div>';
      }).join(''), raw: { unsafe: unsafe.length } };
  }});

/* ============================================================
   CMS
   ============================================================ */
function cmsScan(id, label, paths){
  reg('cms', {
    id: id, icon:'📦', name: label,
    description:'Probe common endpoints',
    fields: [{name:'base', label:'Base URL (default: current origin)'}],
    run: async function(i){
      var base = i.base || L.activeTabOrigin();
      if (!base) throw new Error('no base');
      var hits = [];
      for (var k = 0; k < paths.length; k++){
        var u = base + paths[k];
        try {
          var r = await api('/proxy?url=' + encodeURIComponent(u), {method:'HEAD'});
          if (r.status === 200 || r.status === 403 || r.status === 401){
            hits.push({path: paths[k], url: u, status: r.status});
          }
        } catch(e){}
      }
      if (!hits.length) return { html: msg('info','No endpoints matched.'), raw: {hits:[]} };
      return { html: hits.map(function(h){
        return '<div class="result-list-item" data-open-url="'+esc(h.url)+'">'
          + '<span class="badge">'+h.status+'</span>'
          + '<span style="flex:1;word-break:break-all;">'+esc(h.path)+'</span></div>';
      }).join(''), raw: { base: base, hits: hits } };
    }
  });
}
cmsScan('wp_scan','WordPress', [
  '/wp-login.php','/wp-admin/','/xmlrpc.php','/wp-json/wp/v2/users',
  '/wp-config.php.bak','/readme.html','/wp-content/debug.log']);
cmsScan('joomla_scan','Joomla', [
  '/administrator/','/configuration.php~','/htaccess.txt','/README.txt']);
cmsScan('drupal_scan','Drupal', [
  '/CHANGELOG.txt','/user/login','/user/register','/sites/default/settings.php']);

/* ============================================================
   ENUMERATION
   ============================================================ */
reg('enum', {id:'html_inspector', icon:'🔬', name:'HTML Inspector',
  description:'Select elements, edit, apply', fields: [],
  run: async function(){
    var doc = L.getIframeDoc(L.activeTab()); if (!doc) throw new Error('tab not ready');
    var html = msg('info', 'Tap an element to inspect. Edits apply immediately.')
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;">'
      + '<input id="__hi_sel" placeholder="CSS selector" style="padding:10px;background:#0b1220;'
      + 'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:8px;'
      + 'font-family:ui-monospace,monospace;font-size:12px;outline:none;min-height:40px;box-sizing:border-box;"/>'
      + '<button id="__hi_pick" style="padding:10px;border-radius:8px;border:none;'
      + 'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;font-weight:700;'
      + 'cursor:pointer;font-family:inherit;font-size:12px;">Select</button>'
      + '</div><div id="__hi_out"></div>';

    function showElement(el){
      var tag = el.tagName.toLowerCase();
      var id = el.id ? '#' + el.id : '';
      var cls = (el.className && typeof el.className === 'string')
        ? '.' + el.className.trim().split(/\s+/).slice(0,3).join('.') : '';
      var text = (el.textContent || '').slice(0, 500);
      var outer = (el.outerHTML || '').slice(0, 8000);
      $.querySelector('#__hi_out').innerHTML =
        '<div style="padding:12px;background:#070b16;border-radius:9px;border-left:3px solid #38bdf8;margin-bottom:12px;">'
        + '<div style="font-family:ui-monospace,monospace;color:#38bdf8;font-weight:700;margin-bottom:6px;">'
        + esc(tag + id + cls) + '</div></div>'
        + '<label style="display:block;font-size:11px;color:#94a3b8;margin-bottom:4px;">Text content</label>'
        + '<textarea id="__hi_text" style="width:100%;height:80px;background:#0b1220;color:#e2e8f0;'
        + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:10px;'
        + 'font-family:ui-monospace,monospace;font-size:12px;outline:none;box-sizing:border-box;'
        + 'resize:vertical;">'+esc(text)+'</textarea>'
        + '<label style="display:block;font-size:11px;color:#94a3b8;margin:8px 0 4px;">Outer HTML</label>'
        + '<textarea id="__hi_html" style="width:100%;height:180px;background:#0b1220;color:#e2e8f0;'
        + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:10px;'
        + 'font-family:ui-monospace,monospace;font-size:11.5px;outline:none;box-sizing:border-box;'
        + 'resize:vertical;">'+esc(outer)+'</textarea>'
        + '<div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">'
        + '<button id="__hi_apply_text" style="flex:1;padding:10px;border-radius:8px;border:none;'
        + 'background:#38bdf8;color:#0b1220;font-weight:700;cursor:pointer;font-family:inherit;font-size:12px;">'
        + 'Apply text</button>'
        + '<button id="__hi_apply_html" style="flex:1;padding:10px;border-radius:8px;border:none;'
        + 'background:#818cf8;color:#0b1220;font-weight:700;cursor:pointer;font-family:inherit;font-size:12px;">'
        + 'Apply HTML</button>'
        + '<button id="__hi_hl" style="padding:10px 14px;border-radius:8px;'
        + 'border:1px solid rgba(148,163,184,.3);background:transparent;color:#e2e8f0;'
        + 'font-weight:600;cursor:pointer;font-family:inherit;font-size:12px;">Highlight</button></div>';
      $.querySelector('#__hi_apply_text').onclick = function(){
        try { el.textContent = $.querySelector('#__hi_text').value; UI.toast('Applied', 'ok'); }
        catch(e){ UI.toast('Failed: ' + e.message, 'err'); }
      };
      $.querySelector('#__hi_apply_html').onclick = function(){
        try { el.outerHTML = $.querySelector('#__hi_html').value; UI.toast('Applied', 'ok'); }
        catch(e){ UI.toast('Failed: ' + e.message, 'err'); }
      };
      $.querySelector('#__hi_hl').onclick = function(){
        try {
          el.style.outline = '3px solid #38bdf8';
          el.scrollIntoView({behavior:'smooth', block:'center'});
          setTimeout(function(){ el.style.outline = ''; }, 2500);
        } catch(e){}
      };
    }
    setTimeout(function(){
      $.querySelector('#__hi_pick').onclick = function(){
        var sel = $.querySelector('#__hi_sel').value.trim();
        var el = sel ? doc.querySelector(sel) : null;
        if (!el){ $.querySelector('#__hi_out').innerHTML = msg('warn', 'No match'); return; }
        showElement(el);
      };
      try {
        var firstP = doc.querySelector('p, h1, div[id], main, article, section');
        if (firstP) showElement(firstP);
      } catch(e){}
    }, 0);
    return { html: html, raw: {} };
  }});

reg('enum', {id:'filetree', icon:'🌳', name:'File Tree',
  description:'Crawl the site and build a folder tree',
  fields: [
    {name:'url', label:'Base URL', default:''},
    {name:'depth', label:'Depth', type:'select', options:['1','2','3'], default:'2'},
  ],
  run: async function(i){
    var url = i.url || L.activeTabOrigin() || L.activeTabUrl();
    if (!url) throw new Error('url required');
    var d = await apiJ('/tool/tree?url=' + encodeURIComponent(url) + '&depth=' + (i.depth || '2'));
    if (d.error) throw new Error(d.error);
    function renderTree(node){
      if (!node) return '';
      var icon = iconFor(node.name, node.type);
      if (node.type === 'file'){
        return '<div class="result-list-item" data-view-url="'+esc(node.url)+'" '
          + 'style="cursor:pointer;padding:8px 10px;border-left:2px solid #38bdf8;">'
          + '<span>' + icon + '</span>'
          + '<span style="flex:1;word-break:break-all;font-size:11.5px;">'
          + esc(node.name) + '</span></div>';
      }
      var kids = (node.children || []).slice(0, 200);
      var body = kids.length
        ? '<div style="padding-left:14px;margin-top:2px;">'
          + kids.map(renderTree).join('') + '</div>'
        : '<div style="color:#64748b;font-size:11px;padding-left:14px;">(empty)</div>';
      return '<div style="margin-bottom:2px;">'
        + '<div class="tree-dir" data-open-url="'+esc(node.url)+'" '
        + 'style="padding:8px 10px;background:#070b16;border-radius:6px;cursor:pointer;'
        + 'display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;">'
        + '<span>' + icon + '</span>'
        + '<span style="flex:1;word-break:break-all;">' + esc(node.name) + '</span></div>'
        + body + '</div>';
    }
    var html = msg('info', 'Visited ' + d.visited + ' URLs · ' + d.origin)
      + '<div style="background:#050a14;border-radius:9px;padding:10px;'
      + 'font-family:ui-monospace,monospace;font-size:12px;max-height:60vh;overflow:auto;">'
      + renderTree(d.root) + '</div>';
    return { html: html, raw: d };
  }});

reg('enum', {id:'dirbrute', icon:'📁', name:'Directory Brute',
  description:'Wordlist scan — tap results to view content',
  fields: [
    {name:'url', label:'Base URL', default:''},
    {name:'paths', label:'Paths (blank = bundled)', type:'textarea', default:''},
  ],
  run: async function(i){
    var url = i.url || L.activeTabOrigin();
    if (!url) throw new Error('url required');
    var paths = (i.paths || '').split('\n').map(function(s){return s.trim();}).filter(Boolean);
    var d = await post('/tool/brute', {url: url, paths: JSON.stringify(paths)});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.status && x.status !== 404 && x.status !== 410; });
    if (!hits.length) return { html: msg('info','No interesting paths.'), raw: d };
    var base = url.replace(/\/+$/,'');
    var html = msg('info', hits.length + ' hits of ' + (d.results||[]).length + ' — tap any to view');
    hits.forEach(function(x){
      var u = base + '/' + String(x.path).replace(/^\/+/, '');
      var c = x.status < 300 ? '#10b981' : x.status < 400 ? '#38bdf8'
              : x.status < 500 ? '#f59e0b' : '#f87171';
      html += '<div class="result-list-item" data-view-url="'+esc(u)+'" '
        + 'style="cursor:pointer;border-left:3px solid '+c+';">'
        + '<span style="color:'+c+';font-weight:700;min-width:40px;">'+x.status+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(x.path)+'</span>'
        + (x.size ? '<span style="color:#64748b;font-size:10px;">'+prettySize(x.size)+'</span>' : '')
        + '</div>';
    });
    return { html: html, raw: d };
  }});

reg('enum', {id:'domex', icon:'🧭', name:'DOM Explorer',
  description:'Search DOM elements',
  fields:[
    {name:'selector', label:'CSS selector', default:'div'},
    {name:'text', label:'Text contains (optional)', default:''},
  ],
  run: async function(i){
    var doc = L.getIframeDoc(L.activeTab()); if (!doc) throw new Error('tab not ready');
    var pool;
    try { pool = Array.from(doc.querySelectorAll(i.selector || 'div')); }
    catch(e){ throw new Error('bad selector'); }
    if (i.text){
      var t = i.text.toLowerCase();
      pool = pool.filter(function(el){ return (el.textContent||'').toLowerCase().indexOf(t) !== -1; });
    }
    if (!pool.length) return { html: msg('info','No matches.'), raw: {hits:0} };
    var lim = pool.slice(0, 200);
    return { html: msg('info', pool.length + ' matched' + (pool.length > 200 ? ' (showing 200)' : ''))
      + lim.map(function(el){
        var tag = el.tagName.toLowerCase();
        var id = el.id ? '#' + el.id : '';
        var c = el.className && typeof el.className === 'string'
          ? '.' + el.className.trim().split(/\s+/).slice(0,2).join('.') : '';
        var text = (el.textContent || '').slice(0,100);
        return '<div class="result-list-item" style="flex-direction:column;align-items:flex-start;gap:4px;">'
          + '<span style="font-family:ui-monospace,monospace;font-size:11.5px;color:#38bdf8;">'
          + esc(tag + id + c) + '</span>'
          + (text ? '<span style="font-size:11px;color:#94a3b8;">'+esc(text)+'</span>' : '')
          + '</div>';
      }).join(''), raw: { matched: pool.length } };
  }});

reg('enum', {id:'js_endpoints', icon:'🕸️', name:'JS Endpoints',
  description:'Extract URLs from inline + external JS', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/js-endpoints', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var eps = d.endpoints || [];
    if (!eps.length) return { html: msg('info','No endpoints.'), raw: d };
    return { html: msg('info', eps.length + ' endpoints') + eps.map(function(e){
      return '<div class="result-list-item" data-open-url="'+esc(e.absolute)+'">'
        + '<span style="flex:1;word-break:break-all;">'+esc(e.absolute)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('enum', {id:'api_discover', icon:'🔌', name:'API Discovery',
  description:'Common API paths', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/api-discover', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.status && x.status !== 404; });
    if (!hits.length) return { html: msg('info','No API paths.'), raw: d };
    return { html: hits.map(function(x){
      return '<div class="result-list-item" data-open-url="'+esc(x.url)+'">'
        + '<span class="badge">'+x.status+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(x.path)+'</span></div>';
    }).join(''), raw: d };
  }});

reg('enum', {id:'params', icon:'🔍', name:'Parameter Discovery',
  description:'Brute-force hidden parameters', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/params', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = (d.results||[]).filter(function(x){ return x.reflected || x.differs; });
    if (!hits.length) return { html: msg('info','No interesting params.'), raw: d };
    return { html: hits.map(function(x){
      return row(x.name, (x.reflected?'reflected ':'') + (x.differs?('differs ('+x.diff+')'):''));
    }).join(''), raw: d };
  }});

reg('enum', {id:'graphql', icon:'🔮', name:'GraphQL Introspect',
  description:'Fetch schema', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/graphql', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    function list(label, items){
      if (!items || !items.length) return '';
      return msg('info', label + ' (' + items.length + ')') + items.map(function(x){
        return '<div class="result-list-item">'+esc(x)+'</div>';
      }).join('');
    }
    return { html: list('Queries', d.queries) + list('Mutations', d.mutations)
      + list('Types', (d.types||[]).slice(0, 100)), raw: d };
  }});

reg('enum', {id:'graphql_fuzz', icon:'💥', name:'GraphQL Fuzz',
  description:'Depth, alias, introspection probes', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/graphql-fuzz', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    return { html: (d.probes||[]).map(function(p){
      return row(p.label, p.error ? p.error : ('status ' + p.status + ' · ' + p.length + 'B'));
    }).join(''), raw: d };
  }});

/* ============================================================
   SHELL & TAKEOVER
   ============================================================ */
reg('shell', {id:'webshell_scan', icon:'🐚', name:'Webshell Scan',
  description:'Common backdoor / webshell paths', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/webshell-scan', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = d.hits || [];
    if (!hits.length) return { html: msg('ok','No webshells reachable.'), raw: d };
    return { html: msg('warn', hits.length + ' reachable path(s)') + hits.map(function(h){
      return '<div class="result-list-item" data-view-url="'+esc(h.url)+'" style="cursor:pointer;">'
        + '<span style="color:#f59e0b;font-weight:700;min-width:38px;">'+h.status+'</span>'
        + '<span style="flex:1;word-break:break-all;">'+esc(h.path)+'</span>'
        + '<span style="color:#64748b;">'+h.length+'B</span></div>';
    }).join(''), raw: d };
  }});

reg('shell', {id:'backup_scan', icon:'💾', name:'Backup / Config Hunter',
  description:'Find .bak / .env / .zip / config files', fields:[
    {name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/backup-scan', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    var hits = d.hits || [];
    if (!hits.length) return { html: msg('ok','No backups/config files.'), raw: d };
    return { html: msg('err', hits.length + ' exposed file(s) of ' + (d.results||[]).length)
      + hits.map(function(h){
        return '<div class="result-list-item" data-view-url="'+esc(h.url)+'" '
          + 'style="cursor:pointer;border-left:3px solid #f87171;">'
          + '<span style="flex:1;word-break:break-all;">'+esc(h.path)+'</span>'
          + '<span style="color:#64748b;">'+h.length+'B</span></div>';
      }).join(''), raw: d };
  }});

/* ============================================================
   CAPTCHA
   ============================================================ */
reg('captcha', {id:'captcha_detect', icon:'🤖', name:'Captcha Detector',
  description:'Scan page for reCAPTCHA / hCaptcha / Turnstile / WAF challenges',
  fields: [{name:'url', label:'URL', default:''}],
  run: async function(i){
    var d = await post('/tool/captcha-detect', {url: i.url || L.activeTabUrl()});
    if (d.error) throw new Error(d.error);
    if (!d.detected || !d.detected.length){
      return { html: msg('ok','No captcha detected. HTML size: '+prettySize(d.html_size)),
               raw: d };
    }
    return {
      html: msg('warn', d.detected.length + ' captcha service(s) detected')
        + d.detected.map(function(x){ return row('Detected', x); }).join('')
        + msg('info','Use “Captcha Remover” below to hide overlays. '
             + 'Note: server-side verification still blocks submission.'),
      raw: d,
    };
  }});

reg('captcha', {id:'captcha_remove', icon:'🧹', name:'Captcha Remover',
  description:'Register a snippet that hides captcha widgets and unlocks scroll on every proxied page',
  fields: [],
  run: async function(){
    var r = await post('/tool/captcha-remove', {});
    if (!r.ok) throw new Error(r.reason || 'failed');
    if (r.already){
      return { html: msg('ok','Captcha Remover already active. Reload any proxied tab.'), raw: r };
    }
    return { html: msg('ok','Captcha Remover registered (snippet ' + r.id + '). '
                          + 'Reload any proxied tab to activate.'), raw: r };
  }});

/* ============================================================
   ENCODE
   ============================================================ */
reg('encode', {id:'hash', icon:'#️⃣', name:'Hash',
  description:'SHA-1 / SHA-256 / SHA-512', fields:[
    {name:'text', label:'Text', type:'textarea'}],
  run: async function(i){
    if (!i.text) throw new Error('text required');
    var enc = new TextEncoder().encode(i.text);
    var html = '';
    for (var k = 0; k < 3; k++){
      var alg = ['SHA-1','SHA-256','SHA-512'][k];
      var buf = await crypto.subtle.digest(alg, enc);
      var hex = Array.from(new Uint8Array(buf))
        .map(function(b){return b.toString(16).padStart(2,'0')}).join('');
      html += row(alg, hex);
    }
    return { html: html, raw: { input: i.text } };
  }});

reg('encode', {id:'b64', icon:'🔤', name:'Base64',
  description:'Encode / decode', fields:[
    {name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode'},
    {name:'text', label:'Input', type:'textarea'}],
  run: async function(i){
    var out;
    if (i.mode === 'decode') out = decodeURIComponent(escape(atob(i.text.trim())));
    else out = btoa(unescape(encodeURIComponent(i.text)));
    return { html: row(i.mode, out), raw: { output: out } };
  }});

reg('encode', {id:'url', icon:'🔗', name:'URL Encode',
  description:'Percent-encode / decode', fields:[
    {name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode'},
    {name:'text', label:'Input', type:'textarea'}],
  run: async function(i){
    var out = i.mode === 'decode' ? decodeURIComponent(i.text) : encodeURIComponent(i.text);
    return { html: row(i.mode, out), raw: { output: out } };
  }});

reg('encode', {id:'hex', icon:'⬛', name:'Hex',
  description:'Encode / decode hex', fields:[
    {name:'mode', label:'Mode', type:'select', options:['encode','decode'], default:'encode'},
    {name:'text', label:'Input', type:'textarea'}],
  run: async function(i){
    var out;
    if (i.mode === 'encode'){
      out = Array.from(new TextEncoder().encode(i.text))
        .map(function(b){return b.toString(16).padStart(2,'0')}).join('');
    } else {
      var h = i.text.replace(/\s+/g,'');
      var bytes = new Uint8Array(h.length/2);
      for (var k = 0; k < bytes.length; k++) bytes[k] = parseInt(h.substr(k*2,2),16);
      out = new TextDecoder().decode(bytes);
    }
    return { html: row(i.mode, out), raw: { output: out } };
  }});

reg('encode', {id:'rot13', icon:'🔄', name:'ROT13 / Caesar',
  description:'Brute-force 25 shifts', fields:[
    {name:'text', label:'Text', type:'textarea'}],
  run: async function(i){
    var rows = '';
    for (var s = 1; s <= 25; s++){
      var out = i.text.replace(/[a-zA-Z]/g, function(c){
        var b = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - b + s) % 26) + b);
      });
      rows += row(s, out.slice(0,120));
    }
    return { html: rows, raw: {} };
  }});

reg('encode', {id:'pw', icon:'🔒', name:'Password Strength',
  description:'Entropy estimation', fields:[
    {name:'pw', label:'Password'}],
  run: async function(i){
    var len = i.pw.length, classes = 0;
    if (/[a-z]/.test(i.pw)) classes++;
    if (/[A-Z]/.test(i.pw)) classes++;
    if (/[0-9]/.test(i.pw)) classes++;
    if (/[^A-Za-z0-9]/.test(i.pw)) classes++;
    var alphabet = [0,26,52,62,94][classes];
    var entropy = Math.round(len * Math.log2(alphabet || 1));
    var score = entropy < 28 ? 'very weak' : entropy < 36 ? 'weak'
      : entropy < 60 ? 'reasonable' : entropy < 128 ? 'strong' : 'very strong';
    return { html: row('Length', len) + row('Classes', classes + '/4')
      + row('Entropy', entropy + ' bits') + row('Rating', score),
      raw: { entropy: entropy, rating: score } };
  }});

reg('encode', {id:'ts', icon:'🕒', name:'Timestamp',
  description:'Unix ↔ ISO', fields:[
    {name:'input', label:'Unix or ISO', default: String(Math.floor(Date.now()/1000))}],
  run: async function(i){
    var v = i.input.trim(), out = [];
    if (/^\d+$/.test(v)){
      var n = parseInt(v,10); if (v.length <= 10) n *= 1000;
      var d = new Date(n);
      out.push(['Unix (s)', String(Math.floor(n/1000))]);
      out.push(['Unix (ms)', String(n)]);
      out.push(['ISO', d.toISOString()]);
      out.push(['UTC', d.toUTCString()]);
    } else {
      var d2 = new Date(v);
      out.push(['Unix (s)', String(Math.floor(d2.getTime()/1000))]);
      out.push(['ISO', d2.toISOString()]);
    }
    return { html: out.map(function(r){ return row(r[0], r[1]); }).join(''),
             raw: { results: out } };
  }});

/* ============================================================
   PAYLOADS
   ============================================================ */
reg('payloads', {id:'payloads', icon:'📜', name:'Payload Library',
  description:'Curated payloads for every category', fields:[
    {name:'cat', label:'Category', type:'select',
     options: Object.keys(PAYLOADS), default:'sqli'}],
  run: async function(i){
    var items = PAYLOADS[i.cat] || [];
    return { html: items.map(function(p){
      return '<div class="result-list-item" style="flex-wrap:nowrap;">'
        + '<span style="flex:1;font-family:ui-monospace,monospace;font-size:11.5px;'
        + 'word-break:break-all;">' + esc(p) + '</span>'
        + '<button class="btn small" data-copy="' + esc(p) + '">⧉</button></div>';
    }).join(''), raw: { category: i.cat, items: items } };
  }});

/* ============================================================
   CLONER
   ============================================================ */
reg('cloner', {
  id:'clone_page', icon:'⎘', name:'Clone This Page',
  description:'Capture full state (DOM, JS, storage, IDB, caches, OPFS, cookies) and open the clone.',
  fields: [
    {name:'autoclose', label:'Open in a new tab', type:'select',
     options:['yes','no'], default:'yes'},
  ],
  run: async function(i){
    var r = await L.clonePage();
    if (!r || !r.uuid) throw new Error('capture failed');
    if ((i.autoclose || 'yes') === 'yes') L.openClone(r.uuid);
    var url = location.origin + '/clone/' + r.uuid;
    return {
      html: msg('ok', 'Clone saved.')
        + row('UUID', r.uuid)
        + row('Source URL', r.source_url || '')
        + row('Open URL', url)
        + '<div class="result-list-item" data-open-url="' + esc(url) + '">'
        + '<b style="color:#38bdf8;">Open clone</b>'
        + '<span style="flex:1;color:#94a3b8;">' + esc(url) + '</span></div>'
        + '<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">'
        + '<button class="btn small" data-copy="' + esc(url) + '">⧉ Copy URL</button>'
        + '<button class="btn small" data-open-url="' + esc(url) + '">Open</button>'
        + '</div>',
      raw: r,
    };
  }
});

reg('cloner', {
  id:'clones_list', icon:'📚', name:'My Clones',
  description:'List, open, copy URL, edit or delete saved clones.',
  fields: [],
  run: async function(){
    var clones = await L.listClones();
    if (!clones.length)
      return { html: msg('info', 'No clones yet. Use “Clone This Page”.'), raw: { clones: [] } };
    var rows = clones.map(function(c){
      var url = location.origin + '/clone/' + c.uuid;
      var meta = 'size ' + UI.prettySize(c.size)
        + (c.has_indexeddb ? ' · IDB' : '')
        + (c.has_caches ? ' · cache' : '')
        + (c.has_opfs ? ' · OPFS' : '')
        + (c.dom_counts && c.dom_counts.forms ? ' · ' + c.dom_counts.forms + ' form(s)' : '')
        + (c.dom_counts && c.dom_counts.canvases ? ' · ' + c.dom_counts.canvases + ' canvas' : '');
      return '<div class="result-list-item" style="flex-direction:column;align-items:stretch;gap:6px;padding:10px 12px;">'
        + '<div style="display:flex;gap:8px;align-items:center;min-width:0;">'
        + '<b style="color:#38bdf8;flex-shrink:0;">' + esc(c.uuid.slice(0,8)) + '</b>'
        + '<span style="flex:1;word-break:break-all;font-size:11.5px;">' + esc(c.source_url) + '</span>'
        + '</div>'
        + '<div style="font-size:10.5px;color:#64748b;font-family:ui-monospace,monospace;">'
        + esc(meta) + '</div>'
        + '<div style="font-size:10.5px;color:#64748b;font-family:ui-monospace,monospace;word-break:break-all;">'
        + esc(url) + '</div>'
        + '<div style="display:flex;gap:6px;flex-wrap:wrap;">'
        + '<button class="btn small" data-clone-open="' + esc(c.uuid) + '">Open</button>'
        + '<button class="btn small" data-clone-copy="' + esc(url) + '">⧉ Copy URL</button>'
        + '<button class="btn small" data-clone-view="' + esc(c.uuid) + '">Inspect</button>'
        + '<button class="btn small" data-clone-edit="' + esc(c.uuid) + '">Edit HTML</button>'
        + '<button class="btn small" data-clone-export="' + esc(c.uuid) + '">Export</button>'
        + '<button class="btn small" data-clone-delete="' + esc(c.uuid) + '">Delete</button>'
        + '</div></div>';
    }).join('');
    setTimeout(function(){ wireClonesList(); }, 0);
    return { html: msg('info', clones.length + ' clone(s)') + rows, raw: { clones: clones } };
  }
});

function wireClonesList(){
  $.querySelectorAll('[data-clone-open]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = function(){ L.openClone(b.getAttribute('data-clone-open')); };
  });
  $.querySelectorAll('[data-clone-copy]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = function(){
      var url = b.getAttribute('data-clone-copy');
      if (L.copyURL) L.copyURL(url, 'URL copied');
      else if (UI.copy) UI.copy(url);
    };
  });
  $.querySelectorAll('[data-clone-view]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = async function(){
      var uuid = b.getAttribute('data-clone-view');
      var r = await fetch('/clone/' + uuid + '/meta', { credentials:'same-origin' });
      var m = await r.json();
      UI.modal({ title: 'Clone · ' + uuid.slice(0,8), width: 560 }).body.innerHTML =
        '<pre class="result-pre">' + esc(JSON.stringify(m, null, 2)) + '</pre>';
    };
  });
  $.querySelectorAll('[data-clone-edit]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = async function(){
      var uuid = b.getAttribute('data-clone-edit');
      var r = await fetch('/clone/' + uuid + '/source', { credentials:'same-origin' });
      var j = await r.json();
      if (!j.outer_html) return UI.toast('No source', 'err');
      var m = UI.modal({ title: 'Edit clone ' + uuid.slice(0,8), width: 900 });
      var ta = document.createElement('textarea');
      ta.style.cssText = 'width:100%;height:55vh;background:#050a14;color:#e2e8f0;'
        + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:10px;'
        + 'font-family:ui-monospace,monospace;font-size:11.5px;outline:none;'
        + 'box-sizing:border-box;resize:vertical;';
      ta.value = j.outer_html;
      m.body.appendChild(ta);
      var save = document.createElement('button');
      save.textContent = 'Save';
      save.className = 'btn';
      save.style.cssText += ';margin-top:10px;background:linear-gradient(135deg,#38bdf8,#818cf8);'
        + 'color:#0b1220;border:none;font-weight:700;';
      save.onclick = async function(){
        var body = JSON.stringify({ outer_html: ta.value });
        var rr = await fetch('/clone/' + uuid + '/source', {
          method: 'PUT', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: body,
        });
        var jj = await rr.json();
        if (jj.ok) { UI.toast('Saved (' + jj.edit_count + ')', 'ok'); m.close(); }
        else UI.toast(jj.error || 'Save failed', 'err');
      };
      m.body.appendChild(save);
    };
  });
  $.querySelectorAll('[data-clone-export]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = function(){
      var uuid = b.getAttribute('data-clone-export');
      var a = document.createElement('a');
      a.href = '/clone/' + uuid + '/export';
      a.download = uuid + '.lynkclone';
      document.body.appendChild(a); a.click(); a.remove();
    };
  });
  $.querySelectorAll('[data-clone-delete]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = async function(){
      var uuid = b.getAttribute('data-clone-delete');
      if (!(await UI.confirm('Delete clone ' + uuid.slice(0,8) + '?'))) return;
      await fetch('/clone/' + uuid, { method: 'DELETE', credentials: 'same-origin' });
      UI.toast('Deleted', 'ok');
      activeToolId = 'clones_list'; render();
    };
  });
}

reg('cloner', {
  id:'clone_import', icon:'📥', name:'Import .lynkclone',
  description:'Paste a .lynkclone JSON blob (from /clone/<id>/export) to restore it locally.',
  fields: [
    {name:'blob', label:'File contents', type:'textarea',
     default:'', placeholder:'{"uuid":"…","outer_html":"…"}'},
  ],
  run: async function(i){
    if (!i.blob || !i.blob.trim()) throw new Error('paste the exported JSON');
    var r = await fetch('/clone/import', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: i.blob,
    });
    var j = await r.json();
    if (j.error) throw new Error(j.error);
    return {
      html: msg('ok', 'Imported as ' + j.uuid) + row('Open', j.url),
      raw: j,
    };
  }
});

reg('cloner', {
  id:'clone_capture_js', icon:'📜', name:'Capture Script Info',
  description:'Whether the injected capture helper is ready on the active tab.',
  fields: [],
  run: async function(){
    var t = L.activeTab();
    if (!t) throw new Error('No active tab');
    var win;
    try { win = t.frame.contentWindow; } catch(e){ win = null; }
    var ready = !!(win && typeof win.lynkCapture === 'function');
    var ctxUrl = '';
    try { ctxUrl = (win.__LYNK_CTX__ && win.__LYNK_CTX__.upstream) || ''; } catch(e){}
    return {
      html: row('Capture helper', ready ? 'ready' : 'not loaded')
        + row('Upstream URL', ctxUrl)
        + (ready ? '' : msg('warn', 'Reload the tab if capture is missing.')),
      raw: { ready: ready, upstream: ctxUrl },
    };
  }
});

/* ============================================================
   CUSTOMIZE
   ============================================================ */
function wireInjectList(){
  $.querySelectorAll('[data-inject-toggle]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = async function(e){
      e.stopPropagation();
      await post('/tool/inject/toggle', {id: b.getAttribute('data-inject-toggle')});
      UI.toast('Toggled', 'ok');
      render();
    };
  });
  $.querySelectorAll('[data-inject-delete]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = async function(e){
      e.stopPropagation();
      if (!(await UI.confirm('Delete this snippet?'))) return;
      await post('/tool/inject/delete', {id: b.getAttribute('data-inject-delete')});
      UI.toast('Deleted', 'ok');
      render();
    };
  });
  $.querySelectorAll('[data-inject-view]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.onclick = function(e){
      e.stopPropagation();
      var code = b.getAttribute('data-inject-view');
      UI.modal({ title: 'Snippet source', width: 720 }).body.innerHTML =
        '<pre class="result-pre">' + esc(code) + '</pre>';
    };
  });
}

reg('customize', {id:'inject', icon:'💉', name:'Inject JavaScript',
  description:'Manage per-session snippets injected into every proxied page',
  fields: [
    {name:'name', label:'Name', placeholder:'my snippet'},
    {name:'code', label:'Code', type:'textarea', placeholder:'console.log("hi");'}],
  run: async function(i){
    var added = '';
    if (i.code && i.code.trim()){
      var r = await post('/tool/inject/add', {name: i.name || 'unnamed', code: i.code});
      if (!r.ok) throw new Error(r.reason || 'failed');
      added = msg('ok','Snippet "' + (i.name || 'unnamed') + '" added. Reload any proxied tab.');
    }
    var list = await apiJ('/tool/inject/list-full');
    var snippets = list.snippets || [];
    var rendered = added;
    if (!snippets.length){
      rendered += msg('info','No snippets yet.');
    } else {
      rendered += msg('info', snippets.length + ' snippet(s) in this session');
      rendered += snippets.map(function(s){
        var dotColor = s.enabled ? '#10b981' : '#64748b';
        return '<div class="result-list-item" style="flex-wrap:wrap;gap:6px;align-items:center;">'
          + '<span style="color:'+dotColor+';font-size:14px;line-height:1;">●</span>'
          + '<b style="min-width:0;flex:1;word-break:break-word;">'+esc(s.name)+'</b>'
          + '<span style="color:#64748b;font-size:10.5px;">'+s.size+'B</span>'
          + '<button class="btn small" data-inject-view="'+esc(s.code)+'">View</button>'
          + '<button class="btn small" data-inject-toggle="'+esc(s.id)+'">'
          + (s.enabled ? 'Disable' : 'Enable') + '</button>'
          + '<button class="btn small" data-inject-delete="'+esc(s.id)+'">Delete</button>'
          + '</div>';
      }).join('');
    }
    setTimeout(wireInjectList, 0);
    return { html: rendered, raw: list };
  }});

reg('customize', {id:'console_test', icon:'▸_', name:'Console Test',
  description:'Send a test log via WS', fields:[],
  run: async function(){
    L.emit('console', {
      tab_id: L.activeTab() ? L.activeTab().id : 'system',
      level: 'info',
      text: 'Console test @ ' + new Date().toISOString(),
      src: 'toolkit.js',
    });
    return { html: msg('ok','Emitted — check console drawer (Ctrl+`)'), raw: { ok: true } };
  }});

/* ============================================================
   UI
   ============================================================ */
var activeToolId = null, filterText = '';
var _resizeTimer = null;
var _lastScrollTop = 0;

function render(){
  $ = L.kitBody; $.innerHTML = '';
  var main = document.createElement('div');
  main.style.cssText = 'min-width:0;max-width:100%;box-sizing:border-box;';
  $.appendChild(main);
  if (activeToolId && TOOLS[activeToolId]) renderToolView(main);
  else renderTools(main);
  setTimeout(decorateResults, 0);
}

function decorateResults(){
  $.querySelectorAll('[data-open-url]').forEach(function(el){
    if (el.__wired) return; el.__wired = true;
    el.addEventListener('click', function(){
      L.addTab(el.getAttribute('data-open-url'));
    });
  });
  $.querySelectorAll('[data-view-url]').forEach(function(el){
    if (el.__wired) return; el.__wired = true;
    el.addEventListener('click', function(){
      UI.fileViewer(el.getAttribute('data-view-url'), el.textContent.trim());
    });
  });
  $.querySelectorAll('[data-copy]').forEach(function(b){
    if (b.__wired) return; b.__wired = true;
    b.addEventListener('click', function(e){
      e.stopPropagation();
      UI.copy(b.getAttribute('data-copy'));
    });
  });
}

function renderTools(root){
  root.innerHTML = '';

  var searchWrap = document.createElement('div');
  searchWrap.style.cssText = 'position:sticky;top:0;z-index:5;padding-bottom:10px;'
    + 'background:inherit;';
  var s = document.createElement('input');
  s.type = 'search';
  s.placeholder = 'Filter tools…';
  s.value = filterText;
  s.style.cssText = 'width:100%;padding:10px 14px;background:#070b16;'
    + 'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:9px;'
    + 'font-family:inherit;font-size:13px;outline:none;min-height:44px;'
    + 'box-sizing:border-box;-webkit-appearance:none;';
  searchWrap.appendChild(s);
  root.appendChild(searchWrap);

  var list = document.createElement('div');
  list.style.cssText = 'min-width:0;max-width:100%;';
  root.appendChild(list);

  function draw(){
    var f = filterText.toLowerCase(), shown = 0;
    list.innerHTML = '';
    CATEGORIES.forEach(function(cat){
      var tools = Object.keys(TOOLS).map(function(k){ return TOOLS[k]; })
        .filter(function(t){
          if (t.category !== cat.id) return false;
          if (!f) return true;
          return (t.name||'').toLowerCase().indexOf(f) !== -1
              || (t.description||'').toLowerCase().indexOf(f) !== -1
              || t.id.indexOf(f) !== -1;
        });
      if (!tools.length) return;
      shown += tools.length;

      var c = document.createElement('div');
      c.className = 'kit-cat';
      c.style.cssText = 'margin-bottom:14px;min-width:0;';

      var title = document.createElement('div');
      title.className = 'kit-cat-title';
      title.textContent = cat.name;
      title.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:.08em;'
        + 'text-transform:uppercase;color:#64748b;margin-bottom:8px;padding:0 2px;';
      c.appendChild(title);

      var grid = document.createElement('div');
      grid.className = 'kit-grid';
      grid.style.cssText = 'display:grid;'
        + 'grid-template-columns:repeat(auto-fill,minmax(min(150px,100%),1fr));'
        + 'gap:8px;min-width:0;';
      tools.forEach(function(t){
        var tile = document.createElement('button');
        tile.className = 'kit-tile';
        tile.style.cssText = 'padding:11px;border-radius:10px;background:#070b16;'
          + 'border:1px solid rgba(148,163,184,.1);cursor:pointer;transition:.15s;'
          + 'display:flex;flex-direction:column;gap:5px;text-align:left;'
          + 'font-family:inherit;color:inherit;min-height:96px;min-width:0;'
          + 'overflow:hidden;-webkit-tap-highlight-color:transparent;';
        tile.onmouseenter = function(){ tile.style.background = '#0b1220';
          tile.style.borderColor = 'rgba(56,189,248,.35)'; };
        tile.onmouseleave = function(){ tile.style.background = '#070b16';
          tile.style.borderColor = 'rgba(148,163,184,.1)'; };
        var ic = document.createElement('span');
        ic.style.cssText = 'font-size:18px;line-height:1;';
        ic.textContent = t.icon || '•';
        var nm = document.createElement('span');
        nm.style.cssText = 'font-weight:700;font-size:12px;color:#e2e8f0;'
          + 'line-height:1.3;word-break:break-word;';
        nm.textContent = t.name;
        var ds = document.createElement('span');
        ds.style.cssText = 'font-size:10.5px;color:#64748b;line-height:1.4;'
          + 'word-break:break-word;display:-webkit-box;-webkit-line-clamp:3;'
          + '-webkit-box-orient:vertical;overflow:hidden;';
        ds.textContent = t.description || '';
        tile.appendChild(ic); tile.appendChild(nm); tile.appendChild(ds);
        tile.onclick = function(){ activeToolId = t.id; render(); };
        grid.appendChild(tile);
      });
      c.appendChild(grid);
      list.appendChild(c);
    });
    if (!shown){
      var empty = document.createElement('div');
      empty.innerHTML = msg('info', 'No tools match.');
      list.appendChild(empty);
    }
  }

  s.addEventListener('input', function(){
    filterText = s.value;
    draw();
  });
  draw();
}

function renderToolView(root){
  var t = TOOLS[activeToolId];
  if (!t){ activeToolId = null; render(); return; }

  var back = document.createElement('button');
  back.textContent = '← Back';
  back.style.cssText = 'padding:8px 14px;border-radius:8px;'
    + 'border:1px solid rgba(148,163,184,.25);background:transparent;color:#e2e8f0;'
    + 'cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:600;'
    + 'margin-bottom:12px;min-height:40px;';
  back.onclick = function(){ activeToolId = null; render(); };
  root.appendChild(back);

  var form = document.createElement('div');
  form.style.cssText = 'padding:14px;background:#070b16;border-radius:11px;'
    + 'border:1px solid rgba(148,163,184,.1);margin-bottom:12px;'
    + 'min-width:0;box-sizing:border-box;';

  var head = document.createElement('div');
  head.style.cssText = 'margin-bottom:12px;';
  head.innerHTML = '<div style="font-weight:700;font-size:14px;color:#e2e8f0;'
    + 'word-break:break-word;">' + esc(t.icon||'') + ' ' + esc(t.name) + '</div>'
    + '<div style="font-size:11.5px;color:#64748b;margin-top:2px;'
    + 'word-break:break-word;">' + esc(t.description||'') + '</div>';
  form.appendChild(head);

  var values = {};
  (t.fields||[]).forEach(function(f){
    values[f.name] = f.default !== undefined ? f.default : '';
    var w = document.createElement('div');
    w.style.cssText = 'margin-bottom:10px;min-width:0;';
    var l = document.createElement('label');
    l.textContent = f.label || f.name;
    l.style.cssText = 'display:block;font-size:10.5px;color:#94a3b8;'
      + 'font-weight:600;text-transform:uppercase;letter-spacing:.06em;'
      + 'margin-bottom:4px;';
    w.appendChild(l);
    var el;
    if (f.type === 'textarea'){
      el = document.createElement('textarea');
      el.value = values[f.name];
      if (f.placeholder) el.placeholder = f.placeholder;
      el.style.cssText = 'width:100%;min-height:120px;background:#0b1220;'
        + 'color:#e2e8f0;border:1px solid rgba(148,163,184,.2);border-radius:8px;'
        + 'padding:11px;font-family:ui-monospace,monospace;font-size:12px;'
        + 'outline:none;box-sizing:border-box;resize:vertical;line-height:1.5;';
    } else if (f.type === 'select'){
      el = document.createElement('select');
      (f.options||[]).forEach(function(o){
        var opt = document.createElement('option');
        opt.value = o; opt.textContent = o;
        if (o === values[f.name]) opt.selected = true;
        el.appendChild(opt);
      });
      el.style.cssText = 'width:100%;background:#0b1220;color:#e2e8f0;'
        + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:10px;'
        + 'font-family:inherit;font-size:13px;outline:none;min-height:42px;'
        + 'box-sizing:border-box;-webkit-appearance:none;';
    } else {
      el = document.createElement('input');
      el.type = f.type || 'text';
      el.value = values[f.name];
      if (f.placeholder) el.placeholder = f.placeholder;
      el.style.cssText = 'width:100%;background:#0b1220;color:#e2e8f0;'
        + 'border:1px solid rgba(148,163,184,.2);border-radius:8px;padding:11px;'
        + 'font-family:ui-monospace,monospace;font-size:12.5px;outline:none;'
        + 'min-height:44px;box-sizing:border-box;';
    }
    el.oninput = el.onchange = function(){ values[f.name] = el.value; };
    w.appendChild(el);
    form.appendChild(w);
  });

  var actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:8px;margin-top:12px;'
    + 'padding-top:12px;border-top:1px solid rgba(148,163,184,.1);'
    + 'flex-wrap:wrap;';
  var runBtn = document.createElement('button');
  runBtn.textContent = '▶ Run';
  runBtn.style.cssText = 'flex:1 1 140px;min-width:0;padding:12px 20px;'
    + 'border-radius:9px;border:none;'
    + 'background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220;'
    + 'font-weight:700;cursor:pointer;font-family:inherit;font-size:13px;'
    + 'min-height:44px;';
  actions.appendChild(runBtn);
  form.appendChild(actions);
  root.appendChild(form);

  var host = document.createElement('div');
  host.style.cssText = 'min-width:0;max-width:100%;overflow-wrap:anywhere;';
  root.appendChild(host);

  runBtn.onclick = async function(){
    runBtn.disabled = true;
    runBtn.textContent = 'Running…';
    host.innerHTML = msg('info','Running…');
    try {
      var out = await t.run(values);
      if (out && out.findings && out.findings.length){
        out.findings.forEach(function(f){
          var id = 'f_' + Math.random().toString(36).slice(2,9);
          f.id = id; f.ts = Date.now(); f.toolName = t.name;
          (window.__LYNK_FINDINGS__ = window.__LYNK_FINDINGS__ || []).push(f);
        });
      }
      host.innerHTML = (out && out.html) || msg('ok','Done.');
      decorateResults();
    } catch(e){
      host.innerHTML = msg('err', (e && e.message) || String(e));
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = '▶ Run';
    }
  };
}

window.addEventListener('resize', function(){
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(function(){
    if (!activeToolId) render();
  }, 180);
});

render();
})();
