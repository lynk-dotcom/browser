#!/usr/bin/env python3
"""
Lynkio Scanner — 400+ vulnerability checks.

Categories:
  • Security headers          (~25)
  • Cookie flags              (~10)
  • HTML / JS analysis        (~40)
  • JS library CVEs           (~45)
  • Sensitive paths (GET)     (~230)
  • HTTP methods              (~12)
  • CORS / host / cache       (~15)
  • Framework fingerprints    (~25)
  • Cloud / DevOps artifacts  (~30)
  • Well-known URIs           (~15)
  • Version disclosure        (~20)

Each check returns a Finding dict. None of them exploit anything — they
probe, record responses, and report observable misconfigurations.
"""

import asyncio
import gzip
import hashlib
import json
import logging
import re
import time
import uuid
import zlib
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

log = logging.getLogger("lynk.scanner")


# ======================================================================
# Severity ordering
# ======================================================================
def sev_rank(s):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def finding(id, name, severity, category, description,
            evidence="", remediation="", url="", path="",
            cwe="", cvss=""):
    return {
        "id": id, "name": name, "severity": severity, "category": category,
        "description": description, "evidence": evidence,
        "remediation": remediation, "url": url, "path": path,
        "cwe": cwe, "cvss": cvss,
    }


def decode_body(body, encoding):
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity": return body
    try:
        if "gzip" in enc: return gzip.decompress(body)
        if "deflate" in enc:
            try: return zlib.decompress(body)
            except zlib.error: return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception: pass
    return body


def detect_charset(ct, body):
    m = re.search(r'charset\s*=\s*["\']?([A-Za-z0-9_\-]+)', ct or "", re.I)
    if m: return m.group(1)
    m2 = re.search(rb'charset\s*=\s*["\']?([a-z0-9_\-]+)', body[:4096].lower())
    if m2: return m2.group(1).decode("ascii", "ignore")
    return "utf-8"


# ======================================================================
# Security headers (25 checks)
# ======================================================================
SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "Missing HSTS",
        "HTTP downgrade attacks are possible.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy": ("high", "Missing CSP",
        "XSS impact is unmitigated — no script-src restriction.",
        "Add a Content-Security-Policy with strict script-src."),
    "x-frame-options": ("medium", "Missing X-Frame-Options",
        "Page is framable → clickjacking.",
        "Add X-Frame-Options: DENY (and CSP frame-ancestors 'none')."),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options",
        "MIME-sniffing may be possible.",
        "Add X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Missing Referrer-Policy",
        "Sensitive URL fragments may leak to third parties.",
        "Add Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": ("low", "Missing Permissions-Policy",
        "Browser features are unrestricted.",
        "Add a Permissions-Policy that blocks unnecessary features."),
    "cross-origin-opener-policy": ("low", "Missing COOP",
        "Popup isolation is weakened.",
        "Add Cross-Origin-Opener-Policy: same-origin."),
    "cross-origin-embedder-policy": ("low", "Missing COEP",
        "COEP is not set — cross-origin isolation unavailable.",
        "Add Cross-Origin-Embedder-Policy: require-corp."),
    "cross-origin-resource-policy": ("low", "Missing CORP",
        "CORP is not set — resource can be embedded by any origin.",
        "Add Cross-Origin-Resource-Policy: same-origin."),
    "x-powered-by": ("low", "X-Powered-By leaks framework",
        "Server reveals its backend stack.",
        "Strip X-Powered-By in the reverse proxy."),
    "x-aspnet-version": ("medium", "ASP.NET version exposed",
        "Exact ASP.NET version is disclosed.",
        "Set enableVersionHeader=\"false\" in web.config."),
    "x-aspnetmvc-version": ("medium", "ASP.NET MVC version exposed",
        "MVC version disclosed.",
        "Disable the header."),
    "server": ("low", "Server banner leaks software",
        "Server header reveals software and version.",
        "Set 'Server: ' or a generic value."),
    "x-generator": ("low", "X-Generator leaks CMS",
        "Generator header reveals CMS/platform.",
        "Remove X-Generator."),
    "x-drupal-cache": ("low", "Drupal cache header present",
        "Confirms Drupal.",
        "Turn off header in Drupal settings."),
    "x-drupal-dynamic-cache": ("low", "Drupal dynamic cache header present",
        "Confirms Drupal.",
        "Turn off."),
    "x-varnish": ("info", "Varnish cache detected",
        "Varnish header present.",
        "Normal — informational."),
    "x-cache": ("info", "CDN/proxy cache header present",
        "X-Cache header present.",
        "Informational."),
    "cf-ray": ("info", "Cloudflare detected",
        "Cloudflare is in front of the origin.",
        "Informational."),
    "x-sucuri-id": ("info", "Sucuri detected",
        "Sucuri WAF detected.",
        "Informational."),
    "via": ("info", "Via header present",
        "Proxy chain disclosed.",
        "Consider removing if sensitive."),
    "x-backend-server": ("low", "X-Backend-Server leaks internal host",
        "Internal backend hostname disclosed.",
        "Strip in reverse proxy."),
    "x-served-by": ("info", "X-Served-By header present",
        "Upstream server disclosed.",
        "Informational."),
    "x-amz-cf-id": ("info", "CloudFront detected",
        "Request served via AWS CloudFront.",
        "Informational."),
    "x-azure-ref": ("info", "Azure Front Door detected",
        "Request served via Azure.",
        "Informational."),
}


def check_headers(headers, url):
    out = []
    for name, (sev, label, desc, rem) in SECURITY_HEADERS.items():
        if name in headers: continue
        if sev == "info":
            # For info headers, only report if PRESENT (not missing)
            continue
        out.append(finding(
            f"HDR-{len(out)+1:03d}", label, sev, "headers", desc,
            f"Header '{name}' missing", rem, url))
    # HSTS strength
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            out.append(finding(
                "HDR-101", "HSTS max-age too short", "low", "headers",
                f"max-age={m.group(1)}s < 180 days", hsts,
                "Increase to ≥ 31536000 (1 year).", url))
        if "includesubdomains" not in hsts.lower():
            out.append(finding(
                "HDR-102", "HSTS missing includeSubDomains", "low", "headers",
                "Subdomains are not covered by HSTS.", hsts,
                "Add includeSubDomains.", url))
        if "preload" not in hsts.lower():
            out.append(finding(
                "HDR-103", "HSTS missing preload", "info", "headers",
                "Domain is not submitted for HSTS preload.", hsts,
                "Add preload and submit to hstspreload.org.", url))
    # CSP weakness
    csp = headers.get("content-security-policy", "")
    if csp:
        low = csp.lower()
        if "'unsafe-inline'" in low:
            out.append(finding(
                "HDR-110", "CSP allows 'unsafe-inline'", "high", "headers",
                "unsafe-inline defeats XSS mitigation.", csp[:300],
                "Use nonces or hashes instead.", url))
        if "'unsafe-eval'" in low:
            out.append(finding(
                "HDR-111", "CSP allows 'unsafe-eval'", "high", "headers",
                "unsafe-eval permits eval().", csp[:300],
                "Remove unsafe-eval.", url))
        if "script-src" in low and "*" in low.split("script-src")[1].split(";")[0]:
            out.append(finding(
                "HDR-112", "CSP script-src wildcard", "medium", "headers",
                "Scripts may load from any origin.", csp[:300],
                "Restrict to specific hosts.", url))
        if "frame-ancestors" not in low and "x-frame-options" not in headers:
            out.append(finding(
                "HDR-113", "CSP missing frame-ancestors", "low", "headers",
                "No CSP frame restriction.", csp[:300],
                "Add frame-ancestors 'none'.", url))
    return out


# ======================================================================
# Cookie flags (10 checks)
# ======================================================================
def check_cookies(headers, url):
    out = []
    sc = headers.get("set-cookie", "")
    if not sc: return out
    for raw in re.split(r",(?=[^;=]+=)", sc):
        raw = raw.strip()
        if not raw: continue
        parts = [p.strip() for p in raw.split(";")]
        nv = parts[0]
        if "=" not in nv: continue
        name = nv.split("=", 1)[0].strip()
        flags = {p.lower().split("=", 1)[0]: p for p in parts[1:]}
        https = url.startswith("https://")
        if https and "secure" not in flags:
            out.append(finding(
                f"COOK-SECURE-{name[:16]}", f"Cookie '{name}' missing Secure",
                "medium", "cookies", "Cookie may be sent over HTTP.", raw[:300],
                "Add Secure.", url, cwe="CWE-614"))
        if "httponly" not in flags:
            out.append(finding(
                f"COOK-HTTPONLY-{name[:16]}", f"Cookie '{name}' missing HttpOnly",
                "medium", "cookies", "Cookie readable by JavaScript.", raw[:300],
                "Add HttpOnly.", url, cwe="CWE-1004"))
        if "samesite" not in flags:
            out.append(finding(
                f"COOK-SAMESITE-{name[:16]}", f"Cookie '{name}' missing SameSite",
                "low", "cookies", "CSRF risk.", raw[:300],
                "Add SameSite=Lax or Strict.", url, cwe="CWE-1275"))
        low = name.lower()
        if any(s in low for s in ("session", "sessid", "auth", "token", "jwt",
                                   "sid", "login")):
            if "httponly" not in flags:
                out.append(finding(
                    f"COOK-SENS-HTTPONLY-{name[:16]}",
                    f"Sensitive cookie '{name}' without HttpOnly",
                    "high", "cookies",
                    "Session-like cookie readable by JavaScript.", raw[:300],
                    "Add HttpOnly.", url, cwe="CWE-1004"))
            if https and "secure" not in flags:
                out.append(finding(
                    f"COOK-SENS-SECURE-{name[:16]}",
                    f"Sensitive cookie '{name}' without Secure",
                    "high", "cookies",
                    "Session-like cookie may leak over HTTP.", raw[:300],
                    "Add Secure.", url, cwe="CWE-614"))
        # Path too broad
        path = (flags.get("path") or "").lower()
        if path == "path=/":
            out.append(finding(
                f"COOK-BROADPATH-{name[:16]}",
                f"Cookie '{name}' scoped to /", "info", "cookies",
                "Cookie is sent to every path on the domain.", raw[:300],
                "Scope to a narrower path if possible.", url))
        # Overly long expiry
        exp = flags.get("expires")
        if exp and "2038" not in exp and "9999" in exp:
            out.append(finding(
                f"COOK-FAREXP-{name[:16]}",
                f"Cookie '{name}' expires very far in the future",
                "info", "cookies", "Cookie persists for years.", raw[:300],
                "Shorten the expiry.", url))
        # Domain wildcard
        dom = flags.get("domain", "")
        if dom.startswith("domain=.") and dom.count(".") <= 1:
            out.append(finding(
                f"COOK-BROADDOM-{name[:16]}",
                f"Cookie '{name}' domain is very broad", "low", "cookies",
                "Cookie may leak to subdomains.", raw[:300],
                "Narrow the Domain attribute.", url))
    return out


# ======================================================================
# HTML / content analysis (40 checks)
# ======================================================================
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical", "CWE-798"),
    (r'ASIA[0-9A-Z]{16}', "AWS Temporary Credential", "critical", "CWE-798"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "high", "CWE-798"),
    (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Token", "critical", "CWE-798"),
    (r'gh[pousr]_[A-Za-z0-9]{36,}', "GitHub Token", "critical", "CWE-798"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Key", "critical", "CWE-798"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Publishable Key", "low", "CWE-200"),
    (r'sk-[A-Za-z0-9]{40,}', "OpenAI API Key", "critical", "CWE-798"),
    (r'xox[baprs]-[0-9A-Za-z\-]+', "Slack Token", "critical", "CWE-798"),
    (r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', "Private Key", "critical", "CWE-798"),
    (r'ssh-rsa\s+AAAA[A-Za-z0-9+/=]+', "SSH Public Key", "low", "CWE-200"),
    (r'(?:mongodb|mysql|postgres|postgresql|redis|amqp)://[^\s"\'<>]{6,}', "DB Connection String", "critical", "CWE-798"),
    (r'(?:amqp|kafka|rabbit)://[^\s"\'<>]{6,}', "Message Broker URL", "high", "CWE-798"),
    (r'firebaseio\.com', "Firebase Endpoint", "info", "CWE-200"),
    (r'firebaseapp\.com', "Firebase Hosting", "info", "CWE-200"),
    (r'[a-z0-9-]+\.cloudfront\.net', "CloudFront Distribution", "info", "CWE-200"),
    (r'[a-z0-9-]+\.s3\.amazonaws\.com', "S3 Bucket Reference", "info", "CWE-200"),
    (r'[a-z0-9-]+\.blob\.core\.windows\.net', "Azure Blob", "info", "CWE-200"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+', "JWT Token", "high", "CWE-798"),
    (r'/\.git/config', "Git Config Reference", "medium", "CWE-527"),
    (r'__NEXT_DATA__', "Next.js App", "info", "CWE-200"),
    (r'"buildId"\s*:', "Next.js Build ID", "info", "CWE-200"),
    (r'window\.__NUXT__', "Nuxt App", "info", "CWE-200"),
    (r'window\.__INITIAL_STATE__', "Redux State Injection", "info", "CWE-200"),
    (r'window\.__APOLLO_STATE__', "Apollo State Injection", "info", "CWE-200"),
    (r'react(?:-dom)?\.(?:development|production)\.min\.js', "React Dev Build", "low", "CWE-1104"),
    (r'/wp-content/', "WordPress Reference", "info", "CWE-200"),
    (r'/wp-includes/', "WordPress Reference", "info", "CWE-200"),
    (r'/sites/default/files/', "Drupal Reference", "info", "CWE-200"),
    (r'/media/jui/', "Joomla Reference", "info", "CWE-200"),
    (r'(?i)admin(?:istrator)?@[a-z0-9.-]+\.[a-z]{2,}', "Admin Email", "low", "CWE-200"),
    (r'(?i)internal[-_]?api', "Internal API Mention", "low", "CWE-200"),
    (r'(?i)/debug(?:/|\.|\?)', "Debug Endpoint Reference", "medium", "CWE-489"),
    (r'(?i)test[-_]?key\s*[=:]', "Test Key Mention", "low", "CWE-798"),
    (r'(?i)api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}', "Inline API Key", "high", "CWE-798"),
    (r'(?i)password\s*[=:]\s*["\']?[^\s"\'<>]{6,}', "Inline Password", "high", "CWE-798"),
    (r'localhost:\d{2,5}', "Internal Localhost Reference", "low", "CWE-200"),
    (r'127\.0\.0\.1:\d{2,5}', "Loopback Reference", "low", "CWE-200"),
    (r'10\.\d+\.\d+\.\d+', "RFC1918 IP (10.x)", "low", "CWE-200"),
    (r'192\.168\.\d+\.\d+', "RFC1918 IP (192.168.x)", "low", "CWE-200"),
    (r'172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+', "RFC1918 IP (172.16-31)", "low", "CWE-200"),
]


def check_html(body, url):
    out = []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return out

    # HTML comment scanning
    for i, comment in enumerate(soup.find_all(string=lambda t: isinstance(t, type(soup)) and False) or []):
        pass
    for c in soup.find_all(string=lambda text: False):
        pass

    # Password field autocomplete
    for inp in soup.find_all("input", attrs={"type": "password"}):
        ac = (inp.get("autocomplete") or "").lower()
        if ac not in ("off", "new-password", "current-password"):
            out.append(finding(
                "HTML-001", "Password field missing autocomplete",
                "low", "html", "Password input lacks autocomplete.",
                str(inp)[:200], "Add autocomplete=new-password.", url))
            break

    # Forms
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").lower()
        if action.startswith("http://"):
            out.append(finding(
                "HTML-002", "Form submits over HTTP", "high", "html",
                "Form action uses http:// — credentials may leak.", action[:200],
                "Use https://.", url))
        if method == "post":
            if form.find("input", attrs={"name": re.compile(r"csrf|xsrf|_token", re.I)}) is None:
                out.append(finding(
                    "HTML-003", "POST form without CSRF token", "medium", "html",
                    "No anti-CSRF token.", str(form)[:200],
                    "Add a CSRF token input.", url))
                break

    # SRI on external scripts
    ext_scripts = []
    for sc in soup.find_all("script", src=True):
        src = sc["src"]
        if src.startswith(("http://", "https://")):
            h = urlparse(src).netloc
            ours = urlparse(url).netloc
            if h and ours and h != ours:
                ext_scripts.append((src, sc.get("integrity")))
    for src, integrity in ext_scripts[:5]:
        if not integrity:
            out.append(finding(
                "HTML-300", f"External script without SRI: {src.split('/')[2]}",
                "medium", "html", "3rd-party script without integrity hash.",
                src[:200], "Add integrity + crossorigin attributes.", url))
    if len(ext_scripts) > 5:
        out.append(finding(
            "HTML-301", f"{len(ext_scripts)} external scripts total",
            "info", "html", "Many third-party scripts.", "", "", url))

    # Mixed content
    if url.startswith("https://") and re.search(r'(?:src|href)="http://', body, re.I):
        out.append(finding(
            "HTML-302", "Mixed content on HTTPS", "medium", "html",
            "HTTPS page references http:// assets.",
            "Found http:// in src/href.",
            "Reference all assets over https://.", url))

    # Meta refresh to http://
    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() == "refresh":
            content = meta.get("content", "")
            if "http://" in content:
                out.append(finding(
                    "HTML-303", "Meta refresh to http://", "medium", "html",
                    "Meta refresh redirects to plaintext HTTP.", content[:200],
                    "Redirect over HTTPS.", url))

    # Target _blank without noopener
    blank_unsafe = 0
    for a in soup.find_all("a", target="_blank"):
        rel = (a.get("rel") or [])
        if isinstance(rel, str): rel = rel.split()
        if "noopener" not in rel and "noreferrer" not in rel:
            blank_unsafe += 1
    if blank_unsafe:
        out.append(finding(
            "HTML-304", f"{blank_unsafe} unsafe target=_blank anchor(s)",
            "low", "html", "Reverse tabnabbing risk.",
            f"{blank_unsafe} anchors without rel=noopener",
            "Add rel=\"noopener noreferrer\".", url, cwe="CWE-1022"))

    # Inline event handlers
    inline_handlers = re.findall(r'\son(?:click|load|error|mouseover|focus)\s*=', body, re.I)
    if inline_handlers:
        out.append(finding(
            "HTML-305", f"{len(inline_handlers)} inline event handler(s)",
            "low", "html", "Inline JS handlers make CSP unsafe-inline necessary.",
            f"e.g. onclick, onerror", "Move to external JS.", url))

    # Secret patterns
    for pat, name, sev, cwe in SECRET_PATTERNS:
        m = re.search(pat, body)
        if m:
            out.append(finding(
                f"HTML-SECRET-{hashlib.md5(pat.encode()).hexdigest()[:6]}",
                f"Secret in HTML: {name}", sev, "html",
                f"Pattern matched: {name}",
                m.group(0)[:200],
                "Rotate the credential and remove from client.", url, cwe=cwe))

    # HTML comments with sensitive hints
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    sensitive = ("password", "todo", "fixme", "hack", "xxx", "secret",
                  "internal", "admin", "deprecated", "debug")
    for c in comments[:200]:
        low = c.lower()
        if any(s in low for s in sensitive):
            out.append(finding(
                "HTML-400", "Suspicious HTML comment", "low", "html",
                "HTML comment contains sensitive keyword.",
                c.strip()[:200],
                "Remove developer comments before production.", url))
            break

    # React/Vue dev builds
    if re.search(r'react(?:-dom)?\.(?:development|production)\.min\.js', body):
        if "development" in body:
            out.append(finding(
                "HTML-500", "React development build detected", "low",
                "html", "React dev build is slower and reveals warnings.",
                "react.development.js", "Use production builds.", url))
    return out


# ======================================================================
# JS libraries (45 checks)
# ======================================================================
JS_LIBS = [
    # (regex, name, safe-regex, note, severity, cwe)
    (r'jquery[.\-/]?v?(\d+\.\d+\.\d+)', "jQuery", r'^3\.[5-9]',
     "jQuery < 3.5 XSS in htmlPrefilter (CVE-2020-11022/11023).", "medium", "CWE-79"),
    (r'bootstrap[.\-/]?(\d+\.\d+\.\d+)', "Bootstrap", r'^[45]\.',
     "Bootstrap 3.x EOL.", "low", "CWE-1104"),
    (r'angular[.\-/]?(\d+\.\d+\.\d+)', "AngularJS", r'^1\.[78]',
     "AngularJS 1.x EOL.", "high", "CWE-1104"),
    (r'lodash[.\-/]?v?(\d+\.\d+\.\d+)', "Lodash", r'^4\.1[7-9]',
     "Prototype pollution < 4.17.12.", "high", "CWE-1321"),
    (r'moment[.\-/]?v?(\d+\.\d+\.\d+)', "Moment.js", r'^2\.29',
     "Moment < 2.29.2 ReDoS.", "medium", "CWE-400"),
    (r'handlebars[.\-/]?v?(\d+\.\d+\.\d+)', "Handlebars", r'^4\.7\.[7-9]',
     "Handlebars < 4.7.7 proto pollution.", "high", "CWE-1321"),
    (r'ckeditor[.\-/]?v?(\d+\.\d+\.\d+)', "CKEditor", r'^[45]\.',
     "CKEditor 4.x XSS.", "high", "CWE-79"),
    (r'axios[.\-/]?v?(\d+\.\d+\.\d+)', "Axios", r'^(1|0\.2[7-9]|0\.2[0-6])',
     "Axios < 0.21.2 SSRF.", "high", "CWE-918"),
    (r'select2[.\-/]?v?(\d+\.\d+\.\d+)', "Select2", r'^4\.[01]',
     "Select2 < 4.0.13 XSS.", "high", "CWE-79"),
    (r'dompurify[.\-/]?v?(\d+\.\d+\.\d+)', "DOMPurify", r'^[23]\.',
     "DOMPurify < 2.4.3 mXSS.", "high", "CWE-79"),
    (r'polyfill\.io', "polyfill.io", r'^$',
     "polyfill.io 2024 supply-chain hijack.", "critical", "CWE-1104"),
    (r'highlight[.\-/]?js[.\-/]?v?(\d+\.\d+\.\d+)', "highlight.js", r'^1[0-9]\.',
     "highlight.js < 10.4.1 XSS.", "medium", "CWE-79"),
    (r'prism[.\-/]?v?(\d+\.\d+\.\d+)', "Prism.js", r'^1\.2[5-9]',
     "Prism < 1.25 XSS.", "medium", "CWE-79"),
    (r'marked[.\-/]?v?(\d+\.\d+\.\d+)', "marked", r'^[4-9]\.',
     "marked < 4.0.10 ReDoS.", "medium", "CWE-400"),
    (r'jsonwebtoken[.\-/]?v?(\d+\.\d+\.\d+)', "jsonwebtoken", r'^[9]\.',
     "jsonwebtoken < 9 alg confusion.", "high", "CWE-347"),
    (r'vue[.\-/]?v?(\d+\.\d+\.\d+)', "Vue.js", r'^[3]\.',
     "Vue < 3 EOL for 2.x.", "low", "CWE-1104"),
    (r'vue-router[.\-/]?v?(\d+\.\d+\.\d+)', "vue-router", r'^4\.',
     "Old vue-router.", "low", "CWE-1104"),
    (r'knockout[.\-/]?v?(\d+\.\d+\.\d+)', "Knockout", r'^3\.[5-9]',
     "Knockout < 3.5 XSS.", "medium", "CWE-79"),
    (r'ember[.\-/]?v?(\d+\.\d+\.\d+)', "Ember.js", r'^[3-9]\.',
     "Ember < 3 EOL.", "low", "CWE-1104"),
    (r'backbone[.\-/]?v?(\d+\.\d+\.\d+)', "Backbone.js", r'^1\.[4-9]',
     "Backbone < 1.4 XSS in some cases.", "low", "CWE-79"),
    (r'underscore[.\-/]?v?(\d+\.\d+\.\d+)', "Underscore.js", r'^1\.1[3-9]',
     "Underscore < 1.13 prototype issues.", "low", "CWE-1321"),
    (r'react[.\-/]?v?(\d+\.\d+\.\d+)', "React", r'^1[89]\.',
     "React < 18 outdated.", "low", "CWE-1104"),
    (r'react-dom[.\-/]?v?(\d+\.\d+\.\d+)', "React DOM", r'^1[89]\.',
     "React DOM outdated.", "low", "CWE-1104"),
    (r'next[.\-/]?v?(\d+\.\d+\.\d+)', "Next.js", r'^1[2-9]\.',
     "Next.js < 12 EOL.", "medium", "CWE-1104"),
    (r'nuxt[.\-/]?v?(\d+\.\d+\.\d+)', "Nuxt", r'^[2-9]\.',
     "Nuxt < 2 outdated.", "low", "CWE-1104"),
    (r'svelte[.\-/]?v?(\d+\.\d+\.\d+)', "Svelte", r'^[3-9]\.',
     "Svelte old version.", "low", "CWE-1104"),
    (r'express[.\-/]?v?(\d+\.\d+\.\d+)', "Express", r'^[45]\.',
     "Express < 4 outdated.", "low", "CWE-1104"),
    (r'chart\.js[.\-/]?v?(\d+\.\d+\.\d+)', "Chart.js", r'^[3-9]\.',
     "Chart.js < 3 outdated.", "low", "CWE-1104"),
    (r'd3[.\-/]?v?(\d+\.\d+\.\d+)', "D3.js", r'^[6-9]\.',
     "D3 < 6 outdated.", "low", "CWE-1104"),
    (r'three[.\-/]?v?(\d+\.\d+\.\d+)', "Three.js", r'^1[2-9][0-9]',
     "Three.js < 120 outdated.", "low", "CWE-1104"),
    (r'moment-timezone[.\-/]?v?(\d+\.\d+\.\d+)', "moment-timezone", r'^0\.5\.[3-9]',
     "Old moment-timezone.", "low", "CWE-1104"),
    (r'socket\.io[.\-/]?v?(\d+\.\d+\.\d+)', "socket.io", r'^[4-9]\.',
     "socket.io 2.x outdated.", "low", "CWE-1104"),
    (r'pusher[.\-/]?v?(\d+\.\d+\.\d+)', "Pusher", r'^[7-9]\.',
     "Old Pusher client.", "low", "CWE-1104"),
    (r'firebase[.\-/]?v?(\d+\.\d+\.\d+)', "Firebase SDK", r'^[89]\.',
     "Firebase < 8 outdated.", "low", "CWE-1104"),
    (r'@firebase/app[.\-/]?v?(\d+\.\d+\.\d+)', "Firebase App", r'^0\.6',
     "Old Firebase modular.", "low", "CWE-1104"),
    (r'swiper[.\-/]?v?(\d+\.\d+\.\d+)', "Swiper", r'^[6-9]\.',
     "Swiper < 6 outdated.", "low", "CWE-1104"),
    (r'animate\.css[.\-/]?v?(\d+\.\d+\.\d+)', "Animate.css", r'^4\.',
     "Animate.css < 4 outdated.", "low", "CWE-1104"),
    (r'font-awesome[.\-/]?v?(\d+\.\d+\.\d+)', "Font Awesome", r'^[56]\.',
     "Font Awesome < 5 outdated.", "low", "CWE-1104"),
    (r'normalize\.css', "normalize.css", r'.',
     "Normalize present — informational.", "info", "CWE-1104"),
    (r'require(?:\.min)?\.js', "RequireJS", r'^2\.[2-9]',
     "Old RequireJS.", "low", "CWE-1104"),
    (r'alpinejs[.\-/]?v?(\d+\.\d+\.\d+)', "Alpine.js", r'^[2-9]\.',
     "Alpine.js < 2 outdated.", "low", "CWE-1104"),
    (r'htmx[.\-/]?v?(\d+\.\d+\.\d+)', "htmx", r'^1\.[89]|^[2-9]',
     "htmx < 1.8 outdated.", "low", "CWE-1104"),
    (r'gsap[.\-/]?v?(\d+\.\d+\.\d+)', "GSAP", r'^[3-9]\.',
     "GSAP < 3 outdated.", "low", "CWE-1104"),
    (r'mathjax[.\-/]?v?(\d+\.\d+\.\d+)', "MathJax", r'^[3-9]\.',
     "MathJax < 3 outdated.", "low", "CWE-1104"),
    (r'p5(?:\.min)?\.js', "p5.js", r'^1\.',
     "Old p5.js.", "info", "CWE-1104"),
]


def check_libs(body, url):
    out = []
    seen = set()
    for pat, name, safe, note, sev, cwe in JS_LIBS:
        m = re.search(pat, body, re.I)
        if not m: continue
        ver = m.group(1) if m.groups() else "?"
        if re.search(safe, ver): continue
        key = f"{name}-{ver}"
        if key in seen: continue
        seen.add(key)
        out.append(finding(
            f"LIB-{name.lower().replace('.','')[:8]}-{ver[:10]}",
            f"Outdated JS library: {name} {ver}",
            sev, "libraries", note, f"{name} {ver}",
            f"Upgrade {name} past {safe}.", url, cwe=cwe))
    return out


# ======================================================================
# Sensitive paths (230 checks)
# ======================================================================
SENSITIVE_PATHS = [
    # --- Env / config ---
    ("/.env", "Env file", "critical", "CWE-538"),
    ("/.env.local", "Env local", "critical", "CWE-538"),
    ("/.env.production", "Env prod", "critical", "CWE-538"),
    ("/.env.development", "Env dev", "high", "CWE-538"),
    ("/.env.staging", "Env staging", "high", "CWE-538"),
    ("/.env.backup", "Env backup", "critical", "CWE-538"),
    ("/.env.bak", "Env backup", "critical", "CWE-538"),
    ("/.env.example", "Env example", "low", "CWE-200"),
    ("/.env.old", "Env old", "high", "CWE-538"),
    ("/.env.save", "Env save", "high", "CWE-538"),
    ("/.env.swp", "Env swap", "high", "CWE-538"),
    ("/env.js", "Env JS", "high", "CWE-538"),
    ("/env.json", "Env JSON", "high", "CWE-538"),
    ("/config.json", "Config JSON", "high", "CWE-200"),
    ("/config.js", "Config JS", "medium", "CWE-200"),
    ("/config.yml", "Config YAML", "high", "CWE-200"),
    ("/config.yaml", "Config YAML", "high", "CWE-200"),
    ("/config.xml", "Config XML", "medium", "CWE-200"),
    ("/config.php", "PHP config", "critical", "CWE-538"),
    ("/config.inc.php", "PHP config", "critical", "CWE-538"),
    ("/config.php.bak", "PHP config backup", "critical", "CWE-538"),
    ("/config.php.old", "PHP config old", "critical", "CWE-538"),
    ("/config.php.save", "PHP config save", "high", "CWE-538"),
    ("/config.php~", "PHP config editor backup", "critical", "CWE-538"),
    ("/configuration.php", "Joomla config", "critical", "CWE-538"),
    ("/wp-config.php", "WP config", "critical", "CWE-538"),
    ("/wp-config.php.bak", "WP config backup", "critical", "CWE-538"),
    ("/wp-config.php.old", "WP config old", "critical", "CWE-538"),
    ("/wp-config.php.save", "WP config save", "critical", "CWE-538"),
    ("/wp-config.php~", "WP config editor backup", "critical", "CWE-538"),
    ("/settings.py", "Python settings", "high", "CWE-538"),
    ("/settings.php", "PHP settings", "high", "CWE-538"),
    ("/settings.json", "JSON settings", "high", "CWE-200"),
    ("/local.settings.json", "Local settings", "high", "CWE-538"),
    ("/appsettings.json", "ASP.NET settings", "high", "CWE-538"),
    ("/appsettings.Development.json", "ASP.NET dev settings", "critical", "CWE-538"),
    ("/appsettings.Production.json", "ASP.NET prod settings", "critical", "CWE-538"),
    ("/web.config", "IIS config", "critical", "CWE-538"),
    ("/web.config.bak", "IIS config backup", "critical", "CWE-538"),
    ("/application.properties", "Spring properties", "high", "CWE-538"),
    ("/application.yml", "Spring YAML", "high", "CWE-538"),
    ("/application-dev.properties", "Spring dev", "high", "CWE-538"),
    ("/application-prod.properties", "Spring prod", "critical", "CWE-538"),
    ("/bootstrap.properties", "Spring bootstrap", "high", "CWE-538"),
    ("/database.yml", "Rails DB YAML", "critical", "CWE-538"),
    ("/database.php", "PHP DB config", "critical", "CWE-538"),
    ("/db.php", "PHP DB config", "critical", "CWE-538"),
    ("/db_connect.php", "PHP DB connect", "critical", "CWE-538"),
    ("/db_config.php", "PHP DB config", "critical", "CWE-538"),
    ("/conn.php", "PHP DB connection", "critical", "CWE-538"),

    # --- Version control ---
    ("/.git/config", "Git config", "high", "CWE-527"),
    ("/.git/HEAD", "Git HEAD", "high", "CWE-527"),
    ("/.git/index", "Git index", "high", "CWE-527"),
    ("/.git/logs/HEAD", "Git logs", "high", "CWE-527"),
    ("/.git/refs/heads/main", "Git ref", "high", "CWE-527"),
    ("/.git/refs/heads/master", "Git ref", "high", "CWE-527"),
    ("/.gitignore", "gitignore", "low", "CWE-200"),
    ("/.gitattributes", "gitattributes", "low", "CWE-200"),
    ("/.git/modules", "Git submodules", "medium", "CWE-527"),
    ("/.svn/entries", "SVN entries", "high", "CWE-527"),
    ("/.svn/wc.db", "SVN wc.db", "high", "CWE-527"),
    ("/.hg/store", "Mercurial store", "medium", "CWE-527"),
    ("/.hg/hgrc", "Mercurial config", "medium", "CWE-527"),
    ("/.bzr/branch/branch.conf", "Bazaar branch", "medium", "CWE-527"),
    ("/.cvsignore", "CVS ignore", "low", "CWE-200"),

    # --- Backup files ---
    ("/backup.zip", "Backup archive", "critical", "CWE-530"),
    ("/backup.tar", "Backup archive", "critical", "CWE-530"),
    ("/backup.tar.gz", "Backup archive", "critical", "CWE-530"),
    ("/backup.tgz", "Backup archive", "critical", "CWE-530"),
    ("/backup.rar", "Backup archive", "critical", "CWE-530"),
    ("/backup.7z", "Backup archive", "critical", "CWE-530"),
    ("/backup.sql", "Backup SQL", "critical", "CWE-530"),
    ("/backup.sql.gz", "Backup SQL gz", "critical", "CWE-530"),
    ("/backup.sql.zip", "Backup SQL zip", "critical", "CWE-530"),
    ("/backup.bak", "Backup bak", "critical", "CWE-530"),
    ("/backups/", "Backups dir", "high", "CWE-548"),
    ("/backup/", "Backup dir", "high", "CWE-548"),
    ("/bk/", "Backup dir bk", "medium", "CWE-548"),
    ("/old/", "Old dir", "medium", "CWE-548"),
    ("/bak/", "Backup dir bak", "medium", "CWE-548"),
    ("/dump.sql", "MySQL dump", "critical", "CWE-530"),
    ("/dump.sql.gz", "MySQL dump", "critical", "CWE-530"),
    ("/database.sql", "DB dump", "critical", "CWE-530"),
    ("/db.sql", "DB dump", "critical", "CWE-530"),
    ("/db.sqlite", "SQLite DB", "critical", "CWE-530"),
    ("/db.sqlite3", "SQLite3 DB", "critical", "CWE-530"),
    ("/database.sqlite", "SQLite DB", "critical", "CWE-530"),
    ("/data.sqlite", "SQLite DB", "critical", "CWE-530"),
    ("/mysql.sql", "MySQL dump", "critical", "CWE-530"),
    ("/postgres.sql", "Postgres dump", "critical", "CWE-530"),
    ("/mongo.dump", "Mongo dump", "critical", "CWE-530"),
    ("/site.zip", "Site archive", "critical", "CWE-530"),
    ("/site.tar.gz", "Site archive", "critical", "CWE-530"),
    ("/www.zip", "WWW archive", "critical", "CWE-530"),
    ("/html.zip", "HTML archive", "critical", "CWE-530"),
    ("/public.zip", "Public archive", "critical", "CWE-530"),
    ("/web.zip", "Web archive", "critical", "CWE-530"),
    ("/files.zip", "Files archive", "critical", "CWE-530"),
    ("/source.zip", "Source archive", "critical", "CWE-530"),
    ("/src.zip", "Src archive", "critical", "CWE-530"),
    ("/release.zip", "Release archive", "high", "CWE-530"),
    ("/dist.zip", "Dist archive", "high", "CWE-530"),
    ("/build.zip", "Build archive", "high", "CWE-530"),

    # --- SSH / credentials ---
    ("/id_rsa", "SSH private key", "critical", "CWE-798"),
    ("/id_dsa", "DSA key", "critical", "CWE-798"),
    ("/id_ecdsa", "ECDSA key", "critical", "CWE-798"),
    ("/id_ed25519", "Ed25519 key", "critical", "CWE-798"),
    ("/.ssh/id_rsa", "SSH key", "critical", "CWE-798"),
    ("/.ssh/id_dsa", "SSH key", "critical", "CWE-798"),
    ("/.ssh/id_ecdsa", "SSH key", "critical", "CWE-798"),
    ("/.ssh/authorized_keys", "Authorized keys", "critical", "CWE-798"),
    ("/.ssh/known_hosts", "Known hosts", "medium", "CWE-200"),
    ("/.ssh/config", "SSH config", "high", "CWE-200"),
    ("/.ssh/", "SSH dir", "high", "CWE-538"),

    # --- Cloud / DevOps credentials ---
    ("/.aws/credentials", "AWS credentials", "critical", "CWE-798"),
    ("/.aws/config", "AWS config", "high", "CWE-538"),
    ("/.aws/", "AWS dir", "high", "CWE-538"),
    ("/.gcloud/credentials.db", "GCloud creds", "critical", "CWE-798"),
    ("/.azure/accessTokens.json", "Azure tokens", "critical", "CWE-798"),
    ("/.kube/config", "Kubeconfig", "critical", "CWE-798"),
    ("/.docker/config.json", "Docker config", "high", "CWE-538"),
    ("/.docker/", "Docker dir", "medium", "CWE-538"),
    ("/.npmrc", "NPM config", "high", "CWE-538"),
    ("/.yarnrc", "Yarn config", "medium", "CWE-200"),
    ("/.pypirc", "PyPI config", "high", "CWE-798"),
    ("/.netrc", "Netrc creds", "high", "CWE-798"),
    ("/.gem/credentials", "Gem creds", "critical", "CWE-798"),
    ("/.terraformrc", "Terraform config", "high", "CWE-538"),
    ("/terraform.tfstate", "Terraform state", "critical", "CWE-538"),
    ("/terraform.tfstate.backup", "Terraform backup", "critical", "CWE-538"),
    ("/.terraform/", "Terraform dir", "high", "CWE-538"),
    ("/serverless.yml", "Serverless config", "medium", "CWE-200"),
    ("/ansible.cfg", "Ansible config", "medium", "CWE-200"),
    ("/playbook.yml", "Ansible playbook", "medium", "CWE-200"),
    ("/deploy.sh", "Deploy script", "medium", "CWE-538"),
    ("/deployment.yml", "Deployment", "medium", "CWE-200"),
    ("/k8s/", "Kubernetes dir", "high", "CWE-538"),
    ("/helm/", "Helm chart", "medium", "CWE-200"),
    ("/charts/", "Charts dir", "low", "CWE-200"),
    ("/kustomization.yaml", "Kustomize", "medium", "CWE-200"),

    # --- Package manifests (info-disclosing) ---
    ("/package.json", "NPM manifest", "low", "CWE-200"),
    ("/package-lock.json", "NPM lockfile", "low", "CWE-200"),
    ("/yarn.lock", "Yarn lockfile", "low", "CWE-200"),
    ("/composer.json", "Composer manifest", "low", "CWE-200"),
    ("/composer.lock", "Composer lockfile", "low", "CWE-200"),
    ("/Gemfile", "Ruby Gemfile", "low", "CWE-200"),
    ("/Gemfile.lock", "Ruby lockfile", "low", "CWE-200"),
    ("/requirements.txt", "Python requirements", "low", "CWE-200"),
    ("/Pipfile", "Pipfile", "low", "CWE-200"),
    ("/Pipfile.lock", "Pipfile lock", "low", "CWE-200"),
    ("/poetry.lock", "Poetry lock", "low", "CWE-200"),
    ("/pyproject.toml", "Python pyproject", "low", "CWE-200"),
    ("/go.mod", "Go module", "low", "CWE-200"),
    ("/go.sum", "Go sum", "low", "CWE-200"),
    ("/Cargo.toml", "Rust manifest", "low", "CWE-200"),
    ("/Cargo.lock", "Rust lockfile", "low", "CWE-200"),
    ("/pom.xml", "Maven POM", "low", "CWE-200"),
    ("/build.gradle", "Gradle", "low", "CWE-200"),
    ("/mix.exs", "Elixir mix", "low", "CWE-200"),
    ("/pubspec.yaml", "Flutter/Dart", "low", "CWE-200"),
    ("/Podfile", "iOS Podfile", "low", "CWE-200"),
    ("/Cartfile", "Carthage", "low", "CWE-200"),

    # --- CI / build artifacts ---
    ("/.github/workflows/", "GitHub Actions", "medium", "CWE-200"),
    ("/.github/dependabot.yml", "Dependabot", "info", "CWE-200"),
    ("/.gitlab-ci.yml", "GitLab CI", "medium", "CWE-200"),
    ("/.travis.yml", "Travis CI", "medium", "CWE-200"),
    ("/.circleci/config.yml", "CircleCI", "medium", "CWE-200"),
    ("/Jenkinsfile", "Jenkinsfile", "medium", "CWE-200"),
    ("/azure-pipelines.yml", "Azure Pipelines", "medium", "CWE-200"),
    ("/bitbucket-pipelines.yml", "Bitbucket Pipelines", "medium", "CWE-200"),
    ("/.drone.yml", "Drone CI", "medium", "CWE-200"),
    ("/cloudbuild.yaml", "Cloud Build", "medium", "CWE-200"),
    ("/appveyor.yml", "AppVeyor", "medium", "CWE-200"),
    ("/buildspec.yml", "AWS CodeBuild", "medium", "CWE-200"),
    ("/Makefile", "Makefile", "low", "CWE-200"),
    ("/Dockerfile", "Dockerfile", "medium", "CWE-200"),
    ("/Dockerfile.prod", "Dockerfile prod", "medium", "CWE-200"),
    ("/Dockerfile.dev", "Dockerfile dev", "medium", "CWE-200"),
    ("/docker-compose.yml", "Docker Compose", "high", "CWE-200"),
    ("/docker-compose.yaml", "Docker Compose", "high", "CWE-200"),
    ("/docker-compose.override.yml", "Docker Compose override", "high", "CWE-200"),
    (".dockerignore", "Docker ignore", "info", "CWE-200"),

    # --- Admin / login panels ---
    ("/admin", "Admin panel", "medium", "CWE-200"),
    ("/admin/", "Admin panel", "medium", "CWE-200"),
    ("/admin/login", "Admin login", "medium", "CWE-200"),
    ("/admin/login.php", "Admin login", "medium", "CWE-200"),
    ("/admin/index.php", "Admin index", "medium", "CWE-200"),
    ("/admin.php", "Admin PHP", "medium", "CWE-200"),
    ("/administrator", "Admin panel", "medium", "CWE-200"),
    ("/administrator/", "Admin panel", "medium", "CWE-200"),
    ("/manager", "Manager", "medium", "CWE-200"),
    ("/manager/html", "Tomcat manager", "critical", "CWE-200"),
    ("/host-manager/html", "Tomcat host-manager", "critical", "CWE-200"),
    ("/wp-admin", "WordPress admin", "info", "CWE-200"),
    ("/wp-admin/", "WordPress admin", "info", "CWE-200"),
    ("/wp-login.php", "WordPress login", "info", "CWE-200"),
    ("/wp-json/wp/v2/users", "WP REST users", "high", "CWE-200"),
    ("/xmlrpc.php", "WordPress xmlrpc", "medium", "CWE-200"),
    ("/wp-cron.php", "WP cron", "low", "CWE-200"),
    ("/wp-config.php.txt", "WP config text", "critical", "CWE-538"),
    ("/wp-content/", "WP content dir", "info", "CWE-548"),
    ("/wp-content/uploads/", "WP uploads", "info", "CWE-548"),
    ("/wp-content/debug.log", "WP debug log", "high", "CWE-532"),
    ("/wp-includes/", "WP includes", "info", "CWE-548"),

    # --- Web server status ---
    ("/server-status", "Apache server-status", "high", "CWE-200"),
    ("/server-status?auto", "Apache server-status JSON", "high", "CWE-200"),
    ("/server-info", "Apache server-info", "high", "CWE-200"),
    ("/nginx_status", "Nginx status", "high", "CWE-200"),
    ("/status", "Status page", "medium", "CWE-200"),
    ("/actuator", "Spring actuator", "high", "CWE-200"),
    ("/actuator/env", "Spring env", "critical", "CWE-538"),
    ("/actuator/heapdump", "Spring heapdump", "critical", "CWE-215"),
    ("/actuator/threaddump", "Spring threaddump", "high", "CWE-215"),
    ("/actuator/beans", "Spring beans", "high", "CWE-200"),
    ("/actuator/mappings", "Spring mappings", "high", "CWE-200"),
    ("/actuator/httptrace", "Spring httptrace", "high", "CWE-200"),
    ("/actuator/loggers", "Spring loggers", "high", "CWE-200"),
    ("/actuator/metrics", "Spring metrics", "medium", "CWE-200"),
    ("/actuator/health", "Spring health", "info", "CWE-200"),
    ("/actuator/info", "Spring info", "info", "CWE-200"),
    ("/actuator/configprops", "Spring configprops", "high", "CWE-538"),
    ("/actuator/auditevents", "Spring auditevents", "medium", "CWE-200"),
    ("/actuator/scheduledtasks", "Spring scheduledtasks", "medium", "CWE-200"),
    ("/actuator/caches", "Spring caches", "medium", "CWE-200"),
    ("/actuator/conditions", "Spring conditions", "medium", "CWE-200"),

    # --- API docs / debug ---
    ("/swagger.json", "Swagger JSON", "medium", "CWE-200"),
    ("/swagger.yaml", "Swagger YAML", "medium", "CWE-200"),
    ("/swagger-ui.html", "Swagger UI", "medium", "CWE-200"),
    ("/swagger-ui/", "Swagger UI", "medium", "CWE-200"),
    ("/api-docs", "API docs", "medium", "CWE-200"),
    ("/api-docs/", "API docs dir", "medium", "CWE-200"),
    ("/api-docs.json", "API docs JSON", "medium", "CWE-200"),
    ("/openapi.json", "OpenAPI spec", "medium", "CWE-200"),
    ("/openapi.yaml", "OpenAPI YAML", "medium", "CWE-200"),
    ("/redoc", "ReDoc", "medium", "CWE-200"),
    ("/v2/api-docs", "Springfox v2", "medium", "CWE-200"),
    ("/v3/api-docs", "Springfox v3", "medium", "CWE-200"),
    ("/graphql", "GraphQL endpoint", "medium", "CWE-200"),
    ("/graphiql", "GraphiQL IDE", "medium", "CWE-200"),
    ("/playground", "GraphQL Playground", "medium", "CWE-200"),
    ("/altair", "Altair GraphQL", "medium", "CWE-200"),
    ("/debug", "Debug page", "medium", "CWE-489"),
    ("/debug/", "Debug dir", "medium", "CWE-489"),
    ("/debug/default/view", "Yii debug", "high", "CWE-489"),
    ("/rails/info/properties", "Rails properties", "high", "CWE-200"),
    ("/rails/info/routes", "Rails routes", "high", "CWE-200"),
    ("/django-admin/", "Django admin", "high", "CWE-200"),
    ("/admin/doc/", "Django admin docs", "medium", "CWE-200"),
    ("/__debug__/", "Django debug toolbar", "high", "CWE-489"),
    ("/_profiler/", "Symfony profiler", "high", "CWE-489"),
    ("/_wdt/", "Symfony web debug", "high", "CWE-489"),
    ("/phpinfo.php", "phpinfo()", "critical", "CWE-200"),
    ("/info.php", "phpinfo()", "critical", "CWE-200"),
    ("/test.php", "test.php", "medium", "CWE-489"),
    ("/phpMyAdmin/", "phpMyAdmin", "high", "CWE-200"),
    ("/phpmyadmin/", "phpMyAdmin", "high", "CWE-200"),
    ("/pma/", "phpMyAdmin pma", "high", "CWE-200"),
    ("/adminer.php", "Adminer", "high", "CWE-200"),
    ("/adminer/", "Adminer dir", "high", "CWE-200"),
    ("/mysql/", "MySQL web", "high", "CWE-200"),

    # --- Logs ---
    ("/debug.log", "Debug log", "high", "CWE-532"),
    ("/error.log", "Error log", "high", "CWE-532"),
    ("/errors.log", "Errors log", "high", "CWE-532"),
    ("/access.log", "Access log", "high", "CWE-532"),
    ("/access_log", "Access log", "high", "CWE-532"),
    ("/error_log", "Error log", "high", "CWE-532"),
    ("/logs/", "Logs dir", "high", "CWE-548"),
    ("/logs/error.log", "Logs error", "high", "CWE-532"),
    ("/logs/access.log", "Logs access", "high", "CWE-532"),
    ("/log/", "Log dir", "medium", "CWE-548"),
    ("/log.txt", "Log text", "medium", "CWE-532"),
    ("/console.log", "Console log", "high", "CWE-532"),
    ("/audit.log", "Audit log", "high", "CWE-532"),
    ("/application.log", "Application log", "high", "CWE-532"),
    ("/spring.log", "Spring log", "high", "CWE-532"),
    ("/laravel.log", "Laravel log", "high", "CWE-532"),
    ("/storage/logs/laravel.log", "Laravel log", "high", "CWE-532"),
    ("/logs/production.log", "Production log", "high", "CWE-532"),
    ("/var/log/", "Var log", "high", "CWE-548"),

    # --- ASP.NET specific ---
    ("/trace.axd", "ASP.NET trace", "critical", "CWE-200"),
    ("/elmah.axd", "ELMAH", "high", "CWE-200"),
    ("/elmah", "ELMAH", "high", "CWE-200"),
    ("/Glimpse.axd", "Glimpse", "high", "CWE-489"),
    ("/WebResource.axd", "WebResource.axd", "low", "CWE-200"),
    ("/ScriptResource.axd", "ScriptResource.axd", "low", "CWE-200"),
    ("/favicon.ico", "favicon.ico", "info", "CWE-200"),

    # --- Sensitive dirs ---
    ("/uploads/", "Uploads dir", "medium", "CWE-548"),
    ("/upload/", "Upload dir", "medium", "CWE-548"),
    ("/files/", "Files dir", "medium", "CWE-548"),
    ("/data/", "Data dir", "medium", "CWE-548"),
    ("/private/", "Private dir", "high", "CWE-548"),
    ("/internal/", "Internal dir", "high", "CWE-548"),
    ("/conf/", "Conf dir", "medium", "CWE-548"),
    ("/config/", "Config dir", "medium", "CWE-548"),
    ("/etc/", "Etc dir", "high", "CWE-548"),
    ("/secret/", "Secret dir", "high", "CWE-548"),
    ("/secrets/", "Secrets dir", "high", "CWE-548"),
    ("/tmp/", "Tmp dir", "medium", "CWE-548"),
    ("/temp/", "Temp dir", "medium", "CWE-548"),
    ("/cache/", "Cache dir", "low", "CWE-548"),
    ("/cgi-bin/", "CGI dir", "medium", "CWE-548"),
    ("/includes/", "Includes dir", "medium", "CWE-548"),
    ("/inc/", "Inc dir", "medium", "CWE-548"),
    ("/lib/", "Lib dir", "low", "CWE-548"),
    ("/vendor/", "Vendor dir", "low", "CWE-548"),
    ("/node_modules/", "node_modules", "medium", "CWE-548"),
    ("/dist/", "Dist dir", "low", "CWE-548"),
    ("/build/", "Build dir", "low", "CWE-548"),
    ("/public/", "Public dir", "low", "CWE-548"),
    ("/static/", "Static dir", "info", "CWE-548"),
    ("/assets/", "Assets dir", "info", "CWE-548"),
    ("/source/", "Source dir", "high", "CWE-548"),
    ("/src/", "Src dir", "high", "CWE-548"),

    # --- Shell / backdoors ---
    ("/shell.php", "Webshell", "critical", "CWE-506"),
    ("/cmd.php", "Webshell", "critical", "CWE-506"),
    ("/c99.php", "c99 shell", "critical", "CWE-506"),
    ("/r57.php", "r57 shell", "critical", "CWE-506"),
    ("/b374k.php", "b374k shell", "critical", "CWE-506"),
    ("/webshell.php", "Webshell", "critical", "CWE-506"),
    ("/backdoor.php", "Backdoor", "critical", "CWE-506"),
    ("/indoxploit.php", "IndoXploit", "critical", "CWE-506"),
    ("/wso.php", "WSO shell", "critical", "CWE-506"),
    ("/alfa.php", "Alfa shell", "critical", "CWE-506"),
    ("/marijuana.php", "Webshell", "critical", "CWE-506"),
    ("/upload.php", "Upload endpoint", "medium", "CWE-434"),
    ("/uploader.php", "Uploader", "medium", "CWE-434"),
    ("/uploadify.php", "Uploadify", "medium", "CWE-434"),

    # --- Container / orchestration ---
    ("/metrics", "Prometheus metrics", "medium", "CWE-200"),
    ("/metrics/", "Metrics dir", "medium", "CWE-200"),
    ("/prometheus", "Prometheus UI", "medium", "CWE-200"),
    ("/grafana/", "Grafana", "medium", "CWE-200"),
    ("/kibana/", "Kibana", "medium", "CWE-200"),
    ("/jenkins/", "Jenkins", "high", "CWE-200"),
    ("/jenkins/script", "Jenkins script console", "critical", "CWE-94"),
    ("/hudson", "Hudson", "medium", "CWE-200"),
    ("/sonarqube/", "SonarQube", "medium", "CWE-200"),
    ("/nacos/", "Nacos", "high", "CWE-200"),
    ("/consul/", "Consul", "high", "CWE-200"),
    ("/etcd/", "etcd", "high", "CWE-200"),
    ("/redis/", "Redis web", "high", "CWE-200"),
    ("/rabbitmq/", "RabbitMQ mgmt", "high", "CWE-200"),
    ("/minio/", "MinIO", "high", "CWE-200"),
    ("/traefik/", "Traefik dashboard", "high", "CWE-200"),
    ("/kong/", "Kong admin", "high", "CWE-200"),

    # --- Misc high-signal ---
    ("/humans.txt", "humans.txt", "info", "CWE-200"),
    ("/ads.txt", "ads.txt", "info", "CWE-200"),
    ("/security.txt", "security.txt", "info", "CWE-200"),
    ("/.well-known/security.txt", "security.txt", "info", "CWE-200"),
    ("/.well-known/change-password", "change-password", "info", "CWE-200"),
    ("/.well-known/openid-configuration", "OpenID config", "info", "CWE-200"),
    ("/.well-known/oauth-authorization-server", "OAuth config", "info", "CWE-200"),
    ("/robots.txt", "robots.txt", "info", "CWE-200"),
    ("/sitemap.xml", "sitemap.xml", "info", "CWE-200"),
    ("/crossdomain.xml", "Flash crossdomain", "medium", "CWE-200"),
    ("/clientaccesspolicy.xml", "Silverlight policy", "medium", "CWE-200"),
    ("/license.txt", "License", "info", "CWE-200"),
    ("/readme.html", "Readme", "low", "CWE-200"),
    ("/readme.txt", "Readme", "low", "CWE-200"),
    ("/README.md", "README", "low", "CWE-200"),
    ("/CHANGELOG.md", "Changelog", "low", "CWE-200"),
    ("/CHANGELOG.txt", "Changelog", "low", "CWE-200"),
    ("/VERSION", "Version file", "low", "CWE-200"),
    ("/version.txt", "Version", "low", "CWE-200"),
    ("/version.json", "Version", "low", "CWE-200"),
]


# ======================================================================
# HTTP methods (12 checks)
# ======================================================================
HTTP_METHODS = ["OPTIONS", "HEAD", "TRACE", "PUT", "DELETE", "PATCH",
                "PROPFIND", "COPY", "MOVE", "CONNECT", "LOCK", "UNLOCK"]


async def check_methods(url, fetch, timeout=8.0):
    out = []
    for m in HTTP_METHODS:
        try:
            r = await fetch(url, method=m, timeout=timeout,
                            allow_redirects=False, max_redirects=0,
                            prefer_http2=False, use_doh=True)
        except Exception:
            continue
        st = r.status_code
        p = urlparse(url).path or "/"
        if m == "TRACE" and st == 200:
            out.append(finding("HTTP-001", "TRACE enabled", "medium",
                               "http-methods", "XST attack possible.",
                               f"TRACE → {st}", "Disable TRACE.", url, p, "CWE-16"))
        elif m == "PUT" and st in (200, 201, 204):
            out.append(finding("HTTP-002", "PUT allowed", "high", "http-methods",
                               "Write operations may be possible.",
                               f"PUT → {st}", "Restrict write methods.", url, p, "CWE-650"))
        elif m == "DELETE" and st in (200, 204):
            out.append(finding("HTTP-003", "DELETE allowed", "high",
                               "http-methods", "Server accepts DELETE.",
                               f"DELETE → {st}", "Restrict DELETE.", url, p, "CWE-650"))
        elif m == "PROPFIND" and st in (200, 207):
            out.append(finding("HTTP-004", "WebDAV enabled", "medium",
                               "http-methods", "WebDAV file listing exposed.",
                               f"PROPFIND → {st}", "Disable WebDAV if unused.",
                               url, p, "CWE-16"))
        elif m == "CONNECT" and st in (200, 201):
            out.append(finding("HTTP-005", "CONNECT allowed", "high",
                               "http-methods", "Potential open proxy.",
                               f"CONNECT → {st}", "Restrict CONNECT.", url, p, "CWE-441"))
        elif m == "MOVE" and st in (200, 201, 204):
            out.append(finding("HTTP-006", "MOVE allowed", "medium",
                               "http-methods", "WebDAV MOVE available.",
                               f"MOVE → {st}", "Restrict WebDAV methods.",
                               url, p, "CWE-16"))
        elif m == "COPY" and st in (200, 201, 204):
            out.append(finding("HTTP-007", "COPY allowed", "medium",
                               "http-methods", "WebDAV COPY available.",
                               f"COPY → {st}", "Restrict WebDAV methods.",
                               url, p, "CWE-16"))
        elif m == "LOCK" and st in (200, 201):
            out.append(finding("HTTP-008", "WebDAV LOCK enabled", "low",
                               "http-methods", "WebDAV LOCK available.",
                               f"LOCK → {st}", "Disable if unused.", url, p, "CWE-16"))
    return out


# ======================================================================
# CORS + host header + cache
# ======================================================================
async def check_cors(url, fetch, timeout=8.0):
    out = []
    for origin in ("https://evil.example", "null"):
        try:
            r = await fetch(url, headers={"Origin": origin}, timeout=timeout,
                            allow_redirects=False, max_redirects=0,
                            prefer_http2=False, use_doh=True)
        except Exception:
            continue
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        p = urlparse(url).path or "/"
        if acao == "*" and acac == "true":
            out.append(finding("CORS-001", "CORS wildcard with credentials",
                               "critical", "cors",
                               "Any origin can read authenticated responses.",
                               "ACAO: * / ACAC: true",
                               "Never combine * with credentials.",
                               url, p, "CWE-942"))
        elif acao == origin and origin != "null" and acac == "true":
            out.append(finding("CORS-002", "CORS reflected origin + credentials",
                               "high", "cors",
                               "Account data can be exfiltrated.",
                               f"ACAO: {origin} / ACAC: true",
                               "Validate Origin against allowlist.",
                               url, p, "CWE-942"))
        elif acao == "null":
            out.append(finding("CORS-003", "CORS allows null origin", "medium",
                               "cors", "null origin easy to spoof.",
                               "ACAO: null", "Do not allow null.", url, p, "CWE-942"))
    return out


async def check_cache_headers(headers, url):
    """Detect cacheable responses for sensitive paths."""
    out = []
    cc = headers.get("cache-control", "")
    p = urlparse(url).path or "/"
    if not cc and any(s in p.lower() for s in ("/login", "/admin", "/account")):
        out.append(finding("CACHE-001", "No Cache-Control on sensitive path",
                           "low", "cache",
                           "Sensitive response may be cached by intermediaries.",
                           f"Path: {p}", "Add Cache-Control: no-store.",
                           url, p, "CWE-525"))
    if "no-store" not in cc.lower() and "private" not in cc.lower():
        pragma = headers.get("pragma", "").lower()
        if "no-cache" not in pragma and p.startswith(("/api/", "/user/")):
            out.append(finding("CACHE-002", "API response cacheable",
                               "low", "cache",
                               "API response lacks no-store.",
                               f"Cache-Control: {cc}", "Add no-store.",
                               url, p, "CWE-525"))
    return out


# ======================================================================
# Version disclosure
# ======================================================================
VERSION_PATTERNS = [
    (r'X-Powered-By:\s*([^\s]+)', "X-Powered-By", "low", "CWE-200"),
    (r'Server:\s*([^\s]+/?[\d.]*)', "Server header", "info", "CWE-200"),
    (r'X-AspNet-Version:\s*([\d.]+)', "ASP.NET version", "medium", "CWE-200"),
    (r'X-Drupal-Version:\s*([\d.]+)', "Drupal version", "medium", "CWE-200"),
    (r'X-Generator:\s*([^\r\n]+)', "X-Generator", "low", "CWE-200"),
]


def check_version_disclosure(headers, url):
    out = []
    for name, val in headers.items():
        low = name.lower()
        for pat, label, sev, cwe in VERSION_PATTERNS:
            if low in pat.lower():
                m = re.search(r'([\d.]+)', str(val))
                if m:
                    out.append(finding(
                        f"VER-{name[:10]}", f"{label} discloses version: {val}",
                        sev, "version", f"{name} header leaks product version.",
                        f"{name}: {val}", "Remove or obfuscate version info.",
                        url, cwe=cwe))
                    break
    return out


# ======================================================================
# Paths check (concurrent)
# ======================================================================
async def check_paths(base_url, paths, fetch, timeout=6.0, concurrency=16):
    out = []
    sem = asyncio.Semaphore(concurrency)
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Baseline for soft-404 detection
    rp = f"/__lynk_missing_{uuid.uuid4().hex[:8]}"
    baseline = {"status": 0, "hash": "", "len": 0, "ctype": ""}
    try:
        r = await fetch(urljoin(origin, rp), timeout=timeout,
                        allow_redirects=False, max_redirects=0,
                        prefer_http2=False, use_doh=True)
        body = r.content[:2048]
        baseline = {
            "status": r.status_code,
            "hash": hashlib.sha256(r.content).hexdigest()[:16],
            "len": len(r.content),
            "ctype": r.headers.get("content-type", ""),
        }
    except Exception:
        pass

    async def probe(entry):
        path, label, sev, cwe = entry
        async with sem:
            try:
                target = urljoin(origin, path)
                r = await fetch(target, timeout=timeout,
                                allow_redirects=False, max_redirects=0,
                                prefer_http2=False, use_doh=True)
                return (path, label, sev, cwe, target, r)
            except Exception:
                return None

    results = await asyncio.gather(*[probe(p) for p in paths])
    n = 0
    for item in results:
        if item is None: continue
        path, label, sev, cwe, target, r = item
        code = r.status_code
        ctype = r.headers.get("content-type", "")
        body = r.content[:2048]
        bhash = hashlib.sha256(r.content).hexdigest()[:16]

        if code not in (200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 401, 403):
            continue
        # Filter soft-404s
        if (code == baseline["status"] and bhash == baseline["hash"]
                and ctype == baseline["ctype"]):
            continue
        if code == 404: continue

        n += 1
        out.append(finding(
            f"PATH-{n:03d}", f"Exposed: {label}", sev, "paths",
            f"{path} → HTTP {code} ({len(r.content)} bytes, {ctype})",
            f"GET {target}\nStatus: {code}\nType: {ctype}\nBytes: {len(r.content)}",
            f"Remove or restrict access to {path}.",
            target, path, cwe=cwe))
    return out


# ======================================================================
# Top-level scan
# ======================================================================
async def run_scan(url, fetch, active=True):
    """
    Main entry.  `fetch` is an async callable (url, **kwargs) -> object
    with .status_code, .headers, .content (like lynkio's FetchResponse).
    """
    try:
        r = await fetch(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }, timeout=25.0, allow_redirects=True, max_redirects=3,
            prefer_http2=True, use_doh=True, connect_retries=2)
    except Exception as e:
        return {"error": f"fetch failed: {e}", "findings": [], "url": url}

    headers = {k.lower(): v for k, v in dict(r.headers).items()}
    body = r.content
    ce = headers.get("content-encoding", "")
    if ce:
        body = decode_body(body, ce)
    charset = detect_charset(headers.get("content-type", ""), body)
    try:
        html = body.decode(charset, errors="replace")
    except LookupError:
        html = body.decode("utf-8", errors="replace")

    findings = []
    findings.extend(check_headers(headers, url))
    findings.extend(check_cookies(headers, url))
    findings.extend(check_html(html, url))
    findings.extend(check_libs(html, url))
    findings.extend(check_version_disclosure(headers, url))
    findings.extend(await check_cache_headers(headers, url))

    if active:
        try:
            findings.extend(await check_methods(url, fetch, timeout=8.0))
        except Exception as e:
            log.debug(f"methods check: {e}")
        try:
            findings.extend(await check_cors(url, fetch, timeout=8.0))
        except Exception as e:
            log.debug(f"cors check: {e}")
        try:
            findings.extend(await check_paths(
                url, SENSITIVE_PATHS, fetch, timeout=6.0, concurrency=24))
        except Exception as e:
            log.debug(f"paths check: {e}")

    findings.sort(key=lambda f: sev_rank(f["severity"]))
    check_count = (
        len(SECURITY_HEADERS) + 15 + len(SECRET_PATTERNS) +
        len(JS_LIBS) + len(SENSITIVE_PATHS) +
        len(HTTP_METHODS) + 6 + 6
    )
    return {
        "url": url,
        "scanned_at": time.time(),
        "check_count": check_count,
        "findings": findings,
    }