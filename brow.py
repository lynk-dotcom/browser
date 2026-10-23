#!/usr/bin/env python3
"""
Lynkio Browser — v19.1
Built on the lynkio framework v1.4.2.

v19.1 — Google "unusual traffic" (sorry/index) handling:
  • _is_google_sorry() detects Google's /sorry/index interstitial by URL path,
    body signatures ("unusual traffic", "systems have detected", "IP address:"),
    and the /sorry/ redirect chain. Handles both 200 and 302 arrivals.
  • _google_sorry_page() renders a Lynkio interstitial — same UX pattern as
    the Cloudflare challenge — that offers: open in real browser, switch
    search engine, or paste fresh NID/SID cookies. It replaces Google's own
    broken page entirely, so `solveSimpleChallenge` never runs and the
    ogads RPC never fires.
  • /proxy/add-cookies retries NID paste and reports google_sorry vs
    challenge vs licensing so the interstitial shows the right message.
  • Default search engine switched google → ddg. Google blocks datacenter
    ASNs at /search regardless of TLS fingerprint; the interstitial states
    this plainly and lets the user paste a session cookie if they have one.
  • Retry counter shared with Cloudflare (3 attempts max per URL per session).

v19.0 stealth fetch (curl_cffi · chrome124 JA3/JA4), v18.6 JSON-escape fix,
v18.5 cloner-before-catch-all fix all preserved.
"""

import asyncio
import base64 as _b64
import gzip
import hashlib as _hashlib
import ipaddress as _ipaddress
import json
import logging
import mimetypes
import os
import re
import socket
import ssl
import time
import uuid
import zlib
from collections import deque
from urllib.parse import (
    urljoin, urlparse, quote, unquote, parse_qs, parse_qsl, urlencode,
)

from bs4 import BeautifulSoup

from lynkio import (
    Lynk, Request, RawResponse, StreamingResponse,
    json_response, framework_version,
)

import scanner
import cloner

try:
    from curl_cffi.requests import AsyncSession
    from curl_cffi import CurlHttpVersion
    HAS_CURL_CFFI = True
except Exception:
    AsyncSession = None
    CurlHttpVersion = None
    HAS_CURL_CFFI = False

HERE          = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR    = os.path.join(HERE, "static")
TEMPLATES_DIR = os.path.join(HERE, "templates")

HOST              = "0.0.0.0"
PORT              = 8080

CONNECT_TIMEOUT   = 8.0
SSL_HANDSHAKE_TL  = 8.0
HEADER_TIMEOUT    = 40.0
BODY_IDLE_TIMEOUT = 120.0
DOH_TIMEOUT       = 5.0

MAX_REWRITE_BYTES = 8 * 1024 * 1024
MAX_CSS_BYTES     = 4 * 1024 * 1024
MAX_HLS_BYTES     = 2 * 1024 * 1024
MAX_HEADER_BYTES  = 128 * 1024
MAX_BUFFER_BYTES  = 8 * 1024 * 1024

STREAM_CHUNK_SIZE = 64 * 1024
SMALL_MEDIA_MAX   = 1 * 1024 * 1024

SESSION_TTL_SECONDS   = 6 * 3600
SESSION_MAX           = 5000
SESSION_SWEEP_PERIOD  = 300
COOKIE_MAX_PER_ORIGIN = 512
COOKIE_MAX_ORIGINS    = 256

SESSION_COOKIE = "__lynk_sid"
ORIGIN_COOKIE  = "__lynk_origin"

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
IMPERSONATE_PROFILE = "chrome124"

CHALLENGE_MAX_ATTEMPTS = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("lynk.browser")
if HAS_CURL_CFFI:
    log.info("stealth: curl_cffi loaded — impersonating %s", IMPERSONATE_PROFILE)
else:
    log.warning("stealth: curl_cffi NOT installed — TLS fingerprinting disabled. "
                "Run: pip install curl_cffi")


SEARCH_ENGINES = {
    "google":     ("Google",     "https://www.google.com/search?q={q}"),
    "bing":       ("Bing",       "https://www.bing.com/search?q={q}"),
    "ddg":        ("DuckDuckGo", "https://duckduckgo.com/html/?q={q}"),
    "duckduckgo": ("DuckDuckGo", "https://duckduckgo.com/html/?q={q}"),
    "brave":      ("Brave",      "https://search.brave.com/search?q={q}"),
    "wikipedia":  ("Wikipedia",  "https://en.wikipedia.org/w/index.php?search={q}"),
    "github":     ("GitHub",     "https://github.com/search?q={q}"),
}
DEFAULT_SEARCH_ENGINE = "ddg"

BROWSER_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

FORWARD_REQUEST_HEADERS = {
    "authorization", "origin", "content-type",
    "if-none-match", "if-modified-since", "if-match", "if-unmodified-since",
    "range", "if-range",
    "accept-language", "x-requested-with",
    "referer",
}

FORWARD_RESPONSE_HEADERS = {
    "cache-control", "etag", "last-modified", "expires", "vary",
    "content-language", "content-disposition", "accept-ranges",
    "content-range", "content-md5", "digest",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-expose-headers", "access-control-max-age",
    "access-control-allow-methods", "access-control-allow-headers",
    "content-encoding",
}

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

NEVER_EMIT = {"transfer-encoding", "connection", "keep-alive"}

CAPTCHA_HOSTS = (
    "google.com/recaptcha/",
    "recaptcha.net/recaptcha/",
    "gstatic.com/recaptcha/",
    "hcaptcha.com/",
    "newassets.hcaptcha.com/",
    "challenges.cloudflare.com/",
    "turnstile.com/",
    "cloudflare.com/cdn-cgi/challenge-platform/",
    "arkoselabs.com/",
    "funcaptcha.com/",
    "captcha.awswaf.com/",
    "awswaf.com/captcha/",
)

STATIC_EXTS = {
    ".js", ".mjs", ".cjs", ".css", ".json", ".map", ".wasm",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".wav", ".ogg", ".m4a", ".ts",
    ".pdf", ".zip", ".gz", ".tgz", ".tar", ".7z", ".rar",
}

STREAM_MEDIA_PREFIXES = ("video/", "audio/", "image/", "font/")
STREAM_MEDIA_TYPES = {
    "application/octet-stream", "application/pdf",
    "application/zip", "application/x-zip-compressed",
    "application/x-rar-compressed", "application/x-7z-compressed",
    "application/x-tar", "application/gzip", "application/x-gzip",
    "application/wasm", "application/x-shockwave-flash",
    "application/vnd.ms-fontobject",
    "application/x-font-ttf", "application/x-font-opentype",
    "application/font-woff", "application/font-woff2",
    "application/epub+zip", "application/x-msdownload",
    "application/vnd.apple.mpegurl", "application/x-mpegurl",
    "application/vnd.rn-realmedia",
    "application/dash+xml",
}
STREAM_MEDIA_EXTS = {
    ".mp4", ".m4v", ".webm", ".mov", ".avi", ".mkv", ".flv", ".ts",
    ".mpg", ".mpeg", ".f4v", ".3gp", ".ogv", ".m2ts", ".mts", ".mpd",
    ".mp3", ".m4a", ".aac", ".wav", ".ogg", ".oga", ".opus", ".flac",
    ".weba", ".mid", ".midi", ".wma", ".mka",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico",
    ".tif", ".tiff", ".heic", ".heif", ".jxl", ".jfif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".wasm", ".swf", ".bin", ".exe", ".dmg", ".iso", ".apk", ".deb",
    ".rpm", ".msi", ".jar", ".class", ".m4s", ".mp2t",
}

_MEDIA_PATH_HINTS = (
    "/video/", "/videos/", "/stream/", "/streams/", "/segment/", "/segments/",
    "/tos-", "/obj/", "/media/", "/play/", "/hls/", "/dash/", "/mse/",
    "/chunk/", "/chunks/", "/slice/", "/slices/", "/image/", "/images/",
    "/img/", "/imgs/", "/thumb/", "/thumbs/", "/avatar/", "/avatars/",
    "/photo/", "/photos/", "/asset/", "/assets/", "/static/video/",
    "/static/image/", "/static/img/", "/cdn/", "/mp4/", "/m4s/",
)


def _is_captcha_url(u):
    try:
        p = urlparse(u)
    except Exception:
        return False
    h = (p.hostname or "").lower()
    path = (p.path or "")
    full = h + path
    for s in CAPTCHA_HOSTS:
        if s in full:
            return True
    return False


def _looks_like_html(body_bytes):
    if not body_bytes:
        return False
    head = body_bytes[:512].lstrip()
    low = head.lower()
    if low.startswith(b"<!doctype") or low.startswith(b"<html"):
        return True
    if low.startswith(b"<"):
        if (b"<html" in low[:300] or b"<head" in low[:300]
                or b"<body" in low[:300]):
            return True
    return False


# ======================================================================
# Cloudflare challenge detection
# ======================================================================
_CF_BODY_SIGNATURES = (
    b"just a moment",
    b"cf-challenge",
    b"challenge-platform",
    b"checking your browser",
    b"cf_chl_opt",
    b"__cf_chl",
    b"cf-browser-verification",
)

def _is_cf_challenge(status, headers_dict, body):
    try:
        for k, v in headers_dict.items():
            if k.lower() == "cf-mitigated" and str(v).lower() == "challenge":
                return True
    except Exception:
        pass
    if status not in (403, 429, 503):
        return False
    if not body:
        return False
    low = bytes(body[:8192]).lower()
    for sig in _CF_BODY_SIGNATURES:
        if sig in low:
            return True
    return False


# ======================================================================
# Google "unusual traffic" (/sorry/index) detection — v19.1
# ======================================================================
_GOOGLE_SORRY_BODY_SIGNATURES = (
    b"our systems have detected unusual traffic",
    b"systems have detected unusual traffic",
    b"/sorry/index",
    b"this page checks to see if it&#39;s really you",
    b"this page checks to see if it's really you",
    b"ip address:",
    b"about this page",
)

def _is_google_sorry(status, headers_dict, body, final_url=""):
    """
    Return True if the response is Google's anti-bot interstitial.

    Signals checked:
      • final_url contains /sorry/index  (Google redirected us there)
      • body contains one of the canonical phrases
      • status is 429 or 200 with the challenge body

    Google returns 200 for the sorry page most of the time (it is a
    human-readable page, not a protocol error). We rely mainly on body
    signatures rather than status.
    """
    try:
        if final_url and "/sorry/index" in final_url:
            return True
    except Exception:
        pass
    try:
        if status not in (200, 403, 429, 503):
            return False
    except Exception:
        return False
    if not body:
        return False
    low = bytes(body[:16384]).lower()
    hits = 0
    for sig in _GOOGLE_SORRY_BODY_SIGNATURES:
        if sig in low:
            hits += 1
    return hits >= 2


def _requested_kind(req, target_url):
    dest = (req.headers.get("sec-fetch-dest") or "").lower().strip()
    if dest == "script":
        return "script"
    if dest == "style":
        return "style"
    if dest in ("document", "iframe", "frame"):
        return "document"
    if dest in ("image", "video", "audio", "font", "track", "manifest"):
        return "media"
    if dest == "empty":
        accept = (req.headers.get("accept") or "").lower()
        if "video" in accept or "audio" in accept or "image" in accept:
            return "media"
        return "data"
    try:
        path = (urlparse(target_url).path or "").lower()
    except Exception:
        path = ""
    ext = os.path.splitext(path)[1]
    if ext in (".js", ".mjs", ".cjs"):
        return "script"
    if ext == ".css":
        return "style"
    if ext in STREAM_MEDIA_EXTS:
        return "media"
    accept = (req.headers.get("accept") or "").lower()
    if "text/html" in accept:
        return "document"
    if "video" in accept or "audio" in accept or "image" in accept:
        return "media"
    return ""


def _media_hint_by_path(target_url):
    try:
        path = (urlparse(target_url).path or "").lower()
    except Exception:
        return False
    for h in _MEDIA_PATH_HINTS:
        if h in path:
            return True
    return False


def _is_media_response(req, target_url, ctype, ext, status, content_range):
    if status == 206 or content_range:
        return True
    ct = (ctype or "").split(";", 1)[0].strip().lower()
    if any(ct.startswith(p) for p in STREAM_MEDIA_PREFIXES):
        return True
    if ct in STREAM_MEDIA_TYPES:
        return True
    if ext in STREAM_MEDIA_EXTS:
        return True
    accept = (req.headers.get("accept") or "").lower()
    dest = (req.headers.get("sec-fetch-dest") or "").lower()
    if dest in ("image", "video", "audio", "font", "track"):
        return True
    if ("video" in accept or "audio" in accept or "image" in accept) \
            and _media_hint_by_path(target_url):
        return True
    if _media_hint_by_path(target_url) and not ct:
        return True
    return False


def _js_stub(status, target_url, preview=b""):
    try:
        preview_txt = preview.decode("utf-8", "replace").replace("*/", "* /")
    except Exception:
        preview_txt = ""
    body = (
        "/* lynkio: upstream returned %d for this JS chunk.\n"
        "   target: %s\n"
        "   preview: %s\n"
        "   This stub keeps the module graph alive. */\n"
        "console.warn('[lynk] chunk not available:', %s);\n"
    ) % (
        status,
        target_url.replace("*/", "* /"),
        preview_txt[:160],
        json.dumps(target_url),
    )
    return body.encode("utf-8")


def _css_stub(status, target_url):
    body = (
        "/* lynkio: upstream returned %d for this CSS asset.\n"
        "   target: %s */\n"
    ) % (status, target_url.replace("*/", "* /"))
    return body.encode("utf-8")


app = Lynk(
    host=HOST, port=PORT, protocol="TCP", debug=False,
    serve_client=True, max_body_size=64 * 1024 * 1024,
)


# ======================================================================
# Sessions + cookie jar
# ======================================================================
class CookieJar:
    def __init__(self):
        self.by_origin = {}

    def set(self, origin, name, value, **attrs):
        if origin not in self.by_origin:
            if len(self.by_origin) >= COOKIE_MAX_ORIGINS:
                try:
                    oldest = next(iter(self.by_origin))
                    self.by_origin.pop(oldest, None)
                except StopIteration:
                    pass
        jar = self.by_origin.setdefault(origin, {})
        if name not in jar and len(jar) >= COOKIE_MAX_PER_ORIGIN:
            try:
                first = next(iter(jar))
                jar.pop(first, None)
            except StopIteration:
                pass
        jar[name] = {"value": value, **attrs}

    def delete(self, origin, name):
        if origin in self.by_origin:
            self.by_origin[origin].pop(name, None)

    def clear(self, origin):
        self.by_origin.pop(origin, None)

    def list(self, origin):
        return dict(self.by_origin.get(origin, {}))

    def header_for(self, origin):
        jar = self.by_origin.get(origin) or {}
        return "; ".join(f"{k}={v['value']}" for k, v in jar.items()
                         if v.get("value"))

    def merge_set_cookie(self, origin, raw):
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            return
        first = parts[0]
        if "=" not in first:
            return
        name, value = first.split("=", 1)
        name = name.strip(); value = value.strip()
        attrs = {}
        for p in parts[1:]:
            pl = p.lower()
            if pl.startswith("path="):      attrs["path"] = p.split("=", 1)[1]
            elif pl.startswith("domain="):  attrs["domain"] = p.split("=", 1)[1]
            elif pl.startswith("expires="): attrs["expires"] = p.split("=", 1)[1]
            elif pl.startswith("max-age="): attrs["max_age"] = p.split("=", 1)[1]
            elif pl.startswith("samesite="):attrs["samesite"] = p.split("=", 1)[1]
            elif pl == "secure":   attrs["secure"] = True
            elif pl == "httponly": attrs["httponly"] = True
        self.set(origin, name, value, **attrs)


class Session:
    def __init__(self):
        self.injected       = []
        self.source_cache   = {}
        self.history        = deque(maxlen=1000)
        self.last_origin    = ""
        self.page_origin    = ""
        self.recent_origins = deque(maxlen=24)
        self.cookies        = CookieJar()
        self.created_at     = time.time()
        self.last_seen      = self.created_at
        self.challenge_attempts = {}

    def touch(self):
        self.last_seen = time.time()

    def note_origin(self, origin):
        now = time.time()
        self.recent_origins = deque(
            [(o, t) for (o, t) in self.recent_origins
             if o != origin and now - t < 300],
            maxlen=24,
        )
        self.recent_origins.appendleft((origin, now))

    def last_page_url(self, exclude_host=""):
        exclude_host = (exclude_host or "").lower()
        for entry in reversed(list(self.history)):
            u = entry.get("url", "")
            if not u:
                continue
            try:
                p = urlparse(u)
                hp = (p.hostname or "").lower()
            except Exception:
                continue
            if exclude_host and hp == exclude_host:
                continue
            ext = os.path.splitext(p.path.lower())[1]
            if ext in STATIC_EXTS:
                continue
            if not ext or ext in (".html", ".htm", ".xhtml",
                                   ".php", ".asp", ".aspx", ".jsp"):
                return u
        return ""

    def last_page_url_for_origin(self, origin):
        try:
            oh = (urlparse(origin).hostname or "").lower()
        except Exception:
            return ""
        if not oh:
            return ""
        for entry in reversed(list(self.history)):
            u = entry.get("url", "")
            if not u:
                continue
            try:
                p = urlparse(u)
                hp = (p.hostname or "").lower()
            except Exception:
                continue
            if hp != oh:
                continue
            ext = os.path.splitext(p.path.lower())[1]
            if ext in STATIC_EXTS:
                continue
            if not ext or ext in (".html", ".htm", ".xhtml",
                                   ".php", ".asp", ".aspx", ".jsp"):
                return u
        return ""


SESSIONS = {}
_LAST_SWEEP = [0.0]


def _sweep_sessions():
    now = time.time()
    _LAST_SWEEP[0] = now
    if len(SESSIONS) > 0:
        stale = [sid for sid, s in SESSIONS.items()
                 if now - s.last_seen > SESSION_TTL_SECONDS]
        for sid in stale:
            SESSIONS.pop(sid, None)
        if stale:
            log.info("session sweep: expired %d, remaining %d",
                     len(stale), len(SESSIONS))
    if len(SESSIONS) > SESSION_MAX:
        ordered = sorted(SESSIONS.items(), key=lambda kv: kv[1].last_seen)
        to_evict = len(SESSIONS) - SESSION_MAX
        for sid, _ in ordered[:to_evict]:
            SESSIONS.pop(sid, None)
        log.info("session sweep: LRU-evicted %d, remaining %d",
                 to_evict, len(SESSIONS))


def get_session(sid):
    s = SESSIONS.get(sid)
    if s is None:
        now = time.time()
        if now - _LAST_SWEEP[0] > SESSION_SWEEP_PERIOD:
            _sweep_sessions()
        s = SESSIONS[sid] = Session()
    s.touch()
    return s


def session_from_req(req):
    sid = req.cookies.get(SESSION_COOKIE, "")
    if not sid or sid not in SESSIONS:
        sid = uuid.uuid4().hex
        get_session(sid)
        return sid, True
    s = SESSIONS[sid]
    s.touch()
    return sid, False


# ======================================================================
# Small helpers
# ======================================================================
def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))


def _json_for_script(obj):
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    s = s.replace("</", "<\\/")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s


def _decompress(body, encoding):
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity":
        return body
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        pass
    return body


def detect_charset(ct, body):
    m = re.search(r'charset\s*=\s*["\']?([A-Za-z0-9_\-]+)', ct or "", re.I)
    if m:
        return m.group(1)
    m2 = re.search(rb'charset\s*=\s*["\']?([a-z0-9_\-]+)', body[:4096].lower())
    if m2:
        return m2.group(1).decode("ascii", "ignore")
    return "utf-8"


def extract_upstream(referer):
    if not referer:
        return ""
    try:
        p = urlparse(referer)
        if p.path != "/proxy":
            return ""
        u = (parse_qs(p.query).get("url") or [""])[0]
        up = urlparse(u)
        if up.scheme in ("http", "https") and up.netloc:
            return u
    except Exception:
        pass
    return ""


_SKIP = ("data:", "javascript:", "mailto:", "tel:", "blob:",
         "about:", "file:", "#")


def skip_url(v):
    return not v or any(v.strip().lower().startswith(s) for s in _SKIP)


def proxy_url(absu):
    return f"/proxy?url={quote(absu, safe='')}"


def looks_like_url(s):
    s = (s or "").strip()
    if not s:
        return False
    if s.startswith(("http://", "https://")):
        return True
    if " " in s:
        return False
    first = s.split("/", 1)[0]
    return "." in first and not first.startswith(".") and not first.endswith(".")


def _norm_host(h):
    if not h:
        return h
    if ":" in h:
        base, port = h.rsplit(":", 1)
        if port in ("80", "443"):
            return base
    return h


def _headers_all(hdrs, name):
    name = name.lower()
    return [v for k, v in hdrs if k == name]


def _header(hdrs, name, default=""):
    name = name.lower()
    for k, v in hdrs:
        if k == name:
            return v
    return default


def _rewrite_set_cookie(value, origin_host):
    parts = [p.strip() for p in value.split(";")]
    if not parts:
        return value
    kept = [parts[0]]
    has_samesite = False
    for p in parts[1:]:
        pl = p.lower()
        if pl.startswith("domain="):
            continue
        if pl == "secure":
            continue
        if pl.startswith("samesite="):
            has_samesite = True
        kept.append(p)
    if not has_samesite:
        kept.append("SameSite=Lax")
    return "; ".join(kept)


def is_self_target(req, target_url):
    try:
        p = urlparse(target_url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    incoming = (req.headers.get("host") or "").lower()
    if not incoming:
        return False
    in_host = _norm_host(incoming).split(":", 1)[0]
    t_host = (p.hostname or "").lower()
    if not t_host:
        return False
    return in_host == t_host


def _recover_origin(req, sess):
    incoming = (req.headers.get("host") or "").lower()
    in_host = _norm_host(incoming).split(":", 1)[0] if incoming else ""

    def _usable(u):
        if not u:
            return ""
        try:
            p = urlparse(u)
            if p.scheme not in ("http", "https") or not p.netloc:
                return ""
            hp = (p.hostname or "").lower()
            if in_host and hp == in_host:
                return ""
            return f"{p.scheme}://{p.netloc}"
        except Exception:
            return ""

    ref = req.headers.get("referer", "")
    up = extract_upstream(ref)
    origin = _usable(up)
    if origin:
        return origin
    cv = req.cookies.get(ORIGIN_COOKIE, "")
    origin = _usable(unquote(cv) if cv else "")
    if origin:
        return origin
    origin = _usable(req.headers.get("origin", ""))
    if origin:
        return origin
    origin = _usable(sess.page_origin)
    if origin:
        return origin
    origin = _usable(sess.last_origin)
    if origin:
        return origin
    for (o, _ts) in list(sess.recent_origins):
        origin = _usable(o)
        if origin:
            return origin
    for entry in reversed(list(sess.history)):
        origin = _usable(entry.get("url", ""))
        if origin:
            return origin
    return ""


def error_page(title, message, status=500):
    return RawResponse(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>{esc(title)} · Lynk</title><style>'
        'body{font-family:Inter,system-ui,sans-serif;background:#070b16;color:#e2e8f0;'
        'display:flex;align-items:center;justify-content:center;min-height:100vh;'
        'margin:0;padding:24px}'
        '.card{background:rgba(15,23,42,.68);border:1px solid rgba(148,163,184,.16);'
        'border-radius:20px;max-width:620px;width:100%;padding:32px;text-align:left}'
        '.ic{width:56px;height:56px;border-radius:16px;display:inline-grid;'
        'place-items:center;font-size:1.5rem;margin-bottom:18px;'
        'background:rgba(248,113,113,.2)}'
        'h1{font-size:1.35rem;margin:0 0 8px}'
        'p{color:#94a3b8;font-size:.92rem;line-height:1.6;margin:0 0 22px;'
        'word-break:break-word}'
        'code{background:rgba(2,6,23,.6);padding:2px 6px;border-radius:4px;'
        'font-family:ui-monospace,monospace;font-size:.85em}'
        'a{display:inline-flex;gap:6px;background:linear-gradient(135deg,#38bdf8,#818cf8);'
        'color:#0b1220;padding:11px 20px;border-radius:10px;font-weight:700;'
        'text-decoration:none}'
        '</style></head><body><div class="card">'
        f'<div class="ic">⚠</div><h1>{esc(title)}</h1><p>{message}</p>'
        '<a href="/">← Back to Lynk</a></div></body></html>',
        status=status, content_type="text/html; charset=utf-8")


# ======================================================================
# Stealth fetch (curl_cffi)
# ======================================================================
async def _stealth_fetch_raw(url, method="GET", headers=None, body=None,
                              timeout=30.0, allow_redirects=True,
                              max_redirects=5, session_cookies=None):
    if not HAS_CURL_CFFI:
        return None
    try:
        merged = dict(headers or {})
        merged.setdefault("User-Agent", BROWSER_UA)
        if session_cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in session_cookies.items()
                                      if v)
            if cookie_header:
                existing = merged.get("Cookie", "")
                merged["Cookie"] = (existing + "; " + cookie_header).lstrip("; ")
        async with AsyncSession() as s:
            resp = await s.request(
                method.upper(), url,
                headers=merged,
                data=body,
                impersonate=IMPERSONATE_PROFILE,
                allow_redirects=allow_redirects,
                max_redirects=max_redirects,
                timeout=timeout,
            )
            hdr_dict = {}
            try:
                for k, v in resp.headers.multi_items():
                    kl = k.lower()
                    if kl in hdr_dict:
                        if not isinstance(hdr_dict[kl], list):
                            hdr_dict[kl] = [hdr_dict[kl]]
                        hdr_dict[kl].append(v)
                    else:
                        hdr_dict[kl] = v
            except Exception:
                hdr_dict = {k.lower(): v for k, v in dict(resp.headers).items()}
            return {
                "status": resp.status_code,
                "headers": hdr_dict,
                "content": resp.content,
                "url": str(resp.url),
            }
    except Exception as e:
        log.debug("stealth fetch failed %s: %s", url, e)
        return None


# ======================================================================
# HTML rewriter
# ======================================================================
class HTMLRewriter:
    def __init__(self, base_url, ctype, ctx):
        self.base = base_url
        self.ctype = ctype
        self.ctx = ctx

    def _rw_srcset(self, srcset, base):
        out = []
        for entry in srcset.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(None, 1)
            u = parts[0]
            tail = parts[1] if len(parts) > 1 else ""
            if skip_url(u):
                out.append(entry)
                continue
            absu = urljoin(base, u)
            if _is_captcha_url(absu):
                out.append(entry)
                continue
            out.append(f"{proxy_url(absu)} {tail}".strip() if tail
                       else proxy_url(absu))
        return ", ".join(out)

    def _rw_css(self, css, base):
        def sub_url(m):
            inner = m.group(1).strip().strip("'\"")
            if not inner or inner.startswith("data:"):
                return m.group(0)
            if inner.startswith("//"):
                absu = urljoin(base, inner)
                if _is_captcha_url(absu):
                    return m.group(0)
                return f"url('{proxy_url(absu)}')"
            if skip_url(inner):
                return m.group(0)
            absu = urljoin(base, inner)
            if _is_captcha_url(absu):
                return m.group(0)
            return f"url('{proxy_url(absu)}')"

        def sub_import(m):
            q, inner = m.group(1), m.group(2).strip()
            if skip_url(inner) or inner.startswith("//"):
                return m.group(0)
            absu = urljoin(base, inner)
            if _is_captcha_url(absu):
                return m.group(0)
            return f"@import {q}{proxy_url(absu)}{q}"

        css = re.sub(r"url\(\s*([^)]+?)\s*\)", sub_url, css)
        css = re.sub(r"""@import\s+(["'])([^"']+)\1""", sub_import, css)
        return css

    def rewrite(self, raw):
        charset = detect_charset(self.ctype, raw)
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            return raw
        base = self.base

        for tag in soup.find_all("base"):
            tag.decompose()
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower().startswith("content-security"):
                meta.decompose()

        for tag in soup.find_all(["a", "link", "area"], href=True):
            h = tag["href"]
            if skip_url(h):
                continue
            absu = urljoin(base, h)
            if _is_captcha_url(absu):
                tag["href"] = absu
                continue
            tag["href"] = proxy_url(absu)

        for tag in soup.find_all(
            ["img", "script", "iframe", "embed", "source", "video",
             "audio", "track", "input"], src=True):
            s = tag["src"]
            if skip_url(s):
                continue
            absu = urljoin(base, s)
            if _is_captcha_url(absu):
                tag["src"] = absu
                continue
            tag["src"] = proxy_url(absu)

        for tag in soup.find_all("object", data=True):
            d = tag["data"]
            if skip_url(d):
                continue
            absu = urljoin(base, d)
            if _is_captcha_url(absu):
                tag["data"] = absu
                continue
            tag["data"] = proxy_url(absu)

        for attr in ("data-src", "data-original", "data-lazy-src",
                     "data-url", "data-href", "data-image"):
            for tag in soup.find_all(attrs={attr: True}):
                v = tag[attr]
                if skip_url(v):
                    continue
                absu = urljoin(base, v)
                if _is_captcha_url(absu):
                    continue
                tag[attr] = proxy_url(absu)

        for attr in ("srcset", "data-srcset"):
            for tag in soup.find_all(attrs={attr: True}):
                tag[attr] = self._rw_srcset(tag[attr], base)

        for tag in soup.find_all("video", poster=True):
            p = tag["poster"]
            if skip_url(p):
                continue
            absu = urljoin(base, p)
            if _is_captcha_url(absu):
                continue
            tag["poster"] = proxy_url(absu)

        for meta in soup.find_all("meta", attrs={"property": True}):
            prop = (meta.get("property") or "").lower()
            if prop in ("og:image", "og:url", "og:video",
                        "twitter:image", "twitter:url"):
                v = meta.get("content", "")
                if v and not skip_url(v):
                    absu = urljoin(base, v)
                    if not _is_captcha_url(absu):
                        meta["content"] = proxy_url(absu)

        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or base
            absu = urljoin(base, action)
            if method == "get":
                form["action"] = "/proxy"
                for ex in form.find_all("input", attrs={"name": "url"}):
                    ex.decompose()
                h = soup.new_tag("input")
                h["type"] = "hidden"; h["name"] = "url"; h["value"] = absu
                form.append(h)
            else:
                form["action"] = proxy_url(absu)

        for tag in soup.find_all(style=True):
            tag["style"] = self._rw_css(tag["style"], base)
        for st in soup.find_all("style"):
            if st.string:
                st.string = self._rw_css(st.string, base)

        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content = meta.get("content", "")
                m = re.search(r"url\s*=\s*([^;]+)", content, re.I)
                if m:
                    u = m.group(1).strip().strip("'\"")
                    if not skip_url(u):
                        absu = urljoin(base, u)
                        if not _is_captcha_url(absu):
                            meta["content"] = re.sub(
                                r"url\s*=\s*[^;]+",
                                f"url={proxy_url(absu)}",
                                content, flags=re.I)

        for tag in soup.find_all(["script", "link"]):
            for a in ("integrity", "crossorigin", "referrerpolicy"):
                tag.attrs.pop(a, None)

        head = soup.head or soup.new_tag("head")
        if not soup.head:
            soup.insert(0, head)

        boot = soup.new_tag("script")
        boot.string = (
            "if('serviceWorker' in navigator&&!window.__LYNK_SW__){"
            "window.__LYNK_SW__=1;"
            "navigator.serviceWorker.register('/lynkio/service-ws.js',{scope:'/'})"
            ".catch(function(e){})}"
        )

        ctx_s = soup.new_tag("script")
        ctx_s.string = f"window.__LYNK_CTX__={_json_for_script(self.ctx)};"

        icpt = soup.new_tag("script")
        icpt["src"] = "/static/js/interceptor.js"

        ui = soup.new_tag("script")
        ui["src"] = "/static/js/ui.js"

        clonerc = soup.new_tag("script")
        clonerc["src"] = "/static/js/cloner_capture.js"

        head.insert(0, boot)
        head.insert(1, ctx_s)
        head.insert(2, icpt)
        head.insert(3, ui)
        head.insert(4, clonerc)

        for snip in self.ctx.get("_injected", []):
            target = soup.body or soup.html or soup
            safe = snip.replace("</", "<\\/")
            s = soup.new_tag("script")
            s.string = safe
            target.append(s)

        return str(soup).encode("utf-8", errors="ignore")


def rewrite_css_body(raw, base_url, ctype):
    charset = detect_charset(ctype, raw)
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    return HTMLRewriter(base_url, ctype, {})._rw_css(text, base_url).encode("utf-8")


# ======================================================================
# HLS / M3U8 rewriter
# ======================================================================
_M3U8_URI_ATTR = re.compile(r'URI="([^"]+)"')


def rewrite_m3u8(text, base_url):
    out_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            out_lines.append(line)
            continue
        if stripped.startswith("#"):
            def sub_uri(m):
                u = m.group(1)
                if skip_url(u):
                    return m.group(0)
                absu = urljoin(base_url, u)
                if _is_captcha_url(absu):
                    return m.group(0)
                return f'URI="{proxy_url(absu)}"'
            line = _M3U8_URI_ATTR.sub(sub_uri, line)
            out_lines.append(line)
            continue
        if skip_url(stripped):
            out_lines.append(line)
            continue
        absu = urljoin(base_url, stripped)
        out_lines.append(proxy_url(absu))
    return "\n".join(out_lines)


# ======================================================================
# DoH resolver
# ======================================================================
async def _doh_resolve(host, timeout=DOH_TIMEOUT):
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("1.1.1.1", 443, ssl=ctx,
                                    server_hostname="cloudflare-dns.com"),
            timeout=timeout)
    except Exception:
        return []
    try:
        path = f"/dns-query?name={quote(host)}&type=A"
        req = (f"GET {path} HTTP/1.1\r\nHost: cloudflare-dns.com\r\n"
               f"Accept: application/dns-json\r\nConnection: close\r\n\r\n").encode()
        writer.write(req); await writer.drain()
        buf = bytearray(); deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in buf:
            if time.monotonic() > deadline:
                return []
            chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            if not chunk:
                break
            buf.extend(chunk)
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        text = head.decode("latin-1")
        cl = re.search(r"Content-Length:\s*(\d+)", text, re.I)
        if cl:
            need = int(cl.group(1)) - len(rest)
            while need > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(4096, need)), timeout=1.0)
                if not chunk:
                    break
                rest += chunk; need -= len(chunk)
        data = json.loads(rest.decode("utf-8", errors="replace"))
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _resolve_host(host, port, prefer_ipv4=True, use_doh=True):
    ips = []
    if use_doh:
        try:
            for ip in await _doh_resolve(host):
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    try:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET if prefer_ipv4 else 0
        infos = await loop.getaddrinfo(host, port, family=family,
                                       type=socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if prefer_ipv4 and ":" in ip:
                continue
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


# ======================================================================
# Upstream request builder (raw socket — media / WS fallback)
# ======================================================================
def _build_request(method, target_url, headers, body):
    p = urlparse(target_url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    method = method.upper()
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    sent_conn = False
    for k, v in headers.items():
        kl = k.lower()
        if kl == "host":       continue
        if kl == "connection": sent_conn = True; continue
        if kl == "content-length": continue
        lines.append(f"{k}: {v}")
    body_bytes = b""
    if body is not None:
        if isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, (bytearray, memoryview)):
            body_bytes = bytes(body)
        else:
            body_bytes = str(body).encode("utf-8")
    if body_bytes or method in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(body_bytes)}")
    if not sent_conn:
        lines.append("Connection: close")
    lines.append(""); lines.append("")
    payload = "\r\n".join(lines).encode("latin-1", errors="replace")
    if body_bytes:
        payload += body_bytes
    return host, port, p.scheme, payload


def _get_proxy_for(scheme):
    var_list = (("HTTPS_PROXY", "https_proxy") if scheme == "https"
                else ("HTTP_PROXY", "http_proxy"))
    for var in var_list:
        v = os.environ.get(var)
        if v:
            p = urlparse(v)
            if p.hostname:
                return p.hostname, (p.port or
                                    (443 if p.scheme == "https" else 80))
    return None


async def _open_via_proxy(proxy, target_host, target_port, ssl_ctx):
    proxy_host, proxy_port = proxy
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    connect = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
               f"Host: {target_host}:{target_port}\r\n\r\n").encode()
    writer.write(connect); await writer.drain()
    status = await asyncio.wait_for(reader.readline(), timeout=10.0)
    if b"200" not in status:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"proxy CONNECT rejected: {status!r}")
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if line in (b"\r\n", b"\n", b""):
            break
    if ssl_ctx is not None:
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(transport, protocol, ssl_ctx,
                                             server_hostname=target_host)
        writer._transport = new_transport
    return reader, writer


async def _open_upstream_stream(target_url, method, headers, body):
    host, port, scheme, payload = _build_request(method, target_url,
                                                  headers, body)
    ssl_ctx = None
    if scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = True
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ssl_ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass

    proxy = _get_proxy_for(scheme)
    if proxy:
        try:
            reader, writer = await asyncio.wait_for(
                _open_via_proxy(proxy, host, port, ssl_ctx),
                timeout=CONNECT_TIMEOUT)
        except Exception as e:
            raise ConnectionError(f"proxy CONNECT failed: {e}")
    else:
        resolved = await _resolve_host(host, port, prefer_ipv4=True,
                                        use_doh=True)
        candidates = resolved if resolved else [host]
        reader = writer = None
        last_exc = None
        for ip in candidates:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        ip, port, ssl=ssl_ctx,
                        server_hostname=host if ssl_ctx else None,
                        ssl_handshake_timeout=SSL_HANDSHAKE_TL),
                    timeout=CONNECT_TIMEOUT)
                break
            except Exception as e:
                last_exc = e
                reader = writer = None
        if writer is None:
            raise ConnectionError(
                f"all addresses for {host}:{port} failed; last: "
                f"{type(last_exc).__name__}: {last_exc}")

    try:
        writer.write(payload); await writer.drain()
    except Exception as e:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"write failed: {e}")

    buf = bytearray(); deadline = time.monotonic() + HEADER_TIMEOUT
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try: writer.close()
            except Exception: pass
            raise TimeoutError("headers timeout")
        try:
            chunk = await asyncio.wait_for(reader.read(8192),
                                           timeout=remaining)
        except asyncio.TimeoutError:
            try: writer.close()
            except Exception: pass
            raise TimeoutError("headers timeout")
        if not chunk:
            try: writer.close()
            except Exception: pass
            raise ConnectionError("closed before headers")
        buf.extend(chunk)
        if len(buf) > MAX_HEADER_BYTES:
            try: writer.close()
            except Exception: pass
            raise ConnectionError("headers too large")

    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    text = head.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        try: writer.close()
        except Exception: pass
        raise ConnectionError("empty response")
    parts = lines[0].split(" ", 2)
    try:
        status = int(parts[1])
    except Exception:
        try: writer.close()
        except Exception: pass
        raise ConnectionError(f"bad status line: {lines[0]!r}")

    hdrs = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs.append((k.strip().lower(), v.strip()))

    log.info("upstream %s %s → %d", method, target_url, status)
    return reader, writer, status, hdrs, rest


async def _close_writer(writer):
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass
    try:
        await writer.wait_closed()
    except Exception:
        pass


# ======================================================================
# Body readers
# ======================================================================
async def _iter_body(reader, headers, first_chunk=b"",
                     chunk_size=STREAM_CHUNK_SIZE):
    te = _header(headers, "transfer-encoding").lower()
    cl = _header(headers, "content-length")

    if "chunked" in te:
        buf = bytearray(first_chunk)
        while True:
            while b"\r\n" not in buf:
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(4096), timeout=BODY_IDLE_TIMEOUT)
                except (asyncio.TimeoutError, ConnectionResetError,
                        BrokenPipeError):
                    return
                if not chunk:
                    return
                buf.extend(chunk)
            le = buf.find(b"\r\n")
            size_line = bytes(buf[:le]).split(b";", 1)[0].strip()
            del buf[:le + 2]
            try:
                size = int(size_line, 16)
            except ValueError:
                return
            if size == 0:
                while True:
                    while b"\r\n" not in buf:
                        try:
                            more = await asyncio.wait_for(
                                reader.read(1024), timeout=1.0)
                        except (asyncio.TimeoutError, ConnectionResetError,
                                BrokenPipeError):
                            return
                        if not more:
                            return
                        buf.extend(more)
                    le = buf.find(b"\r\n")
                    line = bytes(buf[:le])
                    del buf[:le + 2]
                    if line == b"":
                        return
            while len(buf) < size + 2:
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(min(chunk_size, size + 2 - len(buf))),
                        timeout=BODY_IDLE_TIMEOUT)
                except (asyncio.TimeoutError, ConnectionResetError,
                        BrokenPipeError):
                    return
                if not chunk:
                    return
                buf.extend(chunk)
            yield bytes(buf[:size]); del buf[:size + 2]
        return

    if cl:
        try:
            length = int(cl)
        except ValueError:
            length = -1
        if length >= 0:
            sent = 0
            if first_chunk:
                take = min(len(first_chunk), length)
                if take:
                    yield bytes(first_chunk[:take]); sent = take
            while sent < length:
                to_read = min(chunk_size, length - sent)
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(to_read), timeout=BODY_IDLE_TIMEOUT)
                except (asyncio.TimeoutError, ConnectionResetError,
                        BrokenPipeError):
                    return
                if not chunk:
                    return
                sent += len(chunk); yield chunk
            return

    if first_chunk:
        yield first_chunk
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(chunk_size),
                                           timeout=BODY_IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            return
        except (ConnectionResetError, BrokenPipeError):
            return
        if not chunk:
            return
        yield chunk


async def _iter_body_identity(reader, headers, first_chunk=b""):
    ce = _header(headers, "content-encoding").lower().strip()
    raw = _iter_body(reader, headers, first_chunk)
    if not ce or ce == "identity":
        async for chunk in raw:
            yield chunk
        return
    if "gzip" in ce:
        wbits = 31
    elif "deflate" in ce:
        wbits = 15
    else:
        async for chunk in raw:
            yield chunk
        return
    decomp = zlib.decompressobj(wbits)
    tried_raw = (wbits != 15)
    async for chunk in raw:
        try:
            out = decomp.decompress(chunk)
        except zlib.error:
            if not tried_raw and wbits == 15:
                tried_raw = True
                decomp = zlib.decompressobj(-15)
                try:
                    out = decomp.decompress(chunk)
                except Exception:
                    out = b""
            else:
                out = b""
        if out:
            yield out
    try:
        tail = decomp.flush()
        if tail:
            yield tail
    except Exception:
        pass


def _make_streaming_body(reader, writer, headers, first, target_url):
    async def _gen():
        try:
            async for chunk in _iter_body(reader, headers, first,
                                           chunk_size=STREAM_CHUNK_SIZE):
                yield chunk
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug("stream aborted: %s: %s", target_url, e)
        finally:
            await _close_writer(writer)
    return _gen


# ======================================================================
# Header assembly
# ======================================================================
def _collect_request_headers(req, target_url=""):
    h = dict(BROWSER_HEADERS)
    incoming = {}
    for k, v in req.headers.items():
        incoming[k.lower()] = v

    for k in [x for x in incoming.keys() if x.startswith("sec-fetch-")]:
        incoming.pop(k, None)

    for k, v in incoming.items():
        if k in FORWARD_REQUEST_HEADERS and v:
            h[k.title()] = v

    if h.get("Range") or h.get("range"):
        h["Accept-Encoding"] = "identity"

    path = ""
    if target_url:
        try:
            path = (urlparse(target_url).path or "").lower()
        except Exception:
            path = ""
    ext = os.path.splitext(path)[1] if path else ""

    if ext in STREAM_MEDIA_EXTS or ext in (".m3u8", ".mpd"):
        h["Accept-Encoding"] = "identity"

    if ext in (".js", ".mjs", ".cjs"):
        h["Accept"] = "*/*"
        h["Sec-Fetch-Dest"] = "script"
        h["Sec-Fetch-Mode"] = "no-cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext == ".css":
        h["Accept"] = "text/css,*/*;q=0.1"
        h["Sec-Fetch-Dest"] = "style"
        h["Sec-Fetch-Mode"] = "no-cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg",
                 ".ico", ".bmp"):
        h["Accept"] = ("image/avif,image/webp,image/apng,image/svg+xml,"
                       "image/*,*/*;q=0.8")
        h["Sec-Fetch-Dest"] = "image"
        h["Sec-Fetch-Mode"] = "no-cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext in (".woff", ".woff2", ".ttf", ".otf", ".eot"):
        h["Accept"] = "*/*"
        h["Sec-Fetch-Dest"] = "font"
        h["Sec-Fetch-Mode"] = "cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext in (".mp4", ".webm", ".m4v", ".mov", ".mkv", ".flv", ".ts",
                 ".m3u8", ".mpd", ".m4s", ".mp2t"):
        h["Accept"] = "*/*"
        h["Sec-Fetch-Dest"] = "video"
        h["Sec-Fetch-Mode"] = "no-cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext in (".mp3", ".m4a", ".aac", ".wav", ".ogg", ".oga", ".flac",
                 ".opus", ".weba"):
        h["Accept"] = "*/*"
        h["Sec-Fetch-Dest"] = "audio"
        h["Sec-Fetch-Mode"] = "no-cors"
        h["Sec-Fetch-Site"] = "cross-site"
    elif ext in (".json", ".map", ".wasm"):
        h["Accept"] = "*/*"
        h["Sec-Fetch-Dest"] = "empty"
        h["Sec-Fetch-Mode"] = "cors"
        h["Sec-Fetch-Site"] = "cross-site"
    else:
        browser_accept = incoming.get("accept", "").lower()
        if browser_accept and "text/html" in browser_accept:
            h["Sec-Fetch-Dest"] = "document"
            h["Sec-Fetch-Mode"] = "navigate"
            h["Sec-Fetch-Site"] = "cross-site"
            h["Sec-Fetch-User"] = "?1"
        else:
            h["Accept"] = incoming.get("accept") or "*/*"
            h["Sec-Fetch-Dest"] = "empty"
            h["Sec-Fetch-Mode"] = "cors"
            h["Sec-Fetch-Site"] = "cross-site"

    if h.get("Sec-Fetch-Mode") != "navigate":
        h.pop("Sec-Fetch-User", None)

    return h


def _referer_for(req, sess, target_url, origin):
    incoming = (req.headers.get("host") or "").lower()
    in_host = _norm_host(incoming).split(":", 1)[0] if incoming else ""
    try:
        target_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        target_host = ""

    def _host_ok(u):
        if not u:
            return False
        try:
            hp = (urlparse(u).hostname or "").lower()
            if not hp:
                return False
            if hp == in_host:
                return False
            return True
        except Exception:
            return False

    same = sess.last_page_url_for_origin(origin)
    if _host_ok(same):
        return same

    ref = extract_upstream(req.headers.get("referer", ""))
    if _host_ok(ref):
        return ref

    any_page = sess.last_page_url(exclude_host=target_host)
    if _host_ok(any_page):
        return any_page

    if _host_ok(sess.page_origin):
        return sess.page_origin

    if _host_ok(sess.last_origin):
        return sess.last_origin

    return origin + "/"


def _incoming_cookie_for_upstream(req):
    cookie = req.headers.get("cookie", "")
    if not cookie:
        return ""
    parts = []
    for p in cookie.split(";"):
        p = p.strip()
        if not p:
            continue
        name = p.split("=", 1)[0].strip().lower()
        if name in (SESSION_COOKIE, ORIGIN_COOKIE):
            continue
        parts.append(p)
    return "; ".join(parts)


def _build_response_headers(up_headers_list, is_rewritten):
    out = {}
    for k, v in up_headers_list:
        kl = k.lower()
        if kl in NEVER_EMIT:
            continue
        if kl == "location":
            continue
        if kl == "set-cookie":
            continue
        if kl == "content-length":
            continue
        if kl == "content-encoding":
            if is_rewritten:
                continue
            out["Content-Encoding"] = v
            continue
        if kl in FORWARD_RESPONSE_HEADERS:
            if kl in out:
                if not isinstance(out[kl], list):
                    out[kl] = [out[kl]]
                out[kl].append(v)
            else:
                out[kl] = v
    return out


def _verbatim_response_headers(up_headers_list):
    out = {}
    for k, v in up_headers_list:
        kl = k.lower()
        if kl in _HOP_BY_HOP:
            continue
        if kl == "location":
            continue
        if kl == "set-cookie":
            continue
        if kl == "content-type":
            continue
        if kl in out:
            if not isinstance(out[kl], list):
                out[kl] = [out[kl]]
            out[kl].append(v)
        else:
            out[kl] = v
    return out


def _add_cookies_to_response(resp, up_headers_list, origin_host):
    for sc in _headers_all(up_headers_list, "set-cookie"):
        if not sc.strip():
            continue
        resp.add_header("Set-Cookie", _rewrite_set_cookie(sc, origin_host))


def _add_cookies_to_streaming(headers_dict, up_headers_list, origin_host):
    cookies = [_rewrite_set_cookie(sc, origin_host)
               for sc in _headers_all(up_headers_list, "set-cookie")
               if sc.strip()]
    if cookies:
        headers_dict["Set-Cookie"] = cookies


def _headers_list_from_dict(d):
    out = []
    for k, v in d.items():
        if isinstance(v, list):
            for vv in v:
                out.append((k.lower(), str(vv)))
        else:
            out.append((k.lower(), str(v)))
    return out


# ======================================================================
# Interstitials — Cloudflare + Google sorry
# ======================================================================

_CHALLENGE_STYLE = """
<style>
:root{--bg:#070b16;--bg-2:#0d1526;--fg:#e2e8f0;--fg-muted:#94a3b8;
--fg-dim:#64748b;--line:rgba(148,163,184,.18);--accent:#38bdf8;
--accent-2:#818cf8;--warn:#f59e0b;--danger:#f87171;--ok:#10b981;
--grad:linear-gradient(135deg,#38bdf8,#818cf8)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,system-ui,-apple-system,sans-serif;background:var(--bg);
color:var(--fg);min-height:100vh;padding:24px;line-height:1.55}
.wrap{max-width:720px;margin:0 auto}
.card{background:var(--bg-2);border:1px solid var(--line);border-radius:16px;
padding:24px;margin-bottom:16px}
.badge{display:inline-flex;align-items:center;gap:6px;
background:rgba(245,158,11,.15);color:var(--warn);padding:4px 12px;
border-radius:8px;font-size:11px;font-weight:700;text-transform:uppercase;
letter-spacing:.08em;margin-bottom:14px}
.badge.host{background:rgba(56,189,248,.12);color:var(--accent)}
h1{font-size:20px;font-weight:800;letter-spacing:-.01em;line-height:1.25;
margin-bottom:10px}
h2{font-size:13px;font-weight:700;color:var(--fg-muted);margin-bottom:12px}
p{color:var(--fg-muted);font-size:13.5px;margin-bottom:12px}
p:last-child{margin-bottom:0}
code{background:rgba(2,6,23,.6);padding:2px 6px;border-radius:4px;
font-family:ui-monospace,monospace;font-size:.88em;color:var(--accent)}
.steps{display:flex;flex-direction:column;gap:12px;margin-top:14px}
.step{display:flex;gap:14px;padding:14px;background:#050a14;border-radius:11px;
border-left:3px solid var(--accent);align-items:flex-start}
.num{flex-shrink:0;width:28px;height:28px;border-radius:50%;background:var(--grad);
color:#0b1220;display:grid;place-items:center;font-weight:800;font-size:13px}
.body{flex:1;min-width:0}
h3{font-size:13.5px;font-weight:700;margin-bottom:6px;color:var(--fg)}
.body p{font-size:12.5px;margin-bottom:8px}
button{padding:9px 16px;border-radius:9px;border:none;font-family:inherit;
font-size:13px;font-weight:700;cursor:pointer;transition:.15s}
button.primary{background:var(--grad);color:#0b1220}
button.primary:hover{filter:brightness(1.1)}
button.primary:active{transform:scale(.98)}
button.ghost{background:transparent;border:1px solid var(--line);
color:var(--fg-muted)}
button.ghost:hover{background:rgba(56,189,248,.08);color:var(--accent);
border-color:rgba(56,189,248,.4)}
textarea{width:100%;min-height:80px;background:#050a14;color:var(--fg);
border:1px solid var(--line);border-radius:8px;padding:10px;
font-family:ui-monospace,monospace;font-size:12px;line-height:1.5;
resize:vertical;outline:none;margin-bottom:10px}
textarea:focus{border-color:rgba(56,189,248,.55);
box-shadow:0 0 0 3px rgba(56,189,248,.12)}
.status{margin-top:10px;font-size:12.5px;font-family:ui-monospace,monospace;
padding:10px 12px;border-radius:8px;display:none}
.status:not(:empty){display:block}
.status.busy{background:rgba(56,189,248,.1);color:var(--accent);
border-left:3px solid var(--accent)}
.status.ok{background:rgba(16,185,129,.1);color:var(--ok);
border-left:3px solid var(--ok)}
.status.err{background:rgba(248,113,113,.1);color:var(--danger);
border-left:3px solid var(--danger)}
.fail{margin-top:16px;padding:16px;border-radius:12px;
background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.25)}
.fail h3{color:var(--danger);margin-bottom:8px}
.fail ol{margin:10px 0 14px 20px;color:var(--fg-muted);font-size:12.5px}
.fail li{margin-bottom:6px;line-height:1.6}
.hidden{display:none}
.kbd{display:inline-block;padding:2px 7px;background:rgba(148,163,184,.12);
border:1px solid rgba(148,163,184,.2);border-radius:4px;
font-family:ui-monospace,monospace;font-size:11px;color:var(--fg)}
.row{display:flex;gap:8px;flex-wrap:wrap}
</style>
"""


def _cf_challenge_page(url, origin, challenge_type="cloudflare", attempt_count=0):
    target_host = urlparse(url).hostname or ""
    safe_host   = esc(target_host)
    url_js      = _json_for_script(url)
    origin_js   = _json_for_script(origin)
    host_js     = _json_for_script(target_host)

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Solve challenge · {safe_host} · Lynkio</title>
{_CHALLENGE_STYLE}
</head><body>
<div class="wrap">
  <div class="card">
    <div class="badge">⚠ Cloudflare challenge</div>
    <h1>{safe_host} is behind a Cloudflare gate</h1>
    <p>Lynkio already presents a real Chrome TLS fingerprint (curl_cffi · chrome124), but this site requires a <strong>JavaScript challenge or Turnstile widget</strong> that can only be cleared by a real browser on the real origin.</p>
    <p>Follow the three steps below — Lynkio will use whatever cookies you paste to retry automatically.</p>
    <div class="steps">
      <div class="step">
        <div class="num">1</div>
        <div class="body">
          <h3>Open the real URL in your browser</h3>
          <p>Solve the challenge in the tab that opens — no second browser needed.</p>
          <div class="row"><button id="openBtn" class="primary">Open {safe_host} ↗</button></div>
        </div>
      </div>
      <div class="step">
        <div class="num">2</div>
        <div class="body">
          <h3>Copy the cookies after solving</h3>
          <p>Once the challenge is cleared, the site sets <code>cf_clearance</code>. Open DevTools → <span class="kbd">Application</span> → <span class="kbd">Cookies</span> → <code>{safe_host}</code>. Copy <code>cf_clearance</code> (and <code>__cf_bm</code> if present).</p>
          <p style="font-size:11.5px;color:var(--fg-dim);"><strong>Note:</strong> Cloudflare may bind <code>cf_clearance</code> to your IP. If Lynkio's egress IP differs, the cookie is rejected — that is a Cloudflare feature, not a Lynkio bug. Self-host Lynkio on your home network, or use a residential proxy.</p>
        </div>
      </div>
      <div class="step">
        <div class="num">3</div>
        <div class="body">
          <h3>Paste them here</h3>
          <p>Paste the whole cookie header (<code>name1=value1; name2=value2</code>) or just the raw <code>cf_clearance</code> value — we'll assume the name.</p>
          <textarea id="cookieInput" placeholder="cf_clearance=abc123...; __cf_bm=..."></textarea>
          <div class="row">
            <button id="retryBtn" class="primary">Save &amp; retry →</button>
            <button id="clearBtn" class="ghost">Clear</button>
          </div>
          <div id="retryStatus" class="status"></div>
        </div>
      </div>
    </div>
    <div id="failBox" class="fail hidden">
      <h3>Verification keeps failing — stopping retries</h3>
      <p id="failMsg" style="font-size:12.5px;color:var(--fg-muted);"></p>
      <ol>
        <li><strong>Copy a fresh cookie.</strong> <code>cf_clearance</code> expires ~30 min; solve again.</li>
        <li><strong>Same IP.</strong> Cloudflare binds <code>cf_clearance</code> to your exit IP. Solved on home network + running Lynkio on Render → rejected. Self-host on the same network, or use a residential proxy.</li>
        <li><strong>Disable VPN</strong> where you solved the challenge.</li>
        <li><strong>Region licensing</strong> (Coinbase etc.) shows as 451/blocking page, not a challenge.</li>
        <li><strong>Stop retrying</strong> — open the URL directly.</li>
      </ol>
      <div class="row">
        <button id="openDirectBtn" class="primary">Open {safe_host} in browser</button>
        <button id="resetBtn" class="ghost">Reset and try again</button>
      </div>
    </div>
  </div>
</div>
<script>
(function(){{
  'use strict';
  var URL_    = {url_js};
  var ORIGIN_ = {origin_js};
  var HOST_   = {host_js};
  var MAX_ATTEMPTS = {CHALLENGE_MAX_ATTEMPTS};
  var attempts = {int(attempt_count)};
  var statusEl = document.getElementById('retryStatus');
  var failBox  = document.getElementById('failBox');
  var failMsg  = document.getElementById('failMsg');
  var retryBtn = document.getElementById('retryBtn');
  var openBtn  = document.getElementById('openBtn');
  var clearBtn = document.getElementById('clearBtn');
  var resetBtn = document.getElementById('resetBtn');
  var openDirect = document.getElementById('openDirectBtn');
  function setStatus(msg, kind){{
    statusEl.textContent = msg || '';
    statusEl.className = 'status' + (kind ? ' ' + kind : '');
  }}
  function parseCookies(text){{
    text = (text || '').trim();
    if (!text) return {{}};
    if (text.charAt(0) === '{{') {{
      try {{ var o = JSON.parse(text); if (o && typeof o === 'object') {{
        var c = {{}}; for (var k in o) if (typeof o[k]==='string') c[k]=o[k];
        if (Object.keys(c).length) return c;
      }} }} catch(e) {{}}
    }}
    var out = {{}};
    text.split(';').forEach(function(p){{
      p = p.trim(); if (!p) return;
      var i = p.indexOf('='); if (i === -1) return;
      var n = p.slice(0,i).trim(), v = p.slice(i+1).trim();
      if (n) out[n] = v;
    }});
    if (Object.keys(out).length === 0) out['cf_clearance'] = text;
    return out;
  }}
  function showFail(reason){{
    failBox.classList.remove('hidden');
    failMsg.textContent = reason || '';
  }}
  openBtn.onclick  = function(){{ window.open(URL_, '_blank', 'noopener,noreferrer'); }};
  openDirect.onclick = function(){{ window.open(URL_, '_blank', 'noopener,noreferrer'); }};
  clearBtn.onclick = function(){{ document.getElementById('cookieInput').value = ''; setStatus('', ''); }};
  resetBtn.onclick = async function(){{
    failBox.classList.add('hidden'); attempts = 0;
    try {{ await fetch('/proxy/reset-challenge', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{origin: ORIGIN_, url: URL_}})
    }}); }} catch(e){{}}
    setStatus('Retry counter reset. Paste a fresh cookie.', 'busy');
  }};
  retryBtn.onclick = async function(){{
    if (attempts >= MAX_ATTEMPTS) {{
      showFail('Retry limit reached. Paste a fresh cookie only if you solved the challenge on the same network just now.');
      return;
    }}
    var raw = document.getElementById('cookieInput').value;
    var cookies = parseCookies(raw);
    if (Object.keys(cookies).length === 0) {{
      setStatus('Paste at least one cookie value.', 'err'); return;
    }}
    retryBtn.disabled = true;
    setStatus('Testing with ' + Object.keys(cookies).length + ' cookie(s)…', 'busy');
    try {{
      var resp = await fetch('/proxy/add-cookies', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{ origin: ORIGIN_, url: URL_, cookies: cookies }})
      }});
      var data = await resp.json();
      if (data.ok) {{
        attempts = 0;
        setStatus('✓ Accepted — loading the page…', 'ok');
        setTimeout(function(){{ window.location.href = '/proxy?url=' + encodeURIComponent(URL_); }}, 400);
        return;
      }}
      attempts++;
      var msg = 'Still blocked. ';
      if (data.limit_reached) msg = 'Retry limit reached.';
      else if (data.google_sorry) msg += 'Google still returned the "unusual traffic" page (HTTP ' + (data.status||'?') + '). The NID cookie is stale or the datacenter IP is still blocked.';
      else if (data.challenge) msg += 'A new challenge was issued (HTTP ' + (data.status||'?') + '). The cookie is stale, expired, or bound to a different IP.';
      else if (data.status === 401 || data.status === 403 || data.status === 451) msg += 'Cookies accepted but access denied (HTTP ' + data.status + '). Likely a region or licensing block, not a challenge.';
      else if (data.error) msg += data.error;
      else msg += 'HTTP ' + (data.status||'?');
      setStatus(msg + '  (' + attempts + '/' + MAX_ATTEMPTS + ' attempts)', 'err');
      if (attempts >= MAX_ATTEMPTS || data.limit_reached) showFail(msg);
    }} catch(e) {{
      setStatus('Network error: ' + (e.message || e), 'err');
    }} finally {{
      retryBtn.disabled = false;
    }}
  }};
  if (attempts >= MAX_ATTEMPTS) showFail('Retry limit reached on a previous attempt.');
}})();
</script>
</body></html>"""

    return RawResponse(html.encode("utf-8"),
                       content_type="text/html; charset=utf-8",
                       status=200)


def _google_sorry_page(url, origin, attempt_count=0):
    """
    Google's anti-bot page. Served instead of forwarding Google's own
    /sorry/index — its scripts reference `solveSimpleChallenge` (a
    same-origin symbol) which fails to load through the proxy, producing
    a broken page. This interstitial replaces that entirely.
    """
    target_host = urlparse(url).hostname or ""
    safe_host   = esc(target_host)
    url_js      = _json_for_script(url)
    origin_js   = _json_for_script(origin)
    host_js     = _json_for_script(target_host)

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google blocked this request · Lynkio</title>
{_CHALLENGE_STYLE}
</head><body>
<div class="wrap">
  <div class="card">
    <div class="badge">⚠ Google "unusual traffic"</div>
    <h1>Google blocked this request from the proxy IP</h1>
    <p>Google detected automated access from <code>{safe_host}</code>'s shared IP. Datacenter ASNs (Render, AWS, GCP, Azure) are blanket-scored as bots — TLS fingerprint impersonation doesn't help because the check happens at the network layer, not the handshake.</p>
    <p>You have three options, ordered by reliability:</p>
    <div class="steps">
      <div class="step">
        <div class="num">1</div>
        <div class="body">
          <h3>Use a different search engine (recommended)</h3>
          <p>DuckDuckGo, Bing, Brave, and GitHub don't block datacenter IPs. Lynkio's <code>/search</code> now defaults to DuckDuckGo for exactly this reason.</p>
          <div class="row">
            <button class="primary" id="switchDdg">Use DuckDuckGo</button>
            <button class="ghost" id="switchBing">Use Bing</button>
            <button class="ghost" id="switchBrave">Use Brave</button>
          </div>
        </div>
      </div>
      <div class="step">
        <div class="num">2</div>
        <div class="body">
          <h3>Solve once in a real browser, then paste <code>NID</code></h3>
          <p>If you have a Google account with a session you trust, open <code>google.com</code> in your browser, sign in, solve any interstitials, then copy the <code>NID</code> (and <code>SID</code>) cookies from DevTools → <span class="kbd">Application</span> → <span class="kbd">Cookies</span> → <code>.google.com</code>.</p>
          <p style="font-size:11.5px;color:var(--fg-dim);"><strong>Caveat:</strong> Google ties <code>NID</code> to the exit IP for some products. It helps here more than it helps on Cloudflare-protected sites, but it may still be rejected if the sessions were created on a different ASN.</p>
        </div>
      </div>
      <div class="step">
        <div class="num">3</div>
        <div class="body">
          <h3>Use a residential proxy for Google specifically</h3>
          <p>Only reliable long-term path. Lynkio already honours <code>HTTPS_PROXY</code>. Set it to a residential or ISP proxy and Google will stop blocking. Not required for the other search engines.</p>
        </div>
      </div>
    </div>

    <div class="fail" style="background:rgba(56,189,248,.06);border-color:rgba(56,189,248,.25);margin-top:18px;">
      <h3 style="color:var(--accent);">Optional: paste NID / SID cookie</h3>
      <textarea id="cookieInput" placeholder="NID=abc123...; SID=..."></textarea>
      <div class="row">
        <button id="retryBtn" class="primary">Save &amp; retry →</button>
        <button id="clearBtn" class="ghost">Clear</button>
      </div>
      <div id="retryStatus" class="status"></div>
    </div>

    <div id="failBox" class="fail hidden">
      <h3>Verification keeps failing — stopping retries</h3>
      <p id="failMsg" style="font-size:12.5px;color:var(--fg-muted);"></p>
      <ol>
        <li>Google's datacenter-IP block cannot be bypassed by any cookie.</li>
        <li>Switch to DuckDuckGo or Bing — they proxy fine from Render.</li>
        <li>Or set <code>HTTPS_PROXY</code> to a residential proxy and restart.</li>
      </ol>
      <div class="row">
        <button id="resetBtn" class="ghost">Reset counter</button>
      </div>
    </div>
  </div>
</div>
<script>
(function(){{
  'use strict';
  var URL_    = {url_js};
  var ORIGIN_ = {origin_js};
  var MAX_ATTEMPTS = {CHALLENGE_MAX_ATTEMPTS};
  var attempts = {int(attempt_count)};
  var statusEl = document.getElementById('retryStatus');
  var failBox  = document.getElementById('failBox');
  var failMsg  = document.getElementById('failMsg');
  var retryBtn = document.getElementById('retryBtn');
  var clearBtn = document.getElementById('clearBtn');
  var resetBtn = document.getElementById('resetBtn');
  function setStatus(msg, kind){{
    statusEl.textContent = msg || '';
    statusEl.className = 'status' + (kind ? ' ' + kind : '');
  }}
  function parseCookies(text){{
    text = (text || '').trim();
    if (!text) return {{}};
    var out = {{}};
    text.split(';').forEach(function(p){{
      p = p.trim(); if (!p) return;
      var i = p.indexOf('='); if (i === -1) return;
      var n = p.slice(0,i).trim(), v = p.slice(i+1).trim();
      if (n) out[n] = v;
    }});
    return out;
  }}
  function showFail(reason){{ failBox.classList.remove('hidden'); failMsg.textContent = reason || ''; }}
  function openSearch(engine){{
    var params = new URLSearchParams(location.search);
    var q = params.get('q') || '';
    if (!q) {{
      var m = URL_.match(/[?&]q=([^&]+)/);
      if (m) q = decodeURIComponent(m[1]);
    }}
    window.location.href = '/search?q=' + encodeURIComponent(q) + '&engine=' + engine;
  }}
  document.getElementById('switchDdg').onclick  = function(){{ openSearch('ddg'); }};
  document.getElementById('switchBing').onclick = function(){{ openSearch('bing'); }};
  document.getElementById('switchBrave').onclick = function(){{ openSearch('brave'); }};
  clearBtn.onclick = function(){{ document.getElementById('cookieInput').value = ''; setStatus('', ''); }};
  resetBtn.onclick = async function(){{
    failBox.classList.add('hidden'); attempts = 0;
    try {{ await fetch('/proxy/reset-challenge', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{origin: ORIGIN_, url: URL_}})
    }}); }} catch(e){{}}
    setStatus('Retry counter reset.', 'busy');
  }};
  retryBtn.onclick = async function(){{
    if (attempts >= MAX_ATTEMPTS) {{
      showFail('Retry limit reached. Datacenter IP block cannot be cleared by cookie alone.');
      return;
    }}
    var cookies = parseCookies(document.getElementById('cookieInput').value);
    if (Object.keys(cookies).length === 0) {{ setStatus('Paste at least one cookie.', 'err'); return; }}
    retryBtn.disabled = true;
    setStatus('Testing with ' + Object.keys(cookies).length + ' cookie(s)…', 'busy');
    try {{
      var resp = await fetch('/proxy/add-cookies', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{ origin: ORIGIN_, url: URL_, cookies: cookies }})
      }});
      var data = await resp.json();
      if (data.ok) {{
        attempts = 0;
        setStatus('✓ Accepted — loading…', 'ok');
        setTimeout(function(){{ window.location.href = '/proxy?url=' + encodeURIComponent(URL_); }}, 400);
        return;
      }}
      attempts++;
      var msg = 'Still blocked. ';
      if (data.google_sorry) msg += 'Google still returned the "unusual traffic" page (HTTP ' + (data.status||'?') + ').';
      else if (data.limit_reached) msg = 'Retry limit reached.';
      else if (data.error) msg += data.error;
      else msg += 'HTTP ' + (data.status||'?');
      setStatus(msg + '  (' + attempts + '/' + MAX_ATTEMPTS + ')', 'err');
      if (attempts >= MAX_ATTEMPTS || data.limit_reached) showFail(msg);
    }} catch(e) {{
      setStatus('Network error: ' + (e.message || e), 'err');
    }} finally {{
      retryBtn.disabled = false;
    }}
  }};
  if (attempts >= MAX_ATTEMPTS) showFail('Retry limit reached.');
}})();
</script>
</body></html>"""

    return RawResponse(html.encode("utf-8"),
                       content_type="text/html; charset=utf-8",
                       status=200)


# ======================================================================
# Main proxy
# ======================================================================
async def serve_proxied(req, target_url, sid):
    sess = get_session(sid)
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if is_self_target(req, target_url):
        recovered = _recover_origin(req, sess)
        if recovered:
            rp = urlparse(recovered)
            if (rp.hostname or "").lower() != (parsed.hostname or "").lower():
                new_target = f"{rp.scheme}://{rp.netloc}{parsed.path}"
                if parsed.query:
                    new_target += "?" + parsed.query
                target_url = new_target
                parsed = urlparse(target_url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
        if is_self_target(req, target_url):
            return error_page(
                "Refusing to proxy to itself",
                f"<code>{esc(target_url)}</code> is this proxy.",
                508)

    sess.last_origin = origin
    sess.note_origin(origin)

    if target_url in sess.source_cache:
        return RawResponse(sess.source_cache[target_url],
                           content_type="text/html; charset=utf-8")

    wants = _requested_kind(req, target_url)

    out_headers = _collect_request_headers(req, target_url)
    out_headers["Referer"] = _referer_for(req, sess, target_url, origin)

    browser_cookie = _incoming_cookie_for_upstream(req)
    jar_cookie = sess.cookies.header_for(origin)
    merged = {}
    for c in (browser_cookie or "").split(";"):
        c = c.strip()
        if "=" in c:
            k, v = c.split("=", 1)
            merged[k.strip()] = v.strip()
    for c in (jar_cookie or "").split(";"):
        c = c.strip()
        if "=" in c:
            k, v = c.split("=", 1)
            merged[k.strip()] = v.strip()
    if merged:
        out_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in merged.items())

    use_stealth = (HAS_CURL_CFFI
                   and wants in ("document", "data", "")
                   and req.method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"))

    if use_stealth:
        jar_cookies = {}
        for c in (jar_cookie or "").split(";"):
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                jar_cookies[k.strip()] = v.strip()
        stealth = await _stealth_fetch_raw(
            target_url, method=req.method, headers=out_headers,
            body=req.body, timeout=30.0,
            allow_redirects=False, max_redirects=0,
            session_cookies=jar_cookies,
        )
        if stealth is not None:
            s_status = stealth["status"]
            s_headers = stealth["headers"]
            s_body = stealth["content"]
            s_final_url = stealth.get("url", target_url)
            s_headers_list = _headers_list_from_dict(s_headers)

            for sc in _headers_all(s_headers_list, "set-cookie"):
                try:
                    sess.cookies.merge_set_cookie(origin, sc)
                except Exception:
                    pass

            # Google sorry page (must be checked before CF, since Google
            # sometimes masks the status as 200)
            if _is_google_sorry(s_status, s_headers, s_body, s_final_url):
                log.warning("google sorry on %s (stealth, %d)", target_url, s_status)
                key = f"{origin}|{target_url}"
                attempts = int(sess.challenge_attempts.get(key, 0))
                return _google_sorry_page(target_url, origin, attempts)

            if _is_cf_challenge(s_status, s_headers, s_body):
                log.warning("cloudflare challenge on %s (stealth, %d)", target_url, s_status)
                key = f"{origin}|{target_url}"
                attempts = int(sess.challenge_attempts.get(key, 0))
                return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

            if 300 <= s_status < 400:
                loc = ""
                for k, v in s_headers_list:
                    if k == "location":
                        loc = v
                        break
                if loc:
                    absu = urljoin(target_url, loc)
                    resp_headers = {"Location": proxy_url(absu)}
                    resp = RawResponse(b"", status=s_status,
                                       headers=resp_headers,
                                       content_type="text/plain; charset=utf-8")
                    _add_cookies_to_response(resp, s_headers_list,
                                             parsed.hostname or "")
                    return resp

            ctype = ""
            for k, v in s_headers_list:
                if k == "content-type":
                    ctype = v
                    break
            low_ct = ctype.lower()

            if (not (os.path.splitext(parsed.path.lower())[1] in STATIC_EXTS)
                    and ("text/html" in low_ct or "application/xhtml" in low_ct)):
                sess.page_origin = origin
                ctx = {"upstream": target_url, "sid": sid,
                       "_injected": [s["code"] for s in sess.injected
                                     if s["enabled"]]}
                body = HTMLRewriter(target_url, ctype, ctx).rewrite(s_body)
                resp_headers = _build_response_headers(s_headers_list,
                                                        is_rewritten=True)
                resp = RawResponse(body, status=s_status,
                                   content_type="text/html; charset=utf-8",
                                   headers=resp_headers)
                _add_cookies_to_response(resp, s_headers_list,
                                         parsed.hostname or "")
                resp.add_header(
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
                resp.add_header(
                    "Set-Cookie",
                    f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
                return resp

            resp_headers = _build_response_headers(s_headers_list,
                                                    is_rewritten=False)
            resp = RawResponse(s_body, status=s_status, content_type=ctype,
                               headers=resp_headers)
            _add_cookies_to_response(resp, s_headers_list,
                                     parsed.hostname or "")
            return resp

    # ---- raw socket path ----
    try:
        reader, writer, status, up_headers, first = \
            await _open_upstream_stream(target_url, req.method,
                                        out_headers, req.body)
    except Exception as e:
        log.warning("upstream open failed for %s: %s", target_url, e)
        if wants == "script":
            resp = RawResponse(_js_stub(0, target_url, b""),
                               status=200,
                               content_type="application/javascript; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            return resp
        if wants == "style":
            resp = RawResponse(_css_stub(0, target_url), status=200,
                               content_type="text/css; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            return resp
        return error_page(
            "Fetch failed",
            f"<b>{esc(type(e).__name__)}</b><br>{esc(str(e))}<br>"
            f"<span style=\"color:#64748b;font-size:.8rem\">"
            f"target: {esc(target_url)}</span>",
            502)

    for sc in _headers_all(up_headers, "set-cookie"):
        try:
            sess.cookies.merge_set_cookie(origin, sc)
        except Exception:
            pass

    ctype = (_header(up_headers, "content-type")
             or "application/octet-stream").strip()
    low_ct = ctype.lower()
    ce = _header(up_headers, "content-encoding").lower().strip()
    content_range = _header(up_headers, "content-range")
    origin_host = parsed.hostname or ""
    path_lower = (parsed.path or "").lower()
    ext = os.path.splitext(path_lower)[1]

    sess.history.append({"url": target_url, "status": status,
                         "method": req.method, "ts": time.time()})

    if req.method == "HEAD":
        await _close_writer(writer)
        resp_headers = _verbatim_response_headers(up_headers)
        resp_headers["Content-Type"] = ctype
        resp = RawResponse(b"", status=status,
                           content_type=ctype, headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    is_binary = _is_media_response(req, target_url, ctype, ext,
                                    status, content_range)

    if is_binary:
        resp_headers = _verbatim_response_headers(up_headers)
        resp_headers.setdefault("Content-Type", ctype)
        _add_cookies_to_streaming(resp_headers, up_headers, origin_host)

        cl_up = _header(up_headers, "content-length")
        expected_len = None
        if cl_up:
            try:
                expected_len = int(cl_up)
            except Exception:
                expected_len = None

        if expected_len is not None and expected_len <= SMALL_MEDIA_MAX:
            buf = bytearray()
            ok = True
            try:
                async for chunk in _iter_body(reader, up_headers, first,
                                               chunk_size=STREAM_CHUNK_SIZE):
                    buf.extend(chunk)
            except Exception as e:
                ok = False
                log.debug("small media read failed: %s: %s", target_url, e)
            await _close_writer(writer)

            if ok and len(buf) == expected_len:
                resp = RawResponse(bytes(buf), status=status,
                                   content_type=ctype, headers=resp_headers)
                resp.add_header("Content-Length", str(len(buf)))
                _add_cookies_to_response(resp, up_headers, origin_host)
                return resp

        body_gen_factory = _make_streaming_body(reader, writer, up_headers,
                                                 first, target_url)
        return StreamingResponse(
            body_gen_factory(),
            content_type=ctype,
            headers=resp_headers,
            status=status)

    if 300 <= status < 400:
        loc = _header(up_headers, "location")
        absu = None
        if loc:
            try:
                lp = urlparse(loc)
                if lp.path == "/proxy":
                    inner_qs = parse_qs(lp.query)
                    inner = (inner_qs.get("url") or [""])[0]
                    if inner:
                        loc = inner
            except Exception:
                pass
            try:
                absu = urljoin(target_url, loc)
            except Exception:
                absu = None

        if wants == "script":
            new_ext = ""
            if absu:
                try:
                    new_ext = os.path.splitext(urlparse(absu).path.lower())[1]
                except Exception:
                    new_ext = ""
            if new_ext not in (".js", ".mjs", ".cjs"):
                try:
                    async for _c in _iter_body(reader, up_headers, first):
                        pass
                except Exception:
                    pass
                await _close_writer(writer)
                resp = RawResponse(_js_stub(status, target_url, b""),
                                   status=200,
                                   content_type="application/javascript; charset=utf-8")
                resp.add_header("Cache-Control", "no-store")
                _add_cookies_to_response(resp, up_headers, origin_host)
                return resp

        if wants == "style":
            new_ext = ""
            if absu:
                try:
                    new_ext = os.path.splitext(urlparse(absu).path.lower())[1]
                except Exception:
                    new_ext = ""
            if new_ext != ".css":
                try:
                    async for _c in _iter_body(reader, up_headers, first):
                        pass
                except Exception:
                    pass
                await _close_writer(writer)
                resp = RawResponse(_css_stub(status, target_url), status=200,
                                   content_type="text/css; charset=utf-8")
                resp.add_header("Cache-Control", "no-store")
                _add_cookies_to_response(resp, up_headers, origin_host)
                return resp

        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        if absu:
            if is_self_target(req, absu):
                ap = urlparse(absu)
                alt = origin + (ap.path or "/")
                if ap.query:
                    alt += "?" + ap.query
                if not is_self_target(req, alt):
                    absu = alt
            resp_headers["Location"] = proxy_url(absu)
        else:
            resp_headers["Location"] = loc or "/"

        await _close_writer(writer)
        resp = RawResponse(b"", status=status, headers=resp_headers,
                           content_type="text/plain; charset=utf-8")
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    is_m3u8 = ("mpegurl" in low_ct
               or "application/vnd.apple" in low_ct
               or path_lower.endswith(".m3u8"))
    if is_m3u8:
        buf = bytearray(); oversized = False
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_HLS_BYTES:
                    oversized = True
                    break
        except Exception:
            pass
        await _close_writer(writer)

        if oversized:
            head_bytes = bytes(buf)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=False)
            cl = _header(up_headers, "content-length")
            if cl:
                try: resp_headers["Content-Length"] = str(int(cl))
                except Exception: pass
            _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
            async def phls_raw():
                try:
                    yield head_bytes
                finally:
                    pass
            return StreamingResponse(
                phls_raw(),
                content_type="application/vnd.apple.mpegurl",
                headers=resp_headers, status=status)

        raw = bytes(buf)
        if ce and ce != "identity":
            raw = _decompress(raw, ce)
        charset = detect_charset(ctype, raw) or "utf-8"
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        rewritten = rewrite_m3u8(text, target_url)
        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        resp = RawResponse(rewritten.encode("utf-8"), status=status,
                           content_type="application/vnd.apple.mpegurl; charset=utf-8",
                           headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    is_static_asset = ext in STATIC_EXTS

    if wants == "script":
        if status >= 400 or ("text/html" in low_ct or "text/xml" in low_ct
                              or "application/xhtml" in low_ct):
            preview = b""
            try:
                preview = bytes(first[:200])
            except Exception:
                preview = b""
            try:
                async for _c in _iter_body(reader, up_headers, first):
                    pass
            except Exception:
                pass
            await _close_writer(writer)
            resp = RawResponse(_js_stub(status, target_url, preview),
                               status=200,
                               content_type="application/javascript; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            _add_cookies_to_response(resp, up_headers, origin_host)
            return resp
        peek = b""
        try:
            peek = bytes(first[:512])
        except Exception:
            peek = b""
        if _looks_like_html(peek):
            try:
                async for _c in _iter_body(reader, up_headers, first):
                    pass
            except Exception:
                pass
            await _close_writer(writer)
            resp = RawResponse(_js_stub(status, target_url, peek),
                               status=200,
                               content_type="application/javascript; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            _add_cookies_to_response(resp, up_headers, origin_host)
            return resp

    if wants == "style":
        if status >= 400 or "text/html" in low_ct:
            try:
                async for _c in _iter_body(reader, up_headers, first):
                    pass
            except Exception:
                pass
            await _close_writer(writer)
            resp = RawResponse(_css_stub(status, target_url), status=200,
                               content_type="text/css; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            _add_cookies_to_response(resp, up_headers, origin_host)
            return resp

    if is_static_asset and ext in (".js", ".mjs", ".cjs"):
        if status >= 400 or ("text/html" in low_ct or "text/xml" in low_ct):
            try:
                async for _c in _iter_body(reader, up_headers, first):
                    pass
            except Exception:
                pass
            await _close_writer(writer)
            resp = RawResponse(_js_stub(status, target_url, b""),
                               status=200,
                               content_type="application/javascript; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            _add_cookies_to_response(resp, up_headers, origin_host)
            return resp

    if is_static_asset and ext == ".css":
        if status >= 400 or "text/html" in low_ct:
            try:
                async for _c in _iter_body(reader, up_headers, first):
                    pass
            except Exception:
                pass
            await _close_writer(writer)
            resp = RawResponse(_css_stub(status, target_url), status=200,
                               content_type="text/css; charset=utf-8")
            resp.add_header("Cache-Control", "no-store")
            _add_cookies_to_response(resp, up_headers, origin_host)
            return resp

    if (not is_static_asset) and ("text/html" in low_ct
                                   or "application/xhtml" in low_ct):
        buf = bytearray(); rewritable = True
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_REWRITE_BYTES:
                    rewritable = False
                    break
        except Exception as e:
            log.debug("html read stopped: %s", e)
        await _close_writer(writer)

        raw = bytes(buf)
        hdr_dict = {k: v for k, v in up_headers}
        if _is_google_sorry(status, hdr_dict, raw, target_url):
            log.warning("google sorry on %s (raw, %d)", target_url, status)
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _google_sorry_page(target_url, origin, attempts)

        if _is_cf_challenge(status, hdr_dict, raw):
            log.warning("cloudflare challenge on %s (raw, %d)", target_url, status)
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

        if rewritable:
            if ce and ce != "identity":
                raw = _decompress(raw, ce)
            sess.page_origin = origin
            ctx = {"upstream": target_url, "sid": sid,
                   "_injected": [s["code"] for s in sess.injected
                                 if s["enabled"]]}
            body = HTMLRewriter(target_url, ctype, ctx).rewrite(raw)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=True)
            resp = RawResponse(body, status=status,
                               content_type="text/html; charset=utf-8",
                               headers=resp_headers)
            _add_cookies_to_response(resp, up_headers, origin_host)
            resp.add_header("Set-Cookie",
                            f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
            resp.add_header("Set-Cookie",
                            f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
            return resp

        head_bytes = bytes(buf)
        resp_headers = _build_response_headers(up_headers, is_rewritten=False)
        cl = _header(up_headers, "content-length")
        if cl:
            try: resp_headers["Content-Length"] = str(int(cl))
            except Exception: pass
        _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
        async def passthrough_html():
            try:
                yield head_bytes
            finally:
                pass
        return StreamingResponse(passthrough_html(),
                                 content_type="text/html; charset=utf-8",
                                 headers=resp_headers, status=status)

    if (not is_static_asset) and "text/css" in low_ct:
        buf = bytearray(); oversized = False
        try:
            async for chunk in _iter_body(reader, up_headers, first):
                buf.extend(chunk)
                if len(buf) > MAX_CSS_BYTES:
                    oversized = True
                    break
        except Exception:
            pass
        await _close_writer(writer)

        if oversized:
            head_bytes = bytes(buf)
            resp_headers = _build_response_headers(up_headers,
                                                    is_rewritten=False)
            cl = _header(up_headers, "content-length")
            if cl:
                try: resp_headers["Content-Length"] = str(int(cl))
                except Exception: pass
            _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
            async def pcss():
                try:
                    yield head_bytes
                finally:
                    pass
            return StreamingResponse(pcss(),
                                     content_type="text/css; charset=utf-8",
                                     headers=resp_headers, status=status)

        raw = bytes(buf)
        if ce and ce != "identity":
            raw = _decompress(raw, ce)
        rewritten = rewrite_css_body(raw, target_url, ctype)
        resp_headers = _build_response_headers(up_headers, is_rewritten=True)
        resp = RawResponse(rewritten, status=status,
                           content_type="text/css; charset=utf-8",
                           headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    resp_headers = _build_response_headers(up_headers, is_rewritten=False)

    cl_up = _header(up_headers, "content-length")
    expected_len = None
    if cl_up:
        try:
            expected_len = int(cl_up)
            resp_headers["Content-Length"] = str(expected_len)
        except Exception:
            pass

    if expected_len is not None and expected_len > MAX_BUFFER_BYTES:
        _add_cookies_to_streaming(resp_headers, up_headers, origin_host)
        body_gen_factory = _make_streaming_body(reader, writer, up_headers,
                                                 first, target_url)
        return StreamingResponse(
            body_gen_factory(),
            content_type=ctype,
            headers=resp_headers,
            status=status)

    buf = bytearray()
    overflow = False
    read_complete = True
    try:
        async for chunk in _iter_body(reader, up_headers, first,
                                       chunk_size=STREAM_CHUNK_SIZE):
            buf.extend(chunk)
            if len(buf) > MAX_BUFFER_BYTES:
                overflow = True
                break
    except Exception as e:
        read_complete = False
        log.debug("passthrough read stopped for %s: %s", target_url, e)

    if not overflow and read_complete:
        await _close_writer(writer)

        buf_len = len(buf)
        if expected_len is not None and buf_len != expected_len:
            log.warning("short read for %s: got %d of %d bytes",
                        target_url, buf_len, expected_len)
            resp_headers.pop("Content-Length", None)

        raw_bytes = bytes(buf)
        hdr_dict = {k: v for k, v in up_headers}
        if _is_google_sorry(status, hdr_dict, raw_bytes, target_url):
            log.warning("google sorry on %s (data)", target_url)
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _google_sorry_page(target_url, origin, attempts)

        if _is_cf_challenge(status, hdr_dict, raw_bytes):
            log.warning("cloudflare challenge on %s (data)", target_url)
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

        resp = RawResponse(raw_bytes, status=status,
                           content_type=ctype, headers=resp_headers)
        try:
            existing = {k.lower() for k in (resp.headers or {}).keys()}
        except Exception:
            existing = set()
        if "content-length" not in existing:
            resp.add_header("Content-Length", str(buf_len))
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    head_bytes = bytes(buf)
    resp_headers.pop("Content-Length", None)
    _add_cookies_to_streaming(resp_headers, up_headers, origin_host)

    async def passthrough():
        try:
            yield head_bytes
            async for chunk in _iter_body(reader, up_headers, b"",
                                           chunk_size=STREAM_CHUNK_SIZE):
                yield chunk
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug("stream aborted for %s: %s", target_url, e)
        finally:
            await _close_writer(writer)

    return StreamingResponse(passthrough(),
                             content_type=ctype,
                             headers=resp_headers, status=status)


async def _try_proxy_candidates(req, sess, sid, path_only, qs, candidates):
    dest = (req.headers.get("sec-fetch-dest") or "").lower()
    if dest in ("document", "iframe", "frame") and sess.page_origin:
        po = sess.page_origin
        if po in candidates:
            candidates = [po] + [c for c in candidates if c != po]

    for origin in candidates:
        target = origin.rstrip("/") + path_only
        if qs:
            target += "?" + qs
        try:
            out_headers = _collect_request_headers(req, target)
            out_headers["Referer"] = _referer_for(req, sess, target, origin)
            incoming_cookie = _incoming_cookie_for_upstream(req)
            if incoming_cookie:
                out_headers["Cookie"] = incoming_cookie

            reader, writer, status, up_headers, first = \
                await _open_upstream_stream(target, req.method,
                                            out_headers, req.body)
            if 400 <= status < 500 and status not in (401, 403):
                await _close_writer(writer)
                continue
            await _close_writer(writer)
            return await serve_proxied(req, target, sid)
        except Exception as e:
            log.debug("candidate %s failed: %s", origin, e)
            continue
    return None


# ======================================================================
# Stealth monkey-patch of app.fetch
# ======================================================================
_original_fetch = app.fetch

async def _stealth_fetch(url, method="GET", headers=None, timeout=30.0,
                          **kwargs):
    if HAS_CURL_CFFI and method.upper() in ("GET", "HEAD"):
        try:
            stealth = await _stealth_fetch_raw(
                url, method=method, headers=headers,
                timeout=timeout, allow_redirects=kwargs.get("allow_redirects", True),
                max_redirects=kwargs.get("max_redirects", 5),
            )
            if stealth is not None:
                if not _is_cf_challenge(stealth["status"],
                                        stealth["headers"],
                                        stealth["content"]) \
                   and not _is_google_sorry(stealth["status"],
                                             stealth["headers"],
                                             stealth["content"],
                                             str(stealth.get("url", ""))):
                    from lynkio.server import FetchResponse  # type: ignore
                    hdrs = {k.lower(): v for k, v in stealth["headers"].items()}
                    return FetchResponse(
                        stealth["status"], hdrs, stealth["content"],
                        url=str(stealth["url"]), reason="")
        except Exception as e:
            log.debug("stealth fetch (toolkit) failed %s: %s", url, e)
    return await _original_fetch(url, method=method, headers=headers,
                                  timeout=timeout, **kwargs)

app.fetch = _stealth_fetch


# ======================================================================
# WebSocket control plane
# ======================================================================
WS_CLIENTS = set()


async def _broadcast(event, data, exclude_id=None):
    payload = json.dumps({"event": event, "data": data})
    for cid in list(app._clients_all.keys()):
        if cid == exclude_id:
            continue
        c = app._clients_all.get(cid)
        if c and not c.closed:
            try:
                await c.send(payload)
            except Exception:
                pass


@app.on("subscribe")
async def _on_subscribe(client, data):
    WS_CLIENTS.add(client.id)
    await client.send(json.dumps({
        "event": "subscribed",
        "data": {"client_id": client.id, "peer_count": len(WS_CLIENTS)},
    }))


@app.on("nav")
async def _on_nav(client, data):
    await _broadcast("nav", data, exclude_id=client.id)


@app.on("progress")
async def _on_progress(client, data):
    await _broadcast("progress", data, exclude_id=client.id)


@app.on("console")
async def _on_console(client, data):
    await _broadcast("console", data, exclude_id=client.id)


@app.on("ping")
async def _on_ping(client, data):
    await client.send(json.dumps({
        "event": "pong",
        "data": {"ts": time.time()},
    }))


@app.on_internal("connect")
async def _on_connect(client, data=None):
    log.info("ws connect %s", client.id)


@app.on_internal("disconnect")
async def _on_disconnect(client, data=None):
    WS_CLIENTS.discard(client.id)
    log.info("ws disconnect %s", client.id)


# ======================================================================
# Tool dispatch
# ======================================================================
TOOLS = {}


def tool(name):
    def deco(fn):
        TOOLS[name] = fn
        return fn
    return deco


async def _get_form(req):
    body = getattr(req, "body", None) or b""
    ct = (req.headers.get("content-type") or "").lower()

    if body and "application/json" in ct:
        try:
            data = json.loads(body.decode("utf-8", "ignore"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    try:
        data = await req.form()
        if isinstance(data, dict) and "fields" in data:
            return data["fields"]
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    if body and "urlencoded" in ct:
        try:
            return dict(parse_qsl(body.decode("utf-8", "ignore")))
        except Exception:
            pass

    try:
        return dict(req.query_params)
    except Exception:
        return {}


# ---- /proxy/add-cookies + /proxy/reset-challenge (v19.1) -------------
@app.route("/proxy/add-cookies", methods=["POST"])
async def proxy_add_cookies(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)

    try:
        body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return json_response({"ok": False, "error": "invalid JSON"}, status=400)

    origin  = (body.get("origin") or "").strip()
    url     = (body.get("url") or "").strip()
    cookies = body.get("cookies") or {}

    if not origin or not url or not isinstance(cookies, dict):
        return json_response(
            {"ok": False, "error": "origin, url, cookies required"},
            status=400)

    key = f"{origin}|{url}"
    attempts_so_far = int(sess.challenge_attempts.get(key, 0))
    if attempts_so_far >= CHALLENGE_MAX_ATTEMPTS:
        return json_response({
            "ok": False,
            "limit_reached": True,
            "error": "retry limit reached for this URL — verification keeps failing",
        }, status=429)

    saved = 0
    for name, value in cookies.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        name = name.strip(); value = value.strip()
        if not name or not value:
            continue
        sess.cookies.set(origin, name, value,
                         path="/", secure=True, samesite="None")
        saved += 1

    log.info("challenge: added %d cookie(s) for %s (attempt %d/%d) session=%s",
             saved, origin, attempts_so_far + 1, CHALLENGE_MAX_ATTEMPTS, sid[:8])

    if not HAS_CURL_CFFI:
        return json_response({
            "ok": False,
            "error": "curl_cffi unavailable — cannot retry with a valid TLS fingerprint",
        }, status=500)

    jar_raw = sess.cookies.list(origin)
    jar = {}
    for n, info in jar_raw.items():
        if isinstance(info, dict) and info.get("value"):
            jar[n] = info["value"]

    stealth = await _stealth_fetch_raw(
        url, method="GET", headers=BROWSER_HEADERS,
        timeout=30.0, allow_redirects=False, max_redirects=0,
        session_cookies=jar,
    )

    if stealth is None:
        sess.challenge_attempts[key] = attempts_so_far + 1
        return json_response({
            "ok": False,
            "error": "upstream fetch failed (network or DNS)",
        }, status=502)

    s_status  = stealth["status"]
    s_headers = stealth["headers"]
    s_body    = stealth["content"]
    s_final_url = stealth.get("url", url)

    for k, v in s_headers.items():
        if k.lower() == "set-cookie":
            vals = v if isinstance(v, list) else [v]
            for sv in vals:
                try:
                    sess.cookies.merge_set_cookie(origin, sv)
                except Exception:
                    pass

    if _is_google_sorry(s_status, s_headers, s_body, s_final_url):
        sess.challenge_attempts[key] = attempts_so_far + 1
        return json_response({
            "ok": False,
            "status": s_status,
            "google_sorry": True,
            "error": "upstream still returned Google's unusual-traffic page",
        })

    if _is_cf_challenge(s_status, s_headers, s_body):
        sess.challenge_attempts[key] = attempts_so_far + 1
        return json_response({
            "ok": False,
            "status": s_status,
            "challenge": True,
            "error": "upstream still returned a Cloudflare challenge",
        })

    sess.challenge_attempts.pop(key, None)

    if 400 <= s_status < 600:
        return json_response({
            "ok": False,
            "status": s_status,
            "error": f"HTTP {s_status} — not a challenge, likely access block",
        })

    return json_response({"ok": True, "status": s_status})


@app.route("/proxy/reset-challenge", methods=["POST"])
async def proxy_reset_challenge(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    try:
        body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
    except json.JSONDecodeError:
        body = {}
    origin = (body.get("origin") or "").strip()
    url    = (body.get("url") or "").strip()
    if origin and url:
        sess.challenge_attempts.pop(f"{origin}|{url}", None)
    return json_response({"ok": True})


# ---- tools -----------------------------------------------------------
@tool("headers")
async def t_headers(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            method="HEAD", allow_redirects=True, max_redirects=3,
                            prefer_http2=True, use_doh=True)
        return {"status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"status": 0, "headers": {"error": str(e)}}


@tool("source")
async def t_source(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=20.0)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return {"body": body.decode("utf-8", errors="replace")[:500000]}
    except Exception as e:
        return {"error": str(e)}


@tool("dns")
async def t_dns(req):
    url = req.query_params.get("url") or ""
    host = urlparse(url).hostname or url
    addrs = []
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
        for info in infos:
            fam, _, _, _, sa = info
            ip = sa[0]
            tag = "IPv6" if fam == socket.AF_INET6 else "IPv4"
            entry = f"{ip} ({tag})"
            if entry not in addrs:
                addrs.append(entry)
    except Exception:
        pass
    return {"host": host, "addresses": addrs}


@tool("diag")
async def t_diag(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    return await app.diagnose_url(url)


@tool("history")
async def t_history(req):
    sid, _ = session_from_req(req)
    return {"entries": list(get_session(sid).history)[-60:][::-1]}


@tool("inject/list")
async def t_inject_list(req):
    sid, _ = session_from_req(req)
    return {"snippets": [{"id": s["id"], "name": s["name"],
                          "enabled": s["enabled"], "size": len(s["code"])}
                         for s in get_session(sid).injected]}


@tool("inject/list-full")
async def t_inject_list_full(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    return {"snippets": [
        {"id": s["id"], "name": s["name"],
         "code": s["code"], "enabled": s["enabled"],
         "size": len(s["code"])}
        for s in sess.injected
    ]}


@tool("inject/add")
async def t_inject_add(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    name = (fields.get("name") or "unnamed").strip()
    code = fields.get("code") or ""
    if not code.strip():
        return {"ok": False, "reason": "empty"}
    snippet = {"id": uuid.uuid4().hex[:8], "name": name,
               "code": code, "enabled": True}
    sess.injected.append(snippet)
    return {"ok": True, "id": snippet["id"], "name": name}


@tool("inject/toggle")
async def t_inject_toggle(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    sid_in = (fields.get("id") or "").strip()
    for s in sess.injected:
        if s["id"] == sid_in:
            s["enabled"] = not s["enabled"]
            return {"ok": True, "enabled": s["enabled"]}
    return {"ok": False, "reason": "not found"}


@tool("inject/delete")
async def t_inject_delete(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    sid_in = (fields.get("id") or "").strip()
    before = len(sess.injected)
    sess.injected = [s for s in sess.injected if s["id"] != sid_in]
    return {"ok": len(sess.injected) < before}


@tool("cookies/list")
async def t_cookies_list(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    url = req.query_params.get("url") or sess.last_origin or ""
    origin = ""
    try:
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}"
    except Exception:
        pass
    jar = sess.cookies.list(origin) if origin else {}
    return {"origin": origin, "cookies": jar}


@tool("cookies/set")
async def t_cookies_set(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    name = (fields.get("name") or "").strip()
    value = fields.get("value") or ""
    if not origin or not name:
        return {"ok": False, "error": "origin and name required"}
    attrs = {}
    for k in ("path", "domain", "samesite", "expires"):
        v = fields.get(k)
        if v:
            attrs[k] = v
    if fields.get("secure"):
        attrs["secure"] = True
    if fields.get("httponly"):
        attrs["httponly"] = True
    sess.cookies.set(origin, name, value, **attrs)
    return {"ok": True}


@tool("cookies/delete")
async def t_cookies_delete(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    name = (fields.get("name") or "").strip()
    if not origin or not name:
        return {"ok": False}
    sess.cookies.delete(origin, name)
    return {"ok": True}


@tool("cookies/clear")
async def t_cookies_clear(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    fields = await _get_form(req)
    origin = (fields.get("origin") or "").strip()
    if not origin:
        return {"ok": False}
    sess.cookies.clear(origin)
    return {"ok": True}


def _classify_content(ctype, url):
    ct = (ctype or "").lower()
    path = urlparse(url).path.lower()
    if any(x in ct for x in ("text/", "json", "xml", "javascript", "yaml",
                              "csv", "html", "css", "x-sh", "sql")):
        return "text"
    if path.endswith((".txt", ".json", ".xml", ".html", ".htm", ".css",
                      ".js", ".mjs", ".ts", ".md", ".log", ".yml", ".yaml",
                      ".env", ".ini", ".conf", ".cfg", ".sh", ".sql", ".csv")):
        return "text"
    if any(x in ct for x in ("image/", "video/", "audio/")):
        return "media"
    if "pdf" in ct:
        return "pdf"
    if any(x in ct for x in ("zip", "gzip", "tar", "7z", "rar",
                              "octet-stream")):
        return "binary"
    return "binary"


@tool("file/view")
async def t_file_view(req):
    url = req.query_params.get("url") or ""
    if not url:
        return {"error": "missing url"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=20.0,
                            allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        ctype = r.headers.get("content-type", "application/octet-stream")
        kind = _classify_content(ctype, url)
        result = {"url": url, "status": r.status_code, "content_type": ctype,
                  "size": len(body), "kind": kind}
        if kind == "text":
            charset = detect_charset(ctype, body)
            try:
                result["body"] = body.decode(charset,
                                             errors="replace")[:200000]
            except LookupError:
                result["body"] = body.decode("utf-8",
                                             errors="replace")[:200000]
            result["truncated"] = len(body) > 200000
        return result
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# (All other tools — recon, osint, web, injection, http, cms, auth,
# enumeration, shell, captcha, encode, payloads — are unchanged from
# v19.0 and are omitted here only for brevity of this reply. Copy them
# verbatim from your v19.0 file. The dispatcher will still find them.)


# ======================================================================
# Static / tools / proxy / search / index
# ======================================================================
def _guess_mime(path):
    mt, _ = mimetypes.guess_type(path)
    if mt:
        return mt
    ext = os.path.splitext(path)[1].lower()
    return {
        ".js":   "application/javascript; charset=utf-8",
        ".mjs":  "application/javascript; charset=utf-8",
        ".cjs":  "application/javascript; charset=utf-8",
        ".css":  "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".htm":  "text/html; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".map":  "application/json; charset=utf-8",
        ".svg":  "image/svg+xml",
        ".wasm": "application/wasm",
        ".woff": "font/woff",
        ".woff2":"font/woff2",
        ".ttf":  "font/ttf",
        ".otf":  "font/otf",
        ".ico":  "image/x-icon",
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".webp": "image/webp",
        ".avif": "image/avif",
        ".mp4":  "video/mp4",
        ".webm": "video/webm",
        ".mp3":  "audio/mpeg",
        ".wav":  "audio/wav",
        ".ogg":  "audio/ogg",
        ".txt":  "text/plain; charset=utf-8",
        ".md":   "text/markdown; charset=utf-8",
        ".xml":  "application/xml; charset=utf-8",
    }.get(ext, "application/octet-stream")


def _serve_static_file(rel_path):
    base_dir = STATIC_DIR
    sub = rel_path
    if rel_path.startswith("templates/"):
        base_dir = TEMPLATES_DIR
        sub = rel_path[len("templates/"):]

    sub = os.path.normpath(sub).lstrip("/\\")
    if sub.startswith("..") or os.path.isabs(sub):
        return None
    full = os.path.join(base_dir, sub)
    real_base = os.path.realpath(base_dir)
    real_full = os.path.realpath(full)
    if (not real_full.startswith(real_base + os.sep)
            and real_full != real_base):
        return None
    if not os.path.isfile(real_full):
        return None

    try:
        with open(real_full, "rb") as f:
            body = f.read()
    except Exception as e:
        log.warning("static read failed %s: %s", real_full, e)
        return None

    ctype = _guess_mime(real_full)
    resp = RawResponse(body, status=200, content_type=ctype)
    resp.add_header("Cache-Control", "no-cache, no-store, must-revalidate")
    resp.add_header("Access-Control-Allow-Origin", "*")
    return resp


@app.get("/static/*")
async def static_file(req, wildcard=""):
    path = (wildcard or "").split("?", 1)[0]
    resp = _serve_static_file(path)
    if resp is None:
        return error_page("Not found",
                          f"<code>/static/{esc(path)}</code> not found.", 404)
    return resp


@app.get("/favicon.ico")
async def favicon(req):
    for name in ("favicon.ico", "favicon.png", "favicon.svg"):
        resp = _serve_static_file(name)
        if resp is not None:
            return resp
    return RawResponse(b"", status=204, content_type="image/x-icon")


@app.route("/tool/*", methods=["GET", "POST", "OPTIONS"])
async def tool_dispatch(req, wildcard=""):
    parts = (wildcard or "").split("?", 1)
    name = parts[0].strip("/")
    fn = TOOLS.get(name)
    if fn is None:
        return json_response({"error": f"unknown tool: {name}"}, status=404)
    try:
        result = await fn(req)
        if isinstance(result, (RawResponse, StreamingResponse)):
            return result
        return json_response(result)
    except Exception as e:
        log.exception("tool %s failed", name)
        return json_response({"error": f"{type(e).__name__}: {e}"}, status=500)


@app.get("/")
async def index(req):
    resp = _serve_static_file("templates/home.html")
    if resp is None:
        return error_page("Not found", "templates/home.html missing.", 404)
    return resp


@app.get("/tabs")
async def tabs_page(req):
    resp = _serve_static_file("templates/tabs.html")
    if resp is None:
        return error_page("Not found", "templates/tabs.html missing.", 404)
    return resp


@app.get("/search")
async def search(req):
    q = (req.query_params.get("q") or "").strip()
    engine = (req.query_params.get("engine") or DEFAULT_SEARCH_ENGINE).lower()
    if not q:
        return error_page("Empty query", "Type a search query.", 400)
    if engine not in SEARCH_ENGINES:
        engine = DEFAULT_SEARCH_ENGINE
    _, tpl = SEARCH_ENGINES[engine]
    sid, _ = session_from_req(req)
    return await serve_proxied(req, tpl.replace("{q}", quote(q)), sid)


@app.route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_route(req):
    raw_q = req.path.split("?", 1)[1] if "?" in req.path else ""
    qs = parse_qs(raw_q, keep_blank_values=True)
    urls = qs.pop("url", [])
    if not urls or not urls[0].strip():
        ct = req.headers.get("content-type", "").lower()
        if req.body and "x-www-form-urlencoded" in ct:
            try:
                urls = parse_qs(
                    req.body.decode("utf-8", errors="ignore")).get("url", [])
            except Exception:
                pass
    if not urls or not urls[0].strip():
        return error_page("Missing URL", "No <code>url</code> parameter.", 400)
    target = urls[0].strip()
    if qs:
        target += ("&" if "?" in target else "?") + urlencode(qs, doseq=True)
    if not target.startswith(("http://", "https://")):
        if looks_like_url(target):
            target = "https://" + target
        else:
            sid, _ = session_from_req(req)
            s_url = SEARCH_ENGINES[DEFAULT_SEARCH_ENGINE][1].replace("{q}", quote(target))
            return await serve_proxied(req, s_url, sid)
    p = urlparse(target)
    if p.scheme not in ("http", "https") or not p.netloc:
        return error_page("Invalid URL",
                          f"Could not parse: {esc(target)}", 400)
    sid, _ = session_from_req(req)
    return await serve_proxied(req, target, sid)


# ======================================================================
# CLONER — installed BEFORE catch-all
# ======================================================================
cloner.install(app, {
    "get_session":      get_session,
    "Session":          Session,
    "RawResponse":      RawResponse,
    "json_response":    json_response,
    "error_page":       error_page,
    "SESSION_COOKIE":   SESSION_COOKIE,
    "session_from_req": session_from_req,
    "SESSIONS":         SESSIONS,
})


@app.route("/*", methods=["GET", "POST", "PUT", "PATCH",
                           "DELETE", "OPTIONS", "HEAD"])
async def catch_all(req, wildcard=""):
    parts = req.path.split("?", 1)
    path_only = parts[0] or "/"
    qs = parts[1] if len(parts) > 1 else ""

    if path_only == "/favicon.ico":
        return RawResponse(b"", status=204, content_type="image/x-icon")

    if path_only.startswith(("/static/", "/lynkio/", "/tool/", "/__lynk_")):
        return error_page("Not found",
                          f"<code>{esc(path_only)}</code> not found.", 404)

    sid, _ = session_from_req(req)
    sess = get_session(sid)

    candidates = []
    ref = req.headers.get("referer", "")
    up = extract_upstream(ref)
    if up:
        p = urlparse(up)
        if p.scheme in ("http", "https") and p.netloc:
            candidates.append(f"{p.scheme}://{p.netloc}")
    for (o, ts) in sess.recent_origins:
        if o not in candidates:
            candidates.append(o)
    cv = req.cookies.get(ORIGIN_COOKIE, "")
    if cv:
        p = urlparse(unquote(cv))
        if p.scheme in ("http", "https") and p.netloc:
            o = f"{p.scheme}://{p.netloc}"
            if o not in candidates:
                candidates.append(o)

    if not candidates:
        return error_page(
            "Lost context",
            f"Received <code>{esc(path_only)}</code> but couldn't determine "
            "the upstream host. <a href='/'>Go home</a> and start a new session.",
            404)

    result = await _try_proxy_candidates(req, sess, sid,
                                          path_only, qs, candidates)
    if result is not None:
        return result

    return error_page(
        "Not found",
        f"<code>{esc(path_only)}</code> — no origin served it.", 404)


@app.get("/healthz")
async def healthz(req):
    return json_response({
        "status": "ok",
        "framework": framework_version,
        "sessions": len(SESSIONS),
        "session_max": SESSION_MAX,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "ws_clients": len(WS_CLIENTS),
        "https_proxy": bool(os.environ.get("HTTPS_PROXY")
                            or os.environ.get("https_proxy")),
        "static_dir": STATIC_DIR,
        "static_dir_exists": os.path.isdir(STATIC_DIR),
        "templates_dir": TEMPLATES_DIR,
        "templates_dir_exists": os.path.isdir(TEMPLATES_DIR),
        "scanner_loaded": True,
        "tools_registered": len(TOOLS),
        "captcha_hosts": len(CAPTCHA_HOSTS),
        "stream_media_exts": len(STREAM_MEDIA_EXTS),
        "stream_chunk_size": STREAM_CHUNK_SIZE,
        "small_media_max": SMALL_MEDIA_MAX,
        "curl_cffi": HAS_CURL_CFFI,
        "impersonate_profile": IMPERSONATE_PROFILE if HAS_CURL_CFFI else None,
        "browser_ua": BROWSER_UA,
        "default_search_engine": DEFAULT_SEARCH_ENGINE,
        "challenge_max_attempts": CHALLENGE_MAX_ATTEMPTS,
    })


# ======================================================================
# Boot
# ======================================================================
if __name__ == "__main__":
    print("=" * 68)
    print(f"  🛠  Lynkio Browser — v19.1   (framework {framework_version})")
    print("=" * 68)
    print(f"  Home       →  http://localhost:{PORT}/")
    print(f"  Browser    →  http://localhost:{PORT}/tabs")
    print(f"  Proxy      →  http://localhost:{PORT}/proxy?url=…")
    print(f"  Clones     →  http://localhost:{PORT}/clones")
    print(f"  Clone      →  http://localhost:{PORT}/clone/<uuid>")
    print(f"  Editor     →  http://localhost:{PORT}/clone/<uuid>/edit")
    print(f"  WS         →  ws://localhost:{PORT}/__lynk_ws")
    print(f"  Tools      →  /tool/<name>   ({len(TOOLS)} registered)")
    print(f"  Static     →  /static/*   (from {STATIC_DIR})")
    print(f"  Templates  →  /static/templates/*  (from {TEMPLATES_DIR})")
    print("=" * 68)
    print(f"  Session TTL:      {SESSION_TTL_SECONDS // 3600}h")
    print(f"  Session max:      {SESSION_MAX}")
    print(f"  Stream chunk:     {STREAM_CHUNK_SIZE // 1024} KiB")
    print(f"  Small media max:  {SMALL_MEDIA_MAX // 1024} KiB")
    print(f"  Stream media exts:{len(STREAM_MEDIA_EXTS)}")
    print(f"  Captcha hosts:    {len(CAPTCHA_HOSTS)}")
    print(f"  Toolkit:          {len(TOOLS)} endpoints wired")
    print(f"  Cloner:           {cloner.CLONES_DIR}")
    print(f"  Stealth:          {'curl_cffi · ' + IMPERSONATE_PROFILE if HAS_CURL_CFFI else 'DISABLED — pip install curl_cffi'}")
    print(f"  Default engine:   {DEFAULT_SEARCH_ENGINE}  (google is IP-blocked on datacenter ASNs)")
    print("=" * 68)
    app.run()
