#!/usr/bin/env python3
"""
Lynkio Browser — v20.0
Built on the lynkio framework v1.4.2.

v20.0 — CDP mode:
  • chrome_launcher.py + cdp_client.py + browser_capture.py + cdp_routes.py
    are new modules wired in below.
  • On startup Lynkio auto-launches Chrome with --remote-debugging-port and
    connects via CDP. If Chrome can't launch, the proxy still works and the
    UI shows a "Launch Chrome" button.
  • Cloudflare challenges in the proxy no longer return the static
    interstitial. When Chrome is connected, the challenge hands off to a
    real Chrome tab (_solve_async), the user solves natively, and the
    captured DOM/cookies/storage are replayed back through the proxy with
    matching TLS/UA.
  • _set_browser_identity / _set_impersonate align curl_cffi to whatever
    browser CDP found, so cf_clearance replays successfully.
  • Session.cdp_captures: URL → HTML cache populated by _solve_async.

Preserved from v19.1: Google sorry handling, curl_cffi stealth fetch,
Cloudflare detection, interstitial fallback, JSON escaping, cloner
ordering, session sweeps, all tools.
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
import cdp_routes

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


def _set_browser_identity(ua):
    """Called by cdp_routes when a real Chrome connects — aligns proxy UA to real Chrome's UA."""
    global BROWSER_UA
    if ua and ua != BROWSER_UA:
        BROWSER_UA = ua
        BROWSER_HEADERS["User-Agent"] = ua
        log.info("cdp: proxy UA aligned to browser (%s)", ua[:60])


def _set_impersonate(profile):
    """Called by cdp_routes to match curl_cffi TLS profile to the real Chrome version."""
    global IMPERSONATE_PROFILE
    if profile and profile != IMPERSONATE_PROFILE:
        IMPERSONATE_PROFILE = profile
        log.info("cdp: TLS impersonation profile set to %s", profile)


CHALLENGE_MAX_ATTEMPTS = 3
EGRESS_IP_CACHE_TTL    = 60.0

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
    b"_cf_chl_opt",
    b"cf_chl_opt",
    b"cdn-cgi/challenge-platform",
    b"cf-browser-verification",
    b"cf_challenge",
    b"just a moment",
    b"checking your browser",
    b"challenge-platform",
    b"__cf_chl",
)


def _is_cf_challenge(status, headers_dict, body):
    """
    Detect a Cloudflare challenge. Status is NOT a gate — Managed
    Challenges are served with HTTP 200 and only the body reveals what
    they are. The markers below are Cloudflare-internal strings that
    never appear on a normal page, so any one of them is definitive.
    """
    # 1. Documented Cloudflare signal (cheap, definitive)
    try:
        for k, v in headers_dict.items():
            if k.lower() == "cf-mitigated" and str(v).lower() == "challenge":
                return True
    except Exception:
        pass

    if not body:
        return False

    # 2. Definitive body markers, independent of status code
    low = bytes(body[:32768]).lower()
    for marker in (
        b"_cf_chl_opt",                 # the config object from your error
        b"cf_chl_opt",                  # variant spelling
        b"cdn-cgi/challenge-platform",  # orchestrate script URL
        b"cf-browser-verification",     # legacy interstitial
        b"cf_challenge",                # generic
    ):
        if marker in low:
            return True

    # 3. Softer signals — must appear together to count
    if (b"challenge-platform" in low
            and (b"just a moment" in low or b"checking your browser" in low)):
        return True

    # 4. Legacy status-only fallback (still useful for older builds)
    if status in (403, 429, 503):
        for sig in _CF_BODY_SIGNATURES:
            if sig in low:
                return True

    return False
    

# ======================================================================
# Google "unusual traffic" detection
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
# Sessions
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
        self.cdp_captures = {}

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
_EGRESS_CACHE = {"ip": "", "ts": 0.0}


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


async def _server_egress_ip(timeout=5.0):
    now = time.time()
    if _EGRESS_CACHE["ip"] and now - _EGRESS_CACHE["ts"] < EGRESS_IP_CACHE_TTL:
        return _EGRESS_CACHE["ip"]
    try:
        r = await _stealth_fetch_raw("https://api.ipify.org?format=json",
                                     timeout=timeout)
        if r is not None:
            data = json.loads(r["content"].decode("utf-8", "replace"))
            ip = str(data.get("ip") or "").strip()
            if ip:
                _EGRESS_CACHE["ip"] = ip
                _EGRESS_CACHE["ts"] = now
                return ip
    except Exception:
        pass
    try:
        r = await _stealth_fetch_raw("https://1.1.1.1/cdn-cgi/trace",
                                     timeout=timeout)
        if r is not None:
            text = r["content"].decode("utf-8", "replace")
            m = re.search(r"^ip=([0-9a-fA-F:.]+)$", text, re.M)
            if m:
                ip = m.group(1)
                _EGRESS_CACHE["ip"] = ip
                _EGRESS_CACHE["ts"] = now
                return ip
    except Exception:
        pass
    return ""


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
            "try{Object.defineProperty(window,'__LYNK_SW__',"
            "{value:1,enumerable:false,configurable:true});}catch(e){window.__LYNK_SW__=1;}"
            "navigator.serviceWorker.register('/lynkio/service-ws.js',{scope:'/'})"
            ".catch(function(e){})}"
        )

        preserve = "true" if self.ctx.get("preserve_captcha") else "false"
        ctx_s = soup.new_tag("script")
        ctx_s.string = (
            "try{Object.defineProperty(window,'__LYNK_CTX__',"
            f"{{value:{_json_for_script(self.ctx)},enumerable:false,configurable:true}});}}"
            f"catch(e){{window.__LYNK_CTX__={_json_for_script(self.ctx)};}}"
            "try{Object.defineProperty(window,'__LYNK_PRESERVE_CAPTCHA__',"
            f"{{value:{preserve},enumerable:false}});}}catch(e){{}}"
        )

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
# Raw socket — media / WS relay fallback
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
# Interstitial CSS — used by _cf_challenge_page and _google_sorry_page
# ======================================================================
_INTERSTITIAL_STYLE = """
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
h1{font-size:20px;font-weight:800;letter-spacing:-.01em;line-height:1.25;
margin-bottom:10px}
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
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg-muted)}
button.ghost:hover{background:rgba(56,189,248,.08);color:var(--accent);
border-color:rgba(56,189,248,.4)}
textarea{width:100%;min-height:80px;background:#050a14;color:var(--fg);
border:1px solid var(--line);border-radius:8px;padding:10px;
font-family:ui-monospace,monospace;font-size:12px;line-height:1.5;
resize:vertical;outline:none;margin-bottom:10px}
.status{margin-top:10px;font-size:12.5px;font-family:ui-monospace,monospace;
padding:10px 12px;border-radius:8px;display:none}
.status:not(:empty){display:block}
.status.busy{background:rgba(56,189,248,.1);color:var(--accent);
border-left:3px solid var(--accent)}
.status.ok{background:rgba(16,185,129,.1);color:var(--ok);
border-left:3px solid var(--ok)}
.status.err{background:rgba(248,113,113,.1);color:var(--danger);
border-left:3px solid var(--danger)}
.row{display:flex;gap:8px;flex-wrap:wrap}
.hidden{display:none}
</style>
"""


def _cf_challenge_page(url, origin, challenge_type="cloudflare", attempt_count=0):
    target_host = urlparse(url).hostname or ""
    safe_host   = esc(target_host)
    url_js      = _json_for_script(url)
    origin_js   = _json_for_script(origin)

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloudflare challenge · {safe_host} · Lynkio</title>
{_INTERSTITIAL_STYLE}
</head><body>
<div class="wrap">
  <div class="card">
    <div class="badge">⚠ Cloudflare challenge</div>
    <h1>{safe_host} requires a real browser</h1>
    <p>Lynkio can solve this automatically when a real Chrome is connected. If Chrome is unavailable, solve the challenge in your own browser and paste the cookies below.</p>
    <div class="row" style="margin-top:14px;">
      <button class="primary" id="solveBtn">Solve with real Chrome</button>
      <button class="ghost" id="openBtn">Open {safe_host} ↗</button>
    </div>
    <p style="margin-top:16px;font-size:12px;color:var(--fg-dim);">
      <b>Why this only works on the same machine:</b> Cloudflare binds
      <code>cf_clearance</code> to IP + User-Agent + TLS fingerprint. Solving
      through a real Chrome on this machine means the cookie will be
      accepted here.
    </p>
    <div style="margin-top:14px;">
      <p style="font-size:12.5px;">If you must paste manually, use
      DevTools → Application → Cookies → <code>{safe_host}</code> after
      solving in your browser. Paste <code>cf_clearance</code> and
      <code>__cf_bm</code> below.</p>
      <textarea id="cookieInput" placeholder="cf_clearance=...; __cf_bm=..."></textarea>
      <div class="row">
        <button class="primary" id="retryBtn">Save &amp; retry</button>
      </div>
      <div id="retryStatus" class="status"></div>
    </div>
  </div>
</div>
<script>
(function(){{
  var URL_    = {url_js};
  var ORIGIN_ = {origin_js};
  var statusEl = document.getElementById('retryStatus');
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
    if (Object.keys(out).length === 0) out['cf_clearance'] = text;
    return out;
  }}
  document.getElementById('solveBtn').onclick = async function(){{
    setStatus('Opening real Chrome tab…', 'busy');
    try {{
      var r = await fetch('/cdp/solve', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{url: URL_}})
      }});
      var j = await r.json();
      if (!j.ok) {{ setStatus('Solve failed: ' + (j.error || '?'), 'err'); return; }}
      var tok = j.token;
      async function poll(){{
        try {{
          var rr = await fetch('/cdp/solve-status/' + tok, {{credentials:'same-origin'}});
          var d = await rr.json();
          if (d.status === 'ready') {{
            setStatus('Solved — reloading…', 'ok');
            location.href = '/proxy?url=' + encodeURIComponent(URL_) + '&_t=' + Date.now();
            return;
          }}
          if (d.status === 'error') {{ setStatus('Error: ' + (d.error || '?'), 'err'); return; }}
          setStatus('Waiting for solve…', 'busy');
        }} catch(e) {{}}
        setTimeout(poll, 1500);
      }}
      setTimeout(poll, 500);
    }} catch(e) {{ setStatus('Network error: ' + e.message, 'err'); }}
  }};
  document.getElementById('openBtn').onclick = function(){{
    window.open(URL_, '_blank', 'noopener,noreferrer');
  }};
  document.getElementById('retryBtn').onclick = async function(){{
    var cookies = parseCookies(document.getElementById('cookieInput').value);
    if (Object.keys(cookies).length === 0) {{ setStatus('Paste at least one cookie.', 'err'); return; }}
    setStatus('Testing…', 'busy');
    try {{
      var r = await fetch('/proxy/add-cookies', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{origin: ORIGIN_, url: URL_, cookies: cookies}})
      }});
      var j = await r.json();
      if (j.ok) {{ setStatus('Accepted — loading…', 'ok'); setTimeout(function(){{
        location.href = '/proxy?url=' + encodeURIComponent(URL_) + '&_t=' + Date.now();
      }}, 400); }}
      else if (j.challenge) setStatus('Still challenged — cookie stale or IP mismatch.', 'err');
      else setStatus(j.error || 'HTTP ' + j.status, 'err');
    }} catch(e) {{ setStatus('Network error: ' + e.message, 'err'); }}
  }};
}})();
</script>
</body></html>"""
    return RawResponse(html.encode("utf-8"),
                       content_type="text/html; charset=utf-8",
                       status=200)


def _google_sorry_page(url, origin, attempt_count=0):
    target_host = urlparse(url).hostname or ""
    safe_host   = esc(target_host)
    url_js      = _json_for_script(url)
    origin_js   = _json_for_script(origin)

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google blocked this request · Lynkio</title>
{_INTERSTITIAL_STYLE}
</head><body>
<div class="wrap">
  <div class="card">
    <div class="badge">⚠ Google unusual traffic</div>
    <h1>Google blocked this request</h1>
    <p>Datacenter ASNs (Render, AWS, GCP) are scored as bots by Google.
    If Chrome is connected, try solving through it. Otherwise use a different
    search engine — <code>/search</code> defaults to DuckDuckGo.</p>
    <div class="row" style="margin-top:14px;">
      <button class="primary" id="solveBtn">Solve with real Chrome</button>
      <button class="ghost" id="switchDdg">Use DuckDuckGo</button>
      <button class="ghost" id="switchBing">Use Bing</button>
    </div>
    <div style="margin-top:18px;">
      <p style="font-size:12.5px;">Or paste <code>NID</code> / <code>SID</code> from a signed-in session.</p>
      <textarea id="cookieInput" placeholder="NID=...; SID=..."></textarea>
      <div class="row">
        <button class="primary" id="retryBtn">Save &amp; retry</button>
      </div>
      <div id="retryStatus" class="status"></div>
    </div>
  </div>
</div>
<script>
(function(){{
  var URL_    = {url_js};
  var ORIGIN_ = {origin_js};
  var statusEl = document.getElementById('retryStatus');
  function setStatus(msg, kind){{
    statusEl.textContent = msg || '';
    statusEl.className = 'status' + (kind ? ' ' + kind : '');
  }}
  function parseCookies(text){{
    text = (text || '').trim();
    var out = {{}};
    text.split(';').forEach(function(p){{
      p = p.trim(); if (!p) return;
      var i = p.indexOf('='); if (i === -1) return;
      var n = p.slice(0,i).trim(), v = p.slice(i+1).trim();
      if (n) out[n] = v;
    }});
    return out;
  }}
  function openSearch(engine){{
    var params = new URLSearchParams(location.search);
    var q = params.get('q') || '';
    if (!q) {{ var m = URL_.match(/[?&]q=([^&]+)/); if (m) q = decodeURIComponent(m[1]); }}
    location.href = '/search?q=' + encodeURIComponent(q) + '&engine=' + engine;
  }}
  document.getElementById('switchDdg').onclick = function(){{ openSearch('ddg'); }};
  document.getElementById('switchBing').onclick = function(){{ openSearch('bing'); }};
  document.getElementById('solveBtn').onclick = async function(){{
    setStatus('Opening real Chrome tab…', 'busy');
    try {{
      var r = await fetch('/cdp/solve', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{url: URL_}})
      }});
      var j = await r.json();
      if (!j.ok) {{ setStatus('Solve failed: ' + (j.error || '?'), 'err'); return; }}
      var tok = j.token;
      async function poll(){{
        try {{
          var rr = await fetch('/cdp/solve-status/' + tok, {{credentials:'same-origin'}});
          var d = await rr.json();
          if (d.status === 'ready') {{
            setStatus('Solved — reloading…', 'ok');
            location.href = '/proxy?url=' + encodeURIComponent(URL_) + '&_t=' + Date.now();
            return;
          }}
          if (d.status === 'error') {{ setStatus('Error: ' + (d.error || '?'), 'err'); return; }}
          setStatus('Waiting for solve…', 'busy');
        }} catch(e) {{}}
        setTimeout(poll, 1500);
      }}
      setTimeout(poll, 500);
    }} catch(e) {{ setStatus('Network error: ' + e.message, 'err'); }}
  }};
  document.getElementById('retryBtn').onclick = async function(){{
    var cookies = parseCookies(document.getElementById('cookieInput').value);
    if (Object.keys(cookies).length === 0) {{ setStatus('Paste at least one cookie.', 'err'); return; }}
    setStatus('Testing…', 'busy');
    try {{
      var r = await fetch('/proxy/add-cookies', {{
        method: 'POST', headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{origin: ORIGIN_, url: URL_, cookies: cookies}})
      }});
      var j = await r.json();
      if (j.ok) {{ setStatus('Accepted — loading…', 'ok'); setTimeout(function(){{
        location.href = '/proxy?url=' + encodeURIComponent(URL_) + '&_t=' + Date.now();
      }}, 400); }}
      else if (j.google_sorry) setStatus('Google still blocked — try DuckDuckGo.', 'err');
      else setStatus(j.error || 'HTTP ' + j.status, 'err');
    }} catch(e) {{ setStatus('Network error: ' + e.message, 'err'); }}
  }};
}})();
</script>
</body></html>"""
    return RawResponse(html.encode("utf-8"), content_type="text/html; charset=utf-8", status=200)


# ======================================================================
# Main proxy
# ======================================================================
async def serve_proxied(req, target_url, sid):
    sess = get_session(sid)
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # ---- Cloudflare challenge-platform short-circuit ----
    # The orchestrate script (/cdn-cgi/challenge-platform/.../chl_page/v1)
    # reads window._cf_chl_opt, which is only defined inside the challenge
    # page's own document. Proxying it into a rewritten page produces:
    #   TypeError: undefined is not an object
    #   (evaluating 'window._cf_chl_opt.qFyP3=false')
    # Never proxy the challenge-platform tree. Script forms return an empty
    # JS stub so the reference resolves; HTML challenge pages hand off to
    # CDP or the interstitial. Every other asset type under this path gets
    # a typed stub so the browser doesn't retry.
    if parsed.path.startswith("/cdn-cgi/challenge-platform/"):
        wants = _requested_kind(req, target_url)
        is_script = (
            wants == "script"
            or parsed.path.endswith(".js")
            or "/orchestrate/" in parsed.path
            or "/scripts/" in parsed.path
        )
        if is_script:
            resp = RawResponse(
                b"/* lynkio: cloudflare challenge script not proxied */",
                status=200,
                content_type="application/javascript; charset=utf-8",
            )
            resp.add_header("Cache-Control", "no-store")
            return resp

        is_html = (
            wants == "document"
            or parsed.path.endswith(".html")
            or "/chl_page/" in parsed.path
        )
        if is_html:
            if cdp_routes.is_available():
                token = cdp_routes._new_token()
                asyncio.create_task(cdp_routes._solve_async(
                    token, target_url, origin, sid,
                    {"get_session": get_session}))
                return RawResponse(
                    cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                    content_type="text/html; charset=utf-8")
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

        # Any other asset type (css, images, fonts) — empty typed stub
        ext = os.path.splitext(parsed.path.lower())[1]
        if ext == ".css" or wants == "style":
            resp = RawResponse(
                b"/* lynkio: cloudflare challenge asset not proxied */",
                status=200,
                content_type="text/css; charset=utf-8",
            )
        else:
            resp = RawResponse(b"", status=204,
                               content_type="application/octet-stream")
        resp.add_header("Cache-Control", "no-store")
        return resp

    # ---- Cached CDP capture early return ----
    _cached_cdp = sess.cdp_captures.pop(target_url, None)
    if _cached_cdp:
        sess.page_origin = origin
        _ctx = {"upstream": target_url, "sid": sid,
                "preserve_captcha": True,
                "_injected": [s["code"] for s in sess.injected if s["enabled"]]}
        _body = HTMLRewriter(target_url, "text/html; charset=utf-8",
                             _ctx).rewrite(_cached_cdp.encode("utf-8", "replace"))
        _resp = RawResponse(_body, status=200,
                            content_type="text/html; charset=utf-8")
        _resp.add_header("Set-Cookie",
                         f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax")
        _resp.add_header("Set-Cookie",
                         f"{ORIGIN_COOKIE}={quote(origin, safe='')}; Path=/; Max-Age=86400; SameSite=Lax")
        return _resp

    # ---- Self-target guard ----
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

    # ================================================================
    # Stealth branch (curl_cffi)
    # ================================================================
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

            # Google "unusual traffic"
            if _is_google_sorry(s_status, s_headers, s_body, s_final_url):
                log.warning("google sorry on %s (stealth, %d)", target_url, s_status)
                if cdp_routes.is_available():
                    token = cdp_routes._new_token()
                    asyncio.create_task(cdp_routes._solve_async(
                        token, target_url, origin, sid,
                        {"get_session": get_session}))
                    return RawResponse(
                        cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                        content_type="text/html; charset=utf-8")
                key = f"{origin}|{target_url}"
                attempts = int(sess.challenge_attempts.get(key, 0))
                return _google_sorry_page(target_url, origin, attempts)

            # Cloudflare challenge — CDP handoff
            if _is_cf_challenge(s_status, s_headers, s_body):
                log.warning("cloudflare challenge on %s (stealth, %d) — trying CDP",
                            target_url, s_status)
                if cdp_routes.is_available():
                    token = cdp_routes._new_token()
                    asyncio.create_task(cdp_routes._solve_async(
                        token, target_url, origin, sid,
                        {"get_session": get_session}))
                    return RawResponse(
                        cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                        content_type="text/html; charset=utf-8")
                key = f"{origin}|{target_url}"
                attempts = int(sess.challenge_attempts.get(key, 0))
                return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

            # Redirect
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
                       "preserve_captcha": True,
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

            # Non-HTML data passthrough
            resp_headers = _build_response_headers(s_headers_list,
                                                    is_rewritten=False)
            resp = RawResponse(s_body, status=s_status, content_type=ctype,
                               headers=resp_headers)
            _add_cookies_to_response(resp, s_headers_list,
                                     parsed.hostname or "")
            return resp

    # ================================================================
    # Raw socket path (media, scripts, styles, fallback)
    # ================================================================
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

    # ---- HEAD ----
    if req.method == "HEAD":
        await _close_writer(writer)
        resp_headers = _verbatim_response_headers(up_headers)
        resp_headers["Content-Type"] = ctype
        resp = RawResponse(b"", status=status,
                           content_type=ctype, headers=resp_headers)
        _add_cookies_to_response(resp, up_headers, origin_host)
        return resp

    # ---- Media ----
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

    # ---- 3xx redirects ----
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

    # ---- HLS / M3U8 ----
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

    # ---- Script stubs (status errors / HTML masquerading as JS) ----
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

    # ---- Style stubs ----
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

    # ---- HTML (with challenge + google-sorry detection) ----
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
            if cdp_routes.is_available():
                token = cdp_routes._new_token()
                asyncio.create_task(cdp_routes._solve_async(
                    token, target_url, origin, sid,
                    {"get_session": get_session}))
                return RawResponse(
                    cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                    content_type="text/html; charset=utf-8")
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _google_sorry_page(target_url, origin, attempts)

        if _is_cf_challenge(status, hdr_dict, raw):
            log.warning("cloudflare challenge on %s (raw, %d) — trying CDP",
                        target_url, status)
            if cdp_routes.is_available():
                token = cdp_routes._new_token()
                asyncio.create_task(cdp_routes._solve_async(
                    token, target_url, origin, sid,
                    {"get_session": get_session}))
                return RawResponse(
                    cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                    content_type="text/html; charset=utf-8")
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _cf_challenge_page(target_url, origin, "cloudflare", attempts)

        if rewritable:
            if ce and ce != "identity":
                raw = _decompress(raw, ce)
            sess.page_origin = origin
            ctx = {"upstream": target_url, "sid": sid,
                   "preserve_captcha": True,
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

    # ---- CSS (non-static) ----
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

    # ---- Default passthrough (data / JSON / anything else) ----
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
            if cdp_routes.is_available():
                token = cdp_routes._new_token()
                asyncio.create_task(cdp_routes._solve_async(
                    token, target_url, origin, sid,
                    {"get_session": get_session}))
                return RawResponse(
                    cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                    content_type="text/html; charset=utf-8")
            key = f"{origin}|{target_url}"
            attempts = int(sess.challenge_attempts.get(key, 0))
            return _google_sorry_page(target_url, origin, attempts)

        if _is_cf_challenge(status, hdr_dict, raw_bytes):
            log.warning("cloudflare challenge on %s (data)", target_url)
            if cdp_routes.is_available():
                token = cdp_routes._new_token()
                asyncio.create_task(cdp_routes._solve_async(
                    token, target_url, origin, sid,
                    {"get_session": get_session}))
                return RawResponse(
                    cdp_routes.solving_page(target_url, origin, token).encode("utf-8"),
                    content_type="text/html; charset=utf-8")
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

    # ---- Oversized / streaming passthrough ----
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
# Cloudflare challenge — cookie paste & retry
# ======================================================================

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
            {"ok": False, "error": "origin, url, cookies required"}, status=400)

    key = f"{origin}|{url}"
    attempts_so_far = int(sess.challenge_attempts.get(key, 0))
    if attempts_so_far >= CHALLENGE_MAX_ATTEMPTS:
        return json_response({
            "ok": False,
            "limit_reached": True,
            "error": "retry limit reached for this URL",
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

    log.info("challenge: added %d cookie(s) for %s (attempt %d/%d) sid=%s",
             saved, origin, attempts_so_far + 1, CHALLENGE_MAX_ATTEMPTS, sid[:8])

    if not HAS_CURL_CFFI:
        return json_response({
            "ok": False,
            "error": "curl_cffi unavailable",
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
            "ok": False, "error": "upstream fetch failed",
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
            "ok": False, "status": s_status, "google_sorry": True,
            "error": "still google-sorry",
        })
    if _is_cf_challenge(s_status, s_headers, s_body):
        sess.challenge_attempts[key] = attempts_so_far + 1
        return json_response({
            "ok": False, "status": s_status, "challenge": True,
            "error": "still challenged",
        })

    sess.challenge_attempts.pop(key, None)
    if 400 <= s_status < 600:
        return json_response({
            "ok": False, "status": s_status,
            "error": f"HTTP {s_status} — access block",
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


@app.get("/proxy/my-ip")
async def proxy_my_ip(req):
    direct = await _server_egress_ip()
    return json_response({
        "server_ip": direct,
        "ua": BROWSER_UA,
        "impersonate": IMPERSONATE_PROFILE,
    })


# ======================================================================
# Stealth app.fetch wrapper
# ======================================================================
_original_fetch = app.fetch


async def _stealth_fetch(url, method="GET", headers=None, timeout=30.0, **kwargs):
    if HAS_CURL_CFFI and method.upper() in ("GET", "HEAD"):
        try:
            stealth = await _stealth_fetch_raw(
                url, method=method, headers=headers,
                timeout=timeout, allow_redirects=kwargs.get("allow_redirects", True),
                max_redirects=kwargs.get("max_redirects", 5),
            )
            if stealth is not None:
                if (not _is_cf_challenge(stealth["status"], stealth["headers"],
                                         stealth["content"])
                        and not _is_google_sorry(stealth["status"],
                                                  stealth["headers"],
                                                  stealth["content"],
                                                  str(stealth.get("url", "")))):
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
    await client.send(json.dumps({"event": "pong", "data": {"ts": time.time()}}))


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


# ---- recon ----
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


# ---- injection ----
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
        {"id": s["id"], "name": s["name"], "code": s["code"],
         "enabled": s["enabled"], "size": len(s["code"])}
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


# ---- cookies ----
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


# ---- file view ----
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
                result["body"] = body.decode(charset, errors="replace")[:200000]
            except LookupError:
                result["body"] = body.decode("utf-8", errors="replace")[:200000]
            result["truncated"] = len(body) > 200000
        return result
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@tool("tree")
async def t_tree(req):
    base = req.query_params.get("url") or ""
    depth = int(req.query_params.get("depth") or 2)
    depth = max(1, min(3, depth))
    if not base:
        return {"error": "missing url"}
    try:
        p = urlparse(base)
        origin = f"{p.scheme}://{p.netloc}"
    except Exception:
        return {"error": "invalid url"}

    seen = set()
    tree = {"url": base, "type": "dir", "name": "/", "children": []}
    by_url = {base: tree}
    queue = [(base, 0)]
    max_nodes = 400
    while queue and len(seen) < max_nodes:
        current, cur_depth = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            r = await app.fetch(current, headers=BROWSER_HEADERS, timeout=15.0,
                                allow_redirects=True, max_redirects=3)
            if r.status_code != 200:
                continue
            ct = (r.headers.get("content-type", "") or "").lower()
            if "text/html" not in ct and "application/xhtml" not in ct:
                node = by_url.get(current)
                if node:
                    node["size"] = len(r.content)
                    node["content_type"] = ct
                continue
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce:
                body = _decompress(body, ce)
            charset = detect_charset(ct, body)
            try:
                text = body.decode(charset, errors="replace")
            except LookupError:
                text = body.decode("utf-8", errors="replace")
            try:
                soup = BeautifulSoup(text, "html.parser")
            except Exception:
                continue
            parent = by_url.get(current)
            if parent is None:
                continue
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                try:
                    absu = urljoin(current, href)
                except Exception:
                    continue
                ap = urlparse(absu)
                if ap.scheme not in ("http", "https"):
                    continue
                if ap.netloc != p.netloc:
                    continue
                if absu in seen:
                    continue
                name = a.get_text(" ", strip=True)[:60] or absu.split("/")[-1] or "/"
                is_dir = absu.endswith("/") or not name.count(".")
                child = {"url": absu, "type": "dir" if is_dir else "file",
                         "name": name, "children": [] if is_dir else None}
                if parent.get("children") is not None:
                    parent["children"].append(child)
                by_url[absu] = child
                if is_dir and cur_depth + 1 < depth:
                    queue.append((absu, cur_depth + 1))
        except Exception as e:
            log.debug("tree crawl %s failed: %s", current, e)
    return {"root": tree, "visited": len(seen), "origin": origin}


@tool("vulnscan")
async def t_vulnscan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    active = (fields.get("active") or req.query_params.get("active") or "1") == "1"
    if not url:
        return {"error": "missing url"}
    return await scanner.run_scan(url, app.fetch, active=active)


_BRUTE_DEFAULT = [
    "admin","login","dashboard","api","api/v1","api/v2","graphql","swagger",
    "swagger.json","swagger-ui.html","openapi.json","docs","api-docs",
    "config","config.json","config.yml",".env","env",".git/config",
    "robots.txt","sitemap.xml","backup.zip","backup.tar.gz","backup.sql",
    "db.sql","dump.sql","test","dev","staging","uploads","files","static",
    "assets","console","manage","manager","panel","cpanel","phpinfo.php",
    "info.php","server-status","server-info","actuator","actuator/health",
    "metrics","health","healthz","status","version","VERSION","README.md",
    "CHANGELOG.md",".well-known/security.txt",".well-known/openid-configuration",
    "user","users","account","profile","settings","register","signup",
    "auth","oauth","token","tokens","keys","secret","secrets","internal",
    "private","tmp","temp","log","logs","debug","trace","test.php","index.php",
    "wp-login.php","wp-admin/","administrator/","xmlrpc.php",
]

_COMMON_PORTS = [
    (21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),
    (80,"HTTP"),(110,"POP3"),(111,"rpcbind"),(135,"msrpc"),
    (139,"netbios"),(143,"IMAP"),(161,"snmp"),(389,"LDAP"),
    (443,"HTTPS"),(445,"SMB"),(465,"SMTPS"),(514,"syslog"),
    (587,"SMTP"),(636,"LDAPS"),(993,"IMAPS"),(995,"POP3S"),
    (1080,"SOCKS"),(1433,"MSSQL"),(1521,"Oracle"),(2049,"NFS"),
    (3000,"Node/Dev"),(3306,"MySQL"),(3389,"RDP"),(4443,"HTTPS-alt"),
    (5000,"Dev"),(5432,"PostgreSQL"),(5900,"VNC"),(5985,"WinRM-HTTP"),
    (6379,"Redis"),(6443,"K8s-API"),(7001,"WebLogic"),(8000,"HTTP-alt"),
    (8080,"HTTP-alt"),(8443,"HTTPS-alt"),(8888,"HTTP-alt"),
    (9000,"PHP-FPM/FastCGI"),(9090,"Prometheus"),(9200,"Elasticsearch"),
    (9300,"Elasticsearch"),(11211,"Memcached"),(27017,"MongoDB"),
    (50000,"SAP"),(50070,"Hadoop"),
]

_WAF_SIGNATURES = [
    ("Cloudflare",  ["cf-ray","cf-cache-status","server:cloudflare"]),
    ("AWS WAF",     ["x-amzn-requestid","x-amz-cf-id","awselb"]),
    ("Akamai",      ["akamai-grn","x-akamai"]),
    ("Sucuri",      ["x-sucuri-id","x-sucuri-cache"]),
    ("Imperva",     ["x-iinfo","visid_incap"]),
    ("F5 BIG-IP",   ["x-wa-info","bigipserver"]),
    ("Fastly",      ["x-served-by:cache","x-fastly"]),
    ("ModSecurity", ["mod_security","modsecurity"]),
    ("Barracuda",   ["barra_counter_session"]),
    ("Wordfence",   ["wordfence"]),
]

_TAKEOVER_SIGS = [
    ("GitHub Pages", ["there isn't a github pages site here",
                       "for root urls (like http://example.com) you must provide an index.html"]),
    ("Heroku",       ["no such app","heroku | no such app"]),
    ("AWS S3",       ["nosuchbucket","the specified bucket does not exist"]),
    ("Azure",        ["404 web site not found","the resource you are looking for has been removed"]),
    ("Shopify",      ["sorry, this shop is currently unavailable"]),
    ("Netlify",      ["not found - request id"]),
    ("Vercel",       ["the deployment you are trying to access was not found"]),
    ("Zendesk",      ["help center closed"]),
    ("Fastly",       ["fastly error: unknown domain"]),
    ("Surge.sh",     ["project not found"]),
    ("Bitbucket",    ["repository not found"]),
    ("Tumblr",       ["there's nothing here","whatever you were looking for doesn't currently exist"]),
    ("Pantheon",     ["the gods are wise, but do not know of the site which you seek"]),
    ("Cargo",        ["<title>404 &mdash; file not found</title>"]),
    ("WordPress",    ["do you want to register"]),
]


async def _fetch_json(url, headers=None, timeout=15.0):
    try:
        r = await app.fetch(url, headers=headers or BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return json.loads(body.decode("utf-8", errors="replace")), r
    except Exception:
        return None, None


async def _fetch_text(url, headers=None, timeout=15.0):
    try:
        r = await app.fetch(url, headers=headers or BROWSER_HEADERS,
                            timeout=timeout, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce:
            body = _decompress(body, ce)
        return body.decode("utf-8", errors="replace"), r
    except Exception:
        return "", None


def _origin_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _host_of(url):
    return urlparse(url).hostname or ""


@tool("agent-run")
async def t_agent_run(req):
    fields = await _get_form(req)
    code = fields.get("code") or ""
    if not code.strip():
        return {"ok": False, "error": "empty code"}
    def _no_import(*a, **k):
        raise ImportError("imports disabled in agent sandbox")
    safe_builtins = {
        "abs": abs, "all": all, "any": any, "bool": bool, "bytes": bytes,
        "chr": chr, "dict": dict, "dir": dir, "divmod": divmod,
        "enumerate": enumerate, "filter": filter, "float": float,
        "format": format, "frozenset": frozenset, "getattr": getattr,
        "hasattr": hasattr, "hash": hash, "hex": hex, "id": id,
        "int": int, "isinstance": isinstance, "issubclass": issubclass,
        "iter": iter, "len": len, "list": list, "map": map,
        "max": max, "min": min, "next": next, "oct": oct, "ord": ord,
        "pow": pow, "print": print, "range": range, "repr": repr,
        "reversed": reversed, "round": round, "set": set, "slice": slice,
        "sorted": sorted, "str": str, "sum": sum, "tuple": tuple,
        "type": type, "zip": zip, "True": True, "False": False, "None": None,
        "__import__": _no_import,
    }
    ns = {"__builtins__": safe_builtins, "result": None}
    try:
        compiled = compile(code, "<lynk-agent>", "exec")
        exec(compiled, ns, ns)
        return {"ok": True, "result": ns.get("result")}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


@tool("subdomains")
async def t_subdomains(req):
    fields = await _get_form(req)
    domain = (fields.get("domain") or req.query_params.get("domain") or "").strip().lower()
    if not domain:
        return {"error": "domain required"}
    data, _ = await _fetch_json(
        "https://crt.sh/?q=%25." + quote(domain) + "&output=json", timeout=25.0)
    if data is None:
        return {"error": "crt.sh unreachable"}
    subs = set()
    for entry in (data if isinstance(data, list) else []):
        for n in (entry.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and n:
                subs.add(n)
    return {"domain": domain, "subdomains": sorted(subs)}


@tool("portscan")
async def t_portscan(req):
    fields = await _get_form(req)
    host = (fields.get("host") or req.query_params.get("host") or "").strip()
    if not host:
        return {"error": "host required"}
    try:
        ip = host
        try:
            _ipaddress.ip_address(host)
        except ValueError:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None)
            ip = infos[0][4][0]
    except Exception as e:
        return {"error": f"resolve failed: {e}"}
    open_ports = []
    async def _probe(port, label):
        try:
            fut = asyncio.open_connection(ip, port)
            r, w = await asyncio.wait_for(fut, timeout=2.5)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return {"port": port, "service": label}
        except Exception:
            return None
    results = await asyncio.gather(*[_probe(p, l) for p, l in _COMMON_PORTS])
    for r in results:
        if r: open_ports.append(r)
    return {"host": host, "ip": ip, "open": open_ports}


@tool("ssltls")
async def t_ssltls(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url if "://" in url else "https://" + url)
    host = p.hostname
    port = p.port or 443
    if not host:
        return {"error": "no host"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        loop = asyncio.get_running_loop()
        fut = loop.create_connection(
            asyncio.Protocol, host, port, ssl=ctx, server_hostname=host)
        _, writer = await asyncio.wait_for(fut, timeout=10.0)
        tls_obj = writer.get_extra_info("ssl_object")
        cert = tls_obj.getpeercert() if tls_obj else None
        cipher = tls_obj.cipher() if tls_obj else None
        version = tls_obj.version() if tls_obj else None
        alpn = tls_obj.selected_alpn_protocol() if tls_obj else None
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        out = {
            "host": host, "port": port,
            "tls_version": version or "",
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else "",
            "alpn": alpn or "",
        }
        if cert:
            out["subject"] = {k: v for tup in cert.get("subject", ()) for k, v in tup}
            out["issuer"] = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
            out["not_before"] = cert.get("notBefore", "")
            out["not_after"] = cert.get("notAfter", "")
            out["serial"] = str(cert.get("serialNumber", ""))
            out["subject_alt_names"] = [v for k, v in cert.get("subjectAltName", ())]
        return out
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@tool("tls-audit")
async def t_tls_audit(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url if "://" in url else "https://" + url)
    host, port = p.hostname, p.port or 443
    if not host:
        return {"error": "no host"}
    versions = []
    findings = []
    for label, proto in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                          ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                          ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
                          ("TLS 1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            fut = asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
            r, w = await asyncio.wait_for(fut, timeout=8.0)
            cipher = w.get_extra_info("ssl_object").cipher()
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            versions.append({"version": label, "supported": True,
                             "cipher": cipher[0] if cipher else ""})
            if proto in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                findings.append({
                    "severity": "high", "name": f"{label} enabled",
                    "description": f"{label} is deprecated and insecure.",
                    "evidence": f"{label} handshake succeeded with {cipher[0] if cipher else '?'}",
                    "remediation": f"Disable {label} on the server.",
                })
        except Exception as e:
            versions.append({"version": label, "supported": False,
                             "error": type(e).__name__})
    return {"url": url, "versions": versions, "findings": findings}


@tool("waf")
async def t_waf(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    probes = []
    detected = set()
    attack_url = url + ("&" if "?" in url else "?") + "q=" + quote("<script>alert(1)</script>' OR 1=1--")
    try:
        r = await app.fetch(attack_url, headers=BROWSER_HEADERS, timeout=12.0,
                            allow_redirects=False, max_redirects=0)
        hl = {k.lower(): v for k, v in dict(r.headers).items()}
        blob = " ".join(f"{k}:{v}" for k, v in hl.items()).lower()
        for name, sigs in _WAF_SIGNATURES:
            for s in sigs:
                if s in blob:
                    detected.add(name); break
        probes.append({"label": "Attack probe", "status": r.status_code,
                       "blocked": r.status_code in (403, 406, 419, 429, 503)})
    except Exception as e:
        probes.append({"label": "Attack probe", "error": str(e)})
    try:
        r2 = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0)
        hl2 = {k.lower(): v for k, v in dict(r2.headers).items()}
        blob2 = " ".join(f"{k}:{v}" for k, v in hl2.items()).lower()
        for name, sigs in _WAF_SIGNATURES:
            for s in sigs:
                if s in blob2:
                    detected.add(name); break
        probes.append({"label": "Baseline", "status": r2.status_code})
    except Exception as e:
        probes.append({"label": "Baseline", "error": str(e)})
    return {"url": url, "detected": sorted(detected), "probes": probes}


@tool("wayback")
async def t_wayback(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    data, _ = await _fetch_json(
        "https://web.archive.org/cdx/search/cdx?output=json&limit=40&url=" + quote(url),
        timeout=20.0)
    if not data or len(data) < 2:
        return {"url": url, "snapshots": []}
    snaps = []
    for row in data[1:]:
        if len(row) >= 3:
            ts, orig = row[1], row[2]
            snaps.append({"timestamp": ts,
                          "url": f"https://web.archive.org/web/{ts}/{orig}"})
    return {"url": url, "snapshots": snaps[::-1]}


@tool("favicon")
async def t_favicon(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    out = {"url": url, "origin": origin, "hash": "", "size": 0, "mmh3": "", "status": 0}
    try:
        r = await app.fetch(origin + "/favicon.ico", headers=BROWSER_HEADERS,
                            timeout=12.0, allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        out["status"] = r.status_code
        out["size"] = len(body)
        if body:
            b64 = _b64.encodebytes(body).decode()
            out["hash"] = _hashlib.md5(b64.encode()).hexdigest()
            out["mmh3"] = _hashlib.sha1(body).hexdigest()[:16]
    except Exception as e:
        out["error"] = str(e)
    return out


@tool("well-known")
async def t_wellknown(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    paths = [
        "/.well-known/security.txt", "/.well-known/change-password",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json", "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/host-meta", "/.well-known/nodeinfo",
        "/.well-known/webfinger", "/.well-known/dnt-policy.txt",
        "/.well-known/gpc.json", "/.well-known/mta-sts.txt",
        "/security.txt", "/humans.txt", "/robots.txt", "/sitemap.xml",
    ]
    results = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            return {"path": path, "url": origin + path,
                    "status": r.status_code, "length": len(r.content)}
        except Exception:
            return None
    rs = await asyncio.gather(*[probe(p) for p in paths])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


@tool("reverse-ip")
async def t_reverse_ip(req):
    fields = await _get_form(req)
    ip = (fields.get("ip") or req.query_params.get("ip") or "").strip()
    if not ip:
        return {"error": "ip or host required"}
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(ip, None)
            ip = infos[0][4][0]
        except Exception as e:
            return {"error": f"resolve failed: {e}"}
    text, _ = await _fetch_text(
        f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}", timeout=15.0)
    if not text or "error" in text.lower()[:60] or "API count exceeded" in text:
        return {"ip": ip, "domains": [], "note": text[:200] if text else "no data"}
    domains = [d.strip() for d in text.splitlines() if d.strip() and not d.startswith("No")]
    return {"ip": ip, "domains": domains}


_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
]
_REDIRECT_PAYLOADS = [
    "https://evil.example", "//evil.example", "/\\evil.example",
    "https:evil.example", "////evil.example", "/%09/evil.example",
]


async def _param_urls(url):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    return [(k, v[0] if v else "") for k, v in qs.items()]


def _replace_param(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode(qs, doseq=True)
    return p._replace(query=new_q).geturl()


@tool("xss-scan")
async def t_xss_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    params = await _param_urls(url)
    if not params:
        return {"url": url, "results": [], "note": "no query params"}
    results = []
    for pname, _ in params[:12]:
        for payload in _XSS_PAYLOADS:
            test = _replace_param(url, pname, payload)
            try:
                r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=12.0,
                                    allow_redirects=True, max_redirects=3)
                body = r.content
                ce = r.headers.get("content-encoding")
                if ce: body = _decompress(body, ce)
                text = body.decode("utf-8", errors="replace")
                if payload in text:
                    idx = text.find(payload)
                    window = text[max(0, idx - 60):idx + len(payload) + 60]
                    results.append({"param": pname, "payload": payload,
                                    "verified": True, "tag": window,
                                    "url": test, "status": r.status_code})
                    break
            except Exception:
                continue
    return {"url": url, "results": results}


@tool("open-redirect-scan")
async def t_open_redirect_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    params = await _param_urls(url)
    if not params:
        params = [("url", ""), ("redirect", ""), ("next", ""), ("return", ""),
                  ("returnUrl", ""), ("continue", ""), ("dest", "")]
    results = []
    for pname, _ in params[:12]:
        for payload in _REDIRECT_PAYLOADS:
            test = _replace_param(url, pname, payload)
            try:
                r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=10.0,
                                    allow_redirects=False, max_redirects=0)
                loc = r.headers.get("location", "")
                if loc and "evil.example" in loc:
                    results.append({"param": pname, "payload": payload,
                                    "location": loc, "status": r.status_code,
                                    "url": test, "vulnerable": True})
                    break
            except Exception:
                continue
    return {"url": url, "results": results}


@tool("subdomain-takeover")
async def t_subdomain_takeover(req):
    fields = await _get_form(req)
    domain_field = (fields.get("domain") or req.query_params.get("domain") or "").strip()
    if not domain_field:
        return {"error": "domain required"}
    subs = [s.strip() for s in re.split(r"[\s,]+", domain_field) if s.strip()]
    results = []
    findings = []
    for sub in subs[:50]:
        entry = {"subdomain": sub, "cname": "", "matched": "", "confirmed": False,
                 "status": 0}
        try:
            await asyncio.get_running_loop().getaddrinfo(sub, None)
            entry["status"] = 200
        except Exception:
            pass
        data, _ = await _fetch_json(
            f"https://cloudflare-dns.com/dns-query?name={quote(sub)}&type=CNAME",
            headers={"Accept": "application/dns-json",
                     "User-Agent": BROWSER_UA}, timeout=6.0)
        if data and data.get("Answer"):
            for a in data["Answer"]:
                if a.get("type") == 5:
                    entry["cname"] = a.get("data", "").rstrip(".")
                    break
        try:
            r = await app.fetch("https://" + sub, headers=BROWSER_HEADERS,
                                timeout=10.0, allow_redirects=True, max_redirects=3)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace").lower()
            entry["status"] = r.status_code
            for svc, sigs in _TAKEOVER_SIGS:
                for s in sigs:
                    if s in text:
                        entry["matched"] = svc
                        entry["confirmed"] = True
                        findings.append({
                            "severity": "high", "cwe": "CWE-1327",
                            "title": f"Subdomain takeover: {sub} → {svc}",
                            "desc": f"CNAME points at {svc} but the resource is unclaimed.",
                            "evidence": f"CNAME: {entry['cname']}\nMatched: {s}",
                            "remediation": f"Remove the {svc} DNS record or claim the resource.",
                            "tabUrl": f"https://{sub}",
                        })
                        break
                if entry["confirmed"]: break
        except Exception:
            pass
        results.append(entry)
    return {"results": results, "findings": findings}


@tool("mass-assign")
async def t_mass_assign(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    base_fields = (fields.get("fields") or "").strip()
    if not url:
        return {"error": "url required"}
    baseline = dict(parse_qsl(base_fields))
    extra_keys = ["admin","is_admin","isAdmin","role","roles","superuser",
                  "user_type","userType","permissions","verified","active",
                  "enabled","owner","account_id","tenant_id","group","groups",
                  "plan","tier","premium","balance","credits"]
    async def submit(fs):
        try:
            r = await app.fetch(url, method="POST", headers={
                **BROWSER_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            }, body=urlencode(fs).encode(), timeout=12.0,
                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return r.status_code, len(body), body[:200].decode("utf-8", "replace")
        except Exception as e:
            return 0, 0, str(e)
    base_status, base_len, _ = await submit(baseline)
    results = []
    for k in extra_keys:
        fs = dict(baseline); fs[k] = "true"
        st, ln, snip = await submit(fs)
        differs = (st != base_status) or (abs(ln - base_len) > 24)
        results.append({"field": k, "status": st, "length": ln,
                        "differs": differs, "diff": snip[:120]})
    return {"url": url, "baseline": {"status": base_status, "length": base_len},
            "results": results}


@tool("host-header")
async def t_host_header(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    origin_host = p.netloc
    tests = [
        ("Host", "evil.example"), ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Server", "evil.example"), ("X-Original-URL", "evil.example"),
        ("X-Rewrite-URL", "evil.example"), ("X-HTTP-Host-Override", "evil.example"),
        ("Forwarded", "host=evil.example"), ("X-Forwarded-For", "127.0.0.1"),
    ]
    results = []
    for hdr, val in tests:
        try:
            hdrs = dict(BROWSER_HEADERS); hdrs[hdr] = val
            r = await app.fetch(url, headers=hdrs, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace")
            loc = r.headers.get("location", "")
            reflected = ("evil.example" in text) or ("evil.example" in loc) \
                        or (r.headers.get("host", "") == "evil.example")
            results.append({"header": hdr, "value": val, "status": r.status_code,
                            "reflected": reflected, "location": loc})
        except Exception as e:
            results.append({"header": hdr, "value": val, "error": str(e),
                            "reflected": False})
    return {"url": url, "results": results, "origin_host": origin_host}


@tool("crlf-scan")
async def t_crlf_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    payloads = ["%0d%0aX-Injected:lynk", "%0aX-Injected:lynk",
                "%0d%0aSet-Cookie:lynk=1", "%E5%98%8A%E5%98%8DX-Injected:lynk",
                "%23%0d%0aX-Injected:lynk"]
    results = []
    for pl in payloads:
        test = url + ("&" if "?" in url else "?") + "x=" + pl
        try:
            r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            hl = {k.lower(): v for k, v in dict(r.headers).items()}
            injected = "x-injected" in hl or "lynk" in hl.get("set-cookie", "").lower()
            results.append({"payload": pl, "status": r.status_code,
                            "injected": injected,
                            "headers_seen": list(hl.keys())[:8]})
        except Exception as e:
            results.append({"payload": pl, "error": str(e), "injected": False})
    return {"url": url, "results": results}


@tool("smuggling")
async def t_smuggling(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    tests = [
        ("CL.TE", {"Content-Length": "6", "Transfer-Encoding": "chunked"}, b"0\r\n\r\nG"),
        ("TE.CL", {"Transfer-Encoding": "chunked", "Content-Length": "3"}, b"8\r\nSMUGGLED\r\n0\r\n\r\n"),
        ("TE space", {"Transfer-Encoding": "chunked ", "Content-Length": "4"}, b"5c\r\nGPOST / HTTP/1.1\r\n0\r\n\r\n"),
        ("TE obfusc", {"Transfer-Encoding": "xchunked", "Content-Length": "6"}, b"0\r\n\r\nG"),
        ("CL.CL", {"Content-Length": "6", "Content-Length": "4"}, b"0\r\n\r\nG"),
    ]
    results = []
    for label, hdrs, body in tests:
        t0 = time.monotonic()
        try:
            merged = {**BROWSER_HEADERS, **hdrs}
            r = await app.fetch(url, method="POST", headers=merged, body=body,
                                timeout=10.0, allow_redirects=False, max_redirects=0)
            results.append({"label": label, "status": r.status_code,
                            "time": int((time.monotonic() - t0) * 1000)})
        except Exception as e:
            results.append({"label": label, "error": str(e),
                            "time": int((time.monotonic() - t0) * 1000)})
    return {"url": url, "results": results}


@tool("cache-poison")
async def t_cache_poison(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    headers = ["X-Forwarded-Host","X-Forwarded-Scheme","X-Forwarded-Proto",
               "X-Host","X-Forwarded-Server","X-Original-URL","X-Rewrite-URL",
               "X-Forwarded-Port","Forwarded"]
    results = []
    marker = "lynk" + uuid.uuid4().hex[:6]
    for hdr in headers:
        try:
            hdrs = dict(BROWSER_HEADERS); hdrs[hdr] = marker + ".example"
            r = await app.fetch(url, headers=hdrs, timeout=10.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            text = body.decode("utf-8", errors="replace")
            loc = r.headers.get("location", "")
            reflected = marker in text or marker in loc
            results.append({"header": hdr, "status": r.status_code,
                            "reflected": reflected,
                            "cache_control": r.headers.get("cache-control", ""),
                            "age": r.headers.get("age", "")})
        except Exception as e:
            results.append({"header": hdr, "error": str(e), "reflected": False})
    return {"url": url, "results": results}


@tool("cache-deception")
async def t_cache_deception(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    path = p.path.rstrip("/")
    tricks = [path + "/nonexistent.css", path + "/nonexistent.js",
              path + "/nonexistent.jpg", path + "/;lynk.css",
              path + "/%2e%2e/lynk.css", path + "/.css", path + "/?x=.css"]
    results = []
    async def probe(u):
        try:
            r = await app.fetch(u, headers=BROWSER_HEADERS, timeout=8.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"url": u, "status": r.status_code, "length": len(body),
                    "cc": r.headers.get("cache-control", ""),
                    "xc": r.headers.get("x-cache", ""), "differs": "?"}
        except Exception as e:
            return {"url": u, "error": str(e), "differs": "?"}
    origin = f"{p.scheme}://{p.netloc}"
    base_len = 0
    try:
        r0 = await app.fetch(url, headers=BROWSER_HEADERS, timeout=8.0)
        base_len = len(r0.content)
    except Exception: pass
    for t in tricks:
        u = origin + t
        out = await probe(u)
        out["differs"] = "same" if out.get("length") == base_len else "differs"
        results.append(out)
    return {"url": url, "results": results}


_WEBSHELL_PATHS = [
    "/shell.php","/cmd.php","/c99.php","/r57.php","/b374k.php","/webshell.php",
    "/backdoor.php","/indoxploit.php","/wso.php","/alfa.php","/marijuana.php",
    "/upload.php","/uploader.php","/uploadify.php","/adminer.php","/adminer/",
    "/phpinfo.php","/info.php","/test.php","/.shell.php","/1.php","/x.php",
    "/wp-content/uploads/shell.php","/uploads/shell.php",
]

@tool("webshell-scan")
async def t_webshell_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    hits = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            if r.status_code in (200, 403, 401):
                body = r.content
                ce = r.headers.get("content-encoding")
                if ce: body = _decompress(body, ce)
                return {"path": path, "url": origin + path,
                        "status": r.status_code, "length": len(body),
                        "content_type": r.headers.get("content-type", "")}
        except Exception:
            pass
        return None
    rs = await asyncio.gather(*[probe(p) for p in _WEBSHELL_PATHS])
    for r in rs:
        if r: hits.append(r)
    return {"url": url, "hits": hits, "total": len(_WEBSHELL_PATHS)}


_BACKUP_PATHS = [
    "/backup.zip","/backup.tar","/backup.tar.gz","/backup.tgz","/backup.rar",
    "/backup.7z","/backup.sql","/backup.sql.gz","/backup.bak","/site.zip",
    "/www.zip","/html.zip","/public.zip","/web.zip","/files.zip","/source.zip",
    "/src.zip","/dist.zip","/release.zip",".env",".env.local",".env.production",
    "/.env",".git/config",".git/HEAD","/config.json","/config.yml","/config.yaml",
    "/wp-config.php.bak","/wp-config.php.old","/wp-config.php~",
    "/database.yml","/settings.py","/web.config","/appsettings.json",
    "/appsettings.Development.json","/dump.sql","/db.sql","/database.sql",
    "/.ssh/id_rsa","/.aws/credentials","/.npmrc","/.netrc",
    "/terraform.tfstate","/id_rsa",
]

@tool("backup-scan")
async def t_backup_scan(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    hits = []
    results = []
    async def probe(path):
        try:
            r = await app.fetch(origin + path, headers=BROWSER_HEADERS,
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": origin + path,
                    "status": r.status_code, "length": len(body),
                    "content_type": r.headers.get("content-type", "")}
        except Exception as e:
            return {"path": path, "error": str(e), "status": 0}
    rs = await asyncio.gather(*[probe(p) for p in _BACKUP_PATHS])
    for r in rs:
        results.append(r)
        if r.get("status") in (200, 206) and r.get("length", 0) > 20:
            hits.append(r)
    return {"url": url, "hits": hits, "results": results}


@tool("brute")
async def t_brute(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    paths_raw = fields.get("paths") or req.query_params.get("paths") or ""
    paths = []
    if paths_raw:
        try:
            parsed = json.loads(paths_raw)
            if isinstance(parsed, list):
                paths = [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            paths = [p.strip() for p in paths_raw.splitlines() if p.strip()]
    if not paths:
        paths = list(_BRUTE_DEFAULT)
    origin = _origin_of(url)
    results = []
    async def probe(path):
        target = origin + "/" + path.lstrip("/")
        try:
            r = await app.fetch(target, headers=BROWSER_HEADERS, timeout=6.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": target,
                    "status": r.status_code, "size": len(body),
                    "content_type": r.headers.get("content-type", "")}
        except Exception:
            return None
    sem = asyncio.Semaphore(20)
    async def guarded(p):
        async with sem:
            return await probe(p)
    rs = await asyncio.gather(*[guarded(p) for p in paths])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


@tool("js-endpoints")
async def t_js_endpoints(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        html = body.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e)}
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for sc in soup.find_all("script"):
        if sc.get("src"):
            try: scripts.append(urljoin(url, sc["src"]))
            except Exception: pass
        elif sc.string:
            scripts.append(None)
    blobs = [html]
    for src in scripts[:15]:
        if not src: continue
        try:
            rr = await app.fetch(src, headers=BROWSER_HEADERS, timeout=12.0)
            b = rr.content
            ce2 = rr.headers.get("content-encoding")
            if ce2: b = _decompress(b, ce2)
            blobs.append(b.decode("utf-8", errors="replace"))
        except Exception:
            continue
    combined = "\n".join(blobs)
    abs_urls = set(re.findall(r'https?://[^\s"\'\)\}\]<>]+', combined))
    paths = set(re.findall(r'["\'](/[A-Za-z0-9_\-./%?=&]+)["\']', combined))
    endpoints = []
    base_origin = _origin_of(url)
    for u in abs_urls:
        endpoints.append({"absolute": u, "kind": "absolute"})
    for p in paths:
        if len(p) < 3 or p.startswith("//"): continue
        try:
            endpoints.append({"absolute": urljoin(base_origin, p), "kind": "relative"})
        except Exception:
            pass
    seen = set(); deduped = []
    for e in endpoints:
        if e["absolute"] in seen: continue
        seen.add(e["absolute"]); deduped.append(e)
    return {"url": url, "endpoints": deduped[:400]}


_API_PATHS = ["/api","/api/v1","/api/v2","/api/v3","/api/health","/api/status",
              "/api/users","/api/user","/api/login","/api/auth","/api/token",
              "/api/me","/api/config","/api/version","/api/docs","/api/search",
              "/api/items","/api/products","/api/orders","/api/admin",
              "/api/graphql","/api/internal","/api/debug","/rest","/rest/api",
              "/v1","/v2","/v3","/graphql","/gql","/query","/rpc"]

@tool("api-discover")
async def t_api_discover(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    origin = _origin_of(url)
    results = []
    async def probe(path):
        target = origin + path
        try:
            r = await app.fetch(target, headers={**BROWSER_HEADERS,
                                                  "Accept": "application/json, */*"},
                                timeout=6.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            return {"path": path, "url": target, "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "size": len(body)}
        except Exception:
            return None
    rs = await asyncio.gather(*[probe(p) for p in _API_PATHS])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


_PARAM_WORDLIST = [
    "id","q","s","search","query","page","limit","offset","lang","locale",
    "redirect","next","url","return","returnUrl","callback","file","path",
    "dir","folder","template","view","action","method","type","mode","format",
    "debug","test","admin","token","key","apikey","api_key","access_token",
    "user","username","email","name","category","tag","sort","order","filter",
    "start","end","from","to","date","include","exclude","fields","expand",
]

@tool("params")
async def t_params(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        base_r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0,
                                 allow_redirects=False, max_redirects=0)
        base_body = base_r.content
        ce = base_r.headers.get("content-encoding")
        if ce: base_body = _decompress(base_body, ce)
        base_hash = _hashlib.md5(base_body).hexdigest()
        base_len = len(base_body)
        base_status = base_r.status_code
    except Exception as e:
        return {"error": str(e)}
    results = []
    async def probe(name):
        marker = "lynk" + uuid.uuid4().hex[:6]
        test = _replace_param(url, name, marker)
        try:
            r = await app.fetch(test, headers=BROWSER_HEADERS, timeout=8.0,
                                allow_redirects=False, max_redirects=0)
            body = r.content
            ce2 = r.headers.get("content-encoding")
            if ce2: body = _decompress(body, ce2)
            h = _hashlib.md5(body).hexdigest()
            reflected = marker.encode() in body
            differs = (h != base_hash) or (r.status_code != base_status)
            delta = abs(len(body) - base_len)
            if reflected or differs:
                return {"name": name, "reflected": reflected,
                        "differs": differs,
                        "diff": f"{'+' if delta>=0 else '-'}{abs(delta)}B",
                        "status": r.status_code}
        except Exception:
            pass
        return None
    rs = await asyncio.gather(*[probe(p) for p in _PARAM_WORDLIST])
    for r in rs:
        if r: results.append(r)
    return {"url": url, "results": results}


_GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind } } }"
}


@tool("graphql")
async def t_graphql(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, method="POST",
                            headers={**BROWSER_HEADERS,
                                     "Content-Type": "application/json",
                                     "Accept": "application/json"},
                            body=json.dumps(_GRAPHQL_INTROSPECTION).encode(),
                            timeout=15.0, allow_redirects=False, max_redirects=0)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if "errors" in data and "data" not in data:
        return {"error": "introspection disabled", "raw": data}
    schema = (data.get("data") or {}).get("__schema") or {}
    types = [t.get("name") for t in (schema.get("types") or []) if t.get("name")]
    return {
        "url": url,
        "queries": [schema.get("queryType", {}).get("name", "")] if schema.get("queryType") else [],
        "mutations": [schema.get("mutationType", {}).get("name", "")] if schema.get("mutationType") else [],
        "types": types[:300],
    }


@tool("graphql-fuzz")
async def t_graphql_fuzz(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    probes = [
        ("Introspection", {"query": "{__schema{queryType{name}}}"}),
        ("Depth bomb", {"query": "{" + "a{" * 40 + "id" + "}" * 40 + "}"}),
        ("Alias bomb", {"query": "{" + " ".join(f"a{i}:__typename" for i in range(200)) + "}"}),
        ("Field suggestion", {"query": "{ __type(name: \"___nonexistent___){name}} "}),
        ("Mutation probe", {"query": "mutation{__typename}"}),
        ("Bad type", {"query": "{ __typename( ) }"}),
    ]
    out = []
    for label, payload in probes:
        t0 = time.monotonic()
        try:
            r = await app.fetch(url, method="POST",
                                headers={**BROWSER_HEADERS,
                                         "Content-Type": "application/json"},
                                body=json.dumps(payload).encode(),
                                timeout=15.0, allow_redirects=False, max_redirects=0)
            body = r.content
            ce = r.headers.get("content-encoding")
            if ce: body = _decompress(body, ce)
            out.append({"label": label, "status": r.status_code,
                        "length": len(body),
                        "time": int((time.monotonic() - t0) * 1000),
                        "snippet": body[:200].decode("utf-8", "replace")})
        except Exception as e:
            out.append({"label": label, "error": str(e),
                        "time": int((time.monotonic() - t0) * 1000)})
    return {"url": url, "probes": out}


@tool("cors-deep")
async def t_cors_deep(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    p = urlparse(url)
    host = p.netloc
    origins = [
        "https://evil.example", "null", "http://evil.example",
        "https://" + host + ".evil.example", "https://evil" + host,
        "https://" + host.replace(".", "x", 1), "https://sub." + host,
    ]
    probes = []
    findings = []
    for o in origins:
        try:
            r = await app.fetch(url, headers={**BROWSER_HEADERS, "Origin": o},
                                timeout=8.0, allow_redirects=False, max_redirects=0)
            hl = {k.lower(): v for k, v in dict(r.headers).items()}
            acao = hl.get("access-control-allow-origin", "")
            acac = hl.get("access-control-allow-credentials", "").lower()
            probes.append({"origin": o, "acao": acao, "acac": acac,
                           "status": r.status_code})
            if acac == "true" and (acao == o or acao == "*"):
                findings.append({
                    "severity": "high",
                    "name": f"CORS: origin '{o}' with credentials",
                    "evidence": f"ACAO: {acao}\nACAC: {acac}",
                    "tabUrl": url,
                })
        except Exception as e:
            probes.append({"origin": o, "error": str(e)})
    return {"url": url, "probes": probes, "findings": findings}


@tool("hsts-audit")
async def t_hsts_audit(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=10.0,
                            allow_redirects=False, max_redirects=0)
        hsts = r.headers.get("strict-transport-security", "")
    except Exception as e:
        return {"error": str(e)}
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    return {
        "url": url, "hsts_header": hsts, "present": bool(hsts),
        "has_include_subdomains": "includesubdomains" in low,
        "has_preload": "preload" in low,
        "max_age": int(m.group(1)) if m else 0,
    }


@tool("captcha-detect")
async def t_captcha_detect(req):
    fields = await _get_form(req)
    url = (fields.get("url") or req.query_params.get("url") or "").strip()
    if not url:
        return {"error": "url required"}
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=15.0,
                            allow_redirects=True, max_redirects=3)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        html = body.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e)}
    markers = [
        ("Google reCAPTCHA", ["g-recaptcha", "recaptcha/api.js",
                               "gstatic.com/recaptcha", "recaptcha.net"]),
        ("hCaptcha", ["hcaptcha.com", "h-captcha", "data-hcaptcha"]),
        ("Cloudflare Turnstile", ["challenges.cloudflare.com/turnstile", "cf-turnstile"]),
        ("Cloudflare Challenge", ["cf-challenge", "cf_chl_", "__cf_chl",
                                   "cdn-cgi/challenge-platform"]),
        ("DataDome", ["datadome", "dd_cookie", "js.datadome.co"]),
        ("PerimeterX / HUMAN", ["_px", "perimeterx", "px-captcha", "px-cloud.net"]),
        ("Arkose Labs", ["arkoselabs", "funcaptcha", "arkose"]),
        ("AWS WAF Captcha", ["awswaf", "captcha.awswaf"]),
        ("Kasada", ["kasada", "x-kpsdk", "kpsdk"]),
        ("FriendlyCaptcha", ["friendlycaptcha", "frc-captcha"]),
        ("Geetest", ["geetest", "gt.js", "gt4.js"]),
        ("MTCaptcha", ["mtcaptcha"]),
    ]
    detected = []
    for name, sigs in markers:
        for s in sigs:
            if s.lower() in html.lower():
                detected.append(name); break
    return {"url": url, "detected": detected, "html_size": len(html),
            "captcha_script_count": sum(1 for s in CAPTCHA_HOSTS if s in html.lower())}


_CAPTCHA_KILL_JS = r"""
(function(){
  if (window.__LYNK_PRESERVE_CAPTCHA__) return;
  if (window.__LYNK_CAPTCHA_KILL__) return;
  window.__LYNK_CAPTCHA_KILL__ = true;
  var FAKE_TOKEN = 'lynk_' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  var BLOCK_HOSTS = ['google.com/recaptcha/','recaptcha.net/recaptcha/',
    'gstatic.com/recaptcha/','hcaptcha.com/','newassets.hcaptcha.com/',
    'challenges.cloudflare.com/','turnstile.com/',
    'cloudflare.com/cdn-cgi/challenge-platform/','arkoselabs.com/',
    'funcaptcha.com/','captcha.awswaf.com/','awswaf.com/captcha/',
    'geetest.com/','geetest.cn/','datadome.co/','perimeterx.net/',
    'px-cloud.net/','kasada.io/','mtcaptcha.com/','friendlycaptcha.com/'];
  function isBlocked(u){
    try { var s = String(u).toLowerCase();
      for (var i = 0; i < BLOCK_HOSTS.length; i++){
        if (s.indexOf(BLOCK_HOSTS[i]) !== -1) return true;
      }
    } catch(e){}
    return false;
  }
  var _fetch0 = window.fetch;
  if (_fetch0){
    window.fetch = function(input, init){
      try { var u = typeof input === 'string' ? input : (input && input.url ? input.url : '');
        if (u && isBlocked(decodeURIComponent(u))){
          return Promise.resolve(new Response('/* blocked */', {
            status: 200, headers: { 'Content-Type': 'text/javascript' }
          }));
        }
      } catch(e){}
      return _fetch0.apply(this, arguments);
    };
  }
  function fakeController(){
    var c = {
      ready: function(cb){ try { if (cb) setTimeout(cb, 0); } catch(e){} return c; },
      execute: function(){ return Promise.resolve(FAKE_TOKEN); },
      render: function(){ return 0; }, reset: function(){ return c; },
      getResponse: function(){ return FAKE_TOKEN; },
      getRespKey: function(){ return FAKE_TOKEN; },
      getResponsePromise: function(){ return Promise.resolve(FAKE_TOKEN); },
      remove: function(){}, on: function(){ return c; },
    };
    return c;
  }
  function installFake(name, extra){
    try { var stub = fakeController();
      if (extra) for (var k in extra) stub[k] = extra[k];
      Object.defineProperty(window, name, { get: function(){ return stub; },
        set: function(){}, configurable: true });
    } catch(e){}
  }
  installFake('grecaptcha'); installFake('hcaptcha'); installFake('turnstile');
  try { Object.defineProperty(window, '___grecaptcha_cfg', {
    get: function(){ return { clients: {}, render: [], auto_render_clients: {}, count: 0 }; },
    set: function(){}, configurable: true }); } catch(e){}
  var SELECTORS = ['.g-recaptcha','#g-recaptcha','[data-sitekey]','.grecaptcha-badge',
    '.grecaptcha-logo','.grecaptcha-error','.h-captcha','[data-hcaptcha-widget-id]',
    '.h-captcha-response','.cf-turnstile','[data-cf-turnstile]','.cf-turnstile-wrapper',
    '.geetest_holder','.geetest_panel','.geetest_wind','.frc-captcha','frc-captcha',
    '[data-px-captcha]','.px-captcha','iframe[src*="recaptcha"]','iframe[src*="hcaptcha"]',
    'iframe[src*="challenges.cloudflare.com"]','iframe[src*="turnstile"]',
    'iframe[src*="arkoselabs"]','iframe[src*="funcaptcha"]','iframe[src*="captcha"]',
    'iframe[src*="geetest"]','iframe[src*="datadome"]',
    'div[class*="captcha" i]','div[id*="captcha" i]','div[class*="challenge" i]',
    'div[id*="challenge" i]','div[class*="turnstile" i]','div[id*="turnstile" i]',
    'div[class*="hcaptcha" i]','div[id*="hcaptcha" i]','div[class*="recaptcha" i]',
    'div[id*="recaptcha" i]','div[class*="px-captcha" i]','div[id*="px-captcha" i]',
    'div[class*="cf-chl" i]','div[id*="cf-chl" i]','div[id^="cf-chl"]',
    'div[class*="challenge-stage"]','div[id*="cf-wrapper"]','div[id*="challenge-wrapper"]',
    'section[class*="challenge" i]','div[class*="dd-" i]','div[id*="dd-" i]',
    'div[class*="datadome" i]','div[class*="kasada" i]'];
  var RESP_FIELDS = ['g-recaptcha-response','h-captcha-response',
    'cf-turnstile-response','arkose-token','geetest_challenge',
    'geetest_validate','geetest_seccode'];
  function fillResponseFields(){
    for (var i = 0; i < RESP_FIELDS.length; i++){
      var n = RESP_FIELDS[i];
      try { var els = document.querySelectorAll(
          'input[name="'+n+'"], textarea[name="'+n+'"]');
        for (var j = 0; j < els.length; j++){
          try { els[j].value = FAKE_TOKEN; } catch(e){}
        }
      } catch(e){}
    }
  }
  function removeNode(el){
    try { if (!el || !el.parentNode) return;
      try {
        el.style.setProperty('display','none','important');
        el.style.setProperty('visibility','hidden','important');
        el.style.setProperty('pointer-events','none','important');
        el.setAttribute('aria-hidden','true');
      } catch(e){}
      el.parentNode.removeChild(el);
    } catch(e){}
  }
  function sweep(){
    fillResponseFields();
    for (var i = 0; i < SELECTORS.length; i++){
      try { var nodes = document.querySelectorAll(SELECTORS[i]);
        for (var j = 0; j < nodes.length; j++){
          var el = nodes[j];
          var nm = (el.name || '').toLowerCase();
          if (nm && /response$|-token$|_challenge$|_validate$|_seccode$/.test(nm)) continue;
          removeNode(el);
        }
      } catch(e){}
    }
    try {
      var all = document.querySelectorAll('body > div, body > section, body > aside, body > main');
      for (var k = 0; k < all.length; k++){
        var d = all[k];
        try { var s = getComputedStyle(d);
          if (s.position !== 'fixed' && s.position !== 'absolute') continue;
          if ((parseFloat(s.zIndex)||0) < 900) continue;
          if (d.offsetWidth >= window.innerWidth * 0.85 && d.offsetHeight >= window.innerHeight * 0.85){
            d.style.setProperty('display','none','important');
            d.style.setProperty('pointer-events','none','important');
          }
        } catch(e){}
      }
    } catch(e){}
    try {
      [document.body, document.documentElement].forEach(function(el){
        if (!el || !el.style) return;
        el.style.setProperty('overflow','auto','important');
        el.style.setProperty('pointer-events','auto','important');
        el.style.removeProperty('position');
      });
    } catch(e){}
    try {
      var forms = document.querySelectorAll('form');
      for (var m = 0; m < forms.length; m++){
        var f = forms[m];
        var had = f.__had_captcha;
        if (!had) {
          try { had = !!f.querySelector('[data-sitekey], .g-recaptcha, .h-captcha, .cf-turnstile'); }
          catch(e){ had = false; }
          if (had) f.__had_captcha = true;
        }
        if (had){
          var btns = f.querySelectorAll('button[disabled], input[type="submit"][disabled], button[aria-disabled="true"], input[aria-disabled="true"]');
          for (var n = 0; n < btns.length; n++){
            try { btns[n].removeAttribute('disabled'); btns[n].removeAttribute('aria-disabled'); }
            catch(e){}
          }
        }
      }
    } catch(e){}
  }
  sweep();
  try {
    var pending = false;
    var obs = new MutationObserver(function(muts){
      if (pending) return; pending = true;
      setTimeout(function(){ pending = false; sweep(); }, 0);
    });
    obs.observe(document.documentElement, {
      subtree: true, childList: true, attributes: true,
      attributeFilter: ['class','style','id','src','hidden','disabled','aria-hidden']
    });
  } catch(e){}
  setInterval(sweep, 500);
  function sweepShadow(root){
    try { if (!root) return;
      var hosts = root.querySelectorAll('*');
      for (var i = 0; i < hosts.length; i++){
        var sr = hosts[i] && hosts[i].shadowRoot;
        if (!sr) continue;
        try { sweepShadow(sr); } catch(e){}
        try {
          var shadowEls = sr.querySelectorAll(SELECTORS.join(','));
          for (var j = 0; j < shadowEls.length; j++) removeNode(shadowEls[j]);
        } catch(e){}
      }
    } catch(e){}
  }
  setInterval(function(){ sweepShadow(document); }, 1500);
  var CAPTCHA_FIELD_RE = /(g-recaptcha-response|h-captcha-response|cf-turnstile-response|arkose-token|geetest_challenge|geetest_validate|geetest_seccode|captcha|recaptcha|hcaptcha|turnstile)/i;
  function cleanBody(body){
    try { if (body == null) return body;
      if (typeof body === 'string'){
        return body.replace(/[&?]?(g-recaptcha-response|h-captcha-response|cf-turnstile-response|arkose-token|geetest_challenge|geetest_validate|geetest_seccode)=[^&]*/gi, '')
          .replace(/^&+/, '&').replace(/&&+/g, '&');
      }
      if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams){
        var arr = [];
        body.forEach(function(v, k){ if (!CAPTCHA_FIELD_RE.test(k)) arr.push([k, v]); });
        arr.push(['g-recaptcha-response', FAKE_TOKEN]);
        var out = new URLSearchParams();
        for (var i = 0; i < arr.length; i++) out.append(arr[i][0], arr[i][1]);
        return out;
      }
      if (typeof FormData !== 'undefined' && body instanceof FormData){
        var drop = [];
        try { body.forEach(function(v, k){ if (CAPTCHA_FIELD_RE.test(k)) drop.push(k); });
          for (var j = 0; j < drop.length; j++){
            try { body.delete(drop[j]); } catch(e){}
          }
          try { if (!body.has('g-recaptcha-response')) body.append('g-recaptcha-response', FAKE_TOKEN); }
          catch(e){}
        } catch(e){}
        return body;
      }
    } catch(e){}
    return body;
  }
  var _fetch1 = window.fetch;
  if (_fetch1){
    window.fetch = function(input, init){
      try { if (init && init.body){
          var nb = cleanBody(init.body);
          if (nb !== init.body) init = Object.assign({}, init, { body: nb });
        }
      } catch(e){}
      return _fetch1.apply(this, arguments);
    };
  }
  var _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body){
    try { body = cleanBody(body); } catch(e){}
    return _xhrSend.call(this, body);
  };
  document.addEventListener('submit', function(e){
    try { var form = e.target;
      if (!form || form.tagName !== 'FORM') return;
      var btn = form.querySelector('button[type="submit"], input[type="submit"]');
      if (btn && btn.disabled) btn.removeAttribute('disabled');
      function ensure(name){
        var f = form.querySelector('input[name="'+name+'"], textarea[name="'+name+'"]');
        if (!f) { f = document.createElement('input'); f.type = 'hidden'; f.name = name; form.appendChild(f); }
        try { f.value = FAKE_TOKEN; } catch(e){}
      }
      ensure('g-recaptcha-response');
    } catch(err){}
  }, true);
})();
"""


@tool("captcha-remove-js")
async def t_captcha_remove_js(req):
    return {"ok": True, "code": _CAPTCHA_KILL_JS}


@tool("captcha-remove")
async def t_captcha_remove(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    for s in sess.injected:
        if s["name"] == "Captcha Remover":
            s["enabled"] = True
            s["code"] = _CAPTCHA_KILL_JS
            return {"ok": True, "id": s["id"], "already": True}
    snippet = {"id": uuid.uuid4().hex[:8], "name": "Captcha Remover",
               "code": _CAPTCHA_KILL_JS, "enabled": True}
    sess.injected.append(snippet)
    return {"ok": True, "id": snippet["id"]}


@tool("captcha-remove-off")
async def t_captcha_remove_off(req):
    sid, _ = session_from_req(req)
    sess = get_session(sid)
    for s in sess.injected:
        if s["name"] == "Captcha Remover":
            s["enabled"] = False
            return {"ok": True, "disabled": True}
    return {"ok": True, "disabled": False, "note": "not present"}


@app.get("/tool/fetch")
async def t_fetch(req):
    url = req.query_params.get("url") or ""
    if not url:
        return json_response({"error": "url required"}, status=400)
    try:
        r = await app.fetch(url, headers=BROWSER_HEADERS, timeout=30.0,
                            allow_redirects=True, max_redirects=5)
        body = r.content
        ce = r.headers.get("content-encoding")
        if ce: body = _decompress(body, ce)
        ctype = r.headers.get("content-type", "application/octet-stream")
        resp = RawResponse(body, status=200, content_type=ctype)
        resp.add_header("Content-Disposition",
                        'attachment; filename="' + (urlparse(url).path.rsplit("/", 1)[-1] or "file") + '"')
        return resp
    except Exception as e:
        return json_response({"error": str(e)}, status=502)


# ======================================================================
# Static files
# ======================================================================
def _guess_mime(path):
    mt, _ = mimetypes.guess_type(path)
    if mt:
        return mt
    ext = os.path.splitext(path)[1].lower()
    return {
        ".js": "application/javascript; charset=utf-8",
        ".mjs": "application/javascript; charset=utf-8",
        ".cjs": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".htm": "text/html; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".map": "application/json; charset=utf-8",
        ".svg": "image/svg+xml", ".wasm": "application/wasm",
        ".woff": "font/woff", ".woff2": "font/woff2",
        ".ttf": "font/ttf", ".otf": "font/otf", ".ico": "image/x-icon",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".avif": "image/avif",
        ".mp4": "video/mp4", ".webm": "video/webm",
        ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
        ".txt": "text/plain; charset=utf-8",
        ".md": "text/markdown; charset=utf-8",
        ".xml": "application/xml; charset=utf-8",
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
    if (not real_full.startswith(real_base + os.sep) and real_full != real_base):
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
                urls = parse_qs(req.body.decode("utf-8", errors="ignore")).get("url", [])
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
        return error_page("Invalid URL", f"Could not parse: {esc(target)}", 400)
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


# ======================================================================
# CDP — installed after cloner, before catch-all
# ======================================================================
cdp_routes.install(app, {
    "get_session":          get_session,
    "RawResponse":          RawResponse,
    "json_response":        json_response,
    "session_from_req":     session_from_req,
    "set_browser_identity": _set_browser_identity,
    "set_impersonate":      _set_impersonate,
    "here_dir":             HERE,
})


@app.route("/*", methods=["GET", "POST", "PUT", "PATCH",
                           "DELETE", "OPTIONS", "HEAD"])
async def catch_all(req, wildcard=""):
    parts = req.path.split("?", 1)
    path_only = parts[0] or "/"
    qs = parts[1] if len(parts) > 1 else ""

    if path_only == "/favicon.ico":
        return RawResponse(b"", status=204, content_type="image/x-icon")

    if path_only.startswith(("/static/", "/lynkio/", "/tool/", "/__lynk_",
                              "/cdp/", "/clone/", "/clones")):
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
        "cdp_available":     cdp_routes.CDP_STATE["available"],
        "cdp_browser":       cdp_routes.CDP_STATE["browser"],
        "cdp_port":          cdp_routes.CDP_STATE["port"],
    })


# ======================================================================
# Boot
# ======================================================================
if __name__ == "__main__":
    print("=" * 68)
    print(f"  🛠  Lynkio Browser — v20.0   (framework {framework_version})")
    print("=" * 68)
    print(f"  Home       →  http://localhost:{PORT}/")
    print(f"  Browser    →  http://localhost:{PORT}/tabs")
    print(f"  Proxy      →  http://localhost:{PORT}/proxy?url=…")
    print(f"  Clones     →  http://localhost:{PORT}/clones")
    print(f"  Clone      →  http://localhost:{PORT}/clone/<uuid>")
    print(f"  Editor     →  http://localhost:{PORT}/clone/<uuid>/edit")
    print(f"  CDP        →  http://localhost:{PORT}/cdp/status")
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
    print(f"  CDP profile:      {HERE}/.lynkio-chrome")
    print("=" * 68)
    app.run()
