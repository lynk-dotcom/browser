#!/usr/bin/env python3
"""
Lynkio Cloner — full page/session/DOM/storage capture + rehydrate.

v2: single handler for GET+DELETE /clone/* (Lynkio routing returns 405
when a path matches but the method is missing on the first-matched route;
combining avoids that trap).
"""

import base64
import copy
import gzip
import hashlib
import json
import logging
import os
import time
import uuid as _uuid
from collections import deque
from urllib.parse import urlparse

log = logging.getLogger("lynk.cloner")

HERE       = os.path.dirname(os.path.abspath(__file__))
CLONES_DIR = os.path.join(HERE, "clones")
os.makedirs(CLONES_DIR, exist_ok=True)

MAX_CLONES             = 2000
MAX_RAW_BYTES          = 64 * 1024 * 1024
MAX_STORED_BYTES       = 512 * 1024 * 1024
INLINE_STATE_THRESHOLD = 8 * 1024 * 1024

CLONE_VISITOR_COOKIE = "__lynk_clone_vid"


# ======================================================================
# Storage
# ======================================================================

def _clone_path(cid):
    return os.path.join(CLONES_DIR, f"{cid}.json.gz")


def _list_files():
    try:
        return [f for f in os.listdir(CLONES_DIR) if f.endswith(".json.gz")]
    except FileNotFoundError:
        return []


def _enforce_capacity():
    files = _list_files()
    if len(files) < MAX_CLONES:
        return
    entries = []
    for f in files:
        full = os.path.join(CLONES_DIR, f)
        try:
            entries.append((os.path.getmtime(full), full))
        except OSError:
            pass
    entries.sort()
    excess = len(entries) - MAX_CLONES + 1
    for _, path in entries[:max(0, excess)]:
        try:
            os.remove(path)
            log.info("cloner: evicted %s", os.path.basename(path))
        except OSError:
            pass


def save_clone(clone):
    _enforce_capacity()
    blob = json.dumps(clone, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(blob, compresslevel=6)
    if len(compressed) > MAX_STORED_BYTES:
        raise ValueError(
            f"clone too large: {len(compressed)} compressed bytes "
            f"(limit {MAX_STORED_BYTES})"
        )
    path = _clone_path(clone["uuid"])
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(compressed)
    os.replace(tmp, path)
    log.info("cloner: saved %s (%d → %d)",
             clone["uuid"], len(blob), len(compressed))


def load_clone(cid):
    path = _clone_path(cid)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            blob = gzip.decompress(f.read())
        return json.loads(blob.decode("utf-8"))
    except Exception as e:
        log.warning("cloner: load %s failed: %s", cid, e)
        return None


def delete_clone(cid):
    try:
        os.remove(_clone_path(cid))
        return True
    except FileNotFoundError:
        return False


def list_clones():
    out = []
    for f in _list_files():
        cid = f[:-len(".json.gz")]
        full = os.path.join(CLONES_DIR, f)
        try:
            size = os.path.getsize(full)
            with open(full, "rb") as fh:
                blob = gzip.decompress(fh.read())
            c = json.loads(blob.decode("utf-8"))
            dom = c.get("dom_state") or {}
            out.append({
                "uuid": cid,
                "source_url": c.get("source_url", ""),
                "page_origin": c.get("page_origin", ""),
                "created_at": c.get("created_at", 0),
                "edit_count": c.get("edit_count", 0),
                "size": size,
                "has_indexeddb": bool(c.get("indexeddb")),
                "has_caches": bool(c.get("caches")),
                "has_opfs": bool(c.get("opfs")),
                "dom_counts": {
                    "forms": len(dom.get("forms") or []),
                    "scrolls": len(dom.get("scrolls") or []),
                    "canvases": len(dom.get("canvases") or []),
                    "media": len(dom.get("media") or []),
                    "shadows": len(dom.get("shadows") or []),
                },
                "globals_count": len(c.get("globals") or {}),
            })
        except Exception as e:
            log.debug("cloner: skip %s (%s)", f, e)
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return out


# ======================================================================
# Capture / hydrate
# ======================================================================

def capture_from_client(sess, payload):
    target_url = (payload.get("target_url") or sess.last_origin or "").strip()
    outer_html = payload.get("outer_html") or ""
    if not outer_html:
        raise ValueError("outer_html is required")

    parsed = urlparse(target_url)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        page_origin = f"{parsed.scheme}://{parsed.netloc}"
    else:
        page_origin = sess.page_origin or ""

    now = time.time()
    clone = {
        "uuid": _uuid.uuid4().hex[:16],
        "created_at": now,
        "source_url": target_url,
        "page_origin": page_origin,
        "final_path": parsed.path or "/",

        "server_cookies": {k: dict(v) for k, v in sess.cookies.by_origin.items()},
        "injected": [
            {"id": s["id"], "name": s["name"],
             "code": s["code"], "enabled": s["enabled"]}
            for s in sess.injected
        ],
        "history": list(sess.history)[-300:],
        "recent_origins": [[o, t] for o, t in sess.recent_origins],

        "outer_html": outer_html,
        "local_storage": payload.get("local_storage") or {},
        "session_storage": payload.get("session_storage") or {},
        "document_cookies": payload.get("document_cookies") or "",
        "indexeddb": payload.get("indexeddb") or {},
        "caches": payload.get("caches") or {},
        "opfs": payload.get("opfs"),
        "dom_state": payload.get("dom_state") or {},
        "globals": payload.get("globals") or {},

        "user_agent": payload.get("user_agent") or "",
        "viewport": payload.get("viewport") or {},
        "edit_count": 0,
        "last_edit_ts": 0,
    }
    save_clone(clone)
    return clone


def hydrate_session_from_clone(sess, clone):
    sess.cookies.by_origin = copy.deepcopy(clone.get("server_cookies") or {})
    sess.page_origin = clone.get("page_origin", "")
    sess.last_origin = sess.page_origin
    sess.injected = [dict(s) for s in (clone.get("injected") or [])]
    sess.history = deque(clone.get("history") or [], maxlen=1000)
    sess.recent_origins = deque(
        [(o, t) for o, t in (clone.get("recent_origins") or [])], maxlen=24,
    )


def clone_session_id(clone_uuid, visitor_id):
    return hashlib.sha256(
        f"{clone_uuid}|{visitor_id}".encode()).hexdigest()[:32]


def state_payload(clone):
    return {
        "uuid": clone["uuid"],
        "source_url": clone.get("source_url", ""),
        "page_origin": clone.get("page_origin", ""),
        "local_storage": clone.get("local_storage") or {},
        "session_storage": clone.get("session_storage") or {},
        "document_cookies": clone.get("document_cookies") or "",
        "indexeddb": clone.get("indexeddb") or {},
        "caches": clone.get("caches") or {},
        "opfs": clone.get("opfs"),
        "dom_state": clone.get("dom_state") or {},
        "globals": clone.get("globals") or {},
        "injected": clone.get("injected") or [],
    }


def build_clone_html(clone):
    html = clone["outer_html"]
    state = state_payload(clone)
    blob = json.dumps(state, separators=(",", ":")).encode("utf-8")

    if len(blob) <= INLINE_STATE_THRESHOLD:
        bootstrap = (
            '<script id="__lynk_clone_state">'
            'window.__LYNK_CLONE_STATE__='
            f'{json.dumps(state, separators=(",", ":"))};'
            '</script>'
            '<script src="/static/js/cloner_hydrate.js"></script>'
        )
    else:
        bootstrap = (
            '<script>'
            f'window.__LYNK_CLONE_STATE_URL__="/clone/{clone["uuid"]}/state.json";'
            '</script>'
            '<script src="/static/js/cloner_hydrate.js"></script>'
        )

    lower = html.lower()
    idx = lower.find("<head")
    if idx != -1:
        close = lower.find(">", idx)
        if close != -1:
            return html[:close + 1] + bootstrap + html[close + 1:]
    idx = lower.find("<html")
    if idx != -1:
        close = lower.find(">", idx)
        if close != -1:
            return html[:close + 1] + "<head>" + bootstrap + "</head>" + html[close + 1:]
    return ("<!DOCTYPE html><html><head>" + bootstrap
            + "</head><body>" + html + "</body></html>")


# ======================================================================
# Route installer
# ======================================================================

def install(app, ctx):
    """
    ctx keys required:
        get_session, Session, RawResponse, json_response, error_page,
        SESSION_COOKIE, session_from_req, SESSIONS
    """
    get_session      = ctx["get_session"]
    Session          = ctx["Session"]
    RawResponse      = ctx["RawResponse"]
    json_response    = ctx["json_response"]
    error_page       = ctx["error_page"]
    SESSION_COOKIE   = ctx["SESSION_COOKIE"]
    session_from_req = ctx["session_from_req"]
    SESSIONS         = ctx["SESSIONS"]

    def _visitor(req):
        vid = req.cookies.get(CLONE_VISITOR_COOKIE, "")
        new = False
        if not vid or len(vid) < 8:
            vid = _uuid.uuid4().hex[:16]
            new = True
        return vid, new

    # ---- capture from live page (exact POST) -----------------------
    @app.route("/clone/capture-client", methods=["POST"])
    async def clone_capture_client(req):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        body = req.body or b""
        if len(body) > MAX_RAW_BYTES:
            return json_response(
                {"error": f"payload too large ({len(body)} > {MAX_RAW_BYTES})"},
                status=413,
            )
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError as e:
            return json_response({"error": f"invalid JSON: {e}"}, status=400)
        try:
            clone = capture_from_client(sess, payload)
        except ValueError as e:
            return json_response({"error": str(e)}, status=400)
        except Exception as e:
            log.exception("cloner: capture failed")
            return json_response({"error": f"capture failed: {e}"}, status=500)
        return json_response({
            "uuid": clone["uuid"],
            "url": f"/clone/{clone['uuid']}",
            "source_url": clone["source_url"],
        })

    # ---- import (exact POST) ---------------------------------------
    @app.route("/clone/import", methods=["POST"])
    async def clone_import(req):
        body = req.body or b""
        if len(body) > MAX_RAW_BYTES:
            return json_response({"error": "too large"}, status=413)
        try:
            c = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError as e:
            return json_response({"error": f"invalid JSON: {e}"}, status=400)
        if "uuid" not in c or "outer_html" not in c:
            return json_response({"error": "not a clone file"}, status=400)
        c["uuid"] = _uuid.uuid4().hex[:16]
        c.setdefault("created_at", time.time())
        c.setdefault("edit_count", 0)
        c.setdefault("last_edit_ts", 0)
        try:
            save_clone(c)
        except ValueError as e:
            return json_response({"error": str(e)}, status=413)
        return json_response({"uuid": c["uuid"], "url": f"/clone/{c['uuid']}"})

    # ---- list (exact GET) ------------------------------------------
    @app.get("/clones")
    async def clones_index(req):
        return json_response({"clones": list_clones()})

    # ---- per-clone sub-resources (specific wildcards) --------------
    # These come BEFORE /clone/* so they match first within wild_routes.
    @app.get("/clone/*/state.json")
    async def clone_state_json(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        return json_response(state_payload(c))

    @app.get("/clone/*/source")
    async def clone_source_get(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        return json_response({
            "uuid": cid,
            "source_url": c["source_url"],
            "outer_html": c["outer_html"],
            "edit_count": c["edit_count"],
        })

    @app.route("/clone/*/source", methods=["PUT"])
    async def clone_source_put(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        try:
            payload = json.loads(
                (req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return json_response({"error": "invalid JSON"}, status=400)
        new_html = payload.get("outer_html")
        if not isinstance(new_html, str):
            return json_response({"error": "outer_html required"}, status=400)
        c["outer_html"] = new_html
        c["edit_count"] = int(c.get("edit_count", 0)) + 1
        c["last_edit_ts"] = time.time()
        try:
            save_clone(c)
        except ValueError as e:
            return json_response({"error": str(e)}, status=413)
        return json_response({"ok": True, "edit_count": c["edit_count"]})

    @app.get("/clone/*/meta")
    async def clone_meta(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        dom = c.get("dom_state") or {}
        return json_response({
            "uuid": cid,
            "source_url": c["source_url"],
            "page_origin": c["page_origin"],
            "created_at": c["created_at"],
            "edit_count": c["edit_count"],
            "last_edit_ts": c["last_edit_ts"],
            "cookie_origins": list((c.get("server_cookies") or {}).keys()),
            "injected_count": len(c.get("injected") or []),
            "history_count": len(c.get("history") or []),
            "local_storage_keys": list((c.get("local_storage") or {}).keys()),
            "session_storage_keys": list((c.get("session_storage") or {}).keys()),
            "indexeddb_dbs": list((c.get("indexeddb") or {}).keys()),
            "cache_names": list((c.get("caches") or {}).keys()),
            "opfs_present": bool(c.get("opfs")),
            "dom_counts": {
                "forms": len(dom.get("forms") or []),
                "scrolls": len(dom.get("scrolls") or []),
                "canvases": len(dom.get("canvases") or []),
                "media": len(dom.get("media") or []),
                "shadows": len(dom.get("shadows") or []),
            },
            "globals_count": len(c.get("globals") or {}),
        })

    @app.get("/clone/*/export")
    async def clone_export(req, wildcard=""):
        cid = (wildcard or "").split("/", 1)[0].strip()
        c = load_clone(cid)
        if not c:
            return json_response({"error": "not found"}, status=404)
        blob = json.dumps(c, ensure_ascii=False).encode("utf-8")
        resp = RawResponse(blob, content_type="application/json")
        resp.add_header("Content-Disposition",
                        f'attachment; filename="{cid}.lynkclone"')
        return resp

    # ---- serve OR delete a clone (ONE handler, both methods) -------
    # Combining GET + DELETE avoids Lynkio's "path matches but method
    # missing → 405 and stop" behaviour when two routes share the same
    # wildcard pattern.
    @app.route("/clone/*", methods=["GET", "DELETE"])
    async def clone_route(req, wildcard=""):
        raw = (wildcard or "").split("?", 1)[0]
        cid = raw.split("/", 1)[0].strip()
        if not cid:
            return error_page("Clone not found", "Missing clone id.", 404)

        if req.method == "DELETE":
            ok = delete_clone(cid)
            return json_response({"ok": ok}, status=200 if ok else 404)

        # GET — serve the clone
        clone = load_clone(cid)
        if not clone:
            return error_page(
                "Clone not found",
                f"No clone with id <code>{cid}</code>.", 404,
            )

        vid, is_new = _visitor(req)
        sid = clone_session_id(cid, vid)
        if sid not in SESSIONS:
            sess = Session()
            hydrate_session_from_clone(sess, clone)
            sess.clone_uuid = cid
            sess.clone_visitor = vid
            SESSIONS[sid] = sess
        SESSIONS[sid].touch()

        html = build_clone_html(clone)
        resp = RawResponse(html.encode("utf-8"),
                           content_type="text/html; charset=utf-8")
        resp.add_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={sid}; Path=/; Max-Age=86400; SameSite=Lax",
        )
        if is_new:
            resp.add_header(
                "Set-Cookie",
                f"{CLONE_VISITOR_COOKIE}={vid}; Path=/; Max-Age=86400; SameSite=Lax",
            )
        resp.add_header("Cache-Control", "no-store")
        return resp

    log.info("cloner: routes installed")
