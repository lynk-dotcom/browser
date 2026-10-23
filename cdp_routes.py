"""CDP routes and background bootstrap for Lynkio."""
import asyncio
import json
import logging
import os
import time
import uuid
from collections import deque
from urllib.parse import urlparse

import browser_capture
import cdp_client
import chrome_launcher

log = logging.getLogger("lynk.cdp_routes")

CDP_STATE = {
    "available": False,
    "port": 0,
    "browser": "",
    "error": "",
    "tabs": [],
    "client": None,
    "profile_dir": "",
    "ua": "",
    "last_probe": 0.0,
    "last_launch_attempt": 0.0,
    "last_focused_target": "",
}

_SOLVES = {}
_SOLVES_ORDER = deque(maxlen=100)

_PROBE_INTERVAL = 5.0
_LAUNCH_RETRY_SECONDS = 60.0


def _choose_impersonate(major):
    candidates = [(136, "chrome136"), (131, "chrome131"), (124, "chrome124"),
                  (120, "chrome120"), (116, "chrome116"), (110, "chrome110")]
    for threshold, profile in candidates:
        if major >= threshold:
            return profile
    return "chrome124"


async def _refresh_tabs():
    client = CDP_STATE.get("client")
    if not client or CDP_STATE.get("_closed"):
        CDP_STATE["tabs"] = []
        return
    try:
        targets = await cdp_client.get_targets(client)
        CDP_STATE["tabs"] = targets
        CDP_STATE["available"] = True
        CDP_STATE["error"] = ""
    except Exception as e:
        CDP_STATE["available"] = False
        CDP_STATE["error"] = f"probe failed: {e}"
        CDP_STATE["tabs"] = []


async def _ensure_running(ctx):
    profile_dir = CDP_STATE["profile_dir"]
    ok, port, msg, _ = chrome_launcher.launch(profile_dir)
    CDP_STATE["last_launch_attempt"] = time.time()
    if not ok:
        CDP_STATE["available"] = False
        CDP_STATE["error"] = msg
        log.warning("cdp: launch failed — %s", msg)
        return False

    client = await cdp_client.connect_browser(port)
    if client is None:
        CDP_STATE["available"] = False
        CDP_STATE["error"] = "CDP probe returned no websocket"
        return False

    CDP_STATE["client"] = client
    CDP_STATE["port"] = port
    CDP_STATE["available"] = True
    CDP_STATE["error"] = ""

    info = cdp_client.probe(port) or {}
    browser_str = info.get("Browser", "")
    CDP_STATE["browser"] = browser_str
    ua = info.get("User-Agent", "")
    if ua:
        CDP_STATE["ua"] = ua
        try:
            ctx["set_browser_identity"](ua)
        except Exception:
            pass
    if "Chrome/" in browser_str:
        try:
            major = int(browser_str.split("Chrome/")[1].split(".")[0])
            profile = _choose_impersonate(major)
            try:
                ctx["set_impersonate"](profile)
            except Exception:
                pass
        except Exception:
            pass

    await _refresh_tabs()
    log.info("cdp: connected on :%s — %s", port, browser_str or "unknown")
    return True


async def _bootstrap_loop(ctx):
    await asyncio.sleep(1.0)
    await _ensure_running(ctx)
    while True:
        await asyncio.sleep(_PROBE_INTERVAL)
        try:
            client = CDP_STATE.get("client")
            if client is not None:
                await _refresh_tabs()
                if not CDP_STATE["available"]:
                    try:
                        await client.close()
                    except Exception:
                        pass
                    CDP_STATE["client"] = None
            else:
                if (time.time() - CDP_STATE["last_launch_attempt"]
                        > _LAUNCH_RETRY_SECONDS):
                    await _ensure_running(ctx)
        except Exception as e:
            log.debug("cdp: bootstrap loop error: %s", e)


def is_available():
    return bool(CDP_STATE.get("available") and CDP_STATE.get("client"))


async def _solve_async(token, target_url, origin, sid, ctx):
    try:
        get_session = ctx["get_session"]
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            _SOLVES[token] = {"status": "error", "error": "Chrome not connected"}
            return

        base = target_url.split("?")[0]
        targets = await cdp_client.get_targets(client)
        target = None
        for t in targets:
            if (t.get("url") or "").startswith(base):
                target = t
                break

        if not target:
            tid = await cdp_client.create_target(client, target_url)
            await asyncio.sleep(1.2)
            for t in await cdp_client.get_targets(client):
                if t.get("targetId") == tid or (t.get("url") or "").startswith(base):
                    target = t
                    break

        if not target:
            _SOLVES[token] = {"status": "error", "error": "could not open tab"}
            return

        tid = target["targetId"]
        CDP_STATE["last_focused_target"] = tid
        try:
            await cdp_client.activate_target(client, tid)
        except Exception:
            pass

        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            _SOLVES[token] = {"status": "error", "error": "attach failed"}
            return

        await cdp_client.navigate(client, session_id, target_url)
        await cdp_client.wait_ready(client, session_id, timeout=30.0)
        await browser_capture.wait_challenge_cleared(
            client, session_id, origin, timeout=45.0)

        clone = await browser_capture.capture(
            client, session_id, target_url, origin, sess)

        sess.cdp_captures[target_url] = clone["outer_html"]
        _SOLVES[token] = {"status": "ready", "uuid": clone["uuid"]}
        log.info("cdp: solve %s ready (uuid=%s)", token[:8], clone["uuid"])

    except Exception as e:
        log.warning("cdp solve %s failed: %s", token[:8], e)
        _SOLVES[token] = {"status": "error", "error": str(e)}


def _new_token():
    tok = uuid.uuid4().hex[:12]
    _SOLVES[tok] = {"status": "pending"}
    _SOLVES_ORDER.append(tok)
    while len(_SOLVES) > _SOLVES_ORDER.maxlen:
        if _SOLVES_ORDER:
            old = _SOLVES_ORDER[0]
            _SOLVES.pop(old, None)
        else:
            break
    return tok


_SOLVING_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Solving via Chrome · __HOST__</title>
<style>
body{font-family:Inter,system-ui,-apple-system,sans-serif;background:#070b16;color:#e2e8f0;
min-height:100vh;margin:0;padding:24px;display:flex;align-items:center;justify-content:center}
.card{max-width:560px;width:100%;background:#0d1526;border:1px solid rgba(148,163,184,.2);
border-radius:16px;padding:28px;text-align:left}
h1{font-size:18px;margin:0 0 10px;color:#38bdf8}
p{margin:0 0 14px;color:#94a3b8;font-size:13.5px;line-height:1.55}
code{background:rgba(2,6,23,.6);padding:2px 6px;border-radius:4px;
font-family:ui-monospace,monospace;font-size:12px;color:#38bdf8}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #38bdf8;
border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;
vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.status{display:flex;align-items:center;gap:8px;padding:12px 14px;border-radius:9px;
background:rgba(56,189,248,.08);border-left:3px solid #38bdf8;margin:14px 0;
font-family:ui-monospace,monospace;font-size:12px;color:#38bdf8}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
button{padding:10px 18px;border-radius:9px;border:none;font-family:inherit;
font-size:13px;font-weight:700;cursor:pointer;transition:.15s}
button.primary{background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0b1220}
button.ghost{background:transparent;border:1px solid rgba(148,163,184,.3);color:#e2e8f0}
button:disabled{opacity:.5;cursor:not-allowed}
</style></head><body>
<div class="card">
  <h1>Opening __HOST__ in Chrome…</h1>
  <p>A real Chrome tab is being opened so the challenge can be solved natively. If the widget needs a click, do it in that window — Lynkio will capture the result automatically.</p>
  <div class="status"><span class="spinner"></span><span id="st">Waiting for Chrome…</span></div>
  <p style="font-size:11.5px;color:#64748b">Once solved, this page reloads through the proxy with all session cookies, <code>cf_clearance</code>, storage and DOM state captured.</p>
  <div class="row">
    <button class="primary" id="retryBtn" disabled>Reload now</button>
    <button class="ghost" id="chromeBtn">Focus Chrome tab</button>
  </div>
</div>
<script>
(function(){
  var TOKEN  = __TOKEN__;
  var TARGET = __TARGET_URL__;
  var st = document.getElementById('st');
  var retryBtn = document.getElementById('retryBtn');
  var chromeBtn = document.getElementById('chromeBtn');
  var done = false;
  function reloadNow(){
    if (done) return;
    done = true;
    location.href = '/proxy?url=' + encodeURIComponent(TARGET) + '&_t=' + Date.now();
  }
  retryBtn.onclick = reloadNow;
  chromeBtn.onclick = function(){
    fetch('/cdp/focus-tab', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({targetId: '' })
    }).catch(function(){});
  };
  async function poll(){
    try {
      var r = await fetch('/cdp/solve-status/' + TOKEN, {credentials: 'same-origin'});
      var d = await r.json();
      if (d.status === 'ready') { st.textContent = 'Solved — reloading…'; reloadNow(); return; }
      if (d.status === 'error') { st.textContent = 'Error: ' + (d.error || 'unknown'); return; }
      st.textContent = 'Waiting for solve… (' + (d.status || '?') + ')';
    } catch(e) {}
    setTimeout(poll, 1200);
  }
  setTimeout(poll, 400);
})();
</script>
</body></html>"""


def solving_page(target_url, origin, token):
    host = urlparse(target_url).hostname or ""
    html = (_SOLVING_HTML
            .replace("__TOKEN__", json.dumps(token))
            .replace("__TARGET_URL__", json.dumps(target_url))
            .replace("__HOST__", host))
    return html


def install(app, ctx):
    RawResponse   = ctx["RawResponse"]
    json_response = ctx["json_response"]
    get_session   = ctx["get_session"]
    session_from_req = ctx["session_from_req"]

    CDP_STATE["profile_dir"] = os.path.join(ctx.get("here_dir", "."), ".lynkio-chrome")

    app.task(lambda: _bootstrap_loop(ctx))

    @app.get("/cdp/status")
    async def cdp_status(req):
        return json_response({
            "available": CDP_STATE["available"],
            "browser":   CDP_STATE["browser"],
            "port":      CDP_STATE["port"],
            "error":     CDP_STATE["error"],
            "tabs":      CDP_STATE["tabs"],
            "profile_dir": CDP_STATE["profile_dir"],
        })

    @app.route("/cdp/launch", methods=["POST"])
    async def cdp_launch(req):
        ok = await _ensure_running(ctx)
        return json_response({
            "ok": ok,
            "browser": CDP_STATE["browser"],
            "port": CDP_STATE["port"],
            "message": CDP_STATE["error"] or "launched",
            "tabs": CDP_STATE["tabs"],
        })

    @app.route("/cdp/focus-tab", methods=["POST"])
    async def cdp_focus(req):
        try:
            body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {}
        tid = (body.get("targetId") or "").strip() or CDP_STATE["last_focused_target"]
        client = CDP_STATE.get("client")
        if not client or not tid:
            return json_response({"ok": False, "error": "no client or targetId"}, status=400)
        ok = await cdp_client.activate_target(client, tid)
        if ok:
            CDP_STATE["last_focused_target"] = tid
        return json_response({"ok": ok})

    @app.route("/cdp/capture", methods=["POST"])
    async def cdp_capture(req):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            return json_response({"ok": False, "error": "Chrome not connected"}, status=503)
        try:
            body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {}
        tid = (body.get("targetId") or "").strip() or CDP_STATE["last_focused_target"]
        url = (body.get("url") or "").strip()

        if not tid and CDP_STATE["tabs"]:
            tid = CDP_STATE["tabs"][0]["targetId"]
            url = url or CDP_STATE["tabs"][0]["url"]
        if not tid or not url:
            return json_response({"ok": False, "error": "targetId/url required"}, status=400)

        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            return json_response({"ok": False, "error": "attach failed"}, status=500)
        try:
            clone = await browser_capture.capture(client, session_id, url, origin, sess)
        except Exception as e:
            log.warning("capture failed: %s", e)
            return json_response({"ok": False, "error": str(e)}, status=500)
        return json_response({
            "ok": True,
            "uuid": clone["uuid"],
            "url": f"/clone/{clone['uuid']}",
            "source_url": clone["source_url"],
        })

    @app.route("/cdp/solve", methods=["POST"])
    async def cdp_solve(req):
        try:
            body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {}
        url = (body.get("url") or "").strip()
        if not url:
            return json_response({"ok": False, "error": "url required"}, status=400)
        sid, _ = session_from_req(req)
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        token = _new_token()
        asyncio.create_task(_solve_async(token, url, origin, sid, ctx))
        return json_response({"ok": True, "token": token})

    @app.get("/cdp/solve-status/*")
    async def cdp_solve_status(req, wildcard=""):
        token = (wildcard or "").split("?", 1)[0].strip("/")
        s = _SOLVES.get(token)
        if not s:
            return json_response({"status": "unknown"}, status=404)
        return json_response(s)

    log.info("cdp: routes installed; profile_dir=%s", CDP_STATE["profile_dir"])
