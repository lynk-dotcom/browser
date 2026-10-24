"""
CDP routes and background bootstrap for Lynkio.

- Spawns /headless-shell/headless-shell (or the configured binary) on CDP_PORT
  as a child of brow.py.
- Polls http://127.0.0.1:<port>/json/version for the WebSocket URL.
- Connects via cdp_client.CDPClient.
- Reconnects automatically if the browser dies.
- Deduplicates concurrent solves for the same URL so pages don't open
  one browser tab per subresource.
- Exposes /cdp/status, /cdp/capture, /cdp/solve, /cdp/solve-status,
  /cdp/launch, /cdp/focus-tab.
"""
import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from collections import deque
from urllib.parse import urlparse

import browser_capture
import cdp_client

log = logging.getLogger("lynk.cdp_routes")

# ---------------------------------------------------------------- config
CDP_PORT         = int(os.environ.get("CDP_PORT", "9222"))
CHROME_BIN       = os.environ.get(
    "CHROME_BIN",
    os.environ.get("OBSCURA_BIN", "/headless-shell/headless-shell"),
)
HEADLESS         = os.environ.get("CDP_HEADLESS", "1") == "1"
PROBE_INTERVAL   = 5.0
SPAWN_RETRY_SEC  = 20.0

# ---------------------------------------------------------------- state
CDP_STATE = {
    "available": False,
    "port": CDP_PORT,
    "browser": "",
    "error": "",
    "tabs": [],
    "client": None,
    "ua": "",
    "last_probe": 0.0,
    "last_spawn_attempt": 0.0,
    "shell_proc": None,
    "last_focused_target": "",
}

_SOLVES = {}
_SOLVES_ORDER = deque(maxlen=100)
_SOLVE_INFLIGHT = {}   # target_url → token of the in-flight solve


def _choose_impersonate(major):
    candidates = [(136, "chrome136"), (131, "chrome131"), (124, "chrome124"),
                  (120, "chrome120"), (116, "chrome116"), (110, "chrome110")]
    for threshold, profile in candidates:
        if major >= threshold:
            return profile
    return "chrome124"


# ---------------------------------------------------------- spawn shell
def _spawn_shell():
    """Launch the headless browser as a background child of brow.py."""
    info = cdp_client.probe(CDP_PORT)
    if info and "webSocketDebuggerUrl" in info:
        return True

    if not os.path.isfile(CHROME_BIN):
        CDP_STATE["error"] = f"headless binary not found at {CHROME_BIN}"
        log.warning("cdp: %s", CDP_STATE["error"])
        return False

    # Detect the Ubuntu chromium snap stub trap
    try:
        if os.path.islink(CHROME_BIN):
            target = os.path.realpath(CHROME_BIN)
            if "/snap/" in target:
                CDP_STATE["error"] = (
                    f"{CHROME_BIN} is a snap stub → {target}. Snap does not "
                    f"work in Docker. Use Debian chromium or headless-shell."
                )
                log.warning("cdp: %s", CDP_STATE["error"])
                return False
    except Exception:
        pass

    args = [
        CHROME_BIN,
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-debugging-address=127.0.0.1",
        "--user-data-dir=/tmp/chrome-profile",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-translate",
        "--disable-extensions",
        "--mute-audio",
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-allow-origins=*",
    ]
    if HEADLESS:
        args.append("--headless=new")
    args.append("about:blank")

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        CDP_STATE["shell_proc"] = proc
    except Exception as e:
        CDP_STATE["error"] = f"spawn failed: {e}"
        log.warning("cdp: %s", CDP_STATE["error"])
        return False

    deadline = time.time() + SPAWN_RETRY_SEC
    while time.time() < deadline:
        info = cdp_client.probe(CDP_PORT)
        if info and "webSocketDebuggerUrl" in info:
            log.info("cdp: spawned pid=%s exe=%s port=%s",
                     proc.pid, CHROME_BIN, CDP_PORT)
            return True
        if proc.poll() is not None:
            CDP_STATE["error"] = f"browser exited early (code {proc.returncode})"
            log.warning("cdp: %s", CDP_STATE["error"])
            return False
        time.sleep(0.4)
    CDP_STATE["error"] = (
        f"browser didn't answer CDP on :{CDP_PORT} within {SPAWN_RETRY_SEC}s"
    )
    log.warning("cdp: %s", CDP_STATE["error"])
    return False


async def _refresh_tabs():
    client = CDP_STATE.get("client")
    if not client:
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
    CDP_STATE["last_spawn_attempt"] = time.time()

    if not _spawn_shell():
        CDP_STATE["available"] = False
        return False

    try:
        client = await cdp_client.connect_browser(CDP_PORT)
    except Exception as e:
        CDP_STATE["available"] = False
        CDP_STATE["error"] = f"connect failed: {e}"
        return False

    if client is None:
        CDP_STATE["available"] = False
        CDP_STATE["error"] = "no websocket from CDP probe"
        return False

    CDP_STATE["client"]    = client
    CDP_STATE["available"] = True
    CDP_STATE["error"]     = ""

    info = cdp_client.probe(CDP_PORT) or {}
    CDP_STATE["browser"] = info.get("Browser", "")
    ua = info.get("User-Agent", "")
    if ua:
        CDP_STATE["ua"] = ua
        try:
            ctx["set_browser_identity"](ua)
        except Exception:
            pass
    if "Chrome/" in CDP_STATE["browser"]:
        try:
            major = int(CDP_STATE["browser"].split("Chrome/")[1].split(".")[0])
            try:
                ctx["set_impersonate"](_choose_impersonate(major))
            except Exception:
                pass
        except Exception:
            pass

    await _refresh_tabs()
    log.info("cdp: connected on :%s — %s", CDP_PORT,
             CDP_STATE["browser"] or "headless")
    return True


async def _bootstrap_loop(ctx):
    await asyncio.sleep(1.5)
    await _ensure_running(ctx)
    while True:
        await asyncio.sleep(PROBE_INTERVAL)
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
                if (time.time() - CDP_STATE["last_spawn_attempt"]) > SPAWN_RETRY_SEC:
                    await _ensure_running(ctx)
        except Exception as e:
            log.debug("cdp: bootstrap loop error: %s", e)


def is_available():
    return bool(CDP_STATE.get("available") and CDP_STATE.get("client"))


# ------------------------------------------------------- solve / capture
async def _solve_async(token, target_url, origin, sid, ctx):
    """
    Open the URL in the headless browser, wait for network idle, capture
    DOM + storage + cookies into a clone artifact.

    Deduplicates concurrent calls: if the same target_url is already being
    solved, the new request chains onto the existing solve's token instead
    of opening a second tab. Without this, a page with N subresources
    triggers N solves and exhausts the container's memory.
    """
    # --- Dedup ---
    existing = _SOLVE_INFLIGHT.get(target_url)
    if existing and existing != token:
        prior = _SOLVES.get(existing)
        if prior and prior.get("status") == "pending":
            _SOLVES[token] = {"status": "deduplicated", "token": existing}
            log.debug("cdp: solve %s deduplicated to %s",
                      token[:8], existing[:8])
            return

    _SOLVE_INFLIGHT[target_url] = token
    try:
        get_session = ctx["get_session"]
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            _SOLVES[token] = {"status": "error",
                               "error": "browser not connected"}
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
            _SOLVES[token] = {"status": "error",
                               "error": "could not open tab"}
            return

        tid = target["targetId"]
        CDP_STATE["last_focused_target"] = tid

        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            _SOLVES[token] = {"status": "error", "error": "attach failed"}
            return

        await cdp_client.navigate(client, session_id, target_url)
        await cdp_client.wait_ready(client, session_id, timeout=30.0)
        await browser_capture.wait_challenge_cleared(
            client, session_id, origin, timeout=20.0)

        clone = await browser_capture.capture(
            client, session_id, target_url, origin, sess)

        sess.cdp_captures[target_url] = clone["outer_html"]
        _SOLVES[token] = {"status": "ready", "uuid": clone["uuid"]}
        log.info("cdp: capture %s ready (uuid=%s)", token[:8], clone["uuid"])

    except Exception as e:
        log.warning("cdp solve %s failed: %s", token[:8], e)
        _SOLVES[token] = {"status": "error", "error": str(e)}
    finally:
        if _SOLVE_INFLIGHT.get(target_url) == token:
            _SOLVE_INFLIGHT.pop(target_url, None)


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
<title>Capturing via headless browser · __HOST__</title>
<style>
body{font-family:Inter,system-ui,-apple-system,sans-serif;background:#070b16;color:#e2e8f0;
min-height:100vh;margin:0;padding:24px;display:flex;align-items:center;justify-content:center}
.card{max-width:560px;width:100%;background:#0d1526;border:1px solid rgba(148,163,184,.2);
border-radius:16px;padding:28px}
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
</style></head><body>
<div class="card">
  <h1>Capturing __HOST__ in headless browser…</h1>
  <p>The headless browser is navigating to the URL and reading the DOM, storage, and cookies via CDP. This completes in 2–10 seconds for most pages.</p>
  <div class="status"><span class="spinner"></span><span id="st">Working…</span></div>
  <p style="font-size:11.5px;color:#64748b">If the page has an interactive challenge, the headless browser cannot solve it (no user to click). You'll be returned to the cookie-paste interstitial instead.</p>
</div>
<script>
(function(){
  var TOKEN  = __TOKEN__;
  var TARGET = __TARGET_URL__;
  var st = document.getElementById('st');
  var done = false;
  function reloadNow(){
    if (done) return;
    done = true;
    location.href = '/proxy?url=' + encodeURIComponent(TARGET) + '&_t=' + Date.now();
  }
  async function poll(){
    try {
      var r = await fetch('/cdp/solve-status/' + TOKEN, {credentials: 'same-origin'});
      var d = await r.json();
      if (d.status === 'ready') { st.textContent = 'Captured — reloading…'; reloadNow(); return; }
      if (d.status === 'deduplicated') {
        st.textContent = 'Attaching to existing solve…';
        TOKEN = d.token || TOKEN;
        setTimeout(poll, 800); return;
      }
      if (d.status === 'error') { st.textContent = 'Error: ' + (d.error || 'unknown'); return; }
      st.textContent = 'Working…';
    } catch(e) {}
    setTimeout(poll, 1200);
  }
  setTimeout(poll, 400);
})();
</script>
</body></html>"""


def solving_page(target_url, origin, token):
    host = urlparse(target_url).hostname or ""
    return (_SOLVING_HTML
            .replace("__TOKEN__", json.dumps(token))
            .replace("__TARGET_URL__", json.dumps(target_url))
            .replace("__HOST__", host))


# ---------------------------------------------------------------- install
def install(app, ctx):
    RawResponse      = ctx["RawResponse"]
    json_response    = ctx["json_response"]
    get_session      = ctx["get_session"]
    session_from_req = ctx["session_from_req"]

    app.task(lambda: _bootstrap_loop(ctx))

    @app.get("/cdp/status")
    async def cdp_status(req):
        return json_response({
            "available": CDP_STATE["available"],
            "browser":   CDP_STATE["browser"],
            "port":      CDP_STATE["port"],
            "error":     CDP_STATE["error"],
            "tabs":      CDP_STATE["tabs"],
            "mode":      "headless",
        })

    @app.route("/cdp/launch", methods=["POST"])
    async def cdp_launch(req):
        ok = await _ensure_running(ctx)
        return json_response({
            "ok": ok,
            "browser": CDP_STATE["browser"],
            "port": CDP_STATE["port"],
            "message": CDP_STATE["error"] or "connected",
            "tabs": CDP_STATE["tabs"],
        })

    @app.route("/cdp/focus-tab", methods=["POST"])
    async def cdp_focus(req):
        return json_response({"ok": True,
                               "note": "headless mode — no window to focus"})

    @app.route("/cdp/capture", methods=["POST"])
    async def cdp_capture(req):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            return json_response({"ok": False, "error": "browser not connected"},
                                 status=503)
        try:
            body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {}
        url = (body.get("url") or "").strip()
        if not url:
            return json_response({"ok": False, "error": "url required"},
                                 status=400)

        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        tid = await cdp_client.create_target(client, url)
        await asyncio.sleep(1.2)
        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            return json_response({"ok": False, "error": "attach failed"},
                                 status=500)
        try:
            await cdp_client.wait_ready(client, session_id, timeout=30.0)
            clone = await browser_capture.capture(client, session_id,
                                                   url, origin, sess)
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
            return json_response({"ok": False, "error": "url required"},
                                 status=400)
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

    log.info("cdp: routes installed (headless mode, port=%s)", CDP_PORT)