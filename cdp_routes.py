"""
CDP routes and background bootstrap for Lynkio.
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
CDP_PORT = int(os.environ.get("CDP_PORT", "9222"))
CHROME_BIN = os.environ.get(
    "CHROME_BIN",
    os.environ.get("OBSCURA_BIN", "/headless-shell/headless-shell"),
)
# FIX: default to VISIBLE Chrome. Headless is what Cloudflare / reCAPTCHA block.
HEADLESS = os.environ.get("CDP_HEADLESS", "0") == "1"
PROBE_INTERVAL = 5.0
SPAWN_RETRY_SEC = 20.0

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
_SOLVE_INFLIGHT = {}


def _choose_impersonate(major):
    candidates = [(136, "chrome136"), (131, "chrome131"), (124, "chrome124"),
                  (120, "chrome120"), (116, "chrome116"), (110, "chrome110")]
    for threshold, profile in candidates:
        if major >= threshold:
            return profile
    return "chrome124"


# ---------------------------------------------------------- spawn shell
def _spawn_shell():
    """Launch the browser as a background child of brow.py."""
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
        # FIX: stealth / anti-detection flags
        "--disable-blink-features=AutomationControlled",
        "--exclude-switches=enable-automation",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation-trials",
        "--window-size=1920,1080",
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
            log.info("cdp: spawned pid=%s exe=%s port=%s", proc.pid, CHROME_BIN, CDP_PORT)
            return True
        if proc.poll() is not None:
            CDP_STATE["error"] = f"browser exited early (code {proc.returncode})"
            log.warning("cdp: %s", CDP_STATE["error"])
            return False
        time.sleep(0.4)

    CDP_STATE["error"] = f"browser didn't answer CDP on :{CDP_PORT} within {SPAWN_RETRY_SEC}s"
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

    CDP_STATE["client"] = client
    CDP_STATE["available"] = True
    CDP_STATE["error"] = ""

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
    log.info("cdp: connected on :%s — %s", CDP_PORT, CDP_STATE["browser"] or "headless")
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

            # FIX: DO NOT close the client when a probe fails.
            # The original code did `await client.close()` here, which killed
            # the WebSocket and aborted any in-flight navigation / XHR /
            # challenge request. That is why the page "closed" when the
            # user closed a tab or the app.
            if not CDP_STATE["available"]:
                if (time.time() - CDP_STATE["last_spawn_attempt"]) > SPAWN_RETRY_SEC:
                    log.info("cdp: reconnecting…")
                    await _ensure_running(ctx)
            # When available, leave the client and all tabs alone.
        except Exception as e:
            log.debug("cdp: bootstrap loop error: %s", e)


def is_available():
    return bool(CDP_STATE.get("available") and CDP_STATE.get("client"))


# ------------------------------------------------------- solve / capture
async def _solve_async(token, target_url, origin, sid, ctx):
    """Open URL in real Chrome, wait for network idle, capture DOM+state.
    Deduplicates concurrent solves for the same URL.
    Keeps the tab open so ongoing requests can finish.
    """
    existing = _SOLVE_INFLIGHT.get(target_url)
    if existing and existing != token:
        prior = _SOLVES.get(existing)
        if prior and prior.get("status") == "pending":
            _SOLVES[token] = {"status": "deduplicated", "token": existing}
            log.debug("cdp: solve %s deduplicated to %s", token[:8], existing[:8])
            return

    _SOLVE_INFLIGHT[target_url] = token
    try:
        get_session = ctx["get_session"]
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            _SOLVES[token] = {"status": "error", "error": "browser not connected"}
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
        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            _SOLVES[token] = {"status": "error", "error": "attach failed"}
            return

        await cdp_client.navigate(client, session_id, target_url)

        # FIX: timeouts raised from 30s / 20s to 90s / 90s.
        await cdp_client.wait_ready(client, session_id, timeout=90.0)
        await browser_capture.wait_challenge_cleared(client, session_id, origin, timeout=90.0)

        clone = await browser_capture.capture(client, session_id, target_url, origin, sess)
        sess.cdp_captures[target_url] = clone["outer_html"]
        _SOLVES[token] = {"status": "ready", "uuid": clone["uuid"]}
        log.info("cdp: capture %s ready (uuid=%s)", token[:8], clone["uuid"])

        # FIX: do not close the tab. Ongoing XHR / WebSocket / challenge
        # requests must be allowed to finish.
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


_SOLVING_HTML = """
<html><head><meta charset="utf-8"><title>Capturing via headless browser · __HOST__</title></head>
<body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:2rem">
<h1>Capturing __HOST__ in browser…</h1>
<p>The browser is navigating to the URL and reading the DOM, storage, and cookies via CDP.</p>
<p>Working…</p>
</body></html>
"""


def solving_page(target_url, origin, token):
    host = urlparse(target_url).hostname or ""
    return _SOLVING_HTML.replace("__TOKEN__", json.dumps(token)).replace(
        "__TARGET_URL__", json.dumps(target_url)
    ).replace("__HOST__", host)


# ---------------------------------------------------------------- install
def install(app, ctx):
    RawResponse = ctx["RawResponse"]
    json_response = ctx["json_response"]
    get_session = ctx["get_session"]
    session_from_req = ctx["session_from_req"]

    app.task(lambda: _bootstrap_loop(ctx))

    @app.get("/cdp/status")
    async def cdp_status(req):
        return json_response({
            "available": CDP_STATE["available"],
            "browser": CDP_STATE["browser"],
            "port": CDP_STATE["port"],
            "error": CDP_STATE["error"],
            "tabs": CDP_STATE["tabs"],
            "mode": "headless" if HEADLESS else "visible",
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
        return json_response({
            "ok": True,
            "note": "visible mode — use the Chrome window directly" if not HEADLESS else "headless mode — no window to focus",
        })

    @app.route("/cdp/capture", methods=["POST"])
    async def cdp_capture(req):
        sid, _ = session_from_req(req)
        sess = get_session(sid)
        client = CDP_STATE.get("client")
        if not client:
            return json_response({"ok": False, "error": "browser not connected"}, status=503)

        try:
            body = json.loads((req.body or b"{}").decode("utf-8", "replace"))
        except json.JSONDecodeError:
            body = {}

        url = (body.get("url") or "").strip()
        if not url:
            return json_response({"ok": False, "error": "url required"}, status=400)

        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        tid = await cdp_client.create_target(client, url)
        await asyncio.sleep(1.2)
        session_id = await cdp_client.attach(client, tid)
        if not session_id:
            return json_response({"ok": False, "error": "attach failed"}, status=500)

        try:
            # FIX: timeout raised from 30s to 90s.
            await cdp_client.wait_ready(client, session_id, timeout=90.0)
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

    log.info("cdp: routes installed (%s mode, port=%s)",
             "headless" if HEADLESS else "visible", CDP_PORT)