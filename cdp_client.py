"""Minimal Chrome DevTools Protocol client for Lynkio (flatten=True mode)."""
import asyncio
import json
import logging
import time
import urllib.request

import websockets

log = logging.getLogger("lynk.cdp")


class CDPError(Exception):
    pass


class CDPClient:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self._ws = None
        self._next_id = 0
        self._pending = {}
        self._event_handlers = []
        self._reader_task = None
        self._closed = False

    async def connect(self):
        self._ws = await websockets.connect(self.ws_url, max_size=64 * 1024 * 1024)
        self._reader_task = asyncio.create_task(self._reader())

    async def close(self):
        self._closed = True
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass

    async def _reader(self):
        try:
            async for msg in self._ws:
                try:
                    data = json.loads(msg)
                except json.JSONDecodeError:
                    continue
                mid = data.get("id")
                if mid is not None and mid in self._pending:
                    fut = self._pending.pop(mid)
                    if not fut.done():
                        if "error" in data:
                            fut.set_exception(CDPError(data["error"].get("message", "cdp error")))
                        else:
                            fut.set_result(data.get("result", {}))
                elif "method" in data:
                    for method, handler in list(self._event_handlers):
                        if method == data["method"]:
                            try:
                                await handler(data.get("params", {}), data.get("sessionId"))
                            except Exception:
                                pass
        except Exception as e:
            log.debug("cdp reader ended: %s", e)
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(CDPError("connection closed"))
            self._pending.clear()

    def on(self, method, handler):
        self._event_handlers.append((method, handler))

    def off(self, method, handler):
        self._event_handlers = [
            (m, h) for m, h in self._event_handlers
            if not (m == method and h is handler)
        ]

    async def send(self, method, params=None, session_id=None):
        if self._closed:
            raise CDPError("client closed")
        self._next_id += 1
        mid = self._next_id
        msg = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        fut = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        await self._ws.send(json.dumps(msg))
        return await asyncio.wait_for(fut, timeout=60.0)


def _http_json(url, timeout=2.0):
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def probe(port):
    return _http_json(f"http://127.0.0.1:{port}/json/version")


async def connect_browser(port):
    info = probe(port)
    if not info or "webSocketDebuggerUrl" not in info:
        return None
    client = CDPClient(info["webSocketDebuggerUrl"])
    await client.connect()
    return client


async def attach(client, target_id):
    try:
        res = await client.send("Target.attachToTarget",
                                {"targetId": target_id, "flatten": True})
        return res.get("sessionId")
    except CDPError as e:
        log.warning("attach %s failed: %s", target_id[:8], e)
        return None


async def get_targets(client):
    res = await client.send("Target.getTargets")
    return [
        {"targetId": t.get("targetId"), "type": t.get("type"),
         "url": t.get("url", ""), "title": t.get("title", "")}
        for t in res.get("targetInfos", [])
        if t.get("type") == "page"
    ]


async def create_target(client, url):
    res = await client.send("Target.createTarget", {"url": url})
    return res.get("targetId")


async def activate_target(client, target_id):
    try:
        await client.send("Target.activateTarget", {"targetId": target_id})
        return True
    except CDPError:
        return False


async def navigate(client, session, url):
    try:
        await client.send("Page.enable", session_id=session)
    except CDPError:
        pass
    return await client.send("Page.navigate", {"url": url}, session_id=session)


async def wait_ready(client, session, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            state = await client.send(
                "Runtime.evaluate",
                {"expression": "document.readyState", "returnByValue": True},
                session_id=session)
            if state.get("result", {}).get("value") == "complete":
                return True
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return False


async def evaluate(client, session, js, await_promise=True, return_by_value=True, timeout=60.0):
    res = await client.send("Runtime.evaluate", {
        "expression": js,
        "awaitPromise": await_promise,
        "returnByValue": return_by_value,
    }, session_id=session)
    if "exceptionDetails" in res:
        raise CDPError(str(res["exceptionDetails"].get("text", "JS exception")))
    return res.get("result", {}).get("value")


async def get_html(client, session):
    try:
        await client.send("DOM.enable", session_id=session)
    except CDPError:
        pass
    doc = await client.send("DOM.getDocument", {"depth": -1}, session_id=session)
    root_id = doc["root"]["nodeId"]
    outer = await client.send("DOM.getOuterHTML", {"nodeId": root_id}, session_id=session)
    return outer.get("outerHTML", "")


async def get_cookies(client, session):
    try:
        await client.send("Network.enable", session_id=session)
    except CDPError:
        pass
    try:
        res = await client.send("Network.getAllCookies", session_id=session)
        return res.get("cookies", [])
    except CDPError:
        try:
            res = await client.send("Storage.getCookies", session_id=session)
            return res.get("cookies", [])
        except CDPError:
            return []


async def get_storage(client, session, origin, kind):
    try:
        await client.send("DOMStorage.enable", session_id=session)
    except CDPError:
        pass
    res = await client.send("DOMStorage.getDOMStorageItems", {
        "storageId": {
            "securityOrigin": origin,
            "isLocalStorage": kind == "localStorage",
        }
    }, session_id=session)
    out = {}
    for item in res.get("entries", []):
        if isinstance(item, list) and len(item) == 2:
            out[item[0]] = item[1]
    return out
