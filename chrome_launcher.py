"""Chrome / Chromium / Brave / Edge launcher for Lynkio CDP mode."""
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.request

log = logging.getLogger("lynk.chrome")

CHROME_PATHS = {
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ],
    "linux": [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/brave-browser",
        "/snap/bin/chromium",
    ],
    "win32": [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ],
}
DEBUG_PORTS = list(range(9222, 9243))


def find_browser():
    system = platform.system().lower()
    key = {"darwin": "darwin", "linux": "linux", "windows": "win32"}.get(system, "linux")
    for candidate in CHROME_PATHS.get(key, []):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    for name in ("google-chrome", "chromium", "chromium-browser", "brave", "brave-browser", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _port_open(port, timeout=0.4):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _cdp_version(port, timeout=2.0):
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/json/version")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def detect_running():
    for port in DEBUG_PORTS:
        if not _port_open(port):
            continue
        info = _cdp_version(port)
        if info and "Browser" in info:
            return port, info
    return None


def launch(profile_dir, force_port=None):
    """Launch Chromium with container-safe, stealth-friendly flags.
    Returns (ok, port, msg, proc)."""
    existing = detect_running()
    if existing:
        port, info = existing
        return True, port, f"Reusing existing browser on :{port} ({info.get('Browser','?')})", None

    exe = find_browser()
    if not exe:
        return False, 0, "Chrome / Chromium / Brave / Edge not found. Install one to enable CDP mode.", None

    # Snap stub detection — Ubuntu/Debian apt chromium on some bases is a
    # symlink to /snap/bin/chromium. Snap does not run in Docker containers.
    try:
        if os.path.islink(exe):
            target = os.path.realpath(exe)
            if "/snap/" in target:
                return (
                    False,
                    0,
                    f"{exe} is a snap stub → {target}. "
                    f"Snap does not work in Docker. Use Debian 12 chromium "
                    f"or google-chrome-stable.",
                    None,
                )
    except Exception:
        pass

    port = force_port
    if port is None:
        for p in DEBUG_PORTS:
            if not _port_open(p):
                port = p
                break
    if port is None:
        return False, 0, "All debug ports 9222-9242 in use.", None

    os.makedirs(profile_dir, exist_ok=True)

    # HOME must exist and be writable — Chromium's crashpad handler needs it.
    home = os.environ.get("HOME") or "/tmp"
    try:
        os.makedirs(home, exist_ok=True)
    except Exception:
        home = "/tmp"
    env = dict(os.environ)
    env["HOME"] = home

    # FIX: default to VISIBLE Chrome (headless is what Cloudflare blocks).
    headless = os.environ.get("CDP_HEADLESS", "0") != "0"

    args = [
        exe,
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={profile_dir}",
        # Container-required flags
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-software-rasterizer",
        # Chrome >=111 requires this or CDP WebSocket upgrade returns 403
        "--remote-allow-origins=*",
        # Reduce noise and prevent first-run dialogs
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-translate",
        "--disable-extensions",
        "--mute-audio",
        # FIX: stealth / anti-detection flags for Cloudflare / reCAPTCHA
        "--disable-blink-features=AutomationControlled",
        "--exclude-switches=enable-automation",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation-trials",
        "--window-size=1920,1080",
        "--start-maximized",
    ]
    if headless:
        args.append("--headless=new")
    args.append("about:blank")

    kwargs = {"env": env, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if platform.system() == "Windows":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(args, **kwargs)
    except Exception as e:
        return False, 0, f"Launch failed: {e}", None

    log.info("chrome: spawned pid=%s exe=%s port=%s headless=%s", proc.pid, exe, port, headless)

    deadline = time.time() + 30.0
    last_state = "no response"
    while time.time() < deadline:
        if proc.poll() is not None:
            return (
                False,
                port,
                f"Chromium exited early (code {proc.returncode}). "
                f"Common cause: missing shared library. Run in the container:\n"
                f"  {exe} --remote-debugging-port=9222 --no-sandbox "
                f"--headless=new --user-data-dir=/tmp/x about:blank\n"
                f"to see the stderr.",
                proc,
            )
        if _port_open(port):
            info = _cdp_version(port)
            if info and "Browser" in info:
                return True, port, f"Launched {info.get('Browser','?')} on :{port}", proc
            last_state = "port open, /json/version invalid"
        else:
            last_state = "port closed"
        time.sleep(0.4)

    return (
        False,
        port,
        f"Chromium alive (pid {proc.pid}) but :{port} never opened. "
        f"Last state: {last_state}. Check docker logs.",
        proc,
    )