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
    for name in ("google-chrome", "chromium", "chromium-browser",
                 "brave", "brave-browser", "chrome"):
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
    existing = detect_running()
    if existing:
        port, info = existing
        return True, port, f"Reusing existing browser on :{port} ({info.get('Browser','?')})", None

    exe = find_browser()
    if not exe:
        return False, 0, "Chrome / Chromium / Brave / Edge not found. Install one to enable CDP mode.", None

    port = force_port
    if port is None:
        for p in DEBUG_PORTS:
            if not _port_open(p):
                port = p
                break
    if port is None:
        return False, 0, "All debug ports 9222-9242 in use. Close another debug-enabled browser.", None

    os.makedirs(profile_dir, exist_ok=True)
    args = [
        exe,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank",
    ]
    kwargs = {}
    if platform.system() == "Windows":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
    except Exception as e:
        return False, 0, f"Launch failed: {e}", None

    deadline = time.time() + 20.0
    while time.time() < deadline:
        if _port_open(port):
            info = _cdp_version(port)
            if info and "Browser" in info:
                return True, port, f"Launched {info.get('Browser','?')} on :{port}", proc
        time.sleep(0.3)

    return False, port, "Browser launched but CDP didn't respond within 20s", proc
