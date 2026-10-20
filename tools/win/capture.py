"""Windows capture driver (runs on the Windows host).

Starts mitmdump (with addon.py) as an HTTP CONNECT proxy, launches a real
Chrome through it, drives the target site, lets the page settle, then stops
both and prints a per-host summary. HTTPS is decrypted by mitm using the CA
installed via trust_ca.ps1.

This captures the HTTP layer (headers, order, bodies) of a REAL browser. The
TLS ClientHello is not measured here — mitmproxy's own fingerprint is not
Chrome's. For the transport layer use the pcap path instead
(tools/ja4_from_pcap.py).

Prereqs on the host:
  pip install "mitmproxy>=12.0,<13.0" websocket-client
  trust_ca.ps1   (one-time, after mitmdump has generated ~\\.mitmproxy\\...)

Environment:
  CHROME          Chrome executable (default: the standard install path)
  MITMDUMP        mitmdump executable (default: next to the running python)
  OUT_DIR         output directory (default: %USERPROFILE%\\site-mimic-capture)
  TARGET_URL      page to open (default: https://example.com/)
  SECOND_URL      optional second page (default: derived from the first)
  PROXY_PORT      mitmdump port (default: 18080)
  DEBUG_PORT      Chrome DevTools port (default: 9222)
  HOME_SECONDS    seconds on the first page (default: 15)
  SECOND_SECONDS  seconds on the second page (default: 40)
  LINK_SELECTOR   CSS selector for the second page's link
                  (default: a[href*="/video/"])
  IGNORE_CERT_ERRORS  set to 0 to require the CA to be trusted instead of
                  running Chrome with --ignore-certificate-errors
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websocket  # noqa: E402

HERE = Path(__file__).resolve().parent
CHROME = os.environ.get(
    "CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
MITMDUMP = os.environ.get(
    "MITMDUMP", r"C:\Python312\Scripts\mitmdump.exe")
OUT_DIR = Path(os.environ.get(
    "OUT_DIR", str(Path.home() / "site-mimic-capture")))
PROFILE = OUT_DIR / "chrome_profile"
FLOWS = OUT_DIR / "flows.jsonl"
PROXY_PORT = int(os.environ.get("PROXY_PORT", "18080"))
DEBUG_PORT = int(os.environ.get("DEBUG_PORT", "9222"))
TARGET_URL = os.environ.get("TARGET_URL", "https://example.com/")
SECOND_URL = os.environ.get("SECOND_URL", "")
LINK_SELECTOR = os.environ.get("LINK_SELECTOR", 'a[href*="/video/"]')
HOME_SECONDS = int(os.environ.get("HOME_SECONDS", "15"))
SECOND_SECONDS = int(os.environ.get("SECOND_SECONDS", "40"))
IGNORE_CERT_ERRORS = os.environ.get("IGNORE_CERT_ERRORS", "1") != "0"


def http_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wait_port(port, deadline):
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def find_page_ws(deadline):
    while time.time() < deadline:
        try:
            targets = http_json(f"http://127.0.0.1:{DEBUG_PORT}/json", 2)
        except Exception:
            time.sleep(0.3)
            continue
        for t in targets:
            if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                return t["webSocketDebuggerUrl"]
        time.sleep(0.3)
    raise RuntimeError("no page target")


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self._id = 0

    def send(self, method, params=None):
        """Fire-and-forget: send a command, do not wait for the response
        (used for Page.navigate, which can be slow to acknowledge through
        a proxy and whose response we don't need)."""
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method,
                                 "params": params or {}}))

    def call(self, method, params=None, timeout=15):
        """Send a command and wait for its response (id-matched). Drains
        intervening events."""
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            self.ws.settimeout(max(0.5, end - time.time()))
            try:
                msg = json.loads(self.ws.recv())
            except Exception:
                continue
            if msg.get("id") == mid:
                return msg
        raise TimeoutError(f"no response to {method}")


def pick_link(cdp: CDP) -> str | None:
    """Grab the first matching link from the rendered DOM."""
    expr = (f"Array.from(document.querySelectorAll({json.dumps(LINK_SELECTOR)}))"
            ".map(a=>a.href)[0]||''")
    r = cdp.call("Runtime.evaluate", {
        "expression": expr,
        "returnByValue": True,
    }, timeout=10)
    try:
        return r["result"]["result"].get("value") or None
    except Exception:
        return None


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cmd", "/c", "rmdir", "/S", "/Q", str(PROFILE)],
                   capture_output=True)

    env = {**os.environ, "CAPTURE_FLOWS": str(FLOWS)}
    print(f"[mitm] starting mitmdump :{PROXY_PORT} with addon.py")
    mitm_log = open(OUT_DIR / "mitmdump.log", "wb")
    mitm = subprocess.Popen(
        [MITMDUMP, "-s", str(HERE / "addon.py"), "--listen-port", str(PROXY_PORT),
         "--set", "flow_detail=1", "--set", "termlog_verbosity=debug"],
        stdout=mitm_log, stderr=subprocess.STDOUT, env=env, cwd=str(HERE))
    chrome = None
    try:
        if not wait_port(PROXY_PORT, time.time() + 25):
            rc = mitm.poll()
            raise RuntimeError(
                f"mitmdump did not open :{PROXY_PORT} (rc={rc}); see mitmdump.log")
        if mitm.poll() is not None:
            raise RuntimeError(
                f"mitmdump exited early (rc={mitm.returncode}); see mitmdump.log")
        print("[mitm] proxy up")

        chrome_args = [
            CHROME, "--headless=new", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--window-size=1920,1080",
            "--autoplay-policy=no-user-gesture-required", "--mute-audio",
            f"--proxy-server=127.0.0.1:{PROXY_PORT}",
            f"--remote-debugging-port={DEBUG_PORT}", "--remote-allow-origins=*",
            "about:blank",
        ]
        if IGNORE_CERT_ERRORS:
            # Silent CA install into the Windows Root store is blocked by the
            # OS anti-malware policy (certutil and X509Store both fail). For
            # this dedicated, isolated, headless capture Chrome we instead
            # accept mitm's intercept cert directly. No trust-store change;
            # the flag is scoped to this throwaway profile + run only.
            chrome_args.insert(1, "--ignore-certificate-errors")
        print("[chrome] launching through proxy")
        chrome = subprocess.Popen(chrome_args, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        ws_url = find_page_ws(time.time() + 25)
        ws = websocket.create_connection(
            ws_url, timeout=5, origin=f"http://127.0.0.1:{DEBUG_PORT}")
        cdp = CDP(ws)
        cdp.call("Page.enable")

        print(f"[nav] {TARGET_URL} ({HOME_SECONDS}s)")
        cdp.send("Page.navigate", {"url": TARGET_URL})
        time.sleep(HOME_SECONDS)

        second = SECOND_URL
        if not second:
            # Best-effort: through the proxy the renderer can be slow, so a
            # CDP failure here must NOT lose the first page's capture.
            try:
                second = pick_link(cdp)
            except Exception as e:
                print(f"[nav] link eval failed ({e!r}); continuing on the first page")
                second = None
        if second:
            print(f"[nav] {second} ({SECOND_SECONDS}s)")
            cdp.send("Page.navigate", {"url": second})
            time.sleep(SECOND_SECONDS)
        else:
            print("[nav] no second page; staying longer on the first one")
            time.sleep(SECOND_SECONDS)

        try:
            ws.close()
        except Exception:
            pass
    finally:
        if chrome and chrome.poll() is None:
            chrome.terminate()
            try:
                chrome.wait(timeout=8)
            except Exception:
                chrome.kill()
        # flush mitm's buffered writes
        time.sleep(1.5)
        mitm.terminate()
        try:
            mitm.wait(timeout=8)
        except Exception:
            mitm.kill()

    summarize()


def summarize():
    if not FLOWS.exists():
        print(f"[sum] no flows file at {FLOWS}")
        return
    by_host: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    n = 0
    with FLOWS.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            n += 1
            r = json.loads(line)
            by_host[r["host"]] = by_host.get(r["host"], 0) + 1
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    print(f"\n[sum] {n} flows captured -> {FLOWS}")
    print("[sum] by category: " + ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items())))
    print("[sum] top hosts:")
    for host, c in sorted(by_host.items(), key=lambda kv: -kv[1])[:15]:
        print(f"  {c:3} {host}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
