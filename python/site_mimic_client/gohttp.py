"""Minimal requests/httpx-style drop-in that routes HTTP through fetchd.

CANONICAL COPY lives in this repo (site-mimic/python/site_mimic_client/gohttp.py),
right next to the Go daemon it drives (cmd/fetchd). Mirrors in consumer
repos are byte-copies produced by python/sync_to.sh; edit HERE, never in
the mirror.

Why: some CDN edges reject the stock Python TLS fingerprint while the
Go uTLS transport (mimic, Chrome ClientHello) passes. This module is the
single Python entry point for site HTTP so the wire behaviour has one
source of truth: the fetchd daemon.

Usage (drop-in for the common requests calls):

    import shared.gohttp as gohttp

    resp = gohttp.get("https://example.com/api/...", headers={...}, cookies={...})
    resp.raise_for_status()
    data = resp.json()

    resp = gohttp.post(url, json={"refresh_token": rt}, cookies=jar, proxy=proxy)

Config (env): GOHTTPD_URL (default http://127.0.0.1:8899) and GOHTTPD_TOKEN
when the daemon requires a bearer. Async callers: wrap calls in
asyncio.to_thread, like the rest of the server runtime does.
"""
from __future__ import annotations

import base64
import contextlib
import json as _json
import logging
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 30.0

# The daemon is trusted local infra: never route daemon calls through
# environment proxies (http_proxy env vars would break loopback access).
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_DAEMON_SPAWN_LOCK = None  # created lazily inside the event loop-free helper


def _daemon_url() -> str:
    """Return the gohttpd/fetchd base URL from the environment."""
    return os.environ.get("GOHTTPD_URL", "http://127.0.0.1:30777").rstrip("/")


def _site_mimic_dir() -> Path:
    """Return the site-mimic checkout used to build/spawn fetchd."""
    return Path(os.environ.get("SITE_MIMIC_DIR", str(Path.home() / "PycharmProjects" / "site-mimic")))


def _daemon_binary() -> Path:
    """Return a usable fetchd binary path, building it from source if missing."""
    env_bin = os.environ.get("GOHTTPD_BIN")
    if env_bin and Path(env_bin).exists():
        return Path(env_bin)
    site = _site_mimic_dir()
    built = site / "fetchd"
    if not built.exists():
        logger.info("gohttp: building fetchd from %s", site)
        subprocess.run(
            ["go", "build", "-o", str(built), "./cmd/fetchd"],
            cwd=site,
            check=True,
            timeout=180,
            capture_output=True,
        )
    return built


def _healthz_once(timeout: float = 1.5) -> bool:
    """Return whether the daemon answers /healthz right now."""
    try:
        with _opener.open(_daemon_url() + "/healthz", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _spawn_daemon() -> bool:
    """Spawn fetchd detached; return whether /healthz comes up within ~8s."""
    try:
        binary = _daemon_binary()
        log_path = Path(os.environ.get("GOHTTPD_LOG", "/tmp/fetchd.log"))
        log_handle = open(log_path, "ab")
        subprocess.Popen(
            [str(binary)],
            stdout=log_handle,
            stderr=log_handle,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        logger.exception("gohttp: failed to spawn fetchd")
        return False
    deadline = os.path.join(os.environ.get("GOHTTPD_LOG_DIR", "/tmp"), ".gohttp-wait")
    _ = deadline  # spawn is asynchronous; poll health below
    for _ in range(16):  # ~8s
        if _healthz_once():
            logger.info("gohttp: fetchd spawned and healthy")
            return True
        time.sleep(0.5)
    return False


def ensure_daemon() -> bool:
    """Ensure the fetchd daemon is running; start it when it is not.

    Idempotent and safe to call concurrently from several processes: the
    loser of the port race simply finds /healthz answering.
    """
    global _DAEMON_SPAWN_LOCK
    import threading

    if _DAEMON_SPAWN_LOCK is None:
        _DAEMON_SPAWN_LOCK = threading.Lock()
    with _DAEMON_SPAWN_LOCK:
        if _healthz_once():
            return True
        return _spawn_daemon()


class GoHTTPDError(RuntimeError):
    """Raised when the gohttpd daemon is unreachable or misconfigured."""


class Response:
    """requests-flavoured response wrapper over a gohttpd /fetch reply."""

    def __init__(self, payload: dict[str, Any], url: str):
        self._payload = payload
        self.url = url
        self.status_code = int(payload.get("status", 0))
        self.headers = dict(payload.get("headers") or {})
        self.error = payload.get("error") or ""
        body_b64 = payload.get("body_b64") or ""
        if body_b64:
            self.content = base64.b64decode(body_b64)
        else:
            self.content = (payload.get("body") or "").encode("utf-8", "replace")
        self._cookies: dict[str, str] | None = None

    @property
    def ok(self) -> bool:
        """Return whether the response status is 2xx."""
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        """Return the decoded body text."""
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        """Parse the body as JSON, mirroring requests' behaviour on failure."""
        return _json.loads(self.text)

    @property
    def cookies(self) -> dict[str, str]:
        """Return cookies set by the response (name → value)."""
        if self._cookies is None:
            self._cookies = {
                c["name"]: c.get("value", "")
                for c in (self._payload.get("set_cookies") or [])
                if c.get("name")
            }
        return self._cookies

    def set_cookie_entries(self) -> list[dict[str, Any]]:
        """Return full Set-Cookie entries (name/value/domain/path/expires)."""
        return list(self._payload.get("set_cookies") or [])

    def raise_for_status(self) -> "Response":
        """Raise GoHTTPDError on 4xx/5xx, mirroring requests semantics."""
        if self.status_code >= 400:
            raise GoHTTPDError(f"{self.status_code} for {self.url}: {self.text[:200]}")
        return self

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<gohttp.Response [{self.status_code}] {self.url}>"


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    json: Any | None = None,
    data: str | bytes | None = None,
    profile: str | None = None,
    proxy: str | None = None,
    resolve: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> Response:
    """Execute one HTTP request through the gohttpd/fetchd daemon.

    ``profile`` is the path to a site-mimic profile.json that selects the
    transport identity (chrome_exact is the verified QRATOR-passing one).
    """
    payload: dict[str, Any] = {
        "method": method.upper(),
        "url": url,
        "timeout_s": timeout,
    }
    if profile:
        payload["profile"] = profile
    if headers:
        payload["headers"] = {str(k): str(v) for k, v in headers.items()}
    if cookies:
        payload["cookies"] = {str(k): str(v) for k, v in cookies.items()}
    if json is not None:
        payload["headers"] = {**payload.get("headers", {}), "Content-Type": "application/json"}
        payload["body"] = _json.dumps(json, ensure_ascii=False)
    elif data is not None:
        if isinstance(data, bytes):
            payload["body_b64"] = base64.b64encode(data).decode("ascii")
        else:
            payload["body"] = str(data)
    if proxy:
        payload["proxy"] = proxy
    if resolve:
        payload["resolve"] = resolve

    daemon_req = urllib.request.Request(
        _daemon_url() + "/fetch",
        data=_json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    daemon_token = os.environ.get("GOHTTPD_TOKEN")
    if daemon_token:
        daemon_req.add_header("Authorization", f"Bearer {daemon_token}")

    # Self-supervision: make sure the daemon is up before every call, and on
    # a transient failure try to (re)start it once before giving up. Callers
    # (e.g. an impit fallback) on top.
    if not _healthz_once():
        ensure_daemon()
    try:
        with _opener.open(daemon_req, timeout=timeout + 15) as resp:
            reply = _json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        with contextlib.suppress(Exception):
            detail = exc.read().decode("utf-8", "replace")[:300]
        raise GoHTTPDError(f"gohttpd {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        logger.warning("gohttp: daemon call failed (%s); attempting restart", exc)
        if not ensure_daemon():
            raise GoHTTPDError(
                f"gohttpd unreachable at {_daemon_url()} and could not be started"
            ) from exc
        with _opener.open(daemon_req, timeout=timeout + 15) as resp:
            reply = _json.loads(resp.read().decode("utf-8"))
    return Response(reply, url)


def get(url: str, **kwargs: Any) -> Response:
    """GET via :func:`request`."""
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    """POST via :func:`request`."""
    return request("POST", url, **kwargs)
