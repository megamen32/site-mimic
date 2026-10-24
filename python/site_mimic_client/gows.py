"""Minimal WebSocket client that routes frames through the wsd daemon.

CANONICAL COPY lives in this repo (site-mimic/python/site_mimic_client/gows.py),
right next to the Go daemon it drives (cmd/wsd). Consumer repos install it as
a git dependency pinned to a tag — there is no file copy to drift:

    pip install "git+https://github.com/megamen32/site-mimic.git@python-vX.Y.Z#subdirectory=python"

To change this file: edit it HERE, bump `version` in python/pyproject.toml,
tag the commit, and re-pin the tag in the consumer. Never patch an installed
copy — the next reinstall silently reverts it.

Why: MAX's WebSocket edge fingerprints the TLS ClientHello and the upgrade
request; the stock Python clients present a Python TLS stack, and a
fingerprint mismatch is one of the ways a scanner gets its accounts flagged.
The wire behaviour has one source of truth: the wsd daemon (mimic.DialWebSocket
underneath, the same uTLS ClientHello as the profile's HTTP client).

Usage:

    from site_mimic_client import gows

    ws = gows.connect(
        "wss://api.oneme.ru/websocket",
        profile="/path/to/profile.json",
        headers={"Origin": "https://web.max.ru"},
    )
    ws.send(b"\x12\x34", opcode="binary")
    msg = ws.recv(timeout_s=30)   # {"opcode","data_b64","closed"} dict
    ws.close()
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

_DAEMON_SPAWN_LOCK = None  # created lazily


def daemon_url() -> str:
    """Return the wsd base URL from the environment."""
    return os.environ.get("WSD_URL", "http://127.0.0.1:30778").rstrip("/")


def _site_mimic_dir() -> Path:
    """Return the site-mimic checkout used to build/spawn wsd.

    Resolution order: SITE_MIMIC_DIR, a checkout this module runs from
    (walk up until cmd/wsd appears), then ~/site-mimic.
    """
    env_dir = os.environ.get("SITE_MIMIC_DIR")
    if env_dir:
        return Path(env_dir)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "cmd" / "wsd").is_dir():
            return parent
    return Path.home() / "site-mimic"


def _daemon_binary() -> Path:
    """Return a usable wsd binary path, building it from source if missing."""
    env_bin = os.environ.get("WSD_BIN")
    if env_bin and Path(env_bin).exists():
        return Path(env_bin)
    site = _site_mimic_dir()
    built = site / "wsd"
    if not built.exists():
        logger.info("gows: building wsd from %s", site)
        subprocess.run(
            ["go", "build", "-o", str(built), "./cmd/wsd"],
            cwd=site,
            check=True,
            timeout=180,
            capture_output=True,
        )
    return built


def _healthz_once(timeout: float = 1.5) -> bool:
    """Return whether the daemon answers /health right now."""
    try:
        with _opener.open(daemon_url() + "/health", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _spawn_daemon() -> bool:
    """Spawn wsd detached; return whether /health comes up within ~8s."""
    try:
        binary = _daemon_binary()
        log_path = Path(os.environ.get("WSD_LOG", "/tmp/wsd.log"))
        log_handle = open(log_path, "ab")
        subprocess.Popen(
            [str(binary)],
            stdout=log_handle,
            stderr=log_handle,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        logger.exception("gows: failed to spawn wsd")
        return False
    for _ in range(16):  # ~8s
        if _healthz_once():
            logger.info("gows: wsd spawned and healthy")
            return True
        time.sleep(0.5)
    return False


def ensure_daemon() -> bool:
    """Ensure the wsd daemon is running; start it when it is not.

    Idempotent and safe to call concurrently from several processes: the
    loser of the port race simply finds /health answering.
    """
    global _DAEMON_SPAWN_LOCK
    import threading

    if _DAEMON_SPAWN_LOCK is None:
        _DAEMON_SPAWN_LOCK = threading.Lock()
    with _DAEMON_SPAWN_LOCK:
        if _healthz_once():
            return True
        return _spawn_daemon()


class WsdError(RuntimeError):
    """Raised when the wsd daemon is unreachable or the dial fails."""


def _daemon_json(
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> tuple[int, dict[str, Any]]:
    """One daemon call; ensures the daemon is up and retries once."""
    req = urllib.request.Request(
        daemon_url() + path,
        data=body,
        method=method,
    )
    token = os.environ.get("WSD_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    if not _healthz_once():
        ensure_daemon()
    try:
        with _opener.open(req, timeout=timeout + 15) as resp:
            return resp.status, _json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        with contextlib.suppress(Exception):
            detail = exc.read().decode("utf-8", "replace")[:300]
        raise WsdError(f"wsd {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        logger.warning("gows: daemon call failed (%s); attempting restart", exc)
        if not ensure_daemon():
            raise WsdError(
                f"wsd unreachable at {daemon_url()} and could not be started"
            ) from exc
        with _opener.open(req, timeout=timeout + 15) as resp:
            return resp.status, _json.loads(resp.read().decode("utf-8"))


def connect(
    url: str,
    *,
    profile: str,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    resolve: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> "WsConnection":
    """Open a WebSocket through the daemon.

    ``profile`` is the path to a site-mimic profile.json that selects the
    transport identity. Raises WsdError when the upstream refuses the
    handshake.
    """
    payload: dict[str, Any] = {"url": url, "profile": profile, "timeout_s": timeout_s}
    if headers:
        payload["headers"] = {str(k): str(v) for k, v in headers.items()}
    if proxy:
        payload["proxy"] = proxy
    if resolve:
        payload["resolve"] = {str(k): str(v) for k, v in resolve.items()}

    status, out = _daemon_json(
        "POST", "/dial", body=_json.dumps(payload).encode("utf-8"), timeout=timeout_s
    )
    if status != 200:
        raise WsdError(f"dial {url}: {out.get('error', status)}")
    return WsConnection(int(out["conn_id"]), url)


class WsConnection:
    """One daemon-side WebSocket: send raw bytes, recv decoded dicts."""

    def __init__(self, conn_id: int, url: str):
        self.conn_id = conn_id
        self.url = url

    def send(self, data: bytes | str, *, opcode: str = "binary") -> int:
        """Send one message; returns the byte count the daemon wrote."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        status, out = _daemon_json(
            "POST",
            f"/conn/{self.conn_id}/send?opcode={opcode}",
            body=payload,
            timeout=DEFAULT_TIMEOUT_S,
        )
        if status != 200:
            raise WsdError(f"send: {out.get('error', status)}")
        return int(out.get("sent", len(payload)))

    def recv(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
        """Wait for one message.

        Returns {"opcode": "binary"|"text", "data_b64": str, "closed": False};
        on idle {"timeout": True}; after close {"closed": True, "code", ...}.
        Raises WsdError on daemon/transport trouble.
        """
        status, out = _daemon_json(
            "GET",
            f"/conn/{self.conn_id}/recv?timeout_s={timeout_s}",
            timeout=timeout_s,
        )
        if status != 200:
            raise WsdError(f"recv: {out.get('error', status)}")
        return out

    def recv_bytes(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> bytes | None:
        """recv() that returns raw bytes; None on idle, raises on close.

        The convenience shape for a scanner loop.
        """
        out = self.recv(timeout_s=timeout_s)
        if out.get("closed"):
            raise WsdError(f"connection closed: {out}")
        if out.get("timeout"):
            return None
        return base64.b64decode(out["data_b64"])

    def close(self, code: int = 1000) -> None:
        """Close the connection gracefully and free daemon-side state."""
        try:
            _daemon_json("DELETE", f"/conn/{self.conn_id}?code={code}")
        except WsdError:
            logger.warning("gows: close of #%d failed", self.conn_id)
