"""pytest suite for site_mimic_client.gohttp against a stub fetchd daemon.

The stub implements the real daemon's HTTP surface (GET /healthz, POST /fetch)
on an ephemeral loopback port; no Go toolchain and no real network needed.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import site_mimic_client.gohttp as gohttp
from site_mimic_client.gohttp import GoHTTPDError

# A port with no listener on it, used to exercise the dead-daemon paths
# without spawning anything.
DEAD_DAEMON_URL = "http://127.0.0.1:1"

DEFAULT_REPLY = {
    "status": 200,
    "headers": {"Content-Type": "text/plain; charset=utf-8"},
    "set_cookies": [
        {"name": "sid", "value": "abc", "path": "/"},
        {"name": "", "value": "skipped"},  # nameless entries must be dropped
    ],
    "body": "hello",
}


class _StubFetchdHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep pytest output clean
        pass

    def _reply(self, status: int, payload: dict | None = None):
        body = json.dumps(payload or {}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/fetch":
            self._reply(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        self.server.requests.append({"headers": dict(self.headers), "payload": payload})
        if self.server.fetch_http_status:
            self._reply(self.server.fetch_http_status, {"error": "stub daemon error"})
            return
        self._reply(200, self.server.reply)


@pytest.fixture()
def stub_daemon(monkeypatch):
    """Run a stub fetchd; point GOHTTPD_URL at it; expose captured requests."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubFetchdHandler)
    server.requests = []
    server.reply = dict(DEFAULT_REPLY)
    server.fetch_http_status = 0  # non-zero => /fetch answers with this HTTP status
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("GOHTTPD_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.delenv("GOHTTPD_TOKEN", raising=False)
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def last_fetch(server) -> dict:
    assert server.requests, "stub daemon saw no /fetch call"
    return server.requests[-1]


# --- configuration ---------------------------------------------------------


def test_daemon_url_default_is_30777(monkeypatch):
    monkeypatch.delenv("GOHTTPD_URL", raising=False)
    assert gohttp._daemon_url() == "http://127.0.0.1:30777"


def test_daemon_url_env_override_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("GOHTTPD_URL", "http://10.0.0.5:9000/")
    assert gohttp._daemon_url() == "http://10.0.0.5:9000"


def test_daemon_binary_prefers_existing_env_path(monkeypatch, tmp_path):
    binary = tmp_path / "fetchd-custom"
    binary.write_bytes(b"#!/bin/sh\n")
    monkeypatch.setenv("GOHTTPD_BIN", str(binary))
    assert gohttp._daemon_binary() == binary


def test_daemon_binary_reuses_built_checkout_binary(monkeypatch, tmp_path):
    monkeypatch.delenv("GOHTTPD_BIN", raising=False)
    monkeypatch.setenv("SITE_MIMIC_DIR", str(tmp_path))
    built = tmp_path / "fetchd"
    built.write_bytes(b"")  # already built -> no `go build` subprocess
    assert gohttp._daemon_binary() == built


# --- request round-trip ----------------------------------------------------


def test_get_round_trip_and_captured_contract(stub_daemon):
    resp = gohttp.get(
        "https://example.com/page",
        headers={"X-A": "1"},
        cookies={"session": "xyz"},
        profile="examples/profiles/linux-chrome152.json",
        timeout=12.5,
    )
    assert resp.status_code == 200 and resp.ok
    assert resp.text == "hello"
    assert resp.headers["Content-Type"].startswith("text/plain")

    captured = last_fetch(stub_daemon)["payload"]
    assert captured["method"] == "GET"
    assert captured["url"] == "https://example.com/page"
    assert captured["profile"] == "examples/profiles/linux-chrome152.json"
    assert captured["headers"] == {"X-A": "1"}
    assert captured["cookies"] == {"session": "xyz"}
    assert captured["timeout_s"] == 12.5


def test_post_json_sets_content_type_and_body(stub_daemon):
    resp = gohttp.post("https://example.com/api", json={"k": "v", "u": "ю"})
    assert resp.ok
    captured = last_fetch(stub_daemon)["payload"]
    assert captured["method"] == "POST"
    assert json.loads(captured["body"]) == {"k": "v", "u": "ю"}
    assert captured["headers"]["Content-Type"] == "application/json"


def test_data_bytes_travel_as_body_b64(stub_daemon):
    gohttp.request("POST", "https://example.com/up", data=b"\x00\xffbin")
    captured = last_fetch(stub_daemon)["payload"]
    assert base64.b64decode(captured["body_b64"]) == b"\x00\xffbin"
    assert "body" not in captured


def test_proxy_and_resolve_forwarded(stub_daemon):
    gohttp.get("https://example.com/", proxy="socks5://127.0.0.1:1080", resolve={"example.com": "1.2.3.4"})
    captured = last_fetch(stub_daemon)["payload"]
    assert captured["proxy"] == "socks5://127.0.0.1:1080"
    assert captured["resolve"] == {"example.com": "1.2.3.4"}


def test_bearer_token_forwarded_to_daemon(stub_daemon, monkeypatch):
    monkeypatch.setenv("GOHTTPD_TOKEN", "s3cret")
    gohttp.get("https://example.com/")
    headers = last_fetch(stub_daemon)["headers"]
    assert headers.get("Authorization") == "Bearer s3cret"


def test_no_authorization_header_without_token(stub_daemon):
    gohttp.get("https://example.com/")
    assert "Authorization" not in last_fetch(stub_daemon)["headers"]


# --- Response wrapper ------------------------------------------------------


def test_response_decodes_body_b64(stub_daemon):
    stub_daemon.reply = {"status": 200, "body_b64": base64.b64encode("привёт".encode()).decode()}
    resp = gohttp.get("https://example.com/")
    assert resp.content == "привёт".encode()
    assert resp.text == "привёт"


def test_response_json_helper(stub_daemon):
    stub_daemon.reply = {"status": 200, "body": '{"n": 42}'}
    assert gohttp.get("https://example.com/").json() == {"n": 42}


def test_response_cookies_helpers(stub_daemon):
    resp = gohttp.get("https://example.com/")
    assert resp.cookies == {"sid": "abc"}  # nameless entry dropped
    entries = resp.set_cookie_entries()
    assert entries[0]["name"] == "sid" and entries[0]["path"] == "/"


def test_raise_for_status_raises_on_4xx_with_context(stub_daemon):
    stub_daemon.reply = {"status": 404, "body": "nope"}
    resp = gohttp.get("https://example.com/missing")
    assert not resp.ok
    with pytest.raises(GoHTTPDError, match="404.*missing.*nope"):
        resp.raise_for_status()


# --- self-supervision ------------------------------------------------------


def test_ensure_daemon_short_circuits_when_healthy(stub_daemon, monkeypatch):
    def _fail(*a, **k):
        raise AssertionError("spawn must not run when /healthz answers")

    monkeypatch.setattr(gohttp, "_spawn_daemon", _fail)
    assert gohttp.ensure_daemon() is True


def test_ensure_daemon_spawns_once_when_dead(monkeypatch):
    monkeypatch.setenv("GOHTTPD_URL", DEAD_DAEMON_URL)
    calls = []

    def _fake_spawn():
        calls.append(1)
        return True

    monkeypatch.setattr(gohttp, "_spawn_daemon", _fake_spawn)
    assert gohttp.ensure_daemon() is True
    assert calls == [1]


def test_request_raises_when_daemon_unreachable_and_spawn_fails(monkeypatch):
    monkeypatch.setenv("GOHTTPD_URL", DEAD_DAEMON_URL)
    monkeypatch.setattr(gohttp, "ensure_daemon", lambda: False)
    with pytest.raises(GoHTTPDError, match="unreachable"):
        gohttp.get("https://example.com/")


def test_daemon_http_error_surfaces(stub_daemon):
    stub_daemon.fetch_http_status = 500
    with pytest.raises(GoHTTPDError, match="gohttpd 500"):
        gohttp.get("https://example.com/")
