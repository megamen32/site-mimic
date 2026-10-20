/**
 * Contract tests for the site-mimic client against a stubbed fetchd daemon.
 *
 * The stub replaces the global fetch, so the suite needs neither a Go
 * toolchain nor a network: the daemon contract is asserted on the exact
 * payload and headers the client puts on the wire.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  SiteMimicError,
  get,
  post,
  request,
  resetDaemonSpawner,
  setDaemonSpawner,
} from "../src/index.js";
import { installStubFetch, type StubDaemon } from "./stub-fetch.js";

const DAEMON_URL = "http://127.0.0.1:30777";
const ENV_KEYS = [
  "GOHTTPD_URL",
  "GOHTTPD_TOKEN",
  "GOHTTPD_AUTOSTART",
  "GOHTTP_PROFILE",
  "GOHTTPD_BIN",
  "GOHTTPD_LOG",
  "SITE_MIMIC_DIR",
] as const;

/** Parse the payload the client sent to the daemon (the newest one by default). */
function sentPayload(stub: StubDaemon, index = -1): Record<string, unknown> {
  const calls = stub.fetchCalls();
  const call = index < 0 ? calls[calls.length + index] : calls[index];
  assert.ok(call, "the daemon saw no /fetch call");
  return JSON.parse(call.body) as Record<string, unknown>;
}

describe("site-mimic client", () => {
  let stub: StubDaemon | null = null;
  let savedEnv = new Map<string, string | undefined>();
  let scratch = "";

  beforeEach(() => {
    savedEnv = new Map(ENV_KEYS.map((key) => [key, process.env[key]]));
    // The environment is read at call time, so every test states the
    // configuration it wants instead of inheriting the developer's shell.
    process.env.GOHTTPD_URL = DAEMON_URL;
    delete process.env.GOHTTPD_TOKEN;
    delete process.env.GOHTTPD_AUTOSTART;
    delete process.env.GOHTTP_PROFILE;
    delete process.env.GOHTTPD_BIN;
    delete process.env.GOHTTPD_LOG;
    // Point the self-supervision at a directory that is not a site-mimic
    // checkout: the suite must never build or spawn a real daemon.
    scratch = mkdtempSync(join(tmpdir(), "site-mimic-client-test-"));
    process.env.SITE_MIMIC_DIR = scratch;
    resetDaemonSpawner();
  });

  afterEach(() => {
    stub?.restore();
    stub = null;
    for (const [key, value] of savedEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(scratch, { recursive: true, force: true });
    resetDaemonSpawner();
  });

  it("parses a successful reply", async () => {
    stub = installStubFetch(() => ({
      status: 200,
      body: JSON.stringify({
        status: 201,
        headers: { "Content-Type": ["application/json"], "X-Trace": ["a", "b"] },
        set_cookies: [
          { name: "sid", value: "abc", domain: "example.com", path: "/", expires: "2026-01-02T03:04:05Z" },
          { name: "", value: "nameless" },
        ],
        body: '{"ok":true}',
      }),
    }));

    const response = await get("https://example.com/api");

    assert.equal(response.statusCode, 201);
    assert.equal(response.text, '{"ok":true}');
    assert.deepEqual(response.headers["X-Trace"], ["a", "b"]);
    assert.deepEqual([...response.content], [...Buffer.from('{"ok":true}')]);
    assert.deepEqual(response.json(), { ok: true });

    const entries = response.setCookieEntries();
    assert.equal(entries.length, 2);
    assert.equal(entries[0]?.name, "sid");
    assert.equal(entries[0]?.domain, "example.com");
    assert.equal(entries[0]?.path, "/");
    // A nameless cookie cannot be acted on, so the jar drops it.
    assert.deepEqual(response.cookies, { sid: "abc" });
  });

  it("raises SiteMimicError when the daemon reports a failure", async () => {
    stub = installStubFetch(() => ({
      status: 200,
      body: JSON.stringify({ status: 0, error: "profile is required (path to a mimic profile.json)" }),
    }));

    await assert.rejects(
      () => get("https://example.com/api"),
      (err: unknown) => {
        assert.ok(err instanceof SiteMimicError);
        assert.equal(err.message, "profile is required (path to a mimic profile.json)");
        return true;
      },
    );
  });

  it("sends binary bodies as base64", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    const bytes = new Uint8Array([0, 255, 98, 105, 110]);
    await request("POST", "https://example.com/upload", { data: bytes });

    const payload = sentPayload(stub);
    assert.equal(payload.body_b64, Buffer.from(bytes).toString("base64"));
    assert.equal("body" in payload, false);
  });

  it("forwards cookies to the daemon", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/", { cookies: { session: "xyz", lang: "ru" } });

    assert.deepEqual(sentPayload(stub).cookies, { session: "xyz", lang: "ru" });
  });

  it("sends the bearer token when GOHTTPD_TOKEN is set", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));
    process.env.GOHTTPD_TOKEN = "s3cret";

    await get("https://example.com/");

    assert.equal(stub.fetchCalls()[0]?.headers.Authorization, "Bearer s3cret");
  });

  it("sends no authorization header without a token", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/");

    assert.equal("Authorization" in (stub.fetchCalls()[0]?.headers ?? {}), false);
  });

  it("sends a JSON body with a JSON content type", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await post("https://example.com/api", { json: { k: "v", u: "ю" } });

    const payload = sentPayload(stub);
    assert.equal(payload.method, "POST");
    assert.deepEqual(JSON.parse(String(payload.body)) as unknown, { k: "v", u: "ю" });
    const headers = payload.headers as Record<string, string>;
    assert.equal(headers["Content-Type"], "application/json");
  });

  it("forwards proxy and resolve", async () => {
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/", {
      proxy: "socks5://127.0.0.1:1080",
      resolve: { "example.com": "1.2.3.4" },
    });

    const payload = sentPayload(stub);
    assert.equal(payload.proxy, "socks5://127.0.0.1:1080");
    assert.deepEqual(payload.resolve, { "example.com": "1.2.3.4" });
  });

  it("talks to the daemon named by GOHTTPD_URL", async () => {
    process.env.GOHTTPD_URL = "http://127.0.0.1:9999/";
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/");

    assert.equal(stub.fetchCalls()[0]?.url, "http://127.0.0.1:9999/fetch");
  });

  it("falls back to the profile named by GOHTTP_PROFILE", async () => {
    process.env.GOHTTP_PROFILE = "/tmp/profile.json";
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/");
    assert.equal(sentPayload(stub, 0).profile, "/tmp/profile.json");

    await get("https://example.com/", { profile: "/tmp/other.json" });
    assert.equal(sentPayload(stub, 1).profile, "/tmp/other.json");
  });

  it("raises when the daemon rejects the request", async () => {
    stub = installStubFetch(() => ({
      status: 400,
      body: JSON.stringify({ error: "profile is required (path to a mimic profile.json)" }),
    }));

    await assert.rejects(
      () => get("https://example.com/"),
      (err: unknown) => {
        assert.ok(err instanceof SiteMimicError);
        assert.equal(err.status, 400);
        assert.match(err.message, /profile is required/);
        return true;
      },
    );
  });

  it("raises when the daemon cannot be reached", async () => {
    stub = installStubFetch(() => {
      throw new TypeError("fetch failed");
    });

    await assert.rejects(
      () => get("https://example.com/"),
      (err: unknown) => {
        assert.ok(err instanceof SiteMimicError);
        assert.match(err.message, /unreachable/);
        return true;
      },
    );
  });

  it("does not probe the daemon when auto-start is off", async () => {
    process.env.GOHTTPD_AUTOSTART = "0";
    stub = installStubFetch(() => ({ status: 200, body: JSON.stringify({ status: 200, body: "ok" }) }));

    await get("https://example.com/");

    assert.equal(stub.calls.length, 1);
    assert.match(stub.calls[0]?.url ?? "", /\/fetch$/);
  });

  it("probes the daemon before the call when auto-start is on", async () => {
    stub = installStubFetch((call) =>
      call.url.endsWith("/healthz")
        ? { status: 200, body: "{}" }
        : { status: 200, body: JSON.stringify({ status: 200, body: "ok" }) },
    );

    await get("https://example.com/");

    assert.match(stub.calls[0]?.url ?? "", /\/healthz$/);
    assert.match(stub.calls[1]?.url ?? "", /\/fetch$/);
  });

  it("starts the daemon and replays the request when it is dead", async () => {
    let healthy = false;
    let fetchAttempts = 0;
    let spawns = 0;
    setDaemonSpawner(async () => {
      spawns += 1;
      healthy = true;
      return true;
    });
    stub = installStubFetch((call) => {
      if (call.url.endsWith("/healthz")) {
        return { status: healthy ? 200 : 503, body: "{}" };
      }
      fetchAttempts += 1;
      if (fetchAttempts === 1) throw new TypeError("fetch failed");
      return { status: 200, body: JSON.stringify({ status: 200, body: "ok" }) };
    });

    const response = await get("https://example.com/");

    assert.equal(response.text, "ok");
    assert.equal(spawns, 1);
    assert.equal(fetchAttempts, 2);
  });

  it("raises when the daemon is dead and cannot be started", async () => {
    setDaemonSpawner(async () => false);
    stub = installStubFetch((call) => {
      if (call.url.endsWith("/healthz")) return { status: 503, body: "{}" };
      throw new TypeError("fetch failed");
    });

    await assert.rejects(
      () => get("https://example.com/"),
      (err: unknown) => {
        assert.ok(err instanceof SiteMimicError);
        assert.match(err.message, /unreachable/);
        return true;
      },
    );
  });
});
