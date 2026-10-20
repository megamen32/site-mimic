/**
 * Tests for the daemon plumbing: where the client thinks the daemon is,
 * how it authenticates and how it supervises the daemon.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  autoStartEnabled,
  daemonBinary,
  daemonUrl,
  ensureDaemon,
  healthz,
  resetDaemonSpawner,
  setDaemonSpawner,
} from "../src/index.js";
import { installStubFetch, type StubDaemon } from "./stub-fetch.js";

const ENV_KEYS = [
  "GOHTTPD_URL",
  "GOHTTPD_TOKEN",
  "GOHTTPD_AUTOSTART",
  "GOHTTP_PROFILE",
  "GOHTTPD_BIN",
  "GOHTTPD_LOG",
  "SITE_MIMIC_DIR",
] as const;

describe("daemon plumbing", () => {
  let stub: StubDaemon | null = null;
  let savedEnv = new Map<string, string | undefined>();
  let scratch = "";

  beforeEach(() => {
    savedEnv = new Map(ENV_KEYS.map((key) => [key, process.env[key]]));
    delete process.env.GOHTTPD_URL;
    delete process.env.GOHTTPD_TOKEN;
    delete process.env.GOHTTPD_AUTOSTART;
    delete process.env.GOHTTPD_BIN;
    // The suite must never build or spawn a real daemon.
    scratch = mkdtempSync(join(tmpdir(), "site-mimic-daemon-test-"));
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

  it("defaults the daemon URL and strips a trailing slash", () => {
    assert.equal(daemonUrl(), "http://127.0.0.1:30777");
    process.env.GOHTTPD_URL = "http://10.0.0.5:9000/";
    assert.equal(daemonUrl(), "http://10.0.0.5:9000");
  });

  it("reads the auto-start switch from the environment", () => {
    assert.equal(autoStartEnabled(), true);
    process.env.GOHTTPD_AUTOSTART = "0";
    assert.equal(autoStartEnabled(), false);
    process.env.GOHTTPD_AUTOSTART = "off";
    assert.equal(autoStartEnabled(), false);
    process.env.GOHTTPD_AUTOSTART = "1";
    assert.equal(autoStartEnabled(), true);
  });

  it("never falls back to a build when GOHTTPD_BIN is set", () => {
    const binary = join(scratch, "fetchd");
    writeFileSync(binary, "");

    process.env.GOHTTPD_BIN = binary;
    assert.equal(daemonBinary(), binary);

    // A configured binary that is not there is a misconfiguration: guessing
    // another one would run a daemon the operator did not ask for.
    process.env.GOHTTPD_BIN = join(scratch, "missing");
    assert.equal(daemonBinary(), undefined);
  });

  it("does not build a daemon outside a site-mimic checkout", () => {
    assert.equal(daemonBinary(), undefined);
  });

  it("reports the daemon as alive only when /healthz answers 200", async () => {
    stub = installStubFetch(() => ({ status: 200, body: "{}" }));
    assert.equal(await healthz(), true);

    stub.restore();
    stub = installStubFetch(() => ({ status: 503, body: "{}" }));
    assert.equal(await healthz(), false);

    stub.restore();
    stub = installStubFetch(() => {
      throw new TypeError("fetch failed");
    });
    assert.equal(await healthz(), false);
  });

  it("does not start the daemon while it is healthy", async () => {
    let spawns = 0;
    setDaemonSpawner(async () => {
      spawns += 1;
      return true;
    });
    stub = installStubFetch(() => ({ status: 200, body: "{}" }));

    assert.equal(await ensureDaemon(), true);
    assert.equal(spawns, 0);
  });

  it("starts the daemon once and shares the attempt between callers", async () => {
    let spawns = 0;
    setDaemonSpawner(async () => {
      spawns += 1;
      return true;
    });
    stub = installStubFetch(() => ({ status: 503, body: "{}" }));

    const results = await Promise.all([ensureDaemon(), ensureDaemon(), ensureDaemon()]);

    assert.deepEqual(results, [true, true, true]);
    assert.equal(spawns, 1);
  });
});
