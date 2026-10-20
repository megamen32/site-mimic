/**
 * Everything that talks to the `fetchd` daemon: its address, its
 * authorisation, the /fetch call itself and the self-supervision that
 * starts the daemon when it is not running.
 *
 * The daemon is the transport: it owns the uTLS ClientHello, so a client
 * that cannot reach it has no way to make the request itself.
 */

import { spawn, spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SiteMimicError } from "./errors.js";
import { fetchText } from "./transport.js";

/** Address of the daemon when the environment does not say otherwise. */
export const DEFAULT_DAEMON_URL = "http://127.0.0.1:30777";

/** A live daemon answers /healthz in microseconds; a dead one never does. */
const HEALTHZ_TIMEOUT_MS = 1_500;
/** A freshly spawned daemon gets this many probes before we give up on it. */
const SPAWN_POLL_ATTEMPTS = 16;
const SPAWN_POLL_INTERVAL_MS = 500;
/** `go build` of the daemon is slow on a cold cache but must not hang. */
const BUILD_TIMEOUT_MS = 180_000;
/** The daemon call gets the request timeout plus this much slack. */
const DAEMON_SLACK_S = 15;

/** The JSON body the daemon expects on POST /fetch. */
export interface FetchRequest {
  method: string;
  url: string;
  timeout_s: number;
  profile?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  body?: string;
  body_b64?: string;
  proxy?: string;
  resolve?: Record<string, string>;
}

/** One Set-Cookie entry as the daemon reports it. */
export interface SetCookieWire {
  name?: string;
  value?: string;
  domain?: string;
  path?: string;
  expires?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
}

/** The JSON body the daemon answers with. */
export interface FetchResult {
  status?: number;
  headers?: Record<string, string[]>;
  set_cookies?: SetCookieWire[];
  body?: string;
  body_b64?: string;
  error?: string;
}

/** Return the daemon base URL from the environment. */
export function daemonUrl(): string {
  const configured = process.env.GOHTTPD_URL?.trim();
  const base = configured && configured.length > 0 ? configured : DEFAULT_DAEMON_URL;
  return base.replace(/\/+$/, "");
}

/** Return the bearer token the daemon expects, when it wants one. */
export function daemonToken(): string | undefined {
  const token = process.env.GOHTTPD_TOKEN?.trim();
  return token && token.length > 0 ? token : undefined;
}

/**
 * Whether the client may start the daemon itself.
 *
 * On by default, because the daemon is the transport and a caller that
 * cannot start it cannot make the request either. `GOHTTPD_AUTOSTART=0`
 * turns it off for deployments that supervise the daemon themselves.
 */
export function autoStartEnabled(): boolean {
  const configured = process.env.GOHTTPD_AUTOSTART?.trim().toLowerCase();
  if (!configured) return true;
  return configured !== "0" && configured !== "false" && configured !== "no" && configured !== "off";
}

/**
 * Return the site-mimic checkout used to build and spawn the daemon.
 *
 * Resolution order: SITE_MIMIC_DIR, then a checkout this module runs from,
 * then ~/site-mimic. There is no machine-specific path baked in — a
 * hard-coded home directory is not a default, it breaks on the next clone.
 */
export function siteMimicDir(): string | undefined {
  const configured = process.env.SITE_MIMIC_DIR?.trim();
  if (configured) return configured;

  // Walking up only helps when the client runs straight from a checkout; an
  // installed npm copy has no repository around it, so SITE_MIMIC_DIR (or
  // GOHTTPD_BIN) is the way to point at the daemon.
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "cmd", "fetchd"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const fallback = join(homedir(), "site-mimic");
  return existsSync(fallback) ? fallback : undefined;
}

/**
 * Return the fetchd binary to spawn, building it from source when needed.
 *
 * An explicit GOHTTPD_BIN wins and is never second-guessed: falling back
 * to a build would silently run a different daemon than the operator asked
 * for. Without it the client looks for a built binary in the checkout and
 * builds one only when the checkout really is a site-mimic tree.
 */
export function daemonBinary(): string | undefined {
  const configured = process.env.GOHTTPD_BIN?.trim();
  if (configured) {
    return existsSync(configured) ? configured : undefined;
  }

  const site = siteMimicDir();
  if (!site) return undefined;

  const built = join(site, "fetchd");
  if (existsSync(built)) return built;
  if (!existsSync(join(site, "cmd", "fetchd"))) return undefined;

  const build = spawnSync("go", ["build", "-o", built, "./cmd/fetchd"], {
    cwd: site,
    stdio: "ignore",
    timeout: BUILD_TIMEOUT_MS,
  });
  if (build.error || build.status !== 0) return undefined;
  return existsSync(built) ? built : undefined;
}

/** Return whether the daemon answers /healthz right now. */
export async function healthz(timeoutMs: number = HEALTHZ_TIMEOUT_MS): Promise<boolean> {
  try {
    const reply = await fetchText(`${daemonUrl()}/healthz`, { method: "GET", headers: {} }, timeoutMs);
    return reply.status === 200;
  } catch {
    return false;
  }
}

/** How the daemon is started. Replaceable so a host can use its own supervisor. */
export type DaemonSpawner = () => Promise<boolean>;

let spawner: DaemonSpawner = spawnFetchd;

/** Replace the way the daemon is started (systemd, launchd, a container…). */
export function setDaemonSpawner(next: DaemonSpawner): void {
  spawner = next;
}

/** Restore the built-in "spawn the fetchd binary" behaviour. */
export function resetDaemonSpawner(): void {
  spawner = spawnFetchd;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Spawn fetchd detached; resolve once /healthz answers, or give up. */
async function spawnFetchd(): Promise<boolean> {
  const binary = daemonBinary();
  if (!binary) return false;

  const logPath = process.env.GOHTTPD_LOG?.trim() || join(tmpdir(), "fetchd.log");
  let fd: number;
  try {
    fd = openSync(logPath, "a");
  } catch {
    return false;
  }
  try {
    const child = spawn(binary, [], { detached: true, stdio: ["ignore", fd, fd] });
    child.unref();
  } catch {
    return false;
  } finally {
    closeSync(fd);
  }

  for (let attempt = 0; attempt < SPAWN_POLL_ATTEMPTS; attempt++) {
    if (await healthz()) return true;
    await delay(SPAWN_POLL_INTERVAL_MS);
  }
  return false;
}

let pendingStart: Promise<boolean> | null = null;

/**
 * Make sure the daemon is running; start it when it is not.
 *
 * Concurrent callers share one attempt: the loser of a port race simply
 * finds /healthz answering.
 */
export function ensureDaemon(): Promise<boolean> {
  if (pendingStart) return pendingStart;

  const attempt = (async (): Promise<boolean> => {
    if (await healthz()) return true;
    return spawner();
  })();
  pendingStart = attempt;
  void attempt.then(
    () => {
      if (pendingStart === attempt) pendingStart = null;
    },
    () => {
      if (pendingStart === attempt) pendingStart = null;
    },
  );
  return attempt;
}

/** Pull the `error` field out of a daemon reply body, when there is one. */
function errorTextOf(body: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed !== null && typeof parsed === "object" && "error" in parsed) {
      const text = (parsed as { error?: unknown }).error;
      if (typeof text === "string" && text.length > 0) return text;
    }
  } catch {
    // A non-JSON body is reported verbatim by the caller.
  }
  return undefined;
}

function parseResult(body: string): FetchResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new SiteMimicError(`fetchd returned a non-JSON reply: ${body.slice(0, 200)}`, { cause: err });
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new SiteMimicError(`fetchd returned a non-object reply: ${body.slice(0, 200)}`);
  }
  return parsed as FetchResult;
}

/** Send one request to the daemon and return its reply. */
export async function callFetch(request: FetchRequest, timeoutS: number): Promise<FetchResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = daemonToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  // The daemon needs a moment beyond the request timeout itself: it answers
  // after the target has answered, not after the target started.
  const timeoutMs = Math.max(1, Math.round((timeoutS + DAEMON_SLACK_S) * 1000));

  let reply: { status: number; body: string };
  try {
    reply = await fetchText(
      `${daemonUrl()}/fetch`,
      { method: "POST", headers, body: JSON.stringify(request) },
      timeoutMs,
    );
  } catch (err) {
    throw new SiteMimicError(`fetchd unreachable at ${daemonUrl()}: ${describe(err)}`, {
      cause: err,
      url: request.url,
    });
  }

  if (reply.status < 200 || reply.status >= 300) {
    const detail = errorTextOf(reply.body);
    throw new SiteMimicError(
      detail ? `fetchd ${reply.status}: ${detail}` : `fetchd ${reply.status}: ${reply.body.slice(0, 300)}`,
      { status: reply.status, body: reply.body, url: request.url },
    );
  }
  return parseResult(reply.body);
}

/** Describe an unknown throwable in one line. */
function describe(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
