/**
 * site-mimic — a requests-flavoured client for Node that routes HTTP
 * through the `fetchd` daemon.
 *
 * The daemon is the transport: it owns the uTLS ClientHello, so a stock
 * Node `fetch` cannot make the request this client is meant to make. This
 * module is the JavaScript/TypeScript twin of the Python client in
 * `python/site_mimic_client/gohttp.py` — same daemon, same wire behaviour,
 * one source of truth for what a request to a protected site looks like.
 *
 * Usage:
 *
 *     import { get, post } from "site-mimic";
 *
 *     const response = await get("https://example.com/api", {
 *       headers: { "User-Agent": "…" },
 *       cookies: { session: "…" },
 *       profile: "/abs/path/profile.json",
 *     });
 *     console.log(response.statusCode, response.text);
 *
 * Config (env): GOHTTPD_URL (default http://127.0.0.1:30777), GOHTTPD_TOKEN
 * when the daemon wants a bearer, GOHTTPD_BIN / SITE_MIMIC_DIR to find the
 * daemon binary, GOHTTPD_LOG for its log file, GOHTTP_PROFILE for the
 * default mimic profile, GOHTTPD_AUTOSTART=0 to forbid starting it.
 */

import { Buffer } from "node:buffer";

import { SiteMimicError } from "./errors.js";
import {
  autoStartEnabled,
  callFetch,
  daemonUrl,
  ensureDaemon,
  healthz,
  type FetchRequest,
  type FetchResult,
  type SetCookieWire,
} from "./daemon.js";

export { SiteMimicError } from "./errors.js";
export type { SiteMimicErrorOptions } from "./errors.js";
export {
  autoStartEnabled,
  daemonBinary,
  daemonUrl,
  ensureDaemon,
  healthz,
  resetDaemonSpawner,
  setDaemonSpawner,
  siteMimicDir,
} from "./daemon.js";
export type { DaemonSpawner } from "./daemon.js";

/** Request timeout in seconds, used when the caller does not pick one. */
export const DEFAULT_TIMEOUT_S = 30;

/** Per-request options. */
export interface RequestOptions {
  /** Request headers, sent verbatim to the target. */
  headers?: Record<string, string>;
  /** Cookies, sent as a single `Cookie` header. */
  cookies?: Record<string, string>;
  /** JSON body: encoded by the client and sent with a JSON content type. */
  json?: unknown;
  /** Raw body: a string goes as is, bytes travel base64-encoded. */
  data?: string | Uint8Array;
  /** Path to the mimic profile that selects the transport identity. */
  profile?: string;
  /** Per-request CONNECT proxy. */
  proxy?: string;
  /** DNS pinning: host → IP, with the original SNI kept. */
  resolve?: Record<string, string>;
  /** Request timeout in seconds. */
  timeout?: number;
}

/** One Set-Cookie entry of a response. */
export interface SetCookieEntry {
  name: string;
  value: string;
  domain: string;
  path: string;
  /** RFC 3339 expiry as reported by the daemon. */
  expires: string;
  /** Present only when the daemon reports the flag. */
  secure?: boolean;
  /** Present only when the daemon reports the flag. */
  httpOnly?: boolean;
  /** Present only when the daemon reports the flag. */
  sameSite?: string;
}

/** A response from the daemon, shaped like the Python client's response. */
export interface Response {
  statusCode: number;
  headers: Record<string, string[]>;
  text: string;
  content: Uint8Array;
  setCookieEntries(): SetCookieEntry[];
  /** Whether the status is 2xx. */
  ok: boolean;
  /** URL the request was sent to. */
  url: string;
  /** Cookies the target set, by name. */
  cookies: Record<string, string>;
  /** Parse the body as JSON. */
  json(): unknown;
  /** Raise on a 4xx/5xx status, mirroring requests semantics. */
  raiseForStatus(): Response;
}

/** A response from the daemon. */
export class SiteMimicResponse implements Response {
  /** URL the request was sent to. */
  readonly url: string;
  /** HTTP status of the target response. */
  readonly statusCode: number;
  /** Response headers; a header with several values keeps all of them. */
  readonly headers: Record<string, string[]>;
  /** Response body as raw bytes. */
  readonly content: Uint8Array;
  /** Response body decoded as UTF-8. */
  readonly text: string;
  /** Cookies the target set, by name. */
  readonly cookies: Record<string, string>;
  /** Whether the status is 2xx. */
  readonly ok: boolean;

  readonly #entries: SetCookieEntry[];

  constructor(result: FetchResult, url: string) {
    this.url = url;
    this.statusCode = result.status ?? 0;
    this.headers = result.headers ?? {};
    this.ok = this.statusCode >= 200 && this.statusCode < 300;

    // The daemon hands binary bodies over as base64 and text bodies as
    // strings; only one of the two is ever filled in.
    const encoded = result.body_b64 ?? "";
    this.content = encoded
      ? new Uint8Array(Buffer.from(encoded, "base64"))
      : new TextEncoder().encode(result.body ?? "");
    this.text = new TextDecoder("utf-8").decode(this.content);

    this.#entries = (result.set_cookies ?? []).map((entry: SetCookieWire) => ({
      name: entry.name ?? "",
      value: entry.value ?? "",
      domain: entry.domain ?? "",
      path: entry.path ?? "",
      expires: entry.expires ?? "",
      ...(entry.secure === undefined ? {} : { secure: entry.secure }),
      ...(entry.httpOnly === undefined ? {} : { httpOnly: entry.httpOnly }),
      ...(entry.sameSite === undefined ? {} : { sameSite: entry.sameSite }),
    }));

    const jar: Record<string, string> = {};
    for (const entry of this.#entries) {
      // A nameless cookie is not a cookie the caller can act on.
      if (entry.name) jar[entry.name] = entry.value;
    }
    this.cookies = jar;
  }

  /** Parse the body as JSON. */
  json(): unknown {
    return JSON.parse(this.text);
  }

  /** Return the full Set-Cookie entries, including the nameless ones. */
  setCookieEntries(): SetCookieEntry[] {
    return this.#entries.map((entry) => ({ ...entry }));
  }

  /** Raise on a 4xx/5xx status, mirroring requests semantics. */
  raiseForStatus(): Response {
    if (this.statusCode >= 400) {
      throw new SiteMimicError(`${this.statusCode} for ${this.url}: ${this.text.slice(0, 200)}`, {
        status: this.statusCode,
        body: this.text,
        url: this.url,
      });
    }
    return this;
  }
}

/** Build the daemon payload for one request. */
function buildRequest(
  method: string,
  url: string,
  options: RequestOptions,
  timeoutS: number,
): FetchRequest {
  const request: FetchRequest = {
    method: method.toUpperCase(),
    url,
    timeout_s: timeoutS,
  };

  // The profile selects the transport identity, and the daemon refuses to
  // work without one — but an operator may pin the default in the
  // environment instead of repeating it at every call site.
  const profile = options.profile ?? process.env.GOHTTP_PROFILE?.trim();
  if (profile) request.profile = profile;

  if (options.headers) request.headers = { ...options.headers };
  if (options.cookies) request.cookies = { ...options.cookies };

  if (options.json !== undefined) {
    // The daemon carries a body as a JSON string, so a JSON body has to be
    // encoded here; pinning the content type keeps the target seeing what
    // a browser would send.
    request.headers = { ...(request.headers ?? {}), "Content-Type": "application/json" };
    request.body = JSON.stringify(options.json) ?? "null";
  } else if (options.data !== undefined) {
    if (typeof options.data === "string") {
      request.body = options.data;
    } else {
      // Arbitrary bytes cannot travel through a JSON string field without
      // being mangled, so they go over the wire base64-encoded.
      request.body_b64 = Buffer.from(options.data).toString("base64");
    }
  }

  if (options.proxy) request.proxy = options.proxy;
  if (options.resolve) request.resolve = { ...options.resolve };

  return request;
}

/** Send the payload, supervising the daemon around it. */
async function send(payload: FetchRequest, timeoutS: number): Promise<FetchResult> {
  const supervise = autoStartEnabled();

  if (supervise && !(await healthz())) {
    // Without the daemon there is no request at all, so try to bring it up
    // before failing the call.
    await ensureDaemon();
  }

  try {
    return await callFetch(payload, timeoutS);
  } catch (err) {
    // Only a transport failure is worth a restart: an HTTP status means the
    // daemon answered and rejected the request, and replaying it would fail
    // the very same way.
    const transportFailure = err instanceof SiteMimicError && err.status === 0;
    if (!supervise || !transportFailure) throw err;

    const started = await ensureDaemon();
    if (!started) {
      throw new SiteMimicError(`fetchd unreachable at ${daemonUrl()} and could not be started`, {
        cause: err,
        url: payload.url,
      });
    }
    return await callFetch(payload, timeoutS);
  }
}

/**
 * Execute one HTTP request through the fetchd daemon.
 *
 * `profile` is the path to a site-mimic profile.json that selects the
 * transport identity; without it the daemon refuses the request.
 */
export async function request(
  method: string,
  url: string,
  options: RequestOptions = {},
): Promise<Response> {
  const timeoutS = options.timeout ?? DEFAULT_TIMEOUT_S;
  const payload = buildRequest(method, url, options, timeoutS);
  const result = await send(payload, timeoutS);

  const response = new SiteMimicResponse(result, url);

  // A failed request is reported by the daemon with HTTP 200 and a filled
  // `error` field: that is a transport failure, not a response.
  const failure = result.error?.trim();
  if (failure) {
    throw new SiteMimicError(failure, {
      status: response.statusCode,
      body: response.text,
      url,
    });
  }

  return response;
}

/** GET via {@link request}. */
export function get(url: string, options: RequestOptions = {}): Promise<Response> {
  return request("GET", url, options);
}

/** POST via {@link request}. */
export function post(url: string, options: RequestOptions = {}): Promise<Response> {
  return request("POST", url, options);
}
