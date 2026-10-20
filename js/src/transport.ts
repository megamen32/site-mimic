/**
 * The thin HTTP layer the client talks to the daemon through.
 *
 * The slice of the WHATWG fetch contract used here is deliberately narrow:
 * the daemon is always addressed by URL, method and a plain header object,
 * and only the status plus the raw text of the reply are ever read. A small
 * surface keeps the client testable against a stub without any network.
 */

import { SiteMimicError } from "./errors.js";

/** The part of a fetch reply this client reads. */
export interface HttpReply {
  readonly status: number;
  text(): Promise<string>;
}

/** The part of the global fetch this client calls. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<HttpReply>;

/** The global object as seen by this module, with fetch left untyped. */
type FetchGlobal = { fetch?: unknown };

function fetchGlobal(): FetchGlobal {
  return globalThis as FetchGlobal;
}

/**
 * Return the global fetch.
 *
 * It is looked up on every call instead of once at import time so that a
 * test — or a host application that installs its own fetch — can replace it.
 */
export function resolveFetch(): FetchLike {
  const candidate = fetchGlobal().fetch;
  if (typeof candidate !== "function") {
    throw new SiteMimicError("global fetch is not available — Node 18 or newer is required");
  }
  return candidate as FetchLike;
}

/** Request shape handed to the global fetch. */
export interface FetchOptions {
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/** Perform one HTTP call under a hard deadline. */
export async function fetchText(
  url: string,
  options: FetchOptions,
  timeoutMs: number,
): Promise<{ status: number; body: string }> {
  const fetchImpl = resolveFetch();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const reply = await fetchImpl(url, {
      method: options.method,
      headers: options.headers,
      // Spreading instead of assigning keeps `body` absent (rather than
      // explicitly undefined) for requests without a payload.
      ...(options.body === undefined ? {} : { body: options.body }),
      signal: controller.signal,
    });
    return { status: reply.status, body: await reply.text() };
  } finally {
    clearTimeout(timer);
  }
}
