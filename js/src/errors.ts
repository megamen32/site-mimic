/**
 * The error type every failure of the site-mimic client surfaces as.
 *
 * The Python sibling calls this `GoHTTPDError`; the name here follows the
 * daemon it actually talks to (`fetchd`) so both clients are recognisably
 * the same piece of software.
 */

/** Context carried by a {@link SiteMimicError}. */
export interface SiteMimicErrorOptions {
  /** Status the daemon answered with; 0 when the daemon never answered. */
  status?: number;
  /** Raw body the daemon answered with, when there was one. */
  body?: string;
  /** URL that was being requested through the daemon. */
  url?: string;
  /** Underlying failure, when this error wraps one. */
  cause?: unknown;
}

export class SiteMimicError extends Error {
  /** Status the daemon answered with; 0 when the daemon never answered. */
  readonly status: number;
  /** Raw body the daemon answered with, when there was one. */
  readonly body: string;
  /** URL that was being requested through the daemon. */
  readonly url: string;

  constructor(message: string, options: SiteMimicErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "SiteMimicError";
    this.status = options.status ?? 0;
    this.body = options.body ?? "";
    this.url = options.url ?? "";
  }
}
