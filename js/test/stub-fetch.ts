/**
 * A stub of the global fetch that stands in for the fetchd daemon.
 *
 * The stub records every call and answers from a handler the test owns, so
 * the suite needs neither a Go toolchain nor a network: the daemon
 * contract is asserted on the exact payload and headers the client puts on
 * the wire.
 */

export interface CapturedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

export interface StubReply {
  status: number;
  body: string;
}

export interface StubDaemon {
  /** Every call the stub saw, in order. */
  readonly calls: CapturedCall[];
  /** Only the calls that reached POST /fetch. */
  fetchCalls(): CapturedCall[];
  /** Put the original global fetch back. */
  restore(): void;
}

type FetchGlobal = { fetch?: unknown };

/** Install the stub and return a handle to inspect what it saw. */
export function installStubFetch(handler: (call: CapturedCall) => StubReply): StubDaemon {
  const holder = globalThis as FetchGlobal;
  const original = holder.fetch;
  const calls: CapturedCall[] = [];

  const stub = async (
    url: string,
    init: { method: string; headers: Record<string, string>; body?: string },
  ): Promise<{ status: number; text(): Promise<string> }> => {
    const call: CapturedCall = {
      url,
      method: init.method,
      headers: { ...init.headers },
      body: init.body ?? "",
    };
    calls.push(call);
    const reply = handler(call);
    return { status: reply.status, text: async () => reply.body };
  };

  holder.fetch = stub;

  return {
    calls,
    fetchCalls: () => calls.filter((call) => call.url.endsWith("/fetch")),
    restore: () => {
      if (original === undefined) delete holder.fetch;
      else holder.fetch = original;
    },
  };
}
