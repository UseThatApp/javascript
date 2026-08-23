/** A response fetched and fully read under a single timeout. */
export interface TimedResponse {
  status: number;
  ok: boolean;
  text: string;
  /** Parsed `Retry-After` header in seconds, or `null` when absent or in
   * HTTP-date form. Carried so a 429/503 can surface the server's own
   * backoff hint instead of forcing the caller to guess (Quiver J-05). */
  retryAfter: number | null;
}

function parseRetryAfter(headers: Headers): number | null {
  const raw = headers.get("retry-after");
  if (raw === null) return null;
  const n = parseInt(raw.trim(), 10);
  return Number.isFinite(n) && n >= 0 && String(n) === raw.trim() ? n : null;
}

/**
 * Fetch `url` and read the whole body under one AbortController timeout,
 * so a body that stalls after headers arrive counts against the timeout
 * just like a stalled connection.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutSeconds: number,
): Promise<TimedResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutSeconds * 1000);
  try {
    const resp = await fetch(url, { ...init, signal: controller.signal, redirect: "follow" });
    return {
      status: resp.status,
      ok: resp.ok,
      text: await resp.text(),
      retryAfter: parseRetryAfter(resp.headers),
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Best-effort string form of a thrown value. */
export function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
