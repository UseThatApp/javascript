/** Shared fetch helper with an AbortController timeout. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutSeconds: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutSeconds * 1000);
  try {
    return await fetch(url, { ...init, signal: controller.signal, redirect: "follow" });
  } finally {
    clearTimeout(timer);
  }
}

/** Best-effort string form of a thrown value. */
export function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
