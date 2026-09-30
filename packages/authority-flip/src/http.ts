export class HttpError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export async function requestJson(
  fetchImpl: typeof fetch,
  url: string,
  init: {
    method: "GET" | "POST";
    timeoutMs: number;
    headers?: Record<string, string>;
    body?: unknown;
  },
): Promise<{ status: number; body: unknown }> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: init.method,
      headers: {
        accept: "application/json",
        ...(init.body === undefined ? {} : { "content-type": "application/json" }),
        ...init.headers,
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(init.timeoutMs),
    });
  } catch (error) {
    throw new HttpError(shortReason(error), null);
  }
  const text = await response.text();
  if (!response.ok) {
    throw new HttpError(`HTTP ${response.status}`, response.status);
  }
  if (text.trim() === "") {
    throw new HttpError("empty response body", response.status);
  }
  try {
    return { status: response.status, body: JSON.parse(text) as unknown };
  } catch {
    throw new HttpError("response was not JSON", response.status);
  }
}

function shortReason(error: unknown): string {
  if (!(error instanceof Error)) {
    return "request failed";
  }
  if (error.name === "TimeoutError" || error.name === "AbortError") {
    return "timed out";
  }
  const message = error.message.replace(/\s+/g, " ").trim();
  const cause = error.cause;
  const code =
    cause instanceof Error && "code" in cause && typeof cause.code === "string" && !message.includes(cause.code)
      ? cause.code
      : "";
  const combined = code ? `${message}: ${code}` : message;
  return combined.slice(0, 180) || "request failed";
}
