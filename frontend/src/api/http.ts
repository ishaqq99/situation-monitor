// Shared HTTP boundary: backend URL, cancellation, timeouts, and safe errors.
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "")


function errorMessage(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object" || !("detail" in body)) return fallback

  const detail = body.detail
  if (typeof detail === "string") return detail
  if (Array.isArray(detail)) {
    const messages = detail.flatMap((item: unknown) => {
      if (
        item
        && typeof item === "object"
        && "msg" in item
        && typeof item.msg === "string"
      ) {
        return [item.msg]
      }
      return []
    })
    return messages.join("; ") || fallback
  }
  return fallback
}


// The status property lets a feature distinguish an expected 404 from a real
// connectivity or server failure without parsing an error message string.
export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}


export async function requestJson<T>(
  path: string,
  options: { method?: string; signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<T> {
  const timeout = AbortSignal.timeout(options.timeoutMs ?? 40_000)
  const signal = options.signal
    ? AbortSignal.any([options.signal, timeout])
    : timeout

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? "GET",
    signal,
  })

  if (!response.ok) {
    let body: unknown
    try {
      body = await response.json()
    } catch {
      body = null
    }
    throw new ApiError(
      response.status,
      errorMessage(body, `Request failed (${response.status})`),
    )
  }

  return response.json() as Promise<T>
}
