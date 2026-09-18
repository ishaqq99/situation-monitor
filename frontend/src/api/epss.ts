// EPSS HTTP client. React components own display state; this file owns paths.

import { ApiError, requestJson } from "./http"
import type { EPSSFeedStatus, EPSSRefreshResult, EPSSScore } from "../types/epss"


export async function getEpssScore(
  cveId: string,
  signal?: AbortSignal,
): Promise<EPSSScore | null> {
  try {
    return await requestJson<EPSSScore>(
      `/api/epss/${encodeURIComponent(cveId)}`,
      { signal },
    )
  } catch (error) {
    // A missing stored score is a normal application state while the first
    // background enrichment is still running.
    if (error instanceof ApiError && error.status === 404) return null
    throw error
  }
}


export function getEpssStatus(signal?: AbortSignal): Promise<EPSSFeedStatus> {
  return requestJson("/api/epss/status", { signal })
}


export function refreshEpss(signal?: AbortSignal): Promise<EPSSRefreshResult> {
  return requestJson("/api/epss/refresh", {
    method: "POST",
    signal,
    timeoutMs: 250_000,
  })
}
