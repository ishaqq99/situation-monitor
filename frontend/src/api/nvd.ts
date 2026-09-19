// NVD HTTP client. React components own display state; this file owns paths.

import { ApiError, requestJson } from "./http"
import type {
  NVDCVE,
  NVDCVSSChange,
  NVDFeedStatus,
  NVDRefreshResult,
} from "../types/nvd"


export async function getNvdDetails(
  cveId: string,
  signal?: AbortSignal,
): Promise<NVDCVE | null> {
  try {
    return await requestJson<NVDCVE>(
      `/api/nvd/${encodeURIComponent(cveId)}`,
      { signal },
    )
  } catch (error) {
    // Missing enrichment is a normal state while the first background backfill
    // is still processing KEVs.
    if (error instanceof ApiError && error.status === 404) return null
    throw error
  }
}


export function getNvdCvssHistory(
  cveId: string,
  signal?: AbortSignal,
): Promise<NVDCVSSChange[]> {
  return requestJson(
    `/api/nvd/${encodeURIComponent(cveId)}/history?limit=20`,
    { signal },
  )
}


export function getNvdStatus(signal?: AbortSignal): Promise<NVDFeedStatus> {
  return requestJson("/api/nvd/status", { signal })
}


export function refreshNvd(signal?: AbortSignal): Promise<NVDRefreshResult> {
  // One public-rate-limited batch can take a few minutes without an API key.
  return requestJson("/api/nvd/refresh", {
    method: "POST",
    signal,
    timeoutMs: 320_000,
  })
}
