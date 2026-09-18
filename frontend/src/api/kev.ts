// Complete KEV client. Components own UI state; these functions own HTTP paths.
// The interfaces mirror the Pydantic response models in backend/app/models/kev.py.
import { requestJson } from "./http"
import type { KEVEntry, KEVFeedStatus, KEVRefreshResult } from "../types/kev"

export function getLatestKev(limit = 10, signal?: AbortSignal): Promise<KEVEntry[]> {
  return requestJson(`/api/kev?limit=${limit}`, { signal })
}

export function getKevStatus(signal?: AbortSignal): Promise<KEVFeedStatus> {
  return requestJson("/api/kev/status", { signal })
}

export function refreshKev(signal?: AbortSignal): Promise<KEVRefreshResult> {
  // The server bounds ingestion at 240 seconds; allow its response to arrive.
  return requestJson("/api/kev/refresh", { method: "POST", signal, timeoutMs: 250_000 })
}

export function searchKev(searchTerm: string, signal?: AbortSignal): Promise<KEVEntry[]> {
  return requestJson(`/api/kev/search?q=${encodeURIComponent(searchTerm)}`, { signal })
}

export function getKevDetails(cveId: string, signal?: AbortSignal): Promise<KEVEntry> {
  return requestJson(`/api/kev/${encodeURIComponent(cveId)}`, { signal })
}
