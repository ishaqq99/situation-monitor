/**
 * 
 * FILE GUIDE
 * ----------
 * WHAT THIS FILE DOES
 * Build requests for stored OTX status, evidence, run history, and refresh queueing.
 * 
 * WHY IT EXISTS
 * Components should express user actions, not duplicate URLs and HTTP error handling.
 * 
 * WHO CALLS OR IMPORTS IT
 * IocStatusPanel and IocPanel call these functions.
 * 
 * WHAT IT CALLS OR IMPORTS
 * Calls the existing frontend/src/api/http.ts helper and uses types/ioc.ts.
 * 
 * ROLE IN THE ARCHITECTURE
 * Frontend HTTP boundary; never includes the secret OTX API key.
 * 
 */
// HTTP boundary for the IOC components. Reuse the app's backend URL, request
// timeout, cancellation, and ApiError behavior from http.ts. The OTX key never
// belongs in Vite configuration and is never sent by this frontend.
import { requestJson } from "./http"
import type { IOCPage, IOCProviderStatus, IOCQueueResult, IOCRun } from "../types/ioc"

/**
 * Called by IocStatusPanel. Read global KEV coverage and the persisted provider
 * cooldown from FastAPI. The route reads PostgreSQL; it does not contact OTX.
 * The optional signal lets the component cancel an obsolete read.
 */
export function getIocStatus(signal?: AbortSignal): Promise<IOCProviderStatus> {
  return requestJson("/api/ioc/status", { signal })
}

/**
 * Called by IocPanel for a selected CVE. Request one 25-row page, with an
 * offset and an explicit choice about historical observations. Encoding the
 * CVE prevents it from changing the URL structure; the backend validates it.
 */
export function getIocPage(cveId: string, offset: number, includeHistory: boolean,
                           signal?: AbortSignal): Promise<IOCPage> {
  const query = new URLSearchParams({ limit: "25", offset: String(offset),
    include_history: String(includeHistory) })
  return requestJson(`/api/ioc/${encodeURIComponent(cveId)}?${query}`, { signal })
}

/** Public evidence endpoint omits job, queue, and report-decision details. */
export function getPublicIocPage(cveId: string, offset: number, includeHistory: boolean,
                                 signal?: AbortSignal): Promise<IOCPage> {
  const query = new URLSearchParams({ limit: "25", offset: String(offset),
    include_history: String(includeHistory) })
  return requestJson(`/api/ioc/public/${encodeURIComponent(cveId)}?${query}`, { signal })
}

/**
 * Called by IocPanel beside the evidence page. Return five recent attempts so
 * a failed or partial run cannot be mistaken for a successful empty response.
 */
export function getIocRuns(cveId: string, signal?: AbortSignal): Promise<IOCRun[]> {
  return requestJson(`/api/ioc/${encodeURIComponent(cveId)}/runs?limit=5`, { signal })
}

/**
 * Called by the refresh button. POST only queues or coalesces a job and returns
 * HTTP 202; the worker later contacts OTX. A queued result is not completed
 * evidence. The secret provider key remains entirely in the backend.
 */
export function queueIocRefresh(cveId: string, signal?: AbortSignal): Promise<IOCQueueResult> {
  return requestJson(`/api/ioc/${encodeURIComponent(cveId)}/refresh`, { method: "POST", signal })
}
