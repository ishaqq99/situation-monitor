/** Browser HTTP boundary for the stored/cached threat overview.
 * App.tsx calls this file. This file calls our FastAPI route through the
 * existing requestJson helper. The browser never contacts Cloudflare Radar.
 */
import { requestJson } from "./http"
import type { ThreatOverview } from "../types/threat"

/** Read the current country snapshot; AbortSignal cancels obsolete page reads. */
export function getThreatOverview(signal?: AbortSignal): Promise<ThreatOverview> {
  return requestJson<ThreatOverview>("/api/threat/overview", { signal })
}
