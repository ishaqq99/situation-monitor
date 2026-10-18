/**
 * 
 * FILE GUIDE
 * ----------
 * WHAT THIS FILE DOES
 * Show catalog-wide OTX coverage, queue state, and provider cooldown.
 * 
 * WHY IT EXISTS
 * Operators need to see whether collection is enabled and progressing.
 * 
 * WHO CALLS OR IMPORTS IT
 * App.tsx renders this component on the dashboard.
 * 
 * WHAT IT CALLS OR IMPORTS
 * Calls frontend/src/api/ioc.ts to read stored /api/ioc/status every 15 seconds.
 * 
 * ROLE IN THE ARCHITECTURE
 * Read-only dashboard summary; it never calls OTX directly.
 * 
 */
// Dashboard summary. Poll stored status after the preceding read finishes, so
// a slow request never creates overlapping interval requests. Cleanup aborts
// in-flight reads and stops timers on unmount, including React StrictMode.
import { useEffect, useState } from "react"
import { getIocStatus } from "../api/ioc"
import type { IOCProviderStatus } from "../types/ioc"
import "./Ioc.css"

/**
 * App.tsx renders this read-only, catalog-wide status card. It lets an operator
 * distinguish disabled collection, a missing key, backlog, a working worker,
 * and provider cooldown without opening a specific CVE.
 */
export default function IocStatusPanel() {
  const [status, setStatus] = useState<IOCProviderStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  // The effect owns one poll chain and one AbortController. It cancels both on
  // unmount, preventing an old response from updating a removed component.
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    /** Fetch one stored status snapshot, then schedule the next poll. */
    async function load() {
      try {
        const result = await getIocStatus(controller.signal)
        if (!controller.signal.aborted) { setStatus(result); setError(null) }
      } catch (err) {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Unable to load OTX status")
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => { void load() }, 15_000)
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [])

  return <section className="status-card ioc-status" aria-label="AlienVault OTX status">
    <h2>AlienVault OTX</h2>
    <p>Stored threat-report context for the KEV catalog. Every KEV is scheduled, including older CVEs.</p>
    {error && <p role="alert" className="error-message">{error} Previously displayed status may be stale.</p>}
    {!status && !error && <p role="status">Loading OTX status...</p>}
    {status && <>
      {!status.enabled && <p>Automatic OTX collection is disabled.</p>}
      {status.enabled && !status.configured && <p>OTX needs its backend API key before collection can start.</p>}
      <dl className="ioc-facts">
        <div><dt>KEVs scheduled</dt><dd>{status.scheduled_kevs} / {status.total_kevs}</dd></div>
        <div><dt>Ever completed a scoped check</dt><dd>{status.ever_completed}</dd></div>
        <div><dt>Due / running</dt><dd>{status.due_jobs} / {status.running_jobs}</dd></div>
        <div><dt>Failed, partial, or deferred</dt><dd>{status.failed_or_partial}</dd></div>
        <div><dt>Stored source observations</dt><dd>{status.stored_observations}</dd></div>
        <div><dt>Worker last checked</dt><dd>{status.heartbeat_at ? new Date(status.heartbeat_at).toLocaleString() : "Not recorded"}</dd></div>
      </dl>
      {status.last_error && <p role="status" className="ioc-warning">{status.last_error}</p>}
      {status.next_allowed_at && new Date(status.next_allowed_at).getTime() > Date.now() &&
        <p>Next provider request allowed after {new Date(status.next_allowed_at).toLocaleString()}.</p>}
      <p className="ioc-muted">A completed check covers the selected reports; it does not establish direct exploitation evidence.</p>
    </>}
  </section>
}
