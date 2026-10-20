/**
 * 
 * FILE GUIDE
 * ----------
 * WHAT THIS FILE DOES
 * Show stored OTX context, report decisions, and refresh history for one selected KEV.
 * 
 * WHY IT EXISTS
 * A CVE detail view needs source provenance and lifecycle, not an unexplained IOC list.
 * 
 * WHO CALLS OR IMPORTS IT
 * KevPanel.tsx renders this component for the chosen CVE.
 * 
 * WHAT IT CALLS OR IMPORTS
 * Calls frontend/src/api/ioc.ts for stored reads and queue requests.
 * 
 * ROLE IN THE ARCHITECTURE
 * Interactive CVE-detail UI; provider data is text unless a fixed OTX pulse link is valid.
 * 
 */
// Stored OTX evidence for one selected KEV. KevPanel renders this with a CVE key,
// so changing selection resets pagination/messages and cancels old requests.
// Observable URLs/domains/IPs are text only. The only clickable evidence links
// are constructed from a validated pulse ID on the fixed OTX HTTPS origin.
import { useEffect, useRef, useState } from "react"
import { getIocPage, getIocRuns, queueIocRefresh } from "../api/ioc"
import type { IOCPage, IOCRun } from "../types/ioc"
import "./Ioc.css"

/** Format an API date in the viewer's locale; null means no recorded event. */
function dateLabel(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "Not recorded"
}

/** Create a clickable link only for a valid pulse ID on the fixed OTX host. */
function pulseLink(id: string): string | null {
  return /^[a-fA-F0-9]{24}$/.test(id) ? `https://otx.alienvault.com/pulse/${id}` : null
}

/** Turn backend enum labels into short human-readable phrases. */
function readable(value: string): string {
  return value.replaceAll("_", " ")
}

/**
 * KevPanel mounts this component for one selected KEV. It reads stored OTX
 * evidence and attempts, shows report provenance and scope limits, and lets
 * the user queue a refresh. None of its GETs call the provider directly.
 */
export default function IocPanel({ cveId }: { cveId: string }) {
  const [page, setPage] = useState<IOCPage | null>(null)
  const [runs, setRuns] = useState<IOCRun[]>([])
  const [offset, setOffset] = useState(0)
  const [includeHistory, setIncludeHistory] = useState(false)
  const [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [queuing, setQueuing] = useState(false)
  const manualRequest = useRef<AbortController | null>(null)

  // Cancel a pending manual queue request if the selected CVE card closes.
  useEffect(() => () => manualRequest.current?.abort(), [])

  // A CVE/page/history change restarts the stored-data poll. The effect clears
  // stale rows, aborts obsolete reads, and schedules one next poll only after
  // both current reads finish.
  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    // Clear data on a page/filter/CVE change so an old page is not mislabeled.
    setPage(null); setRuns([]); setLoading(true)
    /** Read the evidence page and recent runs as one visible snapshot. */
    async function load() {
      // Cancel the sibling read if either request fails; do not leave a slow
      // old request in flight when the next polling cycle begins.
      const batch = new AbortController()
      const signal = AbortSignal.any([controller.signal, batch.signal])
      try {
        const [data, attempts] = await Promise.all([
          getIocPage(cveId, offset, includeHistory, signal),
          getIocRuns(cveId, signal),
        ])
        if (!controller.signal.aborted) {
          // Refreshing a snapshot can shrink its last page. Return to page 1
          // rather than presenting an empty table with an out-of-range offset.
          if (offset > 0 && offset >= data.total) { setOffset(0); return }
          setPage(data); setRuns(attempts); setError(null)
        }
      } catch (err) {
        batch.abort()
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Unable to read OTX evidence")
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
          timer = setTimeout(() => { void load() }, 15_000)
        }
      }
    }
    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [cveId, offset, includeHistory, revision])

  /** Queue/coalesce a manual lookup and re-read its job state; do not wait for OTX. */
  async function requestRefresh() {
    if (queuing) return
    const controller = new AbortController()
    manualRequest.current = controller
    setQueuing(true); setNotice(null)
    try {
      const result = await queueIocRefresh(cveId, controller.signal)
      if (!controller.signal.aborted) { setNotice(result.message); setRevision(value => value + 1) }
    } catch (err) {
      if (!controller.signal.aborted) setNotice(err instanceof Error ? err.message : "Unable to queue refresh")
    } finally {
      if (!controller.signal.aborted) setQueuing(false)
    }
  }

  return <section className="kev-detail-section ioc-panel" aria-label={`OTX evidence for ${cveId}`}>
    <div className="ioc-toolbar">
      <h3>AlienVault OTX — report context</h3>
      {/* The unauthenticated public view cannot queue provider work. */}
      {import.meta.env.VITE_PUBLIC_DEMO !== "true" && (
        <button type="button" disabled={queuing || page?.job?.state === "running"} onClick={() => { void requestRefresh() }}>
          {queuing ? "Queuing..." : "Request OTX refresh"}
        </button>
      )}
    </div>
    <p>Indicators below share a related threat report with this CVE. They are not confirmed exploitation indicators for this CVE.</p>
    {notice && <p role="status">{notice}</p>}
    {loading && <p role="status">Loading stored OTX evidence...</p>}
    {error && <p role="alert" className="error-message">{error} Any previously displayed results may be stale.</p>}
    {page && <>
      <dl className="ioc-facts">
        <div><dt>Refresh state</dt><dd>{readable(page.job?.state ?? "awaiting schedule")}</dd></div>
        <div><dt>Last attempt</dt><dd>{dateLabel(page.job?.last_attempt_at)}</dd></div>
        <div><dt>Last complete scoped check</dt><dd>{dateLabel(page.job?.last_success_at)}</dd></div>
        <div><dt>Next scheduled check</dt><dd>{dateLabel(page.job?.next_check_at)}</dd></div>
      </dl>
      {page.job?.last_error && <p className="ioc-warning">{page.job.last_error}</p>}
      {page.job?.summary && <>
        <p>Last stored collection: {page.job.summary.source_record_count_reported} reports reported,
          {" "}{page.job.summary.source_record_count_processed} fetched,
          {" "}{page.job.summary.source_record_count_skipped} skipped by scope.</p>
        {!page.job.summary.complete && <p className="ioc-warning">That collection was partial. Older stored evidence is retained.</p>}
        {page.job.summary.warnings.map((warning, index) => <p className="ioc-warning" key={`${index}-${warning}`}>{warning}</p>)}
      </>}
      <label className="ioc-history-toggle"><input type="checkbox" checked={includeHistory} onChange={event => {
        setIncludeHistory(event.target.checked); setOffset(0)
      }} /> Include observations absent from the latest complete scope</label>
      {page.total === 0 ? <p>{page.job?.last_success_at
        ? "No stored observations in this view. Review scope, skipped reports, and refresh status before interpreting this as no intelligence."
        : "No observations stored yet. Collection may be pending, incomplete, or unsuccessful."}</p> : <>
        <p>{page.total} source observations in this view. The same indicator may appear in several reports.</p>
        <div className="kev-table-wrapper"><table className="kev-table ioc-table">
          <thead><tr><th>Indicator</th><th>Source evidence</th><th>Provider state</th><th>Locally observed</th></tr></thead>
          <tbody>{page.observations.map(item => {
            const observation = item.observation
            const href = pulseLink(observation.source_record_id)
            return <tr key={`${observation.source_record_id}-${observation.indicator.indicator_type}-${observation.indicator.value}`}>
              <td><strong>{observation.indicator.indicator_type}</strong><pre>{observation.indicator.value}</pre></td>
              <td>{href ? <a href={href} target="_blank" rel="noopener noreferrer">{observation.source_record_name ?? "View OTX report"}</a>
                : <span>{observation.source_record_name ?? "OTX report"}</span>}
                <p>{readable(observation.relationship_type)} / {readable(observation.source_record_relevance)}</p>
                <p>Author: {observation.source_author ?? "Unknown"}; TLP: {observation.source_tlp ?? "Unknown"}</p>
                <details><summary>Report CVEs and references</summary><p>{observation.source_record_cve_ids.join(", ")}</p>
                  {observation.reference_urls.slice(0, 10).map((reference, index) => <p className="ioc-reference" key={`${index}-${reference}`}>{reference}</p>)}
                  {observation.reference_urls.length > 10 && <p>Showing 10 of {observation.reference_urls.length} references.</p>}
                </details>
              </td>
              <td>{readable(item.lifecycle)}<p>Expires: {dateLabel(observation.expires_at)}</p>
                {item.absent_since && <p>Absent from complete scope since {dateLabel(item.absent_since)}</p>}</td>
              <td>First: {dateLabel(item.first_seen_at)}<p>Last: {dateLabel(item.last_seen_at)}</p></td>
            </tr>
          })}</tbody>
        </table></div>
        <div className="ioc-toolbar"><button type="button" disabled={offset === 0 || loading} onClick={() => setOffset(value => Math.max(0, value - 25))}>Previous</button>
          <span>{offset + 1}–{Math.min(offset + page.limit, page.total)} of {page.total}</span>
          <button type="button" disabled={offset + page.limit >= page.total || loading} onClick={() => setOffset(value => value + 25)}>Next</button></div>
      </>}
      <details><summary>Report selection decisions ({page.assessments.length} of {page.assessment_total})</summary>
        {page.assessments.map(assessment => <div className="ioc-assessment" key={assessment.source_record_id}>
          <strong>{assessment.source_record_name ?? assessment.source_record_id}</strong>
          <p>{readable(assessment.relevance)} — {assessment.fetched ? "fetched" : assessment.selected_for_collection ? "selected but not completed" : "skipped by scope"}</p>
          <p>{assessment.reason}</p>
        </div>)}
      </details>
      <details><summary>Recent refresh attempts</summary>
        {runs.length === 0 ? <p>No attempts recorded yet.</p> : <ul>{runs.map(run =>
          <li key={run.run_id}>{dateLabel(run.started_at)} — {readable(run.outcome)}{run.error ? `: ${run.error}` : ""}</li>
        )}</ul>}
      </details>
    </>}
  </section>
}
