/**
 * Compact, read-only view of recently cataloged CISA KEVs.
 *
 * WHY: KevPanel owns search and full details; this panel gives the dashboard
 * a quick signal using the same locally stored data. App.tsx renders it.
 * It calls api/kev.ts, never the external CISA service from the browser.
 */
import { useEffect, useState } from "react"
import { getLatestKev } from "../api/kev"
import type { KEVEntry } from "../types/kev"

/** Keep CISA's date-only field date-only in both display and HTML metadata. */
function displayDate(value: string): string {
  return value.slice(0, 10)
}

/** Read the latest stored KEVs once per minute without overlapping requests. */
export default function RecentKevPanel() {
  const [entries, setEntries] = useState<KEVEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    /** Schedule a new read after this read succeeds or fails. */
    async function load() {
      try {
        const rows = await getLatestKev(7, controller.signal)
        if (!controller.signal.aborted) {
          setEntries(rows)
          setError(null)
        }
      } catch {
        if (!controller.signal.aborted) {
          setError("Unable to update the recent KEV list.")
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
          timer = setTimeout(() => { void load() }, 60_000)
        }
      }
    }

    void load()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [])

  return (
    <section className="status-card recent-kev-panel" aria-labelledby="recent-kev-heading">
      <div className="panel-heading">
        <div><p className="eyebrow">CISA / KNOWN EXPLOITED</p><h2 id="recent-kev-heading">Recent KEVs</h2></div>
        <span className="panel-accent" aria-hidden="true" />
      </div>
      <p className="panel-explainer">Recently added catalog records. Use the explorer below for details.</p>
      {error && <p className="status-warning" role="status">{error} Displayed records may be stale.</p>}
      {loading && <p className="empty-message" role="status">Loading catalog records…</p>}
      {!loading && entries.length === 0 && <p className="empty-message">No KEV records are stored yet.</p>}
      {entries.length > 0 && (
        <ol className="recent-kev-list">
          {entries.map((entry) => (
            <li key={entry.cve_id}>
              <span className="recent-kev-cve">{entry.cve_id}</span>
              <span className="recent-kev-product" title={`${entry.vendor_project} / ${entry.product}`}>
                {entry.vendor_project} / {entry.product}
              </span>
              <time dateTime={displayDate(entry.date_added)}>{displayDate(entry.date_added)}</time>
            </li>
          ))}
        </ol>
      )}
      <a className="panel-link" href="#kev-explorer">SEARCH THE KEV CATALOG ↗</a>
    </section>
  )
}
