/** Public OTX evidence for one selected KEV CVE.
 *
 * KevPanel mounts this component. It reads the narrow public IOC endpoint,
 * which returns source observations but no worker, queue, key, or attempt
 * details. OTX reports are context, not proof of exploitation of this CVE.
 */
import { useEffect, useState } from "react"
import { getPublicIocPage } from "../api/ioc"
import type { IOCPage } from "../types/ioc"
import "./Ioc.css"

/** Turn a known OTX pulse ID into a link on the fixed OTX HTTPS origin. */
function pulseLink(id: string): string | null {
  return /^[a-fA-F0-9]{24}$/.test(id)
    ? `https://otx.alienvault.com/pulse/${id}` : null
}

/** Read only a page of stored source observations for the selected CVE. */
export default function IocPanel({ cveId }: { cveId: string }) {
  const [page, setPage] = useState<IOCPage | null>(null)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    setPage(null)
    setLoading(true)

    /** Load stored evidence and recheck after the previous read finishes. */
    async function load() {
      try {
        const data = await getPublicIocPage(cveId, offset, false, controller.signal)
        if (!controller.signal.aborted) {
          if (offset > 0 && offset >= data.total) { setOffset(0); return }
          setPage(data)
          setError(null)
        }
      } catch {
        if (!controller.signal.aborted) setError("Unable to load OTX observations.")
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
          timer = setTimeout(() => { void load() }, 60_000)
        }
      }
    }

    void load()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [cveId, offset])

  return <section className="kev-detail-section ioc-panel" aria-label={`OTX evidence for ${cveId}`}>
    <h3>AlienVault OTX — related reports</h3>
    <p>These indicators appear in reports related to this CVE. They are not confirmed exploitation indicators for this CVE.</p>
    {loading && <p role="status">Loading OTX observations...</p>}
    {error && <p role="alert" className="error-message">{error} Earlier results may be stale.</p>}
    {page && (page.total === 0 ? <p>No source observations are available yet.</p> : <>
      <p>{page.total} source observations. The same indicator may appear in multiple reports.</p>
      <div className="kev-table-wrapper"><table className="kev-table ioc-table">
        <thead><tr><th>Indicator</th><th>Source report</th><th>Last observed</th></tr></thead>
        <tbody>{page.observations.map(item => {
          const observation = item.observation
          const href = pulseLink(observation.source_record_id)
          return <tr key={`${observation.source_record_id}-${observation.indicator.indicator_type}-${observation.indicator.value}`}>
            <td><strong>{observation.indicator.indicator_type}</strong>
              <pre>{observation.indicator.value}</pre></td>
            <td>{href ? <a href={href} target="_blank" rel="noopener noreferrer">
              {observation.source_record_name ?? "View OTX report"}</a>
              : <span>{observation.source_record_name ?? "OTX report"}</span>}</td>
            <td>{new Date(item.last_seen_at).toLocaleString()}</td>
          </tr>
        })}</tbody>
      </table></div>
      <div className="ioc-toolbar">
        <button type="button" disabled={offset === 0 || loading}
          onClick={() => setOffset(value => Math.max(0, value - 25))}>Previous</button>
        <span>{offset + 1}–{Math.min(offset + page.limit, page.total)} of {page.total}</span>
        <button type="button" disabled={offset + page.limit >= page.total || loading}
          onClick={() => setOffset(value => value + 25)}>Next</button>
      </div>
    </>)}
  </section>
}
