// Stored NVD enrichment and CVSS change history for the currently selected KEV.
//
// FILE ROLE
// ---------
// KevPanel renders this component after a user opens a CVE. The component reads
// PostgreSQL-backed FastAPI endpoints only; it never triggers a live NVD lookup
// merely because a user opened a CVE.
//
// DATA FLOW
// ---------
// selected KEV -> NvdDetails -> frontend api/nvd.ts -> FastAPI -> PostgreSQL
//
// ``revision`` changes after a successful scheduled/manual status-panel refresh
// so an already-open CVE can reload its stored NVD state without being closed.

import { useEffect, useState } from "react"

import { getNvdCvssHistory, getNvdDetails } from "../api/nvd"
import type { NVDCVE, NVDCVSSChange, NVDCVSSMetric } from "../types/nvd"


const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : "NVD request failed"


function formatDateTime(value: string): string {
  return new Date(value).toLocaleString()
}


function metricLabel(metric: NVDCVSSMetric | null): string {
  if (!metric) return "No CVSS"
  const severity = metric.base_severity ? ` ${metric.base_severity}` : ""
  const source = metric.source ? ` — ${metric.source}` : ""
  return `CVSS ${metric.cvss_version}: ${metric.base_score.toFixed(1)}${severity}${source}`
}


function NvdDetails({ cveId, revision }: {
  cveId: string
  revision: string | null
}) {
  const [record, setRecord] = useState<NVDCVE | null>(null)
  const [history, setHistory] = useState<NVDCVSSChange[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    async function loadNvd() {
      setLoading(true)
      setError(null)

      try {
        const [details, changes] = await Promise.all([
          getNvdDetails(cveId, controller.signal),
          getNvdCvssHistory(cveId, controller.signal),
        ])

        if (!controller.signal.aborted) {
          setRecord(details)
          setHistory(changes)
        }
      } catch (requestError) {
        if (!controller.signal.aborted) {
          setRecord(null)
          setHistory([])
          setError(messageOf(requestError))
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }

    void loadNvd()
    return () => controller.abort()
  }, [cveId, revision])

  return (
    <div className="kev-detail-section">
      <strong>NVD technical enrichment</strong>
      <p>
        NVD supplies technical severity, weakness, affected-platform, and
        reference context. Opening this CVE reads the stored local copy.
      </p>

      {loading && <p role="status">Loading stored NVD enrichment...</p>}
      {error && <p className="error-message" role="alert">{error}</p>}

      {!loading && !error && record === null && (
        <p>
          No NVD enrichment is stored yet. The background KEV enrichment
          backfill may still be processing this CVE.
        </p>
      )}

      {!loading && !error && record && (
        <>
          <div className="kev-details-grid">
            <div>
              <strong>CVSS</strong>
              <p>{record.cvss ? record.cvss.base_score.toFixed(1) : "Unavailable"}</p>
            </div>
            <div>
              <strong>Severity</strong>
              <p>{record.cvss?.base_severity ?? "Unavailable"}</p>
            </div>
            <div>
              <strong>CVSS Version</strong>
              <p>{record.cvss?.cvss_version ?? "Unavailable"}</p>
            </div>
            <div>
              <strong>NVD Status</strong>
              <p>{record.vuln_status ?? "Not provided"}</p>
            </div>
            <div>
              <strong>NVD Published</strong>
              <p>{formatDateTime(record.published_at)}</p>
            </div>
            <div>
              <strong>NVD Last Modified</strong>
              <p>{formatDateTime(record.last_modified_at)}</p>
            </div>
          </div>

          {record.cvss && (
            <>
              <div className="kev-detail-section">
                <strong>CVSS Vector</strong>
                <p>{record.cvss.vector_string}</p>
              </div>
              <div className="kev-detail-section">
                <strong>CVSS Assessment Source</strong>
                <p>
                  {record.cvss.source ?? "Not provided"}
                  {record.cvss.metric_type ? ` (${record.cvss.metric_type})` : ""}
                </p>
              </div>
            </>
          )}

          <div className="kev-detail-section">
            <strong>NVD Description</strong>
            <p>{record.description ?? "No NVD description is stored."}</p>
          </div>

          <div className="kev-detail-section">
            <strong>NVD CWE</strong>
            <p>{record.cwes.length ? record.cwes.join(", ") : "Not provided"}</p>
          </div>

          <div className="kev-detail-section">
            <strong>Affected CPEs</strong>
            {record.affected_cpes.length === 0 ? (
              <p>No vulnerable CPE criteria are stored.</p>
            ) : (
              <>
                <ul>
                  {record.affected_cpes.slice(0, 6).map((cpe) => (
                    <li key={cpe}>{cpe}</li>
                  ))}
                </ul>
                {record.affected_cpes.length > 6 && (
                  <p>+{record.affected_cpes.length - 6} additional affected CPEs</p>
                )}
              </>
            )}
          </div>

          <div className="kev-detail-section">
            <strong>References</strong>
            {record.reference_urls.length === 0 ? (
              <p>No NVD references are stored.</p>
            ) : (
              <ul>
                {record.reference_urls.slice(0, 5).map((url) => (
                  <li key={url}>
                    <a href={url} target="_blank" rel="noreferrer">{url}</a>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="kev-detail-section">
            <strong>CVSS Change History</strong>
            {history.length === 0 ? (
              <p>No selected-CVSS changes have been observed yet.</p>
            ) : (
              <div className="kev-table-wrapper">
                <table className="kev-table">
                  <thead>
                    <tr>
                      <th>Observed</th>
                      <th>Previous</th>
                      <th>Current</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((change) => (
                      <tr key={`${change.observed_at}-${change.nvd_last_modified_at}`}>
                        <td>{formatDateTime(change.observed_at)}</td>
                        <td>{metricLabel(change.previous_cvss)}</td>
                        <td>{metricLabel(change.current_cvss)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="kev-detail-section">
            <strong>Situation Monitor fetched NVD</strong>
            <p>{formatDateTime(record.fetched_at)}</p>
          </div>
        </>
      )}
    </div>
  )
}


export default NvdDetails
