/** Public CISA KEV explorer.
 *
 * App.tsx mounts this component. It reads stored KEV data through api/kev.ts
 * and opens EPSS, NVD, and OTX evidence panels for one selected CVE. Workers
 * update the backend; this component has no manual refresh or status action.
 */
import { useCallback, useEffect, useRef, useState } from "react"
import type { FormEvent } from "react"

import { getKevDetails, getLatestKev, searchKev } from "../api/kev"
import type { KEVEntry } from "../types/kev"
import EpssScore from "./EpssScore"
import NvdDetails from "./NvdDetails"
import IocPanel from "./IocPanel"

type ViewMode = "latest" | "search"

/** Convert an unknown request failure into safe display text. */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "Request failed"
}

/** Search the stored catalog and render details without exposing operations. */
export default function KevPanel() {
  const [entries, setEntries] = useState<KEVEntry[]>([])
  const [operation, setOperation] = useState<ViewMode | null>("latest")
  const [searchTerm, setSearchTerm] = useState("")
  const [viewMode, setViewMode] = useState<ViewMode>("latest")
  const [selectedKev, setSelectedKev] = useState<KEVEntry | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const listRequest = useRef<AbortController | null>(null)
  const detailRequest = useRef<AbortController | null>(null)
  const currentView = useRef<ViewMode>("latest")
  const detailActive = useRef(false)
  const selectedButton = useRef<HTMLButtonElement | null>(null)
  const detailsElement = useRef<HTMLDivElement | null>(null)

  // Bring the selected record into view after React renders it. This also
  // gives keyboard users an obvious destination after selecting a CVE.
  useEffect(() => {
    if (!selectedKev) return
    detailsElement.current?.focus({ preventScroll: true })
    detailsElement.current?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "instant" : "smooth",
      block: "start",
    })
  }, [selectedKev])

  /** Cancel an obsolete detail read before changing the selected record. */
  const closeDetails = useCallback(() => {
    detailRequest.current?.abort()
    detailRequest.current = null
    setDetailLoading(false)
    setSelectedKev(null)
    detailActive.current = false
  }, [])

  /** Read latest rows or search matches; only the newest request may update UI. */
  const loadList = useCallback(async (mode: ViewMode, query = "") => {
    listRequest.current?.abort()
    const controller = new AbortController()
    listRequest.current = controller
    closeDetails()
    setOperation(mode)
    setError(null)
    try {
      const rows = mode === "search"
        ? await searchKev(query, controller.signal)
        : await getLatestKev(10, controller.signal)
      if (!controller.signal.aborted) {
        setEntries(rows)
        setViewMode(mode)
        currentView.current = mode
      }
    } catch (requestError) {
      if (!controller.signal.aborted) setError(messageOf(requestError))
    } finally {
      if (listRequest.current === controller) {
        listRequest.current = null
        if (!controller.signal.aborted) setOperation(null)
      }
    }
  }, [closeDetails])

  useEffect(() => {
    void loadList("latest")
    return () => {
      listRequest.current?.abort()
      detailRequest.current?.abort()
    }
  }, [loadList])

  // Keep an idle Latest view current without interrupting an open detail or
  // search. The backend worker owns ingestion; this is only a stored-data read.
  useEffect(() => {
    const timer = setInterval(() => {
      if (currentView.current === "latest" && !detailActive.current && !listRequest.current) {
        void loadList("latest")
      }
    }, 300_000)
    return () => clearInterval(timer)
  }, [loadList])

  /** Submit a visitor's search term to the stored KEV search route. */
  async function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const query = searchTerm.trim()
    if (query) await loadList("search", query)
  }

  /** Clear the search and restore the latest catalog records. */
  async function handleClearSearch() {
    setSearchTerm("")
    await loadList("latest")
  }

  /** Read full KEV detail before mounting its three enrichment panels. */
  async function handleSelectCve(cveId: string, button: HTMLButtonElement) {
    closeDetails()
    selectedButton.current = button
    detailActive.current = true
    const controller = new AbortController()
    detailRequest.current = controller
    setDetailLoading(true)
    setError(null)
    try {
      const details = await getKevDetails(cveId, controller.signal)
      if (!controller.signal.aborted) setSelectedKev(details)
    } catch (requestError) {
      if (!controller.signal.aborted) {
        detailActive.current = false
        setError(messageOf(requestError))
      }
    } finally {
      if (detailRequest.current === controller) {
        detailRequest.current = null
        setDetailLoading(false)
      }
    }
  }

  const loading = operation === "latest"
  const searching = operation === "search"

  return (
    <section className="kev-panel">
      <div className="kev-header">
        <div>
          <h2>Known Exploited Vulnerabilities</h2>
          <p>Latest CISA KEV intelligence enriched with FIRST EPSS and NVD</p>
        </div>
      </div>

      <form className="kev-search" onSubmit={handleSearch}>
        <input type="text" value={searchTerm} maxLength={100}
          aria-label="Search CISA KEV catalog"
          onChange={event => setSearchTerm(event.target.value)}
          placeholder="Search CVE, vendor, product, or vulnerability..." />
        <button type="submit" disabled={searching}>
          {searching ? "Searching..." : "Search"}
        </button>
        {viewMode === "search" && <button type="button" className="clear-button"
          onClick={handleClearSearch}>Clear</button>}
      </form>

      {detailLoading && <p role="status">Loading CVE details...</p>}
      {loading && <p>Loading KEV data...</p>}
      {error && <p className="error-message" role="alert">{error}</p>}

      {!loading && <>
        <h3>{viewMode === "search" ? `Search Results (${entries.length})` : "Latest KEVs"}</h3>
        {entries.length === 0 ? <p className="empty-message">
          {viewMode === "search" ? "No matching CISA KEVs found."
            : "No KEV records are available right now."}</p> :
          <div className="kev-table-wrapper"><table className="kev-table">
            <thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Added</th><th>Ransomware</th></tr></thead>
            <tbody>{entries.map(entry => <tr key={entry.cve_id}>
              <td><button className="cve-link" onClick={event =>
                handleSelectCve(entry.cve_id, event.currentTarget)}>{entry.cve_id}</button></td>
              <td>{entry.vendor_project}</td><td>{entry.product}</td>
              <td>{entry.date_added}</td><td>{entry.known_ransomware_campaign_use}</td>
            </tr>)}</tbody>
          </table></div>}
      </>}

      {selectedKev && <div className="kev-details" ref={detailsElement} tabIndex={-1}
        role="region" aria-labelledby="selected-cve-heading">
        <div className="kev-details-header">
          <div><h2 id="selected-cve-heading">{selectedKev.cve_id}</h2>
            <p>{selectedKev.vulnerability_name}</p></div>
          <button className="close-button" onClick={() => {
            closeDetails(); selectedButton.current?.focus()
          }}>Close</button>
        </div>

        <div className="kev-details-grid">
          <div><strong>Vendor</strong><p>{selectedKev.vendor_project}</p></div>
          <div><strong>Product</strong><p>{selectedKev.product}</p></div>
          <div><strong>Date Added</strong><p>{selectedKev.date_added}</p></div>
          <div><strong>Remediation Due</strong><p>{selectedKev.due_date}</p></div>
          <div><strong>Known Ransomware Use</strong><p>{selectedKev.known_ransomware_campaign_use}</p></div>
          <div><strong>CWE</strong><p>{selectedKev.cwes.length
            ? selectedKev.cwes.join(", ") : "Not provided"}</p></div>
        </div>

        <EpssScore key={`epss-${selectedKev.cve_id}`} cveId={selectedKev.cve_id} revision={null} />
        <NvdDetails key={`nvd-${selectedKev.cve_id}`} cveId={selectedKev.cve_id} revision={null} />
        <IocPanel key={`ioc-${selectedKev.cve_id}`} cveId={selectedKev.cve_id} />

        <div className="kev-detail-section"><strong>Description</strong>
          <p>{selectedKev.short_description}</p></div>
        <div className="kev-detail-section"><strong>Required Action</strong>
          <p>{selectedKev.required_action}</p></div>
        {selectedKev.notes && <div className="kev-detail-section"><strong>Notes</strong>
          <p>{selectedKev.notes}</p></div>}
      </div>}
    </section>
  )
}
