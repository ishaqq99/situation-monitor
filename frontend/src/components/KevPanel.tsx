// Complete KEV dashboard with locally stored EPSS and NVD enrichment in CVE details.

import { useCallback, useEffect, useRef, useState } from "react"
import type { FormEvent } from "react"

import {
  getKevDetails,
  getKevStatus,
  getLatestKev,
  refreshKev,
  searchKev,
} from "../api/kev"
import type { KEVEntry, KEVFeedStatus } from "../types/kev"
import EpssScore from "./EpssScore"
import NvdDetails from "./NvdDetails"


type ViewMode = "latest" | "search"

const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : "Request failed"


function KevPanel({ epssRevision, nvdRevision }: {
  epssRevision: string | null
  nvdRevision: string | null
}) {
  const [entries, setEntries] = useState<KEVEntry[]>([])
  const [feedStatus, setFeedStatus] = useState<KEVFeedStatus | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [operation, setOperation] = useState<ViewMode | null>("latest")
  const [refreshing, setRefreshing] = useState(false)
  const [searchTerm, setSearchTerm] = useState("")
  const [viewMode, setViewMode] = useState<ViewMode>("latest")
  const [selectedKev, setSelectedKev] = useState<KEVEntry | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  // Separate controllers prevent an old list or detail response from
  // overwriting a newer user action.
  const listRequest = useRef<AbortController | null>(null)
  const detailRequest = useRef<AbortController | null>(null)
  const refreshRequest = useRef<AbortController | null>(null)
  const currentView = useRef<ViewMode>("latest")
  const detailsElement = useRef<HTMLDivElement | null>(null)
  const detailActive = useRef(false)
  const selectedButton = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (!selectedKev) return
    // Wait for React's render before moving focus/scroll to the loaded card.
    detailsElement.current?.focus({ preventScroll: true })
    detailsElement.current?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "instant" : "smooth",
      block: "start",
    })
  }, [selectedKev])

  const loading = operation === "latest"
  const searching = operation === "search"

  const closeDetails = useCallback(() => {
    detailRequest.current?.abort()
    detailRequest.current = null
    setDetailLoading(false)
    setSelectedKev(null)
    detailActive.current = false
  }, [])

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

      if (controller.signal.aborted) return
      setEntries(rows)
      setViewMode(mode)
      currentView.current = mode
    } catch (requestError) {
      if (!controller.signal.aborted) setError(messageOf(requestError))
    } finally {
      if (listRequest.current === controller) {
        listRequest.current = null
        setOperation(null)
      }
    }
  }, [closeDetails])

  useEffect(() => {
    const controller = new AbortController()
    listRequest.current = controller

    async function initialLoad() {
      try {
        const rows = await getLatestKev(10, controller.signal)
        if (!controller.signal.aborted) setEntries(rows)
      } catch (requestError) {
        if (!controller.signal.aborted) setError(messageOf(requestError))
      } finally {
        if (listRequest.current === controller && !controller.signal.aborted) {
          listRequest.current = null
          setOperation(null)
        }
      }
    }

    void initialLoad()
    return () => {
      listRequest.current?.abort()
      detailRequest.current?.abort()
      refreshRequest.current?.abort()
    }
  }, [])

  useEffect(() => {
    // KEV status polling is independent from list loading. Redis failure does
    // not prevent PostgreSQL rows from remaining visible.
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let previousTimestamp: string | null | undefined

    async function pollStatus() {
      try {
        const status = await getKevStatus(controller.signal)
        if (controller.signal.aborted) return

        setFeedStatus(status)
        setStatusError(null)

        if (
          previousTimestamp !== status.last_refreshed_at
          && currentView.current === "latest"
          && !listRequest.current
          && !refreshRequest.current
          && !detailActive.current
        ) {
          previousTimestamp = status.last_refreshed_at
          if (status.last_refreshed_at !== null) void loadList("latest")
        }
      } catch {
        if (!controller.signal.aborted) {
          setFeedStatus(null)
          setStatusError(
            "Feed status is unavailable. Stored KEV data can still be viewed.",
          )
        }
      } finally {
        if (!controller.signal.aborted) {
          timer = setTimeout(() => { void pollStatus() }, 5_000)
        }
      }
    }

    void pollStatus()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [loadList])

  async function handleRefresh() {
    if (refreshRequest.current) return

    const controller = new AbortController()
    refreshRequest.current = controller
    listRequest.current?.abort()
    listRequest.current = null

    setOperation(null)
    closeDetails()
    setRefreshing(true)
    setMessage(null)
    setError(null)

    try {
      const result = await refreshKev(controller.signal)
      if (controller.signal.aborted) return

      setMessage(
        `Refresh complete: ${result.fetched_count} KEVs fetched, `
        + `${result.cached_count} cached.`,
      )
      setSearchTerm("")
      await loadList("latest")
    } catch (requestError) {
      if (!controller.signal.aborted) setError(messageOf(requestError))
    } finally {
      if (refreshRequest.current === controller) {
        refreshRequest.current = null
        if (!controller.signal.aborted) setRefreshing(false)
      }
    }
  }

  async function handleSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const query = searchTerm.trim()
    if (!query || refreshRequest.current) return
    setMessage(null)
    await loadList("search", query)
  }

  async function handleClearSearch() {
    if (refreshRequest.current) return
    setSearchTerm("")
    setMessage(null)
    await loadList("latest")
  }

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

  const refreshDisabled = refreshing || feedStatus?.refresh_in_progress === true

  return (
    <section className="kev-panel">
      <div className="kev-header">
        <div>
          <h2>Known Exploited Vulnerabilities</h2>
          <p>Latest CISA KEV intelligence enriched with FIRST EPSS and NVD</p>
        </div>
        <button onClick={handleRefresh} disabled={refreshDisabled}>
          {refreshDisabled ? "Refreshing..." : "Refresh KEV"}
        </button>
      </div>

      <div className="kev-status">
        <span>Cached: {feedStatus?.cached_entries ?? 0}</span>
        <span>
          Last refresh:{" "}
          {feedStatus?.last_refreshed_at
            ? new Date(feedStatus.last_refreshed_at).toLocaleString()
            : "Not recorded"}
        </span>
      </div>

      <form className="kev-search" onSubmit={handleSearch}>
        <input
          type="text"
          value={searchTerm}
          maxLength={100}
          aria-label="Search CISA KEV catalog"
          onChange={(event) => setSearchTerm(event.target.value)}
          placeholder="Search CVE, vendor, product, or vulnerability..."
        />
        <button type="submit" disabled={searching || refreshing}>
          {searching ? "Searching..." : "Search"}
        </button>
        {viewMode === "search" && (
          <button type="button" className="clear-button" onClick={handleClearSearch}>
            Clear
          </button>
        )}
      </form>

      {statusError && <p className="status-warning" role="status">{statusError}</p>}
      {detailLoading && <p role="status">Loading CVE details...</p>}
      {loading && <p>Loading KEV data...</p>}
      {error && <p className="error-message" role="alert">{error}</p>}
      {message && <p className="success-message">{message}</p>}

      {!loading && (
        <>
          <h3>
            {viewMode === "search"
              ? `Search Results (${entries.length})`
              : "Latest KEVs"}
          </h3>

          {entries.length === 0 ? (
            <p className="empty-message">
              {viewMode === "search"
                ? "No matching CISA KEVs found."
                : "No KEV data is stored yet. The startup refresh may still be running."}
            </p>
          ) : (
            <div className="kev-table-wrapper">
              <table className="kev-table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Added</th>
                    <th>Ransomware</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.cve_id}>
                      <td>
                        <button
                          className="cve-link"
                          onClick={(event) => handleSelectCve(entry.cve_id, event.currentTarget)}
                        >
                          {entry.cve_id}
                        </button>
                      </td>
                      <td>{entry.vendor_project}</td>
                      <td>{entry.product}</td>
                      <td>{entry.date_added}</td>
                      <td>{entry.known_ransomware_campaign_use}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {selectedKev && (
        <div className="kev-details" ref={detailsElement} tabIndex={-1}
          role="region" aria-labelledby="selected-cve-heading">
          <div className="kev-details-header">
            <div>
              <h2 id="selected-cve-heading">{selectedKev.cve_id}</h2>
              <p>{selectedKev.vulnerability_name}</p>
            </div>
            <button className="close-button" onClick={() => {
              closeDetails()
              selectedButton.current?.focus()
            }}>Close</button>
          </div>

          <div className="kev-details-grid">
            <div><strong>Vendor</strong><p>{selectedKev.vendor_project}</p></div>
            <div><strong>Product</strong><p>{selectedKev.product}</p></div>
            <div><strong>Date Added</strong><p>{selectedKev.date_added}</p></div>
            <div><strong>Remediation Due</strong><p>{selectedKev.due_date}</p></div>
            <div>
              <strong>Known Ransomware Use</strong>
              <p>{selectedKev.known_ransomware_campaign_use}</p>
            </div>
            <div>
              <strong>CWE</strong>
              <p>
                {selectedKev.cwes.length > 0
                  ? selectedKev.cwes.join(", ")
                  : "Not provided"}
              </p>
            </div>
          </div>

          <EpssScore key={`epss-${selectedKev.cve_id}`} cveId={selectedKev.cve_id}
            revision={epssRevision} />

          <NvdDetails key={`nvd-${selectedKev.cve_id}`} cveId={selectedKev.cve_id}
            revision={nvdRevision} />

          <div className="kev-detail-section">
            <strong>Description</strong>
            <p>{selectedKev.short_description}</p>
          </div>
          <div className="kev-detail-section">
            <strong>Required Action</strong>
            <p>{selectedKev.required_action}</p>
          </div>
          {selectedKev.notes && (
            <div className="kev-detail-section">
              <strong>Notes</strong>
              <p>{selectedKev.notes}</p>
            </div>
          )}
        </div>
      )}
    </section>
  )
}


export default KevPanel
