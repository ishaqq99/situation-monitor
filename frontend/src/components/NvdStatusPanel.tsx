// NVD enrichment coverage/status plus an explicit one-batch manual refresh.
//
// FILE ROLE
// ---------
// This component does not decide which CVEs need NVD. It asks the backend for
// status and lets the user trigger the same protected service the worker uses.
// The backend still owns locking, candidate selection, pacing, and storage.

import { useCallback, useEffect, useRef, useState } from "react"

import { getNvdStatus, refreshNvd } from "../api/nvd"
import type { NVDFeedStatus } from "../types/nvd"


const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : "NVD request failed"


function NvdStatusPanel({ onRefreshed }: {
  onRefreshed: (timestamp: string | null) => void
}) {
  const [status, setStatus] = useState<NVDFeedStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const refreshRequest = useRef<AbortController | null>(null)

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await getNvdStatus(signal)
      if (!signal?.aborted) {
        setStatus(result)
        setStatusError(null)
        onRefreshed(result.last_refreshed_at)
      }
    } catch (requestError) {
      if (!signal?.aborted) {
        setStatus(null)
        setStatusError(messageOf(requestError))
      }
    }
  }, [onRefreshed])

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    async function poll() {
      await loadStatus(controller.signal)
      if (!controller.signal.aborted) {
        timer = setTimeout(() => { void poll() }, 15_000)
      }
    }

    void poll()
    return () => {
      controller.abort()
      refreshRequest.current?.abort()
      clearTimeout(timer)
    }
  }, [loadStatus])

  async function handleRefresh() {
    if (refreshRequest.current) return

    const controller = new AbortController()
    refreshRequest.current = controller
    setRefreshing(true)
    setError(null)
    setMessage(null)

    try {
      const result = await refreshNvd(controller.signal)
      if (controller.signal.aborted) return

      setMessage(
        `NVD batch complete: ${result.stored_count} of ${result.requested_count} `
        + `requested CVEs stored; ${result.remaining_count} candidates remain.`,
      )
      onRefreshed(result.refreshed_at)
      await loadStatus(controller.signal)
    } catch (requestError) {
      if (!controller.signal.aborted) setError(messageOf(requestError))
    } finally {
      if (refreshRequest.current === controller) {
        refreshRequest.current = null
        if (!controller.signal.aborted) setRefreshing(false)
      }
    }
  }

  const refreshDisabled = refreshing || status?.refresh_in_progress === true

  return (
    <section className="status-card">
      <h2>NVD Enrichment</h2>

      <div className="status-grid">
        <div>
          <strong>Coverage</strong>
          <span>
            {status
              ? `${status.total_stored_cves} / ${status.total_kev_cves} KEVs`
              : "Unavailable"}
          </span>
        </div>
        <div>
          <strong>Pending / stale</strong>
          <span>{status?.pending_count ?? "Unavailable"}</span>
        </div>
        <div>
          <strong>Last batch</strong>
          <span>
            {status?.last_refreshed_at
              ? new Date(status.last_refreshed_at).toLocaleString()
              : "Not recorded"}
          </span>
        </div>
        <div>
          <strong>Last batch failures</strong>
          <span>{status?.failed_count ?? "Unavailable"}</span>
        </div>
        <div>
          <strong>Last batch unavailable</strong>
          <span>{status?.unavailable_count ?? "Unavailable"}</span>
        </div>
        <div>
          <strong>State</strong>
          <span>
            {refreshDisabled ? "Refreshing"
              : statusError ? "Unavailable"
              : !status ? "Loading"
              : status.last_error ? "Retrying after error"
              : status.pending_count > 0 ? "Backfilling / refreshing"
              : "Ready"}
          </span>
        </div>
      </div>

      {/* The public site shows stored results; its worker owns refreshes. */}
      {import.meta.env.VITE_PUBLIC_DEMO !== "true" && (
        <button className="primary-button" onClick={handleRefresh} disabled={refreshDisabled}>
          {refreshDisabled ? "Refreshing NVD..." : "Refresh NVD Batch"}
        </button>
      )}

      {error && <p className="error-message" role="alert">{error}</p>}
      {statusError && <p className="status-warning" role="status">{statusError}</p>}
      {status?.last_error && <p className="status-warning">{status.last_error}</p>}
      {message && <p className="success-message" role="status">{message}</p>}
    </section>
  )
}


export default NvdStatusPanel
