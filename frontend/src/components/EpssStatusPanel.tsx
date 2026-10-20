// EPSS feed status and an explicit manual refresh control.

import { useCallback, useEffect, useRef, useState } from "react"

import { getEpssStatus, refreshEpss } from "../api/epss"
import type { EPSSFeedStatus } from "../types/epss"


const messageOf = (error: unknown) =>
  error instanceof Error ? error.message : "EPSS request failed"


function EpssStatusPanel({ onRefreshed }: {
  onRefreshed: (timestamp: string | null) => void
}) {
  const [status, setStatus] = useState<EPSSFeedStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const refreshRequest = useRef<AbortController | null>(null)

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await getEpssStatus(signal)
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
      const result = await refreshEpss(controller.signal)
      if (controller.signal.aborted) return
      setMessage(
        `EPSS refresh complete: ${result.stored_count} of `
        + `${result.requested_count} requested scores stored.`,
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
      <h2>EPSS Enrichment</h2>

      <div className="status-grid">
        <div>
          <strong>Stored scores</strong>
          <span>{status?.total_stored_scores ?? "Unavailable"}</span>
        </div>
        <div>
          <strong>Last refresh</strong>
          <span>
            {status?.last_refreshed_at
              ? new Date(status.last_refreshed_at).toLocaleString()
              : "Not recorded"}
          </span>
        </div>
        <div>
          <strong>State</strong>
          <span>{refreshDisabled ? "Refreshing" : statusError ? "Unavailable"
            : !status ? "Loading" : status.last_error ? "Retrying after error"
            : !status.last_refreshed_at ? "Waiting for first refresh" : "Ready"}</span>
        </div>
      </div>

      {/* Public deployments refresh in the background; local dev keeps this action. */}
      {import.meta.env.VITE_PUBLIC_DEMO !== "true" && (
        <button className="primary-button" onClick={handleRefresh} disabled={refreshDisabled}>
          {refreshDisabled ? "Refreshing EPSS..." : "Refresh EPSS"}
        </button>
      )}

      {error && <p className="error-message" role="alert">{error}</p>}
      {statusError && <p className="status-warning" role="status">{statusError}</p>}
      {status?.last_error && <p className="status-warning">{status.last_error}</p>}
      {message && <p className="success-message" role="status">{message}</p>}
    </section>
  )
}


export default EpssStatusPanel
