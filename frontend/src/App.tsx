import { useEffect, useState } from "react"

import "./App.css"

import { requestJson } from "./api/http"
import EpssStatusPanel from "./components/EpssStatusPanel"
import KevPanel from "./components/KevPanel"


interface HealthStatus {
  status: string
  api: boolean
  database: string
  redis: string
}


function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)
  // A successful scheduled or manual EPSS refresh invalidates an open score
  // card so users do not have to close/reopen a CVE to see the new value.
  const [epssRevision, setEpssRevision] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    async function checkBackend() {
      try {
        const data = await requestJson<HealthStatus>("/api/health", {
          signal: controller.signal,
        })
        if (!controller.signal.aborted) {
          setHealth(data)
          setHealthError(null)
        }
      } catch {
        if (!controller.signal.aborted) {
          setHealth(null)
          setHealthError("Unable to reach backend")
        }
      } finally {
        if (!controller.signal.aborted) {
          timer = setTimeout(() => { void checkBackend() }, 15_000)
        }
      }
    }

    void checkBackend()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [])

  return (
    <main className="dashboard">
      <header className="page-header">
        <div>
          <h1>Situation Monitor</h1>
          <p>Real-time security and global situational awareness.</p>
        </div>
      </header>

      <section className="status-card">
        <h2>Platform Status</h2>

        {healthError && <p className="error-message">{healthError}</p>}
        {health && (
          <div className="status-grid">
            <div>
              <strong>API</strong>
              <span>{health.api ? "healthy" : "unhealthy"}</span>
            </div>
            <div>
              <strong>PostgreSQL</strong>
              <span>{health.database}</span>
            </div>
            <div>
              <strong>Redis</strong>
              <span>{health.redis}</span>
            </div>
          </div>
        )}
      </section>

      <EpssStatusPanel onRefreshed={setEpssRevision} />
      <KevPanel epssRevision={epssRevision} />
    </main>
  )
}


export default App
