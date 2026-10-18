/**
 * Dashboard composition root. main.tsx mounts this file.
 *
 * App arranges existing KEV, EPSS, NVD, and OTX components around a real
 * globe. It reads only the existing /api/health route; individual panels own
 * their own requests. It never calls an external intelligence provider.
 */
import { useEffect, useState } from "react"

import "./App.css"
import { requestJson } from "./api/http"
import EpssStatusPanel from "./components/EpssStatusPanel"
import IocStatusPanel from "./components/IocStatusPanel"
import KevPanel from "./components/KevPanel"
import NvdStatusPanel from "./components/NvdStatusPanel"
import RecentKevPanel from "./components/RecentKevPanel"
import SecurityGlobe from "./components/SecurityGlobe"

/** Shape returned by the existing FastAPI health endpoint. */
interface HealthStatus {
  status: string
  api: boolean
  database: string
  redis: string
}

/** Assemble the SOC layout and keep platform health current. */
function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [healthError, setHealthError] = useState(false)
  const [epssRevision, setEpssRevision] = useState<string | null>(null)
  const [nvdRevision, setNvdRevision] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    /** Schedule the next health check only after this one finishes. */
    async function checkBackend() {
      try {
        const data = await requestJson<HealthStatus>("/api/health", {
          signal: controller.signal,
        })
        if (!controller.signal.aborted) {
          setHealth(data)
          setHealthError(false)
        }
      } catch {
        if (!controller.signal.aborted) {
          setHealth(null)
          setHealthError(true)
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

  // This indicator reports our API's reachability, not live provider activity.
  const backendState = healthError ? "OFFLINE" : !health ? "CHECKING"
    : health.api && health.status === "healthy" ? "CONNECTED" : "DEGRADED"

  return (
    <main className="dashboard">
      <header className="page-header">
        <div className="brand-block">
          <span className="brand-mark" aria-hidden="true">◈</span>
          <div>
            <p className="eyebrow">SECURITY OPERATIONS / OPEN-SOURCE INTELLIGENCE</p>
            <h1>Situation Monitor</h1>
            <p className="page-subtitle">Vulnerability intelligence and source health in one view</p>
          </div>
        </div>
        <div className="header-actions">
          <span className={`connection-state state-${backendState.toLowerCase()}`} role="status">
            <span className="state-light" aria-hidden="true" />
            API {backendState}
          </span>
          <a className="header-link" href="#kev-explorer">OPEN CVE EXPLORER ↗</a>
        </div>
      </header>

      <div className="source-tape" aria-label="Configured intelligence sources">
        <span>CISA KEV</span><span>FIRST EPSS</span><span>NVD</span><span>ALIENVAULT OTX</span>
        <span className="source-tape-note">Feed timestamps and status appear below</span>
      </div>

      <div className="soc-layout">
        <aside className="soc-rail" aria-label="Enrichment feed status">
          <div className="rail-heading"><span>01 / ENRICHMENT</span><span>FEED STATUS</span></div>
          <EpssStatusPanel onRefreshed={setEpssRevision} />
          <NvdStatusPanel onRefreshed={setNvdRevision} />
        </aside>

        <section className="globe-column" aria-label="Global view">
          <div className="globe-heading">
            <div><p className="eyebrow">GLOBAL VIEW / GEOSPATIAL LAYER</p><h2>World overview</h2></div>
            <span className="globe-phase">MAP READY · THREAT LAYER NEXT</span>
          </div>
          <SecurityGlobe />
          <div className="globe-footer">
            <span>Drag to explore · map data © OpenStreetMap contributors</span>
            <span>Threat locations appear only when a source supplies defensible coordinates.</span>
          </div>
        </section>

        <aside className="soc-rail" aria-label="Current vulnerability intelligence">
          <div className="rail-heading"><span>02 / INTELLIGENCE</span><span>KEV + OTX</span></div>
          <RecentKevPanel />
          <IocStatusPanel />
        </aside>
      </div>

      <section className="explorer-section" id="kev-explorer" aria-label="CVE explorer">
        <div className="explorer-intro">
          <p className="eyebrow">INVESTIGATE / CISA KEV CATALOG</p>
          <h2>Explore vulnerabilities</h2>
          <p>Search a CVE to inspect its KEV record, EPSS score, NVD context, and OTX observations.</p>
        </div>
        <KevPanel epssRevision={epssRevision} nvdRevision={nvdRevision} />
      </section>

      <footer className="dashboard-footer">
        <span>SITUATION MONITOR / SECURITY-FIRST BUILD</span>
        <span>API {backendState} · POSTGRESQL {health?.database ?? "UNKNOWN"} · REDIS {health?.redis ?? "UNKNOWN"}</span>
      </footer>
    </main>
  )
}

export default App
