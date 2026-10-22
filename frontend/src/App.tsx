/** Public dashboard composition.
 *
 * main.tsx mounts App. App polls only the read-only threat overview; feature
 * components read stored KEV, EPSS, NVD, and OTX evidence. Operational health,
 * worker status, and manual refresh controls are intentionally not mounted.
 */
import { useEffect, useState } from "react"

import "./App.css"
import { getThreatOverview } from "./api/threat"
import KevPanel from "./components/KevPanel"
import RecentKevPanel from "./components/RecentKevPanel"
import SecurityGlobe from "./components/SecurityGlobe"
import ThreatOverviewPanel from "./components/ThreatOverviewPanel"
import type { ThreatOverview } from "./types/threat"

/** Arrange the public page and share one threat snapshot with list and map. */
function App() {
  const [threats, setThreats] = useState<ThreatOverview | null>(null)
  const [threatError, setThreatError] = useState(false)
  const [threatLoading, setThreatLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined

    /** Read cached threat data and retry five minutes after each completed read. */
    async function loadThreats() {
      try {
        const snapshot = await getThreatOverview(controller.signal)
        if (!controller.signal.aborted) {
          setThreats(snapshot)
          setThreatError(false)
        }
      } catch {
        if (!controller.signal.aborted) setThreatError(true)
      } finally {
        if (!controller.signal.aborted) {
          setThreatLoading(false)
          timer = setTimeout(() => { void loadThreats() }, 300_000)
        }
      }
    }

    void loadThreats()
    return () => { controller.abort(); clearTimeout(timer) }
  }, [])

  return (
    <main className="dashboard">
      <header className="page-header">
        <div className="brand-block">
          <span className="brand-mark" aria-hidden="true">◈</span>
          <div>
            <p className="eyebrow">SECURITY OPERATIONS / OPEN-SOURCE INTELLIGENCE</p>
            <h1>Situation Monitor</h1>
            <p className="page-subtitle">Vulnerabilities and recent web threat activity in one view</p>
          </div>
        </div>
        <div className="header-actions">
          <a className="header-link" href="#kev-explorer">OPEN CVE EXPLORER ↗</a>
        </div>
      </header>

      <div className="source-tape" aria-label="Intelligence sources">
        <span>CISA KEV</span><span>FIRST EPSS</span><span>NVD</span>
        <span>ALIENVAULT OTX</span><span>CLOUDFLARE RADAR</span>
      </div>

      <div className="soc-layout">
        <aside className="soc-rail" aria-label="Recent web threat activity">
          <div className="rail-heading"><span>01 / THREAT ACTIVITY</span><span>24H VIEW</span></div>
          <ThreatOverviewPanel overview={threats} loading={threatLoading} error={threatError} />
        </aside>

        <section className="globe-column" aria-label="Global view">
          <div className="globe-heading">
            <div><p className="eyebrow">GLOBAL VIEW / COUNTRY SUMMARY</p><h2>World overview</h2></div>
            <span className="globe-phase">RECENT WEB THREATS</span>
          </div>
          <SecurityGlobe overview={threats} />
          <div className="globe-footer">
            <span>Drag to explore · map data © OpenStreetMap contributors</span>
            <span>Markers represent source IP countries; points are illustrative country positions.</span>
          </div>
        </section>

        <aside className="soc-rail" aria-label="Current vulnerability intelligence">
          <div className="rail-heading"><span>02 / VULNERABILITIES</span><span>CISA KEV</span></div>
          <RecentKevPanel />
        </aside>
      </div>

      <section className="explorer-section" id="kev-explorer" aria-label="CVE explorer">
        <div className="explorer-intro">
          <p className="eyebrow">INVESTIGATE / CISA KEV CATALOG</p>
          <h2>Explore vulnerabilities</h2>
          <p>Search a CVE to inspect its KEV record, EPSS score, NVD context, and OTX observations.</p>
        </div>
        <KevPanel />
      </section>

      <footer className="dashboard-footer">
        <span>SITUATION MONITOR</span>
        <span>Threat summary: <a href="https://radar.cloudflare.com/security-and-attacks">Cloudflare Radar</a> · CC BY-NC 4.0</span>
      </footer>
    </main>
  )
}

export default App
