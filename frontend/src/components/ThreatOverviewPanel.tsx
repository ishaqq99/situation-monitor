/** Ranked source data for the globe.
 * App.tsx owns the polling and passes a snapshot here and to SecurityGlobe.
 * This panel never starts a refresh or makes a direct provider request.
 */
import type { ThreatOverview } from "../types/threat"

interface Props {
  overview: ThreatOverview | null
  loading: boolean
  error: boolean
}

/** Render a concise public explanation and top source-country shares. */
export default function ThreatOverviewPanel({ overview, loading, error }: Props) {
  return <section className="status-card threat-panel" aria-labelledby="threat-heading">
    <p className="eyebrow">CLOUDFLARE RADAR / LAST 24 HOURS</p>
    <h2 id="threat-heading">Web threat activity</h2>
    <p className="panel-explainer">Share of mitigated HTTP requests by source IP country across Cloudflare's network.</p>
    {loading && !overview && <p role="status">Loading recent activity…</p>}
    {error && <p role="status" className="status-warning">Current data is unavailable.
      {overview && " The last saved snapshot is shown."}</p>}
    {overview && <>
      <p className="threat-period">Window: {new Date(overview.window_start).toLocaleString()} – {new Date(overview.window_end).toLocaleString()}</p>
      {overview.stale && <p className="status-warning">Showing an earlier snapshot while the source is unavailable.</p>}
      <ol className="threat-list">{overview.countries.slice(0, 10).map(row =>
        <li key={row.country_code}>
          <span>{row.country_name}</span><strong>{row.percentage.toFixed(2)}%</strong>
        </li>)}</ol>
      <p className="threat-method">Map points represent countries, not exact attack locations or attacker homes. This feed is not linked to a CVE.</p>
    </>}
    <a className="panel-link" href="https://radar.cloudflare.com/security-and-attacks"
      target="_blank" rel="noopener noreferrer">SOURCE: CLOUDFLARE RADAR ↗</a>
  </section>
}
