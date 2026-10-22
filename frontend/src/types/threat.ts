/** Public shape returned by GET /api/threat/overview. No provider token or IPs. */
export interface ThreatCountry {
  country_code: string
  country_name: string
  percentage: number
  rank: number
}

/** A dated source snapshot; stale means a cached copy survived a fetch error. */
export interface ThreatOverview {
  source: string
  metric: string
  window_start: string
  window_end: string
  source_updated_at: string | null
  fetched_at: string
  stale: boolean
  countries: ThreatCountry[]
}
