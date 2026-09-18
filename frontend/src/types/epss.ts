// TypeScript contracts matching backend/app/models/epss.py.

export interface EPSSScore {
  cve_id: string
  epss_score: number
  percentile: number
  score_date: string
}

export interface EPSSRefreshResult {
  requested_count: number
  stored_count: number
  unavailable_count: number
  refreshed_at: string
}

export interface EPSSFeedStatus {
  last_refreshed_at: string | null
  refresh_in_progress: boolean
  requested_count: number
  stored_count: number
  unavailable_count: number
  total_stored_scores: number
  last_error: string | null
}
