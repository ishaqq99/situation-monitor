// TypeScript contracts matching backend/app/models/nvd.py.
//
// FILE ROLE
// ---------
// This file gives React a stable typed view of NVD data returned by FastAPI.
// It does not fetch data or render UI.

export interface NVDCVSSMetric {
  cvss_version: string
  base_score: number
  base_severity: string | null
  vector_string: string
  source: string | null
  metric_type: string | null
  exploitability_score: number | null
  impact_score: number | null
}


export interface NVDCVE {
  cve_id: string
  source_identifier: string | null
  published_at: string
  last_modified_at: string
  vuln_status: string | null
  description: string | null
  cvss: NVDCVSSMetric | null
  cwes: string[]
  affected_cpes: string[]
  reference_urls: string[]
  fetched_at: string
}


export interface NVDCVSSChange {
  cve_id: string
  observed_at: string
  nvd_last_modified_at: string
  previous_cvss: NVDCVSSMetric | null
  current_cvss: NVDCVSSMetric | null
}


export interface NVDRefreshResult {
  requested_count: number
  stored_count: number
  unavailable_count: number
  failed_count: number
  remaining_count: number
  refreshed_at: string
}


export interface NVDFeedStatus {
  last_refreshed_at: string | null
  refresh_in_progress: boolean
  requested_count: number
  stored_count: number
  unavailable_count: number
  failed_count: number
  remaining_count: number
  total_stored_cves: number
  total_kev_cves: number
  pending_count: number
  last_error: string | null
}
