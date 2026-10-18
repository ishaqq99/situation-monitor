/**
 * 
 * FILE GUIDE
 * ----------
 * WHAT THIS FILE DOES
 * Describe the JSON fields the browser receives from /api/ioc routes.
 * 
 * WHY IT EXISTS
 * Typed response data makes missing/nullable fields visible during development.
 * 
 * WHO CALLS OR IMPORTS IT
 * frontend/src/api/ioc.ts and IOC components import these TypeScript interfaces.
 * 
 * WHAT IT CALLS OR IMPORTS
 * Mirrors backend/app/models/ioc_api.py; contains no executable network logic.
 * 
 * ROLE IN THE ARCHITECTURE
 * Frontend data-contract layer.
 * 
 */
// Contracts returned by backend/app/models/ioc_api.py.
// Dates cross HTTP as ISO strings; components format them for display.
// 'active' is provider state. It is not proof of maliciousness or exploitation.
/** One KEV's durable schedule and most recently stored result summary. */
export interface IOCJob {
  cve_id: string
  state: string
  next_check_at: string
  last_attempt_at: string | null
  last_success_at: string | null
  last_error: string | null
  summary: {
    complete: boolean
    collection_scope: string
    source_record_count_reported: number
    source_record_count_processed: number
    source_record_count_skipped: number
    observation_count: number
    unique_indicator_count: number
    warnings: string[]
    fetched_at: string
  } | null
}

/** Whole-catalog coverage and provider health shown by IocStatusPanel. */
export interface IOCProviderStatus {
  enabled: boolean
  configured: boolean
  collection_scope: string
  total_kevs: number
  scheduled_kevs: number
  ever_completed: number
  due_jobs: number
  running_jobs: number
  failed_or_partial: number
  stored_observations: number
  next_allowed_at: string | null
  heartbeat_at: string | null
  last_error: string | null
}

/** Why a related OTX report was selected, skipped, or left for analyst review. */
export interface IOCAssessment {
  source_record_id: string
  source_record_name: string | null
  source_record_cve_ids: string[]
  relevance: string
  reason: string
  selected_for_collection: boolean
  fetched: boolean
  indicator_count: number | null
}

/**
 * A provider observation together with local retrieval history. first_seen_at
 * and last_seen_at are times our app saw it, not attacker activity timestamps.
 */
export interface StoredIOC {
  observation: {
    cve_id: string
    indicator: { indicator_type: string; value: string }
    relationship_type: string
    source_record_relevance: string
    source_record_cve_ids: string[]
    source_record_id: string
    source_record_name: string | null
    source_record_url: string | null
    source_author: string | null
    source_tlp: string | null
    active: boolean | null
    expires_at: string | null
    reference_urls: string[]
    tags: string[]
    fetched_at: string
  }
  first_seen_at: string
  last_seen_at: string
  absent_since: string | null
  lifecycle: "active" | "inactive" | "expired" | "unknown" | "not_in_latest_scope"
}

/** One bounded CVE page with its schedule and report-decision preview. */
export interface IOCPage {
  cve_id: string
  job: IOCJob | null
  total: number
  limit: number
  offset: number
  include_history: boolean
  observations: StoredIOC[]
  assessments: IOCAssessment[]
  assessment_total: number
}

/** HTTP 202 queue result; queued does not mean the provider lookup has finished. */
export interface IOCQueueResult {
  cve_id: string
  queued: boolean
  state: string
  message: string
}

/** One historical collection attempt, including partial and failed outcomes. */
export interface IOCRun {
  run_id: string
  started_at: string
  finished_at: string | null
  outcome: string
  summary: IOCJob["summary"]
  error: string | null
}
