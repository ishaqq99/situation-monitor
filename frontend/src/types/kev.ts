// -----------------------------
//
// This file defines the TypeScript shapes used by the frontend for CISA KEV
// data.
//
// It does NOT fetch data.
// It does NOT render UI.
// It does NOT talk to PostgreSQL.
//
// Its job is to tell TypeScript:
//
//     "This is what KEV data looks like."
//
//
//
// WHY THIS FILE EXISTS
// --------------------
//
// FastAPI returns JSON.
//
// TypeScript needs to know what fields we expect inside that JSON so VS Code
// can provide:
//
// - autocomplete,
// - type checking,
// - safer property access,
// - compile-time error detection.
//
//
//
// BACKEND ↔ FRONTEND CONTRACT
// ---------------------------
//
// Backend Pydantic:
//
//     KEVEntry
//
// corresponds to frontend:
//
//     interface KEVEntry
//
//
//
// WHO IMPORTS THIS FILE
// ---------------------
//
// frontend/src/api/kev.ts
// frontend/src/components/KevPanel.tsx
//
//
//
// DATA FLOW
// ---------
//
// FastAPI KEVEntry
//      ↓
// JSON response
//      ↓
// frontend api/kev.ts
//      ↓
// TypeScript KEVEntry type
//      ↓
// React component
// =============================================================================

export interface KEVEntry {
  // Unique CVE identifier.
  cve_id: string

  // Vendor/project reported by CISA.
  vendor_project: string

  // Product affected by the CVE.
  product: string

  // CISA vulnerability title/name.
  vulnerability_name: string

  // ISO date strings sent by FastAPI.
  date_added: string
  due_date: string

  // Full CISA description and remediation instruction.
  short_description: string
  required_action: string

  // CISA indication of known ransomware campaign usage.
  known_ransomware_campaign_use: string

  // Optional CISA notes field.
  notes: string

  // CWE identifiers related to the vulnerability.
  cwes: string[]
}


export interface KEVRefreshResult {
  // Number of records downloaded from CISA.
  fetched_count: number

  // Number of records processed into PostgreSQL.
  stored_count: number

  // Number of newest records cached in Redis.
  cached_count: number

  // UTC timestamp of the successful refresh.
  refreshed_at: string
}


export interface KEVFeedStatus {
  // Last successful refresh time stored in Redis.
  last_refreshed_at: string | null

  // True when the Redis refresh lock currently exists.
  refresh_in_progress: boolean

  // Number of KEV entries currently stored in the Redis dashboard cache.
  cached_entries: number
}
