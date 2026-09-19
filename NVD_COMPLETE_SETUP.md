# Situation Monitor — Complete NVD Integration Setup

This guide finishes the KEV-centered NVD feature without turning Situation Monitor into a full NVD mirror.

## Final architecture

CISA KEV decides which vulnerabilities the project tracks.

For those KEVs:

- FIRST EPSS provides exploitation probability.
- NVD provides CVSS, CWE, description, affected CPEs, references, and NVD lifecycle metadata.
- PostgreSQL stores the current NVD state.
- PostgreSQL also stores CVSS change history only when the selected CVSS assessment changes.
- Redis coordinates refresh locking/status only; losing Redis does not lose NVD data.
- A background worker gradually backfills missing KEVs and later rechecks stale NVD records.
- React reads stored NVD data; opening a CVE never performs a live NVD request.

---

## Files to replace

Replace the entire contents of these existing files:

- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/models/nvd.py`
- `backend/app/collectors/nvd.py`
- `backend/app/storage/postgres.py`
- `backend/app/storage/nvd_repository.py`
- `backend/tests/test_nvd_storage_integration.py`
- `.env.example`
- `frontend/src/App.tsx`
- `frontend/src/components/KevPanel.tsx`
- `frontend/src/App.css`

## Files to create

Create these new files:

- `backend/app/storage/nvd_cache.py`
- `backend/app/services/nvd_service.py`
- `backend/app/workers/nvd_worker.py`
- `backend/app/api/nvd.py`
- `backend/tests/test_nvd_automation.py`
- `frontend/src/types/nvd.ts`
- `frontend/src/api/nvd.ts`
- `frontend/src/components/NvdDetails.tsx`
- `frontend/src/components/NvdStatusPanel.tsx`

Existing `check_nvd.py` and `check_nvd_storage.py` remain unchanged.

---

## Environment settings

The new code has safe defaults, so NVD can run without adding anything to `.env`.

For a faster first backfill, request a free NVD API key and add this to the project-root `.env`:

```text
NVD_API_KEY=your_key_here
```

Optional tuning values are documented in the replacement `.env.example`.

Important defaults:

- batch size: 25 CVEs
- stored NVD records become refresh candidates after 168 hours (7 days)
- NVD worker startup delay: 120 seconds
- backlog retry: 60 seconds when progress is being made
- idle status/candidate check: 3600 seconds
- request spacing: about 6.5 seconds without a key, about 0.75 seconds with a key

Do not put the API key in frontend files. It belongs only in the backend `.env`.

---

## Database changes

Starting FastAPI runs `initialize_database()`.

It preserves the existing:

- `kev_entries`
- `epss_scores`
- `nvd_cves`

and creates a new table:

- `nvd_cvss_history`

Existing NVD rows are preserved.

`nvd_cvss_history` only receives a row when the selected CVSS assessment actually changes. Re-fetching the same score does not create duplicate history.

---

## Test 1 — existing NVD parser regression

From:

```text
C:\Users\ishaq\Documents\GitHub\situation-monitor\backend
```

with `(.venv)` active:

```powershell
python -m unittest tests.test_nvd -v
```

Expected:

```text
Ran 12 tests
OK
```

---

## Test 2 — NVD service/API unit tests

```powershell
python -m unittest tests.test_nvd_automation -v
```

Expected:

```text
Ran 7 tests
OK
```

These tests do not contact live NVD, Redis, or PostgreSQL.

---

## Test 3 — real PostgreSQL NVD integration test

Make sure Docker/PostgreSQL are running first.

```powershell
$env:NVD_INTEGRATION_TESTS="1"
python -m unittest discover -s tests -p "test_nvd_storage_integration.py" -v
Remove-Item Env:NVD_INTEGRATION_TESTS
```

Expected: the integration test passes.

It uses an isolated PostgreSQL schema/transaction and rolls its test data back.

It verifies:

- current NVD storage
- CVSS history creation
- no duplicate history for unchanged CVSS
- stale provider revisions cannot overwrite newer records
- missing/stale candidate selection
- non-KEV NVD rows are rejected

---

## Test 4 — existing live single-CVE storage check

Use a CVE you know exists in your local KEV table, for example the one you already tested:

```powershell
python check_nvd_storage.py CVE-2026-53266
```

Expected: current NVD data is fetched, stored, and read back successfully.

Running it again with unchanged CVSS should not add a CVSS-history row.

---

## Start the full backend

From `backend/`:

```powershell
uvicorn app.main:app --reload
```

The FastAPI lifespan now starts three workers:

- KEV worker
- EPSS worker
- NVD worker

The NVD worker waits 120 seconds before its first automatic batch so KEV can initialize first.

Open:

```text
http://127.0.0.1:8000/docs
```

You should see the new NVD endpoints.

---

## Test 5 — NVD API endpoints

### Status

```text
GET /api/nvd/status
```

Expected fields include:

- total stored NVD CVEs
- total KEVs
- pending/stale count
- refresh state
- last batch counts

### Manual one-batch refresh

```text
POST /api/nvd/refresh
```

This processes at most `NVD_BATCH_SIZE` candidates.

### Current stored NVD record

```text
GET /api/nvd/CVE-2026-53266
```

This reads PostgreSQL only.

### CVSS history

```text
GET /api/nvd/CVE-2026-53266/history
```

An empty list is normal until Situation Monitor observes a real CVSS change.

---

## Start/test the frontend

From `frontend/`:

```powershell
npm run build
```

Then during development:

```powershell
npm run dev
```

Open:

```text
http://localhost:5173
```

Expected UI changes:

1. A new `NVD Enrichment` status card appears.
2. It shows stored coverage and pending/stale KEVs.
3. `Refresh NVD Batch` triggers the same protected backend service as the worker.
4. Clicking a KEV CVE shows the existing EPSS section plus an NVD technical-enrichment section.
5. NVD details include current CVSS, source, vector, NVD dates/status, description, CWE, CPEs, and references.
6. CVSS Change History is empty until a real selected-CVSS transition is observed.

---

## First backfill behavior

The project does not download the whole NVD database.

It asks PostgreSQL which KEVs are missing NVD enrichment and processes those in bounded batches.

Example:

```text
1709 KEVs
1500 already enriched
209 missing/stale
```

One worker batch may process 25, then Redis/status reports the remaining candidate count. While progress continues, the worker schedules another batch after the backlog interval.

Without an API key the initial backfill is intentionally slower because requests are spaced conservatively. The API remains usable while the worker runs in the background.

---

## Ongoing refresh / CVSS history behavior

After backfill, an NVD row becomes a refresh candidate after the configured stale period (default 7 days).

If NVD still returns the same selected CVSS assessment:

```text
current row refreshed
history unchanged
```

If the selected assessment changes, for example:

```text
9.8 CRITICAL -> 7.5 HIGH
```

Situation Monitor performs both operations in one database transaction:

1. append the old/new assessment to `nvd_cvss_history`
2. update `nvd_cves` with the new current state

The frontend history table then shows that transition.

---

## Recommended final checks before committing

From `backend/`:

```powershell
python -m unittest tests.test_nvd -v
python -m unittest tests.test_nvd_automation -v
```

Run the opt-in PostgreSQL test as shown above.

From `frontend/`:

```powershell
npm run build
```

Then start Docker, Uvicorn, and Vite and confirm the existing KEV + EPSS functionality still works alongside NVD.

Only after those checks should you commit/push the completed NVD feature.
