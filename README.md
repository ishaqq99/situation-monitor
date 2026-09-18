# Situation Monitor

FastAPI and React dashboard for CISA Known Exploited Vulnerabilities (KEV),
enriched with FIRST Exploit Prediction Scoring System (EPSS) scores.
Python 3.11+ is required; the project was checked with Python 3.13 and Node 24.
Docker Compose runs PostgreSQL and Redis. Run the API and frontend separately.

## Local setup (PowerShell)

1. Copy `.env.example` to `.env` if `.env` does not already exist. Set database
   credentials and use the same credentials in `DATABASE_URL`. Do not overwrite
   an existing `.env` or commit secrets.
2. Start Docker Desktop, then run `docker compose up -d` from the project root.
3. In a backend terminal:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

4. In a frontend terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173. API documentation is at http://127.0.0.1:8000/docs.
The startup worker populates a new database; the first page load may be empty
while that refresh runs. The dashboard polls status and reloads latest rows
when a new successful refresh is observed. Manual refresh is also available.

## Configuration and deployment scope

- Root `.env`: database/Redis connections, positive refresh interval, allowed
  browser origins. Existing process environment variables take precedence.
- `frontend/.env`: optional `VITE_API_BASE_URL` (see its `.env.example`). This is
  public configuration compiled into the frontend. Rebuild after changing it.
  An empty value uses the browser's origin and requires a proxy for `/api`.
- PostgreSQL and Redis are published only on host loopback. Redis has no
  authentication in this local-development Compose configuration.
- Compose does not deploy the API or frontend. Before exposing the application
  publicly, provide HTTPS, access control for manual refresh, and an appropriate
  reverse proxy/origin configuration. Do not expose database ports publicly.
- Changing PostgreSQL environment credentials does not change credentials in
  an existing data volume. Preserve the volume and update credentials deliberately.

## Architecture and refresh behavior

`React component -> frontend API client -> FastAPI route -> service -> storage/collector`

PostgreSQL stores the full catalog. Ingestion uses an atomic upsert batch and
preserves first-seen timestamps. Existing records absent from a later feed are
retained as historical records. Redis stores the newest 50 entries, a last-success
timestamp, and a unique-owner refresh lease. Cache and timestamp publication is
atomic; cached entries expire after twice the refresh interval (at least one hour).
The last-success timestamp is Redis metadata, not a durable ingestion audit log.

The worker refreshes immediately, then at the configured interval. Redis prevents
simultaneous refreshes and enforces a 60-second cooldown. Refresh work is bounded
at 240 seconds, shorter than its 300-second lock lease. Lock release checks ownership.
Latest reads fall back to PostgreSQL if Redis fails. Search/detail reads use
PostgreSQL directly. GET requests never initiate downloads. Refresh requires Redis;
if cache publication fails after a database commit, rows remain available but the
refresh reports failure and does not advance the success timestamp.

Startup creates the schema and adds missing notes/CWE/first-seen/last-seen columns
from earlier iterations. Future schema changes need explicit migrations; changing
`CREATE TABLE IF NOT EXISTS` alone does not migrate existing columns.

## Checks

```powershell
cd backend
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
cd ../frontend
npm run build
npm run lint
cd ..
docker compose config --quiet
```

Unit/HTTP-contract tests mock external services and do not alter your database.

To also exercise your running local PostgreSQL/Redis instances:

```powershell
cd backend
$env:KEV_INTEGRATION_TESTS = "1"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
Remove-Item Env:KEV_INTEGRATION_TESTS
```

These optional tests use rolled-back SQL schemas and temporary, uniquely named
Redis keys. They do not modify the stored KEV catalog or regular cache keys.

## EPSS enrichment

The EPSS worker enriches CVEs already present in the local KEV catalog. It starts
after a 60-second delay and refreshes missing or older scores daily. If KEV has
not loaded yet or a refresh fails, it retries after five minutes. Configure this
with `EPSS_STARTUP_DELAY_SECONDS`, `EPSS_REFRESH_INTERVAL_SECONDS`, and
`EPSS_RETRY_INTERVAL_SECONDS` in the root environment. Defaults work with an
existing `.env`; no credential or database-volume replacement is needed.

The collector requests small batches from FIRST and validates their identifiers,
dates, and numeric bounds. PostgreSQL stores the scores; Redis coordinates refresh
ownership, a five-minute success cooldown, and status. GET requests read stored
data and do not contact FIRST. EPSS failure leaves KEV details available.

- `GET /api/epss/status`: refresh status and total stored scores.
- `POST /api/epss/refresh`: refresh missing or older scores for the KEV catalog.
- `GET /api/epss/{cve_id}`: stored score; 404 means no score has been stored.

An EPSS score is a probability of exploitation in the next 30 days. Its percentile
compares it with other scored vulnerabilities and is not another probability.
The dashboard shows the score's date and distinguishes loading, absent data,
failed requests, and stale scores. Selecting a CVE scrolls and focuses its detail
panel. Successful EPSS refreshes update an already open score panel.

Scores for non-KEV CVEs are outside this version's scope. Refresh timestamps and
error status are temporary Redis metadata; stored scores survive a Redis restart.

## Manual regression checks

1. Start Docker Desktop, PostgreSQL/Redis, the backend, and Vite as above. Check
   `/api/health` and the API documentation for all KEV and EPSS routes.
2. Load the dashboard and wait for KEV to populate (or refresh it). Select a CVE:
   its details should scroll into view, with description, action, and EPSS state.
3. Refresh EPSS after KEV is ready. Its stored count should increase if FIRST has
   scores for the catalog. Keep a detail panel open and confirm the score updates.
4. Try another CVE, then close details. Search KEV and confirm details still work.
   Status polling should not close a detail panel that is open.
5. Refresh EPSS again within five minutes: a cooldown message is expected. A
   missing score should say it is not stored; a request failure should show an
   error while keeping the KEV details visible.

The opt-in database tests mock FIRST responses. A passing test suite verifies the
application contracts but does not prove live FIRST connectivity.
