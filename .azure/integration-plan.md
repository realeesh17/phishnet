# Integration hand-off — PhishNet

## Backend
- Project: `backend/`
- Azure Functions Python v2 entry point: `backend/function_app.py`
- Run: from `backend/`, `func start` (host port `7071`)
- Local FastAPI fallback: from `backend/`, `python -m uvicorn app.main:app --host 127.0.0.1 --port 7071`
- Build/syntax check: `python -m compileall -q app function_app.py`
- Health: `GET /api/health`

## Frontend
- Project: `extension/`
- Build: `npm --prefix extension run build`
- Dev: `npm --prefix extension run dev` (Vite; preview-compatible host settings in `extension/vite.config.ts`)
- API seam: `extension/src/api/index.ts`; select `HttpApiClient` instead of `MockApiClient`
- Live HTTP client already scaffolded: `extension/src/api/httpClient.ts`; API base: `VITE_PHISHNET_API_BASE_URL`, default `http://localhost:7071/api`
- Mock files to remove or convert: `extension/src/api/mockClient.ts`, `extension/src/api/mockClient.test.ts`
- Remove the dev-only preview-state selector and simulation from `extension/src/App.tsx` after live wiring; retain real loading/error/empty states.
- No separate `src/mocks/` directory or `previewState.ts`; current mock fixtures and preview-state switcher are in the paths above.
- Local API types: `extension/src/api/types.ts`

## Routes — mirror the existing `ApiClient` methods
- `GET /api/health` → `{ status, services }`
- `POST /api/analyze` with `{ url }` → `{ url, verdict, indicators: [{ code, label, detail }], sourceChecks: { openphish, phishtank } }`
- Validation/server errors use `{ error: { code, message, details } }`

## Database and migrations
- Database: none; submitted URLs and scan history are not persisted.
- Migration tool/directory/connection variables: not applicable.
- Create no database schema or migrations; explicitly create **NO seed data**.

## Shared types and services
- Shared types: `extension/src/api/types.ts` (no separate shared package or import alias).
- Essential: Azure Functions-hosted PhishNet API and baseline analysis.
- Enhancements: optional OpenPhish (`OPENPHISH_ENABLED`), optional PhishTank (`PHISHTANK_API_KEY`), optional Application Insights (`APPLICATIONINSIGHTS_CONNECTION_STRING`).
- Optional threat-source failures must preserve the baseline analysis and report `unavailable`.

## Integration results — 2026-11-06

- Database: none in the approved plan; no migration or seed files were created.
- Backend checks: `python -m compileall -q backend/app backend/function_app.py` succeeded; `python -m pytest -q backend/tests` passed (9 tests).
- Backend host: `func` (Azure Functions Core Tools) is not installed, so the documented local FastAPI fallback was used from `backend/`: `python -m uvicorn app.main:app --host 127.0.0.1 --port 7071`.
- Smoke tests: `GET /api/health` returned 200 (`healthy`, analysis healthy, OpenPhish/PhishTank not configured); `POST /api/analyze` with `https://news.example/` returned 200 with a live baseline result and source statuses.
- Frontend: `extension/src/api/index.ts` now selects `HttpApiClient`; local development defaults to `/api` and Vite proxies `/api` to `http://127.0.0.1:7071`. Mock client and its tests were replaced with HTTP-client tests; the preview-state selector/simulation was removed.
- Frontend checks: `npm --prefix extension run build` succeeded; `npm --prefix extension test` passed (3 tests); source search found no `MockApiClient`, `mockClient`, `previewState`, `dev-controls`, `illustrative mock`, `Illustrative mode`, or `mockData` references.
- Concurrent end-to-end check: with the backend fallback and `npm --prefix extension run dev` running, the Vite-served extension page returned 200; `GET http://localhost:5173/api/health` and `POST http://localhost:5173/api/analyze` both returned 200 through the Vite proxy, with the analysis response returned by the backend.
