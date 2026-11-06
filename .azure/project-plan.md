# Project Plan

**Status**: Integrated
**Created**: 2026-11-05
**Mode**: NEW

---

## 1. Project Overview

**Goal**: Build PhishNet, a Chrome extension and FastAPI backend that analyzes the active-tab or a manually entered URL for phishing indicators. Include safe URL validation, explainable URL features, a transparent baseline classifier, optional configurable OpenPhish and PhishTank inputs with safe unavailable/unconfigured fallbacks, setup instructions, and automated tests. Do not claim unmeasured model performance or operational integrations. The project is designed so that every module is independently testable.

**App Type**: SPA + API

**API Login**: No

**Mode**: NEW

**Deployment Plan**: No deployment plan found

---

## 2. Backend — Azure Functions

| Component | Technology |
|-----------|-----------|
| **Language** | Python |
| **Framework** | FastAPI |
| **Runtime** | CPython |
| **Azure Functions Model** | Python programming model v2, Functions host v4 |
| **Package Manager** | pip |
| **Test Runner** | pytest |
| **Mocking Library** | unittest.mock |
| **Test Command** | pytest |
| **Orchestration** | docker-compose |

The API handles URL validation, feature extraction, rule-based classification, and optional OpenPhish/PhishTank checks behind independently testable interfaces. If an optional source is unconfigured or unavailable, return the baseline analysis with a clear source status instead of failing the request. Do not persist submitted URLs or analysis history.

---

## 3. Frontend — Web App

| Component | Technology |
|-----------|-----------|
| **Language** | TypeScript |
| **Framework** | React + Vite |
| **Package Manager** | npm |
| **Test Runner** | vitest |
| **Mocking Library** | vi.mock |
| **Test Command** | npm test |

The frontend is a Chrome extension popup/options experience. It can submit the active-tab URL or a manually entered URL to the configured API and present the result, explainable indicators, and safe loading/error states.

---

## 4. Services Required

| Azure Service | Role in App | Environment Variable | Default Value (Local) | Classification |
|---------------|------------|---------------------|----------------------|----------------|
| Azure Functions | Host the Python HTTP API for URL analysis and health checks; the extension calls this endpoint | `VITE_PHISHNET_API_BASE_URL` | `http://localhost:7071/api` | Essential |
| Application Insights | Optional API exception and dependency telemetry | `APPLICATIONINSIGHTS_CONNECTION_STRING` | Not configured locally | Enhancement |

No application datastore is planned; URL analysis is request-scoped and scan history is not persisted. The Chrome extension is packaged for Chrome rather than hosted as an Azure web site. OpenPhish and PhishTank are optional external inputs, not Azure resources.

---

## 5. Prerequisites

Double-check all tools marked ❓ are installed before proceeding. Versions shown are from a local environment scan; ❓ means installation could not be confirmed.

### Run

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Python | PhishNet API | ✅ | 3.10.11 |
| pip | PhishNet API | ✅ | 25.2 |
| Azure Functions Core Tools | PhishNet API | ❓ | Not confirmed |
| pytest | PhishNet API | ❓ | Not confirmed |
| Node.js | PhishNet Chrome Extension | ✅ | 22.17.1 |
| npm | PhishNet Chrome Extension | ✅ | 11.12.1 |
| Vitest | PhishNet Chrome Extension | ❓ | Not confirmed |
| Google Chrome | PhishNet Chrome Extension | ✅ | 156.0.8078.80 |

### Debug

| Tool | Service(s) | Installed | Version |
|------|------------|-----------|---------|
| Visual Studio Code | * | ✅ | 1.143.1 |
| Docker | PhishNet API, PhishNet Chrome Extension | ❓ | Not confirmed |
| Docker Compose | PhishNet API, PhishNet Chrome Extension | ❓ | Not confirmed |
| `ms-azuretools.vscode-azurefunctions` | PhishNet API | ✅ | 1.22.2 |
| `ms-python.python` | PhishNet API | ✅ | 2026.10.0 |
| `ms-python.debugpy` | PhishNet API | ✅ | 2026.6.0 |
| VS Code JavaScript Debugger (built-in) | PhishNet Chrome Extension | ✅ | Bundled with VS Code 1.143.1 |

---

## 6. Design System & UI

**Component Library**: Fluent UI v9
**Style Direction**: A compact, trustworthy security-tool popup with clear URL entry, calm teal actions, and restrained amber caution states. Keep the interface scannable and transparent: explain signals without implying certainty or measured detection performance.
**Typography**: Inter, system-ui

### Color Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `primary` | `#0F766E` | PhishNet scan actions, selected navigation, and result links |
| `accent` | `#B45309` | Caution indicators and optional-source status highlights |
| `surface` | `#F4F7F9` | Extension workspace background |
| `text` | `#102A43` | URL labels, result explanations, and primary content |
| `muted` | `#52667A` | Helper text, source details, and secondary metadata |
| `border` | `#D8E1E8` | URL field, result panels, and navigation dividers |

### Pages

| Page | Route | Purpose | Layout |
|------|-------|---------|--------|
| Scan URL | `/` | Analyze the active tab URL or a manually entered URL | `header, nav, main, form, action-bar, card-list, footer` |
| Analysis Result | `/result` | Show a baseline verdict with the URL signals that explain it | `header, nav, main, tabs, card-list, action-bar, footer` |
| Threat Sources | `/sources` | Show optional OpenPhish and PhishTank configuration/availability and safe fallback behavior | `header, nav, main, table, empty, footer` |

### Sample Content

The URLs below use reserved example addresses and are illustrative fixtures only, not a measured classifier evaluation or saved scan history.

Scan URL — URL input fixtures:
| URL | Entry point | Fixture purpose | State |
|---|---|---|---|
| `https://news.example/` | Active tab or manual entry | Ordinary HTTPS example | Ready to analyze |
| `http://192.0.2.25/sign-in` | Manual entry | Reserved IP-literal host example | Ready to analyze |
| `https://xn--bcher-kva.example/account` | Manual entry | Punycode-host example | Ready to analyze |

Analysis Result — illustrative analysis:
| URL | Example verdict | Explainable signal | Source check |
|---|---|---|---|
| `https://news.example/` | Low concern | HTTPS; no matching baseline warning rule | Not configured |
| `http://192.0.2.25/sign-in` | Review | HTTP scheme and IP-literal hostname | Not configured |
| `https://xn--bcher-kva.example/account` | Review | Punycode hostname | Not configured |

Threat Sources — optional source status:
| Source | Configuration state | Fallback behavior |
|---|---|---|
| OpenPhish | Not configured | Skip lookup; keep baseline result |
| PhishTank | Not configured | Skip lookup; keep baseline result |

Threat Sources empty state: No source matches are available for the current URL; the baseline explanation remains visible.

---

## 7. Project Structure

```text
project-root/
├── .azure/
│   ├── project-plan.md
│   └── .preview-temp/
├── .env.example
├── .gitignore
├── README.md
├── docker-compose.yml
└── services/
    ├── phishnet-api/
    │   ├── host.json
    │   ├── function_app.py
    │   ├── requirements.txt
    │   ├── src/
    │   │   └── phishnet_api/
    │   │       ├── api/
    │   │       ├── analysis/
    │   │       ├── features/
    │   │       ├── classifiers/
    │   │       └── integrations/
    │   └── tests/
    │       ├── unit/
    │       └── api/
    └── phishnet-extension/
        ├── manifest.json
        ├── package.json
        ├── vite.config.ts
        ├── public/
        └── src/
            ├── api/
            ├── components/
            ├── popup/
            ├── options/
            └── tests/
```

---

## 8. Route Definitions

| # | Method | Path | Description | Request Body | Response Body | Status Codes |
|---|--------|------|-------------|-------------|--------------|-------------|
| 1 | GET | `/api/health` | API health check | — | `{ status, services }` | 200, 503 |
| 2 | POST | `/api/analyze` | Validate and analyze one submitted URL; optional source failures do not suppress the baseline result | `{ url }` | `{ url, verdict, indicators: [{ code, label, detail }], sourceChecks: { openphish, phishtank } }` | 200, 400, 422, 500 |

All errors use `{ "error": { "code": "NOT_FOUND", "message": "Item not found", "details": null } }` with the appropriate error code and HTTP status.

---

## 9. Next Steps

1. Run **azure-project-scaffold** to execute this plan
2. Run **azure-project-integrate** to wire the frontend to live data, smoke-test the backend, and create the migrations
3. Run **azure-debug-plan** → **azure-debug-generate** for Docker emulators and VS Code debugging
4. Run the **azure-deploy** agent when ready; it uses **azure-app-onboard** for architecture, cost estimation, IaC generation, provisioning, and health verification
