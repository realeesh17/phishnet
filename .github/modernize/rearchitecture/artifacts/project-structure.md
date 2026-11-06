# Project structure

PhishNet is a full-stack Chrome Manifest V3 extension with a React/TypeScript/Vite popup and a Python/FastAPI-compatible Azure Functions backend.

- `extension/src`: popup UI, API client, and styling.
- `extension/public/manifest.json`: extension action, popup, and permissions.
- `backend/app`: API routes, URL feature extraction, security middleware, and threat intelligence.
- `backend/tests`: FastAPI contract and security tests.
- Entry points: `extension/src/main.tsx`, `backend/function_app.py`, and `backend/app/main.py`.
