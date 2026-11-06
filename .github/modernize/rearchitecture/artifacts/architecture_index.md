# PhishNet architecture index

## Implementation Guide

This index is not the full contract. Do not implement from this file alone; follow the artifact paths below.

Global artifacts: `unit_graph.yaml`, `migration_boundary.yaml`, `wire_contracts.yaml`, `shared_modules.yaml`, and `cross_unit_state.yaml` describe runtime boundaries, API compatibility, shared code, and state flows.

### Unit: popup

- Trigger: Chrome extension popup opening and user URL submission.
- Read `units/popup/behavior.yaml` for loading, automatic-tab, manual-submit, and error behavior.
- Read `units/popup/bindings.yaml` for Manifest V3 permissions and UI/API bindings.
- Read `units/popup/unit_decomposition.yaml` for advisory split candidates only.
- Completion evidence: preserve automatic current-tab analysis, manual analysis, restricted-tab errors, loading/error states, and frontend build output.

### Unit: api-analyze

- Trigger: `POST /api/analyze`.
- Read `units/api-analyze/behavior.yaml` for validation, partial-failure, security, and response behavior.
- Read `units/api-analyze/bindings.yaml` for FastAPI/runtime configuration.
- Read `units/api-analyze/unit_decomposition.yaml` for advisory service boundaries.
- Filter `wire_contracts.yaml` to this unit and preserve legacy response fields.
- Completion evidence: backend tests, security tests, and API response compatibility.

### Unit: api-health

- Trigger: `GET /api/health` and `GET /health`.
- Read `units/api-health/behavior.yaml`, `bindings.yaml`, and `unit_decomposition.yaml`.
- Completion evidence: existing health response and source configuration status remain valid.
