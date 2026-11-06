from fastapi.testclient import TestClient

from app.main import app, threat_intel
from app.threat_intel import ProviderResult


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_planned_health_endpoint_reports_source_configuration() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "healthy"
    assert result["services"]["analysis"] == "healthy"
    assert result["services"]["openphish"] == "not_configured"
    assert result["services"]["phishtank"] == "not_configured"


def test_analysis_returns_explainable_result(monkeypatch) -> None:
    monkeypatch.setattr(
        threat_intel,
        "check",
        lambda _url: [
            ProviderResult("OpenPhish", "disabled", None),
            ProviderResult("PhishTank", "disabled", None),
        ],
    )

    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "low_concern"
    assert result["model"] == "transparent_heuristic_v1"
    assert result["features"]["uses_https"] is True
    assert result["features"]["domain_age_days"] is None
    assert result["reasons"]
    assert result["threat_intelligence"]["matched"] is False
    assert result["indicators"][0]["code"] == "https"
    assert result["sourceChecks"]["openphish"]["status"] == "not_configured"
    assert result["sourceChecks"]["phishtank"]["status"] == "not_configured"


def test_high_risk_url_is_flagged(monkeypatch) -> None:
    monkeypatch.setattr(
        threat_intel,
        "check",
        lambda _url: [ProviderResult("OpenPhish", "disabled", None)],
    )

    response = client.post(
        "/api/analyze",
        json={"url": "http://192.0.2.10/login/verify/account"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "review"
    assert result["risk_score"] >= 0.65
    assert result["features"]["is_ip_host"] is True


def test_threat_feed_match_overrides_heuristic(monkeypatch) -> None:
    monkeypatch.setattr(
        threat_intel,
        "check",
        lambda _url: [ProviderResult("OpenPhish", "checked", True)],
    )

    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "high_risk"
    assert response.json()["risk_score"] == 1.0


def test_optional_source_failure_keeps_baseline_result(monkeypatch) -> None:
    monkeypatch.setattr(threat_intel, "openphish_enabled", True)
    monkeypatch.setattr(threat_intel, "phishtank_api_key", "test-key")
    monkeypatch.setattr(
        threat_intel,
        "check",
        lambda _url: (_ for _ in ()).throw(RuntimeError("provider unavailable")),
    )
    response = client.post("/api/analyze", json={"url": "https://news.example/"})
    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "low_concern"
    assert result["sourceChecks"]["openphish"]["status"] == "unavailable"
    assert result["sourceChecks"]["phishtank"]["status"] == "unavailable"


def test_rejects_non_http_and_malformed_urls() -> None:
    for url in ("file:///etc/passwd", "javascript:alert(1)", "https://", "ftp://example.com"):
        response = client.post("/api/analyze", json={"url": url})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_rejects_overlong_input() -> None:
    response = client.post("/api/analyze", json={"url": f"https://example.com/{'a' * 2048}"})
    assert response.status_code == 422


def test_request_schema_errors_use_the_standard_error_envelope() -> None:
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert payload["error"]["message"]
    assert payload["error"]["details"]
