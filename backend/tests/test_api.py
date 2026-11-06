from fastapi.testclient import TestClient
from limits import parse

from app.main import app, threat_intel
from app.security import ConcurrencyLimiter, SecuritySettings, client_ip
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
        json={"url": "http://8.8.8.8/login/verify/account"},
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


def test_rejects_local_private_and_reserved_hosts() -> None:
    for url in (
        "http://localhost/",
        "https://sub.localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.1.1/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://192.0.2.1/",
        "http://127.1/",
    ):
        response = client.post("/api/analyze", json={"url": url})
        assert response.status_code == 422, url


def test_accepts_public_domain_and_ip_hosts() -> None:
    for url in ("https://example.com/", "https://news.example/", "https://8.8.8.8/"):
        response = client.post("/api/analyze", json={"url": url})
        assert response.status_code == 200, url


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


def test_request_body_size_limit_returns_413() -> None:
    response = client.post(
        "/api/analyze",
        json={"url": f"https://example.com/{'a' * 17_000}"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_rate_limit_returns_429(monkeypatch) -> None:
    controls = app.state.security_controls
    controls.storage.reset()
    monkeypatch.setattr(controls, "rate_limit_item", parse("1/minute"))

    first = client.get("/health")
    second = client.get("/health")
    controls.storage.reset()

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"
    assert second.json()["error"]["code"] == "RATE_LIMITED"


def test_concurrency_limiter_caps_total_and_per_client_requests() -> None:
    limiter = ConcurrencyLimiter(total_limit=2, per_client_limit=1)
    assert limiter.acquire("client-a") is True
    assert limiter.acquire("client-a") is False
    assert limiter.acquire("client-b") is True
    assert limiter.acquire("client-c") is False

    limiter.release("client-a")
    assert limiter.acquire("client-c") is True


def test_untrusted_forwarded_for_is_ignored() -> None:
    scope = {
        "client": ("203.0.113.10", 1234),
        "headers": [(b"x-forwarded-for", b"198.51.100.20")],
    }
    assert client_ip(scope, ()) == "203.0.113.10"


def test_forwarded_for_uses_trusted_proxy_chain() -> None:
    scope = {
        "client": ("10.0.0.5", 1234),
        "headers": [(b"x-forwarded-for", b"198.51.100.20, 10.0.0.4")],
    }
    assert client_ip(scope, ("10.0.0.0/8",)) == "198.51.100.20"


def test_cors_and_security_headers_are_restricted() -> None:
    allowed = client.get("/health", headers={"Origin": "http://localhost:5173"})
    denied = client.get("/health", headers={"Origin": "https://untrusted.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
    assert allowed.headers["x-content-type-options"] == "nosniff"
    assert allowed.headers["x-frame-options"] == "DENY"
    assert allowed.headers["referrer-policy"] == "no-referrer"
    assert allowed.headers["cache-control"] == "no-store"


def test_validation_error_does_not_echo_submitted_url() -> None:
    submitted = f"https://example.com/?token={'s' * 2100}"
    response = client.post("/api/analyze", json={"url": submitted})

    assert response.status_code == 422
    assert submitted not in response.text


def test_security_settings_separate_development_and_production() -> None:
    development = SecuritySettings.from_env({"PHISHNET_ENV": "development"})
    production = SecuritySettings.from_env(
        {
            "PHISHNET_ENV": "production",
            "PHISHNET_RATE_LIMIT_STORAGE_URL": "redis://localhost:6379/0",
            "PHISHNET_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
        }
    )

    assert development.production is False
    assert production.production is True
    assert production.rate_limit_storage_url == "redis://localhost:6379/0"
    assert production.trusted_proxy_cidrs == ("10.0.0.0/8",)
