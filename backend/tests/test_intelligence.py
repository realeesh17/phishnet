from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.threat_intel import ProviderResult
from app.url_parser import parse_url


client = TestClient(app)


def test_url_parser_exposes_origin_and_domain_parts() -> None:
    parsed = parse_url("https://login.example.co.uk:443/account?next=home#form")

    assert parsed.normalized_url == "https://login.example.co.uk:443/account?next=home#form"
    assert parsed.origin == "https://login.example.co.uk:443"
    assert parsed.registered_domain == "example.co.uk"
    assert parsed.subdomain == "login"
    assert parsed.tld == "uk"


def test_analysis_returns_partial_intelligence_without_fabricating_scores(monkeypatch) -> None:
    monkeypatch.setattr(main.threat_intel, "check", lambda _url: [ProviderResult("OpenPhish", "disabled", None)])
    monkeypatch.setattr(main, "lookup_domain", lambda _parsed: {"status": "available", "domain_age_days": 12, "recently_registered": True, "source": "RDAP"})
    monkeypatch.setattr(main, "collect_dns", lambda _parsed: {"status": "available", "records": {"A": ["93.184.216.34"]}, "resolved_ip_addresses": ["93.184.216.34"], "source": "local resolver"})
    monkeypatch.setattr(main, "collect_ip_intelligence", lambda _addresses: [{"ip": "93.184.216.34", "organization": "Example Org", "country": "US", "status": "available"}])
    monkeypatch.setattr(main, "analyze_ssl", lambda _parsed, _addresses: {"status": "valid", "certificate_valid": True})
    monkeypatch.setattr(main, "analyze_http", lambda _parsed: {"status": "available", "status_code": 200, "security_headers": {}, "redirect_count": 0})

    response = client.post("/api/analyze", json={"url": "https://example.com/"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["url_parts"]["origin"] == "https://example.com"
    assert payload["domain_info"]["domain_age_days"] == 12
    assert payload["phishing"]["phishing_probability"] is None
    assert payload["phishing"]["model_confidence"] is None
    assert any(item["name"] == "Recently registered domain" for item in payload["phishing"]["findings"])
