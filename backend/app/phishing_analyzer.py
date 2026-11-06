from __future__ import annotations

from typing import Any

from .features import UrlFeatures


def build_phishing_analysis(
    features: UrlFeatures,
    risk_score: float,
    reasons: list[str],
    providers: list[Any],
    domain_info: dict[str, Any],
    http_info: dict[str, Any],
    ssl_info: dict[str, Any],
) -> dict[str, Any]:
    matched = [provider.name for provider in providers if provider.matched is True]
    findings: list[dict[str, Any]] = []
    if matched:
        findings.append({"name": "Threat intelligence match", "severity": "critical", "explanation": "A configured threat feed reported this URL.", "evidence": ", ".join(matched), "source": "OpenPhish/PhishTank", "kind": "detection"})
    if domain_info.get("recently_registered"):
        findings.append({"name": "Recently registered domain", "severity": "medium", "explanation": "New domains deserve additional review; age alone is not proof of phishing.", "evidence": f"{domain_info.get('domain_age_days')} days old", "source": "RDAP", "kind": "heuristic"})
    if features.is_ip_host:
        findings.append({"name": "IP address used as host", "severity": "medium", "explanation": "IP literals are less typical for consumer websites and can make impersonation easier.", "evidence": features.domain, "source": "URL parser", "kind": "heuristic"})
    if features.suspicious_keyword_count:
        findings.append({"name": "Suspicious URL terms", "severity": "low", "explanation": "Account, sign-in, or verification terms appear in the URL.", "evidence": f"{features.suspicious_keyword_count} matching term(s)", "source": "URL parser", "kind": "heuristic"})
    if http_info.get("redirect_count", 0) > 2:
        findings.append({"name": "Redirect chain", "severity": "medium", "explanation": "Multiple redirects can obscure the final destination.", "evidence": f"{http_info['redirect_count']} redirects", "source": "HTTP analyzer", "kind": "heuristic"})
    if ssl_info.get("status") == "invalid_certificate":
        findings.append({"name": "Invalid TLS certificate", "severity": "high", "explanation": "The certificate could not be verified for the destination.", "evidence": ssl_info.get("certificate_verification_error"), "source": "TLS analyzer", "kind": "detection"})
    for header in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"):
        if http_info.get("security_headers", {}).get(header) is None and http_info.get("status") == "available":
            findings.append({"name": f"Missing {header}", "severity": "info", "explanation": "A missing security header is informational and is not phishing evidence.", "evidence": "Header not observed", "source": "HTTP analyzer", "kind": "informational"})
    if not findings:
        findings.append({"name": "No observed warning signals", "severity": "info", "explanation": "No configured feed match or supported heuristic was observed.", "evidence": "Available scan data", "source": "PhishNet", "kind": "informational"})
    return {
        "verdict": "high_risk" if matched else "review" if risk_score >= 0.65 else "low_concern",
        "risk_level": "critical" if matched or risk_score >= 0.8 else "high" if risk_score >= 0.6 else "medium" if risk_score >= 0.3 else "low",
        "heuristic_score": risk_score,
        "phishing_probability": None,
        "model_confidence": None,
        "probability_basis": "not_calibrated",
        "reasons": reasons,
        "findings": findings,
        "threat_intelligence_match": bool(matched),
    }
