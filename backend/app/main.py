from __future__ import annotations

import os
import asyncio
import time
from enum import Enum
from typing import Any, Literal

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .features import UrlFeatures, extract_features, parse_http_url, score_url
from .dns_intelligence import collect_dns
from .domain_intelligence import lookup_domain
from .http_analyzer import analyze_http
from .ip_intelligence import collect_ip_intelligence
from .phishing_analyzer import build_phishing_analysis
from .report_builder import build_intelligence_report
from .security import SecurityControls, SecurityMiddleware, SecuritySettings
from .threat_intel import ThreatIntel
from .url_parser import parse_url
from .ssl_analyzer import analyze_ssl


structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
)
logger = structlog.get_logger("phishnet.api")


class ErrorCode(str, Enum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    BAD_REQUEST = "BAD_REQUEST"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class ErrorBody(BaseModel):
    code: ErrorCode
    message: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class Indicator(BaseModel):
    code: str
    label: str
    detail: str


class SourceCheck(BaseModel):
    status: Literal["not_configured", "available", "unavailable"]
    matched: bool | None
    error: str | None = None


class AnalysisResponse(BaseModel):
    url: str
    verdict: Literal["low_concern", "review", "high_risk"]
    indicators: list[Indicator]
    sourceChecks: dict[str, SourceCheck]
    # Diagnostic details supplement the approved plan response.
    risk_score: float
    model: str
    features: dict[str, Any]
    reasons: list[str]
    threat_intelligence: dict[str, object]
    normalized_url: str
    url_parts: dict[str, Any]
    domain_info: dict[str, Any]
    dns: dict[str, Any]
    ip_intelligence: list[dict[str, Any]]
    resolved_ip_addresses: list[str]
    ssl: dict[str, Any]
    http: dict[str, Any]
    redirects: list[dict[str, Any]]
    phishing: dict[str, Any]
    scan_metadata: dict[str, Any]


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    services: dict[str, str]


security_settings = SecuritySettings.from_env()
security_controls = SecurityControls(security_settings)
app = FastAPI(
    title="PhishNet API",
    description="Explainable URL risk analysis for the PhishNet Chrome extension.",
    version="1.0.0",
    debug=False,
    docs_url=None if security_settings.production else "/docs",
    redoc_url=None if security_settings.production else "/redoc",
    openapi_url=None if security_settings.production else "/openapi.json",
)
app.add_middleware(
    SecurityMiddleware,
    settings=security_settings,
    controls=security_controls,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=list(security_settings.allowed_hosts),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(security_settings.cors_origins),
    allow_origin_regex=r"chrome-extension://[a-p]{32}",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)
app.state.security_controls = security_controls

threat_intel = ThreatIntel()


@app.middleware("http")
async def log_request(request: Request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error(
            "http_request_failed",
            http_method=request.method,
            http_path=request.url.path,
            error_type=type(exc).__name__,
        )
        raise
    logger.info(
        "http_request_completed",
        http_method=request.method,
        http_path=request.url.path,
        http_status=response.status_code,
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    details = [
        {
            "field": ".".join(str(part) for part in error.get("loc", ())),
            "reason": error.get("type", "invalid"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": ErrorCode.VALIDATION_ERROR.value,
                "message": "The request did not match the expected schema.",
                "details": details,
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    code = (
        ErrorCode.VALIDATION_ERROR
        if exc.status_code == 422
        else ErrorCode.BAD_REQUEST
        if exc.status_code == 400
        else ErrorCode.NOT_FOUND
        if exc.status_code == 404
        else ErrorCode.RATE_LIMITED
        if exc.status_code == 429
        else ErrorCode.REQUEST_TOO_LARGE
        if exc.status_code == 413
        else ErrorCode.SERVICE_UNAVAILABLE
        if exc.status_code == 503
        else ErrorCode.INTERNAL_ERROR
    )
    message = (
        "Too many requests. Please try again later."
        if exc.status_code == 429
        else "The request body is too large."
        if exc.status_code == 413
        else "The service is temporarily unavailable."
        if exc.status_code == 503
        else str(exc.detail)
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code.value,
                "message": message,
                "details": None,
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_api_error", error_type=type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": ErrorCode.INTERNAL_ERROR.value,
                "message": "An unexpected error occurred.",
                "details": None,
            }
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/health", response_model=HealthResponse)
def api_health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        services={
            "analysis": "healthy",
            "openphish": "available" if threat_intel.openphish_enabled else "not_configured",
            "phishtank": "available" if threat_intel.phishtank_api_key else "not_configured",
            "intelligence": "healthy",
        },
    )


@app.post("/api/analyze", response_model=AnalysisResponse)
@app.post("/analyze", response_model=AnalysisResponse, include_in_schema=False)
async def analyze(request: AnalyzeRequest) -> AnalysisResponse:
    try:
        parse_http_url(request.url)
        features = extract_features(request.url)
        parsed = parse_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    risk_score, reasons = score_url(features)
    try:
        providers = await asyncio.to_thread(threat_intel.check, request.url)
    except Exception as exc:
        # Optional enhancement providers must never suppress the baseline result.
        logger.error("threat_intelligence_unavailable", error_type=type(exc).__name__)
        providers = []
    matched_sources = [
        provider.name for provider in providers if provider.matched is True
    ]

    if matched_sources:
        verdict = "high_risk"
        risk_score = 1.0
        reasons.insert(0, f"Threat intelligence reported a match: {', '.join(matched_sources)}.")
    elif risk_score >= 0.65:
        verdict = "review"
    else:
        verdict = "low_concern"

    indicators = [
        Indicator(code=code, label=label, detail=detail)
        for code, label, detail in _indicators(features, reasons)
    ]
    source_checks: dict[str, SourceCheck] = {}
    source_names = {"openphish": "OpenPhish", "phishtank": "PhishTank"}
    for key, source_name in source_names.items():
        provider = next(
            (item for item in providers if item.name.lower() == source_name.lower()),
            None,
        )
        configured = (
            threat_intel.openphish_enabled if key == "openphish"
            else bool(threat_intel.phishtank_api_key)
        )
        source_status = (
            "not_configured" if not configured
            else "unavailable" if provider is None or provider.status == "unavailable"
            else "available"
        )
        source_checks[key] = SourceCheck(
            status=source_status,
            matched=provider.matched if provider else None,
            error=provider.error if provider else "Provider check failed.",
        )

    domain_info, dns_info, http_info = await asyncio.gather(
        _safe_lookup(lookup_domain, parsed),
        _safe_lookup(collect_dns, parsed),
        _safe_lookup(analyze_http, parsed),
    )
    addresses = dns_info.get("resolved_ip_addresses", [])
    ip_info = await _safe_lookup(collect_ip_intelligence, addresses)
    if not isinstance(ip_info, list):
        ip_info = []
    ssl_info = await _safe_lookup(analyze_ssl, parsed, addresses)
    phishing = build_phishing_analysis(
        features,
        risk_score,
        reasons,
        providers,
        domain_info,
        http_info,
        ssl_info,
    )
    report = build_intelligence_report(
        parsed,
        dns_info,
        ip_info,
        domain_info,
        ssl_info,
        http_info,
        phishing,
    )

    return AnalysisResponse(
        url=request.url,
        verdict=verdict,
        indicators=indicators,
        sourceChecks=source_checks,
        risk_score=risk_score,
        model="transparent_heuristic_v1",
        features=features.to_dict(),
        reasons=reasons,
        threat_intelligence={
            "matched": bool(matched_sources),
            "providers": [provider.to_dict() for provider in providers],
        },
        normalized_url=report["normalized_url"],
        url_parts=report["url_parts"],
        domain_info=report["domain_info"],
        dns=report["dns"],
        ip_intelligence=report["ip_intelligence"],
        resolved_ip_addresses=report["resolved_ip_addresses"],
        ssl=report["ssl"],
        http=report["http"],
        redirects=report["redirects"],
        phishing=report["phishing"],
        scan_metadata=report["scan_metadata"],
    )


async def _safe_lookup(function, *args: Any) -> Any:
    try:
        return await asyncio.to_thread(function, *args)
    except ValueError as exc:
        return {"status": "blocked", "source": "PhishNet SSRF protection", "error": str(exc)}
    except Exception as exc:
        logger.warning("intelligence_provider_unavailable", provider=getattr(function, "__name__", "unknown"), error_type=type(exc).__name__)
        return {"status": "unavailable", "source": "PhishNet", "error": "Provider unavailable."}


def _indicators(
    features: UrlFeatures, reasons: list[str]
) -> list[tuple[str, str, str]]:
    mapped = [
        ("https", "HTTPS scheme", features.uses_https, "The URL uses HTTPS."),
        ("http", "HTTP scheme", not features.uses_https, "The URL does not use HTTPS."),
        ("ip_host", "IP-literal hostname", features.is_ip_host, "The host is an IP address."),
        ("long_url", "URL length", features.url_length > 75, "The URL is longer than typical."),
        ("subdomains", "Subdomain count", features.subdomain_count > 1, "The hostname has multiple subdomains."),
        ("suspicious_terms", "URL terms", features.suspicious_keyword_count > 0, "Sign-in, account, or verification terms appear in the URL."),
        ("userinfo", "Embedded user information", features.has_userinfo, "The URL includes user information before the host."),
        ("punycode", "Punycode hostname", features.has_punycode, "The hostname contains an internationalized punycode label."),
    ]
    active = [
        (code, label, detail)
        for code, label, detected, detail in mapped
        if detected
    ]
    if not active:
        return [("baseline", "Baseline check", reasons[0])]
    return active


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.getenv("PHISHNET_HOST", "127.0.0.1"),
        port=int(os.getenv("PHISHNET_PORT", "7071")),
        reload=False,
        proxy_headers=False,
    )
