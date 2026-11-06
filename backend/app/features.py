from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from urllib.parse import SplitResult, urlsplit


SUSPICIOUS_KEYWORDS = (
    "account",
    "auth",
    "billing",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
)


@dataclass(frozen=True)
class UrlFeatures:
    url_length: int
    uses_https: bool
    is_ip_host: bool
    subdomain_count: int
    suspicious_keyword_count: int
    has_userinfo: bool
    has_punycode: bool
    domain_age_days: int | None

    def to_dict(self) -> dict[str, int | bool | None]:
        return asdict(self)


def parse_http_url(url: str) -> SplitResult:
    if not url or url != url.strip() or any(ord(char) < 32 for char in url):
        raise ValueError("Enter a URL without leading, trailing, or control characters.")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("Only absolute HTTP and HTTPS URLs can be analyzed.")

    return parsed


def extract_features(url: str) -> UrlFeatures:
    parsed = parse_http_url(url)
    hostname = (parsed.hostname or "").rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip_host = True
    except ValueError:
        is_ip_host = False

    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not is_ip_host else 0
    searchable_url = url.lower()

    return UrlFeatures(
        url_length=len(url),
        uses_https=parsed.scheme.lower() == "https",
        is_ip_host=is_ip_host,
        subdomain_count=subdomain_count,
        suspicious_keyword_count=sum(
            keyword in searchable_url for keyword in SUSPICIOUS_KEYWORDS
        ),
        has_userinfo=parsed.username is not None or parsed.password is not None,
        has_punycode=any(label.startswith("xn--") for label in labels),
        domain_age_days=None,
    )


def score_url(features: UrlFeatures) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    if not features.uses_https:
        score += 0.12
        reasons.append("The URL does not use HTTPS.")
    if features.is_ip_host:
        score += 0.35
        reasons.append("The host is an IP address rather than a domain name.")
    if features.url_length > 120:
        score += 0.18
        reasons.append("The URL is unusually long.")
    elif features.url_length > 75:
        score += 0.08
        reasons.append("The URL is longer than typical.")
    if features.subdomain_count > 3:
        score += 0.12
        reasons.append("The URL contains many subdomains.")
    elif features.subdomain_count > 1:
        score += 0.06
        reasons.append("The URL contains multiple subdomains.")
    if features.suspicious_keyword_count:
        score += min(0.24, 0.08 * features.suspicious_keyword_count)
        reasons.append("The URL contains sign-in, account, or verification terms.")
    if features.has_userinfo:
        score += 0.20
        reasons.append("The URL includes user information before the host.")
    if features.has_punycode:
        score += 0.12
        reasons.append("The host contains an internationalized punycode label.")

    score = min(score, 1.0)
    if not reasons:
        reasons.append("No configured URL risk indicators were detected.")
    return round(score, 2), reasons
