from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .url_parser import ParsedUrl


def build_intelligence_report(
    parsed: ParsedUrl,
    dns_info: dict[str, Any],
    ip_info: list[dict[str, Any]],
    domain_info: dict[str, Any],
    ssl_info: dict[str, Any],
    http_info: dict[str, Any],
    phishing: dict[str, Any],
) -> dict[str, Any]:
    return {
        "submitted_url": parsed.submitted_url,
        "normalized_url": parsed.normalized_url,
        "url_parts": {
            "protocol": parsed.scheme.upper(), "hostname": parsed.hostname, "domain": parsed.domain,
            "registered_domain": parsed.registered_domain, "subdomain": parsed.subdomain,
            "tld": parsed.tld, "port": parsed.port, "path": parsed.path,
            "query": parsed.query, "fragment": parsed.fragment, "origin": parsed.origin,
        },
        "domain_info": domain_info,
        "dns": dns_info,
        "ip_intelligence": ip_info,
        "resolved_ip_addresses": dns_info.get("resolved_ip_addresses", []),
        "ssl": ssl_info,
        "http": http_info,
        "redirects": http_info.get("redirect_chain", []),
        "phishing": phishing,
        "scan_metadata": {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "partial_results": any(item.get("status") in {"unavailable", "partially_available"} for item in [domain_info, dns_info, ssl_info, http_info]),
            "active_content_executed": False,
        },
    }
