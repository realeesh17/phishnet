from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .url_parser import ParsedUrl


_CACHE_SECONDS = 900
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def lookup_domain(parsed: ParsedUrl) -> dict[str, Any]:
    if parsed.is_ip:
        return {"status": "not_applicable", "source": "RDAP", "reason": "IP literal has no domain registration record."}
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(parsed.registered_domain)
        if cached and cached[0] > now:
            return cached[1]
    if parsed.tld == "example":
        result = {"status": "unavailable", "source": "RDAP", "reason": "Reserved example domain."}
    else:
        result = _fetch_rdap(parsed.registered_domain)
    with _cache_lock:
        _cache[parsed.registered_domain] = (now + _CACHE_SECONDS, result)
    return result


def _fetch_rdap(domain: str) -> dict[str, Any]:
    request = Request(
        f"https://rdap.org/domain/{domain}",
        headers={"Accept": "application/rdap+json", "User-Agent": "PhishNet/2.0"},
    )
    try:
        with urlopen(request, timeout=4) as response:
            payload = json.loads(response.read(500_000).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "source": "RDAP", "reason": _error_text(exc)}
    events = {item.get("eventAction"): item.get("eventDate") for item in payload.get("events", [])}
    creation = _parse_date(events.get("registration"))
    expiration = _parse_date(events.get("expiration"))
    updated = _parse_date(events.get("last changed") or events.get("last update"))
    age_days = (datetime.now(timezone.utc) - creation).days if creation else None
    registrar = None
    for entity in payload.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        for item in entity.get("vcardArray", [None, []])[1]:
            if len(item) >= 4 and item[0] == "fn":
                registrar = item[3]
                break
    result = {
        "status": "available",
        "source": "RDAP",
        "registrar": registrar,
        "creation_date": creation.isoformat() if creation else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "last_updated_date": updated.isoformat() if updated else None,
        "domain_age_days": age_days,
        "recently_registered": age_days is not None and age_days < 30,
        "nameservers": sorted({item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")}),
        "dnssec": payload.get("secureDNS", {}).get("delegationSigned") if isinstance(payload.get("secureDNS"), dict) else None,
        "registration_status": payload.get("status", []),
    }
    return result


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _error_text(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"RDAP returned HTTP {exc.code}."
    if isinstance(exc, URLError):
        return "RDAP provider could not be reached."
    return "RDAP lookup unavailable."
