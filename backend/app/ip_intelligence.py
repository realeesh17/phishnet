from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def collect_ip_intelligence(addresses: list[str]) -> list[dict[str, Any]]:
    return [_lookup(address) for address in addresses[:4]]


def _lookup(address: str) -> dict[str, Any]:
    parsed = ipaddress.ip_address(address)
    result: dict[str, Any] = {
        "ip": address,
        "version": parsed.version,
        "classification": "public" if parsed.is_global else "private_or_reserved",
        "reverse_dns": None,
        "status": "available" if parsed.is_global else "blocked",
    }
    if not parsed.is_global:
        return result
    try:
        result["reverse_dns"] = socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror):
        pass
    request = Request(f"https://ipwho.is/{address}", headers={"User-Agent": "PhishNet/2.0"})
    try:
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read(100_000).decode("utf-8"))
        connection = payload.get("connection") or {}
        result.update({
            "asn": connection.get("asn"),
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "country": payload.get("country"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "status": "available" if payload.get("success", True) else "unavailable",
            "source": "ipwho.is",
        })
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        result["status"] = "partially_available"
        result["source"] = "reverse DNS only"
    return result
