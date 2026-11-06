from __future__ import annotations

import socket
from typing import Any

from .url_parser import ParsedUrl, is_public_address


def resolve_addresses(parsed: ParsedUrl) -> list[str]:
    if parsed.is_ip:
        return [parsed.hostname]
    addresses: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            results = socket.getaddrinfo(parsed.hostname, parsed.port, family, socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            continue
        for result in results:
            address = result[4][0]
            if not is_public_address(address):
                raise ValueError("The hostname resolved to a local, private, or reserved address.")
            addresses.add(address)
    return sorted(addresses)


def collect_dns(parsed: ParsedUrl) -> dict[str, Any]:
    records: dict[str, list[str]] = {key: [] for key in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")}
    errors: list[str] = []
    try:
        addresses = resolve_addresses(parsed)
    except ValueError:
        raise
    except Exception as exc:
        addresses = []
        errors.append(type(exc).__name__)
    records["A"] = [item for item in addresses if "." in item]
    records["AAAA"] = [item for item in addresses if ":" in item]
    try:
        aliases = socket.gethostbyname_ex(parsed.hostname)[1]
        records["CNAME"] = sorted({alias.rstrip(".") for alias in aliases if alias.lower() != parsed.hostname.lower()})
    except OSError:
        pass
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        errors.append("DNS record provider is not installed")
    else:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 3.0
        for record_type in ("MX", "NS", "TXT", "SOA"):
            try:
                answers = resolver.resolve(parsed.hostname, record_type)
                if record_type == "MX":
                    records[record_type] = sorted(str(item.exchange).rstrip(".") for item in answers)
                else:
                    records[record_type] = sorted(str(item).strip('"') for item in answers)
            except Exception:
                continue
    return {
        "records": records,
        "resolved_ip_addresses": addresses,
        "status": "available" if addresses or any(records.values()) else "unavailable",
        "errors": errors,
        "source": "local resolver",
    }
