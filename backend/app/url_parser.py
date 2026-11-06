from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit


_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.in", "com.br", "com.cn", "com.mx", "co.nz", "co.za",
}


@dataclass(frozen=True)
class ParsedUrl:
    submitted_url: str
    normalized_url: str
    scheme: str
    hostname: str
    domain: str
    registered_domain: str
    subdomain: str
    tld: str | None
    port: int
    path: str
    query: str | None
    fragment: str | None
    origin: str
    is_ip: bool

    @property
    def host_header(self) -> str:
        return f"[{self.hostname}]" if ":" in self.hostname else self.hostname


def parse_url(value: str) -> ParsedUrl:
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError("Enter a URL without leading, trailing, or control characters.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("Only absolute HTTP and HTTPS URLs can be analyzed.")
    hostname = hostname.rstrip(".").lower()
    _validate_hostname(hostname)
    port = explicit_port or (443 if scheme == "https" else 80)
    if port not in {80, 443}:
        raise ValueError("Only HTTP and HTTPS ports 80 and 443 can be analyzed.")
    is_ip = _is_ip(hostname)
    domain, registered_domain, subdomain, tld = _domain_parts(hostname, is_ip)
    normalized_host = f"[{hostname}]" if ":" in hostname else hostname
    normalized = urlunsplit((scheme, f"{normalized_host}:{port}" if explicit_port else normalized_host,
                             parsed.path or "/", parsed.query, parsed.fragment))
    origin = f"{scheme}://{normalized_host}:{port}" if explicit_port else f"{scheme}://{normalized_host}"
    return ParsedUrl(
        submitted_url=value,
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        domain=domain,
        registered_domain=registered_domain,
        subdomain=subdomain,
        tld=tld,
        port=port,
        path=parsed.path or "/",
        query=parsed.query or None,
        fragment=parsed.fragment or None,
        origin=origin,
        is_ip=is_ip,
    )


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _validate_hostname(hostname: str) -> None:
    if _is_ip(hostname):
        if not is_public_address(hostname):
            raise ValueError("Local, private, and reserved IP addresses cannot be analyzed.")
        return
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Local hostnames cannot be analyzed.")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Enter a URL with a valid hostname.") from exc
    labels = ascii_hostname.split(".")
    if len(ascii_hostname) > 253 or any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Enter a URL with a valid hostname.")


def _domain_parts(hostname: str, is_ip: bool) -> tuple[str, str, str, str | None]:
    if is_ip:
        return hostname, hostname, "", None
    labels = hostname.split(".")
    tld = labels[-1] if labels else None
    suffix_size = 2 if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES else 1
    registered_size = min(len(labels), suffix_size + 1)
    registered = ".".join(labels[-registered_size:])
    subdomain = ".".join(labels[:-registered_size])
    return hostname, registered, subdomain, tld
