from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from .url_parser import ParsedUrl


def analyze_ssl(parsed: ParsedUrl, addresses: list[str]) -> dict[str, Any]:
    if parsed.scheme != "https":
        return {"status": "not_enabled", "https_enabled": False, "source": "URL scheme"}
    if not addresses:
        return {"status": "unavailable", "https_enabled": True, "source": "TLS socket", "error": "No public address resolved."}
    last_error = "TLS connection failed."
    for address in addresses[:2]:
        try:
            return _connect(parsed, address, verify=True)
        except ssl.SSLCertVerificationError as exc:
            last_error = "Certificate verification failed."
            try:
                result = _connect(parsed, address, verify=False)
                result["certificate_valid"] = False
                result["certificate_verification_error"] = str(exc.reason)
                result["status"] = "invalid_certificate"
                return result
            except (OSError, ssl.SSLError) as fallback_exc:
                last_error = type(fallback_exc).__name__
        except (OSError, ssl.SSLError) as exc:
            last_error = type(exc).__name__
    return {"status": "unavailable", "https_enabled": True, "source": "TLS socket", "error": last_error}


def _connect(parsed: ParsedUrl, address: str, verify: bool) -> dict[str, Any]:
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    with socket.create_connection((address, parsed.port), timeout=4) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=parsed.hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            valid_until = _certificate_date(certificate.get("notAfter"))
            return {
                "status": "valid" if verify else "unverified",
                "https_enabled": True,
                "certificate_valid": verify and (valid_until is None or valid_until > datetime.now(timezone.utc)),
                "issuer": _name(certificate.get("issuer", ())),
                "subject": _name(certificate.get("subject", ())),
                "valid_from": _certificate_date(certificate.get("notBefore")),
                "valid_until": valid_until,
                "expired": valid_until is not None and valid_until <= datetime.now(timezone.utc),
                "subject_alternative_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
                "tls_version": tls_socket.version(),
                "source": "TLS socket",
            }


def _name(value: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    for group in value:
        for key, item in group:
            if key == "commonName":
                return item
    return None


def _certificate_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None
