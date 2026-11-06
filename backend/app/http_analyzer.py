from __future__ import annotations

import socket
import ssl
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin

from .dns_intelligence import resolve_addresses
from .url_parser import ParsedUrl, parse_url


MAX_RESPONSE_BYTES = 128_000
MAX_REDIRECTS = 5


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = None
        self.favicon = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "meta" and attributes.get("name", "").lower() == "description":
            self.description = attributes.get("content")
        if tag.lower() == "link" and attributes.get("rel", "").lower() in {"icon", "shortcut icon"}:
            self.favicon = attributes.get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            self.title = data.strip()[:300]


def analyze_http(parsed: ParsedUrl) -> dict[str, Any]:
    current = parsed
    redirects: list[dict[str, Any]] = []
    started = time.perf_counter()
    last: dict[str, Any] = {}
    for _ in range(MAX_REDIRECTS + 1):
        addresses = resolve_addresses(current)
        if not addresses:
            return {"status": "unavailable", "error": "No public address resolved.", "redirects": redirects}
        last = _request_once(current, addresses[0])
        location = last.get("headers", {}).get("location")
        if not location or not 300 <= int(last.get("status_code", 0)) < 400:
            break
        target = parse_url(urljoin(current.normalized_url, location))
        redirects.append({"from": current.normalized_url, "to": target.normalized_url, "status_code": last.get("status_code")})
        current = target
    else:
        last["error"] = "Redirect limit exceeded."
    return {
        **last,
        "status": "available" if last else "unavailable",
        "final_url": current.normalized_url,
        "redirect_chain": redirects,
        "redirect_count": len(redirects),
        "response_time_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _request_once(parsed: ParsedUrl, address: str) -> dict[str, Any]:
    raw_socket = socket.create_connection((address, parsed.port), timeout=4)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            try:
                connection = context.wrap_socket(raw_socket, server_hostname=parsed.hostname)
                tls_error = None
            except ssl.SSLCertVerificationError as exc:
                raw_socket.close()
                raw_socket = socket.create_connection((address, parsed.port), timeout=4)
                connection = ssl._create_unverified_context().wrap_socket(raw_socket, server_hostname=parsed.hostname)
                tls_error = "Certificate verification failed."
        else:
            connection = raw_socket
            tls_error = None
        request_path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
        if parsed.query:
            request_path += f"?{parsed.query}"
        request = (
            f"GET {request_path} HTTP/1.1\r\nHost: {parsed.host_header}\r\n"
            "User-Agent: PhishNet/2.0\r\nAccept: text/html,application/xhtml+xml\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).encode("ascii", "ignore")
        connection.sendall(request)
        reader = connection.makefile("rb")
        status_line = reader.readline(4096).decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers: dict[str, str] = {}
        while True:
            line = reader.readline(8192)
            if line in {b"\r\n", b"\n", b""}:
                break
            name, _, value = line.decode("latin-1", "replace").partition(":")
            if name:
                headers[name.lower()] = value.strip()
        body = reader.read(MAX_RESPONSE_BYTES + 1)
        limited = len(body) > MAX_RESPONSE_BYTES
        body = body[:MAX_RESPONSE_BYTES]
        content_type = headers.get("content-type")
        page = _PageParser()
        if content_type and "html" in content_type.lower():
            try:
                page.feed(body.decode("utf-8", "replace"))
            except Exception:
                pass
        return {
            "status_code": status_code,
            "headers": headers,
            "server": headers.get("server"),
            "content_type": content_type,
            "content_length": len(body),
            "response_size_limited": limited,
            "title": page.title or None,
            "description": page.description,
            "favicon_url": urljoin(parsed.normalized_url, page.favicon) if page.favicon else None,
            "security_headers": {key: headers.get(key) for key in (
                "strict-transport-security", "content-security-policy", "x-frame-options",
                "x-content-type-options", "referrer-policy",
            )},
            "tls_certificate_verification_error": tls_error,
        }
    finally:
        try:
            connection.close()  # type: ignore[has-type]
        except (NameError, OSError):
            raw_socket.close()
