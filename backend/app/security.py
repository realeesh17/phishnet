from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Mapping

from limits import parse
from limits.storage import MemoryStorage, RedisStorage
from limits.strategies import MovingWindowRateLimiter
from starlette.types import ASGIApp, Message, Receive, Scope, Send


logger = logging.getLogger("phishnet.security")


@dataclass(frozen=True)
class SecuritySettings:
    environment: str
    max_request_bytes: int
    max_concurrent_requests: int
    max_concurrent_requests_per_client: int
    rate_limit: str
    rate_limit_storage_url: str
    trusted_proxy_cidrs: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    cors_origins: tuple[str, ...]

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SecuritySettings:
        values = os.environ if env is None else env
        environment = values.get(
            "PHISHNET_ENV", values.get("AZURE_FUNCTIONS_ENVIRONMENT", "development")
        ).strip().lower()

        def positive_int(name: str, default: int) -> int:
            try:
                value = int(values.get(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be a positive integer.") from exc
            if value < 1:
                raise ValueError(f"{name} must be a positive integer.")
            return value

        trusted_proxies = tuple(
            item.strip()
            for item in values.get("PHISHNET_TRUSTED_PROXY_CIDRS", "").split(",")
            if item.strip()
        )
        for network in trusted_proxies:
            ipaddress.ip_network(network, strict=False)

        return cls(
            environment=environment,
            max_request_bytes=positive_int("PHISHNET_MAX_REQUEST_BYTES", 16_384),
            max_concurrent_requests=positive_int("PHISHNET_MAX_CONCURRENT_REQUESTS", 32),
            max_concurrent_requests_per_client=positive_int(
                "PHISHNET_MAX_CONCURRENT_REQUESTS_PER_CLIENT", 4
            ),
            rate_limit=values.get("PHISHNET_RATE_LIMIT", "30/minute").strip(),
            rate_limit_storage_url=values.get("PHISHNET_RATE_LIMIT_STORAGE_URL", "").strip(),
            trusted_proxy_cidrs=trusted_proxies,
            allowed_hosts=tuple(
                item.strip()
                for item in values.get(
                    "PHISHNET_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver,testclient"
                ).split(",")
                if item.strip()
            ),
            cors_origins=tuple(
                item.strip()
                for item in values.get(
                    "PHISHNET_CORS_ORIGINS",
                    "http://localhost:5173,http://127.0.0.1:5173",
                ).split(",")
                if item.strip()
            ),
        )


class ConcurrencyLimiter:
    def __init__(self, total_limit: int, per_client_limit: int) -> None:
        self.total_limit = total_limit
        self.per_client_limit = per_client_limit
        self._active_by_client: dict[str, int] = {}
        self._active_total = 0
        self._lock = threading.Lock()

    def acquire(self, client: str) -> bool:
        with self._lock:
            active = self._active_by_client.get(client, 0)
            if self._active_total >= self.total_limit or active >= self.per_client_limit:
                return False
            self._active_total += 1
            self._active_by_client[client] = active + 1
            return True

    def release(self, client: str) -> None:
        with self._lock:
            active = self._active_by_client.get(client, 0)
            if active <= 1:
                self._active_by_client.pop(client, None)
            else:
                self._active_by_client[client] = active - 1
            self._active_total = max(0, self._active_total - 1)


class SecurityControls:
    def __init__(self, settings: SecuritySettings) -> None:
        storage = (
            RedisStorage(settings.rate_limit_storage_url)
            if settings.rate_limit_storage_url
            else MemoryStorage()
        )
        self.storage = storage
        self.rate_limit_item = parse(settings.rate_limit)
        self.rate_limiter = MovingWindowRateLimiter(storage)
        self.concurrency = ConcurrencyLimiter(
            settings.max_concurrent_requests,
            settings.max_concurrent_requests_per_client,
        )

    def allow_request(self, client: str) -> bool:
        return self.rate_limiter.hit(self.rate_limit_item, client)


def _ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def _trusted(address: ipaddress.IPv4Address | ipaddress.IPv6Address, cidrs: tuple[str, ...]) -> bool:
    return any(address in ipaddress.ip_network(network, strict=False) for network in cidrs)


def client_ip(scope: Scope, trusted_proxy_cidrs: tuple[str, ...]) -> str:
    peer_host = (scope.get("client") or ("unknown", 0))[0]
    peer_address = _ip_address(peer_host)
    if peer_address is None or not _trusted(peer_address, trusted_proxy_cidrs):
        return str(peer_address) if peer_address is not None else peer_host

    forwarded_values = [
        value.decode("latin-1")
        for name, value in scope.get("headers", [])
        if name.lower() == b"x-forwarded-for"
    ]
    forwarded = ",".join(forwarded_values)
    if not forwarded:
        return str(peer_address)

    chain = [_ip_address(item) for item in forwarded.split(",")]
    if any(item is None for item in chain):
        return str(peer_address)

    addresses = [item for item in chain if item is not None]
    for address in reversed(addresses):
        if not _trusted(address, trusted_proxy_cidrs):
            return str(address)
    return str(addresses[0]) if addresses else str(peer_address)


class SecurityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        settings: SecuritySettings,
        controls: SecurityControls,
    ) -> None:
        self.app = app
        self.settings = settings
        self.controls = controls
        self.trusted_proxies = tuple(
            ipaddress.ip_network(network, strict=False)
            for network in settings.trusted_proxy_cidrs
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        peer = (scope.get("client") or ("unknown", 0))[0]
        peer_address = _ip_address(peer)
        trusted_peer = peer_address is not None and any(
            peer_address in network for network in self.trusted_proxies
        )
        secure = scope.get("scheme") == "https"
        if trusted_peer:
            forwarded_proto = [
                value.decode("latin-1")
                for name, value in scope.get("headers", [])
                if name.lower() == b"x-forwarded-proto"
            ]
            if forwarded_proto:
                secure = forwarded_proto[-1].split(",")[-1].strip().lower() == "https"

        send_response = self._secure_sender(send, secure)
        if self.settings.production and not secure:
            await self._reject(
                send_response,
                400,
                "HTTPS_REQUIRED",
                "This service requires HTTPS.",
            )
            return

        remote_ip = client_ip(scope, self.settings.trusted_proxy_cidrs)
        try:
            allowed = self.controls.allow_request(remote_ip)
        except Exception as exc:
            logger.error("rate_limit_storage_failed", error_type=type(exc).__name__)
            await self._reject(
                send_response,
                503,
                "SERVICE_UNAVAILABLE",
                "Request protection is temporarily unavailable.",
            )
            return
        if not allowed:
            await self._reject(
                send_response,
                429,
                "RATE_LIMITED",
                "Too many requests. Please try again later.",
                [(b"retry-after", b"60")],
            )
            return

        if not self.controls.concurrency.acquire(remote_ip):
            await self._reject(
                send_response,
                429,
                "RATE_LIMITED",
                "Too many requests are being processed. Please try again shortly.",
                [(b"retry-after", b"1")],
            )
            return

        try:
            content_length = self._header(scope, b"content-length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    await self._reject(send_response, 400, "BAD_REQUEST", "Invalid request.")
                    return
                if declared_size < 0 or declared_size > self.settings.max_request_bytes:
                    await self._reject(
                        send_response,
                        413,
                        "REQUEST_TOO_LARGE",
                        "The request body is too large.",
                    )
                    return

            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    continue
                body.extend(message.get("body", b""))
                if len(body) > self.settings.max_request_bytes:
                    await self._reject(
                        send_response,
                        413,
                        "REQUEST_TOO_LARGE",
                        "The request body is too large.",
                    )
                    return
                if not message.get("more_body", False):
                    break

            body_sent = False

            async def replay_body() -> Message:
                nonlocal body_sent
                if body_sent:
                    return {"type": "http.disconnect"}
                body_sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            await self.app(scope, replay_body, send_response)
        finally:
            self.controls.concurrency.release(remote_ip)

    @staticmethod
    def _header(scope: Scope, name: bytes) -> str | None:
        for header_name, value in scope.get("headers", []):
            if header_name.lower() == name:
                return value.decode("latin-1")
        return None

    def _secure_sender(self, send: Send, secure: bool) -> Send:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"cache-control", b"no-store"),
                ]
                if self.settings.production and secure:
                    security_headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                existing = {name.lower() for name, _ in headers}
                headers.extend(
                    (name, value) for name, value in security_headers if name not in existing
                )
                message["headers"] = headers
            await send(message)

        return send_with_headers

    @staticmethod
    async def _reject(
        send: Send,
        status: int,
        code: str,
        message: str,
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        body = json.dumps(
            {"error": {"code": code, "message": message, "details": None}}
        ).encode("utf-8")
        response_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        response_headers.extend(headers or [])
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": body})