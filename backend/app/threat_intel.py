from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .features import parse_http_url


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
FEED_CACHE_SECONDS = 300
MAX_FEED_BYTES = 5_000_000
REQUEST_TIMEOUT_SECONDS = 3


@dataclass(frozen=True)
class ProviderResult:
    name: str
    status: str
    matched: bool | None
    error: str | None = None

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "name": self.name,
            "status": self.status,
            "matched": self.matched,
            "error": self.error,
        }


def _request_error(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"Provider returned HTTP {exc.code}."
    if isinstance(exc, (TimeoutError, URLError)):
        return "Provider could not be reached."
    if isinstance(exc, json.JSONDecodeError):
        return "Provider returned an invalid response."
    return "Provider request failed."


class ThreatIntel:
    def __init__(
        self,
        openphish_enabled: bool | None = None,
        phishtank_api_key: str | None = None,
    ) -> None:
        if openphish_enabled is None:
            openphish_enabled = os.getenv("OPENPHISH_ENABLED", "false").lower() == "true"
        self.openphish_enabled = openphish_enabled
        self.phishtank_api_key = (
            phishtank_api_key if phishtank_api_key is not None else os.getenv("PHISHTANK_API_KEY", "")
        )
        self._feed: set[str] = set()
        self._feed_expires_at = 0.0
        self._feed_lock = threading.Lock()

    def check(self, url: str) -> list[ProviderResult]:
        results: list[ProviderResult] = []
        if self.openphish_enabled:
            results.append(self._check_openphish(url))
        else:
            results.append(ProviderResult("OpenPhish", "disabled", None))

        if self.phishtank_api_key:
            results.append(self._check_phishtank(url))
        else:
            results.append(ProviderResult("PhishTank", "disabled", None))
        return results

    def _check_openphish(self, url: str) -> ProviderResult:
        try:
            with self._feed_lock:
                if time.monotonic() >= self._feed_expires_at:
                    request = Request(
                        OPENPHISH_FEED_URL,
                        headers={"User-Agent": "PhishNet/1.0"},
                    )
                    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                        content = response.read(MAX_FEED_BYTES + 1)
                    if len(content) > MAX_FEED_BYTES:
                        raise ValueError("OpenPhish feed exceeded the configured size limit.")
                    self._feed = {
                        line.strip()
                        for line in content.decode("utf-8").splitlines()
                        if line.strip()
                    }
                    self._feed_expires_at = time.monotonic() + FEED_CACHE_SECONDS
            return ProviderResult("OpenPhish", "checked", url in self._feed)
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, ValueError) as exc:
            return ProviderResult("OpenPhish", "unavailable", None, _request_error(exc))

    def _check_phishtank(self, url: str) -> ProviderResult:
        try:
            body = urlencode(
                {
                    "url": url,
                    "format": "json",
                    "app_key": self.phishtank_api_key,
                }
            ).encode("utf-8")
            request = Request(
                PHISHTANK_CHECK_URL,
                data=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "PhishNet/1.0",
                },
                method="POST",
            )
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read(100_000).decode("utf-8"))
            in_database = payload.get("results", {}).get("in_database")
            if not isinstance(in_database, bool):
                raise ValueError("PhishTank response did not contain a valid match result.")
            return ProviderResult("PhishTank", "checked", in_database)
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return ProviderResult("PhishTank", "unavailable", None, _request_error(exc))
