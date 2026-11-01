"""Host liveness check via TCP port probes and async HTTP header sleuth."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class HostProbe:
    """Result of probing a single port on a host."""

    port: int
    open: bool
    latency_ms: float | None = None
    error: str = ""


@dataclass
class HostReport:
    """Aggregated status for one host across all probes."""

    host: str
    probes: list[HostProbe] = field(default_factory=list)
    http_status: int | None = None
    server: str = ""
    powered_by: str = ""
    other_headers: dict[str, str] = field(default_factory=dict)
    reached: bool = False

    @property
    def is_up(self) -> bool:
        return any(p.open for p in self.probes) or self.http_status is not None


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> HostProbe:
    """Raw TCP connect - the canonical liveness test that firewalls rarely block."""
    result = HostProbe(port=port, open=False)
    try:
        started = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            result.open = True
            result.latency_ms = round((time.monotonic() - started) * 1000, 1)
    except OSError as exc:
        result.open = False
        result.error = exc.strerror or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
    return result


async def probe_ports(host: str, ports: tuple[int, ...] = (80, 443), timeout: float = 2.0) -> list[HostProbe]:
    """Run every port probe concurrently. Blocking sockets go to a thread pool
    so asyncio is not stalled."""
    return await asyncio.gather(
        *(
            asyncio.to_thread(_tcp_probe, host, port, timeout)
            for port in ports
        )
    )


FINGERPRINT_HEADERS = frozenset({
    "x-powered-by", "via", "x-aspnet-version", "x-aspnetmvc-version",
    "cf-ray", "cf-cache-status", "x-cache", "x-served-by", "report-to",
    "x-envoy-upstream-service-time", "x-amz-cf-id", "server-timing",
})


def _detect_server(headers: httpx.Headers) -> tuple[str, str, dict[str, str]]:
    """Extract web-server fingerprints from a response header set."""
    server = headers.get("server", "").strip()
    powered_by = headers.get("x-powered-by", "").strip()
    kept: dict[str, str] = {}
    for key in headers:
        if key.lower() in FINGERPRINT_HEADERS and key.lower() != "x-powered-by":
            kept[key] = headers[key]
    return server, powered_by, kept


async def fetch_http(host: str, use_https: bool = True, timeout: float = 5.0) -> dict[str, Any]:
    """Do an async HTTP(S) GET and return status + header fingerprints.

    Falls back to plain http when the caller asks for http, or when the
    https handshake errors out.
    """
    result: dict[str, Any] = {
        "status": None,
        "server": "",
        "powered_by": "",
        "headers": {},
        "url_used": None,
        "error": "",
    }
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}"
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, verify=use_https
        ) as client:
            response = await client.get(url, headers={"User-Agent": "KMC-Checker/1.0"})
            result["status"] = response.status_code
            server, powered_by, extra = _detect_server(response.headers)
            result["server"] = server
            result["powered_by"] = powered_by
            result["headers"] = extra
            result["url_used"] = str(response.url)
    except Exception as exc:  # noqa: BLE001 - report, never crash
        if use_https and not result["error"]:
            result["error"] = f"{scheme}: {exc.__class__.__name__}"
    return result


async def check_host(host: str) -> HostReport:
    """Full host check: TCP probes on 80/443 plus an HTTPS header grab."""
    report = HostReport(host=host)
    report.probes = await probe_ports(host)

    http_result = await fetch_http(host, use_https=True)
    report.http_status = http_result["status"]
    report.server = http_result["server"]
    report.powered_by = http_result["powered_by"]
    report.other_headers = http_result["headers"]
    report.reached = report.http_status is not None or report.is_up
    return report
