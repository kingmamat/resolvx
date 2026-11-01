"""Domain registration data via raw WHOIS socket and SSL/TLS expiry checks.

WHOIS is a plain-text protocol on port 43 - no third-party client needed.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Any

from .dns_resolver import detect_backend as _detect_backend

WHOIS_PORT = 43
WHOIS_TIMEOUT = 10.0

TLD_REGISTRIES: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "co": "whois.nic.cc",
    "id": "whois.pandi.id",
    "co.id": "whois.pandi.id",
    "or.id": "whois.pandi.id",
    "go.id": "whois.pandi.id",
    "ac.id": "whois.pandi.id",
    "sch.id": "whois.pandi.id",
    "biz.id": "whois.pandi.id",
    "web.id": "whois.pandi.id",
    "dev.id": "whois.pandi.id",
    "my.id": "whois.pandi.id",
    "sch.my": "whois.whois.ms",
    "com.my": "whois.whois.ms",
    "gov.my": "whois.whois.ms",
    "org.my": "whois.whois.ms",
    "edu.my": "whois.whois.ms",
    "net.my": "whois.whois.ms",
    "co.th": "whois.thnic.co.th",
    "in": "whois.registry.in",
    "jp": "whois.nic.ad.jp",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "us": "whois.verisign-grs.com",
    "io": "whois.nic.io",
    "dev": "whois.nic.io",
    "app": "whois.nic.io",
    "me": "whois.nic.me",
    "tv": "whois.uniregistry.com",
    "co.nz": "whois.nz",
}


def _lookup_registry(domain: str) -> str:
    """Find the correct WHOIS registry server for the domain's TLD.
    Falls back to Verisign (handles .com/.net/.org).
    """
    parts = domain.rsplit(".", 2)
    if len(parts) >= 3:
        two_part = ".".join(parts[-2:])
        if two_part in TLD_REGISTRIES:
            return TLD_REGISTRIES[two_part]
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    return TLD_REGISTRIES.get(tld, "whois.verisign-grs.com")


def _extract_field(text: str, keys: tuple[str, ...]) -> str:
    for line in text.splitlines():
        normalized = line.strip().lower()
        for key in keys:
            if normalized.startswith(key):
                return line.split(":", 1)[-1].strip()
    return ""


@dataclass
class WhoisInfo:
    registrar: str = ""
    created: str = ""
    expiry: str = ""
    updated: str = ""
    nameservers: list[str] = field(default_factory=list)
    raw: str = ""
    error: str = ""


@dataclass
class SslInfo:
    valid: bool = False
    issuer: str = ""
    subject_cn: str = ""
    not_after: datetime.datetime | None = None
    days_remaining: int | None = None
    error: str = ""


def fetch_whois(domain: str) -> WhoisInfo:
    info = WhoisInfo()
    registry = _lookup_registry(domain)
    try:
        with socket.create_connection((registry, WHOIS_PORT), timeout=WHOIS_TIMEOUT) as sock:
            sock.sendall(f"{domain}\n".encode())
            buffer = bytearray()
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
        info.raw = buffer.decode(errors="replace")
        info.registrar = _extract_field(info.raw, ("registrar:", "sponsoring registrar:", "registrar name:"))
        info.created = _extract_field(info.raw, ("creation date:", "created on:", "registered on:", "registrar creation date:"))
        info.expiry = _extract_field(info.raw, ("expiry date:", "expiration date:", "registrar registration expiration date:", "paid-up until:", "dns expiry:", "exp date:", "expires on:"))
        info.updated = _extract_field(info.raw, ("last updated:", "updated date:", "last modified:", "registrar last updated:"))
        for line in info.raw.splitlines():
            if line.strip().lower().startswith(("name server:", "ns ", "dns ")):
                value = line.split(":", 1)[-1].strip() or line.strip()
                if value and "." in value:
                    info.nameservers.append(value)
    except OSError as exc:
        info.error = exc.strerror or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001
        info.error = str(exc)
    return info


def check_ssl(domain: str, port: int = 443, timeout: float = 8.0) -> SslInfo:
    info = SslInfo()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        info.issuer = ", ".join(issuer.values()) if issuer else "Unknown"
        info.subject_cn = subject.get("commonName", domain)
        _populate_ssl_fields(info, cert, domain)
    except ssl.SSLCertVerificationError:
        try:
            fallback = ssl.create_default_context()
            fallback.check_hostname = False
            fallback.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with fallback.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    cert = tls_sock.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            info.issuer = "Unknown (CA store unavailable)"
            info.subject_cn = subject.get("commonName", domain)
            _populate_ssl_fields(info, cert, domain)
        except Exception as exc:  # noqa: BLE001
            info.error = str(exc)
    except OSError as exc:
        info.error = exc.strerror or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001
        info.error = str(exc)
    return info


def _populate_ssl_fields(info: SslInfo, cert: dict, domain: str) -> None:
    not_after = cert.get("notAfter", "")
    if not_after:
        expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        info.not_after = expiry_dt
        info.days_remaining = (expiry_dt - datetime.datetime.utcnow()).days
        info.valid = info.days_remaining > 0


def ssl_status_color(days: int | None) -> str:
    if days is None:
        return "red"
    if days <= 0:
        return "red"
    if days <= 14:
        return "yellow"
    return "green"


async def fetch_whois_async(domain: str) -> WhoisInfo:
    return await asyncio.to_thread(fetch_whois, domain)


async def check_ssl_async(domain: str) -> SslInfo:
    return await asyncio.to_thread(check_ssl, domain)


async def detect_backend(domain: str) -> dict[str, object]:
    return await _detect_backend(domain)


async def domain_summary(domain: str) -> dict[str, Any]:
    whois = await fetch_whois_async(domain)
    ssl_info = await check_ssl_async(domain)
    backend = await detect_backend(domain)
    return {
        "whois": whois,
        "ssl": ssl_info,
        "backend": backend,
    }
