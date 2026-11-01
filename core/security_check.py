"""Security exposure scanner for KMC DNS & Host Checker.

Detects data-leak and misconfiguration issues across ports, paths, headers,
TLS, WHOIS PII, and DNS zone transfer. No new dependencies required.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import httpx

from .host_ping import _tcp_probe, fetch_http
from .domain_whois import fetch_whois


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    check: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    detail: str
    value: str = ""


@dataclass
class SecurityReport:
    domain: str
    findings: list[SecurityFinding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# port -> severity when open
EXPOSED_PORTS: dict[int, str] = {
    23: "CRITICAL",
    3389: "HIGH",
    5432: "HIGH",
    3306: "HIGH",
    27017: "HIGH",
    6379: "HIGH",
    8080: "MEDIUM",
    8443: "MEDIUM",
    8888: "MEDIUM",
    9200: "MEDIUM",
}

# path -> severity when it returns 200
SENSITIVE_PATHS: dict[str, str] = {
    "/.env": "CRITICAL",
    "/.git/HEAD": "CRITICAL",
    "/.git/config": "CRITICAL",
    "/.DS_Store": "CRITICAL",
    "/admin": "MEDIUM",
    "/wp-admin": "MEDIUM",
    "/wp-login.php": "MEDIUM",
    "/phpmyadmin": "MEDIUM",
    "/actuator/env": "MEDIUM",
    "/server-status": "MEDIUM",
    "/server-info": "MEDIUM",
}

# lowercase header name -> severity when missing
MISSING_HEADERS: dict[str, str] = {
    "content-security-policy": "HIGH",
    "strict-transport-security": "HIGH",
    "x-frame-options": "MEDIUM",
    "x-content-type-options": "MEDIUM",
    "referrer-policy": "LOW",
    "x-xss-protection": "LOW",
}

# Regex to catch version numbers in Server / X-Powered-By headers
VERSION_RE = re.compile(
    r"(\bApache\b/\d[\d.]*)"
    r"|(\bnginx\b/\d[\d.]*)"
    r"|(\bPHP\b/\d[\d.]*)"
    r"|(\bExpress\b)"
    r"|(\bASP\.NET\b)"
    r"|(\bPython\b/\d[\d.]*)"
    r"|(\bWSGI\b)"
    r"|(\bJSP\b)",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

# HTTP status that means "probably leaking" for sensitive paths
LEAKY_STATUSES: frozenset[int] = frozenset({200, 201, 204, 301, 302})


# ---------------------------------------------------------------------------
# Check functions — each returns a list of findings
# ---------------------------------------------------------------------------

async def _check_exposed_ports(domain: str) -> list[SecurityFinding]:
    """Probe EXPOSED_PORTS; open port = finding at configured severity."""
    findings: list[SecurityFinding] = []
    ports = tuple(EXPOSED_PORTS.keys())
    probes = await asyncio.gather(
        *(asyncio.to_thread(_tcp_probe, domain, p, 1.5) for p in ports)
    )
    for probe in probes:
        if probe.open:
            severity = EXPOSED_PORTS[probe.port]
            findings.append(SecurityFinding(
                check="Exposed port",
                severity=severity,
                detail=f"TCP port {probe.port} is open ({probe.latency_ms}ms)",
                value=str(probe.port),
            ))
    return findings


async def _check_sensitive_paths(domain: str, root_result: dict) -> list[SecurityFinding]:
    """GET each SENSITIVE_PATH; report status for anything that isn't 404."""
    if root_result.get("error") and not root_result.get("status"):
        # Host unreachable - skip path checks
        return []

    findings: list[SecurityFinding] = []
    scheme = "https" if root_result.get("status") else "http"

    async def probe_one(path: str) -> SecurityFinding | None:
        url = f"{scheme}://{domain}{path}"
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                resp = await client.get(url, headers={"User-Agent": "KMC-Checker/1.0"})
            status = resp.status_code
        except Exception:
            return None

        if status == 404:
            return None
        if status in LEAKY_STATUSES:
            severity = SENSITIVE_PATHS.get(path, "MEDIUM")
            return SecurityFinding(
                check="Sensitive path",
                severity=severity,
                detail=f"{path} returned HTTP {status}",
                value=path,
            )
        # 403 or other protected status
        return SecurityFinding(
            check="Sensitive path",
            severity="LOW",
            detail=f"{path} returned HTTP {status} (protected)",
            value=path,
        )

    results = await asyncio.gather(*[probe_one(p) for p in SENSITIVE_PATHS.keys()])
    return [f for f in results if f is not None]


async def _check_version_disclosure(root_result: dict) -> list[SecurityFinding]:
    """Detect version strings in Server / X-Powered-By headers."""
    findings: list[SecurityFinding] = []
    headers = root_result.get("headers", {})
    # Server and X-Powered-By are kept separately; add them to a merged view
    merged = {
        "server": root_result.get("server", ""),
        "x-powered-by": root_result.get("powered_by", ""),
        **{k: v for k, v in headers.items()},
    }
    for key, value in merged.items():
        if not value:
            continue
        match = VERSION_RE.search(value)
        if match:
            findings.append(SecurityFinding(
                check="Version disclosure",
                severity="MEDIUM",
                detail=f"{key}: {value}",
                value=match.group(0),
            ))
    return findings


async def _check_missing_headers(root_result: dict) -> list[SecurityFinding]:
    """Report security headers that are absent from the response."""
    if root_result.get("error") and not root_result.get("status"):
        return []

    findings: list[SecurityFinding] = []
    present_keys = {k.lower() for k in root_result.get("headers", {})}
    # Also check top-level server/powered_by keys
    all_keys = present_keys | {k.lower() for k in root_result.get("headers", {})}
    for header_name, severity in MISSING_HEADERS.items():
        if header_name not in all_keys:
            findings.append(SecurityFinding(
                check="Missing header",
                severity=severity,
                detail=f"{header_name} header is not set",
                value=header_name,
            ))
    return findings


async def _check_cookies(root_result: dict) -> list[SecurityFinding]:
    """Check Set-Cookie flags: Secure, HttpOnly, SameSite."""
    findings: list[SecurityFinding] = []
    set_cookie = root_result.get("headers", {}).get("set-cookie", "")
    if not set_cookie:
        return findings

    cookie = set_cookie.lower()
    if "secure" not in cookie:
        findings.append(SecurityFinding(
            check="Cookie security",
            severity="MEDIUM",
            detail="Set-Cookie missing Secure flag",
        ))
    if "httponly" not in cookie:
        findings.append(SecurityFinding(
            check="Cookie security",
            severity="MEDIUM",
            detail="Set-Cookie missing HttpOnly flag",
        ))
    if "samesite" not in cookie:
        findings.append(SecurityFinding(
            check="Cookie security",
            severity="LOW",
            detail="Set-Cookie missing SameSite attribute",
        ))
    return findings


async def _check_cors(root_result: dict) -> list[SecurityFinding]:
    """Detect CORS misconfigurations."""
    findings: list[SecurityFinding] = []
    headers = root_result.get("headers", {})
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()

    if acao == "*":
        if acac == "true":
            findings.append(SecurityFinding(
                check="CORS misconfig",
                severity="HIGH",
                detail="Access-Control-Allow-Origin: * combined with credentials",
            ))
        else:
            findings.append(SecurityFinding(
                check="CORS misconfig",
                severity="MEDIUM",
                detail="Access-Control-Allow-Origin: * (wildcard)",
            ))
    return findings


async def _check_whois_pii(domain: str) -> list[SecurityFinding]:
    """Fetch WHOIS and check for exposed email addresses."""
    try:
        whois = await asyncio.to_thread(fetch_whois, domain)
    except Exception as exc:
        return [SecurityFinding(
            check="WHOIS PII",
            severity="INFO",
            detail=f"WHOIS lookup failed: {exc}",
        )]

    if whois.error:
        return [SecurityFinding(
            check="WHOIS PII",
            severity="INFO",
            detail=f"WHOIS returned error: {whois.error}",
        )]

    emails = set(EMAIL_RE.findall(whois.raw))
    # Filter out obvious placeholder / null values
    emails = {e for e in emails if not e.endswith((".null", "none", "n/a"))}

    if emails:
        sample = ", ".join(list(emails)[:3])
        return [SecurityFinding(
            check="WHOIS PII",
            severity="MEDIUM",
            detail=f"{len(emails)} email address(es) public in WHOIS: {sample}",
            value=sample,
        )]
    return [SecurityFinding(
        check="WHOIS PII",
        severity="INFO",
        detail="No email address found in WHOIS record (PII protected or record unavailable)",
    )]


async def _check_tls_weak(domain: str) -> list[SecurityFinding]:
    """Test whether the server accepts TLSv1.0 or TLSv1.1 connections."""
    findings: list[SecurityFinding] = []

    def probe_protocol(protocol: int, label: str) -> SecurityFinding | None:
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    pass
            return SecurityFinding(
                check="TLS weak protocol",
                severity="HIGH",
                detail=f"Server accepts {label} (deprecated / broken)",
            )
        except (OSError, ssl.SSLError):
            return None

    for proto, label in [(ssl.PROTOCOL_TLSv1, "TLSv1.0"), (ssl.PROTOCOL_TLSv1_1, "TLSv1.1")]:
        try:
            result = await asyncio.to_thread(probe_protocol, proto, label)
            if result:
                findings.append(result)
        except Exception:
            pass

    if not findings:
        findings.append(SecurityFinding(
            check="TLS weak protocol",
            severity="INFO",
            detail="TLSv1.0 and TLSv1.1 rejected - modern protocols only",
        ))
    return findings


async def _check_axfr(domain: str) -> list[SecurityFinding]:
    """Attempt DNS AXFR zone transfer against each NS. Success = critical leak."""
    findings: list[SecurityFinding] = []

    def do_axfr() -> list[SecurityFinding]:
        out: list[SecurityFinding] = []
        # Resolve NS records to get the authoritative servers
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
        except Exception:
            return out

        axfr_type = dns.rdatatype.from_text("AXFR")
        target = dns.name.from_text(domain)
        rdata_class = dns.rdataclass.from_text("IN")

        for ns in ns_records:
            ns_name = ns.to_text().rstrip(".")
            try:
                message = dns.message.make_query(target, axfr_type, rdata_class)
                response = dns.query.send(message, ns_name, timeout=3)
                rcount = response.answer[0] if response.answer else 0
                if rcount >= 1:
                    out.append(SecurityFinding(
                        check="DNS zone transfer",
                        severity="CRITICAL",
                        detail=f"AXFR allowed on {ns_name} - full zone exposed",
                        value=ns_name,
                    ))
            except dns.exception.Timeout:
                out.append(SecurityFinding(
                    check="DNS zone transfer",
                    severity="INFO",
                    detail=f"AXFR query to {ns_name} timed out (likely blocked)",
                    value=ns_name,
                ))
            except Exception:
                out.append(SecurityFinding(
                    check="DNS zone transfer",
                    severity="INFO",
                    detail=f"AXFR to {ns_name} refused or failed (expected)",
                    value=ns_name,
                ))
        return out

    findings = await asyncio.to_thread(do_axfr)
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def security_check(domain: str) -> SecurityReport:
    """Run all security checks concurrently and return a sorted SecurityReport."""
    # One root fetch for header-based checks (https, fallback http)
    root_result: dict = {}
    try:
        root_result = await fetch_http(domain, use_https=True)
        if root_result.get("error") and not root_result.get("status"):
            root_result = await fetch_http(domain, use_https=False)
    except Exception:
        root_result = {"error": "fetch failed", "headers": {}, "status": None}

    all_checks = [
        _check_exposed_ports(domain),
        _check_sensitive_paths(domain, root_result),
        _check_version_disclosure(root_result),
        _check_missing_headers(root_result),
        _check_cookies(root_result),
        _check_cors(root_result),
        _check_whois_pii(domain),
        _check_tls_weak(domain),
        _check_axfr(domain),
    ]
    results = await asyncio.gather(*all_checks, return_exceptions=True)

    findings: list[SecurityFinding] = []
    for r in results:
        if isinstance(r, Exception):
            findings.append(SecurityFinding(
                check="Internal",
                severity="INFO",
                detail=f"Check failed: {r}",
            ))
        elif isinstance(r, list):
            findings.extend(r)

    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 99))
    return SecurityReport(domain=domain, findings=findings)
