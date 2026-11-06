"""Database Security & Leakage Recon Scanner.

Scans domain databases to detect exposed ports, weak service banners,
and common leaked credentials without requiring valid user access.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

import httpx


@dataclass
class DatabaseFinding:
    check: str
    severity: str
    detail: str
    value: str = ""

@dataclass
class DatabaseAuditReport:
    domain: str
    findings: list[DatabaseFinding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("CRITICAL", "HIGH"))

# 1. Port -> Severity Mapping
DB_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
}

# 2. Common default cred guesses
DEFAULT_CREDS = {
    3306: ["root", "", "root", "password", "admin"],
    5432: ["postgres", "", "postgres", "password", "admin"],
}


def _probe_db_port(domain: str, port: int, timeout: float = 2.0) -> tuple[bool, float | None]:
    """TCP connect and check if port is open."""
    try:
        start = asyncio.get_event_loop().time()
        with socket.create_connection((domain, port), timeout=timeout):
            latency = (asyncio.get_event_loop().time() - start) * 1000
            return True, latency
    except (OSError, ConnectionRefusedError, socket.timeout):
        return False, None


def _try_default_creds(username: str, password: str, host: str, port: int, engine: str) -> str | None:
    """Tries to connect with guessed credentials to see if default settings exist."""
    try:
        if engine.lower() == "mysql":
            import pymysql
            conn = pymysql.connect(host=host, port=port, user=username, password=password, connect_timeout=2)
            if conn:
                conn.close()
                return "Connected to MySQL default credentials"
        elif engine.lower() == "postgresql":
            import psycopg2
            conn = psycopg2.connect(host=host, port=port, user=username, password=password, connect_timeout=2)
            if conn:
                conn.close()
                return "Connected to PostgreSQL default credentials"
    except Exception as e:
        pass
    return None


async def _check_ports(domain: str) -> list[DatabaseFinding]:
    """Check if database service is listening on the public IP."""
    findings: list[DatabaseFinding] = []

    def _probe():
        results = []
        for port, engine in DB_PORTS.items():
            open, latency = _probe_db_port(domain, port)
            results.append((port, engine, open, latency))
        return results

    probes = await asyncio.to_thread(_probe)

    for port, engine, open, latency in probes:
        if open:
            findings.append(DatabaseFinding(
                check="Exposed Database Port",
                severity="HIGH",
                detail=f"{engine} port {port} is open to the internet ({latency}ms)",
                value=f"{domain}:{port}"
            ))
    return findings


async def _check_banners(domain: str) -> list[DatabaseFinding]:
    """Check if exposed DB version discloses exact version string."""
    findings: list[DatabaseFinding] = []

    def _probe():
        for port, engine in DB_PORTS.items():
            open, _ = _probe_db_port(domain, port)
            if not open: continue

            # Read greeting banner
            try:
                with socket.create_connection((domain, port), timeout=2.0) as sock:
                    # Attempt basic banner grab
                    data = sock.recv(1024)
                    banner = data.decode('utf-8', errors='ignore')
                    if '5.7' in banner or '8.0' in banner or '9.0' in banner:
                        findings.append(DatabaseFinding(
                            check="Version Disclosure",
                            severity="MEDIUM",
                            detail=f"{engine} service exposed raw version banner: {banner.strip()[:30]}",
                            value=banner.strip()
                        ))
            except Exception:
                pass
        return findings

    return await asyncio.to_thread(_probe)


async def _check_env_leaks(domain: str) -> list[DatabaseFinding]:
    """Check if standard sensitive paths like .env are leaking DB passwords."""
    findings: list[DatabaseFinding] = []

    async def _fetch_env():
        targets = ["/.env", "/config.php", "/wp-config.php", "/.env.local"]
        for target in targets:
            url = f"https://{domain}{target}"
            try:
                async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
                    resp = await client.get(url, headers={"User-Agent": "KMC-DBAuditor/1.0"})
                    if resp.status_code == 200:
                        text = resp.text
                        if "DB_PASSWORD" in text or "PGPASSWORD" in text or "MYSQL_PWD" in text:
                            findings.append(DatabaseFinding(
                                check="Credentials Leak",
                                severity="CRITICAL",
                                detail=f"Sensitive configuration file {target} is public. May contain DB passwords.",
                                value=f"{domain}{target}"
                            ))
            except Exception:
                pass
    return await _fetch_env()


async def database_audit(domain: str) -> DatabaseAuditReport:
    """Run all database audits and return a sorted report."""
    all_checks = [
        _check_ports(domain),
        _check_banners(domain),
        _check_env_leaks(domain),
    ]
    results = await asyncio.gather(*all_checks, return_exceptions=True)

    findings: list[DatabaseFinding] = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    findings.sort(key=lambda f: {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
    }.get(f.severity, 99))

    return DatabaseAuditReport(domain=domain, findings=findings)
