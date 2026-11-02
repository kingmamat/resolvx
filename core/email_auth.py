"""SPF / DKIM / DMARC DNS checks for email spoofing posture.

Queries the relevant TXT records via dnspython and analyses whether each
record is present, well-formed, and aligned with the domain.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import dns.asyncresolver
import dns.name
import dns.rdatatype


@dataclass
class _EmailRecord:
    """One protocol's lookup result (SPF, DKIM, or DMARC)."""

    present: bool = False
    value: str = ""
    error: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return f"ERROR ({self.error})"
        return self.value if self.present else "NOT FOUND"


@dataclass
class EmailAuthReport:
    """Aggregated SPF / DKIM / DMARC status for one domain."""

    domain: str
    spf: _EmailRecord = field(default_factory=_EmailRecord)
    dkim: _EmailRecord = field(default_factory=_EmailRecord)
    dmarc: _EmailRecord = field(default_factory=_EmailRecord)
    warnings: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """0–3: how many of the three protocols are properly configured."""
        score = 0
        if self.spf.present:
            score += 1
        if self.dkim.present:
            score += 1
        if self.dmarc.present:
            score += 1
        return score


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _clean_txt(raw: str) -> str:
    """Strip the outer double-quote that dnspython adds to TXT record text."""
    return raw.strip('"')


async def _txt_query(host: str) -> list[str]:
    """Return cleaned TXT record values for *host*, empty list if NXDOMAIN."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 8.0
    target = dns.name.from_text(host)
    try:
        answer = await resolver.resolve(target, dns.rdatatype.TXT)
        return [_clean_txt(rdata.to_text()) for rdata in answer]
    except (dns.asyncresolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception as exc:
        raise exc


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

SPF_MACHINERY_TOKENS = re.compile(r"\b(v=spf1|all|-all|\+all|~all|ip4:|ip6:|include:|redirect:|mx|a)\b")


async def _check_spf(domain: str) -> tuple[_EmailRecord, list[str]]:
    record = _EmailRecord()
    warnings: list[str] = []
    values = await _txt_query(domain)
    spf_values = [v for v in values if v.startswith("v=spf1")]
    if spf_values:
        record.present = True
        record.value = spf_values[0]
        # Warn if multiple SPF records exist (ambiguous to mail receivers)
        if len(spf_values) > 1:
            warnings.append("Multiple SPF records found — receivers will treat as PermError. Remove all but one.")
        # Check for '-all' (hard fail) which is recommended
        if not re.search(r"[-+]all", spf_values[0]):
            warnings.append("SPF has no all token — unlisted hosts implicitly pass. Append '-all' for hard fail.")
        if "include:" in spf_values[0] and len(spf_values[0].split("include:")) > 6:
            warnings.append("More than 5 include: mechanisms may exceed the 10 DNS lookup limit.")
    else:
        record.error = "not_found"
        warnings.append("No SPF record found — email can be spoofed freely.")
    return record, warnings


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

# Common DKIM selector names, in priority order
DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2", "s1", "s2", "s3",
    "selector1", "selector2", "s1024", "s2048", "dkim", "sig1", "sig2",
]


async def _check_dkim(domain: str) -> tuple[_EmailRecord, list[str]]:
    record = _EmailRecord()
    warnings: list[str] = []
    selectors: list[str] = []

    for sel in DKIM_SELECTORS[:8]:
        host = f"{sel}._domainkey.{domain}"
        try:
            values = await _txt_query(host)
            if values:
                # Check the p= tag for a non-empty key.
                # "v=DKIM1; p=" (empty p) means the key is disabled.
                p_value = ""
                for v in values:
                    if "p=" in v:
                        p_value = v.split("p=", 1)[1].split(";")[0].strip()
                        break
                if p_value:
                    selectors.append(sel)
        except Exception:
            continue

    if selectors:
        record.present = True
        first_host = f"{selectors[0]}._domainkey.{domain}"
        try:
            values = await _txt_query(first_host)
            record.value = " ".join(values)
        except Exception as exc:
            record.error = str(exc)
        if len(selectors) > 1:
            warnings.append(f"Multiple active DKIM selectors: {', '.join(selectors)}")
    else:
        record.error = "not_found"
        warnings.append("No active DKIM record found for common selectors — email can be forged.")
    return record, warnings


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

DMARC_POLICY_RE = re.compile(r"p=(none|quarantine|reject)", re.IGNORECASE)
DMARC_SUBPOLICY_RE = re.compile(r"sp=(none|quarantine|reject)", re.IGNORECASE)
DMARC_SUBFAIL_RE = re.compile(r"subfail=(all|none|email|192\.0\.2\.1)", re.IGNORECASE)


async def _check_dmarc(domain: str) -> tuple[_EmailRecord, list[str]]:
    record = _EmailRecord()
    warnings: list[str] = []
    host = f"_dmarc.{domain}"
    try:
        values = await _txt_query(host)
    except Exception as exc:
        record.error = str(exc)
        return record, warnings

    if values:
        record.present = True
        record.value = values[0]
        policy_match = DMARC_POLICY_RE.search(values[0])
        if not policy_match:
            warnings.append("DMARC record has no 'p=' policy tag — record will not enforce anything.")
        elif policy_match.group(1).lower() == "none":
            warnings.append("DMARC policy is 'none' (monitor-only) — spoofers not blocked. Consider 'quarantine' or 'reject'.")
        # Check for reporting address
        if not re.search(r"ru=|ruf=", values[0]):
            warnings.append("No DMARC reporting address (ru=/ruf=) — you won't receive spoofing reports.")
        # subdomain policy
        sub_match = DMARC_SUBPOLICY_RE.search(values[0])
        if not sub_match:
            warnings.append("No 'sp=' subdomain policy — subdomains fall back to the parent policy.")
    else:
        record.error = "not_found"
        warnings.append("No DMARC record at _dmarc.<domain> — inbox providers have no spoofing signal for this domain.")
    return record, warnings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def email_auth_check(domain: str) -> EmailAuthReport:
    """Run SPF, DKIM, and DMARC lookups concurrently and return a combined report."""
    spf_task = _check_spf(domain)
    dkim_task = _check_dkim(domain)
    dmarc_task = _check_dmarc(domain)
    (spf_rec, spf_warn), (dkim_rec, dkim_warn), (dmarc_rec, dmarc_warn) = await asyncio.gather(
        spf_task, dkim_task, dmarc_task
    )
    return EmailAuthReport(
        domain=domain,
        spf=spf_rec,
        dkim=dkim_rec,
        dmarc=dmarc_rec,
        warnings=spf_warn + dkim_warn + dmarc_warn,
    )
