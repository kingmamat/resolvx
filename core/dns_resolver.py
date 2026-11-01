"""Deep DNS record lookup and any-cast multi-resolver propagation check.

Uses dnspython for the wire protocol. Resolver set is a fixed list of
global public any-cast endpoints so a record is cross-checked across
independent networks.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.name
import dns.rdatatype

# Public any-cast resolvers, in a stable order.
RESOLVERS: list[dict[str, str]] = [
    {"name": "Cloudflare", "address": "1.1.1.1"},
    {"name": "Google", "address": "8.8.8.8"},
    {"name": "Quad9", "address": "9.9.9.9"},
]

CLOUDFLARE_A_NETS = ("104.16.", "172.67.", "188.114.", "190.93.", "131.0.72.")
NS_CLOUDFLARE_MARKERS = ("ns.cloudflare.com",)


@dataclass
class ResolverResult:
    """What one resolver returned for one record type."""

    resolver: str
    address: str
    rtype: str
    values: list[str] = field(default_factory=list)
    error: str = ""
    latency_ms: float | None = None


@dataclass
class PropagationRow:
    """One record-type row across all resolvers."""

    rtype: str
    results: list[ResolverResult] = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        sets = [frozenset(r.values) for r in self.results if not r.error]
        return len(sets) > 1 and all(s == sets[0] for s in sets)


def _build_resolver(address: str) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [address]
    resolver.timeout = 3.0
    resolver.lifetime = 6.0
    return resolver


async def _query_one(resolver: dns.asyncresolver.Resolver, name: dns.name.Name, rtype: dns.rdatatype) -> list[str]:
    answer = await resolver.resolve(name, rtype)
    return [rdata.to_text() for rdata in answer]


async def resolve_record(name: str, rtype: dns.rdatatype, resolver_address: str) -> ResolverResult:
    """Run one record query against one resolver and record latency."""
    target = dns.name.from_text(name)
    outcome = ResolverResult(
        resolver=next(r["name"] for r in RESOLVERS if r["address"] == resolver_address),
        address=resolver_address,
        rtype=dns.rdatatype.to_text(rtype),
    )
    resolver = _build_resolver(resolver_address)
    try:
        started = asyncio.get_running_loop().time()
        outcome.values = await _query_one(resolver, target, rtype)
        outcome.latency_ms = round((asyncio.get_running_loop().time() - started) * 1000, 1)
    except dns.asyncresolver.NoAnswer:
        outcome.error = "NoAnswer"
    except dns.resolver.NXDOMAIN:
        outcome.error = "NXDOMAIN"
    except dns.resolver.Timeout:
        outcome.error = "Timeout"
    except Exception as exc:  # noqa: BLE001 - one resolver failure must not abort others
        outcome.error = f"{exc.__class__.__name__}: {exc}"
    return outcome


async def deep_records(name: str, record_types: tuple[dns.rdatatype, ...] | None = None) -> dict[str, list[str]]:
    """Fetch a full record set using the default resolver and return
    {TYPE: [values]} for display."""
    if record_types is None:
        record_types = (
            dns.rdatatype.A,
            dns.rdatatype.AAAA,
            dns.rdatatype.CNAME,
            dns.rdatatype.MX,
            dns.rdatatype.NS,
            dns.rdatatype.TXT,
        )
    default = _build_resolver(RESOLVERS[0]["address"])
    target = dns.name.from_text(name)
    collected: dict[str, list[str]] = {}
    for rtype in record_types:
        try:
            collected[dns.rdatatype.to_text(rtype)] = await _query_one(default, target, rtype)
        except Exception:  # noqa: BLE001
            collected[dns.rdatatype.to_text(rtype)] = []
    return collected


async def propagation_check(name: str, rtype: dns.rdatatype = dns.rdatatype.A) -> list[PropagationRow]:
    """Cross-resolve one record across every public resolver in parallel."""
    tasks = [
        resolve_record(name, rtype, res["address"]) for res in RESOLVERS
    ]
    results = await asyncio.gather(*tasks)
    row = PropagationRow(rtype=dns.rdatatype.to_text(rtype), results=list(results))
    return [row]


def is_cloudflare_proxied(a_values: list[str], ns_values: list[str]) -> bool:
    """Heuristic: an A record that maps into Cloudflare's any-cast ranges,
    or NS names that resolve to Cloudflare's nameservers, indicate a
    proxied / managed-domain behind Cloudflare (as opposed to raw VPS/cPanel).
    """
    for value in a_values:
        for prefix in CLOUDFLARE_A_NETS:
            if value.startswith(prefix):
                return True
    for value in ns_values:
        for marker in NS_CLOUDFLARE_MARKERS:
            if marker in value.lower():
                return True
    return False


async def detect_backend(name: str) -> dict[str, object]:
    """Report whether a domain sits behind Cloudflare or exposes its origin IP."""
    records = await deep_records(name, (dns.rdatatype.A, dns.rdatatype.NS))
    a_values = records.get("A", [])
    ns_values = records.get("NS", [])
    proxied = is_cloudflare_proxied(a_values, ns_values)
    return {
        "proxied": proxied,
        "verdict": "Cloudflare-proxied (origin IP hidden)" if proxied else "Origin / VPS IP exposed",
        "a": a_values,
        "ns": ns_values,
    }
