"""KMC RESOLVX ENGINE — interactive menu-driven CLI.

Usage:
    python main.py
    Then select options from the terminal menu.
"""

from __future__ import annotations

import asyncio
import os
import sys

import dns.rdatatype as rtype
from rich import box
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

from core.dns_resolver import RESOLVERS, deep_records, propagation_check, detect_backend
from core.host_ping import check_host
from core.domain_whois import fetch_whois, check_ssl, ssl_status_color
from core.security_check import security_check
from core.email_auth import email_auth_check
from core.tech_detect import detect_tech
from utils.display import console, render_logo, status_style, kv_table

BLUE = "blue"
BRIGHT_CYAN = "bright_cyan"
MAGENTA = "bright_magenta"
AMBER = "yellow"
RED = "red"
GREEN = "green"
DIM = "dim"
WHITE = "white"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def sanitize_domain(raw: str) -> str:
    value = raw.strip().lower()
    for scheme in ("https://", "http://"):
        if value.startswith(scheme):
            value = value[len(scheme):]
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return value.strip()


def show_main_menu() -> int:
    clear_screen()
    render_logo()
    table = Table(
        title="Actions",
        border_style=BLUE,
        title_style=f"bold {BLUE}",
        box=box.SIMPLE,
        header_style=f"bold {BLUE}",
    )
    table.add_column("#", style=f"bold {BLUE}", no_wrap=True, width=3)
    table.add_column("Action", style=WHITE)

    rows = [
        ("1", "DNS records lookup"),
        ("2", "DNS propagation across 3 resolvers"),
        ("3", "Host liveness & HTTP fingerprint"),
        ("4", "WHOIS + TLS certificate monitor"),
        ("5", "Full infrastructure & security audit"),
        ("6", "SPF / DKIM / DMARC email-auth check"),
        ("7", "Website technology fingerprint (CMS / WAF)"),
        ("0", "Exit"),
    ]
    for num, label in rows:
        table.add_row(num, label)
    console.print(table)

    while True:
        raw = input("  select (0-7): ").strip()
        if raw.isdigit() and 0 <= int(raw) <= 7:
            return int(raw)
        if raw == "":
            return -1
        console.print(f"  [{DIM}]enter a number between 0 and 7[/{DIM}]")


def _title(section: str, name: str) -> str:
    return f"{section}  [{MAGENTA}]{name}[/]"


def run_dns_records(name: str) -> None:
    console.print()
    table = kv_table(_title("DNS records", name))
    records = asyncio.run(deep_records(name))
    for record_type in (rtype.A, rtype.AAAA, rtype.CNAME, rtype.MX, rtype.NS, rtype.TXT):
        label = rtype.to_text(record_type)
        values = records.get(label, [])
        display = "\n".join(values) if values else f"[{DIM}](none)[/{DIM}]"
        table.add_row(label, display)
    console.print(table)


def run_dns_propagation(name: str) -> None:
    async def _propagate() -> list:
        return await propagation_check(name, rtype.A)

    console.print()
    rows = asyncio.run(_propagate())
    prop = kv_table(_title(f"DNS propagation ({len(RESOLVERS)} resolvers)", name))
    for row in rows:
        for result in row.results:
            state = result.error if result.error else ", ".join(result.values) or "(empty)"
            color = status_style("up" if not result.error else "down")
            prop.add_row(result.resolver, f"[{color}]{state}[/{color}]")
    console.print(prop)


def run_dns_backend(name: str) -> None:
    async def _backend() -> dict[str, object]:
        return await detect_backend(name)

    console.print()
    backend = asyncio.run(_backend())
    color = AMBER if backend["proxied"] else GREEN
    console.print(
        f"[{color}]backend: {backend['verdict']}[/{color}]"
        f"  [{DIM}]A={backend['a']}  NS={backend['ns']}[/{DIM}]"
    )


def run_host_check(name: str) -> None:
    async def _check() -> object:
        return await check_host(name)

    console.print()
    report = asyncio.run(_check())
    table = kv_table(_title("Host liveness", name))
    for probe in report.probes:
        state = "open" if probe.open else "closed"
        detail = state if probe.open else (probe.error or "unreachable")
        color = status_style(state)
        latency = f"  {probe.latency_ms}ms" if probe.open and probe.latency_ms is not None else ""
        table.add_row(f"TCP :{probe.port}", f"[{color}]{detail}[/{color}]{latency}")
    if report.http_status is not None:
        table.add_row("HTTP status", f"[{GREEN}]{report.http_status}[/{GREEN}]")
    else:
        table.add_row("HTTP status", f"[{RED}]unreachable[/{RED}]")
    if report.server:
        table.add_row("Server", report.server)
    if report.powered_by:
        table.add_row("Powered-By", report.powered_by)
    for key, value in report.other_headers.items():
        table.add_row(key, value)
    console.print(table)


def run_whois_ssl(name: str) -> None:
    console.print()
    whois = fetch_whois(name)
    table = kv_table(_title("WHOIS", name))
    if whois.error:
        table.add_row("Status", f"[{RED}]{whois.error}[/{RED}]")
    else:
        table.add_row("Registrar", whois.registrar or "(unknown)")
        table.add_row("Created", whois.created or "(unknown)")
        table.add_row("Expiry", whois.expiry or "(unknown)")
        if whois.nameservers:
            table.add_row("Nameservers", "\n".join(whois.nameservers))
    console.print(table)

    ssl_info = check_ssl(name)
    ssl_table = kv_table(_title("TLS certificate", f"{name}:443"))
    if ssl_info.error:
        ssl_table.add_row("Status", f"[{RED}]{ssl_info.error}[/{RED}]")
    else:
        ssl_table.add_row("Issuer", ssl_info.issuer)
        ssl_table.add_row("Subject CN", ssl_info.subject_cn)
        if ssl_info.days_remaining is not None:
            if ssl_info.valid:
                color = ssl_status_color(ssl_info.days_remaining)
                ssl_table.add_row("Valid", f"[{color}]{ssl_info.days_remaining} days remaining[/{color}]")
            else:
                ssl_table.add_row("Valid", f"[{RED}]expired {abs(ssl_info.days_remaining)} days ago[/{RED}]")
    console.print(ssl_table)


def run_security_scan(name: str) -> None:
    async def _scan() -> object:
        return await security_check(name)

    console.print()
    report = asyncio.run(_scan())
    table = Table(title=_title("Security scan", name), border_style=BLUE, title_style=f"bold {BRIGHT_CYAN}")
    table.add_column("Check", overflow="fold", style=WHITE)
    table.add_column("Severity", overflow="fold", width=10)
    table.add_column("Detail", overflow="fold")

    SEV_COLOR = {
        "CRITICAL": RED,
        "HIGH": RED,
        "MEDIUM": AMBER,
        "LOW": BLUE,
        "INFO": DIM,
    }
    for f in report.findings:
        color = SEV_COLOR.get(f.severity, WHITE)
        table.add_row(f.check, f"[{color}]{f.severity}[/{color}]", f.detail)
    console.print(table)

    c = report.counts
    parts = [
        f"[{RED}]{c.get('CRITICAL', 0)} CRIT[/{RED}]",
        f"[{RED}]{c.get('HIGH', 0)} HIGH[/{RED}]",
        f"[{AMBER}]{c.get('MEDIUM', 0)} MED[/{AMBER}]",
        f"[{BLUE}]{c.get('LOW', 0)} LOW[/{BLUE}]",
        f"[{DIM}]{c.get('INFO', 0)} INFO[/{DIM}]",
    ]
    console.print(f"  summary: {'   '.join(parts)}")


def run_email_auth(name: str) -> None:
    async def _check() -> object:
        return await email_auth_check(name)

    console.print()
    report = asyncio.run(_check())

    table = kv_table(_title("Email auth (SPF / DKIM / DMARC)", name))
    for protocol, rec in (("SPF", report.spf), ("DKIM", report.dkim), ("DMARC", report.dmarc)):
        if rec.error == "not_found":
            display = f"[{RED}]not found[/{RED}]"
        elif rec.error:
            display = f"[{RED}]{rec.error}[/{RED}]"
        else:
            snippet = rec.value[:72] + ("..." if len(rec.value) > 72 else "")
            display = f"[{GREEN}]{snippet}[/{GREEN}]"
        table.add_row(protocol, display)
    console.print(table)

    score_color = GREEN if report.score == 3 else (AMBER if report.score >= 1 else RED)
    console.print(f"  posture: [{score_color}]{report.score}/3 protocols configured[/{score_color}]")

    if report.warnings:
        warn = kv_table("Warnings")
        for w in report.warnings:
            warn.add_row("", f"[{AMBER}]{w}[/{AMBER}]")
        console.print(warn)


def run_tech_detect(name: str) -> None:
    async def _detect() -> object:
        return await detect_tech(name)

    console.print()
    report = asyncio.run(_detect())

    if report.error:
        table = kv_table(_title("Tech fingerprint", name))
        table.add_row("Status", f"[{RED}]{report.error}[/{RED}]")
        console.print(table)
        return

    status_html = (
        f"[{GREEN}]HTTP {report.http_status}[/{GREEN}]" if report.http_status
        else f"[{RED}]no response[/{RED}]"
    )
    header = _title("Tech fingerprint", name) + f"  {status_html}"
    if report.url_used:
        header += f"  [{DIM}]{report.url_used}[/{DIM}]"

    table = kv_table(header)
    for group_name, items in (
        ("WAF / CDN", report.waf_list),
        ("CMS / Framework", report.cms_list),
        ("Web server", report.server_list),
    ):
        if items:
            for item in items:
                table.add_row(group_name, f"[{BRIGHT_CYAN}]{item}[/{BRIGHT_CYAN}]")
        else:
            table.add_row(group_name, f"[{DIM}]none detected[/{DIM}]")
    console.print(table)


def run_full_audit(name: str) -> None:
    run_dns_records(name)
    run_dns_propagation(name)
    run_dns_backend(name)
    run_host_check(name)
    run_whois_ssl(name)
    run_security_scan(name)
    run_email_auth(name)
    run_tech_detect(name)


def _prompt_target() -> str:
    raw = input("  enter domain or IP (e.g., example.com): ").strip()
    return raw


def _return_to_menu() -> None:
    input("  press Enter to return to menu...")


def main() -> None:
    while True:
        choice = show_main_menu()

        if choice == 0:
            console.print()
            console.print(Panel("engine shut down — goodbye.", border_style=BLUE, title="KMC RESOLVX"))
            sys.exit(0)

        if choice == -1:
            continue

        raw = _prompt_target()
        if not raw:
            console.print(f"[{DIM}]no target — back to menu[/{DIM}]")
            _return_to_menu()
            continue

        name = sanitize_domain(raw)
        if not name:
            console.print(f"[{DIM}]invalid target — back to menu[/{DIM}]")
            _return_to_menu()
            continue

        dispatch = {
            1: run_dns_records,
            2: run_dns_propagation,
            3: run_host_check,
            4: run_whois_ssl,
            5: run_full_audit,
            6: run_email_auth,
            7: run_tech_detect,
        }

        console.print()
        with Status(f"[{BLUE}]processing target infrastructure...[/{BLUE}]", console=console, spinner="dots"):
            dispatch[choice](name)

        _return_to_menu()


if __name__ == "__main__":
    main()
