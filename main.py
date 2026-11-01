"""KMC RESOLVX ENGINE - interactive menu-driven CLI.

Usage:
    python main.py
    Then select options from the terminal menu.
"""

from __future__ import annotations

import asyncio
import os
import sys

import dns.rdatatype as rtype
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

from core.dns_resolver import RESOLVERS, deep_records, propagation_check, detect_backend
from core.host_ping import check_host
from core.domain_whois import fetch_whois, check_ssl, ssl_status_color
from core.security_check import security_check
from utils.display import console, render_logo, status_style, kv_table


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def sanitize_domain(raw: str) -> str:
    """Strip URL scheme, trailing slashes, query strings, and surrounding whitespace."""
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
        title="Choose an action",
        border_style="cyan",
        title_style="bold cyan",
    )
    table.add_column("#", style="bold cyan", no_wrap=True)
    table.add_column("Action", style="white")

    rows = [
        ("1", "Deep DNS Records Lookup"),
        ("2", "Any-Cast DNS Propagation Emulator"),
        ("3", "Advanced Host Pinger & Server Sleuth"),
        ("4", "Domain WHOIS & SSL Monitor"),
        ("5", "Run Full Security & Infrastructure Audit"),
        ("0", "Exit Engine"),
    ]
    for num, label in rows:
        table.add_row(num, label)
    console.print(table)

    while True:
        raw = input("Choose an option (0-5): ").strip()
        if raw.isdigit() and 0 <= int(raw) <= 5:
            return int(raw)
        if raw == "":
            return -1
        console.print("[yellow dim]Please enter a number between 0 and 5.[/]")


def run_dns_records(name: str) -> None:
    console.print()
    table = kv_table(f"Deep DNS records  [bright_magenta]{name}[/]")
    records = asyncio.run(deep_records(name))
    for record_type in (rtype.A, rtype.AAAA, rtype.CNAME, rtype.MX, rtype.NS, rtype.TXT):
        label = rtype.to_text(record_type)
        values = records.get(label, [])
        display = "\n".join(values) if values else "[dim](none)[/]"
        table.add_row(label, display)
    console.print(table)


def run_dns_propagation(name: str) -> None:
    async def _propagate() -> list:
        return await propagation_check(name, rtype.A)

    console.print()
    rows = asyncio.run(_propagate())
    prop = kv_table(f"A-record propagation  ({len(RESOLVERS)} resolvers)  [bright_magenta]{name}[/]")
    for row in rows:
        for result in row.results:
            state = result.error if result.error else ", ".join(result.values) or "(empty)"
            prop.add_row(
                result.resolver,
                f"[{status_style('up' if not result.error else 'down')}]{state}[/]",
            )
    console.print(prop)


def run_dns_backend(name: str) -> None:
    async def _backend() -> dict[str, object]:
        return await detect_backend(name)

    console.print()
    backend = asyncio.run(_backend())
    color = "yellow" if backend["proxied"] else "green"
    console.print(
        f"[{color}]Backend : {backend['verdict']}[/]  "
        f"[dim]A={backend['a']}  NS={backend['ns']}[/]"
    )


def run_host_check(name: str) -> None:
    async def _check() -> object:
        return await check_host(name)

    console.print()
    report = asyncio.run(_check())
    table = kv_table(f"Host liveness  [bright_magenta]{name}[/]")
    for probe in report.probes:
        state = "open" if probe.open else "closed"
        detail = state if probe.open else (probe.error or "unreachable")
        table.add_row(
            f"TCP :{probe.port}",
            f"[{status_style(state)}]{detail}[/]"
            + (f"  {probe.latency_ms}ms" if probe.open else ""),
        )
    if report.http_status is not None:
        table.add_row("HTTP status", f"[green]{report.http_status}[/]")
    else:
        table.add_row("HTTP status", "[red]unreachable[/]")
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
    table = kv_table(f"WHOIS  [bright_magenta]{name}[/]")
    if whois.error:
        table.add_row("Status", f"[red]{whois.error}[/]")
    else:
        table.add_row("Registrar", whois.registrar or "(unknown)")
        table.add_row("Created", whois.created or "(unknown)")
        table.add_row("Expiry", whois.expiry or "(unknown)")
        if whois.nameservers:
            table.add_row("Nameservers", "\n".join(whois.nameservers))
    console.print(table)

    ssl_info = check_ssl(name)
    ssl_table = kv_table(f"TLS  [bright_magenta]{name}:443[/]")
    if ssl_info.error:
        ssl_table.add_row("Status", f"[red]{ssl_info.error}[/]")
    else:
        ssl_table.add_row("Issuer", ssl_info.issuer)
        ssl_table.add_row("Subject CN", ssl_info.subject_cn)
        if ssl_info.days_remaining is not None:
            ssl_table.add_row(
                "Valid",
                (
                    f"[{ssl_status_color(ssl_info.days_remaining)}]"
                    f"{ssl_info.days_remaining} days remaining[/]"
                    if ssl_info.valid
                    else f"[red]expired {abs(ssl_info.days_remaining)} days ago[/]"
                ),
            )
    console.print(ssl_table)


def run_security_scan(name: str) -> None:
    async def _scan() -> object:
        return await security_check(name)

    console.print()
    report = asyncio.run(_scan())
    table = Table(title=f"Security scan  [bright_magenta]{name}[/]")
    table.add_column("Check", overflow="fold")
    table.add_column("Severity", overflow="fold")
    table.add_column("Detail", overflow="fold")
    for f in report.findings:
        color = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }.get(f.severity, "white")
        table.add_row(f.check, f"[{color}]{f.severity}[/{color}]", f.detail)
    console.print(table)
    c = report.counts
    parts = [
        f"[red bold]{c.get('CRITICAL', 0)} CRITICAL[/]",
        f"[red]{c.get('HIGH', 0)} HIGH[/]",
        f"[yellow]{c.get('MEDIUM', 0)} MEDIUM[/]",
        f"[blue]{c.get('LOW', 0)} LOW[/]",
        f"[dim]{c.get('INFO', 0)} INFO[/]",
    ]
    console.print(f"Summary: {'  '.join(parts)}")


def run_full_audit(name: str) -> None:
    """Run all core checks plus security scan for a single target."""
    run_dns_records(name)
    run_dns_propagation(name)
    run_dns_backend(name)
    run_host_check(name)
    run_whois_ssl(name)
    run_security_scan(name)


def _prompt_target() -> str:
    raw = input("Enter target domain or IP (e.g., example.com): ").strip()
    return raw


def _return_to_menu() -> None:
    input("Press [Enter] to return to main menu...")


def main() -> None:
    while True:
        choice = show_main_menu()

        if choice == 0:
            console.print()
            console.print(Panel("Engine shut down. Goodbye.", border_style="cyan", title="KMC RESOLVX"))
            sys.exit(0)

        if choice == -1:
            continue

        raw = _prompt_target()
        if not raw:
            console.print("[yellow dim]No target provided - returning to menu.[/]")
            _return_to_menu()
            continue

        name = sanitize_domain(raw)
        if not name:
            console.print("[yellow dim]Invalid target - returning to menu.[/]")
            _return_to_menu()
            continue

        dispatch = {
            1: run_dns_records,
            2: run_dns_propagation,
            3: run_host_check,
            4: run_whois_ssl,
            5: run_full_audit,
        }

        console.print()
        with Status("[cyan]Processing target infrastructure...[/cyan]", console=console, spinner="dots"):
            dispatch[choice](name)

        _return_to_menu()


if __name__ == "__main__":
    main()
