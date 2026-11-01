"""KMC DNS & Host Checker -- visual engine.

Dark-mode minimalist terminal UI built on rich.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

ENGINE_VERSION = "1.0.0"
AUTHOR = "Bagas Budi Prakasa"


def _ascii_kmc() -> str:
    """Return the raw KMC ASCII art."""
    return (
        "  _  __ __  __  ____\n"
        " | |/ /|  \\/  |/ ___|\n"
        " | ' / | |\\/| | |\n"
        " | . \\ | |  | | |___\n"
        " |_|\\_\\|_|  |_|\\____|"
    )


def render_logo(status: str = "Operational") -> None:
    """Display the KMC brand panel using a dim cyan/magenta theme."""
    art = _ascii_kmc()
    meta = Text()
    meta.append(" [ KMC NETWORK UTILITY ]\n", style="bold cyan")
    meta.append("-" * 25 + "\n", style="cyan")
    meta.append(f"  Engine Ver : {ENGINE_VERSION}\n", style="bright_magenta")
    meta.append(f"  Author     : {AUTHOR}\n", style="bright_magenta")
    meta.append(f"  Status     : {status}\n", style="green" if status == "Operational" else "yellow")

    body = Group(Text(art, style="cyan"), meta)
    panel = Panel(body, border_style="cyan")
    console.print(panel)


def status_style(state: str) -> str:
    """Map a status keyword to a rich color style."""
    s = state.lower()
    if s in ("up", "active", "ok", "open", "reachable", "valid", "secure"):
        return "green"
    if s in ("down", "closed", "failed", "error", "expired"):
        return "red"
    return "yellow"


def make_table(title: str) -> Table:
    """Create a clean bordered table for results."""
    table = Table(
        title=title,
        border_style="cyan",
        title_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=False,
    )
    return table


def kv_table(title: str) -> Table:
    """Create a two-column table for key/value rows (caller adds rows)."""
    table = make_table(title)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    return table


def progress_display() -> Live:
    """Return a Live object usable for streaming progress updates."""
    return Live(console=console, screen=False, auto_refresh=False)


if __name__ == "__main__":
    render_logo()
