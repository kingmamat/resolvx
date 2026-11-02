"""KMC RESOLVX — terminal visual engine.

A restrained two-tone palette: deep blue for structure, bright cyan for
emphasis, warm amber for warnings, and red only for failures.
"""

from __future__ import annotations

from typing import Any

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

ENGINE_VERSION = "1.1.0"
AUTHOR = "Bagas Budi Prakasa"

# Palette
BLUE = "blue"
CYAN = "cyan"
BRIGHT_CYAN = "bright_cyan"
DIM = "dim"
GREEN = "green"
AMBER = "yellow"
RED = "red"
WHITE = "white"
MAGENTA = "bright_magenta"


def _ascii_resolvx() -> str:
    return (
        "   ___     ___  ___  ___   ___  ___   ___\n"
        "  / _ \\   / _ \\/ _ \\|_ _| |__|/ _ \\|_ _/\n"
        " | (_) | | (_) | | | || | |_ | (_) || |\n"
        "  \\__, |  \\__,/|_|_|___| |__|\\__,/|_|\n"
    )


def render_logo(status: str = "Operational") -> None:
    art = _ascii_resolvx()
    meta = Text()
    meta.append("  KMC RESOLVX  ", style=f"bold {BRIGHT_CYAN}")
    meta.append(f"  v{ENGINE_VERSION}\n", style=DIM)
    meta.append("  " + "-" * 30 + "\n", style=BLUE)
    meta.append(f"  author   {AUTHOR}\n", style=DIM)
    meta.append(f"  status   ", style=DIM)
    meta.append(status, style=GREEN if status == "Operational" else AMBER)
    meta.append("\n")

    body = Group(Text(art, style=BLUE), meta)
    panel = Panel(body, border_style=BLUE, box=ROUNDED, padding=(1, 2))
    console.print(panel)


def status_style(state: str) -> str:
    s = state.lower()
    if s in ("up", "active", "ok", "open", "reachable", "valid", "secure"):
        return GREEN
    if s in ("down", "closed", "failed", "error", "expired"):
        return RED
    return AMBER


def make_table(title: str) -> Table:
    table = Table(
        title=title,
        border_style=BLUE,
        title_style=f"bold {BRIGHT_CYAN}",
        show_lines=False,
        pad_edge=False,
        expand=False,
    )
    return table


def kv_table(title: str) -> Table:
    table = make_table(title)
    table.add_column("Field", style=BLUE, no_wrap=True, width=18)
    table.add_column("Value", style=WHITE)
    return table


def progress_display() -> Live:
    return Live(console=console, screen=False, auto_refresh=False)


if __name__ == "__main__":
    render_logo()
