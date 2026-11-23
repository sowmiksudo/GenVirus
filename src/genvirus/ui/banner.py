"""Modernized Rich ASCII banner paying homage to GenVirus v1.0."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from genvirus import __author__, __codename__, __version__

_ASCII_LOGO = r"""
  ██████╗ ███████╗███╗   ██╗██╗   ██╗██╗██████╗ ██╗   ██╗███████╗
 ██╔════╝ ██╔════╝████╗  ██║██║   ██║██║██╔══██╗██║   ██║██╔════╝
 ██║  ███╗█████╗  ██╔██╗ ██║██║   ██║██║██████╔╝██║   ██║███████╗
 ██║   ██║██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║
 ╚██████╔╝███████╗██║ ╚████║ ╚████╔╝ ██║██║  ██║╚██████╔╝███████║
  ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""


def print_banner(console: Console) -> None:
    """Render the GenVirus v2.0 Reborn header banner."""
    banner_text = Text(_ASCII_LOGO.strip("\n"), style="bold red")
    subtitle = (
        f"[bold cyan]GenVirus v{__version__} ({__codename__})[/bold cyan] "
        f"[dim]|[/dim] [white]Defensive Simulation, Deobfuscation & RE Lab[/white]\n"
        f"[dim]Author: {__author__} | Strictly Ethical & Benign Educational Specimens[/dim]"
    )
    console.print(
        Panel(
            banner_text,
            subtitle=subtitle,
            border_style="bright_red",
            padding=(0, 2),
        )
    )
