"""Interactive Rich Cyber-Menu (launched when running GenVirus without arguments)."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from genvirus.analyzers.deobfuscator import deobfuscate_file
from genvirus.analyzers.reporter import export_html, export_json, export_markdown
from genvirus.analyzers.static_triage import analyze_file
from genvirus.generators.eicar import generate_eicar_specimen
from genvirus.generators.obfuscator import generate_obfuscated_specimen
from genvirus.generators.telemetry import run_telemetry_simulation
from genvirus.generators.triggers import generate_trigger_specimen
from genvirus.lab.challenges import CHALLENGES, prepare_lab_specimens, verify_answer
from genvirus.ui.banner import print_banner
from genvirus.ui.renderers import (
    render_deobfuscation,
    render_specimen,
    render_static_report,
    render_telemetry_events,
)


def _menu_generate_specimen(console: Console) -> None:
    console.print("\n[bold cyan]Specimen Generator[/bold cyan]")
    console.print("  [1] EICAR Antivirus Test File (raw / zip / base64 / hex / polyglot)")
    console.print("  [2] Multi-Layer Obfuscated Benign Script (light / legacy-v1 / deep)")
    console.print("  [3] YARA & Sigma Trigger Specimens (pe-mock / high-entropy / ioc-strings / all)")
    sub = Prompt.ask("Select generator", choices=["1", "2", "3"], default="1")

    if sub == "1":
        variant = Prompt.ask("Variant", choices=["raw", "zip", "base64", "hex", "polyglot"], default="raw")
        spec = generate_eicar_specimen(variant=variant, output_dir="artifacts_out")
        render_specimen(console, spec)
    elif sub == "2":
        preset = Prompt.ask("Preset", choices=["light", "legacy-v1", "deep"], default="legacy-v1")
        msg = Prompt.ask("Benign echo message", default="Hello from GenVirus v2.0 Benchmark!")
        spec = generate_obfuscated_specimen(
            payload_message=msg,
            preset=preset,
            output_path=f"artifacts_out/obfuscated_{preset}.sh",
        )
        render_specimen(console, spec)
    else:
        prof = Prompt.ask("Profile", choices=["all", "pe-mock", "high-entropy", "ioc-strings"], default="all")
        specs = generate_trigger_specimen(profile=prof, output_dir="artifacts_out")
        for s in specs:
            render_specimen(console, s)


def _menu_telemetry(console: Console) -> None:
    dry_run = Confirm.ask("Run in dry-run mode (no local sandbox files/processes)?", default=True)
    events, log_path = run_telemetry_simulation(technique="all", dry_run=dry_run, output_dir="artifacts_out")
    render_telemetry_events(console, events, str(log_path))


def _menu_deobfuscate(console: Console) -> None:
    default_target = "legacy/GenVirus_v1_2021.sh" if Path("legacy/GenVirus_v1_2021.sh").exists() else ""
    target = Prompt.ask("Path to script/specimen to deobfuscate", default=default_target)
    if not Path(target).is_file():
        console.print(f"[red]File not found: {target}[/red]")
        return
    res = deobfuscate_file(target)
    render_deobfuscation(console, res, show_payload=True)


def _menu_analyze(console: Console) -> None:
    default_target = "legacy/GenVirus_v1_2021.sh" if Path("legacy/GenVirus_v1_2021.sh").exists() else ""
    target = Prompt.ask("Path to file for static triage & YARA export", default=default_target)
    if not Path(target).is_file():
        console.print(f"[red]File not found: {target}[/red]")
        return
    report = analyze_file(target)
    render_static_report(console, report)

    if Confirm.ask("Export JSON, Markdown, and HTML reports to artifacts_out/reports/?", default=False):
        stem = Path(target).stem
        out_dir = Path("artifacts_out/reports")
        j = export_json(report, out_dir / f"{stem}_report.json")
        m = export_markdown(report, out_dir / f"{stem}_report.md")
        h = export_html(report, out_dir / f"{stem}_report.html")
        console.print(f"[green]Reports saved:[/green]\n  - {j}\n  - {m}\n  - {h}")


def _menu_ctf_lab(console: Console) -> None:
    prepare_lab_specimens()
    table = Table(title="Crack The Specimen — Interactive Reverse-Engineering Lab", border_style="bright_magenta")
    table.add_column("ID", style="bold cyan")
    table.add_column("Title", style="white")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Target Specimen", style="dim")
    for ch in CHALLENGES:
        table.add_row(ch.id, ch.title, ch.difficulty, ch.specimen_hint_path)
    console.print(table)

    cid = Prompt.ask("Select Challenge ID", choices=[c.id for c in CHALLENGES], default="c1")
    ok_ch = next(c for c in CHALLENGES if c.id == cid)
    console.print(Panel(f"[bold]{ok_ch.title}[/bold]\n\n{ok_ch.description}\n\n[cyan]Hint:[/cyan] {ok_ch.hint}"))
    ans = Prompt.ask(ok_ch.prompt_question)
    passed, _ = verify_answer(cid, ans)
    if passed:
        console.print(f"[bold green]CORRECT! Challenge {cid.upper()} solved![/bold green]")
    else:
        console.print("[bold red]Not quite! Try inspecting the specimen with option [03] or [04].[/bold red]")


def run_interactive_menu(console: Console | None = None) -> None:
    """Launch the interactive Rich Cyber-Menu loop."""
    con = console or Console()
    con.clear()
    print_banner(con)

    while True:
        menu_table = Table(show_header=False, box=None, padding=(0, 2))
        menu_table.add_row("[bold yellow][01][/bold yellow]", "Benign Specimen Generator [dim](EICAR / Multi-Layer Obfuscator / YARA Triggers)[/dim]")
        menu_table.add_row("[bold yellow][02][/bold yellow]", "Behavioral Telemetry Simulator [dim](Sandboxed Atomic Tests)[/dim]")
        menu_table.add_row("[bold yellow][03][/bold yellow]", "Automated Multi-Layer Deobfuscator [dim](Unpack Scripts & Legacy v1.0)[/dim]")
        menu_table.add_row("[bold yellow][04][/bold yellow]", "Static Triage Analyzer & Auto-YARA Exporter [dim](JSON / MD / HTML)[/dim]")
        menu_table.add_row("[bold yellow][05][/bold yellow]", "Interactive Reverse-Engineering CTF Lab [dim]('Crack The Specimen')[/dim]")
        menu_table.add_row("[bold red][00][/bold red]", "Exit")
        con.print(Panel(menu_table, title="[bold green]Main Index Menu[/bold green]", border_style="cyan"))

        choice = Prompt.ask("Select an option", choices=["0", "00", "1", "01", "2", "02", "3", "03", "4", "04", "5", "05"], default="00")
        norm = choice.lstrip("0") or "0"
        if norm == "0":
            con.print("[cyan]Stay ethical, stay curious. Exiting GenVirus Reborn.[/cyan]")
            break
        elif norm == "1":
            _menu_generate_specimen(con)
        elif norm == "2":
            _menu_telemetry(con)
        elif norm == "3":
            _menu_deobfuscate(con)
        elif norm == "4":
            _menu_analyze(con)
        elif norm == "5":
            _menu_ctf_lab(con)
