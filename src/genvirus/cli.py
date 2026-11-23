"""Dual-mode Typer CLI for GenVirus v2.0 Reborn."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from genvirus import __codename__, __version__
from genvirus.analyzers.deobfuscator import deobfuscate_file
from genvirus.analyzers.reporter import export_html, export_json, export_markdown
from genvirus.analyzers.static_triage import analyze_file
from genvirus.generators.eicar import generate_eicar_specimen
from genvirus.generators.obfuscator import generate_obfuscated_specimen
from genvirus.generators.telemetry import run_telemetry_simulation
from genvirus.generators.triggers import generate_trigger_specimen
from genvirus.lab.challenges import CHALLENGES, prepare_lab_specimens, verify_answer
from genvirus.ui.banner import print_banner
from genvirus.ui.menu import run_interactive_menu
from genvirus.ui.renderers import (
    render_deobfuscation,
    render_specimen,
    render_static_report,
    render_telemetry_events,
)

app = typer.Typer(
    name="genvirus",
    help="GenVirus v2.0 Reborn — Benign Malware/Telemetry Simulator, Deobfuscator & Reverse-Engineering Lab.",
    add_completion=False,
    no_args_is_help=False,
)
generate_app = typer.Typer(help="Pillar 1: Generate 100% benign test specimens (EICAR, obfuscated, YARA triggers).")
lab_app = typer.Typer(help="Pillar 2: Interactive Reverse-Engineering CTF Lab ('Crack The Specimen').")
app.add_typer(generate_app, name="generate")
app.add_typer(lab_app, name="lab")

console = Console()


@app.callback(invoke_without_command=True)
def default_entrypoint(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit."),
) -> None:
    """Launch the Interactive Rich Cyber-Menu when invoked without a subcommand."""
    if version:
        console.print(f"GenVirus v{__version__} ({__codename__})")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        run_interactive_menu(console)


@app.command("menu")
def cmd_menu() -> None:
    """Launch the interactive Rich Cyber-Menu."""
    run_interactive_menu(console)


@generate_app.command("eicar")
def cmd_generate_eicar(
    variant: str = typer.Option("raw", "--variant", "-v", help="raw, zip, base64, hex, or polyglot"),
    output: Path = typer.Option(Path("artifacts_out"), "--output", "-o", help="Output directory"),
    depth: int = typer.Option(3, "--depth", "-d", help="ZIP nesting depth when variant=zip"),
) -> None:
    """Generate a standard or wrapped benign EICAR antivirus test file."""
    print_banner(console)
    spec = generate_eicar_specimen(variant=variant, output_dir=output, nesting_depth=depth)
    render_specimen(console, spec)


@generate_app.command("obfuscate")
def cmd_generate_obfuscate(
    payload: str = typer.Option("Hello from GenVirus v2.0 Benign Benchmark!", "--payload", "-p"),
    preset: Optional[str] = typer.Option("legacy-v1", "--preset", help="light, legacy-v1, or deep"),
    layers: Optional[str] = typer.Option(None, "--layers", "-l", help="Comma-separated layers (overrides preset)"),
    output: Path = typer.Option(Path("artifacts_out/obfuscated_specimen.sh"), "--output", "-o"),
) -> None:
    """Generate a multi-layer obfuscated benign Bash script for deobfuscator benchmarking."""
    print_banner(console)
    layer_list = [x.strip() for x in layers.split(",")] if layers else None
    spec = generate_obfuscated_specimen(
        payload_message=payload,
        layers=layer_list,
        preset=preset,
        output_path=output,
    )
    render_specimen(console, spec)


@generate_app.command("trigger")
def cmd_generate_trigger(
    profile: str = typer.Option("all", "--profile", "-p", help="pe-mock, high-entropy, ioc-strings, or all"),
    output: Path = typer.Option(Path("artifacts_out"), "--output", "-o", help="Output directory"),
) -> None:
    """Generate inert YARA/Sigma trigger specimens with RFC-5737 test IoCs."""
    print_banner(console)
    specs = generate_trigger_specimen(profile=profile, output_dir=output)
    for spec in specs:
        render_specimen(console, spec)


@app.command("simulate")
def cmd_simulate(
    technique: str = typer.Option("all", "--technique", "-t", help="MITRE technique ID or 'all'"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate without spawning processes or writing sandbox files"),
    keep_artifacts: bool = typer.Option(False, "--keep-artifacts", help="Keep sandbox directory after run"),
    output: Path = typer.Option(Path("artifacts_out"), "--output", "-o", help="Output directory"),
) -> None:
    """Run sandboxed Atomic-style behavioral telemetry simulations with auto-cleanup."""
    print_banner(console)
    events, log_path = run_telemetry_simulation(
        technique=technique,
        dry_run=dry_run,
        keep_artifacts=keep_artifacts,
        output_dir=output,
    )
    render_telemetry_events(console, events, str(log_path))


@app.command("deobfuscate")
def cmd_deobfuscate(
    target: Path = typer.Argument(..., exists=True, readable=True, help="Path to obfuscated script/file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write unpacked payload to file"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write deobfuscation trace as JSON"),
) -> None:
    """Automatically detect and peel nested obfuscation layers statically."""
    print_banner(console)
    result = deobfuscate_file(target)
    render_deobfuscation(console, result, show_payload=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.final_payload, encoding="utf-8")
        console.print(f"[green]Unpacked payload saved to:[/green] {output}")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Trace JSON saved to:[/green] {json_out}")


@app.command("analyze")
def cmd_analyze(
    target: Path = typer.Argument(..., exists=True, readable=True, help="Path to specimen to analyze"),
    yara_out: Optional[Path] = typer.Option(None, "--yara-out", help="Export auto-generated .yar rule"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export JSON report"),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown", help="Export Markdown report"),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Export standalone HTML report"),
) -> None:
    """Run full static triage, entropy profiling, IoC extraction, and YARA rule generation."""
    print_banner(console)
    report = analyze_file(target)
    render_static_report(console, report)

    if yara_out:
        yara_out.parent.mkdir(parents=True, exist_ok=True)
        yara_out.write_text(report.yara_rule, encoding="utf-8")
        console.print(f"[green]YARA rule saved to:[/green] {yara_out}")
    if json_out:
        console.print(f"[green]JSON report saved to:[/green] {export_json(report, json_out)}")
    if markdown_out:
        console.print(f"[green]Markdown report saved to:[/green] {export_markdown(report, markdown_out)}")
    if html_out:
        console.print(f"[green]HTML report saved to:[/green] {export_html(report, html_out)}")


@lab_app.command("list")
def cmd_lab_list() -> None:
    """List all Crack The Specimen CTF challenges and prepare local lab files."""
    print_banner(console)
    prepare_lab_specimens()
    table = Table(title="Crack The Specimen — Lab Challenges", border_style="magenta")
    table.add_column("ID", style="bold cyan")
    table.add_column("Title", style="white")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Specimen Path", style="dim")
    for ch in CHALLENGES:
        table.add_row(ch.id, ch.title, ch.difficulty, ch.specimen_hint_path)
    console.print(table)


@lab_app.command("verify")
def cmd_lab_verify(
    challenge_id: str = typer.Argument(..., help="Challenge ID (c1, c2, c3, c4)"),
    answer: str = typer.Option(..., "--answer", "-a", help="Your discovered flag or answer"),
) -> None:
    """Verify an answer for a Crack The Specimen CTF challenge."""
    passed, ch = verify_answer(challenge_id, answer)
    if passed:
        console.print(f"[bold green]PASS:[/bold green] {ch.id.upper()} ({ch.title}) solved!")
    else:
        console.print(f"[bold red]FAIL:[/bold red] Incorrect answer for {ch.id.upper()}. Hint: {ch.hint}")
        raise typer.Exit(code=1)


def main() -> None:
    """Console script entrypoint."""
    app()


if __name__ == "__main__":
    main()
