"""Rich terminal renderers for reports, traces, specimens, and telemetry."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from genvirus.core.entropy import entropy_sparkline
from genvirus.core.models import (
    DeobfuscationResult,
    GeneratedSpecimen,
    StaticAnalysisReport,
    TelemetryEvent,
)


def render_specimen(console: Console, specimen: GeneratedSpecimen) -> None:
    """Display generated specimen summary in a Rich table."""
    table = Table(title=f"Generated Benign Specimen ({specimen.artifact_type})", border_style="green")
    table.add_column("Property", style="bold cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Output Path", specimen.output_path)
    table.add_row("Variant", specimen.variant)
    table.add_row("Size", f"{specimen.size_bytes} bytes")
    table.add_row("SHA256", specimen.hashes.sha256)
    table.add_row("Description", specimen.description)
    if specimen.layers:
        table.add_row("Layers", " -> ".join(specimen.layers))
    if specimen.expected_detections:
        table.add_row("Expected Detections", ", ".join(specimen.expected_detections))
    console.print(table)


def render_deobfuscation(console: Console, result: DeobfuscationResult, show_payload: bool = True) -> None:
    """Display layer-by-layer deobfuscation trace."""
    if not result.is_obfuscated:
        console.print(Panel(f"[yellow]No obfuscation layers detected in {result.source_path}[/yellow]"))
        return

    table = Table(
        title=f"Deobfuscation Trace ({result.total_layers} Layers Peeled)",
        border_style="cyan",
    )
    table.add_column("#", justify="right", style="bold yellow")
    table.add_column("Technique", style="bold green")
    table.add_column("Size Transition", style="white")
    table.add_column("Entropy Delta", style="magenta")
    table.add_column("Preview", style="dim")

    for step in result.steps:
        table.add_row(
            str(step.step),
            step.technique,
            step.details,
            f"{step.entropy_before:.2f} -> {step.entropy_after:.2f}",
            step.preview[:50],
        )
    console.print(table)

    if show_payload:
        console.print(
            Panel(
                Syntax(result.final_payload[:3000], "bash", theme="monokai", word_wrap=True),
                title="Final Unpacked Payload (Truncated at 3000 chars if longer)",
                border_style="bright_blue",
            )
        )


def render_static_report(console: Console, report: StaticAnalysisReport) -> None:
    """Display full static triage report."""
    spark = entropy_sparkline(report.chunk_entropies)
    risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(report.risk_level, "green")

    overview = Table(title=f"Static Triage: {report.file_name}", border_style=risk_color)
    overview.add_column("Field", style="bold cyan", no_wrap=True)
    overview.add_column("Value", style="white")
    overview.add_row("File Type", report.file_type)
    overview.add_row("Size", f"{report.file_size} bytes ({report.printable_strings_count} printable strings)")
    overview.add_row("Risk Score", f"[{risk_color}]{report.risk_level} ({report.risk_score}/100)[/{risk_color}]")
    overview.add_row("Shannon Entropy", f"{report.overall_entropy:.4f} / 8.0   {spark}")
    overview.add_row("MD5", report.hashes.md5)
    overview.add_row("SHA256", report.hashes.sha256)
    console.print(overview)

    if report.deobfuscation and report.deobfuscation.is_obfuscated:
        render_deobfuscation(console, report.deobfuscation, show_payload=False)

    if report.matches:
        sig_table = Table(title="Matched Heuristic Signatures", border_style="yellow")
        sig_table.add_column("Severity", style="bold")
        sig_table.add_column("Rule ID", style="cyan")
        sig_table.add_column("Description", style="white")
        for m in report.matches:
            sig_table.add_row(m.severity, m.rule_id, m.description)
        console.print(sig_table)

    if report.iocs.deceptive_urls or report.iocs.urls or report.iocs.ipv4_addresses or report.iocs.suspicious_commands:
        ioc_table = Table(title="Extracted IoCs & Behavioral Indicators", border_style="red")
        ioc_table.add_column("Category", style="bold magenta")
        ioc_table.add_column("Indicators", style="white")
        if report.iocs.deceptive_urls:
            for d in report.iocs.deceptive_urls:
                ioc_table.add_row(
                    "Deceptive @ URL",
                    f"[yellow]Bait:[/yellow] {d.bait_userinfo}  |  [red]True Host:[/red] {d.true_host}",
                )
        if report.iocs.urls:
            ioc_table.add_row("URLs", "\n".join(report.iocs.urls[:10]))
        if report.iocs.ipv4_addresses:
            ioc_table.add_row("IPv4", ", ".join(report.iocs.ipv4_addresses))
        if report.iocs.suspicious_commands:
            ioc_table.add_row("Shell Heuristics", ", ".join(report.iocs.suspicious_commands))
        console.print(ioc_table)

    console.print(
        Panel(
            Syntax(report.yara_rule, "c", theme="monokai"),
            title="Auto-Generated YARA Rule",
            border_style="green",
        )
    )


def render_telemetry_events(console: Console, events: list[TelemetryEvent], log_path: str) -> None:
    """Display simulated Atomic-style telemetry events."""
    table = Table(title="Behavioral Telemetry Simulation Summary", border_style="magenta")
    table.add_column("Technique", style="bold cyan", no_wrap=True)
    table.add_column("Mode", style="yellow")
    table.add_column("Action", style="white")
    table.add_column("Cleaned Up", style="green")
    for ev in events:
        table.add_row(
            f"{ev.technique_id}\n[dim]{ev.technique_name}[/dim]",
            "DRY-RUN" if ev.dry_run else "EXECUTED",
            ev.action,
            "Yes" if ev.cleaned_up else "Kept in sandbox",
        )
    console.print(table)
    console.print(f"[dim]Telemetry JSONL log written to:[/dim] [cyan]{log_path}[/cyan]")
