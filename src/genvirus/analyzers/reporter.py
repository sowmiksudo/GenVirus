"""JSON, Markdown, and standalone HTML report exporters."""

from __future__ import annotations

import html
import json
from pathlib import Path

from genvirus.core.entropy import entropy_sparkline
from genvirus.core.models import StaticAnalysisReport


def export_json(report: StaticAnalysisReport, output_path: str | Path) -> Path:
    """Write StaticAnalysisReport as formatted JSON."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return out


def export_markdown(report: StaticAnalysisReport, output_path: str | Path) -> Path:
    """Write StaticAnalysisReport as a structured Markdown report."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    spark = entropy_sparkline(report.chunk_entropies)

    lines = [
        f"# GenVirus Reborn — Static Triage Report: `{report.file_name}`",
        "",
        f"- **Generated**: {report.timestamp}",
        f"- **File Type**: {report.file_type}",
        f"- **Size**: {report.file_size} bytes",
        f"- **Risk Assessment**: **{report.risk_level}** (`{report.risk_score}/100`)",
        f"- **Overall Shannon Entropy**: `{report.overall_entropy:.4f} / 8.0` (`{spark}`)",
        "",
        "## Cryptographic Hashes",
        "| Algorithm | Digest |",
        "|---|---|",
        f"| MD5 | `{report.hashes.md5}` |",
        f"| SHA1 | `{report.hashes.sha1}` |",
        f"| SHA256 | `{report.hashes.sha256}` |",
        "",
    ]

    if report.deobfuscation and report.deobfuscation.is_obfuscated:
        lines.extend([
            f"## Deobfuscation Trace ({report.deobfuscation.total_layers} Layers Peeled)",
            "| Layer | Technique | Size Transition | Entropy Delta |",
            "|---|---|---|---|",
        ])
        for s in report.deobfuscation.steps:
            lines.append(
                f"| {s.step} | `{s.technique}` | {s.details} | {s.entropy_before:.2f} -> {s.entropy_after:.2f} |"
            )
        lines.append("")

    lines.append("## Matched Heuristic Signatures")
    if report.matches:
        for m in report.matches:
            lines.append(f"- **[{m.severity}] `{m.rule_id}`**: {m.description}")
    else:
        lines.append("- No heuristic rules triggered.")
    lines.append("")

    lines.append("## Extracted Indicators of Compromise (IoCs)")
    if report.iocs.deceptive_urls:
        lines.append("### Deceptive `userinfo@host` Masked URLs")
        for d in report.iocs.deceptive_urls:
            lines.append(f"- Bait: `{d.bait_userinfo}` | True Host: `{d.true_host}` | Full: `{d.full_url}`")
    if report.iocs.urls:
        lines.append("### URLs")
        for u in report.iocs.urls:
            lines.append(f"- `{u}`")
    if report.iocs.ipv4_addresses:
        lines.append(f"- **IPv4**: {', '.join(f'`{ip}`' for ip in report.iocs.ipv4_addresses)}")
    if report.iocs.suspicious_commands:
        lines.append(f"- **Shell Indicators**: {', '.join(f'`{c}`' for c in report.iocs.suspicious_commands)}")

    lines.extend([
        "",
        "## Auto-Generated YARA Rule",
        "```yara",
        report.yara_rule.strip(),
        "```",
        "",
    ])

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def export_html(report: StaticAnalysisReport, output_path: str | Path) -> Path:
    """Write StaticAnalysisReport as a standalone dark-mode HTML report."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    esc = html.escape

    matches_html = "".join(
        f"<li><span class='badge {esc(m.severity.lower())}'>{esc(m.severity)}</span> "
        f"<strong>{esc(m.rule_id)}</strong>: {esc(m.description)}</li>"
        for m in report.matches
    ) or "<li>No heuristic rules triggered.</li>"

    steps_html = ""
    if report.deobfuscation and report.deobfuscation.is_obfuscated:
        rows = "".join(
            f"<tr><td>{s.step}</td><td><code>{esc(s.technique)}</code></td>"
            f"<td>{esc(s.details)}</td><td>{s.entropy_before:.2f} &rarr; {s.entropy_after:.2f}</td></tr>"
            for s in report.deobfuscation.steps
        )
        steps_html = (
            f"<h2>Deobfuscation Trace ({report.deobfuscation.total_layers} Layers)</h2>"
            f"<table><tr><th>#</th><th>Technique</th><th>Size</th><th>Entropy</th></tr>{rows}</table>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GenVirus Reborn Report - {esc(report.file_name)}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; margin: 2rem auto; max-width: 960px; padding: 0 1rem; }}
h1, h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .3rem; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #30363d; padding: .5rem; text-align: left; }}
th {{ background: #21262d; }}
code, pre {{ background: #161b22; color: #79c0ff; padding: .15rem .35rem; border-radius: 4px; }}
pre {{ padding: 1rem; overflow-x: auto; border: 1px solid #30363d; }}
.badge {{ padding: .15rem .45rem; border-radius: 4px; font-size: .8rem; font-weight: 700; }}
.high {{ background: #da3633; color: #fff; }}
.medium {{ background: #d29922; color: #000; }}
.low {{ background: #388bfd; color: #fff; }}
.info {{ background: #30363d; color: #c9d1d9; }}
</style>
</head>
<body>
<h1>GenVirus Reborn &mdash; Triage Report: <code>{esc(report.file_name)}</code></h1>
<div class="card">
  <p><strong>Risk:</strong> {esc(report.risk_level)} ({report.risk_score}/100) &bull;
     <strong>Size:</strong> {report.file_size} bytes &bull;
     <strong>Entropy:</strong> {report.overall_entropy:.4f}/8.0</p>
  <p><strong>SHA256:</strong> <code>{esc(report.hashes.sha256)}</code></p>
</div>
{steps_html}
<h2>Matched Heuristic Signatures</h2>
<ul>{matches_html}</ul>
<h2>Auto-Generated YARA Rule</h2>
<pre>{esc(report.yara_rule)}</pre>
</body>
</html>
"""
    out.write_text(doc, encoding="utf-8")
    return out
