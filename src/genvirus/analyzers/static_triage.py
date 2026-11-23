"""Static File & Script Triage Analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from genvirus.analyzers.deobfuscator import deobfuscate_text
from genvirus.analyzers.ioc_extractor import extract_iocs
from genvirus.analyzers.yara_engine import generate_yara_rule, scan_heuristics
from genvirus.core.entropy import (
    calculate_shannon_entropy,
    chunked_entropy_profile,
    compute_hashes,
)
from genvirus.core.models import StaticAnalysisReport


def _detect_file_type(data: bytes, path: Path) -> str:
    """Identify basic file type from magic bytes and extension."""
    if data.startswith(b"MZ"):
        return "PE/DOS Executable (or Mock)"
    if data.startswith(b"\x7fELF"):
        return "ELF Binary"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP Archive"
    if data.startswith(b"#!") or path.suffix in {".sh", ".bash", ".py"}:
        return f"Script ({path.suffix or 'shebang'})"
    try:
        data.decode("utf-8")
        return "UTF-8 Text"
    except UnicodeDecodeError:
        return "Binary Data"


def analyze_file(file_path: str | Path) -> StaticAnalysisReport:
    """Run full static triage, entropy profiling, deobfuscation, IoC & YARA analysis."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Specimen not found: {path}")

    raw_data = path.read_bytes()
    hashes = compute_hashes(raw_data)
    overall_entropy = calculate_shannon_entropy(raw_data)
    chunk_entropies = chunked_entropy_profile(raw_data, chunks=16)
    file_type = _detect_file_type(raw_data, path)

    printable_strings = re.findall(rb"[\x20-\x7e]{4,}", raw_data)
    text_view = raw_data.decode("utf-8", errors="replace")

    deobf = deobfuscate_text(text_view, source_path=str(path))
    analysis_text = deobf.final_payload if deobf.is_obfuscated else text_view
    iocs = extract_iocs(analysis_text)

    matches = scan_heuristics(
        raw_data=raw_data,
        text_view=analysis_text,
        overall_entropy=overall_entropy,
        iocs=iocs,
        deobf=deobf,
    )

    severity_weights = {"HIGH": 35, "MEDIUM": 20, "LOW": 10, "INFO": 5}
    risk_score = min(100, sum(severity_weights.get(m.severity, 10) for m in matches))
    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN / BENIGN"

    yara_rule = generate_yara_rule(
        file_name=path.name,
        sha256=hashes.sha256,
        raw_data=raw_data,
        iocs=iocs,
        matches=matches,
    )

    return StaticAnalysisReport(
        file_path=str(path),
        file_name=path.name,
        file_size=len(raw_data),
        file_type=file_type,
        hashes=hashes,
        overall_entropy=overall_entropy,
        chunk_entropies=chunk_entropies,
        printable_strings_count=len(printable_strings),
        iocs=iocs,
        deobfuscation=deobf,
        matches=matches,
        risk_score=risk_score,
        risk_level=risk_level,
        yara_rule=yara_rule,
    )
