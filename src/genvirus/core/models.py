"""Structured data models used across generators, analyzers, lab, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HashSet:
    """Cryptographic hash digest bundle for a specimen."""

    md5: str
    sha1: str
    sha256: str


@dataclass
class DeceptiveURL:
    """Represents an RFC 3986 userinfo@host masked URL used in phishing/social engineering."""

    full_url: str
    bait_userinfo: str
    true_host: str
    path: str


@dataclass
class IoCReport:
    """Extracted Indicators of Compromise and behavioral heuristics."""

    urls: list[str] = field(default_factory=list)
    deceptive_urls: list[DeceptiveURL] = field(default_factory=list)
    ipv4_addresses: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    suspicious_commands: list[str] = field(default_factory=list)


@dataclass
class DeobfuscationStep:
    """One peeled obfuscation layer in a deobfuscation trace."""

    step: int
    technique: str
    input_size: int
    output_size: int
    entropy_before: float
    entropy_after: float
    details: str
    preview: str


@dataclass
class DeobfuscationResult:
    """Complete result of multi-layer deobfuscation."""

    source_path: str
    total_layers: int
    steps: list[DeobfuscationStep]
    final_payload: str
    is_obfuscated: bool
    iocs: IoCReport = field(default_factory=IoCReport)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class SignatureMatch:
    """A matched heuristic or YARA-style rule."""

    rule_id: str
    severity: str
    description: str
    matched_indicators: list[str] = field(default_factory=list)


@dataclass
class StaticAnalysisReport:
    """Full static triage report for a file or specimen."""

    file_path: str
    file_name: str
    file_size: int
    file_type: str
    hashes: HashSet
    overall_entropy: float
    chunk_entropies: list[float]
    printable_strings_count: int
    iocs: IoCReport
    deobfuscation: DeobfuscationResult | None
    matches: list[SignatureMatch]
    risk_score: int
    risk_level: str
    yara_rule: str
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class GeneratedSpecimen:
    """Metadata describing a safely generated test specimen."""

    artifact_type: str
    variant: str
    output_path: str
    size_bytes: int
    hashes: HashSet
    description: str
    layers: list[str] = field(default_factory=list)
    expected_detections: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class TelemetryEvent:
    """One simulated Atomic-style behavioral telemetry event."""

    technique_id: str
    technique_name: str
    action: str
    dry_run: bool
    sandbox_dir: str
    artifact_path: str | None
    command_executed: str
    pid: int | None
    cleaned_up: bool
    audit_hint: str
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)
