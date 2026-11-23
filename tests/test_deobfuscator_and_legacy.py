"""Tests for Pillar 2: Deobfuscation Engine & Legacy 2021 GenVirus v1.0 Unpacking."""

from __future__ import annotations

from pathlib import Path

from genvirus.analyzers.deobfuscator import deobfuscate_file
from genvirus.analyzers.static_triage import analyze_file

LEGACY_V1_PATH = Path("legacy/GenVirus_v1_2021.sh")


def test_legacy_v1_deobfuscation() -> None:
    assert LEGACY_V1_PATH.exists(), "legacy/GenVirus_v1_2021.sh must exist"
    result = deobfuscate_file(LEGACY_V1_PATH)

    assert result.is_obfuscated is True
    assert result.total_layers == 6
    assert "bash_var_substitution" in result.steps[0].technique
    assert "IGN0R3DH4X0R" in result.steps[1].technique
    assert "SHAYER MAHMUD" in result.final_payload
    assert len(result.iocs.deceptive_urls) >= 1
    assert result.iocs.deceptive_urls[0].true_host == "ffmodmenu.page.link"


def test_legacy_v1_static_triage() -> None:
    report = analyze_file(LEGACY_V1_PATH)
    rule_ids = {m.rule_id for m in report.matches}

    assert report.risk_level == "HIGH"
    assert "GEN_MultiLayer_Shell_Obfuscation" in rule_ids
    assert "GEN_Deceptive_URL_Userinfo_Masking" in rule_ids
    assert "rule GenVirus_Auto_GenVirus_v1_2021" in report.yara_rule
