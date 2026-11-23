"""Tests for Entropy, Reporters, CTF Lab, and Typer CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from genvirus.analyzers.reporter import export_html, export_json, export_markdown
from genvirus.analyzers.static_triage import analyze_file
from genvirus.cli import app
from genvirus.core.entropy import calculate_shannon_entropy, entropy_sparkline
from genvirus.lab.challenges import prepare_lab_specimens, verify_answer

runner = CliRunner()


def test_entropy_calculations() -> None:
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"A" * 100) == 0.0
    high = calculate_shannon_entropy(bytes(range(256)))
    assert high == 8.0
    spark = entropy_sparkline([0.0, 4.0, 8.0])
    assert len(spark) == 3


def test_reporters(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("http://bait@203.0.113.5/test.sh\n", encoding="utf-8")
    report = analyze_file(sample)

    j_path = export_json(report, tmp_path / "out.json")
    m_path = export_markdown(report, tmp_path / "out.md")
    h_path = export_html(report, tmp_path / "out.html")

    parsed = json.loads(j_path.read_text(encoding="utf-8"))
    assert parsed["file_name"] == "sample.txt"
    assert "Auto-Generated YARA Rule" in m_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in h_path.read_text(encoding="utf-8")


def test_ctf_lab_verification(tmp_path: Path) -> None:
    prepare_lab_specimens(tmp_path)
    assert (tmp_path / "c2_matryoshka.sh").exists()
    assert (tmp_path / "trigger_ioc_strings.txt").exists()

    ok1, _ = verify_answer("c1", "ffmodmenu.page.link")
    ok2, _ = verify_answer("c2", "FLAG{matryoshka_beacon_203.0.113.99}")
    ok3, _ = verify_answer("c3", "198.51.100.42")
    ok4, _ = verify_answer("c4", "T1547")
    bad, _ = verify_answer("c1", "wrong-host.example")

    assert ok1 and ok2 and ok3 and ok4
    assert not bad


def test_cli_commands(tmp_path: Path) -> None:
    res_ver = runner.invoke(app, ["--version"])
    assert res_ver.exit_code == 0
    assert "2.0.0" in res_ver.stdout

    res_eicar = runner.invoke(app, ["generate", "eicar", "--variant", "raw", "--output", str(tmp_path)])
    assert res_eicar.exit_code == 0
    assert (tmp_path / "eicar_standard.com.txt").exists()

    res_sim = runner.invoke(app, ["simulate", "--dry-run", "--output", str(tmp_path)])
    assert res_sim.exit_code == 0

    res_lab = runner.invoke(app, ["lab", "verify", "c1", "--answer", "ffmodmenu.page.link"])
    assert res_lab.exit_code == 0
    assert "PASS" in res_lab.stdout
