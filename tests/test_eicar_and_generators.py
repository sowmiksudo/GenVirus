"""Tests for Pillar 1: EICAR, Multi-Layer Obfuscation Benchmark, Triggers & Telemetry."""

from __future__ import annotations

import zipfile
from pathlib import Path

from genvirus import BENIGN_MARKER
from genvirus.analyzers.deobfuscator import deobfuscate_file
from genvirus.generators.eicar import build_eicar_bytes, generate_eicar_specimen
from genvirus.generators.obfuscator import generate_obfuscated_specimen
from genvirus.generators.telemetry import run_telemetry_simulation
from genvirus.generators.triggers import generate_trigger_specimen


def test_eicar_variants(tmp_path: Path) -> None:
    expected = build_eicar_bytes()
    assert len(expected) == 68

    raw_spec = generate_eicar_specimen(variant="raw", output_dir=tmp_path)
    assert Path(raw_spec.output_path).read_bytes() == expected

    b64_spec = generate_eicar_specimen(variant="base64", output_dir=tmp_path)
    assert Path(b64_spec.output_path).exists()

    hex_spec = generate_eicar_specimen(variant="hex", output_dir=tmp_path)
    assert bytes.fromhex(Path(hex_spec.output_path).read_text()) == expected

    poly_spec = generate_eicar_specimen(variant="polyglot", output_dir=tmp_path)
    assert expected.decode("ascii") in Path(poly_spec.output_path).read_text()

    zip_spec = generate_eicar_specimen(variant="zip", output_dir=tmp_path, nesting_depth=2)
    assert zipfile.is_zipfile(zip_spec.output_path)


def test_obfuscator_roundtrip_presets(tmp_path: Path) -> None:
    for preset in ("light", "legacy-v1", "deep"):
        out_file = tmp_path / f"spec_{preset}.sh"
        spec = generate_obfuscated_specimen(
            payload_message=f"Test-{preset}",
            preset=preset,
            output_path=out_file,
        )
        assert out_file.exists()
        assert spec.size_bytes > 0

        res = deobfuscate_file(out_file)
        assert res.is_obfuscated is True
        assert res.total_layers >= 2
        assert BENIGN_MARKER in res.final_payload
        assert f"Test-{preset}" in res.final_payload


def test_trigger_specimens(tmp_path: Path) -> None:
    specs = generate_trigger_specimen(profile="all", output_dir=tmp_path)
    assert len(specs) == 3
    assert (tmp_path / "trigger_manifest.json").exists()
    for s in specs:
        assert Path(s.output_path).exists()


def test_telemetry_simulation_cleanup(tmp_path: Path) -> None:
    events, log_path = run_telemetry_simulation(
        technique="all",
        dry_run=False,
        keep_artifacts=False,
        output_dir=tmp_path,
    )
    assert len(events) == 5
    assert log_path.exists()
    # Sandbox directory should have been cleaned up automatically
    sandboxes = list(tmp_path.glob("telemetry_sandbox_*"))
    assert sandboxes == []
