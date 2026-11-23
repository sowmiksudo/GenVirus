"""EICAR & AV Test File Generator (strictly benign standard test artifacts)."""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path

from genvirus import BENIGN_MARKER
from genvirus.core.entropy import compute_hashes
from genvirus.core.models import GeneratedSpecimen

# Dynamically assembled standard 68-byte EICAR test string so source code is not flagged
_EICAR_PARTS = (
    "X5O!P%@AP[4\\PZX54(P^",
    ")7CC)7}$EICAR-STANDARD-",
    "ANTIVIRUS-TEST-FILE!$H+H*",
)


def build_eicar_bytes() -> bytes:
    """Return the official 68-byte EICAR antivirus test string."""
    return "".join(_EICAR_PARTS).encode("ascii")


def generate_eicar_specimen(
    variant: str = "raw",
    output_dir: str | Path = "artifacts_out",
    nesting_depth: int = 3,
) -> GeneratedSpecimen:
    """Generate an EICAR test specimen in the requested wrapper format."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_eicar = build_eicar_bytes()
    variant_norm = variant.lower().strip()

    if variant_norm == "raw":
        out_path = out_dir / "eicar_standard.com.txt"
        out_path.write_bytes(raw_eicar)
        desc = "Standard 68-byte EICAR antivirus test file."
        detections = ["EICAR-Test-File", "GEN_EICAR_Antivirus_Test_Signature"]
    elif variant_norm == "base64":
        out_path = out_dir / "eicar_encoded.b64"
        encoded = base64.b64encode(raw_eicar)
        out_path.write_bytes(encoded)
        desc = "Base64-encoded EICAR test payload for DLP / stream-decoding AV checks."
        detections = ["Base64-Encoded EICAR"]
    elif variant_norm == "hex":
        out_path = out_dir / "eicar_encoded.hex"
        out_path.write_text(raw_eicar.hex(), encoding="utf-8")
        desc = "Hex-encoded EICAR test payload."
        detections = ["Hex-Encoded EICAR"]
    elif variant_norm == "zip":
        out_path = out_dir / f"eicar_nested_{nesting_depth}x.zip"
        current_bytes = raw_eicar
        inner_name = "eicar.com.txt"
        depth = max(1, min(nesting_depth, 10))
        for level in range(1, depth + 1):
            buf_path = out_dir / f".tmp_layer_{level}.zip"
            with zipfile.ZipFile(buf_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(inner_name, current_bytes)
            current_bytes = buf_path.read_bytes()
            buf_path.unlink()
            inner_name = f"layer_{level}.zip"
        out_path.write_bytes(current_bytes)
        desc = f"Nested ZIP ({depth} layers) containing EICAR to test archive recursion depth."
        detections = ["Archive-Nested EICAR", f"RecursionDepth>={depth}"]
    elif variant_norm == "polyglot":
        out_path = out_dir / "eicar_polyglot.sh"
        script = (
            "#!/usr/bin/env bash\n"
            f"# {BENIGN_MARKER}\n"
            "echo '[GenVirus] Benign polyglot EICAR test specimen'\n"
            f"# {raw_eicar.decode('ascii')}\n"
        )
        out_path.write_text(script, encoding="utf-8")
        desc = "Benign Bash script with EICAR embedded as a trailing comment."
        detections = ["EICAR-Test-File", "GEN_EICAR_Antivirus_Test_Signature"]
    else:
        raise ValueError(f"Unsupported EICAR variant: {variant}. Choose raw, base64, hex, zip, or polyglot.")

    data = out_path.read_bytes()
    return GeneratedSpecimen(
        artifact_type="eicar",
        variant=variant_norm,
        output_path=str(out_path),
        size_bytes=len(data),
        hashes=compute_hashes(data),
        description=desc,
        layers=[variant_norm],
        expected_detections=detections,
    )
