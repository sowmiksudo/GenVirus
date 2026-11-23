"""Multi-Layer Script Obfuscation Benchmark Generator (benign payloads only)."""

from __future__ import annotations

import base64
import codecs
import random
import string
import zlib
from pathlib import Path

from genvirus import BENIGN_MARKER
from genvirus.core.entropy import compute_hashes
from genvirus.core.models import GeneratedSpecimen

PRESET_PIPELINES: dict[str, list[str]] = {
    "light": ["base64", "rot13"],
    "legacy-v1": ["base32", "base64", "bash_vars"],
    "deep": ["rot13", "hex", "zlib", "base32", "base64", "bash_vars"],
}


def _wrap_bash_vars(script_text: str, seed: int = 2021) -> str:
    """Wrap a shell script using GenVirus v1.0-style randomized variable chunk substitution."""
    rng = random.Random(seed)
    chunk_size = 4
    chunks = [script_text[i : i + chunk_size] for i in range(0, len(script_text), chunk_size)]
    assignments: list[str] = ['z="\n"']
    refs: list[str] = []
    used_names: set[str] = {"z"}

    for chunk in chunks:
        if chunk == "\n":
            refs.append("$z")
            continue
        while True:
            name = "".join(rng.choices(string.ascii_letters, k=4))
            if name not in used_names:
                used_names.add(name)
                break
        safe_chunk = chunk.replace("'", "'\"'\"'")
        assignments.append(f"{name}='{safe_chunk}'")
        refs.append(f"${name}")

    rng.shuffle(assignments)
    var_block = ";".join(assignments)
    eval_expr = "".join(refs)
    return f'#!/usr/bin/env bash\n# {BENIGN_MARKER}\n{var_block};eval "{eval_expr}"\n'


def _apply_layer(content: str, layer: str) -> str:
    """Wrap a bash script string in one decoding layer."""
    layer = layer.strip().lower()
    raw_bytes = content.encode("utf-8")

    if layer == "base64":
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        return (
            "GENV_TMP=$(mktemp)\n"
            f"base64 -d >${{GENV_TMP}}<<GENVIRUS_LAYER\n{b64}\nGENVIRUS_LAYER\n"
            "source ${GENV_TMP}\nrm -f ${GENV_TMP}\n"
        )
    if layer == "base32":
        b32 = base64.b32encode(raw_bytes).decode("ascii")
        return (
            "GENV_TMP=$(mktemp)\n"
            f"base32 -d >${{GENV_TMP}}<<GENVIRUS_LAYER\n{b32}\nGENVIRUS_LAYER\n"
            "source ${GENV_TMP}\nrm -f ${GENV_TMP}\n"
        )
    if layer == "hex":
        hx = raw_bytes.hex()
        return (
            "GENV_TMP=$(mktemp)\n"
            f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{hx}'))\" >\"${{GENV_TMP}}\"\n"
            "source \"${GENV_TMP}\"\nrm -f \"${GENV_TMP}\"\n"
        )
    if layer == "rot13":
        encoded = codecs.encode(content, "rot_13")
        b64_rot = base64.b64encode(encoded.encode("utf-8")).decode("ascii")
        return (
            "GENV_TMP=$(mktemp)\n"
            f"python3 -c \"import base64,codecs; print(codecs.decode(base64.b64decode('{b64_rot}').decode(),'rot_13'))\" >\"${{GENV_TMP}}\"\n"
            "source \"${GENV_TMP}\"\nrm -f \"${{GENV_TMP}}\"\n"
        )
    if layer == "zlib":
        comp = base64.b64encode(zlib.compress(raw_bytes, level=9)).decode("ascii")
        return (
            "GENV_TMP=$(mktemp)\n"
            f"python3 -c \"import base64,zlib; print(zlib.decompress(base64.b64decode('{comp}')).decode())\" >\"${{GENV_TMP}}\"\n"
            "source \"${GENV_TMP}\"\nrm -f \"${GENV_TMP}\"\n"
        )
    if layer == "xor":
        key = 0x5A
        xored = bytes(b ^ key for b in raw_bytes).hex()
        return (
            "GENV_TMP=$(mktemp)\n"
            f"python3 -c \"d=bytes.fromhex('{xored}'); print(bytes(b^0x{key:02x} for b in d).decode())\" >\"${{GENV_TMP}}\"\n"
            "source \"${GENV_TMP}\"\nrm -f \"${{GENV_TMP}}\"\n"
        )
    if layer == "bash_vars":
        return _wrap_bash_vars(content)
    raise ValueError(
        f"Unknown obfuscation layer '{layer}'. Supported: base64, base32, hex, rot13, zlib, xor, bash_vars."
    )


def generate_obfuscated_specimen(
    payload_message: str = "Hello from GenVirus v2.0 Benign Benchmark Specimen!",
    layers: list[str] | None = None,
    preset: str | None = "legacy-v1",
    output_path: str | Path = "artifacts_out/obfuscated_specimen.sh",
) -> GeneratedSpecimen:
    """Generate a multi-layer obfuscated benign Bash script for testing deobfuscators."""
    if layers:
        pipeline = [item.strip().lower() for item in layers if item.strip()]
    elif preset and preset in PRESET_PIPELINES:
        pipeline = list(PRESET_PIPELINES[preset])
    else:
        raise ValueError(f"Invalid preset '{preset}'. Choose from {list(PRESET_PIPELINES)} or pass explicit layers.")

    safe_msg = payload_message.replace('"', '\\"').replace("$", "\\$")
    current_script = (
        "#!/usr/bin/env bash\n"
        f"# {BENIGN_MARKER}\n"
        f'echo "[GenVirus Benchmark] {safe_msg}"\n'
    )

    for layer in pipeline:
        current_script = _apply_layer(current_script, layer)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(current_script, encoding="utf-8")
    data = out_file.read_bytes()

    return GeneratedSpecimen(
        artifact_type="obfuscated_script",
        variant=preset or "custom",
        output_path=str(out_file),
        size_bytes=len(data),
        hashes=compute_hashes(data),
        description=f"Benign shell specimen wrapped in {len(pipeline)} obfuscation layer(s): {' -> '.join(pipeline)}.",
        layers=pipeline,
        expected_detections=[
            "GEN_MultiLayer_Shell_Obfuscation",
            "GEN_Eval_Mktemp_Source_Dropper",
        ],
    )
