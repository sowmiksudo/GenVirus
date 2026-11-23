"""Automated Multi-Layer Deobfuscator Engine (safe static unpacking, never executes eval)."""

from __future__ import annotations

import base64
import codecs
import re
import zlib
from pathlib import Path

from genvirus.analyzers.ioc_extractor import extract_iocs
from genvirus.core.entropy import calculate_shannon_entropy
from genvirus.core.models import DeobfuscationResult, DeobfuscationStep

_VAR_ASSIGN_RE = re.compile(r"([A-Za-z0-9_]+)=('([^']*)'|\"([^\"]*)\")")
_HEREDOC_BASE_RE = re.compile(
    r"base(64|32)\s+-d\b[^\n]*<<\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\n(.*?)\n\2",
    re.DOTALL,
)
_PY_HEX_RE = re.compile(r"bytes\.fromhex\(['\"]([0-9a-fA-F]+)['\"]\)")
_PY_XOR_RE = re.compile(
    r"bytes\.fromhex\(['\"]([0-9a-fA-F]+)['\"]\).*?b\s*\^\s*(0x[0-9a-fA-F]+|\d+)",
    re.DOTALL,
)
_PY_ZLIB_RE = re.compile(r"zlib\.decompress\(base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)\)")
_PY_ROT13_RE = re.compile(r"codecs\.decode\(base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\).*?['\"]rot_13['\"]\)")


def _try_peel_bash_vars(text: str) -> tuple[str, str] | None:
    """Resolve Bash variable-chunk substitution (e.g., GenVirus v1.0 style) statically."""
    if "eval \"" not in text or text.count("='") < 5:
        return None
    vars_dict: dict[str, str] = {}
    for m in _VAR_ASSIGN_RE.finditer(text):
        val = m.group(3) if m.group(3) is not None else (m.group(4) or "")
        vars_dict[m.group(1)] = val

    eval_idx = text.find('eval "')
    if eval_idx == -1:
        return None
    end_idx = text.rfind('"')
    if end_idx <= eval_idx + 6:
        return None
    template = text[eval_idx + 6 : end_idx]
    expanded = re.sub(
        r"\$\{?([A-Za-z0-9_]+)\}?",
        lambda m: vars_dict.get(m.group(1), m.group(0)),
        template,
    )
    if expanded == template:
        return None
    return "bash_var_substitution", expanded


def _try_peel_heredoc_base(text: str) -> tuple[str, str] | None:
    """Decode base64/base32 heredoc payloads."""
    m = _HEREDOC_BASE_RE.search(text)
    if not m:
        return None
    kind, tag, payload = m.group(1), m.group(2), re.sub(r"\s+", "", m.group(3))
    try:
        raw = base64.b64decode(payload) if kind == "64" else base64.b32decode(payload)
        decoded = raw.decode("utf-8", errors="replace")
        return f"base{kind}_heredoc (tag={tag})", decoded
    except Exception:
        return None


def _try_peel_python_stub(text: str) -> tuple[str, str] | None:
    """Decode common Python one-liner decoder stubs statically."""
    m_zlib = _PY_ZLIB_RE.search(text)
    if m_zlib:
        try:
            raw = zlib.decompress(base64.b64decode(m_zlib.group(1)))
            return "zlib+base64_stub", raw.decode("utf-8", errors="replace")
        except Exception:
            pass

    m_rot = _PY_ROT13_RE.search(text)
    if m_rot:
        try:
            raw = base64.b64decode(m_rot.group(1)).decode("utf-8", errors="replace")
            return "rot13+base64_stub", codecs.decode(raw, "rot_13")
        except Exception:
            pass

    m_xor = _PY_XOR_RE.search(text)
    if m_xor:
        try:
            data = bytes.fromhex(m_xor.group(1))
            key = int(m_xor.group(2), 0)
            decoded = bytes(b ^ key for b in data).decode("utf-8", errors="replace")
            return f"xor_hex_stub (key=0x{key:02x})", decoded
        except Exception:
            pass

    m_hex = _PY_HEX_RE.search(text)
    if m_hex:
        try:
            decoded = bytes.fromhex(m_hex.group(1)).decode("utf-8", errors="replace")
            return "hex_stub", decoded
        except Exception:
            pass

    return None


def _try_peel_raw_encoding(text: str) -> tuple[str, str] | None:
    """Attempt to decode standalone Base64, Base32, or Hex blobs."""
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 16:
        return None

    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0:
        try:
            decoded = bytes.fromhex(stripped).decode("utf-8")
            if sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(1, len(decoded)) > 0.85:
                return "raw_hex", decoded
        except Exception:
            pass

    if re.fullmatch(r"[A-Z2-7=]+", stripped) and len(stripped) % 8 == 0:
        try:
            decoded = base64.b32decode(stripped).decode("utf-8")
            if sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(1, len(decoded)) > 0.85:
                return "raw_base32", decoded
        except Exception:
            pass

    if re.fullmatch(r"[A-Za-z0-9+/=]+", stripped) and len(stripped) % 4 == 0:
        try:
            decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
            if sum(c.isprintable() or c in "\n\r\t" for c in decoded) / max(1, len(decoded)) > 0.85:
                return "raw_base64", decoded
        except Exception:
            pass

    return None


def deobfuscate_text(text: str, source_path: str = "<memory>", max_depth: int = 25) -> DeobfuscationResult:
    """Iteratively peel obfuscation layers from text without executing code."""
    current = text
    steps: list[DeobfuscationStep] = []

    for depth in range(1, max_depth + 1):
        peeled = (
            _try_peel_bash_vars(current)
            or _try_peel_heredoc_base(current)
            or _try_peel_python_stub(current)
            or _try_peel_raw_encoding(current)
        )
        if not peeled:
            break
        technique, next_text = peeled
        ent_before = calculate_shannon_entropy(current.encode("utf-8", errors="replace"))
        ent_after = calculate_shannon_entropy(next_text.encode("utf-8", errors="replace"))
        preview = next_text.strip().splitlines()[0][:80] if next_text.strip() else ""
        steps.append(
            DeobfuscationStep(
                step=depth,
                technique=technique,
                input_size=len(current),
                output_size=len(next_text),
                entropy_before=ent_before,
                entropy_after=ent_after,
                details=f"{len(current)} -> {len(next_text)} bytes",
                preview=preview,
            )
        )
        current = next_text

    return DeobfuscationResult(
        source_path=source_path,
        total_layers=len(steps),
        steps=steps,
        final_payload=current,
        is_obfuscated=len(steps) > 0,
        iocs=extract_iocs(current),
    )


def deobfuscate_file(file_path: str | Path, max_depth: int = 25) -> DeobfuscationResult:
    """Read a file and run multi-layer static deobfuscation."""
    path = Path(file_path)
    content = path.read_text(encoding="utf-8", errors="replace")
    return deobfuscate_text(content, source_path=str(path), max_depth=max_depth)
