"""Shannon entropy calculation, chunked profiling, and hash helpers."""

from __future__ import annotations

import hashlib
import math

from genvirus.core.models import HashSet


def compute_hashes(data: bytes) -> HashSet:
    """Compute MD5, SHA1, and SHA256 digests for raw bytes."""
    return HashSet(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def calculate_shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    for count in counts:
        if count:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def chunked_entropy_profile(data: bytes, chunks: int = 16) -> list[float]:
    """Divide data into N roughly equal chunks and compute entropy for each."""
    if not data:
        return [0.0]
    actual_chunks = min(chunks, len(data))
    step = max(1, len(data) // actual_chunks)
    profile: list[float] = []
    for i in range(0, len(data), step):
        segment = data[i : i + step]
        if segment:
            profile.append(calculate_shannon_entropy(segment))
        if len(profile) >= actual_chunks:
            break
    return profile


def entropy_sparkline(profile: list[float]) -> str:
    """Render an 8-level Unicode sparkline for a list of entropy values (0.0-8.0)."""
    blocks = " ▁▂▃▄▅▆▇█"
    chars: list[str] = []
    for val in profile:
        idx = min(8, max(0, round((val / 8.0) * 8)))
        chars.append(blocks[idx])
    return "".join(chars)
