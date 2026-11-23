"""Built-in Heuristic & Pattern Scanner + Auto YARA Rule Exporter."""

from __future__ import annotations

import re
from pathlib import Path

from genvirus.core.models import DeobfuscationResult, IoCReport, SignatureMatch
from genvirus.generators.eicar import build_eicar_bytes


def scan_heuristics(
    raw_data: bytes,
    text_view: str,
    overall_entropy: float,
    iocs: IoCReport,
    deobf: DeobfuscationResult | None = None,
) -> list[SignatureMatch]:
    """Evaluate built-in detection rules against raw bytes, decoded text, and IoCs."""
    matches: list[SignatureMatch] = []

    eicar_sig = build_eicar_bytes()
    if eicar_sig in raw_data or eicar_sig.decode("ascii") in text_view:
        matches.append(
            SignatureMatch(
                rule_id="GEN_EICAR_Antivirus_Test_Signature",
                severity="INFO",
                description="Standard 68-byte EICAR antivirus test signature detected.",
                matched_indicators=["EICAR-STANDARD-ANTIVIRUS-TEST-FILE"],
            )
        )

    if deobf and deobf.total_layers >= 2:
        matches.append(
            SignatureMatch(
                rule_id="GEN_MultiLayer_Shell_Obfuscation",
                severity="HIGH",
                description=f"Detected {deobf.total_layers} nested obfuscation/encoding layers.",
                matched_indicators=[s.technique for s in deobf.steps],
            )
        )

    if "eval_exec" in iocs.suspicious_commands and "mktemp_source" in iocs.suspicious_commands:
        matches.append(
            SignatureMatch(
                rule_id="GEN_Eval_Mktemp_Source_Dropper",
                severity="HIGH",
                description="Script decodes payload to mktemp file and executes via eval/source.",
                matched_indicators=["eval_exec", "mktemp_source"],
            )
        )

    if iocs.deceptive_urls:
        matches.append(
            SignatureMatch(
                rule_id="GEN_Deceptive_URL_Userinfo_Masking",
                severity="MEDIUM",
                description="RFC 3986 userinfo@host credential-masking URL trick detected.",
                matched_indicators=[
                    f"bait='{d.bait_userinfo}' -> true_host='{d.true_host}'"
                    for d in iocs.deceptive_urls
                ],
            )
        )

    if overall_entropy >= 7.2:
        matches.append(
            SignatureMatch(
                rule_id="GEN_High_Entropy_Packed_Section",
                severity="MEDIUM",
                description=f"High Shannon entropy ({overall_entropy:.2f}/8.0) indicates packing/encryption.",
                matched_indicators=[f"entropy={overall_entropy:.4f}"],
            )
        )

    if "trap_signal" in iocs.suspicious_commands:
        matches.append(
            SignatureMatch(
                rule_id="GEN_Suspicious_Trap_Handler",
                severity="LOW",
                description="Script intercepts SIGINT/SIGTSTP signals using trap.",
                matched_indicators=["trap_signal"],
            )
        )

    pe_apis = [api for api in (b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread") if api in raw_data]
    if pe_apis:
        matches.append(
            SignatureMatch(
                rule_id="GEN_Suspicious_PE_API_Strings",
                severity="MEDIUM",
                description="Process injection API string markers detected in binary.",
                matched_indicators=[a.decode("ascii") for a in pe_apis],
            )
        )

    if any(cmd in iocs.suspicious_commands for cmd in ("curl_pipe_shell", "rm_rf")):
        matches.append(
            SignatureMatch(
                rule_id="GEN_Suspicious_Shell_Indicators",
                severity="MEDIUM",
                description="Potentially destructive or remote-pipe shell command patterns found.",
                matched_indicators=[c for c in iocs.suspicious_commands if c in ("curl_pipe_shell", "rm_rf")],
            )
        )

    return matches


def generate_yara_rule(
    file_name: str,
    sha256: str,
    raw_data: bytes,
    iocs: IoCReport,
    matches: list[SignatureMatch],
) -> str:
    """Auto-generate a ready-to-use YARA rule from an analyzed specimen."""
    safe_rule_name = re.sub(r"[^A-Za-z0-9_]", "_", Path(file_name).stem) or "specimen"
    if safe_rule_name[0].isdigit():
        safe_rule_name = f"rule_{safe_rule_name}"
    rule_name = f"GenVirus_Auto_{safe_rule_name}"

    string_lines: list[str] = []
    idx = 1

    # Include up to 3 URLs or domains
    for url in iocs.urls[:3]:
        escaped = url.replace("\\", "\\\\").replace('"', '\\"')
        string_lines.append(f'        $ioc_url_{idx} = "{escaped}" ascii nocase')
        idx += 1

    # Include up to 3 notable ASCII strings from raw bytes
    ascii_tokens = re.findall(rb"[A-Za-z0-9_./:@-]{8,48}", raw_data)
    seen_tokens: set[str] = set()
    for tok in ascii_tokens:
        s = tok.decode("ascii", errors="ignore")
        if s not in seen_tokens and not s.startswith("AAAA"):
            seen_tokens.add(s)
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')
            string_lines.append(f'        $str_{idx} = "{escaped}" ascii')
            idx += 1
        if len(seen_tokens) >= 3:
            break

    if not string_lines:
        # Fallback to first 16 bytes hex pattern
        hex_prefix = " ".join(f"{b:02X}" for b in raw_data[:16])
        string_lines.append(f"        $magic_hex = {{ {hex_prefix} }}")

    max_size = max(1024, len(raw_data) * 2)
    tags = ", ".join(m.rule_id for m in matches) if matches else "generic_specimen"

    return (
        f"rule {rule_name}\n"
        "{\n"
        "    meta:\n"
        '        author = "GenVirus Reborn v2.0 Auto-YARA"\n'
        f'        source_file = "{file_name}"\n'
        f'        sha256 = "{sha256}"\n'
        f'        matched_heuristics = "{tags}"\n'
        "    strings:\n"
        + "\n".join(string_lines)
        + "\n    condition:\n"
        f"        filesize <= {max_size} and any of them\n"
        "}\n"
    )
