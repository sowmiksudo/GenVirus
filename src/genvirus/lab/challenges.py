"""Progressive hands-on CTF challenges ('Crack The Specimen')."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from genvirus.generators.obfuscator import generate_obfuscated_specimen
from genvirus.generators.triggers import generate_trigger_specimen


@dataclass(frozen=True)
class Challenge:
    """Definition of an interactive reverse-engineering challenge."""

    id: str
    title: str
    difficulty: str
    description: str
    prompt_question: str
    hint: str
    accepted_answers: tuple[str, ...]
    specimen_hint_path: str


CHALLENGES: list[Challenge] = [
    Challenge(
        id="c1",
        title="The 2021 Time Capsule (GenVirus v1.0)",
        difficulty="Beginner",
        description=(
            "Inspect the original 2021 GenVirus script archived at `legacy/GenVirus_v1_2021.sh`. "
            "Use `genvirus deobfuscate` or `genvirus analyze` to peel its 6 obfuscation layers "
            "without executing it."
        ),
        prompt_question="What is the TRUE destination hostname hidden behind the '@' masked URL in v1.0?",
        hint="Look at the Masked Link in the deobfuscated output: http://<bait>@<true_host>/LatestMODMENU",
        accepted_answers=("ffmodmenu.page.link",),
        specimen_hint_path="legacy/GenVirus_v1_2021.sh",
    ),
    Challenge(
        id="c2",
        title="Matryoshka Beacon",
        difficulty="Intermediate",
        description=(
            "Generate or inspect the Matryoshka Beacon specimen (`artifacts_out/lab/c2_matryoshka.sh`), "
            "which wraps a simulated RFC-5737 beacon inside 4 nested encoding layers."
        ),
        prompt_question="Deobfuscate the specimen and enter the full FLAG{...} string:",
        hint="Run: genvirus deobfuscate artifacts_out/lab/c2_matryoshka.sh",
        accepted_answers=("FLAG{matryoshka_beacon_203.0.113.99}",),
        specimen_hint_path="artifacts_out/lab/c2_matryoshka.sh",
    ),
    Challenge(
        id="c3",
        title="High-Entropy & IoC Trigger Hunt",
        difficulty="Intermediate",
        description=(
            "Generate the YARA trigger specimens (`artifacts_out/lab/trigger_ioc_strings.txt`) "
            "and run static triage to uncover the RFC-5737 C2 simulation IP."
        ),
        prompt_question="What is the primary C2_SIMULATION_IP embedded in `trigger_ioc_strings.txt`?",
        hint="Run: genvirus analyze artifacts_out/lab/trigger_ioc_strings.txt",
        accepted_answers=("198.51.100.42",),
        specimen_hint_path="artifacts_out/lab/trigger_ioc_strings.txt",
    ),
    Challenge(
        id="c4",
        title="Ghost in the Sandbox (Telemetry)",
        difficulty="Advanced",
        description=(
            "Run `genvirus simulate --dry-run` and inspect the MITRE ATT&CK technique IDs "
            "used for the mock `.desktop` autostart persistence simulation."
        ),
        prompt_question="Which MITRE ATT&CK Technique ID corresponds to Boot or Logon Autostart Execution?",
        hint="Check the technique table in `genvirus simulate --dry-run`.",
        accepted_answers=("T1547", "t1547"),
        specimen_hint_path="artifacts_out/telemetry_events_*.jsonl",
    ),
]


def prepare_lab_specimens(lab_dir: str | Path = "artifacts_out/lab") -> list[Path]:
    """Ensure dynamic lab specimens (c2, c3) exist on disk for hands-on solving."""
    out_dir = Path(lab_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    c2_path = out_dir / "c2_matryoshka.sh"
    if not c2_path.exists():
        generate_obfuscated_specimen(
            payload_message="Beacon=http://203.0.113.99/api | FLAG{matryoshka_beacon_203.0.113.99}",
            layers=["zlib", "hex", "base32", "base64"],
            output_path=c2_path,
        )
    created.append(c2_path)

    c3_path = out_dir / "trigger_ioc_strings.txt"
    if not c3_path.exists():
        generate_trigger_specimen(profile="ioc-strings", output_dir=out_dir)
    created.append(c3_path)

    return created


def get_challenge(challenge_id: str) -> Challenge | None:
    """Look up a challenge by its ID (case-insensitive)."""
    cid = challenge_id.strip().lower()
    for ch in CHALLENGES:
        if ch.id == cid:
            return ch
    return None


def verify_answer(challenge_id: str, user_answer: str) -> tuple[bool, Challenge]:
    """Verify a user's answer against accepted answers."""
    ch = get_challenge(challenge_id)
    if not ch:
        raise ValueError(f"Unknown challenge ID '{challenge_id}'. Valid IDs: {[c.id for c in CHALLENGES]}")
    normalized = user_answer.strip()
    ok = normalized in ch.accepted_answers or normalized.lower() in {a.lower() for a in ch.accepted_answers}
    return ok, ch
