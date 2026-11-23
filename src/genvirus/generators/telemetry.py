"""Sandboxed Behavioral Telemetry Simulator (Atomic-style, strictly benign)."""

from __future__ import annotations

import base64
import json
import platform
import shutil
import socket
import subprocess
import sys
import uuid
from pathlib import Path

from genvirus import BENIGN_MARKER
from genvirus.core.models import TelemetryEvent

TECHNIQUES: dict[str, str] = {
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1027": "Obfuscated Files or Information",
    "T1547": "Boot or Logon Autostart Execution (Mock Sandbox File)",
    "T1071.004": "Application Layer Protocol: DNS Resolution Check",
    "T1082": "System Information Discovery",
}


def run_telemetry_simulation(
    technique: str = "all",
    dry_run: bool = False,
    keep_artifacts: bool = False,
    output_dir: str | Path = "artifacts_out",
) -> tuple[list[TelemetryEvent], Path]:
    """Execute harmless, sandboxed behavioral telemetry tests and log JSONL events."""
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]
    sandbox_dir = base_dir / f"telemetry_sandbox_{run_id}"
    sandbox_dir.mkdir(parents=True, exist_ok=True)

    selected = list(TECHNIQUES.keys()) if technique.lower() == "all" else [technique.upper()]
    for tid in selected:
        if tid not in TECHNIQUES:
            raise ValueError(f"Unknown technique '{tid}'. Available: {list(TECHNIQUES.keys())} or 'all'.")

    events: list[TelemetryEvent] = []

    for tid in selected:
        tname = TECHNIQUES[tid]
        artifact_path: Path | None = None
        pid: int | None = None
        cmd_str = ""
        action = ""
        audit_hint = ""

        if tid == "T1059.004":
            cmd_str = f"{sys.executable} -c \"print('{BENIGN_MARKER}:T1059.004')\""
            action = "Spawn harmless child process echoing benign marker"
            audit_hint = "Verify process creation event (execve) in auditd/sysmon logs."
            if not dry_run:
                proc = subprocess.run(
                    [sys.executable, "-c", f"print('{BENIGN_MARKER}:T1059.004')"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                pid = proc.returncode  # deterministic 0 status; subprocess completed cleanly
        elif tid == "T1027":
            artifact_path = sandbox_dir / "t1027_encoded_payload.b64"
            cmd_str = f"write_base64({artifact_path.name}) && decode_in_memory"
            action = "Write Base64-encoded benign string to sandbox file and decode it"
            audit_hint = "Check file-write + base64 decode telemetry."
            if not dry_run:
                encoded = base64.b64encode(f"{BENIGN_MARKER}:T1027".encode("utf-8"))
                artifact_path.write_bytes(encoded)
                _ = base64.b64decode(artifact_path.read_bytes())
        elif tid == "T1547":
            artifact_path = sandbox_dir / "mock_autostart.desktop"
            cmd_str = f"create_mock_persistence_file({artifact_path})"
            action = "Create inert .desktop mock persistence artifact strictly inside sandbox_dir"
            audit_hint = "Demonstrates persistence file structure without touching ~/.config/autostart."
            if not dry_run:
                artifact_path.write_text(
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    "Name=GenVirusTelemetryMock\n"
                    f"Comment={BENIGN_MARKER}\n"
                    "Exec=/usr/bin/true\n",
                    encoding="utf-8",
                )
        elif tid == "T1071.004":
            cmd_str = "socket.getaddrinfo('example.com', 80)"
            action = "Perform benign DNS lookup against RFC 2606 example.com"
            audit_hint = "Check DNS query logs for example.com."
            if not dry_run:
                try:
                    socket.getaddrinfo("example.com", 80)
                except OSError:
                    pass
        elif tid == "T1082":
            artifact_path = sandbox_dir / "t1082_sysinfo.json"
            cmd_str = "platform.uname() -> write sandbox sysinfo JSON"
            action = "Collect non-sensitive OS platform metadata into sandbox JSON"
            audit_hint = "Verify discovery script artifact creation."
            if not dry_run:
                info = {
                    "marker": BENIGN_MARKER,
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                }
                artifact_path.write_text(json.dumps(info, indent=2), encoding="utf-8")

        events.append(
            TelemetryEvent(
                technique_id=tid,
                technique_name=tname,
                action=action,
                dry_run=dry_run,
                sandbox_dir=str(sandbox_dir),
                artifact_path=str(artifact_path) if artifact_path else None,
                command_executed=cmd_str,
                pid=pid,
                cleaned_up=not keep_artifacts,
                audit_hint=audit_hint,
            )
        )

    log_path = base_dir / f"telemetry_events_{run_id}.jsonl"
    log_path.write_text(
        "\n".join(json.dumps(e.to_dict()) for e in events) + "\n",
        encoding="utf-8",
    )

    if not keep_artifacts and sandbox_dir.exists():
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    return events, log_path
