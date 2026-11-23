#!/usr/bin/env bash
# GenVirus v2.0 (Reborn) — Smart Launcher & Bootstrapper
# Preserves backward compatibility for `bash GenVirus.sh` on Linux, macOS, and Termux.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required for GenVirus v2.0 Reborn." >&2
    exit 1
fi

# Prefer existing virtualenv or create one automatically if venv module is available
if [[ -x "${VENV_DIR}/bin/python" ]]; then
    PY_BIN="${VENV_DIR}/bin/python"
elif python3 -c "import rich, typer" >/dev/null 2>&1; then
    PY_BIN="python3"
else
    echo "[*] Setting up isolated Python virtual environment in .venv..."
    if python3 -m venv "${VENV_DIR}" >/dev/null 2>&1; then
        "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
        "${VENV_DIR}/bin/pip" install --quiet -e "${SCRIPT_DIR}"
        PY_BIN="${VENV_DIR}/bin/python"
    else
        echo "[*] Installing dependencies into user site-packages..."
        python3 -m pip install --user --quiet -e "${SCRIPT_DIR}"
        PY_BIN="python3"
    fi
fi

export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PY_BIN}" -m genvirus "$@"
