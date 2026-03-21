#!/usr/bin/env bash
# Create or update the workspace virtual environment for all Python tools.
#
# Usage:
#   ./setup_venv.sh
#   ./setup_venv.sh NETSQUID_USERNAME NETSQUID_PASSWORD
#   ./setup_venv.sh --netsquid-wheel path/to/netsquid-*.whl

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Load .env for credentials if present (keeps username/password out of CLI history)
if [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
fi

NETSQUID_WHEEL=""
NETSQUID_USER=""
NETSQUID_PASS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --netsquid-wheel)
      NETSQUID_WHEEL="${2:?Missing wheel path after --netsquid-wheel}"
      shift 2
      ;;
    *)
      [[ -z "${NETSQUID_USER:-}" ]] && NETSQUID_USER="$1" || NETSQUID_PASS="$1"
      shift
      ;;
  esac
done

# Fall back to .env credentials when not passed as args
NETSQUID_USER="${NETSQUID_USER:-${NETSQUID_USERNAME:-}}"
NETSQUID_PASS="${NETSQUID_PASS:-${NETSQUID_PASSWORD:-}}"

# Prefer Python 3.11 for full compatibility; fall back to 3.12, 3.13, then python3
if [[ -n "${PY311_BIN:-}" ]] && [[ -x "${PY311_BIN}" ]]; then
  :
elif command -v python3.11 >/dev/null 2>&1; then
  PY311_BIN="$(command -v python3.11)"
elif command -v python311 >/dev/null 2>&1; then
  PY311_BIN="$(command -v python311)"
elif command -v python3.12 >/dev/null 2>&1; then
  PY311_BIN="$(command -v python3.12)"
  echo "WARN: Python 3.11 not found; using Python 3.12. SeQUeNCe and NetSquid may have limited support."
elif command -v python3.13 >/dev/null 2>&1; then
  PY311_BIN="$(command -v python3.13)"
  echo "WARN: Python 3.11/3.12 not found; using Python 3.13. Some tools may have limited support."
elif [[ -x "$HOME/.local/share/uv/python/cpython-3.11-linux-x86_64-gnu/bin/python3.11" ]]; then
  PY311_BIN="$HOME/.local/share/uv/python/cpython-3.11-linux-x86_64-gnu/bin/python3.11"
  echo "INFO: Using uv-managed Python 3.11 at ${PY311_BIN}."
elif command -v python3 >/dev/null 2>&1; then
  PY311_BIN="$(command -v python3)"
  echo "WARN: Python 3.11-3.13 not found; using $(python3 --version). SeQUeNCe requires <3.14; some tools may fail."
else
  echo "ERROR: No suitable Python found. Python 3.11-3.13 recommended." >&2
  echo "Install Python 3.11 and rerun: sudo pacman -S python311  # Arch" >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  "$PY311_BIN" -m venv .venv
fi

VENV_PY="${PROJECT_ROOT}/.venv/bin/python"
NETSQUID_VENV_PY="${PROJECT_ROOT}/.venv_netsquid/bin/python"

if [[ ! -x "$VENV_PY" ]]; then
  echo "ERROR: ${VENV_PY} was not created correctly." >&2
  exit 1
fi

VENV_PY_VERSION="$($VENV_PY -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

"$VENV_PY" -m pip install --upgrade pip setuptools wheel

# SimQN: network-layer QKD simulator (pip-installable).
"$VENV_PY" -m pip install "qns"

# SeQUeNCe: discrete-event quantum network simulator (requires <3.14 on PyPI).
"$VENV_PY" -m pip install "sequence" || {
  echo "WARN: SeQUeNCe install failed (may require Python <3.14). Continuing." >&2
}

# Optional: install NetSquid (required for Quditto experiments).
if [[ -n "$NETSQUID_WHEEL" && -f "$NETSQUID_WHEEL" ]]; then
  if [[ ! -d .venv_netsquid ]]; then
    "$PY311_BIN" -m venv .venv_netsquid
  fi
  "$NETSQUID_VENV_PY" -m pip install --upgrade pip setuptools wheel
  "$NETSQUID_VENV_PY" -m pip install "numpy==1.24.4" "scipy==1.9.3" "pandas<2" "cysignals"
  "$NETSQUID_VENV_PY" -m pip install --no-deps "$NETSQUID_WHEEL"
  INSTALLED_NETSQUID=1
elif [[ -n "${NETSQUID_USER:-}" && -n "${NETSQUID_PASS:-}" ]]; then
  if [[ ! -d .venv_netsquid ]]; then
    "$PY311_BIN" -m venv .venv_netsquid
  fi
  "$NETSQUID_VENV_PY" -m pip install --upgrade pip setuptools wheel
  "$NETSQUID_VENV_PY" -m pip install "numpy==1.24.4" "scipy==1.9.3" "pandas<2" "cysignals"
  "$NETSQUID_VENV_PY" -m pip install \
    --extra-index-url "https://${NETSQUID_USER}:${NETSQUID_PASS}@pypi.netsquid.org" \
    "pydynaa==1.0.2"
  "$NETSQUID_VENV_PY" -m pip install \
    --no-deps \
    --extra-index-url "https://${NETSQUID_USER}:${NETSQUID_PASS}@pypi.netsquid.org" \
    "netsquid"
  INSTALLED_NETSQUID=1
else
  echo "INFO: NetSquid skipped (provide username/password or --netsquid-wheel to install)."
  echo "      NetSquid is required for Quditto experiments only."
  INSTALLED_NETSQUID=0
fi

echo ""
echo "--- Installed tool verification ---"
"$VENV_PY" -c "import qns; print('SimQN (qns):', qns.__name__)"
"$VENV_PY" -c "import sequence; print('SeQUeNCe (sequence):', sequence.__name__)" 2>/dev/null || echo "WARN: SeQUeNCe import check skipped"

if [[ "$INSTALLED_NETSQUID" -eq 1 ]]; then
  "$NETSQUID_VENV_PY" -c "import netsquid as ns; print('NetSquid:', getattr(ns, 'version', ns.__version__))"
fi

echo ""
echo "Single environment ready: ${PROJECT_ROOT}/.venv (Python ${VENV_PY_VERSION})"
if [[ "$INSTALLED_NETSQUID" -eq 1 ]]; then
  echo "NetSquid environment ready: ${PROJECT_ROOT}/.venv_netsquid"
fi
echo "Activate with: source .venv/bin/activate"
