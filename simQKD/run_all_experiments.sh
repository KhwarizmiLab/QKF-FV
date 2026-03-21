#!/usr/bin/env bash
# Run all QKD vulnerability experiments.
# Discovers and executes Python experiment scripts in _*/experiments/
# Usage: ./run_all_experiments.sh [--tool NAME] [--vuln N]

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Load .env if present (for QKDNETSIM_NS3_DIR, NETSQUID_USER, etc.)
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "${PROJECT_ROOT}/.env"
  set +a
fi

VENV_PY="${PROJECT_ROOT}/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  echo "ERROR: .venv not found. Run ./setup_venv.sh first." >&2
  exit 1
fi
NETSQUID_PY="${PROJECT_ROOT}/.venv_netsquid/bin/python"

VENV_PY_VERSION="$($VENV_PY -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
VENV_PY_MAJOR="$($VENV_PY -c 'import sys; print(sys.version_info.major)')"
VENV_PY_MINOR="$($VENV_PY -c 'import sys; print(sys.version_info.minor)')"
if [[ "$VENV_PY_MAJOR" != "3" ]] || [[ "$VENV_PY_MINOR" -lt 11 ]]; then
  echo "ERROR: .venv uses Python ${VENV_PY_VERSION}, expected 3.11 or higher." >&2
  echo "Recreate it with: rm -rf .venv && ./setup_venv.sh" >&2
  exit 1
fi
if [[ "$VENV_PY_VERSION" != "3.11" ]]; then
  echo "WARN: .venv uses Python ${VENV_PY_VERSION}; 3.11 is recommended for compatibility." >&2
fi

RESULTS_DIR="${PROJECT_ROOT}/results"
FILTER_TOOL=""
FILTER_VULN=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --tool|-t)
      FILTER_TOOL="${2:?Usage: $0 --tool NAME}"
      shift 2
      ;;
    --vuln|-v)
      FILTER_VULN="${2:?Usage: $0 --vuln N}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${RESULTS_DIR}/run_${TIMESTAMP}.log"

# Skip Quditto if NetSquid is not installed
NETSQUID_AVAILABLE=0
if [[ -x "$NETSQUID_PY" ]]; then
  "$NETSQUID_PY" -c "import netsquid" 2>/dev/null && NETSQUID_AVAILABLE=1
fi
if [[ "$NETSQUID_AVAILABLE" -eq 0 ]]; then
  echo "INFO: NetSquid not installed; skipping Quditto experiments." | tee -a "$LOG_FILE"
  echo "      To include Quditto: ./setup_venv.sh USERNAME PASSWORD" | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"
fi

echo "========================================"
echo "QKD Vulnerability Experiment Runner"
echo "========================================"
echo "Log: $LOG_FILE"
echo ""

# Discover and run Python experiments: _ToolName/experiments/V{n}_*.py
for exp in _*/experiments/V*.py; do
  [[ -f "$exp" ]] || continue
  basename_exp=$(basename "$exp")
  tool_dir=$(dirname "$(dirname "$exp")")
  tool_name="${tool_dir#_}"

  # Apply filters
  [[ -n "$FILTER_TOOL" ]] && [[ "$tool_name" != *"$FILTER_TOOL"* ]] && continue
  vuln_num=$(echo "$basename_exp" | sed -n 's/^V\([0-9]\)_.*/\1/p')
  [[ -n "$FILTER_VULN" ]] && [[ "$vuln_num" != "$FILTER_VULN" ]] && continue

  # Skip Quditto when NetSquid is not installed
  [[ "$tool_name" == "Quditto" ]] && [[ "$NETSQUID_AVAILABLE" -eq 0 ]] && continue

  RUNNER_PY="$VENV_PY"
  if [[ "$tool_name" == "Quditto" ]]; then
    RUNNER_PY="$NETSQUID_PY"
  fi

  echo ">>> Running $exp ($tool_name)" | tee -a "$LOG_FILE"
  if "$RUNNER_PY" "$exp" 2>&1 | tee -a "$LOG_FILE"; then
    echo "[OK] $exp" >> "$LOG_FILE"
  else
    echo "[FAIL/ERROR] $exp" >> "$LOG_FILE"
  fi
  echo "" >> "$LOG_FILE"
  echo "---" >> "$LOG_FILE"
done

echo ""
echo "Run complete. Log saved to $LOG_FILE"
echo "" >> "$LOG_FILE"
echo "Legend:" >> "$LOG_FILE"
echo "  checkmark = Vulnerability replicated with tool's native APIs" >> "$LOG_FILE"
echo "  * = Tool lacks quantum-layer support for this attack" >> "$LOG_FILE"
echo "  - = Vulnerability replicated; tool has no built-in MAC (manual MAC used)" >> "$LOG_FILE"
