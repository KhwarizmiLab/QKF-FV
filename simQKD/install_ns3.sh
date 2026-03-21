#!/usr/bin/env bash
# Set up ns-3 with QKDNetSim for simQKD experiments.
#
# Clones ns-3.46, installs the bundled QKDNetSim module from _QKDNetSim/QKDNetSim,
# builds ns-3, and configures QKDNETSIM_NS3_DIR for this repo.
#
# Usage:
#   ./install_ns3.sh [ns-3-install-dir]
#   ./install_ns3.sh                    # uses ./ns-3-dev by default
#   ./install_ns3.sh /opt/ns-3-dev      # custom path
#
# After running, ensure QKDNETSIM_NS3_DIR is set (script appends to .env if present).
# Run: export QKDNETSIM_NS3_DIR="$(pwd)/ns-3-dev"  # or your chosen path

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="${1:-${PROJECT_ROOT}/ns-3-dev}"
QKDNETSIM_SRC="${PROJECT_ROOT}/_QKDNetSim/QKDNetSim"

cd "$PROJECT_ROOT"

if [[ ! -d "$QKDNETSIM_SRC" ]]; then
  echo "ERROR: QKDNetSim source not found at ${QKDNETSIM_SRC}" >&2
  exit 1
fi

echo "=== ns-3 + QKDNetSim setup ==="
echo "Install directory: ${NS3_DIR}"
echo ""

# Prerequisites check
echo "Checking prerequisites..."
MISSING=""
for pkg in gcc g++ python3 git cmake; do
  if ! command -v "$pkg" &>/dev/null; then
    MISSING="${MISSING} ${pkg}"
  fi
done

for lib in libcrypto++-dev uuid-dev; do
  if ! pkg-config --exists libcrypto++ 2>/dev/null && ! [[ -f /usr/include/cryptopp/cryptlib.h ]]; then
    if [[ "$lib" == "libcrypto++-dev" ]]; then
      MISSING="${MISSING} libcrypto++-dev"
    fi
  fi
done

if [[ -n "$MISSING" ]]; then
  echo "WARN: Some prerequisites may be missing. On Debian/Ubuntu/Arch, install:"
  echo "  Debian/Ubuntu: sudo apt-get install gcc g++ python3 python3-dev git cmake libcrypto++-dev uuid-dev libboost-all-dev flex bison libxml2-dev libsqlite3-dev"
  echo "  Arch:          sudo pacman -S base-devel python git cmake crypto++ util-linux boost"
  echo ""
  read -r -p "Continue anyway? [y/N] " r
  [[ "${r,,}" == "y" ]] || exit 1
fi

# Clone ns-3 if needed
if [[ ! -d "${NS3_DIR}" ]]; then
  echo "Cloning ns-3.46..."
  git clone -b ns-3.46 --depth 1 https://gitlab.com/nsnam/ns-3-dev.git "${NS3_DIR}"
else
  echo "Using existing ns-3 at ${NS3_DIR}"
fi

# Install QKDNetSim into contrib
CONTRIB="${NS3_DIR}/contrib"
QKDNETSIM_CONTRIB="${CONTRIB}/qkdnetsim"
mkdir -p "${CONTRIB}"

if [[ -L "${QKDNETSIM_CONTRIB}" ]]; then
  rm "${QKDNETSIM_CONTRIB}"
fi
if [[ -d "${QKDNETSIM_CONTRIB}" ]]; then
  echo "Removing existing ${QKDNETSIM_CONTRIB}"
  rm -rf "${QKDNETSIM_CONTRIB}"
fi

echo "Linking QKDNetSim from repo into ns-3 contrib..."
ln -s "$QKDNETSIM_SRC" "${QKDNETSIM_CONTRIB}"

# Apply patches
cd "${NS3_DIR}"
for patch in gnuplot_cc.patches gnuplot_h.patches; do
  P="${QKDNETSIM_CONTRIB}/patches/${patch}"
  if [[ -f "$P" ]]; then
    if git apply --check "$P" 2>/dev/null; then
      echo "Applying ${patch}..."
      git apply "$P"
    else
      echo "Skipping ${patch} (already applied or not applicable)"
    fi
  fi
done

# Configure and build
echo "Configuring ns-3..."
./ns3 configure --enable-examples

echo "Building ns-3 (this may take several minutes)..."
./ns3 build

# Write .env so run_all_experiments.sh picks up QKDNETSIM_NS3_DIR
ENV_FILE="${PROJECT_ROOT}/.env"
if ! grep -q "QKDNETSIM_NS3_DIR" "$ENV_FILE" 2>/dev/null; then
  {
    [[ -f "$ENV_FILE" ]] && echo ""
    echo "# ns-3 + QKDNetSim (added by install_ns3.sh)"
    echo "export QKDNETSIM_NS3_DIR=\"${NS3_DIR}\""
  } >> "$ENV_FILE"
  echo "Wrote QKDNETSIM_NS3_DIR to ${ENV_FILE}"
fi

echo ""
echo "=== Done ==="
echo "ns-3 with QKDNetSim is ready at: ${NS3_DIR}"
echo ""
echo "To enable QKDNetSim experiments, set QKDNETSIM_NS3_DIR:"
echo "  export QKDNETSIM_NS3_DIR=\"${NS3_DIR}\""
echo ""
echo "Or run with: QKDNETSIM_NS3_DIR=\"${NS3_DIR}\" ./run_all_experiments.sh"
