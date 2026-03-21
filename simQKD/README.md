# simQKD: QKD vulnerability replication experiments

Experimental replication of four vulnerabilities identified through formal analysis of QKD standards and specifications. Each vulnerability targets the hybrid QKD protocol (quantum phase + classical phase) and is reproduced across four quantum network simulation tools.

## Vulnerabilities

| ID | Name | Protocol | Attack vector |
|----|------|----------|---------------|
| V1 | Entanglement injection | EB-QKD | Eve controls entangled source, defers measurement until basis announcement |
| V2 | Identity misbinding | EB-QKD | MitM blind-relays qubits, swaps MAC tags on classical messages |
| V3 | Basis-deferred measurement | PM-QKD | Eve stores qubits, reads early basis announcement, measures in correct basis |
| V4 | Message reflection | PM-QKD | Attacker reflects Bob's own MAC-authenticated message back to him |

Full descriptions are in `vulnerabilities/V1.md` through `V4.md`.

## Simulation tools

| Tool | Language | Scope |
|------|----------|-------|
| SimQN | Python | Network-layer simulator with routing and multi-hop QKD |
| SeQUeNCe | Python | Discrete-event simulator for hardware and network layers |
| Quditto | Python (NetSquid) | Digital twin platform conforming to ETSI QKD 014 REST APIs |
| QKDNetSim | C++ (ns-3) | KMS-layer simulator with ETSI QKD 004/014 interfaces |

## Prerequisites

- Python 3.11+ (3.11 recommended for full compatibility)
- Linux (tested on Ubuntu, Fedora, Arch)

Platform-specific install:
```bash
# Ubuntu/Debian
sudo apt install python3.11 python3.11-venv

# Fedora
sudo dnf install python3.11

# Arch
sudo pacman -S python311
```

## Setup

```bash
# Create virtual environment and install SimQN + SeQUeNCe
./setup_venv.sh

# Include NetSquid (required for Quditto experiments only)
# Register at https://forum.netsquid.org/ucp.php?mode=register
./setup_venv.sh YOUR_USERNAME YOUR_PASSWORD

# Or install from a local wheel
./setup_venv.sh --netsquid-wheel path/to/netsquid.whl

# Activate the environment
source .venv/bin/activate
```

If Python 3.11 is installed in a non-default location:
```bash
PY311_BIN=/path/to/python3.11 ./setup_venv.sh
```

**QKDNetSim (ns-3):** Requires a separate ns-3 build. Run the install script:

```bash
./install_ns3.sh
```

This clones ns-3.46, links the bundled QKDNetSim module, builds ns-3, and appends `QKDNETSIM_NS3_DIR` to `.env` (if present). Alternatively, set the variable manually:

```bash
export QKDNETSIM_NS3_DIR=/path/to/ns-3-dev
```

`run_all_experiments.sh` loads `.env` automatically, so `ns-3 available: True` will appear once the path is set.

## Running experiments

```bash
source .venv/bin/activate

# Run all experiments
./run_all_experiments.sh

# Filter by tool
./run_all_experiments.sh --tool SimQN
./run_all_experiments.sh --tool SeQUeNCe
./run_all_experiments.sh --tool Quditto

# Filter by vulnerability
./run_all_experiments.sh --vuln 1

# Include QKDNetSim (requires ns-3 build)
QKDNETSIM_NS3_DIR=/path/to/ns-3-dev ./run_all_experiments.sh

# Generate LaTeX evaluation table for the paper
python generate_latex_table.py
python generate_latex_table.py --cached    # reuse last run
python generate_latex_table.py -o results/eval_table.tex
```

Logs are written to `results/run_YYYYMMDD_HHMMSS.log`.

## Repository structure

```
_SimQN/
  experiments/    V1-V4 attack scripts (Python)
  scenarios/      Reusable topology and protocol runners
_SeQUeNCe/
  experiments/    V1-V4 attack scripts (Python)
  scenarios/      Reusable topology and protocol runners
_Quditto/
  experiments/    V1-V4 attack scripts (Python, requires NetSquid)
  scenarios/      PM-QKD scenarios only (no EB-QKD support in Quditto)
_QKDNetSim/
  experiments/    V1-V4 attack scripts (Python, KMS-layer analogues)
  scenarios/      KMS authentication and relay testing
  QKDNetSim/      Upstream QKDNetSim source (ns-3 module)
shared/           MAC helpers, result formatting, match rate computation
vulnerabilities/  Formal vulnerability definitions (V1-V4)
```

## Result symbols

| Symbol | Meaning |
|--------|---------|
| `checkmark` | Vulnerability replicated with the tool's native APIs |
| `*` | Tool lacks quantum-layer support for this attack |
| `-` | Vulnerability replicated; tool has no built-in MAC (manual MAC used) |
