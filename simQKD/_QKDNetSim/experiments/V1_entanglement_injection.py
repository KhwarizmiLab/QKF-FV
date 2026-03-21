"""
V1: Subverted Entanglement Injection - QKDNetSim

Tests whether QKDNetSim can model entanglement injection attacks; it cannot.

QKDNetSim operates at the KMS layer and has no quantum-level simulation.
V1 requires controlling an entangled source and performing qubit-level
operations (Bell pair creation, deferred measurement), which are not
available in QKDNetSim.

RESULT: NOT FEASIBLE (*)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.experiment_utils import (
    SYMBOL_UNSUPPORTED, print_result_verdict, print_experiment_header,
)
from scenarios.scenario_kms_auth_relay import get_capability_summary


def main():
    print_experiment_header("V1: Subverted Entanglement Injection", "QKDNetSim")

    results = {
        "vulnerability": "V1",
        "tool": "QKDNetSim",
        "attack": "Subverted Entanglement Injection",
        "attack_successful": False,
        "notes": [],
    }

    caps = get_capability_summary()

    print("\n--- Capability Assessment ---")
    print(f"Quantum layer: {caps['quantum_layer']}")
    print(f"KMS layer: {caps['kms_layer']}")
    print(f"ns-3 available: {caps['ns3_available']}")

    results["notes"] = [
        "QKDNetSim models KMS/key relay, not qubit transmission.",
        "V1 requires: entangled source control, Bell pair creation, "
        "quantum memory, deferred measurement.",
        "None of these quantum operations are available in QKDNetSim.",
        "V1 CANNOT be replicated with this tool.",
    ]

    for note in results["notes"]:
        print(f"  - {note}")

    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:              QKDNetSim")
    print(f"Vulnerability:     V1 - Subverted Entanglement Injection")
    print(f"Attack Successful: {results['attack_successful']}")

    print_result_verdict(results, 1, "QKDNetSim", symbol=SYMBOL_UNSUPPORTED)


if __name__ == '__main__':
    main()
