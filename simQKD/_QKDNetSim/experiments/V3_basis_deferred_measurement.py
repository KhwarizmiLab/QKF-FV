"""
V3: Basis-Deferred Measurement - QKDNetSim

Tests whether QKDNetSim can model deferred measurement attacks; it cannot.

QKDNetSim operates at the KMS layer and has no quantum-level simulation.
V3 requires qubit interception, quantum memory, and deferred measurement,
which are not available in QKDNetSim.

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
    print_experiment_header("V3: Basis-Deferred Measurement", "QKDNetSim")

    results = {
        "vulnerability": "V3",
        "tool": "QKDNetSim",
        "attack": "Basis-Deferred Measurement",
        "attack_successful": False,
        "notes": [],
    }

    caps = get_capability_summary()

    print("\n--- Capability Assessment ---")
    print(f"Quantum layer: {caps['quantum_layer']}")
    print(f"KMS layer: {caps['kms_layer']}")

    results["notes"] = [
        "QKDNetSim models KMS/key relay, not qubit transmission.",
        "V3 requires: qubit interception, quantum memory for storage, "
        "deferred measurement in announced basis.",
        "None of these quantum operations are available in QKDNetSim.",
        "V3 CANNOT be replicated with this tool.",
    ]

    for note in results["notes"]:
        print(f"  - {note}")

    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:              QKDNetSim")
    print(f"Vulnerability:     V3 - Basis-Deferred Measurement")
    print(f"Attack Successful: {results['attack_successful']}")

    print_result_verdict(results, 3, "QKDNetSim", symbol=SYMBOL_UNSUPPORTED)


if __name__ == '__main__':
    main()
