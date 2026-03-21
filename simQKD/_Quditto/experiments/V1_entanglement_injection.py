"""
V1: Subverted Entanglement Injection - Quditto

Reports that V1 is not feasible because Quditto supports only PM-QKD (BB84).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.experiment_utils import (
    SYMBOL_UNSUPPORTED, print_result_verdict, print_experiment_header,
)

try:
    import netsquid as ns
    NETSQUID_AVAILABLE = True
except ImportError:
    NETSQUID_AVAILABLE = False

NUM_ROUNDS = 200


def main():
    print_experiment_header("V1: Subverted Entanglement Injection", "Quditto")

    results = {
        "vulnerability": "V1",
        "tool": "Quditto",
        "attack": "Subverted Entanglement Injection",
        "attack_successful": False,
        "notes": [],
    }

    print("\n--- Capability Assessment ---")
    print(f"NetSquid available: {NETSQUID_AVAILABLE}")
    print(f"Quditto protocol: PM-QKD (BB84) only")
    print(f"EB-QKD protocol (E91/BBM92): NOT SUPPORTED")

    results["notes"] = [
        "Quditto runs PM-QKD (BB84) on NetSquid, not EB-QKD.",
        "V1 requires: entangled source control, Bell pair creation, "
        "quantum memory with deferred measurement in an EB protocol context.",
        "Quditto has no E91 or BBM92 protocol.",
        "NetSquid supports entanglement primitives, but Quditto's protocol "
        "stack (KeySenderProtocol / KeyReceiverProtocol) is purely prepare-and-measure.",
        "V1 CANNOT be replicated with this tool.",
    ]

    for note in results["notes"]:
        print(f"  - {note}")

    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:              Quditto (NetSquid-based)")
    print(f"Vulnerability:     V1 - Subverted Entanglement Injection")
    print(f"Protocol:          PM-QKD (BB84) only; no EB-QKD")
    print(f"Attack Successful: {results['attack_successful']}")

    print_result_verdict(results, 1, "Quditto", symbol=SYMBOL_UNSUPPORTED)


if __name__ == '__main__':
    main()
