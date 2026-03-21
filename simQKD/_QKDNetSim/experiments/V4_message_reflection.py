"""
V4: Message Reflection - QKDNetSim

Tests KMS-layer message reflection as a V4 analogue.

QKDNetSim has no quantum layer, but V4's message reflection (MAC without
directionality) can be tested at the KMS key confirmation layer.

RESULT: KMS-LAYER ANALOGUE ONLY
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.experiment_utils import (
    SYMBOL_UNSUPPORTED, SYMBOL_UNAUTH_CHAN, print_result_verdict,
    print_experiment_header,
)
from scenarios.scenario_kms_auth_relay import (
    simulate_kms_message_reflection, get_capability_summary,
)


def main():
    print_experiment_header("V4: Message Reflection", "QKDNetSim")

    results = {
        "vulnerability": "V4",
        "tool": "QKDNetSim",
        "attack": "Message Reflection (KMS-layer analogue)",
        "attack_successful": False,
        "notes": [],
    }

    caps = get_capability_summary()
    print("\n--- Capability Assessment ---")
    print(f"Quantum layer: {caps['quantum_layer']} (qubit injection not possible)")
    print(f"KMS layer: {caps['kms_layer']}")
    print(f"V4 KMS analogue feasible: {caps['kms_analogues']['V4_message_reflection']}")

    print("\n--- KMS Message Reflection Test ---")
    reflection = simulate_kms_message_reflection()
    results["reflection_accepted"] = reflection["reflection_accepted"]
    results["directionality_binding"] = reflection["directionality_binding"]

    print(f"Bob accepts own reflected message: {reflection['bob_accepts_own_message']}")
    print(f"Directionality binding: {reflection['directionality_binding']}")

    if reflection["reflection_accepted"]:
        results["attack_successful"] = True
        results["notes"] = reflection["notes"]

    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                    QKDNetSim")
    print(f"Vulnerability:           V4 - Message Reflection (KMS analogue)")
    print(f"Reflection Accepted:     {results.get('reflection_accepted')}")
    print(f"Attack Successful:       {results['attack_successful']}")
    print(f"Note: KMS-layer only; no qubit injection tested")

    from shared.experiment_utils import SYMBOL_SUCCESS
    symbol = SYMBOL_SUCCESS if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 4, "QKDNetSim", symbol=symbol)


if __name__ == '__main__':
    main()
