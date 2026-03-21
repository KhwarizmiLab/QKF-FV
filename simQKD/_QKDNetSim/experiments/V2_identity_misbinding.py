"""
V2: Identity Misbinding - QKDNetSim

Tests KMS-layer authentication manipulation as a V2 analogue.

QKDNetSim has no quantum layer, but V2's classical authentication
manipulation (MAC tag swapping) can be tested at the KMS layer.
We use the KMS relay misbinding scenario as an analogue.

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
    simulate_kms_relay_misbinding, get_capability_summary,
)


def main():
    print_experiment_header("V2: Identity Misbinding", "QKDNetSim")

    results = {
        "vulnerability": "V2",
        "tool": "QKDNetSim",
        "attack": "Identity Misbinding (KMS-layer analogue)",
        "attack_successful": False,
        "notes": [],
    }

    caps = get_capability_summary()
    print("\n--- Capability Assessment ---")
    print(f"Quantum layer: {caps['quantum_layer']} (blind qubit relay not possible)")
    print(f"KMS layer: {caps['kms_layer']}")
    print(f"V2 KMS analogue feasible: {caps['kms_analogues']['V2_identity_misbinding']}")

    print("\n--- KMS Relay Misbinding Test ---")
    relay = simulate_kms_relay_misbinding()
    results["relay_success"] = relay["relay_success"]
    results["identity_misbinding"] = relay["identity_misbinding"]

    print(f"Relay verifies Alice: {relay['relay_verifies_alice']}")
    print(f"Bob verifies relay: {relay['bob_verifies_relay']}")
    print(f"Relay MAC swap success: {relay['relay_success']}")
    print(f"Bob binds key to: {relay['bob_binds_key_to']}")

    if relay["identity_misbinding"]:
        results["attack_successful"] = True
        results["notes"] = relay["notes"]

    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                    QKDNetSim")
    print(f"Vulnerability:           V2 - Identity Misbinding (KMS analogue)")
    print(f"KMS Relay Misbinding:    {results.get('identity_misbinding')}")
    print(f"Attack Successful:       {results['attack_successful']}")
    print(f"Note: KMS-layer only; no quantum blind relay tested")

    from shared.experiment_utils import SYMBOL_SUCCESS
    symbol = SYMBOL_SUCCESS if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 2, "QKDNetSim", symbol=symbol)


if __name__ == '__main__':
    main()
