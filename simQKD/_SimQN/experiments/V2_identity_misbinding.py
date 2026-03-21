"""
V2: Identity Misbinding - SimQN

Runs Scenario B (EB-QKD with active Charlie) to demonstrate the V2 attack.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.experiment_utils import (
    SYMBOL_UNAUTH_CHAN, SYMBOL_UNSUPPORTED, print_result_verdict,
    print_experiment_header,
)

try:
    from qns.models.qubit.qubit import Qubit
    SIMQN_AVAILABLE = True
except ImportError:
    SIMQN_AVAILABLE = False

from scenarios.scenario_B_eb_charlie_active import (
    run_honest_eb_qkd, run_charlie_misbinding_attack,
)

NUM_ROUNDS = 200


def main():
    print_experiment_header("V2: Identity Misbinding (MitM)", "SimQN")

    results = {
        "vulnerability": "V2",
        "tool": "SimQN",
        "attack": "Identity Misbinding (MitM)",
        "attack_successful": False,
        "mac_available": False,
        "mac_added_manually": True,
        "notes": [],
    }

    if not SIMQN_AVAILABLE:
        results["notes"].append("SimQN (qns) is not installed.")
        print_result_verdict(results, 2, "SimQN", symbol=SYMBOL_UNSUPPORTED)
        return

    # Test 1: Honest baseline
    print("\n--- Test 1: Honest EB-QKD baseline ---")
    honest = run_honest_eb_qkd(NUM_ROUNDS)
    print(f"Honest match rate: {honest['match_rate']:.4f} "
          f"(sifted key length: {honest['sifted_length']})")

    # Test 2: MAC check
    print("\n--- Test 2: MAC availability check ---")
    results["mac_available"] = False
    results["notes"].append(
        "SimQN has no built-in MAC or authentication on classical channels. "
        "MAC added manually via shared.experiment_utils (HMAC-SHA256)."
    )
    print("Built-in MAC/auth: NO")
    print("Manual MAC added for V2: YES")

    # Test 3: Full V2 attack (via Scenario B)
    print("\n--- Test 3: V2 attack (blind relay + MAC swap via Scenario B) ---")
    attack = run_charlie_misbinding_attack(NUM_ROUNDS)
    results["mac_swap_success"] = attack["mac_swap_success"]
    results["blind_relay_match_rate"] = attack["match_rate"]
    results["identity_misbinding"] = attack["identity_misbinding"]

    print(f"Charlie blind-relays qubits (QBER ~ 0): match rate = {attack['match_rate']:.4f}")
    print(f"MAC tag swap success: {attack['mac_swap_success']}")
    print(f"Alice binds key to: {attack['alice_binds_to']}")
    print(f"Bob binds key to: {attack['bob_binds_to']}")
    print(f"Identity misbinding: {attack['identity_misbinding']}")

    if attack["identity_misbinding"]:
        results["attack_successful"] = True
        results["notes"].append(
            "V2 succeeds: Charlie blind-relays qubits (QBER ~ 0), swaps MAC "
            "tags between PSK_AC and PSK_CB sessions. Alice and Bob derive "
            "matching key but bind it to Charlie's identity."
        )

    # Summary
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                        SimQN")
    print(f"Vulnerability:               V2 - Identity Misbinding")
    print(f"Scenario:                    B (EB + Charlie active)")
    print(f"Built-in MAC:                {results['mac_available']}")
    print(f"MAC Swap Success:            {results.get('mac_swap_success')}")
    print(f"Blind Relay Match Rate:      {results.get('blind_relay_match_rate')}")
    print(f"Identity Misbinding:         {results.get('identity_misbinding')}")
    print(f"Attack Successful:           {results['attack_successful']}")

    symbol = SYMBOL_UNAUTH_CHAN if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 2, "SimQN", symbol=symbol)


if __name__ == '__main__':
    main()
