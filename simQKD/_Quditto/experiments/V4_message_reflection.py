"""
V4: Message Reflection - Quditto

Demonstrates V4 via Scenario D (PM-QKD with active Charlie).
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
    import netsquid as ns
    NETSQUID_AVAILABLE = True
except ImportError:
    NETSQUID_AVAILABLE = False

from scenarios.scenario_D_pm_charlie_active import (
    run_honest_bb84_with_pe, run_message_reflection_attack,
)

NUM_ROUNDS = 200


def main():
    print_experiment_header("V4: Message Reflection", "Quditto")

    results = {
        "vulnerability": "V4",
        "tool": "Quditto",
        "attack": "Message Reflection",
        "attack_successful": False,
        "mac_available": False,
        "mac_added_manually": True,
        "directionality_binding": False,
        "notes": [],
    }

    # Test 1: MAC and authentication check
    print("\n--- Test 1: MAC and authentication check ---")
    print(f"NetSquid available: {NETSQUID_AVAILABLE}")
    results["notes"].append(
        "Quditto has no built-in MAC or authentication on classical channels. "
        "MAC added manually (HMAC-SHA256, no directionality)."
    )
    print("Built-in MAC/auth: NO")
    print("Manual MAC (HMAC-SHA256): YES")
    print("Directionality binding: NO")

    # Test 2: Honest BB84 with PE baseline (via Scenario D)
    print("\n--- Test 2: Honest BB84 with PE baseline (Scenario D) ---")
    honest = run_honest_bb84_with_pe(NUM_ROUNDS)
    print(f"Honest match rate: {honest['match_rate']:.4f} "
          f"(sifted: {honest['sifted_length']})")
    print(f"PE QBER: {honest['pe_qber']:.4f}")
    print(f"Backend: {honest['backend']}")

    # Test 3: V4 reflection attack (via Scenario D)
    print("\n--- Test 3: V4 reflection attack ---")
    attack = run_message_reflection_attack(NUM_ROUNDS)
    results["reflection_accepted"] = attack["reflection_accepted"]
    results["pe_qber_seen_by_bob"] = attack["pe_qber_seen_by_bob"]
    results["charlie_match_rate"] = attack["charlie_match_rate"]

    print(f"Bob's PE message reflected by Charlie: accepted={attack['reflection_accepted']}")
    print(f"PE QBER seen by Bob (reflected): {attack['pe_qber_seen_by_bob']}")
    print(f"Charlie-Bob match rate: {attack['charlie_match_rate']:.4f}")
    print(f"Bob accepts session: {attack['bob_accepts_session']}")

    if attack["bob_accepts_session"]:
        results["attack_successful"] = True
        results["notes"].append(
            "V4 succeeds: Charlie injects qubits (mimicking Quditto's "
            "KeySenderProtocol Encode pattern), reflects Bob's PE message. "
            "Bob verifies MAC (no directionality), sees QBER=0 (his own data "
            "reflected), and accepts session key from Charlie's injected qubits."
        )

    # Test 4: Directionality analysis
    print("\n--- Test 4: Directionality analysis ---")
    print("MAC is symmetric (no sender/receiver binding): YES")
    print("Nonce/sequence protection: NO")

    # Summary
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                        Quditto (NetSquid-based)")
    print(f"Vulnerability:               V4 - Message Reflection")
    print(f"Scenario:                    D (PM + Charlie active)")
    print(f"Built-in MAC:                {results['mac_available']}")
    print(f"Directionality Binding:      {results['directionality_binding']}")
    print(f"Reflection Accepted:         {results.get('reflection_accepted')}")
    print(f"PE QBER (reflected):         {results.get('pe_qber_seen_by_bob')}")
    print(f"Attack Successful:           {results['attack_successful']}")

    symbol = SYMBOL_UNAUTH_CHAN if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 4, "Quditto", symbol=symbol)


if __name__ == '__main__':
    main()
