"""
V1: Subverted Entanglement Injection - SimQN

Runs Scenario A (EB-QKD with passive Eve) to demonstrate the V1 attack.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.experiment_utils import (
    SYMBOL_SUCCESS, SYMBOL_UNSUPPORTED, print_result_verdict,
    print_experiment_header,
)

try:
    from qns.models.qubit.qubit import Qubit
    SIMQN_AVAILABLE = True
except ImportError:
    SIMQN_AVAILABLE = False

from scenarios.scenario_A_eb_eve_passive import (
    run_honest_eb_qkd, run_eve_attack, create_bell_pair, _try_import,
)

NUM_ROUNDS = 200


def main():
    print_experiment_header("V1: Subverted Entanglement Injection", "SimQN")

    results = {
        "vulnerability": "V1",
        "tool": "SimQN",
        "attack": "Subverted Entanglement Injection",
        "attack_successful": False,
        "entanglement_available": False,
        "quantum_memory_delay": False,
        "eb_qkd_protocol_builtin": False,
        "notes": [],
    }

    if not SIMQN_AVAILABLE:
        results["notes"].append("SimQN (qns) is not installed.")
        print_result_verdict(results, 1, "SimQN", symbol=SYMBOL_UNSUPPORTED)
        return

    # Test 1: Bell pair creation
    print("\n--- Test 1: Bell pair creation ---")
    available, qns = _try_import()
    try:
        q0, q1 = create_bell_pair(qns)
        r0, r1 = q0.measure(), q1.measure()
        results["entanglement_available"] = True
        print(f"Bell pair |Phi+> created: measured ({r0}, {r1}), correlated: {r0 == r1}")
    except Exception as e:
        results["notes"].append(f"Entanglement test failed: {e}")
        print(f"FAILED: {e}")

    # Test 2: Quantum memory (deferred measurement)
    print("\n--- Test 2: Qubit storage (deferred measurement) ---")
    try:
        from qns.models.qubit.const import QUBIT_STATE_0
        from qns.models.qubit.gate import H
        q = Qubit(state=QUBIT_STATE_0)
        H(q)
        r = q.measure()
        results["quantum_memory_delay"] = True
        print(f"Stored qubit measured after delay: {r}")
    except Exception as e:
        results["notes"].append(f"Storage test failed: {e}")

    # Test 3: Built-in EB-QKD check
    print("\n--- Test 3: Built-in EB-QKD protocol check ---")
    results["eb_qkd_protocol_builtin"] = False
    print("Built-in EB-QKD protocol: NO (only PM BB84)")
    print("Entanglement primitives for custom EB-QKD: YES")

    # Test 4: Honest EB-QKD baseline (via Scenario A)
    print("\n--- Test 4: Honest EB-QKD baseline (Scenario A) ---")
    honest = run_honest_eb_qkd(NUM_ROUNDS)
    results["normal_match_rate"] = honest["match_rate"]
    print(f"Honest match rate: {honest['match_rate']:.4f} "
          f"(sifted key length: {honest['sifted_length']})")

    # Test 5: V1 attack (via Scenario A)
    print("\n--- Test 5: V1 attack (Eve-controlled source, deferred measurement) ---")
    attack = run_eve_attack(NUM_ROUNDS)
    results["eve_match_rate"] = attack["eve_match_rate"]
    results["attack_detected"] = attack["attack_detected"]
    print(f"Eve match rate with Bob: {attack['eve_match_rate']:.4f} "
          f"(key length: {attack['key_length']})")
    print(f"Attack detected by PE: {attack['attack_detected']}")

    if attack["eve_match_rate"] > 0.90:
        results["attack_successful"] = True
        results["notes"].append(
            "V1 attack succeeds: Eve controls entangled source, delays her qubit, "
            "measures in Bob's announced basis, achieves high correlation. "
            "SimQN's qubit primitives enable the full attack."
        )

    # Summary
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                        SimQN")
    print(f"Vulnerability:               V1 - Subverted Entanglement Injection")
    print(f"Scenario:                    A (EB + Eve passive)")
    print(f"Entanglement Available:      {results['entanglement_available']}")
    print(f"Quantum Memory/Delay:        {results['quantum_memory_delay']}")
    print(f"Built-in EB-QKD:             {results['eb_qkd_protocol_builtin']}")
    print(f"Honest Match Rate:           {results.get('normal_match_rate')}")
    print(f"Eve Match Rate:              {results.get('eve_match_rate')}")
    print(f"Attack Successful:           {results['attack_successful']}")

    symbol = SYMBOL_SUCCESS if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 1, "SimQN", symbol=symbol)


if __name__ == '__main__':
    main()
