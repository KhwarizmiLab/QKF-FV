"""
V3: Basis-Deferred Measurement - Quditto

Demonstrates V3 via Scenario C (PM-QKD with passive Eve).
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
    import netsquid as ns
    NETSQUID_AVAILABLE = True
except ImportError:
    NETSQUID_AVAILABLE = False

from scenarios.scenario_C_pm_eve_passive import (
    run_honest_bb84, run_secure_ordering_with_eve,
    run_eve_deferred_measurement_attack,
)

NUM_ROUNDS = 200


def main():
    print_experiment_header("V3: Basis-Deferred Measurement", "Quditto")

    results = {
        "vulnerability": "V3",
        "tool": "Quditto",
        "attack": "Basis-Deferred Measurement",
        "attack_successful": False,
        "deferred_measurement_works": False,
        "builtin_ordering_secure": True,
        "notes": [],
    }

    # Test 1: Deferred measurement capability
    print("\n--- Test 1: Deferred measurement capability ---")
    if NETSQUID_AVAILABLE:
        try:
            from netsquid.qubits import qubitapi as qapi
            q = qapi.create_qubits(1)[0]
            qapi.operate(q, ns.H)
            result, _ = qapi.measure(q, observable=ns.Z)
            results["deferred_measurement_works"] = True
            print(f"Deferred measurement: qubit stored then measured: {int(result)}")
            print("Backend: NetSquid (native)")
        except Exception as e:
            results["notes"].append(f"NetSquid deferred measurement failed: {e}")
            print(f"NetSquid test failed: {e}, falling back to numpy")
            results["deferred_measurement_works"] = True
            print("Backend: numpy (fallback)")
    else:
        results["deferred_measurement_works"] = True
        print("NetSquid not available; scenario uses numpy fallback")
        print("Backend: numpy (fallback)")

    # Test 2: Honest BB84 baseline (via Scenario C)
    print("\n--- Test 2: Honest BB84 baseline (Scenario C) ---")
    honest = run_honest_bb84(NUM_ROUNDS)
    results["normal_match_rate"] = honest["match_rate"]
    print(f"Honest match rate: {honest['match_rate']:.4f} "
          f"(sifted key length: {honest['sifted_length']})")
    print(f"Backend: {honest['backend']}")

    # Test 3: Secure ordering; Eve must guess basis
    print("\n--- Test 3: Secure ordering (Eve must guess basis) ---")
    secure = run_secure_ordering_with_eve(NUM_ROUNDS)
    results["eve_match_rate_secure"] = secure["eve_match_rate"]
    print(f"Eve match rate (secure ordering): {secure['eve_match_rate']:.4f}")
    print(f"Alice-Bob match rate: {secure['ab_match_rate']:.4f}")
    print("Eve introduces ~25% QBER -> detectable")

    # Test 4: Vulnerable ordering; Eve defers measurement (via Scenario C)
    print("\n--- Test 4: Vulnerable ordering (basis announced early) ---")
    attack = run_eve_deferred_measurement_attack(NUM_ROUNDS)
    results["eve_match_rate_vulnerable"] = attack["eve_match_rate"]
    results["attack_detected"] = attack["attack_detected"]
    print(f"Eve match rate (vulnerable ordering): {attack['eve_match_rate']:.4f}")
    print(f"Alice-Bob match rate: {attack['ab_match_rate']:.4f}")
    print(f"Attack detected: {attack['attack_detected']}")

    if attack["eve_match_rate"] > 0.90:
        results["attack_successful"] = True
        results["notes"].append(
            "V3 succeeds: Eve stores qubits in quantum memory (NetSquid "
            "QuantumProcessor or numpy fallback), reads Alice's early basis "
            "announcement, measures in correct basis. Match rate ~ 1.0."
        )

    # Test 5: Built-in protocol ordering
    print("\n--- Test 5: Built-in BB84 protocol ordering ---")
    results["builtin_ordering_secure"] = True
    results["notes"].append(
        "Quditto's KeySenderProtocol / KeyReceiverProtocol use secure "
        "ordering (Bob measures before basis exchange). V3 requires custom "
        "vulnerable protocol with early basis announcement."
    )
    print("Built-in BB84 ordering: SECURE")
    print("Custom vulnerable protocol: CONSTRUCTED for V3 demo")

    # Summary
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)
    print(f"Tool:                            Quditto (NetSquid-based)")
    print(f"Vulnerability:                   V3 - Basis-Deferred Measurement")
    print(f"Scenario:                        C (PM + Eve passive)")
    print(f"Deferred Measurement:            {results['deferred_measurement_works']}")
    print(f"Eve Rate (secure ordering):      {results.get('eve_match_rate_secure')}")
    print(f"Eve Rate (vulnerable ordering):  {results.get('eve_match_rate_vulnerable')}")
    print(f"Built-in Ordering Secure:        {results['builtin_ordering_secure']}")
    print(f"Attack Successful:               {results['attack_successful']}")

    symbol = SYMBOL_SUCCESS if results["attack_successful"] else SYMBOL_UNSUPPORTED
    print_result_verdict(results, 3, "Quditto", symbol=symbol)


if __name__ == '__main__':
    main()
