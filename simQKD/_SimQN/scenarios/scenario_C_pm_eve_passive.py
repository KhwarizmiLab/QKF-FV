"""
V3: Basis-Deferred Measurement - Scenario C

PM-QKD topology with passive Eve who intercepts, stores, and re-encodes qubits.
"""

import random
import numpy as np

SEED = 42
NUM_ROUNDS = 200
EVE_CLASSICAL_DELAY = 0


def _try_import():
    try:
        from qns.models.qubit.qubit import Qubit
        from qns.models.qubit.const import QUBIT_STATE_0
        from qns.models.qubit.gate import H, X
        return True, {"Qubit": Qubit, "QUBIT_STATE_0": QUBIT_STATE_0, "H": H, "X": X}
    except ImportError:
        return False, {}


def encode_qubit(bit, basis, qns):
    """Encode a classical bit into a qubit using BB84 encoding."""
    q = qns["Qubit"](state=qns["QUBIT_STATE_0"])
    if bit == 1:
        qns["X"](q)
    if basis == 1:
        qns["H"](q)
    return q


def measure_qubit(q, basis):
    """Measure qubit in Z (basis=0) or X (basis=1)."""
    if basis == 1:
        return q.measureX()
    return q.measure()


def run_honest_bb84(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest BB84 PM-QKD between Alice and Bob.
    Standard ordering: Bob measures BEFORE basis exchange.

    Returns dict with alice_key, bob_key, match_rate, sifted_length.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = encode_qubit(alice_bits[i], alice_bases[i], qns)
        bob_bits.append(measure_qubit(q, bob_bases[i]))

    alice_key, bob_key = [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_key.append(alice_bits[i])
            bob_key.append(bob_bits[i])

    match = sum(1 for a, b in zip(alice_key, bob_key) if a == b)
    rate = match / len(alice_key) if alice_key else 0.0

    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "match_rate": rate, "sifted_length": len(alice_key),
    }


def run_secure_ordering_with_eve(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Eve intercepts but Bob measures BEFORE basis announcement.
    Eve must guess basis -> ~25% QBER on sifted key.
    Demonstrates that secure ordering defeats V3.

    Returns dict with eve_key, alice_key, eve_match_rate, ab_match_rate.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        q = encode_qubit(alice_bits[i], alice_bases[i], qns)
        # Eve intercepts, must guess basis
        eve_basis = rng.randint(0, 1)
        eve_result = measure_qubit(q, eve_basis)
        eve_bits.append(eve_result)
        # Eve re-encodes in her guessed basis
        q_resend = encode_qubit(eve_result, eve_basis, qns)
        bob_bits.append(measure_qubit(q_resend, bob_bases[i]))

    alice_sifted, bob_sifted, eve_sifted = [], [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_sifted.append(alice_bits[i])
            bob_sifted.append(bob_bits[i])
            eve_sifted.append(eve_bits[i])

    eve_match = sum(1 for e, a in zip(eve_sifted, alice_sifted) if e == a)
    ab_match = sum(1 for a, b in zip(alice_sifted, bob_sifted) if a == b)

    return {
        "eve_key": eve_sifted, "alice_key": alice_sifted, "bob_key": bob_sifted,
        "eve_match_rate": eve_match / len(eve_sifted) if eve_sifted else 0.0,
        "ab_match_rate": ab_match / len(alice_sifted) if alice_sifted else 0.0,
        "sifted_length": len(alice_sifted),
        "attack_detected": True,  # high QBER detectable
    }


def run_eve_deferred_measurement_attack(num_rounds=NUM_ROUNDS, seed=SEED,
                                         eve_delay=EVE_CLASSICAL_DELAY):
    """
    V3 Attack: Vulnerable ordering where Alice announces basis BEFORE Bob measures.
    1. Alice encodes qubits and transmits.
    2. Eve intercepts all qubits, stores in quantum memory.
    3. Alice announces her bases on classical channel.
    4. Eve reads announcement, measures stored qubits in Alice's basis -> perfect extraction.
    5. Eve re-encodes and forwards to Bob.
    6. Eve relays classical data (with optional delay).

    Returns dict with eve_key, alice_key, bob_key, eve_match_rate, transcript.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    transcript = []

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    # Phase 1: Alice encodes, Eve intercepts and stores (quantum memory)
    eve_stored_qubits = []
    for i in range(num_rounds):
        q = encode_qubit(alice_bits[i], alice_bases[i], qns)
        eve_stored_qubits.append(q)
        transcript.append({
            "round": i, "phase": "intercept",
            "eve_action": "store_qubit", "qubit_in_memory": True,
        })

    # Phase 2: Alice announces bases (vulnerable: before Bob measures)
    # Eve reads announcement and measures stored qubits in correct basis
    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        eve_result = measure_qubit(eve_stored_qubits[i], alice_bases[i])
        eve_bits.append(eve_result)

        # Eve re-encodes and sends to Bob
        q_resend = encode_qubit(eve_result, alice_bases[i], qns)
        bob_bits.append(measure_qubit(q_resend, bob_bases[i]))

        transcript.append({
            "round": i, "phase": "deferred_measure",
            "eve_basis": alice_bases[i], "eve_bit": eve_result,
            "classical_delay": eve_delay,
        })

    # Sift
    alice_sifted, bob_sifted, eve_sifted = [], [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_sifted.append(alice_bits[i])
            bob_sifted.append(bob_bits[i])
            eve_sifted.append(eve_bits[i])

    eve_match = sum(1 for e, a in zip(eve_sifted, alice_sifted) if e == a)
    ab_match = sum(1 for a, b in zip(alice_sifted, bob_sifted) if a == b)

    return {
        "eve_key": eve_sifted, "alice_key": alice_sifted, "bob_key": bob_sifted,
        "eve_match_rate": eve_match / len(eve_sifted) if eve_sifted else 0.0,
        "ab_match_rate": ab_match / len(alice_sifted) if alice_sifted else 0.0,
        "sifted_length": len(alice_sifted),
        "attack_detected": False,  # Eve's re-encoded qubits match perfectly
        "transcript": transcript,
    }
