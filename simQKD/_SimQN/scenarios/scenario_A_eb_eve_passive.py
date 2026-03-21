"""
V1: Subverted Entanglement Injection - Scenario A

EB-QKD topology with passive Eve who controls the entangled source.
"""

import random
import numpy as np

SEED = 42
NUM_ROUNDS = 200

# Delay configuration (simulated time steps)
EVE_CLASSICAL_DELAY = 0  # additional delay Eve adds to classical forwarding


def _try_import():
    try:
        from qns.models.qubit.qubit import Qubit
        from qns.models.qubit.const import QUBIT_STATE_0
        from qns.models.qubit.gate import H, CNOT, X, Z
        return True, {"Qubit": Qubit, "QUBIT_STATE_0": QUBIT_STATE_0,
                       "H": H, "CNOT": CNOT, "X": X, "Z": Z}
    except ImportError:
        return False, {}


def create_bell_pair(qns):
    """Create a Bell |Phi+> pair using SimQN primitives."""
    q0 = qns["Qubit"](state=qns["QUBIT_STATE_0"], name="q0")
    q1 = qns["Qubit"](state=qns["QUBIT_STATE_0"], name="q1")
    qns["H"](q0)
    qns["CNOT"](q0, q1)
    return q0, q1


def measure_qubit(q, basis, qns):
    """Measure qubit in Z (basis=0) or X (basis=1)."""
    if basis == 1:
        return q.measureX()
    return q.measure()


def run_honest_eb_qkd(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest EB-QKD (BBM92-like): entangled source distributes pairs
    to Alice and Bob. Both measure independently in random bases,
    then sift on matching bases.

    Returns dict with alice_key, bob_key, match_rate, sifted_length, transcript.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    transcript = []

    alice_bits, bob_bits = [], []
    alice_bases, bob_bases = [], []

    for r in range(num_rounds):
        q_a, q_b = create_bell_pair(qns)

        a_base = rng.randint(0, 1)
        b_base = rng.randint(0, 1)
        alice_bases.append(a_base)
        bob_bases.append(b_base)

        a_result = measure_qubit(q_a, a_base, qns)
        b_result = measure_qubit(q_b, b_base, qns)
        alice_bits.append(a_result)
        bob_bits.append(b_result)

        transcript.append({
            "round": r, "alice_basis": a_base, "bob_basis": b_base,
            "alice_bit": a_result, "bob_bit": b_result,
        })

    # Sift on matching bases
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
        "transcript": transcript,
    }


def run_eve_attack(num_rounds=NUM_ROUNDS, seed=SEED, eve_delay=EVE_CLASSICAL_DELAY):
    """
    V1 Attack: Eve controls entangled source.
    1. Eve generates Bell pairs, sends q_B to Bob, retains q_A in memory.
    2. Bob measures in random basis and announces basis over classical channel.
    3. Eve reads Bob's basis announcement (with optional delay).
    4. Eve measures retained q_A in Bob's announced basis -> perfect correlation.
    5. Eve forges qubits for Alice using extracted key.

    Returns dict with eve_key, bob_key, eve_match_rate, transcript.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    transcript = []

    eve_retained = []  # quantum memory
    bob_bits, bob_bases = [], []

    # Phase 1: Eve generates pairs, sends q_B to Bob, retains q_A
    for r in range(num_rounds):
        q_eve, q_bob = create_bell_pair(qns)
        eve_retained.append(q_eve)

        b_base = rng.randint(0, 1)
        bob_bases.append(b_base)
        b_result = measure_qubit(q_bob, b_base, qns)
        bob_bits.append(b_result)

        transcript.append({
            "round": r, "phase": "quantum", "bob_basis": b_base,
            "bob_bit": b_result, "eve_qubit_stored": True,
        })

    # Phase 2: Bob announces bases (classical channel, Eve reads with delay)
    # Eve measures retained qubits in Bob's announced basis
    eve_bits = []
    for r in range(num_rounds):
        e_result = measure_qubit(eve_retained[r], bob_bases[r], qns)
        eve_bits.append(e_result)

        transcript.append({
            "round": r, "phase": "eve_measure", "eve_basis": bob_bases[r],
            "eve_bit": e_result, "classical_delay": eve_delay,
        })

    # Compute Eve's correlation with Bob (all rounds, same basis)
    eve_key, bob_key = [], []
    for i in range(num_rounds):
        eve_key.append(eve_bits[i])
        bob_key.append(bob_bits[i])

    match = sum(1 for e, b in zip(eve_key, bob_key) if e == b)
    rate = match / len(eve_key) if eve_key else 0.0

    return {
        "eve_key": eve_key, "bob_key": bob_key,
        "eve_match_rate": rate, "key_length": len(eve_key),
        "transcript": transcript,
        "attack_detected": False,  # QBER ~ 0 since Eve has perfect correlation
    }
