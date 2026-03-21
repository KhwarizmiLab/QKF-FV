"""
Scenario C: Prepare-and-Measure QKD with Passive Eve
======================================================
Topology:
  - Nodes: Alice (sender), Bob (receiver), Eve (interceptor)
  - Quantum: Alice -> Eve -> Bob (Eve intercepts, stores, re-encodes)
  - Classical: Alice <-> Bob routed through Eve (read + delay, no modify)

Eve capabilities:
  - Intercept qubits on quantum channel
  - Quantum memory to store qubits (deferred measurement)
  - Read classical basis announcements
  - Configurable delay on classical forwarding
  - Re-encode and forward qubits to Bob

Maps to V3: Basis-Deferred Measurement

Note: SeQUeNCe provides BB84 via QKDNode, but the protocol internals are
not easily hookable at the individual qubit level. We use numpy-simulated
BB84 encoding/measurement and optionally use SeQUeNCe's Timeline for
simulation context.
"""

import random
import numpy as np

SEED = 42
NUM_ROUNDS = 200
EVE_CLASSICAL_DELAY = 0


def _try_import_sequence():
    """Check if SeQUeNCe is importable and return available components."""
    try:
        from sequence.kernel.timeline import Timeline
        from sequence.topology.node import QKDNode
        return True, {"Timeline": Timeline, "QKDNode": QKDNode}
    except ImportError:
        return False, {}


def _encode_qubit_numpy(bit, basis):
    """
    Simulate BB84 encoding using numpy.
    Returns a dict representing the qubit state (bit + basis).
    """
    return {"bit": bit, "basis": basis}


def _measure_qubit_numpy(qubit_state, measurement_basis, rng):
    """
    Simulate BB84 measurement using numpy.
    If measurement basis matches encoding basis -> deterministic result.
    If bases differ -> random 50/50 outcome.
    """
    if qubit_state["basis"] == measurement_basis:
        return qubit_state["bit"]
    else:
        return rng.randint(0, 1)


def run_honest_bb84(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest BB84 PM-QKD between Alice and Bob.
    Standard ordering: Bob measures BEFORE basis exchange.

    Uses numpy-simulated BB84 encoding. Optionally initializes SeQUeNCe
    Timeline for simulation context.

    Returns dict with alice_key, bob_key, match_rate, sifted_length.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)

    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = _encode_qubit_numpy(alice_bits[i], alice_bases[i])
        bob_bits.append(_measure_qubit_numpy(q, bob_bases[i], rng))

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
        "sequence_available": seq_available,
    }


def run_secure_ordering_with_eve(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Eve intercepts but Bob measures BEFORE basis announcement.
    Eve must guess basis -> ~25% QBER on sifted key.
    Demonstrates that secure ordering defeats V3.

    Returns dict with eve_key, alice_key, eve_match_rate, ab_match_rate.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)

    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        q = _encode_qubit_numpy(alice_bits[i], alice_bases[i])
        # Eve intercepts, must guess basis
        eve_basis = rng.randint(0, 1)
        eve_result = _measure_qubit_numpy(q, eve_basis, rng)
        eve_bits.append(eve_result)
        # Eve re-encodes in her guessed basis
        q_resend = _encode_qubit_numpy(eve_result, eve_basis)
        bob_bits.append(_measure_qubit_numpy(q_resend, bob_bases[i], rng))

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
        "sequence_available": seq_available,
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

    Uses numpy-simulated BB84 encoding/measurement. Stored qubits are
    represented as state dicts in Eve's memory.

    Returns dict with eve_key, alice_key, bob_key, eve_match_rate, transcript.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)
    transcript = []

    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()
        transcript.append({"note": "SeQUeNCe Timeline initialized for simulation context"})
    else:
        transcript.append({"note": "SeQUeNCe not available; using pure numpy simulation"})

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    # Phase 1: Alice encodes, Eve intercepts and stores (quantum memory)
    eve_stored_qubits = []
    for i in range(num_rounds):
        q = _encode_qubit_numpy(alice_bits[i], alice_bases[i])
        eve_stored_qubits.append(q)
        transcript.append({
            "round": i, "phase": "intercept",
            "eve_action": "store_qubit", "qubit_in_memory": True,
        })

    # Phase 2: Alice announces bases (vulnerable: before Bob measures)
    # Eve reads announcement and measures stored qubits in correct basis
    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        eve_result = _measure_qubit_numpy(eve_stored_qubits[i], alice_bases[i], rng)
        eve_bits.append(eve_result)

        # Eve re-encodes and sends to Bob
        q_resend = _encode_qubit_numpy(eve_result, alice_bases[i])
        bob_bits.append(_measure_qubit_numpy(q_resend, bob_bases[i], rng))

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
        "sequence_available": seq_available,
    }
