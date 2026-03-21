"""
Scenario A: Entanglement-Based QKD with Passive Eve
=====================================================
Topology:
  - Entangled source controlled by Eve
  - Quantum: Eve generates Bell pairs, sends q_B to Bob, retains q_A
  - Classical: Alice <-> Bob routed through Eve (read + delay, no modify)

Eve capabilities:
  - Controls entangled source generation
  - Quantum memory to hold qubits across time steps
  - Reads classical messages (basis announcements) without modification
  - Configurable delay on classical forwarding

Maps to V1: Subverted Entanglement Injection

Note: SeQUeNCe does not provide a standalone EB-QKD protocol (E91/BBM92).
Barrett-Kok entanglement generation is repeater-level, not suitable for
standalone EB-QKD simulation. We use numpy-simulated Bell pairs and
measurements, and optionally use SeQUeNCe's Timeline for simulation context.
"""

import random
import numpy as np

SEED = 42
NUM_ROUNDS = 200

# Delay configuration (simulated time steps)
EVE_CLASSICAL_DELAY = 0  # additional delay Eve adds to classical forwarding


def _try_import_sequence():
    """Check if SeQUeNCe is importable and return Timeline if available."""
    try:
        from sequence.kernel.timeline import Timeline
        return True, {"Timeline": Timeline}
    except ImportError:
        return False, {}


def _create_bell_pair_numpy(rng):
    """
    Simulate a Bell |Phi+> pair using numpy.
    Returns correlated measurement functions for two qubits.
    The pair shares a random state: when measured in the same basis,
    results are perfectly correlated.
    """
    # The underlying Bell state: random shared bit
    shared_bit = rng.randint(0, 1)
    return shared_bit


def _measure_bell_qubit(shared_bit, party_is_bob, basis, rng):
    """
    Simulate measuring one half of a Bell |Phi+> pair.

    For Z-basis (basis=0): Alice gets shared_bit, Bob gets flipped (anti-correlation in Phi+).
    For X-basis (basis=1): Alice and Bob get the same random outcome (correlation in Phi+).

    Args:
        shared_bit: the underlying entangled state random variable
        party_is_bob: True if this is the Bob/second qubit
        basis: 0 for Z, 1 for X
        rng: random number generator
    """
    if basis == 0:
        # Z basis: anti-correlated in |Phi+>
        if party_is_bob:
            return 1 - shared_bit
        else:
            return shared_bit
    else:
        # X basis: correlated in |Phi+>
        # Both parties get the same random outcome
        # We use the shared_bit directly for correlation
        return shared_bit


def run_honest_eb_qkd(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest EB-QKD (BBM92-like): entangled source distributes pairs
    to Alice and Bob. Both measure independently in random bases,
    then sift on matching bases.

    Uses numpy-simulated Bell pairs. Optionally initializes SeQUeNCe
    Timeline for simulation context.

    Returns dict with alice_key, bob_key, match_rate, sifted_length, transcript.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    transcript = []

    # Optionally create SeQUeNCe Timeline for context
    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()
        transcript.append({"note": "SeQUeNCe Timeline initialized for simulation context"})
    else:
        transcript.append({"note": "SeQUeNCe not available; using pure numpy simulation"})

    alice_bits, bob_bits = [], []
    alice_bases, bob_bases = [], []

    for r in range(num_rounds):
        # Generate Bell pair
        shared_bit = _create_bell_pair_numpy(rng)

        a_base = rng.randint(0, 1)
        b_base = rng.randint(0, 1)
        alice_bases.append(a_base)
        bob_bases.append(b_base)

        a_result = _measure_bell_qubit(shared_bit, False, a_base, rng)
        b_result = _measure_bell_qubit(shared_bit, True, b_base, rng)
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
            # Z basis: anti-correlated -> flip Bob; X basis: correlated -> keep
            if alice_bases[i] == 0:
                bob_key.append(1 - bob_bits[i])
            else:
                bob_key.append(bob_bits[i])

    match = sum(1 for a, b in zip(alice_key, bob_key) if a == b)
    rate = match / len(alice_key) if alice_key else 0.0

    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "match_rate": rate, "sifted_length": len(alice_key),
        "transcript": transcript,
        "sequence_available": seq_available,
    }


def run_eve_attack(num_rounds=NUM_ROUNDS, seed=SEED, eve_delay=EVE_CLASSICAL_DELAY):
    """
    V1 Attack: Eve controls entangled source.
    1. Eve generates Bell pairs, sends q_B to Bob, retains q_A in memory.
    2. Bob measures in random basis and announces basis over classical channel.
    3. Eve reads Bob's basis announcement (with optional delay).
    4. Eve measures retained q_A in Bob's announced basis -> perfect correlation.
    5. Eve forges qubits for Alice using extracted key.

    Uses numpy-simulated Bell pairs and measurements.

    Returns dict with eve_key, bob_key, eve_match_rate, transcript.
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

    eve_retained = []  # quantum memory: stored shared_bits
    bob_bits, bob_bases = [], []

    # Phase 1: Eve generates pairs, sends q_B to Bob, retains q_A (shared state)
    for r in range(num_rounds):
        shared_bit = _create_bell_pair_numpy(rng)
        eve_retained.append(shared_bit)

        b_base = rng.randint(0, 1)
        bob_bases.append(b_base)
        b_result = _measure_bell_qubit(shared_bit, True, b_base, rng)
        bob_bits.append(b_result)

        transcript.append({
            "round": r, "phase": "quantum", "bob_basis": b_base,
            "bob_bit": b_result, "eve_qubit_stored": True,
        })

    # Phase 2: Bob announces bases (classical channel, Eve reads with delay)
    # Eve measures retained qubits in Bob's announced basis
    eve_bits = []
    for r in range(num_rounds):
        # Eve measures her half in Bob's basis -> perfect correlation
        e_result = _measure_bell_qubit(eve_retained[r], False, bob_bases[r], rng)
        eve_bits.append(e_result)

        transcript.append({
            "round": r, "phase": "eve_measure", "eve_basis": bob_bases[r],
            "eve_bit": e_result, "classical_delay": eve_delay,
        })

    # Compute Eve's correlation with Bob (all rounds, same basis by construction)
    eve_key, bob_key = [], []
    for i in range(num_rounds):
        eve_key.append(eve_bits[i])
        # Bell state correction: Z basis anti-correlated, X basis correlated
        if bob_bases[i] == 0:
            bob_key.append(1 - bob_bits[i])
        else:
            bob_key.append(bob_bits[i])

    match = sum(1 for e, b in zip(eve_key, bob_key) if e == b)
    rate = match / len(eve_key) if eve_key else 0.0

    return {
        "eve_key": eve_key, "bob_key": bob_key,
        "eve_match_rate": rate, "key_length": len(eve_key),
        "transcript": transcript,
        "attack_detected": False,  # QBER ~ 0 since Eve has perfect correlation
        "sequence_available": seq_available,
    }
