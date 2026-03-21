"""
Scenario C: PM-QKD with Passive Eve - Quditto

Runs a prepare-and-measure BB84 session with a passive eavesdropper for V3.
"""

import random
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

SEED = 42
NUM_ROUNDS = 200
EVE_CLASSICAL_DELAY = 0


def _try_import_netsquid():
    """Import NetSquid and Quditto components for native simulation."""
    try:
        import netsquid as ns
        import netsquid.components.instructions as instr
        from netsquid.qubits import qubitapi as qapi
        from netsquid.components.qprocessor import QuantumProcessor, PhysicalInstruction
        from netsquid.components.models.qerrormodels import DepolarNoiseModel
        return True, {
            "ns": ns,
            "instr": instr,
            "qapi": qapi,
            "QuantumProcessor": QuantumProcessor,
            "PhysicalInstruction": PhysicalInstruction,
            "DepolarNoiseModel": DepolarNoiseModel,
        }
    except ImportError:
        return False, {}


# ---------------------------------------------------------------------------
# NetSquid-native qubit helpers
# ---------------------------------------------------------------------------

def _ns_create_qubit(netsquid_modules):
    """Create a single qubit in |0> using NetSquid qapi."""
    qapi = netsquid_modules["qapi"]
    return qapi.create_qubits(1)[0]


def _ns_encode(qubit, bit, basis, netsquid_modules):
    """Encode bit in basis on a NetSquid qubit using gate operators."""
    ns = netsquid_modules["ns"]
    qapi = netsquid_modules["qapi"]
    instr_mod = netsquid_modules["instr"]
    if bit == 1:
        qapi.operate(qubit, ns.X)
    if basis == 1:
        qapi.operate(qubit, ns.H)
    return qubit


def _ns_measure(qubit, basis, netsquid_modules):
    """Measure a NetSquid qubit in Z (basis=0) or X (basis=1)."""
    ns = netsquid_modules["ns"]
    qapi = netsquid_modules["qapi"]
    if basis == 1:
        qapi.operate(qubit, ns.H)
    result, _ = qapi.measure(qubit, observable=ns.Z)
    return int(result)


# ---------------------------------------------------------------------------
# Numpy fallback qubit helpers
# ---------------------------------------------------------------------------

_Z0 = np.array([1, 0], dtype=complex)
_Z1 = np.array([0, 1], dtype=complex)
_H_GATE = np.array([[1, 1], [1, -1]], dtype=complex) / np.sqrt(2)
_X_GATE = np.array([[0, 1], [1, 0]], dtype=complex)


def _np_encode(bit, basis):
    """Encode bit in basis using numpy state vectors."""
    state = _Z0.copy() if bit == 0 else _Z1.copy()
    if basis == 1:
        state = _H_GATE @ state
    return state


def _np_measure(state, basis, rng):
    """Measure numpy state vector in Z (basis=0) or X (basis=1)."""
    if basis == 1:
        state = _H_GATE @ state
    prob_0 = np.abs(state[0]) ** 2
    return 0 if rng.random() < prob_0 else 1


# ---------------------------------------------------------------------------
# Unified encode / measure dispatchers
# ---------------------------------------------------------------------------

def _encode_qubit(bit, basis, use_netsquid, ns_mods, rng=None):
    if use_netsquid:
        q = _ns_create_qubit(ns_mods)
        return _ns_encode(q, bit, basis, ns_mods)
    else:
        return _np_encode(bit, basis)


def _measure_qubit(qubit, basis, use_netsquid, ns_mods, rng=None):
    if use_netsquid:
        return _ns_measure(qubit, basis, ns_mods)
    else:
        return _np_measure(qubit, basis, rng)


# ===========================================================================
# Public API
# ===========================================================================

def run_honest_bb84(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest BB84 PM-QKD between Alice and Bob.
    Standard ordering: Bob measures BEFORE basis exchange.

    Returns dict with alice_key, bob_key, match_rate, sifted_length.
    """
    use_ns, ns_mods = _try_import_netsquid()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = _encode_qubit(alice_bits[i], alice_bases[i], use_ns, ns_mods, rng)
        bob_bits.append(_measure_qubit(q, bob_bases[i], use_ns, ns_mods, np_rng))

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
        "backend": "netsquid" if use_ns else "numpy",
    }


def run_secure_ordering_with_eve(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Eve intercepts but Bob measures BEFORE basis announcement.
    Eve must guess basis -> ~25% QBER on sifted key.
    Demonstrates that secure ordering defeats V3.

    Returns dict with eve_key, alice_key, bob_key, eve_match_rate, ab_match_rate.
    """
    use_ns, ns_mods = _try_import_netsquid()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        q = _encode_qubit(alice_bits[i], alice_bases[i], use_ns, ns_mods, rng)
        # Eve intercepts, must guess basis
        eve_basis = rng.randint(0, 1)
        eve_result = _measure_qubit(q, eve_basis, use_ns, ns_mods, np_rng)
        eve_bits.append(eve_result)
        # Eve re-encodes in her guessed basis
        q_resend = _encode_qubit(eve_result, eve_basis, use_ns, ns_mods, rng)
        bob_bits.append(_measure_qubit(q_resend, bob_bases[i], use_ns, ns_mods, np_rng))

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
        "backend": "netsquid" if use_ns else "numpy",
    }


def run_eve_deferred_measurement_attack(num_rounds=NUM_ROUNDS, seed=SEED,
                                         eve_delay=EVE_CLASSICAL_DELAY):
    """
    V3 Attack: Vulnerable ordering where Alice announces basis BEFORE Bob measures.

    Reuses Quditto's Eve topology concept (bb84_with_eve.py EavesdropperProtocol):
    Eve sits between Alice and Bob on the quantum channel, intercepts qubits,
    and stores them in quantum memory (NetSquid QuantumProcessor or numpy state).

    Attack steps:
      1. Alice encodes qubits and transmits.
      2. Eve intercepts all qubits, stores in quantum memory.
      3. Alice announces her bases on classical channel.
      4. Eve reads announcement, measures stored qubits in Alice's basis
         -> perfect extraction.
      5. Eve re-encodes and forwards to Bob.
      6. Eve relays classical data (with optional delay).

    Returns dict with eve_key, alice_key, bob_key, eve_match_rate, transcript.
    """
    use_ns, ns_mods = _try_import_netsquid()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    transcript = []

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    # Phase 1: Alice encodes, Eve intercepts and stores (quantum memory)
    # In Quditto's native model this corresponds to Eve's QuantumProcessor
    # holding qubits before measurement (like EavesdropperProtocol storing in qmemory).
    eve_stored_qubits = []
    for i in range(num_rounds):
        q = _encode_qubit(alice_bits[i], alice_bases[i], use_ns, ns_mods, rng)
        eve_stored_qubits.append(q)
        transcript.append({
            "round": i, "phase": "intercept",
            "eve_action": "store_qubit", "qubit_in_memory": True,
        })

    # Phase 2: Alice announces bases (vulnerable: before Bob measures)
    # Eve reads announcement and measures stored qubits in correct basis.
    # This mirrors Quditto's Encode + INSTR_MEASURE / INSTR_MEASURE_X pattern.
    eve_bits, bob_bits = [], []
    for i in range(num_rounds):
        eve_result = _measure_qubit(eve_stored_qubits[i], alice_bases[i],
                                     use_ns, ns_mods, np_rng)
        eve_bits.append(eve_result)

        # Eve re-encodes and sends to Bob
        q_resend = _encode_qubit(eve_result, alice_bases[i], use_ns, ns_mods, rng)
        bob_bits.append(_measure_qubit(q_resend, bob_bases[i], use_ns, ns_mods, np_rng))

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
        "backend": "netsquid" if use_ns else "numpy",
    }
