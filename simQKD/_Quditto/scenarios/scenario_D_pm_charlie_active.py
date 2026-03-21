"""
Scenario D: PM-QKD with Active Charlie - Quditto

Runs a prepare-and-measure BB84 session with an active MitM for V4.
"""

import random
import json
import numpy as np
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

SEED = 42
NUM_ROUNDS = 200
PE_SAMPLE_SIZE = 30


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

def run_honest_bb84_with_pe(num_rounds=NUM_ROUNDS, seed=SEED,
                             pe_sample_size=PE_SAMPLE_SIZE):
    """
    Honest BB84 with parameter estimation phase.
    Alice and Bob exchange PE samples with MAC-authenticated messages.

    Uses Quditto's Encode pattern (INSTR_INIT + INSTR_X + INSTR_H) when
    NetSquid is available; otherwise falls back to numpy state vectors.

    Returns dict with alice_key, bob_key, match_rate, pe_qber.
    """
    use_ns, ns_mods = _try_import_netsquid()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    psk = "alice-bob-psk-honest"

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = _encode_qubit(alice_bits[i], alice_bases[i], use_ns, ns_mods, rng)
        bob_bits.append(_measure_qubit(q, bob_bases[i], use_ns, ns_mods, np_rng))

    # Sift
    alice_key, bob_key = [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_key.append(alice_bits[i])
            bob_key.append(bob_bits[i])

    # Parameter estimation
    actual_pe_size = min(pe_sample_size, len(alice_key) // 2)
    pe_indices = rng.sample(range(len(alice_key)), actual_pe_size)

    alice_pe = [alice_key[j] for j in pe_indices]
    bob_pe = [bob_key[j] for j in pe_indices]

    pe_errors = sum(1 for a, b in zip(alice_pe, bob_pe) if a != b)
    pe_qber = pe_errors / len(alice_pe) if alice_pe else 0.0

    match = sum(1 for a, b in zip(alice_key, bob_key) if a == b)
    rate = match / len(alice_key) if alice_key else 0.0

    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "match_rate": rate, "sifted_length": len(alice_key),
        "pe_qber": pe_qber, "pe_sample_size": actual_pe_size,
        "backend": "netsquid" if use_ns else "numpy",
    }


def run_message_reflection_attack(num_rounds=NUM_ROUNDS, seed=SEED,
                                    pe_sample_size=PE_SAMPLE_SIZE):
    """
    V4 Attack: Charlie injects qubits and reflects Bob's PE message.

    Charlie's qubit injection mirrors Quditto's KeySenderProtocol:
    he encodes known bits via the Encode program (INSTR_INIT, INSTR_X, INSTR_H)
    and transmits to Bob in place of Alice.

    Attack steps:
      1. Charlie generates own qubits from known key, sends to Bob as "Alice".
      2. Bob measures and prepares PE message with MAC(PSK).
      3. Charlie intercepts Bob's PE message + MAC.
      4. Charlie reflects the exact message + MAC back to Bob.
      5. Bob verifies reflected MAC (same PSK, no directionality) -> accepts.
      6. Bob compares reflected PE data against his own -> 0% QBER.
      7. Bob accepts session key derived from Charlie's injected qubits.

    Returns dict with charlie_key, bob_key, reflection_accepted,
    pe_qber_seen_by_bob, transcript.
    """
    use_ns, ns_mods = _try_import_netsquid()
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)
    psk = "alice-bob-psk-v4"  # symmetric, no directionality
    transcript = []

    # Charlie generates his own key and encodes qubits for Bob
    # This mirrors Quditto's KeySenderProtocol: generate key + bases,
    # encode via QuantumProcessor (Encode program), pop, transmit.
    charlie_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    charlie_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = _encode_qubit(charlie_bits[i], charlie_bases[i], use_ns, ns_mods, rng)
        bob_bits.append(_measure_qubit(q, bob_bases[i], use_ns, ns_mods, np_rng))
        transcript.append({
            "round": i, "phase": "quantum_inject",
            "charlie_bit": charlie_bits[i], "charlie_basis": charlie_bases[i],
        })

    # Sift (Charlie knows both his bases and can learn Bob's from classical)
    charlie_sifted, bob_sifted = [], []
    sifted_indices = []
    for i in range(num_rounds):
        if charlie_bases[i] == bob_bases[i]:
            charlie_sifted.append(charlie_bits[i])
            bob_sifted.append(bob_bits[i])
            sifted_indices.append(i)

    # Bob prepares PE message
    actual_pe_size = min(pe_sample_size, max(1, len(bob_sifted) // 2))
    pe_indices = rng.sample(range(len(bob_sifted)), actual_pe_size)
    pe_bits = [bob_sifted[j] for j in pe_indices]
    pe_message = json.dumps({"indices": pe_indices, "bits": pe_bits})

    # Bob MACs his PE message (no directionality flag)
    bob_mac = compute_mac(psk, pe_message)

    transcript.append({
        "phase": "pe_message",
        "bob_sends_pe": True, "pe_sample_size": actual_pe_size,
    })

    # Charlie intercepts and reflects Bob's message + MAC back to Bob
    reflected_msg = pe_message
    reflected_mac = bob_mac  # identical, no direction binding

    # Bob verifies reflected message
    bob_accepts = verify_mac(psk, reflected_msg, reflected_mac)

    transcript.append({
        "phase": "reflection",
        "charlie_reflects": True,
        "bob_accepts_reflected": bob_accepts,
    })

    # If Bob accepts, he compares reflected PE against his own measurements
    pe_qber = None
    if bob_accepts:
        reflected_data = json.loads(reflected_msg)
        pe_match = sum(
            1 for j, idx in enumerate(reflected_data["indices"])
            if reflected_data["bits"][j] == bob_sifted[idx]
        )
        pe_qber = 1.0 - (pe_match / len(reflected_data["indices"]))

    # Charlie's match with Bob's sifted key
    charlie_match = sum(1 for c, b in zip(charlie_sifted, bob_sifted) if c == b)
    charlie_rate = charlie_match / len(charlie_sifted) if charlie_sifted else 0.0

    return {
        "charlie_key": charlie_sifted, "bob_key": bob_sifted,
        "charlie_match_rate": charlie_rate,
        "sifted_length": len(bob_sifted),
        "reflection_accepted": bob_accepts,
        "pe_qber_seen_by_bob": pe_qber,
        "bob_accepts_session": bob_accepts and (pe_qber is not None and pe_qber < 0.05),
        "attack_detected": False if (bob_accepts and pe_qber == 0.0) else True,
        "transcript": transcript,
        "backend": "netsquid" if use_ns else "numpy",
    }
