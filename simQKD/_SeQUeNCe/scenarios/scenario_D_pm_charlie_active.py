"""
Scenario D: Prepare-and-Measure QKD with Active Charlie
=========================================================
Topology:
  - Nodes: Alice (sender), Bob (receiver), Charlie (active MitM)
  - Quantum: Alice -> Charlie -> Bob (Charlie injects own qubits to Bob)
  - Classical: Alice <-> Charlie (PSK_AC), Charlie <-> Bob (PSK_CB)

Charlie capabilities:
  - Inject own encoded qubits to Bob (replacing Alice's)
  - Intercept Bob's PE message and reflect it back unmodified
  - MAC tags lack directionality -> Bob accepts his own reflected message
  - Force 0% QBER on Bob's parameter estimation

Maps to V4: Message Reflection

Note: SeQUeNCe provides BB84 via QKDNode, but the protocol internals are
not easily hookable at the individual qubit level. We use numpy-simulated
BB84 encoding/measurement and optionally use SeQUeNCe's Timeline for
simulation context.
"""

import random
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

import numpy as np

SEED = 42
NUM_ROUNDS = 200
PE_SAMPLE_SIZE = 30


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


def run_honest_bb84_with_pe(num_rounds=NUM_ROUNDS, seed=SEED,
                             pe_sample_size=PE_SAMPLE_SIZE):
    """
    Honest BB84 with parameter estimation phase.
    Alice and Bob exchange PE samples with MAC-authenticated messages.

    Uses numpy-simulated BB84 encoding. Optionally initializes SeQUeNCe
    Timeline for simulation context.

    Returns dict with alice_key, bob_key, match_rate, pe_qber.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)
    psk = "alice-bob-psk-honest"

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
        "sequence_available": seq_available,
    }


def run_message_reflection_attack(num_rounds=NUM_ROUNDS, seed=SEED,
                                    pe_sample_size=PE_SAMPLE_SIZE):
    """
    V4 Attack: Charlie injects qubits and reflects Bob's PE message.
    1. Charlie generates own qubits from known key, sends to Bob as "Alice".
    2. Bob measures and prepares PE message with MAC(PSK).
    3. Charlie intercepts Bob's PE message + MAC.
    4. Charlie reflects the exact message + MAC back to Bob.
    5. Bob verifies reflected MAC (same PSK, no directionality) -> accepts.
    6. Bob compares reflected PE data against his own -> 0% QBER.
    7. Bob accepts session key derived from Charlie's injected qubits.

    Uses numpy-simulated BB84 encoding/measurement.

    Returns dict with charlie_key, bob_key, reflection_accepted,
    pe_qber_seen_by_bob, transcript.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)
    psk = "alice-bob-psk-v4"  # symmetric, no directionality
    transcript = []

    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()
        transcript.append({"note": "SeQUeNCe Timeline initialized for simulation context"})
    else:
        transcript.append({"note": "SeQUeNCe not available; using pure numpy simulation"})

    # Charlie generates his own key and encodes qubits for Bob
    charlie_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    charlie_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = _encode_qubit_numpy(charlie_bits[i], charlie_bases[i])
        bob_bits.append(_measure_qubit_numpy(q, bob_bases[i], rng))
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
        "sequence_available": seq_available,
    }
