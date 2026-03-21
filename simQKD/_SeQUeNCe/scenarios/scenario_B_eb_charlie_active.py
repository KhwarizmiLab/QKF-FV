"""
Scenario B: Entanglement-Based QKD with Active Charlie (MitM)
==============================================================
Topology:
  - Nodes: Alice, Bob, Charlie (attacker)
  - Quantum: Alice -> Charlie -> Bob (Charlie blind-relays qubits)
  - Classical: Alice <-> Charlie (PSK_AC), Charlie <-> Bob (PSK_CB)
  - Expected: Alice <-> Bob (PSK_AB) but Charlie mediates

Charlie capabilities:
  - Blind relay of quantum states (no measurement, no disturbance)
  - Terminate independent classical sessions with Alice and Bob
  - Strip and re-tag MAC on classical messages (PSK swap)
  - Alice and Bob each bind the key to Charlie's identity

Maps to V2: Identity Misbinding

Note: SeQUeNCe does not provide a standalone EB-QKD protocol (E91/BBM92).
We use numpy-simulated quantum operations for BB84 encoding/measurement
and optionally use SeQUeNCe's Timeline for simulation context.
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

# Pre-shared keys
PSK_AC = "alice-charlie-psk-2024"
PSK_CB = "charlie-bob-psk-2024"
PSK_AB = "alice-bob-psk-2024"  # present for completeness; not used in the attack


def _try_import_sequence():
    """Check if SeQUeNCe is importable and return Timeline if available."""
    try:
        from sequence.kernel.timeline import Timeline
        return True, {"Timeline": Timeline}
    except ImportError:
        return False, {}


def _encode_qubit_numpy(bit, basis, rng):
    """
    Simulate BB84 encoding using numpy.
    Returns a dict representing the qubit state.
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


def run_honest_eb_qkd(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest EB-QKD between Alice and Bob (no Charlie).
    Baseline for comparison.

    Uses numpy-simulated Bell pairs.

    Returns dict with alice_key, bob_key, match_rate, sifted_length.
    """
    seq_available, seq = _try_import_sequence()
    rng = random.Random(seed)

    tl = None
    if seq_available:
        tl = seq["Timeline"]()
        tl.init()

    alice_bits, bob_bits = [], []
    alice_bases, bob_bases = [], []

    for _ in range(num_rounds):
        # Simulate Bell pair: shared random bit
        shared_bit = rng.randint(0, 1)

        a_base = rng.randint(0, 1)
        b_base = rng.randint(0, 1)
        alice_bases.append(a_base)
        bob_bases.append(b_base)

        # Z basis: anti-correlated; X basis: correlated
        if a_base == 0:
            alice_bits.append(shared_bit)
        else:
            alice_bits.append(shared_bit)

        if b_base == 0:
            bob_bits.append(1 - shared_bit)  # anti-correlated in Z
        else:
            if a_base == b_base:
                bob_bits.append(shared_bit)  # correlated in X when same basis
            else:
                bob_bits.append(rng.randint(0, 1))  # different basis -> random

    alice_key, bob_key = [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_key.append(alice_bits[i])
            bob_key.append(1 - bob_bits[i] if alice_bases[i] == 0 else bob_bits[i])

    match = sum(1 for a, b in zip(alice_key, bob_key) if a == b)
    rate = match / len(alice_key) if alice_key else 0.0

    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "match_rate": rate, "sifted_length": len(alice_key),
        "sequence_available": seq_available,
    }


def run_charlie_misbinding_attack(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    V2 Attack: Charlie performs identity misbinding.
    1. Alice encodes qubits for EB-QKD session (thinking she talks to Bob).
    2. Charlie blind-relays qubits to Bob (no measurement -> no disturbance).
    3. Alice sends basis announcement + MAC(PSK_AC).
    4. Charlie strips MAC, re-tags with MAC(PSK_CB), forwards to Bob.
    5. Bob sends basis + MAC(PSK_CB) back.
    6. Charlie strips, re-tags with MAC(PSK_AC), forwards to Alice.
    7. Alice and Bob derive matching key but each binds it to Charlie's identity.

    Uses numpy-simulated BB84 encoding for the quantum phase.

    Returns dict with alice_key, bob_key, match_rate, mac_swap_success,
    identity_misbinding, transcript.
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

    # Quantum phase: Alice encodes, Charlie blind-relays to Bob
    bob_measurements = []
    for i in range(num_rounds):
        q = _encode_qubit_numpy(alice_bits[i], alice_bases[i], rng)
        # Charlie forwards without measurement (blind relay)
        bob_measurements.append(_measure_qubit_numpy(q, bob_bases[i], rng))
        transcript.append({
            "round": i, "phase": "quantum",
            "charlie_action": "blind_relay", "qubit_disturbed": False,
        })

    # Classical phase: Alice sends bases with MAC(PSK_AC)
    alice_bases_msg = json.dumps(alice_bases)
    alice_mac_ac = compute_mac(PSK_AC, alice_bases_msg)

    # Charlie intercepts, verifies with PSK_AC, re-tags with PSK_CB
    charlie_verifies_alice = verify_mac(PSK_AC, alice_bases_msg, alice_mac_ac)
    charlie_retag_for_bob = compute_mac(PSK_CB, alice_bases_msg)

    # Bob verifies with PSK_CB
    bob_verifies_alice_bases = verify_mac(PSK_CB, alice_bases_msg, charlie_retag_for_bob)

    # Bob sends bases with MAC(PSK_CB)
    bob_bases_msg = json.dumps(bob_bases)
    bob_mac_cb = compute_mac(PSK_CB, bob_bases_msg)

    # Charlie intercepts, verifies with PSK_CB, re-tags with PSK_AC
    charlie_verifies_bob = verify_mac(PSK_CB, bob_bases_msg, bob_mac_cb)
    charlie_retag_for_alice = compute_mac(PSK_AC, bob_bases_msg)

    # Alice verifies with PSK_AC
    alice_verifies_bob_bases = verify_mac(PSK_AC, bob_bases_msg, charlie_retag_for_alice)

    mac_swap_success = all([
        charlie_verifies_alice, bob_verifies_alice_bases,
        charlie_verifies_bob, alice_verifies_bob_bases,
    ])

    transcript.append({
        "phase": "classical_mac_swap",
        "charlie_verifies_alice": charlie_verifies_alice,
        "bob_verifies_retagged": bob_verifies_alice_bases,
        "charlie_verifies_bob": charlie_verifies_bob,
        "alice_verifies_retagged": alice_verifies_bob_bases,
        "mac_swap_success": mac_swap_success,
    })

    # Sift keys
    alice_key, bob_key = [], []
    for i in range(num_rounds):
        if alice_bases[i] == bob_bases[i]:
            alice_key.append(alice_bits[i])
            bob_key.append(bob_measurements[i])

    match = sum(1 for a, b in zip(alice_key, bob_key) if a == b)
    rate = match / len(alice_key) if alice_key else 0.0

    # Identity misbinding: Alice thinks she shares key with Charlie (not Bob)
    # Bob thinks he shares key with Charlie (not Alice)
    identity_misbinding = mac_swap_success and rate > 0.90

    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "match_rate": rate, "sifted_length": len(alice_key),
        "mac_swap_success": mac_swap_success,
        "identity_misbinding": identity_misbinding,
        "alice_binds_to": "Charlie" if mac_swap_success else "Bob",
        "bob_binds_to": "Charlie" if mac_swap_success else "Alice",
        "attack_detected": False,  # QBER ~ 0 since blind relay
        "transcript": transcript,
        "sequence_available": seq_available,
    }
