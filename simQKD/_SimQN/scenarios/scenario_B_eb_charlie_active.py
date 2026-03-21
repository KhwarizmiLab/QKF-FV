"""
V2: Identity Misbinding - Scenario B

EB-QKD topology with active Charlie who blind-relays qubits and swaps MAC tags.
"""

import random
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

SEED = 42
NUM_ROUNDS = 200

# Pre-shared keys
PSK_AC = "alice-charlie-psk-2024"
PSK_CB = "charlie-bob-psk-2024"
PSK_AB = "alice-bob-psk-2024"  # expected but never used directly


def _try_import():
    try:
        from qns.models.qubit.qubit import Qubit
        from qns.models.qubit.const import QUBIT_STATE_0
        from qns.models.qubit.gate import H, CNOT, X, Z
        return True, {"Qubit": Qubit, "QUBIT_STATE_0": QUBIT_STATE_0,
                       "H": H, "CNOT": CNOT, "X": X, "Z": Z}
    except ImportError:
        return False, {}


def encode_qubit(bit, basis, qns):
    """Encode a classical bit into a qubit."""
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


def run_honest_eb_qkd(num_rounds=NUM_ROUNDS, seed=SEED):
    """
    Honest EB-QKD between Alice and Bob (no Charlie).
    Baseline for comparison.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)

    alice_bits, bob_bits = [], []
    alice_bases, bob_bases = [], []

    for _ in range(num_rounds):
        q0 = qns["Qubit"](state=qns["QUBIT_STATE_0"], name="q0")
        q1 = qns["Qubit"](state=qns["QUBIT_STATE_0"], name="q1")
        qns["H"](q0)
        qns["CNOT"](q0, q1)

        a_base = rng.randint(0, 1)
        b_base = rng.randint(0, 1)
        alice_bases.append(a_base)
        bob_bases.append(b_base)

        alice_bits.append(measure_qubit(q0, a_base))
        bob_bits.append(measure_qubit(q1, b_base))

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

    Returns dict with alice_key, bob_key, match_rate, mac_swap_success,
    identity_misbinding, transcript.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    transcript = []

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    # Quantum phase: Alice encodes, Charlie blind-relays to Bob
    bob_measurements = []
    for i in range(num_rounds):
        q = encode_qubit(alice_bits[i], alice_bases[i], qns)
        # Charlie forwards without measurement (blind relay)
        bob_measurements.append(measure_qubit(q, bob_bases[i]))
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
    }
