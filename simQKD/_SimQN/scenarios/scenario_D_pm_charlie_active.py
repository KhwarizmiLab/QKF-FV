"""
V4: Message Reflection - Scenario D

PM-QKD topology with active Charlie who injects qubits and reflects PE messages.
"""

import random
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

SEED = 42
NUM_ROUNDS = 200
PE_SAMPLE_SIZE = 30


def _try_import():
    try:
        from qns.models.qubit.qubit import Qubit
        from qns.models.qubit.const import QUBIT_STATE_0
        from qns.models.qubit.gate import H, X
        return True, {"Qubit": Qubit, "QUBIT_STATE_0": QUBIT_STATE_0, "H": H, "X": X}
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


def run_honest_bb84_with_pe(num_rounds=NUM_ROUNDS, seed=SEED,
                             pe_sample_size=PE_SAMPLE_SIZE):
    """
    Honest BB84 with parameter estimation phase.
    Alice and Bob exchange PE samples with MAC-authenticated messages.

    Returns dict with alice_key, bob_key, match_rate, pe_qber.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    psk = "alice-bob-psk-honest"

    alice_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    alice_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = encode_qubit(alice_bits[i], alice_bases[i], qns)
        bob_bits.append(measure_qubit(q, bob_bases[i]))

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

    Returns dict with charlie_key, bob_key, reflection_accepted,
    pe_qber_seen_by_bob, transcript.
    """
    available, qns = _try_import()
    if not available:
        return {"error": "SimQN not available"}

    rng = random.Random(seed)
    psk = "alice-bob-psk-v4"  # symmetric, no directionality
    transcript = []

    # Charlie generates his own key and encodes qubits for Bob
    charlie_bits = [rng.randint(0, 1) for _ in range(num_rounds)]
    charlie_bases = [rng.randint(0, 1) for _ in range(num_rounds)]
    bob_bases = [rng.randint(0, 1) for _ in range(num_rounds)]

    bob_bits = []
    for i in range(num_rounds):
        q = encode_qubit(charlie_bits[i], charlie_bases[i], qns)
        bob_bits.append(measure_qubit(q, bob_bases[i]))
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
    }
