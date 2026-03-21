"""
QKDNetSim KMS-layer authentication and relay scenarios.

Since QKDNetSim has no quantum-level simulation, these scenarios test
the KMS and key delivery interfaces for analogous vulnerabilities:

  - Key relay authentication (V2 analogue: identity binding at KMS level)
  - Message reflection at ETSI 004/014 API level (V4 analogue)
  - Key buffer manipulation and delivery timing

These scenarios operate on the classical/application layer only.
No qubit operations are involved.

Requires: ns-3 with QKDNetSim module (C++ simulation)
Fallback: Python-only simulation of KMS message flows
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.experiment_utils import compute_mac, verify_mac

SEED = 42

# KMS node identities
KMS_ALICE = "kms-alice"
KMS_BOB = "kms-bob"
KMS_RELAY = "kms-relay"

# PSK table for KMS authentication
PSK_TABLE = {
    (KMS_ALICE, KMS_BOB): "kms-ab-psk-2024",
    (KMS_ALICE, KMS_RELAY): "kms-ar-psk-2024",
    (KMS_RELAY, KMS_BOB): "kms-rb-psk-2024",
}


def check_qkdnetsim_available():
    """Check if QKDNetSim (ns-3) is available."""
    ns3_dir = os.environ.get("QKDNETSIM_NS3_DIR", "")
    return bool(ns3_dir and os.path.isdir(ns3_dir))


def simulate_etsi004_key_delivery(key_id, key_material, source_kms, dest_kms):
    """
    Simulate an ETSI GS QKD 004 key delivery request.
    Returns a key delivery response dict.
    """
    psk_key = PSK_TABLE.get((source_kms, dest_kms))
    if not psk_key:
        return {"status": "error", "reason": "no PSK for this KMS pair"}

    payload = json.dumps({"key_id": key_id, "key_material": key_material})
    mac_tag = compute_mac(psk_key, payload)

    return {
        "status": "ok",
        "key_id": key_id,
        "source": source_kms,
        "destination": dest_kms,
        "payload": payload,
        "mac": mac_tag,
    }


def simulate_kms_relay_misbinding():
    """
    V2 KMS analogue: Relay node re-tags key delivery messages.
    KMS-Relay intercepts key delivery between KMS-Alice and KMS-Bob,
    strips MAC and re-tags with its own PSK.

    Returns dict with relay_success, alice_accepts, bob_accepts.
    """
    key_id = "key-001"
    key_material = "abcdef1234567890"

    # Alice sends key delivery to Bob via relay
    alice_payload = json.dumps({"key_id": key_id, "key_material": key_material})
    alice_mac = compute_mac(PSK_TABLE[(KMS_ALICE, KMS_RELAY)], alice_payload)

    # Relay verifies from Alice
    relay_verifies_alice = verify_mac(
        PSK_TABLE[(KMS_ALICE, KMS_RELAY)], alice_payload, alice_mac
    )

    # Relay re-tags for Bob
    relay_mac_for_bob = compute_mac(PSK_TABLE[(KMS_RELAY, KMS_BOB)], alice_payload)

    # Bob verifies from relay
    bob_verifies = verify_mac(
        PSK_TABLE[(KMS_RELAY, KMS_BOB)], alice_payload, relay_mac_for_bob
    )

    # Bob thinks key came from relay (not Alice) -> identity misbinding
    return {
        "relay_verifies_alice": relay_verifies_alice,
        "bob_verifies_relay": bob_verifies,
        "relay_success": relay_verifies_alice and bob_verifies,
        "bob_binds_key_to": KMS_RELAY,  # not KMS_ALICE
        "identity_misbinding": True,
        "notes": [
            "QKDNetSim KMS-layer analogue of V2.",
            "Key relay node re-tags authentication on key delivery messages.",
            "Bob binds key to relay identity, not Alice's.",
            "No quantum channel involved; this is a KMS-layer vulnerability.",
        ],
    }


def simulate_kms_message_reflection():
    """
    V4 KMS analogue: Reflect Bob's key confirmation message back to him.
    Bob sends key confirmation with MAC, attacker reflects it.
    Bob accepts his own MAC (no directionality).

    Returns dict with reflection_accepted, notes.
    """
    psk = PSK_TABLE[(KMS_ALICE, KMS_BOB)]

    # Bob confirms key receipt
    confirmation = json.dumps({
        "key_id": "key-002",
        "status": "received",
        "sample_bits": [0, 1, 1, 0, 1],
    })
    bob_mac = compute_mac(psk, confirmation)

    # Attacker reflects Bob's message + MAC back to Bob
    reflected_msg = confirmation
    reflected_mac = bob_mac

    # Bob verifies (same PSK, no direction flag)
    bob_accepts = verify_mac(psk, reflected_msg, reflected_mac)

    return {
        "reflection_accepted": bob_accepts,
        "bob_accepts_own_message": bob_accepts,
        "directionality_binding": False,
        "notes": [
            "QKDNetSim KMS-layer analogue of V4.",
            "MAC on key confirmation lacks sender/receiver binding.",
            "Bob accepts his own reflected message as authentic.",
            "No quantum channel involved; this is a KMS-layer vulnerability.",
        ],
    }


def get_capability_summary():
    """Return a summary of what QKDNetSim can and cannot test."""
    return {
        "tool": "QKDNetSim",
        "quantum_layer": False,
        "kms_layer": True,
        "feasible_scenarios": {
            "A_eb_eve": False,
            "B_eb_charlie": False,
            "C_pm_eve": False,
            "D_pm_charlie": False,
        },
        "kms_analogues": {
            "V2_identity_misbinding": True,
            "V4_message_reflection": True,
        },
        "requires_ns3": True,
        "ns3_available": check_qkdnetsim_available(),
        "notes": [
            "QKDNetSim models KMS/key relay at the network layer.",
            "No qubit-level simulation; cannot intercept, store, or measure qubits.",
            "V1 (entanglement injection) and V3 (deferred measurement) require quantum operations.",
            "V2 and V4 can be tested at the KMS authentication layer.",
        ],
    }
