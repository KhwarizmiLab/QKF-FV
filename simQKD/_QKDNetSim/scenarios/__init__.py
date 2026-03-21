"""
QKDNetSim scenario modules for QKD vulnerability testing.

QKDNetSim operates at the KMS (Key Management System) layer and does NOT
model qubit-level transmission or interception. Scenarios A-D cannot be
directly replicated. Instead, we provide KMS-layer analogues that test
message authentication, key relay, and reflection at the application and
management layer.

Feasible:
  - KMS message relay and authentication scenarios
  - ETSI 004/014 key delivery interface testing

Not feasible:
  - Qubit interception (V1, V3)
  - Blind qubit relay (V2)
  - Qubit injection (V4)
"""
