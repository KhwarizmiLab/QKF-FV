"""
SeQUeNCe Scenario modules for QKD vulnerability testing.

SeQUeNCe is a discrete-event quantum network simulator with Timeline-based
simulation kernel. It provides BB84 via QKDNode and Barrett-Kok entanglement
generation, but no standalone EB-QKD (E91/BBM92) protocol.

Because SeQUeNCe's protocol internals are not easily hookable at the
individual qubit level, scenarios use numpy-simulated quantum operations
(Bell pairs, BB84 encoding/measurement) and optionally use SeQUeNCe's
Timeline for simulation context when available.

Scenarios A-D provide reusable topology setups and protocol runners:
  A: EB-QKD with passive Eve (V1: Subverted Entanglement Injection)
  B: EB-QKD with active Charlie (V2: Identity Misbinding)
  C: PM-QKD with passive Eve (V3: Basis-Deferred Measurement)
  D: PM-QKD with active Charlie (V4: Message Reflection)
"""
