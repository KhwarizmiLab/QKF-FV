"""
Quditto scenario modules for QKD vulnerability testing.

Quditto is a NetSquid-based quantum digital twin platform that supports
PM-QKD (BB84) but not EB-QKD (no entanglement-based protocols).

Only Scenarios C and D are feasible:
  C: PM-QKD with passive Eve  (V3: Basis-Deferred Measurement)
  D: PM-QKD with active Charlie (V4: Message Reflection)

Scenarios A and B (EB-QKD) cannot be built in Quditto.
"""
