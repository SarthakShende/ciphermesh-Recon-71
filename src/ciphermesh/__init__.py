"""CipherMesh Edge - hardware-rooted decentralized IoT trust network agent.

This package runs on a Raspberry Pi 4B and implements the PI-A (gateway /
sensor node) and PI-B (receiver node) roles from a single codebase. The role
is chosen at install time and is the only behavioural difference between the
two devices.
"""

__version__ = "1.0.0"

# Bumped whenever the canonical event representation changes in a way that
# would invalidate previously generated signatures. This is NOT the same as
# the event schema version (see constants.EVENT_VERSION).
CANONICALIZATION_VERSION = 1

__all__ = ["__version__", "CANONICALIZATION_VERSION"]
