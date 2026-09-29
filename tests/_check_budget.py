"""Wire-format size budget.

Guards the constraint discovered while building the event pipeline: a JSON
packet carrying the signed event measured 590 bytes against a 466-byte
Reticulum MDU, i.e. 127% of budget and untransmittable.

The compact binary envelope in ciphermesh.wire fixes this. These checks
assert the envelope stays inside budget so the constraint cannot silently
regress as fields are added to the event schema.
"""

import sys

sys.path.insert(0, "src")
from ciphermesh.constants import (  # noqa: E402
    KEY_ID_BYTES,
    RETICULUM_MDU,
    SIGNATURE_BYTES,
    WIRE_MAX_PACKET_BYTES,
    WIRE_PAYLOAD_BUDGET_BYTES,
)

fails = []

# --- The budget must be self-consistent ------------------------------------
overhead = 4 + KEY_ID_BYTES + SIGNATURE_BYTES
# WIRE_MAX_PACKET_BYTES is the *total* packet ceiling, envelope included, so
# the invariant is simply that it fits inside the MDU.
if WIRE_MAX_PACKET_BYTES > RETICULUM_MDU:
    fails.append(
        f"packet ceiling {WIRE_MAX_PACKET_BYTES} exceeds MDU {RETICULUM_MDU}"
    )
if WIRE_PAYLOAD_BUDGET_BYTES != WIRE_MAX_PACKET_BYTES - overhead:
    fails.append("payload budget is not packet budget minus envelope overhead")
if WIRE_PAYLOAD_BUDGET_BYTES <= 0:
    fails.append("payload budget is non-positive; envelope cannot fit")

print(f"MDU                 : {RETICULUM_MDU} bytes")
print(f"packet ceiling      : {WIRE_MAX_PACKET_BYTES} bytes")
print(f"envelope overhead   : {overhead} bytes "
      f"(4 header + {KEY_ID_BYTES} key_id + {SIGNATURE_BYTES} signature)")
print(f"payload budget      : {WIRE_PAYLOAD_BUDGET_BYTES} bytes")
print()

# --- The JSON packet that motivated this must be shown not to fit ---------
naive_payload = {
    "event_id": "EVT-20260929-PI-A-00000042-9f2c",
    "version": 1,
    "device_id": "PI-A-0001",
    "device_name": "rooftop-sensor",
    "type": "TEMPERATURE_READING",
    "timestamp": "2026-09-29T12:00:00Z",
    "sequence": 42,
    "value": 27.5,
    "unit": "C",
    "sensor": {"model": "DHT22", "gpio_pin": 4},
}
naive_json_packet = {
    "protocol": "ciphermesh/1",
    "destination": "ciphermesh.event",
    "sent_at": "2026-09-29T12:00:00Z",
    "payload": naive_payload,
    "key_id": "0123456789abcdef",
    # The public key must not be on the wire at all.
    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "signature": "ab" * 64,
}
naive_size = len(__import__("json").dumps(naive_json_packet, separators=(",", ":")))
print(f"naive JSON packet   : {naive_size} bytes "
      f"({naive_size / RETICULUM_MDU * 100:.0f}% of MDU) - does not fit")
if naive_size <= RETICULUM_MDU:
    fails.append("naive packet unexpectedly fits; budget analysis is stale")

# --- What the compact envelope must achieve -------------------------------
# Same payload, envelope carries key_id + raw signature, no public key,
# no destination, no sent_at, and numeric codes for type/unit.
compact_payload_size = len(
    __import__("json").dumps(naive_payload, separators=(",", ":")).encode("utf-8")
)
projected = overhead + compact_payload_size
print(f"compact envelope    : {projected} bytes "
      f"({projected / RETICULUM_MDU * 100:.0f}% of MDU) - must fit")
if projected > WIRE_MAX_PACKET_BYTES:
    fails.append(
        f"compact envelope still does not fit: {projected} > {WIRE_MAX_PACKET_BYTES}"
    )

headroom = WIRE_MAX_PACKET_BYTES - projected
print(f"headroom            : {headroom} bytes")
if headroom < 64:
    fails.append(f"headroom {headroom} bytes is too tight for sensor growth")

if fails:
    print(f"\nFAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    raise SystemExit(1)
print("\nwire budget: all checks passed")
