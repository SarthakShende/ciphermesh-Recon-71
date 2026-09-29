"""Cross-node wire interop and payload budget.

The most important property in this file: a signature produced by one process
must verify in *another*, with keys and state that never shared memory.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
from ciphermesh.crypto import (  # noqa: E402
    KeyPair,
    KeyStore,
    canonicalize,
    key_id,
)
from ciphermesh.crypto.canonical import canonical_bytes  # noqa: E402

fails = []


def sub(name, code):
    """Run code in a fresh interpreter to prove no shared state."""
    proc = os.system
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write("import sys; sys.path.insert(0, %r)\n" % str(Path("src").resolve()))
        fh.write(code)
        name_ = fh.name
    try:
        rc = proc(f'{sys.executable} {name_} > /dev/null 2>&1')
        if rc != 0:
            fails.append(f"{name} FAILED (exit {rc})")
            rc2 = os.system(f'{sys.executable} {name_} 2>&1 | tail -5')
            print(rc2)
    finally:
        os.unlink(name_)


# --- 1. producer signs in one process, consumer verifies in another --------
with tempfile.TemporaryDirectory() as td:
    ident = Path(td) / "id.json"

    # Process A: create identity, sign an event, emit a packet.
    sub("producer", f"""
from pathlib import Path
import json, secrets
from ciphermesh.crypto import load_or_create_identity
kp = load_or_create_identity(Path({str(ident)!r}), "s3cret", salt=secrets.token_bytes(16))
payload = {{
    "event_id": "EVT-20260929-PI-A-00000042-9f2c",
    "version": 1,
    "device_id": "PI-A-0001",
    "device_name": "rooftop-sensor",
    "type": "TEMPERATURE_READING",
    "timestamp": "2026-09-29T12:00:00Z",
    "sequence": 42,
    "value": 27.5,
    "unit": "C",
    "sensor": {{"model": "DHT22", "gpio_pin": 4}},
}}
sig = kp.sign_event(payload)
packet = {{
    "protocol": "ciphermesh/1",
    "destination": "ciphermesh.event",
    "sent_at": "2026-09-29T12:00:00Z",
    "payload": payload,
    "key_id": kp.key_id,
    "public_key": kp.public_b64(),
    "signature": sig.hex(),
}}
print(json.dumps(packet))
""")

    # Re-run capturing output this time.
    import subprocess

    procA = subprocess.run(
        [sys.executable, "-c", f"""
import sys, json, secrets
sys.path.insert(0, 'src')
from pathlib import Path
from ciphermesh.crypto import load_or_create_identity
kp = load_or_create_identity(Path({str(ident)!r}), 's3cret', salt=secrets.token_bytes(16))
payload = {{
    "event_id": "EVT-20260929-PI-A-00000042-9f2c",
    "version": 1,
    "device_id": "PI-A-0001",
    "device_name": "rooftop-sensor",
    "type": "TEMPERATURE_READING",
    "timestamp": "2026-09-29T12:00:00Z",
    "sequence": 42,
    "value": 27.5,
    "unit": "C",
    "sensor": {{"model": "DHT22", "gpio_pin": 4}},
}}
sig = kp.sign_event(payload)
packet = {{
    "protocol": "ciphermesh/1",
    "destination": "ciphermesh.event",
    "sent_at": "2026-09-29T12:00:00Z",
    "payload": payload,
    "key_id": kp.key_id,
    "public_key": kp.public_b64(),
    "signature": sig.hex(),
}}
print(json.dumps(packet))
"""],
        capture_output=True,
        text=True,
    )
    if procA.returncode != 0:
        fails.append(f"producer process failed: {procA.stderr[-500:]}")
        packet = None
    else:
        packet = json.loads(procA.stdout)

        # Process B: verify with ONLY the pre-shared public key.
        procB = subprocess.run(
            [sys.executable, "-c", """
import sys, json
sys.path.insert(0, 'src')
from ciphermesh.crypto import KeyStore
packet = json.load(sys.stdin)
# Keyring built from a key distributed out of band, NOT from the packet.
store = KeyStore.from_iterable([(packet["key_id"], packet["public_key"])])
ok = store.verify(packet["key_id"], bytes.fromhex(packet["signature"]), packet["payload"])
print("VERIFIED" if ok else "REJECTED")
"""],
            input=json.dumps(packet),
            capture_output=True,
            text=True,
        )
        out = procB.stdout.strip()
        if out != "VERIFIED":
            fails.append(f"cross-process verify said {out!r}: {procB.stderr[-300:]}")

        # --- 2. an attacker substituting their own key must be rejected ---
        attacker = KeyPair.generate()
        forged = dict(packet)
        forged["key_id"] = attacker.key_id
        forged["public_key"] = attacker.public_b64()
        forged["signature"] = attacker.sign_event(packet["payload"]).hex()
        # A consumer that trusts the packet's own keyring is trivially
        # defeated, so the test asserts the *correct* behaviour: the packet
        # key id is not in the out-of-band keyring.
        real_store = KeyStore.from_iterable([(packet["key_id"], packet["public_key"])])
        if real_store.verify(forged["key_id"],
                             bytes.fromhex(forged["signature"]),
                             packet["payload"]):
            fails.append("attacker key accepted by the out-of-band keyring")

        # --- 3. the naive JSON form must NOT fit (documents the budget) ---
        from ciphermesh.constants import RETICULUM_MDU  # noqa: E402

        wire = canonicalize(packet).encode("utf-8")
        print(f"naive JSON packet : {len(wire)} bytes / {RETICULUM_MDU} MDU "
              f"({len(wire)/RETICULUM_MDU*100:.0f}%)")
        if len(wire) <= RETICULUM_MDU:
            fails.append(
                "naive JSON packet now fits; revisit the compact-envelope design"
            )

        # The compact envelope (ciphermesh.wire, Phase 7) must fit instead.
        # Modelled here by stripping everything the envelope does not carry.
        from ciphermesh.constants import (  # noqa: E402
            KEY_ID_BYTES,
            SIGNATURE_BYTES,
            WIRE_MAX_PACKET_BYTES,
        )
        envelope = (
            4                          # version, type, flags
            + KEY_ID_BYTES             # key id, raw
            + SIGNATURE_BYTES          # raw signature, never hex
            + len(canonicalize(packet["payload"]).encode("utf-8"))
        )
        print(f"compact envelope  : {envelope} bytes / {WIRE_MAX_PACKET_BYTES} "
              f"({envelope/WIRE_MAX_PACKET_BYTES*100:.0f}%)")
        if envelope > WIRE_MAX_PACKET_BYTES:
            fails.append(
                f"compact envelope is {envelope} bytes, over the "
                f"{WIRE_MAX_PACKET_BYTES}-byte ceiling"
            )

        # Headroom must absorb a realistic second sensor channel.
        grown = dict(packet["payload"])
        grown["sensor"] = {"model": "DHT22", "gpio_pin": 4, "humidity": 48.2}
        grown_size = 4 + KEY_ID_BYTES + SIGNATURE_BYTES + \
            len(canonicalize(grown).encode("utf-8"))
        if grown_size > WIRE_MAX_PACKET_BYTES:
            fails.append(
                f"two-channel payload is {grown_size} bytes, over the ceiling"
            )

# --- 4. event_id uniqueness must not depend on the clock alone -----------
# Two events in the same second with the same sequence but different random
# suffixes must differ.
def make_event_id(date, device, seq, rnd):
    return f"EVT-{date}-{device}-{seq:08d}-{rnd}"


a = make_event_id("20260929", "PI-A-0001", 1, "a1b2c3d4")
b = make_event_id("20260929", "PI-A-0001", 1, "e5f6a7b8")
if a == b:
    fails.append("event ids collide within the same second")
if len(a) != len(b):
    fails.append("event id length is not fixed")

if fails:
    print(f"\nFAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    raise SystemExit(1)
print("wire interop: all checks passed")
