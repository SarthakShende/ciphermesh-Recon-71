"""Security-relevant checks for the crypto layer.

These are not unit tests of coverage; each one asserts a property that, if
it broke, would silently weaken the trust model.
"""

import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
from ciphermesh.crypto import (  # noqa: E402
    KeyPair,
    KeyStore,
    canonicalize,
    hash_event_payload,
    key_id,
    load_or_create_identity,
    read_identity,
    verify_event,
    verify_hash,
)
from ciphermesh.errors import CryptoError, IdentityError  # noqa: E402

fails = []


def expect_raises(exc, fn, label):
    try:
        fn()
    except exc:
        return
    except Exception as e:  # noqa: BLE001
        fails.append(f"{label}: raised {type(e).__name__} not {exc.__name__}: {e}")
        return
    fails.append(f"{label}: did not raise {exc.__name__}")


PAYLOAD = {
    "event_id": "EVT-20260929-PI-A-00000001-a1b2",
    "version": 1,
    "device_id": "PI-A-0001",
    "type": "TEMPERATURE_READING",
    "timestamp": "2026-09-29T12:00:00Z",
    "value": 27.5,
    "unit": "C",
    "sequence": 1,
}

# --- 1. sign/verify round trip --------------------------------------------
kp = KeyPair.generate()
sig = kp.sign_event(PAYLOAD)
if not verify_event(kp.public_raw, sig, PAYLOAD):
    fails.append("valid signature failed to verify")

# --- 2. tamper detection: every field must matter -------------------------
for field, mutated in [
    ("value", 27.6),
    ("timestamp", "2026-09-29T12:00:01Z"),
    ("device_id", "PI-A-0002"),
    ("type", "HUMIDITY_READING"),
    ("sequence", 2),
    ("event_id", "EVT-20260929-PI-A-00000002-a1b2"),
]:
    bad = dict(PAYLOAD)
    bad[field] = mutated
    if verify_event(kp.public_raw, sig, bad):
        fails.append(f"tampered field {field!r} still verified")

# --- 3. key insertion (drop a field) must break the signature -------------
dropped = dict(PAYLOAD)
del dropped["unit"]
if verify_event(kp.public_raw, sig, dropped):
    fails.append("payload with a removed field still verified")

# --- 4. a different key must not verify -----------------------------------
other = KeyPair.generate()
if verify_event(other.public_raw, sig, PAYLOAD):
    fails.append("signature verified under the wrong public key")

# --- 5. malformed signatures are rejected, not raised ----------------------
for bad_sig in [b"", b"\x00" * 64, sig[:-1] + bytes([sig[-1] ^ 1])]:
    if verify_event(kp.public_raw, bad_sig, PAYLOAD):
        fails.append("malformed signature verified")

expect_raises(CryptoError, lambda: verify_event(b"short", sig, PAYLOAD),
              "short public key")

# --- 6. domain separation: signature must not transfer to raw bytes -------
# If signing() had omitted the domain prefix, this same signature would
# verify over the bare canonical JSON and could be replayed elsewhere.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from ciphermesh.crypto.canonical import canonical_bytes  # noqa: E402

try:
    Ed25519PublicKey.from_public_bytes(kp.public_raw).verify(sig, canonical_bytes(PAYLOAD))
    fails.append("SIGNATURE IS NOT DOMAIN SEPARATED: verified over bare canonical bytes")
except Exception:
    pass

# --- 7. hash integrity ------------------------------------------------------
h = hash_event_payload(PAYLOAD)
if not verify_hash(PAYLOAD, h):
    fails.append("hash did not verify against itself")
if verify_hash({**PAYLOAD, "value": 99.9}, h):
    fails.append("hash verified against modified payload")
if verify_hash(PAYLOAD, "not-hex"):
    fails.append("hash verified against non-hex input")
if verify_hash(PAYLOAD, "ab"):
    fails.append("hash verified against truncated hex")

# --- 8. canonical form is stable regardless of dict order -----------------
reordered = {k: PAYLOAD[k] for k in sorted(PAYLOAD, reverse=True)}
if hash_event_payload(reordered) != h:
    fails.append("hash depends on dict insertion order")
if hash_event_payload(PAYLOAD) != hash_event_payload(reordered):
    fails.append("hash not order-independent")

# --- 9. keystore: untrusted key in packet must not verify ------------------
store = KeyStore({kp.key_id: kp.public_raw})
if not store.verify(kp.key_id, sig, PAYLOAD):
    fails.append("keystore rejected a trusted key")
if store.verify(other.key_id, sig, PAYLOAD):
    fails.append("keystore accepted an untrusted key id")
if store.verify("deadbeefdeadbeef", sig, PAYLOAD):
    fails.append("keystore accepted an unknown key id")

# --- 10. revocation --------------------------------------------------------
revoked = store.with_revoked([kp.key_id])
if revoked.verify(kp.key_id, sig, PAYLOAD):
    fails.append("revoked key still verified")
if kp.key_id in revoked:
    fails.append("revoked key still reported as present")

# --- 11. keystore id mismatch on load is rejected -------------------------
expect_raises(
    IdentityError,
    lambda: KeyStore.from_iterable([("deadbeefdeadbeef", kp.public_b64())]),
    "keystore id mismatch",
)

# --- 12. identity file contains no usable secret ---------------------------
with tempfile.TemporaryDirectory() as td:
    ident = Path(td) / "identity.json"
    salt = secrets.token_bytes(16)
    kp2 = load_or_create_identity(ident, "correct horse battery staple", salt=salt)
    raw = ident.read_text()
    if "private" in raw.lower() or "seed" in raw.lower():
        fails.append(f"identity file mentions a private secret: {raw!r}")
    # The whole file must not contain the 32-byte seed in any encoding.
    from cryptography.hazmat.primitives import serialization
    seed = kp2.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    import base64
    if seed.hex() in raw or base64.b64encode(seed).decode() in raw:
        fails.append("identity file leaks the derived private seed")

    # --- 13. permissions enforced at creation -----------------------------
    m = stat.S_IMODE(ident.stat().st_mode)
    if m != 0o600:
        fails.append(f"identity file mode is {oct(m)}, expected 0o600")
    dm = stat.S_IMODE(ident.parent.stat().st_mode)
    if dm != 0o700:
        fails.append(f"identity dir mode is {oct(dm)}, expected 0o700")

    # --- 14. determinism: same passphrase+salt -> same key ---------------
    kp2b = load_or_create_identity(ident, "correct horse battery staple")
    if kp2b.key_id != kp2.key_id:
        fails.append("same passphrase+salt produced a different key")
    if kp2b.public_raw != kp2.public_raw:
        fails.append("same passphrase+salt produced a different public key")

    # --- 15. wrong passphrase detected, not silently accepted -------------
    expect_raises(
        IdentityError,
        lambda: load_or_create_identity(ident, "wrong passphrase"),
        "wrong passphrase",
    )

    # --- 16. tampered identity file (key_id vs public_key) is rejected ----
    tampered = Path(td) / "tampered.json"
    tampered.write_text(raw.replace(f"key_id {kp2.key_id}", "key_id " + "0" * 16))
    os.chmod(tampered, 0o600)
    expect_raises(IdentityError, lambda: read_identity(tampered), "inconsistent key_id")

    # --- 17. world-readable identity file is refused ----------------------
    loose = Path(td) / "loose.json"
    loose.write_text(raw)
    os.chmod(loose, 0o644)
    expect_raises(IdentityError, lambda: read_identity(loose), "loose permissions")

    # --- 18. missing identity file gives an actionable error -------------
    expect_raises(
        IdentityError,
        lambda: read_identity(Path(td) / "nope.json"),
        "missing identity",
    )

    # --- 19. key_id is 8 bytes of sha256 over the raw key ---------------
    import hashlib
    expect = hashlib.sha256(kp.public_raw).hexdigest()[:16]
    if kp.key_id != expect:
        fails.append(f"key_id {kp.key_id} != expected {expect}")
    if len(kp.key_id) != 16:
        fails.append(f"key_id is {len(kp.key_id)} chars, expected 16")

# --- 20. sign is deterministic (Ed25519 is not randomized) ---------------
if kp.sign_event(PAYLOAD) != kp.sign_event(PAYLOAD):
    fails.append("Ed25519 signing is not deterministic; replay protection must not rely on it")

# --- 21. non-JSON types rejected in signed payload -----------------------
import datetime  # noqa: E402
expect_raises(Exception, lambda: kp.sign_event({"t": datetime.datetime.now()}),
              "datetime in payload")
expect_raises(Exception, lambda: kp.sign_event({"d": {1, 2}}), "set in payload")
expect_raises(Exception, lambda: kp.sign_event({"n": float("nan")}), "NaN in payload")

# --- 22. NaN cannot be smuggled in via float equality ---------------------
# NaN != NaN, so a naive "payload unchanged" check would pass a mutated NaN.
try:
    bad = dict(PAYLOAD)
    bad["value"] = float("nan")
    kp.sign_event(bad)
    fails.append("NaN was accepted into a signed payload")
except CryptoError:
    pass

if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    raise SystemExit(1)
print(f"crypto: all security properties hold ({len(fails) == 0})")
