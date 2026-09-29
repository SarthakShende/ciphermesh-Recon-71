"""SHA-256 helpers.

The hash is always computed over *domain-separated* bytes: a short, fixed
prefix is prepended before hashing and before signing. Without this, a
signature produced here could be replayed into any other protocol that
happens to verify Ed25519 signatures over the same canonical bytes, because
Ed25519 signs a message, not a message type.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_bytes

#: Domain separator for event hashing and signing. Changing this invalidates
#: every previously signed event, so it is versioned and frozen.
EVENT_DOMAIN = b"CIPHERMESH-EVENT-v1\x00"

#: Bumping this changes every hash and signature without changing the event
#: schema. Distinct from ``constants.EVENT_VERSION``, which is the schema
#: version carried inside the signed payload.
HASH_ALGORITHM = "sha256"
HASH_LENGTH = 32


def sha256(data: bytes) -> bytes:
    """Raw SHA-256 digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_event_payload(payload: Any) -> str:
    """Hash a canonical event payload and return a hex digest.

    ``payload`` is canonicalized internally, so callers must pass the plain
    dict/list structure and never a pre-serialized string.
    """
    return sha256_hex(EVENT_DOMAIN + canonical_bytes(payload))


def verify_hash(payload: Any, expected_hex: str) -> bool:
    """Constant-time-ish comparison of a recomputed hash against a claim.

    The recomputation is authoritative: a receiver must never accept the
    hash carried on the wire, only one it derived itself. This helper exists
    so the fast pre-check and the authoritative check use identical code.
    """
    if not isinstance(expected_hex, str) or len(expected_hex) != HASH_LENGTH * 2:
        return False
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    computed = bytes.fromhex(hash_event_payload(payload))
    return _constant_time_equal(computed, expected)


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare digests without leaking their contents through timing."""
    import hmac

    return hmac.compare_digest(a, b)


def key_id(public_key_raw: bytes) -> str:
    """Short, stable identifier for a public key.

    The first 8 bytes of SHA-256 over the raw 32-byte Ed25519 public key.
    This travels in every wire packet so a receiver knows which key to
    verify against without carrying a full keyring in the payload.
    """
    if len(public_key_raw) != 32:
        raise ValueError(f"expected a 32-byte Ed25519 public key, got {len(public_key_raw)}")
    return sha256(public_key_raw)[:8].hex()


def fingerprint(public_key_raw: bytes) -> str:
    """Full-length SHA-256 of a public key, for display and lookup."""
    return sha256_hex(public_key_raw)
