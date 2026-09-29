"""The signed event model.

An :class:`Event` is the *content*; a :class:`SignedEvent` is the content plus
the bytes that authenticate it. Splitting them keeps it impossible to
accidentally treat an unsigned event as if it had been verified.

The signed payload is exactly :meth:`Event.canonical_payload` - a plain dict
that goes through RFC 8785 canonical JSON with the ``CIPHERMESH-EVENT-v1``
domain separator applied. Two rules make the signature meaningful:

* **The signed field set is fixed and explicit.** It is a method, not
  ``self.__dict__``, so adding an attribute to the dataclass does not silently
  start covering it, and a hand-edited event cannot smuggle an extra key past
  the hash.
* **Absent is not the same as null.** Optional fields are omitted from the
  payload rather than serialised as ``null``. That keeps the common case
  smaller on a 464-byte MDU and keeps the canonical form stable when an
  optional field is not set.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..constants import EVENT_VERSION, EventType, Unit
from ..crypto import canonical_bytes, hash_event_payload, verify_event
from ..crypto.hashing import key_id as compute_key_id
from ..errors import EventValidationError

#: Event ids are operator-visible and travel over LoRa, so the charset is
#: restricted to what survives every hop and every log formatter.
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

#: Longest event id this implementation will accept on the wire. The format
#: says 128; anything longer is a protocol violation, not a long name.
MAX_EVENT_ID_LENGTH = 128

__all__ = [
    "MAX_EVENT_ID_LENGTH",
    "Event",
    "SignedEvent",
    "format_timestamp",
    "parse_timestamp",
]


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def format_timestamp(when: datetime | float | int | None = None) -> str:
    """Render a UTC timestamp in the one format the wire accepts.

    Second resolution is deliberate. The signed ``sequence`` is the ordering
    authority, so sub-second precision would add bytes without adding
    information a receiver can rely on.
    """
    if when is None:
        when = datetime.now(timezone.utc)
    elif isinstance(when, (int, float)):
        when = datetime.fromtimestamp(when, tz=timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(text: str) -> datetime:
    """Parse a timestamp produced by :func:`format_timestamp`.

    Raises :class:`EventValidationError` rather than ``ValueError`` so a
    malformed field on the wire is reported with the same type as every other
    schema failure.
    """
    if not isinstance(text, str) or not _TIMESTAMP_RE.match(text):
        raise EventValidationError(
            f"timestamp must be UTC ISO-8601 like '2026-09-29T12:00:00Z', got {text!r}"
        )
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EventValidationError(f"timestamp {text!r} is not a real instant") from exc


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Event:
    """One observation, before signing.

    Construct through :class:`~ciphermesh.events.factory.EventFactory` rather
    than directly: the factory owns id rendering, value rounding and sequence
    allocation, and bypassing it is how an event ends up with a value that
    does not match what the operator will see.
    """

    event_id: str
    device_id: str
    event_type: EventType
    value: float
    unit: Unit
    sequence: int
    timestamp: str
    version: int = EVENT_VERSION
    device_name: str | None = None
    location: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not _EVENT_ID_RE.match(self.event_id):
            raise EventValidationError(
                "event_id must be 1-128 characters from [A-Za-z0-9._:-], "
                f"got {self.event_id!r}"
            )
        if not isinstance(self.device_id, str) or not _DEVICE_ID_RE.match(self.device_id):
            raise EventValidationError(f"device_id is malformed: {self.device_id!r}")
        if not isinstance(self.event_type, EventType):
            raise EventValidationError(f"event_type must be an EventType, got {self.event_type!r}")
        if not isinstance(self.unit, Unit):
            raise EventValidationError(f"unit must be a Unit, got {self.unit!r}")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise EventValidationError(f"value must be a number, got {self.value!r}")
        if not math.isfinite(self.value):
            # NaN and +/-Inf both break canonical JSON, and a NaN comparison
            # always says "unchanged", so a range check written the obvious way
            # would pass it.
            raise EventValidationError(f"value must be finite, got {self.value!r}")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise EventValidationError(f"sequence must be an integer, got {self.sequence!r}")
        if self.sequence < 0:
            raise EventValidationError(f"sequence must not be negative, got {self.sequence}")
        if self.version < 1:
            raise EventValidationError(f"version must be at least 1, got {self.version}")
        # Raises EventValidationError if malformed; the value is not stored, so
        # parse_timestamp is used purely as a validator.
        parse_timestamp(self.timestamp)

    # -- serialisation ------------------------------------------------------

    def canonical_payload(self) -> dict[str, Any]:
        """The exact dict that is hashed and signed.

        The order here is irrelevant - canonical JSON sorts keys - but the
        *key set* is not. Optional fields are omitted when unset.
        """
        payload: dict[str, Any] = {
            "event_id": self.event_id,
            "version": self.version,
            "device_id": self.device_id,
            "type": self.event_type.value,
            "timestamp": self.timestamp,
            "value": self.value,
            "unit": self.unit.value,
            "sequence": self.sequence,
        }
        if self.device_name is not None:
            payload["device_name"] = self.device_name
        if self.location is not None:
            payload["location"] = self.location
        return payload

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.canonical_payload())

    def to_dict(self) -> dict[str, Any]:
        """Full representation for storage and the local API.

        Includes the computed ``hash`` so a stored row can be compared without
        recomputing, but the hash is *not* part of the signed payload - it is
        derived from it.
        """
        payload = self.canonical_payload()
        payload["event_hash"] = self.hash()
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        """Parse an event from a wire or storage dict, strictly.

        Unknown keys are rejected. This is the boundary where a future field
        could otherwise be introduced by a peer and silently ignored, leaving
        this node verifying a payload that is not the one it will store.
        """
        if not isinstance(data, dict):
            raise EventValidationError(f"event must be an object, got {type(data).__name__}")

        known = {
            "event_id", "version", "device_id", "type", "timestamp",
            "value", "unit", "sequence", "device_name", "location", "event_hash",
        }
        extra = set(data) - known
        if extra:
            raise EventValidationError(f"unknown event fields: {sorted(extra)}")

        missing = {"event_id", "device_id", "type", "timestamp", "value", "unit", "sequence"} - set(data)
        if missing:
            raise EventValidationError(f"event is missing fields: {sorted(missing)}")

        value = data["value"]
        if isinstance(value, str):
            # A peer that sends the number as a string is a protocol error, not
            # something to coerce: "27.5" and 27.5 canonicalize differently, so
            # accepting it would create two hashes for one event.
            raise EventValidationError("value must be a JSON number, not a string")

        try:
            event_type = EventType(data["type"])
            unit = Unit(data["unit"])
        except ValueError as exc:
            raise EventValidationError(str(exc)) from exc

        version = data.get("version", EVENT_VERSION)
        if not isinstance(version, int) or isinstance(version, bool):
            raise EventValidationError(f"version must be an integer, got {version!r}")

        return cls(
            event_id=data["event_id"],
            device_id=data["device_id"],
            event_type=event_type,
            value=value,
            unit=unit,
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            version=version,
            device_name=data.get("device_name"),
            location=data.get("location"),
        )

    # -- derived ------------------------------------------------------------

    def hash(self) -> str:
        """SHA-256 over the domain-separated canonical payload."""
        return hash_event_payload(self.canonical_payload())

    @property
    def signed_at(self) -> datetime:
        return parse_timestamp(self.timestamp)

    def age_seconds(self, now: datetime | None = None) -> float:
        reference = now or datetime.now(timezone.utc)
        return (reference - self.signed_at).total_seconds()

    def sign(self, private_key) -> SignedEvent:
        """Sign with an :class:`~ciphermesh.crypto.KeyPair` or an identity manager."""
        payload = self.canonical_payload()
        signature = private_key.sign_event(payload)
        return SignedEvent(
            event=self,
            signature=signature,
            key_id=compute_key_id(private_key.public_raw),
        )


# ---------------------------------------------------------------------------
# Signed event
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignedEvent:
    """An :class:`Event` plus its Ed25519 signature.

    Construction alone proves nothing: the signature has to be checked against
    a key the *receiver* already trusts. :meth:`verify` takes that key
    explicitly and never falls back to one carried in the message.
    """

    event: Event
    signature: bytes
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise EventValidationError(
                "signature must be 64 raw bytes, got "
                f"{len(self.signature) if isinstance(self.signature, bytes) else type(self.signature).__name__}"
            )
        if not isinstance(self.key_id, str) or len(self.key_id) != 16:
            raise EventValidationError(
                f"key_id must be 16 hex characters, got {self.key_id!r}"
            )

    # -- verification -------------------------------------------------------

    def verify(self, public_key: bytes) -> bool:
        """Verify against a public key the caller already trusts."""
        return verify_event(public_key, self.signature, self.event.canonical_payload())

    def verify_with(self, keystore) -> bool:
        """Verify against a :class:`~ciphermesh.crypto.KeyStore`.

        Returns False for an unknown or revoked key id. It never raises, so a
        hostile packet cannot turn into an unhandled exception on the receive
        path; a keystore failure and a bad signature are the same answer here.
        """
        return keystore.verify(self.key_id, self.signature, self.event.canonical_payload())

    def recompute_hash(self) -> str:
        """The receiver's own hash, ignoring any hash the sender claimed."""
        return self.event.hash()

    def to_wire_dict(self) -> dict[str, Any]:
        """Payload as it goes on air, without the redundant event_hash."""
        return self.event.canonical_payload()

    @classmethod
    def from_wire(cls, payload: dict[str, Any], signature: bytes, key_id: str) -> SignedEvent:
        return cls(event=Event.from_dict(payload), signature=signature, key_id=key_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.event.to_dict(),
            "key_id": self.key_id,
            "signature": self.signature.hex(),
        }

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"SignedEvent(event_id={self.event.event_id!r}, "
            f"key_id={self.key_id!r}, signature=<{len(self.signature)} bytes>)"
        )
