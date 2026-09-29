"""Project-wide constants and enumerations.

Anything in this module is part of the wire or on-disk contract. Changing a
value here is a breaking change and must be accompanied by a new version
number and a migration where applicable.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------

#: Version of the event object schema. Part of the signed payload, so
#: incrementing this changes every signature and event hash.
EVENT_VERSION = 1

#: Application software version, reported to the cloud backend and shown by
#: `ciphermesh device`. Kept in sync with pyproject.toml by test_infra.py.
SOFTWARE_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class Role(str, Enum):
    """Deployment role. Selected during `install.sh`."""

    GATEWAY_SENSOR = "GATEWAY_SENSOR"
    RECEIVER_NODE = "RECEIVER_NODE"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


class EventType(str, Enum):
    """Event kinds emitted by PI-A and understood by PI-B."""

    TEMPERATURE = "TEMPERATURE"
    HUMIDITY = "HUMIDITY"
    SYSTEM = "SYSTEM"

    @classmethod
    def from_code(cls, code: int) -> "EventType":
        try:
            return WIRE_EVENT_TYPES[code]
        except KeyError:
            raise ValueError(f"unknown event type code {code}") from None

    @classmethod
    def to_code(cls, value: "EventType") -> int:
        return WIRE_CODES[value]


WIRE_EVENT_TYPES: dict[int, EventType] = {
    0x01: EventType.TEMPERATURE,
    0x02: EventType.HUMIDITY,
    0x03: EventType.SYSTEM,
}

WIRE_CODES: dict[EventType, int] = {v: k for k, v in WIRE_EVENT_TYPES.items()}


class Unit(str, Enum):
    """Measurement units. Encoded on the wire as a single byte."""

    CELSIUS = "C"
    PERCENT_RH = "%RH"
    NONE = ""

    @classmethod
    def from_code(cls, code: int) -> "Unit":
        try:
            return WIRE_UNITS[code]
        except KeyError:
            raise ValueError(f"unknown unit code {code}") from None

    @classmethod
    def to_code(cls, value: "Unit") -> int:
        return WIRE_UNIT_CODES[value]


WIRE_UNIT_CODES: dict[Unit, int] = {Unit.CELSIUS: 0x01, Unit.PERCENT_RH: 0x02, Unit.NONE: 0x03}
WIRE_UNITS: dict[int, Unit] = {v: k for k, v in WIRE_UNIT_CODES.items()}


# ---------------------------------------------------------------------------
# Verification outcomes
# ---------------------------------------------------------------------------


class VerificationStatus(str, Enum):
    """Terminal result of running an event through the verification pipeline.

    The order of definition is the order in which the pipeline evaluates
    stages (see verification/pipeline.py). The first stage that fails
    determines the reported status.
    """

    VERIFIED = "VERIFIED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    HASH_MISMATCH = "HASH_MISMATCH"
    SEQUENCE_REPLAY = "SEQUENCE_REPLAY"
    STALE_EVENT = "STALE_EVENT"
    FUTURE_EVENT = "FUTURE_EVENT"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    MALFORMED_PACKET = "MALFORMED_PACKET"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def accepted(self) -> bool:
        return self is VerificationStatus.VERIFIED


# ---------------------------------------------------------------------------
# Subsystem health
# ---------------------------------------------------------------------------


class LinkState(str, Enum):
    """State reported for a physical or logical link.

    NOTE: these are reported from *observed* state only. No component is
    permitted to report ONLINE for a link it has not actually verified.
    """

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class SensorStatus(str, Enum):
    """State of the temperature/humidity sensor subsystem."""

    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"
    MOCK = "MOCK"
    NOT_CONFIGURED = "NOT_CONFIGURED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class SyncState(str, Enum):
    """Overall cloud synchronisation state."""

    DISABLED = "DISABLED"
    IDLE = "IDLE"
    SYNCING = "SYNCING"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class QueueStatus(str, Enum):
    """Per-record state in the sync queue."""

    PENDING = "PENDING"
    SYNCING = "SYNCING"
    SYNCED = "SYNCED"
    FAILED = "FAILED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class RegistrationState(str, Enum):
    """Cloud device registration state."""

    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    PENDING_REGISTRATION = "PENDING_REGISTRATION"
    REGISTERED = "REGISTERED"
    FAILED = "FAILED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# ---------------------------------------------------------------------------
# Security event codes
# ---------------------------------------------------------------------------


class SecurityEventCode(str, Enum):
    """Codes recorded in the `security_events` table and the logs.

    These are stable identifiers. Do not rename without a migration.
    """

    # Verification rejections
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    STALE_EVENT = "STALE_EVENT"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    HASH_MISMATCH = "HASH_MISMATCH"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"

    # Local subsystem failures
    SENSOR_FAILURE = "SENSOR_FAILURE"
    LORA_FAILURE = "LORA_FAILURE"
    RETICULUM_FAILURE = "RETICULUM_FAILURE"
    DATABASE_FAILURE = "DATABASE_FAILURE"

    # Connectivity transitions
    INTERNET_LOST = "INTERNET_LOST"
    INTERNET_RESTORED = "INTERNET_RESTORED"

    # Cloud sync
    SYNC_FAILURE = "SYNC_FAILURE"
    SYNC_RESTORED = "SYNC_RESTORED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


#: Log event codes (a superset of :class:`SecurityEventCode`).
#:
#: Every log line emitted by ciphermesh carries one of these in its
#: ``event_code`` field, so operators can filter precisely.
LOG_EVENT_CODES = frozenset(
    {
        # Lifecycle
        "NODE_STARTING",
        "NODE_STARTED",
        "NODE_STOPPING",
        "NODE_STOPPED",
        "CONFIG_LOADED",
        "IDENTITY_GENERATED",
        "IDENTITY_LOADED",
        "MIGRATIONS_APPLIED",
        # Sensor
        "SENSOR_CONNECTED",
        "SENSOR_DISCONNECTED",
        "SENSOR_READING",
        # Event pipeline
        "EVENT_CREATED",
        "EVENT_SIGNED",
        "EVENT_SENT",
        "EVENT_SEND_FAILED",
        "EVENT_RECEIVED",
        "EVENT_BUFFERED",
        "EVENT_STORED",
        "EVENT_ACK_SENT",
        # Verification
        "SIGNATURE_VERIFIED",
        "SIGNATURE_INVALID",
        "REPLAY_REJECTED",
        "STALE_EVENT",
        "DEVICE_REVOKED",
        # Radio / network
        "RETICULUM_STARTED",
        "RETICULUM_STOPPED",
        "LORA_CONNECTED",
        "LORA_DISCONNECTED",
        "LORA_UNAVAILABLE",
        # Sync
        "SYNC_STARTED",
        "SYNC_SUCCESS",
        "SYNC_FAILED",
        "CONNECTIVITY_CHANGED",
        "REGISTRATION_SENT",
        "REGISTRATION_PENDING",
        # Security
        "SECURITY_EVENT",
        "KEY_PERMISSION_FIXED",
        "PRIVATE_KEY_ACCESS",
    }
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Reticulum destination name. Reticulum forbids dots inside `app_name` and
#: aspects but joins them with dots, so the full name expands to
#: "ciphermesh.event" while each component stays dot-free. The protocol
#: version is deliberately NOT an aspect - it travels in the wire header.
RETICULUM_APP_NAME = "ciphermesh"
RETICULUM_ASPECTS = ("event",)

#: Reticulum link-layer MTU and the resulting maximum data unit.
#: Source: RNS/Reticulum.py @ 1.5.4 -
#:   TRUNCATED_HASHLENGTH = 128  (bits)
#:   HEADER_MAXSIZE       = 2 + 1 + (128//8)*2 = 35
#:   IFAC_MIN_SIZE        = 1
#:   MDU                  = 500 - 35 - 1 = 464
RETICULUM_MTU = 500
RETICULUM_MDU = RETICULUM_MTU - (2 + 1 + (128 // 8) * 2) - 1  # == 464

# ---------------------------------------------------------------------------
# Wire size budget
# ---------------------------------------------------------------------------
#
# A naive "wrap the signed event in JSON" packet was measured at 590 bytes -
# 127% of the 466-byte MDU, so it could never be transmitted. The wire
# format in ciphermesh.wire is therefore a compact binary envelope, and the
# following budget is enforced by tests so the constraint cannot regress.
#
#   envelope header (version, type, flags)         4 bytes
#   key id (SHA-256 prefix, raw bytes)             8 bytes
#   Ed25519 signature (raw, never hex)            64 bytes
#   canonical payload                           ~200 bytes typical
#                                              ------
#                                              ~276 bytes total
#
# Headroom of ~190 bytes absorbs a second sensor channel and a longer
# device name without fragmenting.
#
# Consequences that must not be undone:
#   * The public key does NOT travel on the wire. A receiver resolves it
#     from its own keyring by key_id. This is a size saving *and* the
#     security property that stops an attacker shipping their own key.
#   * Signatures travel as 64 raw bytes. Hex would double this to 128.
#   * `destination` is not in the envelope; the Reticulum destination
#     already carries it.
#   * `sent_at` is not in the envelope; the signed payload timestamp does
#     the same job without a second untrusted clock reading.

#: Hard ceiling on an encoded packet. Kept below the MDU so that a future
#: IFAC-bearing packet still fits.
WIRE_MAX_PACKET_BYTES = RETICULUM_MDU - 8  # 456, leaving room for framing

#: Raw Ed25519 signature size, and the 8-byte key id prefix.
SIGNATURE_BYTES = 64
KEY_ID_BYTES = 8
PUBLIC_KEY_BYTES = 32

#: Fraction of the packet budget the payload may occupy before the encoder
#: raises PayloadTooLargeError rather than transmitting a fragment.
WIRE_PAYLOAD_BUDGET_BYTES = WIRE_MAX_PACKET_BYTES - 4 - KEY_ID_BYTES - SIGNATURE_BYTES

#: Serial speed used by RNodeInterface. NOT configurable - Reticulum hardcodes
#: this in RNS/Interfaces/RNodeInterface.py (`self.speed = 115200`). The
#: installer surfaces it as a read-only fact rather than a user setting.
RNODE_FIXED_BAUD = 115200

#: Sensor sampling floor mandated by the AM2302 datasheet (Table 6).
#: Converting faster than this produces checksum failures on real hardware.
DHT22_MIN_SAMPLE_INTERVAL_SECONDS = 2.0

#: Default TCP port for the local monitoring API.
DEFAULT_MONITORING_PORT = 8080
