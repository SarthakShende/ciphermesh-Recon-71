"""Configuration schema.

Every setting the node understands is declared here as a frozen dataclass.
The loader builds these from ``/etc/ciphermesh/config.yaml`` and rejects
unknown keys, so a typo in the config is a startup error rather than a
silently ignored line.

Design rules for this module:

* No defaults here encode a security policy. Where a safe default exists
  (e.g. API binds to loopback) it is set; where the correct value depends on
  the deployment (e.g. radio transmit power) it is ``None`` and must be
  supplied by the operator.
* Secrets are never stored in this file. Anything secret is either an
  ``${ENV_VAR}`` reference resolved from ``/etc/ciphermesh/ciphermesh.env`` or
  absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

from ..constants import (
    DEFAULT_MONITORING_PORT,
    DHT22_MIN_SAMPLE_INTERVAL_SECONDS,
    EventType,
    Role,
    SOFTWARE_VERSION,
    Unit,
)
from ..errors import ValidationError

# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceConfig:
    """Identity and role of this node.

    ``id`` is the human-facing identifier carried in every event. It is not a
    secret and is safe to publish. The Ed25519 keypair is what actually
    authenticates the node.
    """

    id: str
    name: str
    role: Role
    location: str | None = None
    #: Contact address published to the cloud backend. Optional.
    contact: str | None = None

    def validate(self) -> None:
        if not self.id or not self.id.strip():
            raise ValidationError("device.id", "must not be empty")
        if len(self.id) > 64:
            raise ValidationError("device.id", "must be 64 characters or fewer", self.id)
        if not _is_safe_identifier(self.id):
            raise ValidationError(
                "device.id",
                "may only contain letters, digits, '-', '_' and '.'",
                self.id,
            )
        if not self.name or not self.name.strip():
            raise ValidationError("device.name", "must not be empty")


# ---------------------------------------------------------------------------
# Sensor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SensorConfig:
    """Temperature/humidity sensor.

    ``type`` must be a key in :mod:`ciphermesh.sensors.registry`. ``mock`` is
    never enabled implicitly: a hardware sensor configured but missing reports
    DISCONNECTED, it does not fall back to simulated data.
    """

    enabled: bool = False
    type: str = "mock"
    interface: str = ""
    interval_seconds: float = 5.0
    #: Emit HUMIDITY events when the sensor provides a humidity reading.
    humidity_enabled: bool = True
    #: Reject readings that fall outside the datasheet operating range.
    #: AM2302: -40..80 C, 0..100 %RH.
    enforce_range: bool = True
    min_valid_celsius: float = -40.0
    max_valid_celsius: float = 80.0
    min_valid_humidity: float = 0.0
    max_valid_humidity: float = 100.0
    #: DHT22-specific settings (ignored by other sensor types).
    gpio_pin: int = 4
    gpio_chip: str = "gpiochip0"
    #: Retries per read when the first attempt returns an invalid frame.
    read_retries: int = 2
    #: Timeout for a full 40-bit frame read.
    frame_timeout_ms: float = 8.0
    #: Consecutive failed reads before status becomes DISCONNECTED.
    failure_threshold: int = 3
    #: Deterministic starting value for MockTemperatureSensor (no randomness).
    mock_fixed_value: float | None = 26.0
    #: If set, MockTemperatureSensor walks between min and max instead of
    #: returning a constant. Still clearly labelled MOCK.
    mock_sweep: bool = False

    def validate(self) -> None:
        if self.interval_seconds <= 0:
            raise ValidationError("sensor.interval_seconds", "must be greater than 0")
        if self.type.lower().startswith("dht") and (
            self.interval_seconds < DHT22_MIN_SAMPLE_INTERVAL_SECONDS
        ):
            # The AM2302 requires >=2s between conversions. Converting faster
            # reliably yields checksum failures, so this is an error rather
            # than a warning.
            raise ValidationError(
                "sensor.interval_seconds",
                "must be at least "
                f"{DHT22_MIN_SAMPLE_INTERVAL_SECONDS}s for DHT22/AM2302 "
                "(datasheet minimum sampling period)",
                self.interval_seconds,
            )
        if self.gpio_pin < 0 or self.gpio_pin > 27:
            raise ValidationError(
                "sensor.gpio_pin",
                "must be a BCM pin number between 0 and 27 on Raspberry Pi 4B",
                self.gpio_pin,
            )
        if self.read_retries < 0 or self.read_retries > 10:
            raise ValidationError("sensor.read_retries", "must be between 0 and 10")
        if self.failure_threshold < 1:
            raise ValidationError("sensor.failure_threshold", "must be at least 1")
        if self.min_valid_celsius >= self.max_valid_celsius:
            raise ValidationError(
                "sensor.min_valid_celsius", "must be less than sensor.max_valid_celsius"
            )
        self._validate_gpio_chip()
        self._validate_interface()

    def _validate_gpio_chip(self) -> None:
        """Check the chip name is one this host could actually open.

        Accepted spellings are ``0``, ``gpiochip0`` and ``/dev/gpiochip0``,
        mirroring ``ciphermesh.sensors.gpio.parse_chip_number``. The parse
        itself is not imported from there: that module lives under
        ``ciphermesh.sensors``, whose package ``__init__`` imports this one, so
        importing it back would be a cycle. The rule is small and is asserted
        against the parser in ``tests/test_sensors.py`` so the two cannot drift.
        """
        text = str(self.gpio_chip).strip().rsplit("/", 1)[-1]
        if text.startswith("gpiochip"):
            text = text[len("gpiochip") :]
        if not text.isdigit():
            raise ValidationError(
                "sensor.gpio_chip",
                "must name a GPIO chip, e.g. 'gpiochip0', '/dev/gpiochip0' or "
                "'0'. On a Raspberry Pi 5 the header pins are on chip 4, not "
                "chip 0.",
                self.gpio_chip,
            )

    def _validate_interface(self) -> None:
        """Reject a config whose ``interface`` contradicts ``gpio_pin``.

        Both are accepted spellings of the same thing, and the template sets
        both. Only ``gpio_pin`` is acted on, so a mismatch would otherwise
        edit the wrong line, see it take effect, and read the other pin.
        """
        if not self.interface:
            return
        spec = self.interface.strip().lower()
        if not spec.startswith("gpio:"):
            raise ValidationError(
                "sensor.interface",
                "only single-wire GPIO sensors are supported, written as "
                "'gpio:<BCM pin>', or left empty to use sensor.gpio_pin",
                self.interface,
            )
        try:
            pin = int(spec[len("gpio:") :])
        except ValueError:
            raise ValidationError(
                "sensor.interface",
                "expected 'gpio:<BCM pin>', e.g. 'gpio:4'",
                self.interface,
            ) from None
        if pin != self.gpio_pin:
            raise ValidationError(
                "sensor.interface",
                f"names pin {pin} but sensor.gpio_pin is {self.gpio_pin}; they "
                "are the same setting, so they have to agree",
                self.interface,
            )


# ---------------------------------------------------------------------------
# Reticulum
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReticulumConfig:
    """Reticulum Network Stack settings.

    ``mode`` selects how PI-A addresses PI-B:

    ``plain``
        A PLAIN destination (no Reticulum identity, no key exchange). Both
        nodes derive an identical addressable hash from the name, so the
        packet is broadcast on every online outgoing interface. Zero pairing
        ceremony. Confidentiality comes from the interface IFAC passphrase
        instead (see :class:`LoraConfig`). This is the MVP default.

    ``group``
        A GROUP destination. Requires both nodes to share a passphrase. The
        address hash still folds in the local identity, so a GROUP
        destination is only reachable by nodes that already know each
        other's hash; it is not a drop-in replacement for ``plain``.

    ``single``
        Per-node identities. PI-B announces, PI-A recalls its identity by
        ``peer_destination_hash``. Gives Reticulum-native encryption and
        forward secrecy at the cost of a pairing step.
    """

    enabled: bool = True
    config_dir: str = ""  # resolved to paths.reticulum_dir() when empty
    mode: str = "plain"
    app_name: str = "ciphermesh"
    #: Reticulum joins app_name and aspects with "." and forbids dots in any
    #: component, so ("event",) expands to exactly "ciphermesh.event". The
    #: protocol version is not an aspect: it already travels in the wire
    #: header, and duplicating it here would fork the destination namespace
    #: for no benefit.
    aspects: tuple[str, ...] = ("event",)
    #: Human-readable full name, shown by `ciphermesh reticulum`. Reticulum
    #: derives the addressable hash from app_name + aspects; this is purely
    #: for display and must equal ".".join([app_name, *aspects]).
    destination_name: str = "ciphermesh.event"
    #: Reticulum loglevel 0-8. 4 == Notice.
    loglevel: int = 4
    #: Reticulum transport. Off for the 2-node MVP: the node then does not
    #: route traffic for other mesh operators on shared IN865 spectrum.
    enable_transport: bool = False
    #: Only the first process may open the radios. Off so our private
    #: instance does not contend with a personal Reticulum instance.
    share_instance: bool = False
    #: Seconds between destination announcements (0 disables announcing).
    announce_interval: int = 0
    #: Destination hash of the peer, required by ``single`` mode.
    peer_destination_hash: str = ""
    #: Shared secret for ``group`` mode. Must come from an env reference.
    group_passphrase: str = ""
    #: Seconds to wait for a transport path before giving up on a send.
    send_timeout: float = 8.0
    #: Maximum size of an event packet we will put on the wire.
    max_payload_bytes: int = 466
    #: Signed acknowledgement: return the verification verdict to the sender.
    send_acknowledgements: bool = True

    def validate(self) -> None:
        if self.mode not in ("plain", "group", "single"):
            raise ValidationError(
                "reticulum.mode", "must be one of: plain, group, single", self.mode
            )
        if "." in self.app_name:
            # Reticulum joins name components with "." and rejects dots in any
            # component, so a dotted app_name can never be addressed.
            raise ValidationError(
                "reticulum.app_name",
                "must not contain '.' (Reticulum uses it as a name separator)",
                self.app_name,
            )
        for aspect in self.aspects:
            if "." in aspect:
                raise ValidationError("reticulum.aspects", "must not contain '.'", aspect)
        if not 0 <= self.loglevel <= 8:
            raise ValidationError("reticulum.loglevel", "must be between 0 and 8")
        expected_name = ".".join([self.app_name, *self.aspects])
        if self.destination_name != expected_name:
            raise ValidationError(
                "reticulum.destination_name",
                f"must be {expected_name!r} to match app_name and aspects",
                self.destination_name,
            )
        if self.max_payload_bytes <= 0:
            raise ValidationError("reticulum.max_payload_bytes", "must be greater than 0")
        if self.mode == "group" and not self.group_passphrase:
            raise ValidationError(
                "reticulum.group_passphrase",
                "required in group mode; set it via an ${ENV_VAR} reference, "
                "never inline in config.yaml",
            )
        if self.mode == "single" and not self.peer_destination_hash:
            raise ValidationError(
                "reticulum.peer_destination_hash",
                "required in single mode (set with `ciphermesh reticulum pair`)",
            )
        if self.peer_destination_hash and len(self.peer_destination_hash) != 32:
            raise ValidationError(
                "reticulum.peer_destination_hash",
                "must be a 32-character hex string (16 bytes)",
                self.peer_destination_hash,
            )


# ---------------------------------------------------------------------------
# LoRa
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoraConfig:
    """LoRa radio parameters.

    Every RF parameter here is written verbatim into the Reticulum interface
    block. None of them have an invented default: if the radio is enabled,
    ``frequency``/``bandwidth``/``txpower``/``spreadingfactor``/``codingrate``
    must all be supplied and must pass region validation.

    ``baud_rate`` is accepted for interface compatibility but is NOT
    forwarded: RNodeInterface hardcodes 115200 (RNS/Interfaces/
    RNodeInterface.py, `self.speed = 115200`).
    """

    enabled: bool = False
    #: Only ``rnode`` is supported by Reticulum. Anything else is reported
    #: UNSUPPORTED rather than silently ignored.
    interface: str = "rnode"
    device: str = ""
    #: Shown for operator awareness; the installer warns it is fixed.
    baud_rate: int = 115200

    frequency: int | None = None
    bandwidth: int | None = None
    spreading_factor: int | None = None
    coding_rate: int | None = None
    tx_power: int | None = None

    #: Regulatory region used to validate the above. See config/regions.py.
    region: str = ""
    #: Operator-supplied transmit power ceiling in dBm. CipherMesh has no
    #: opinion on the correct value: the gazetted limit depends on the device
    #: category and the operator's licence position. When set, a configured
    #: ``tx_power`` above this is rejected at startup.
    max_tx_power_dbm: int | None = None
    #: Operator confirmation that the EIRP and duty-cycle limits in force
    #: have been checked against the applicable gazette. The installer
    #: refuses to enable the radio until this is true.
    regulatory_confirmed: bool = False
    #: Free-text note recording what the operator confirmed, e.g.
    #: "Gazette of India 2021 SRD rules, 25 mW ERP, 1% duty".
    regulatory_reference: str = ""

    #: Interface Access Control. Encrypts and authenticates every frame at
    #: the link layer. Both ends of the link MUST use the same value or
    #: frames are dropped on receive. Supplied via ${ENV_VAR}.
    network_name: str = ""
    passphrase: str = ""

    #: RNode firmware over USB. Optional; set for BLE-connected boards.
    id_interval: int = 0
    id_callsign: str = ""
    flow_control: bool = False

    #: Optional invariant that the installer offers to pre-fill.
    max_payload_bytes: int = 200

    def validate(self) -> None:
        if not self.enabled:
            return

        if self.interface.lower() != "rnode":
            # Not a rejection: the node still starts, but `ciphermesh lora`
            # and the API report UNSUPPORTED with the reason.
            return

        missing = [
            name
            for name in (
                "device",
                "frequency",
                "bandwidth",
                "spreading_factor",
                "coding_rate",
                "tx_power",
            )
            if getattr(self, name) in (None, "")
        ]
        if missing:
            raise ValidationError(
                "lora",
                "radio enabled but these required parameters are missing: "
                + ", ".join(f"lora.{m}" for m in missing),
            )

        if not self.device.startswith("/dev/"):
            raise ValidationError(
                "lora.device",
                "must be an absolute device path such as /dev/ciphermesh/lora "
                "or /dev/serial/by-id/... (not a USB product string)",
                self.device,
            )
        if self.baud_rate != 115200:
            raise ValidationError(
                "lora.baud_rate",
                "RNodeInterface fixes the serial rate at 115200 "
                "(RNS/Interfaces/RNodeInterface.py). Set to 115200 or remove it.",
                self.baud_rate,
            )
        if not self.regulatory_confirmed:
            raise ValidationError(
                "lora.regulatory_confirmed",
                "must be set to true before the radio may transmit. Confirm the "
                "applicable EIRP and duty-cycle limit for your region first; "
                "see docs/lora.md and config/regions.py",
            )
        if not self.region:
            raise ValidationError(
                "lora.region",
                "required when the radio is enabled; e.g. 'IN865-867' for India",
            )
        if self.max_tx_power_dbm is not None and self.tx_power is not None:
            if self.tx_power > self.max_tx_power_dbm:
                raise ValidationError(
                    "lora.tx_power",
                    f"exceeds the operator-confirmed ceiling of {self.max_tx_power_dbm} dBm",
                    self.tx_power,
                )
        if not self.network_name:
            raise ValidationError("lora.network_name", "required when the radio is enabled")
        if not self.passphrase:
            raise ValidationError(
                "lora.passphrase",
                "required when the radio is enabled; reference it with "
                "${CIPHERMESH_LORA_PASSPHRASE} rather than writing it inline",
            )


# ---------------------------------------------------------------------------
# Cloud
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CloudConfig:
    """Cloud backend integration.

    Disabled by default. When enabled and the backend is unreachable, every
    call returns an explicit :class:`CloudUnavailableError` - ciphermesh
    never fabricates a success.
    """

    enabled: bool = False
    api_url: str = ""
    api_key: str = ""
    device_token: str = ""
    request_timeout_seconds: float = 10.0
    connect_timeout_seconds: float = 5.0
    #: Probe this URL to decide whether the internet is reachable at all.
    #: Kept separate from api_url so a cloud outage does not read as an
    #: internet outage.
    connectivity_probe_url: str = "https://connectivitycheck.gstatic.com/generate_204"
    connectivity_probe_timeout: float = 5.0
    connectivity_cache_seconds: float = 30.0
    #: Batch size for bulk event upload.
    batch_size: int = 50
    #: TLS verification. Present so the intent is explicit and so no code
    #: path can quietly disable it.
    verify_tls: bool = True

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.api_url:
            raise ValidationError("cloud.api_url", "required when cloud.enabled is true")
        if not self.api_url.startswith("https://"):
            # Plain HTTP would put device credentials and signed events on the
            # wire in the clear. Not configurable.
            raise ValidationError("cloud.api_url", "must use https://", self.api_url)
        if not self.verify_tls:
            raise ValidationError(
                "cloud.verify_tls",
                "must remain true; ciphermesh does not support running with "
                "TLS verification disabled",
            )
        if self.batch_size < 1 or self.batch_size > 1000:
            raise ValidationError("cloud.batch_size", "must be between 1 and 1000")
        if self.request_timeout_seconds <= self.connect_timeout_seconds:
            raise ValidationError(
                "cloud.request_timeout_seconds",
                "must be greater than cloud.connect_timeout_seconds",
            )


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StorageConfig:
    """Local SQLite storage."""

    sqlite_path: str = ""  # resolved to paths.default_db_path() when empty
    busy_timeout_ms: int = 5000
    #: WAL keeps the sensor loop readable while the sync worker writes.
    journal_mode: str = "WAL"
    synchronous: str = "NORMAL"
    #: Retention. 0 disables pruning.
    event_retention_days: int = 0
    security_event_retention_days: int = 0
    #: VACUUM/ANALYZE cadence in hours. 0 disables.
    maintenance_interval_hours: int = 24
    db_file_mode: int = 0o640

    def validate(self) -> None:
        if self.journal_mode.upper() not in ("WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY"):
            raise ValidationError(
                "storage.journal_mode",
                "must be one of WAL, DELETE, TRUNCATE, PERSIST, MEMORY",
                self.journal_mode,
            )
        if self.synchronous.upper() not in ("OFF", "NORMAL", "FULL", "EXTRA"):
            raise ValidationError(
                "storage.synchronous", "must be one of OFF, NORMAL, FULL, EXTRA", self.synchronous
            )
        if self.busy_timeout_ms < 0:
            raise ValidationError("storage.busy_timeout_ms", "must not be negative")


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Verification and replay policy.

    These are policy, not protocol. Every value is operator-configurable and
    has a conservative default that is documented in docs/security.md.
    """

    #: Events older than this are rejected as STALE_EVENT.
    max_event_age_seconds: int = 900
    #: Events dated further in the future than this are rejected as
    #: FUTURE_EVENT, absorbing modest clock skew without opening a gap.
    max_future_skew_seconds: int = 120
    #: Reject any event whose sequence is <= the highest accepted sequence.
    #: This is the primary replay defence and defaults to on.
    enforce_monotonic_sequence: bool = True
    #: Allow a bounded number of out-of-order events within the replay
    #: window. Off by default: on a lossy LoRa link, reordering is normal
    # and enabling this weakens the guarantee.
    allow_out_of_order: bool = False
    out_of_order_tolerance: int = 0
    #: How long event hashes are retained for duplicate detection.
    replay_window_seconds: int = 86400
    #: Hard cap on retained hashes regardless of age, protecting against
    #: unbounded growth.
    replay_window_max_entries: int = 100000
    #: Accept events from device IDs that have never been seen before.
    #: Off by default: an unknown device cannot be authenticated.
    auto_register_devices: bool = False
    #: Consult the local revocation list during verification.
    check_revocation: bool = True
    #: Treat a verification failure as a security event worth recording.
    record_security_events: bool = True
    #: Reject timestamps outside these bounds even before hashing. Guards
    #: against absurd values before they reach the canonicalizer.
    min_valid_unix_timestamp: int = 946684800  # 2000-01-01T00:00:00Z
    max_valid_unix_timestamp: int = 4102444800  # 2100-01-01T00:00:00Z

    def validate(self) -> None:
        if self.max_event_age_seconds <= 0:
            raise ValidationError("security.max_event_age_seconds", "must be greater than 0")
        if self.max_future_skew_seconds < 0:
            raise ValidationError(
                "security.max_future_skew_seconds", "must not be negative"
            )
        if self.allow_out_of_order and self.out_of_order_tolerance <= 0:
            raise ValidationError(
                "security.out_of_order_tolerance",
                "must be greater than 0 when allow_out_of_order is enabled",
            )
        if not self.allow_out_of_order and self.out_of_order_tolerance != 0:
            raise ValidationError(
                "security.out_of_order_tolerance",
                "must be 0 when allow_out_of_order is disabled",
            )
        if self.replay_window_seconds <= 0:
            raise ValidationError("security.replay_window_seconds", "must be greater than 0")
        if self.min_valid_unix_timestamp >= self.max_valid_unix_timestamp:
            raise ValidationError(
                "security.min_valid_unix_timestamp", "must be less than the maximum"
            )


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SyncConfig:
    """Offline-first upload queue."""

    enabled: bool = True
    #: Seconds between queue sweeps when idle.
    interval_seconds: float = 30.0
    #: Records claimed per sweep.
    batch_size: int = 25
    #: Exponential backoff: base * 2^(attempt-1), capped, with jitter.
    base_backoff_seconds: float = 15.0
    max_backoff_seconds: float = 3600.0
    #: Jitter fraction applied to each delay, e.g. 0.2 => +/-20%.
    jitter_fraction: float = 0.2
    #: After this many failed attempts a record moves to FAILED and is left
    #: for an operator. Prevents infinite retry loops.
    max_attempts: int = 12
    #: Sweep immediately when connectivity is restored rather than waiting
    #: out the interval.
    sync_on_reconnect: bool = True
    #: Re-queue FAILED records for another attempt cycle.
    retry_failed: bool = False
    #: Send device registration once the backend becomes reachable.
    auto_register: bool = True

    def validate(self) -> None:
        if self.interval_seconds <= 0:
            raise ValidationError("sync.interval_seconds", "must be greater than 0")
        if self.batch_size < 1:
            raise ValidationError("sync.batch_size", "must be at least 1")
        if not 0 <= self.jitter_fraction <= 1:
            raise ValidationError("sync.jitter_fraction", "must be between 0 and 1")
        if self.max_attempts < 1:
            raise ValidationError("sync.max_attempts", "must be at least 1")
        if self.base_backoff_seconds > self.max_backoff_seconds:
            raise ValidationError(
                "sync.max_backoff_seconds", "must be greater than the base backoff"
            )


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MonitoringConfig:
    """Local HTTP API.

    Binds to loopback by default. If ``bind_address`` is changed to anything
    other than a loopback address, ``auth_required`` is forced on by the
    loader - there is no configuration that yields an unauthenticated API on
    a routable interface.
    """

    enabled: bool = True
    bind_address: str = "127.0.0.1"
    port: int = DEFAULT_MONITORING_PORT
    #: Bearer token. Supplied via ${CIPHERMESH_API_TOKEN}. Generated by the
    #: installer when remote access is chosen.
    auth_token: str = ""
    #: Force authentication even on loopback.
    auth_required: bool = False
    #: Serve the minimal HTML dashboard at "/".
    dashboard_enabled: bool = True
    #: Server threads. 4 is ample for a demo dashboard.
    max_workers: int = 4
    #: Rows returned by GET /events when no limit is supplied.
    default_event_limit: int = 50
    max_event_limit: int = 1000
    request_log_enabled: bool = True

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValidationError("monitoring.port", "must be between 1 and 65535", self.port)
        if self.max_workers < 1:
            raise ValidationError("monitoring.max_workers", "must be at least 1")
        if self.default_event_limit < 1:
            raise ValidationError("monitoring.default_event_limit", "must be at least 1")
        if self.default_event_limit > self.max_event_limit:
            raise ValidationError(
                "monitoring.default_event_limit", "must not exceed monitoring.max_event_limit"
            )

    @property
    def effective_auth_required(self) -> bool:
        """Authentication is mandatory for any non-loopback bind."""
        if self.auth_required:
            return True
        return not is_loopback_address(self.bind_address)


def is_loopback_address(address: str) -> bool:
    """True if ``address`` only accepts connections from this host."""
    import ipaddress

    if address in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Structured logging.

    Records are JSON lines. ``redact_keys`` is applied by a filter on every
    record and is the last line of defence against a secret reaching the
    journal; the correct fix is still never putting one in a log call.
    """

    level: str = "INFO"
    #: JSON for machine consumption, plain for readability during setup.
    format: str = "json"
    #: Also write to <log_dir>/ciphermesh.log. Off by default; journald
    #: already captures stdout.
    file_enabled: bool = False
    file_name: str = "ciphermesh.log"
    max_file_bytes: int = 10 * 1024 * 1024
    backup_count: int = 3
    #: Mirror Reticulum's own output into our log stream.
    reticulum_log_enabled: bool = True
    redact_keys: tuple[str, ...] = (
        "api_key",
        "device_token",
        "auth_token",
        "passphrase",
        "group_passphrase",
        "private_key",
        "password",
        "secret",
        "authorization",
    )

    def validate(self) -> None:
        if self.level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValidationError(
                "logging.level", "must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL", self.level
            )
        if self.format.lower() not in ("json", "text"):
            raise ValidationError("logging.format", "must be 'json' or 'text'", self.format)


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventConfig:
    """Event construction parameters."""

    version: int = 1
    #: ID template. Placeholders: {date} {device} {sequence} {random}
    id_template: str = "EVT-{date}-{device}-{sequence:08d}-{random}"
    random_suffix_bytes: int = 2
    #: Decimal places retained in the canonical value. Applied when the
    #: reading is captured, so what is signed is what is displayed.
    value_decimals: int = 2
    #: Default unit for events with no natural unit.
    default_unit: Unit = Unit.CELSIUS
    default_event_type: EventType = EventType.TEMPERATURE
    #: Reject an event whose canonical payload would exceed this many bytes.
    max_canonical_bytes: int = 4096

    def validate(self) -> None:
        if self.version < 1:
            raise ValidationError("event.version", "must be at least 1")
        if not 0 <= self.value_decimals <= 9:
            raise ValidationError("event.value_decimals", "must be between 0 and 9")
        # Each placeholder may carry a format spec, e.g. {sequence:08d}.
        for placeholder in ("date", "device", "sequence", "random"):
            if not re.search(r"\{" + placeholder + r"(?::[^}]*)?\}", self.id_template):
                raise ValidationError(
                    "event.id_template",
                    f"must contain {{{placeholder}}}; uniqueness must not depend on "
                    "the clock alone. Supported placeholders: {date}, {device}, "
                    "{sequence}, {random}",
                    self.id_template,
                )
        if self.random_suffix_bytes < 1 or self.random_suffix_bytes > 8:
            raise ValidationError("event.random_suffix_bytes", "must be between 1 and 8")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApplicationConfig:
    """Software identity reported to the cloud backend.

    ``secure_boot`` is reported only when it is positively detected. A Pi 4B
    without the OTP-based secure boot flow is reported as NOT_CONFIGURED,
    never as secure.
    """

    software_version: str = SOFTWARE_VERSION
    #: Override the computed SHA-256 of the installed package tree. Empty
    #: means "compute at runtime".
    application_hash: str = ""
    #: Advertised by `ciphermesh status`. Does not gate any behaviour.
    node_description: str = "CipherMesh Edge"

    def validate(self) -> None:
        if not self.software_version:
            raise ValidationError("application.software_version", "must not be empty")
        if self.application_hash and len(self.application_hash) != 64:
            raise ValidationError(
                "application.application_hash", "must be a 64-character SHA-256 hex digest"
            )


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """The complete node configuration."""

    device: DeviceConfig
    sensor: SensorConfig = field(default_factory=SensorConfig)
    reticulum: ReticulumConfig = field(default_factory=ReticulumConfig)
    lora: LoraConfig = field(default_factory=LoraConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)
    event: EventConfig = field(default_factory=EventConfig)
    application: ApplicationConfig = field(default_factory=ApplicationConfig)

    def validate(self) -> None:
        """Validate every section and the cross-section invariants."""
        for section in self._sections():
            section.validate()

        # A gateway without a sensor has nothing to originate. A receiver
        # without Reticulum cannot receive.
        if self.device.role is Role.GATEWAY_SENSOR and not self.sensor.enabled:
            raise ValidationError(
                "sensor.enabled",
                "must be true for role GATEWAY_SENSOR",
            )
        if self.reticulum.enabled and not self.reticulum.max_payload_bytes:
            raise ValidationError("reticulum.max_payload_bytes", "must be greater than 0")
        if self.lora.enabled and self.lora.max_payload_bytes > self.reticulum.max_payload_bytes:
            raise ValidationError(
                "lora.max_payload_bytes",
                "must not exceed reticulum.max_payload_bytes "
                f"({self.lora.max_payload_bytes} > {self.reticulum.max_payload_bytes})",
            )
        if self.sync.enabled and not self.cloud.enabled:
            # Permitted: records accumulate until the cloud is configured.
            pass
        if self.cloud.enabled and not self.sync.enabled:
            raise ValidationError(
                "sync.enabled", "must be true when cloud.enabled is true"
            )

    def _sections(self) -> tuple:
        return (
            self.device,
            self.sensor,
            self.reticulum,
            self.lora,
            self.cloud,
            self.storage,
            self.security,
            self.monitoring,
            self.logging,
            self.sync,
            self.event,
            self.application,
        )

    @property
    def is_gateway(self) -> bool:
        return self.device.role is Role.GATEWAY_SENSOR

    @property
    def is_receiver(self) -> bool:
        return self.device.role is Role.RECEIVER_NODE

    def redacted(self) -> dict[str, Any]:
        """Configuration as a dict with every secret masked.

        Used by ``ciphermesh config show`` and ``GET /status``. The set of
        masked keys comes from :attr:`LoggingConfig.redact_keys` so there is
        a single definition of what counts as secret.
        """
        raw = to_dict(self)
        secrets = {k.lower() for k in self.logging.redact_keys}
        return _mask(raw, secrets, prefix="")


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _mask(value: Any, secrets: set[str], prefix: str) -> Any:
    """Recursively mask values whose key looks like a secret."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            if key.lower() in secrets and item not in (None, "", False):
                out[key] = "***REDACTED***"
            else:
                out[key] = _mask(item, secrets, child_prefix)
        return out
    if isinstance(value, list):
        return [_mask(item, secrets, prefix) for item in value]
    return value


#: Enums that appear in the config tree and serialise to their value.
_CONFIG_ENUMS = (Role, EventType, Unit)


def to_dict(obj: Any) -> Any:
    """Recursively convert a config dataclass tree to plain Python types.

    The enums used by the schema all derive from ``str``, so they would
    serialise correctly anyway; they are unwrapped explicitly so that
    ``ciphermesh config show`` prints ``C`` rather than ``Unit.CELSIUS``.
    """
    if isinstance(obj, _CONFIG_ENUMS):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple)):
        return [to_dict(item) for item in obj]
    return obj


def _is_safe_identifier(value: str) -> bool:
    return all(c.isalnum() or c in "-_." for c in value)
