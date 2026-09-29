"""Exception hierarchy.

Every failure path in ciphermesh that can reasonably reach an operator gets a
specific type so the CLI, the API and the log all report the same category.
"""

from __future__ import annotations


class CipherMeshError(Exception):
    """Base class for all CipherMesh errors."""


# -- Configuration ---------------------------------------------------------


class ConfigError(CipherMeshError):
    """Configuration is missing, malformed, or internally inconsistent."""


class ValidationError(ConfigError):
    """A configuration value failed validation.

    Carries the offending key path so the CLI can point at the exact line.
    """

    def __init__(self, key: str, message: str, value: object = None) -> None:
        self.key = key
        self.value = value
        super().__init__(f"{key}: {message}")


class ConfigNotFoundError(ConfigError):
    """The configuration file does not exist."""


class RegionError(ConfigError):
    """A radio parameter is not valid for the configured regulatory region."""


# -- Identity / crypto -----------------------------------------------------


class CryptoError(CipherMeshError):
    """A cryptographic operation failed.

    Common parent so callers that only care about "the crypto layer is
    unhappy" can catch this one type.
    """


class IdentityError(CryptoError):
    """Device identity could not be created, loaded, or used."""


class PrivateKeyPermissionError(IdentityError):
    """The private key file is more permissive than the required 0600."""


class SigningError(CryptoError):
    """An event could not be signed."""


class CanonicalizationError(CryptoError):
    """A value cannot be canonically serialized."""


# -- Events ----------------------------------------------------------------


class EventValidationError(CipherMeshError):
    """An event failed schema validation."""


class SequenceError(CipherMeshError):
    """The event sequence could not be allocated."""


class WireFormatError(CipherMeshError):
    """A transport packet could not be encoded or decoded."""


class PayloadTooLargeError(WireFormatError):
    """A packet exceeds the configured maximum payload size."""


# -- Storage ---------------------------------------------------------------


class StorageError(CipherMeshError):
    """A database operation failed."""


class MigrationError(StorageError):
    """Schema migrations could not be applied."""


class DuplicateEventError(StorageError):
    """An event with this id, or this device's sequence, is already stored.

    Distinct from :class:`StorageError` so the receive path can record it as
    REPLAY_REJECTED without also swallowing genuine storage faults, which must
    surface rather than be reported as a replay.
    """


# -- Radio / network -------------------------------------------------------


class ReticulumError(CipherMeshError):
    """The Reticulum stack could not be started or used."""


class ReticulumUnavailableError(ReticulumError):
    """Reticulum could not be initialised in this process."""


class LoraError(CipherMeshError):
    """A LoRa radio operation failed."""


class UnsupportedRadioError(LoraError):
    """The configured radio cannot be used with Reticulum.

    Raised instead of silently degrading. See docs/lora.md.
    """


# -- Sensors ---------------------------------------------------------------


class SensorError(CipherMeshError):
    """A sensor could not be initialised or read."""


class SensorNotFoundError(SensorError):
    """The configured sensor is not present on the bus or GPIO."""


class GpioUnavailableError(SensorError):
    """No usable GPIO backend could be initialised."""


class ChecksumError(SensorError):
    """A sensor frame failed its integrity check."""


class SensorRateLimitError(SensorError):
    """The sensor was asked to read again before it could convert.

    Distinct from a generic :class:`SensorError` because it is not a fault:
    the sensor is fine, the caller is early. ``BaseSensor.read`` treats it as
    non-retryable and, if an earlier attempt already failed, lets that earlier
    error be the one reported - a rate limit triggered by our own retry must
    not hide the checksum failure that caused the retry.
    """


# -- Sync / cloud ----------------------------------------------------------


class SyncError(CipherMeshError):
    """Synchronisation failed."""


class CloudError(CipherMeshError):
    """The cloud backend could not satisfy a request.

    This is always an explicit failure. CipherMesh never synthesises a
    successful response on behalf of an unreachable backend.
    """


class CloudDisabledError(CloudError):
    """Cloud integration is switched off in configuration."""


class CloudAuthError(CloudError):
    """The backend rejected the supplied credentials."""


class CloudUnavailableError(CloudError):
    """The backend could not be reached (DNS, TCP, TLS or HTTP failure)."""


# -- Monitoring ------------------------------------------------------------


class AuthError(CipherMeshError):
    """A request to the local API failed authentication."""


class NotFoundError(CipherMeshError):
    """A resource was not found."""


# -- Verification ----------------------------------------------------------


class VerificationError(CipherMeshError):
    """Verification could not be completed."""
