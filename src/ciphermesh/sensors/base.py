"""Sensor base classes.

A sensor is anything that produces readings. The abstraction here is
deliberately narrow: ``read()`` returns a :class:`Reading` or raises. No
sensors module knows about events, storage, or the radio, which is what makes
them testable without hardware and reusable if a different sensor is added.

Three rules, all of them about not lying to the operator:

* **A failed read raises. It never returns a substituted value.** There is no
  "last good reading" fallback and no zero. A node that cannot read its sensor
  must be visibly offline, because a stale number signed and uploaded as
  current is worse than a gap.
* **A reading outside the configured range raises.** The DHT22 will happily
  report values a disconnected data line can produce; those are corrupt frames
  that happen to pass checksum, and publishing them as measurements is
  fabrication.
* **Status is derived from observations only.** ``CONNECTED`` means a real
  reading was obtained. There is no optimistic status, and a sensor that has
  never been read is ``DISCONNECTED``, not ``CONNECTED``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..constants import SensorStatus
from ..errors import (
    ChecksumError,
    SensorError,
    SensorNotFoundError,
    SensorRateLimitError,
)
from ..logging_setup import get_logger

LOG = get_logger(__name__)

__all__ = ["BaseSensor", "Reading", "Sensor"]


@dataclass(frozen=True, slots=True)
class Reading:
    """One observation from a sensor.

    ``mock`` is not cosmetic. A reading from a simulated sensor must stay
    labelled as such for its whole life, including after it has been signed
    and uploaded, or a test node's data is indistinguishable from a real node's
    in the cloud. :mod:`ciphermesh.events` does not carry the flag, so it is
    the caller's job to keep ``mock`` sensors out of the upload path - see
    :meth:`BaseSensor.mock` and the registry's type check.
    """

    temperature_c: float
    humidity_percent: float | None = None
    timestamp: float = 0.0
    mock: bool = False

    def __post_init__(self) -> None:
        # A non-finite reading cannot be signed (EventFactory rejects it), and
        # allowing one through here would mean the failure surfaces far from
        # its cause. NaN survives every comparison, hence the explicit form.
        for name in ("temperature_c", "humidity_percent"):
            value = getattr(self, name)
            if value is None:
                continue
            if value != value or value in (float("inf"), float("-inf")):
                raise SensorError(f"sensor returned a non-finite {name}: {value!r}")

    @property
    def age_seconds(self) -> float:
        if not self.timestamp:
            return 0.0
        return max(0.0, time.time() - self.timestamp)

    def as_dict(self) -> dict[str, Any]:
        return {
            "temperature_c": self.temperature_c,
            "humidity_percent": self.humidity_percent,
            "mock": self.mock,
        }


class Sensor(ABC):
    """Minimal sensor contract.

    Deliberately narrower than most sensor libraries: a sensor knows how to
    produce numbers and nothing else. Scheduling, event creation, and failure
    accounting live in :class:`BaseSensor` so every sensor type gets them for
    free and none can forget them.
    """

    @abstractmethod
    def read_raw(self) -> Reading:
        """Read the hardware exactly once, without retries or range checks.

        Raising is the correct behaviour on failure. Retries and range
        enforcement are the base class's job because they must be identical
        for every sensor type.
        """

    @abstractmethod
    def close(self) -> None:
        """Release the underlying resource. Must be idempotent."""


class BaseSensor(Sensor):
    """Shared behaviour: retries, range enforcement, and failure status.

    The failure policy is the interesting part. A single failed read is normal
    on a DHT22 - it returns garbage for the first conversion after power-on,
    and a marginal data line produces intermittent checksum failures. Reporting
    the sensor offline on the first error would make the status useless. So a
    read is retried within the call, and only ``failure_threshold``
    *consecutive exhausted reads* flips the status to ``DISCONNECTED``.
    """

    def __init__(
        self,
        *,
        enforce_range: bool = True,
        min_celsius: float = -40.0,
        max_celsius: float = 80.0,
        min_humidity: float = 0.0,
        max_humidity: float = 100.0,
        read_retries: int = 2,
        failure_threshold: int = 3,
    ) -> None:
        if read_retries < 0:
            raise SensorError(f"read_retries must be >= 0, got {read_retries}")
        if failure_threshold < 1:
            raise SensorError(f"failure_threshold must be >= 1, got {failure_threshold}")
        if min_celsius >= max_celsius:
            raise SensorError("min_celsius must be less than max_celsius")
        if min_humidity >= max_humidity:
            raise SensorError("min_humidity must be less than max_humidity")

        self._enforce_range = enforce_range
        self._min_celsius = min_celsius
        self._max_celsius = max_celsius
        self._min_humidity = min_humidity
        self._max_humidity = max_humidity
        self._read_retries = read_retries
        self._failure_threshold = failure_threshold

        self._consecutive_failures = 0
        self._status = SensorStatus.DISCONNECTED
        self._last_error: str | None = None
        self._last_reading: Reading | None = None
        self._closed = False
        self._mock = False

    # -- status -------------------------------------------------------------

    @property
    def status(self) -> SensorStatus:
        return self._status

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def last_reading(self) -> Reading | None:
        return self._last_reading

    @property
    def mock(self) -> bool:
        """Whether this sensor is simulated. Never set by a hardware sensor."""
        return self._mock

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def is_healthy(self) -> bool:
        return self._status is SensorStatus.CONNECTED

    # -- reading ------------------------------------------------------------

    def read(self) -> Reading:
        """Read the sensor, with retries and range enforcement.

        Raises :class:`~ciphermesh.errors.SensorError` (or a subclass) if no
        attempt succeeds. A caller that catches this and carries on is
        correct; a caller that substitutes a value is not.
        """
        if self._closed:
            raise SensorError("sensor is closed")

        last_error: Exception | None = None
        for attempt in range(self._read_retries + 1):
            try:
                reading = self.read_raw()
                self._check_range(reading)
            except SensorRateLimitError as exc:
                # A slow-converting sensor (the DHT22 needs 2s) refuses an
                # immediate retry, so retrying again would just produce the
                # same answer. Report the *earlier* failure instead: it is the
                # one that explains why a retry was attempted, and surfacing
                # "read too soon" to an operator whose problem is a bad data
                # line sends them to fix the wrong thing.
                # `from None`: the rate limit is a consequence of this retry
                # loop's own timing, not the cause of the failure being
                # reported, so chaining it would point the traceback at the
                # symptom the caller has to work around.
                self._record_failure(last_error or exc)
                raise last_error or exc from None
            except ChecksumError as exc:
                # A checksum failure is the documented symptom of a marginal
                # DHT22 data line, so it is retried rather than escalated.
                last_error = exc
                LOG.debug(
                    "sensor frame failed checksum, retrying",
                    extra={
                        "event_code": "SENSOR_READING",
                        "attempt": attempt + 1,
                        "detail": str(exc),
                    },
                )
                continue
            except SensorNotFoundError as exc:
                # Not a transient condition. Retrying a missing device just
                # delays the report that the hardware is absent, and
                # DISCONNECTED is the right status for it either way.
                self._record_failure(exc)
                raise
            except SensorError as exc:
                last_error = exc
                continue
            self._record_success(reading)
            return reading

        assert last_error is not None
        self._record_failure(last_error)
        raise last_error

    def _check_range(self, reading: Reading) -> None:
        if not self._enforce_range:
            return
        if not (self._min_celsius <= reading.temperature_c <= self._max_celsius):
            raise SensorError(
                f"temperature {reading.temperature_c}C is outside the configured "
                f"range {self._min_celsius}..{self._max_celsius}C. A value like this "
                "is a corrupt frame, not a measurement; the reading is discarded "
                "rather than published."
            )
        humidity = reading.humidity_percent
        if humidity is not None and not (
            self._min_humidity <= humidity <= self._max_humidity
        ):
            raise SensorError(
                f"humidity {humidity}% is outside the configured range "
                f"{self._min_humidity}..{self._max_humidity}%"
            )

    def _record_success(self, reading: Reading) -> None:
        was = self._status
        self._last_reading = reading
        self._last_error = None
        self._consecutive_failures = 0
        if self._mock:
            self._status = SensorStatus.MOCK
        else:
            self._status = SensorStatus.CONNECTED
        if was is not SensorStatus.CONNECTED:
            LOG.info(
                "sensor connected",
                extra={"event_code": "SENSOR_CONNECTED", "status": self._status.value},
            )

    def _record_failure(self, error: Exception) -> None:
        self._last_error = str(error)
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            if self._status is not SensorStatus.DISCONNECTED:
                LOG.error(
                    "sensor disconnected",
                    extra={
                        "event_code": "SENSOR_DISCONNECTED",
                        "consecutive_failures": self._consecutive_failures,
                        "detail": str(error),
                    },
                )
            self._status = SensorStatus.DISCONNECTED

    def mark_not_configured(self) -> None:
        """Record that the sensor is disabled in configuration."""
        self._status = SensorStatus.NOT_CONFIGURED

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

    def __enter__(self) -> BaseSensor:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"{type(self).__name__}(status={self._status.value}, "
            f"failures={self._consecutive_failures})"
        )
