"""Sensor construction from configuration.

One place decides what ``sensor.type`` means, so a typo is a clear error at
startup rather than a sensor that silently never reads.

The rule this module exists to enforce: **a configured hardware sensor that
cannot be built is an error.** It does not fall back to a mock. Silently
simulating a temperature reading on a node whose sensor is unplugged produces
signed, uploaded events that look exactly like real ones, and the failure is
invisible until someone trusts the data. The only way to get a mock is to ask
for one by name.
"""

from __future__ import annotations

from typing import Any, Callable

from ..config.schema import SensorConfig
from ..constants import SensorStatus
from ..errors import GpioUnavailableError, SensorError, SensorNotFoundError
from ..logging_setup import get_logger
from .base import BaseSensor, Reading, Sensor
from .dht22 import DHT22Sensor
from .mock import MockTemperatureSensor

LOG = get_logger(__name__)

__all__ = [
    "SENSOR_TYPES",
    "build",
    "describe",
    "is_mock",
    "sensor_types",
]

#: Configuration ``sensor.type`` -> constructor. Populated at the bottom of the
#: module so the mapping is declared once, in one readable block.
SENSOR_TYPES: dict[str, Callable[..., Sensor]] = {}


def _build_dht22(config: SensorConfig) -> Sensor:
    from .gpio import resolve_pin

    backend, line = resolve_pin(config.gpio_pin, config.gpio_chip)
    LOG.info(
        "dht22 initialised",
        extra={
            "event_code": "SENSOR_CONNECTED",
            "backend": backend.name,
            "detail": backend.description,
            "chip": config.gpio_chip,
            "pin": config.gpio_pin,
        },
    )
    return DHT22Sensor(
        line,
        frame_timeout_ms=config.frame_timeout_ms,
        **range_kwargs(config),
        read_retries=config.read_retries,
        failure_threshold=config.failure_threshold,
    )


def _build_mock(config: SensorConfig) -> Sensor:
    return MockTemperatureSensor(
        fixed_value=config.mock_fixed_value,
        sweep=config.mock_sweep,
        min_celsius=config.min_valid_celsius,
        max_celsius=config.max_valid_celsius,
        enforce_range=config.enforce_range,
        read_retries=config.read_retries,
        failure_threshold=config.failure_threshold,
    )


SENSOR_TYPES = {
    "dht22": _build_dht22,
    "am2302": _build_dht22,
    "mock": _build_mock,
}


def range_kwargs(config: SensorConfig) -> dict[str, Any]:
    """The subset of config that is a sensor concern rather than a policy one."""
    return {
        "enforce_range": config.enforce_range,
        "min_celsius": config.min_valid_celsius,
        "max_celsius": config.max_valid_celsius,
        "min_humidity": config.min_valid_humidity,
        "max_humidity": config.max_valid_humidity,
    }


def sensor_types() -> list[str]:
    return sorted(SENSOR_TYPES)


def build(config: SensorConfig) -> Sensor:
    """Construct the configured sensor.

    A disabled sensor returns a placeholder whose status is
    ``NOT_CONFIGURED`` and whose ``read()`` raises. Returning ``None`` instead
    would push the "is there a sensor" check onto every caller, and one caller
    would forget it.
    """
    if not config.enabled:
        LOG.info(
            "sensor disabled in configuration",
            extra={"event_code": "SENSOR_DISCONNECTED"},
        )
        return _DisabledSensor()

    kind = (config.type or "").strip().lower()
    factory = SENSOR_TYPES.get(kind)
    if factory is None:
        raise SensorError(
            f"unknown sensor.type {config.type!r}; expected one of {sensor_types()}"
        )

    try:
        return factory(config)
    except GpioUnavailableError as exc:
        # The single most likely misconfiguration: a Pi without any usable
        # GPIO backend. Surfaced as a sensor error with the full reason, not
        # swallowed into a mock.
        raise SensorNotFoundError(
            f"cannot initialise sensor type {config.type!r} on gpio_pin "
            f"{config.gpio_pin}: {exc}"
        ) from exc


def is_mock(sensor: Sensor) -> bool:
    """Whether this sensor is simulated.

    Callers that create events must check this. A mock reading must not be
    signed and uploaded as if it came from the sensor.
    """
    return bool(getattr(sensor, "mock", False))


def describe(sensor: Sensor | None) -> dict[str, Any]:
    """A status summary for the monitoring API and ``ciphermesh device``."""
    if sensor is None:
        return {"status": SensorStatus.NOT_CONFIGURED.value, "type": None, "mock": False}
    reading: Reading | None = getattr(sensor, "last_reading", None)
    return {
        "type": type(sensor).__name__,
        "status": getattr(sensor, "status", SensorStatus.NOT_CONFIGURED).value,
        "mock": is_mock(sensor),
        "consecutive_failures": getattr(sensor, "consecutive_failures", 0),
        "last_error": getattr(sensor, "last_error", None),
        "last_reading": reading.as_dict() if reading else None,
    }


class _DisabledSensor(BaseSensor):
    """Placeholder for ``sensor.enabled: false``.

    Refuses to read rather than reporting a plausible value, so a disabled
    sensor cannot contribute data to anything.
    """

    def __init__(self) -> None:
        super().__init__()
        self.mark_not_configured()

    def read_raw(self) -> Reading:
        raise SensorError("sensor is disabled in configuration")

    def close(self) -> None:
        super().close()
