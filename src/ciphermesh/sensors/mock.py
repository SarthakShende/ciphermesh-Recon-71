"""Mock sensor.

A mock exists so the rest of the node can be exercised on a machine with no
GPIO - CI, a laptop, a demo before the sensor is wired. Its whole purpose is to
be obvious.

That is why ``mock`` is carried on the :class:`~ciphermesh.sensors.base.Reading`
and reported as :attr:`~ciphermesh.constants.SensorStatus.MOCK`, and why the
registry refuses to hand a mock out unless configuration asks for one. A mock
that silently stood in for a missing DHT22 would put fabricated readings into a
signed, uploaded event stream under a real device id, and nothing downstream
would be able to tell.
"""

from __future__ import annotations

import time
from typing import Any

from ..constants import SensorStatus
from ..errors import SensorError
from ..logging_setup import get_logger
from .base import BaseSensor, Reading

LOG = get_logger(__name__)

__all__ = ["MockTemperatureSensor"]


class MockTemperatureSensor(BaseSensor):
    """A deterministic simulated sensor.

    Deterministic by default: it returns ``fixed_value`` until the reading is
    changed, so a test that signs an event can assert on the value it signed.
    ``sweep`` walks linearly between the configured bounds instead, for
    exercising charts and rate limits.
    """

    def __init__(
        self,
        *,
        fixed_value: float | None = 26.0,
        humidity: float | None = 55.0,
        sweep: bool = False,
        min_celsius: float = 0.0,
        max_celsius: float = 50.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(min_celsius=min_celsius, max_celsius=max_celsius, **kwargs)
        self._mock = True
        self._status = SensorStatus.MOCK
        self._fixed_value = fixed_value
        self._humidity = humidity
        self._sweep = sweep
        self._min = min_celsius
        self._max = max_celsius
        self._ticks = 0

    @property
    def is_sweeping(self) -> bool:
        return self._sweep

    def set_fixed_value(self, value: float) -> None:
        """Pin the next reading. The hook a test uses to drive the sensor.

        The value is range-checked here rather than at the next read. A mock is
        usually driven from a test that already knows the value is fine, so a
        failure at set time points straight at the line that set it; failing
        later would surface as a read error several calls away, in a test
        about something else.
        """
        if not (self._min <= value <= self._max):
            raise SensorError(
                f"mock value {value}C is outside the mock's own range "
                f"{self._min}..{self._max}C. A mock is checked against the same "
                "range as hardware, so a test cannot assert on a reading no "
                "real sensor could produce."
            )
        self._fixed_value = value
        self._sweep = False

    def read_raw(self) -> Reading:
        if self._sweep:
            # Wraps over the configured range so a long run does not walk off
            # the end and start failing the range check.
            span = self._max - self._min
            value = self._min + (self._ticks % 100) * span / 100.0
            self._ticks += 1
        else:
            value = self._fixed_value if self._fixed_value is not None else 26.0

        LOG.debug(
            "mock reading",
            extra={"event_code": "SENSOR_READING", "detail": str(value)},
        )
        return Reading(
            temperature_c=value,
            humidity_percent=self._humidity,
            timestamp=time.time(),
            mock=True,
        )
