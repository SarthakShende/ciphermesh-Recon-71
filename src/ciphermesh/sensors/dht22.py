"""DHT22/AM2302 temperature and humidity sensor.

The DHT22 is a single-wire digital sensor with no register map and no
read command: the entire protocol is "hold the line low, release it, and time
40 bits coming back". That makes it cheap, robust to noise, and trivially
spoofable by anything that can drive a GPIO.

The frame is 40 bits, MSB first:

===========  ==========================  ==================================
Bits         Field                       Datasheet range
===========  ==========================  ==================================
0-7          humidity, high byte        together with bits 8-15, a 16-bit
8-15         humidity, low byte         value in tenths of %RH, 0..1000
16-23        temperature, high byte     together with bits 24-31, a 16-bit
24-31        temperature, low byte      value in tenths of C, bit 15 = sign
32-39        checksum                   sum of bytes 0-3, low byte
===========  ==========================  ==================================

Two details of the frame are easy to get wrong, so both are spelled out here
rather than left to the reader of a datasheet:

**Negative temperature.** Bit 7 of byte 2 is the sign. The AM2302 datasheet
states that when the highest bit of the temperature field is 1 the reading is
below zero, and gives ``1000 0000 0110 0101`` as -10.1C. The field is
sign-magnitude, not two's complement. The sensor measures -40..80C, so a
decoder that refuses a set sign bit - as an earlier version here did, on the
theory that the part had no negative range - reports no temperature at all
below freezing, which is indistinguishable from an unplugged sensor.

**No humidity special case.** The humidity field is a plain 16-bit value in
tenths of a percent: 65.2%RH arrives as 652. An earlier version of this module
special-cased the byte pair ``0x03 0x2D`` to 100%, which silently clamped every
out-of-range frame to 100% and made the caller's range check unreachable for
exactly the corrupt frames it exists to catch.

Decoding is separated from timing in :func:`decode_frame`, so the bit-packing
rules can be tested exhaustively without a GPIO.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from ..constants import DHT22_MIN_SAMPLE_INTERVAL_SECONDS
from ..errors import ChecksumError, SensorError, SensorRateLimitError
from ..logging_setup import get_logger
from .base import BaseSensor, Reading

LOG = get_logger(__name__)

#: A DHT22 frame is 5 bytes.
FRAME_BITS = 40
FRAME_BYTES = 5

#: Datasheet: the conversion takes at most 4ms, so a frame that has not
#: started within this window means the sensor is not responding at all.
#: Chosen well above the datasheet maximum because the host is a general
#: purpose Linux process and may be descheduled mid-read.
RESPONSE_TIMEOUT_MS = 40.0

#: A data bit is a high pulse whose width carries the value: 26-28us for '0'
#: and ~70us for '1'. The threshold sits between the datasheet's two clusters.
#: The margin is wide (27 vs 70) precisely so that a host which measures the
#: pulse to within a few microseconds - or a few dozen - still classifies
#: correctly.
BIT_THRESHOLD_US = 40.0

#: Upper bound on a '0' bit's high pulse (datasheet: 26-28us). A line still
#: high this long after a rising edge cannot be a '0' pulse in progress, so
#: the sensor must have released it. This is what identifies the final data
#: bit: after the 40th pulse the sensor stops driving and the pull-up takes
#: the line high, so a checksum ending in '0' has no falling edge to measure.
#: 35us is past the 28us maximum with room for a late edge detection.
ZERO_PULSE_MAX_US = 35.0

#: Nominal width of a '1' pulse, reported when the line is still high after
#: ZERO_PULSE_MAX_US and so cannot be measured. Only its being above
#: BIT_THRESHOLD_US matters, not the exact value.
ONE_PULSE_US = 70.0

#: How often the line is polled while waiting for an edge. Short relative to a
#: data bit so edges are not missed; the deadline, not this, bounds the wait.
POLL_INTERVAL_US = 5

#: Host-side start signal: the line must be held low for at least 1ms (DHT22
#: datasheet says 1-10ms). 2ms is inside that window and reliably long enough
#: for the sensor to latch.
START_LOW_MS = 2.0

__all__ = ["DHT22Sensor", "classify_bit", "decode_frame"]


def decode_frame(frame: int) -> tuple[float, float | None]:
    """Decode 40 raw bits into ``(temperature_c, humidity_percent)``.

    The humidity return is optional only because the base class supports
    sensors that do not measure it; a DHT22 always supplies one, so this
    function always returns a pair.

    Raises :class:`~ciphermesh.errors.ChecksumError` on a failed checksum, and
    :class:`~ciphermesh.errors.SensorError` on a frame that is well-formed
    enough to decode but physically impossible.
    """
    if not 0 <= frame < (1 << FRAME_BITS):
        raise SensorError(f"DHT22 frame out of range: {frame:#x}")

    data = [(frame >> (8 * (4 - i))) & 0xFF for i in range(FRAME_BYTES)]

    expected = (data[0] + data[1] + data[2] + data[3]) & 0xFF
    if data[4] != expected:
        raise ChecksumError(
            f"DHT22 checksum mismatch: got {data[4]:#04x}, expected {expected:#04x}. "
            "Usually a marginal data line, a missing pull-up, or a read that "
            "started too soon after the previous one."
        )

    # Bit 7 of byte 2 is the sign. The AM2302 datasheet is explicit: "when
    # highest bit of temperature is 1, it means the temperature is below 0
    # degree Celsius", with 1000 0000 0110 0101 given as -10.1C. The value is
    # sign-magnitude, not two's complement: the magnitude is the low 15 bits,
    # and the sign is applied after scaling.
    #
    # This matters more than it looks. The AM2302 measures -40..80C, and
    # refusing every negative frame means a node in winter reports no
    # temperature at all - and a node reporting nothing looks exactly like a
    # node whose sensor is unplugged.
    negative = bool(data[2] & 0x80)
    magnitude = ((data[2] & 0x7F) << 8) | data[3]

    # Straight decode, with no clamping or special-casing of the humidity
    # field. The DHT22 is specified as 0-100% RH, so anything above that is a
    # corrupt frame, and the caller's range check is what should refuse it.
    # Clamping here would quietly turn a corrupt read into a plausible 100% and
    # make that check unreachable.
    humidity = ((data[0] << 8) | data[1]) / 10.0
    temperature = -magnitude / 10.0 if negative else magnitude / 10.0

    return temperature, humidity


class DHT22Sensor(BaseSensor):
    """A DHT22 on a single GPIO, read by bit-banging the 1-wire protocol.

    ``line`` is anything with ``write_drive(0|1)`` and ``read()``; the GPIO
    backends in :mod:`ciphermesh.sensors.gpio` provide one, and tests provide
    a scripted stand-in. Keeping the timing logic independent of the GPIO
    backend is what makes this testable without a Pi.
    """

    def __init__(
        self,
        line: Any,
        *,
        frame_timeout_ms: float = RESPONSE_TIMEOUT_MS,
        mock: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall_clock: Callable[[], float] = time.time,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if frame_timeout_ms <= 0:
            raise SensorError(f"frame_timeout_ms must be > 0, got {frame_timeout_ms}")
        self._line = line
        self._mock = mock
        self._frame_timeout_ms = frame_timeout_ms
        self._last_conversion = 0.0
        # Time is injected rather than reached for via the module. The 1-wire
        # protocol is a sequence of sleeps and deadline checks, so it can only
        # be tested with a clock under the test's control - and binding
        # time.sleep as a default argument captures it at import, which
        # silently makes the protocol untestable.
        self._monotonic = monotonic
        self._sleep = sleep
        self._wall_clock = wall_clock

    # -- Sensor -------------------------------------------------------------

    def read_raw(self) -> Reading:
        if self._mock:
            raise SensorError("mock sensor has no hardware to read")

        elapsed = self._monotonic() - self._last_conversion
        if 0 < elapsed < DHT22_MIN_SAMPLE_INTERVAL_SECONDS:
            # Not fatal - the caller may be asking early. Surfacing it makes
            # the rate-limit visible instead of silently corrupting a frame.
            # Its own error type, because BaseSensor.read() must be able to
            # tell "the sensor is sick" from "you asked too soon".
            raise SensorRateLimitError(
                f"DHT22 was read {elapsed:.2f}s after the last one; the sensor "
                f"needs {DHT22_MIN_SAMPLE_INTERVAL_SECONDS}s to convert. A read "
                "inside that window reliably returns a checksum error."
            )

        try:
            frame = self._read_frame()
        finally:
            # Recorded even on failure. The conversion the sensor started has
            # happened whether or not we captured it, so the next attempt still
            # has to wait.
            self._last_conversion = self._monotonic()

        temperature, humidity = decode_frame(frame)
        return Reading(
            temperature_c=temperature,
            humidity_percent=humidity,
            timestamp=self._wall_clock(),
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        release = getattr(self._line, "close", None)
        if callable(release):
            release()

    # -- protocol -----------------------------------------------------------

    def _read_frame(self) -> int:
        line = self._line
        now = self._monotonic
        sleep = self._sleep
        deadline = now() + self._frame_timeout_ms / 1000.0

        # 1. Host start signal: pull low, wait, release to input.
        line.write_drive(0)
        sleep(START_LOW_MS / 1000.0)
        line.write_drive(1)

        # 2. The sensor answers with ~30us low then ~80us high. Waiting for
        #    the line to go low is what synchronises us to the sensor's clock.
        #    Polling rather than sleeping a fixed interval, because the host's
        #    scheduling delay is unbounded and the sensor's is not.
        if not _wait_for_level(line, 0, deadline, "start response", now, sleep):
            raise SensorError(
                "DHT22 did not respond to the start signal. Check the pin "
                "(gpio_pin), the 4.7k pull-up resistor, and that the sensor is "
                "powered."
            )

        # 3. The response high, then 40 data bits. Each bit is ~50us low
        #    followed by a high whose width encodes the value.
        _wait_for_level(line, 1, deadline, "response high", now, sleep)
        _wait_for_level(line, 0, deadline, "first data bit", now, sleep)

        frame = 0
        for bit in range(FRAME_BITS):
            if not _wait_for_level(line, 1, deadline, f"bit {bit} rising", now, sleep):
                raise SensorError(f"DHT22 frame truncated at bit {bit}")
            pulse_us = _measure_pulse_us(line, deadline, f"bit {bit}", now, sleep)
            if pulse_us is None:
                raise SensorError(f"DHT22 frame truncated at bit {bit}")
            frame = (frame << 1) | (1 if classify_bit(pulse_us) else 0)

            # Ride out the rest of this bit's pulse. A '1' is still high when
            # the measurement gives up, and the next bit does not start until
            # the line falls, so waiting for that fall is what keeps the loop
            # aligned to one bit per pulse. Skipping it would let the next
            # rising-edge wait match the tail of the current pulse and read it
            # as bit n+1, losing sync for the remainder of the frame.
            #
            # The last bit is the exception: the sensor releases the line after
            # the 40th pulse, and the pull-up holds it high, so that falling
            # edge may never arrive and there is nothing left to stay aligned
            # to.
            if bit < FRAME_BITS - 1 and not _wait_for_level(
                line, 0, deadline, f"bit {bit} falling", now, sleep
            ):
                raise SensorError(f"DHT22 frame truncated at bit {bit}")

        LOG.debug(
            "DHT22 frame read",
            extra={"event_code": "SENSOR_READING", "frame": hex(frame)},
        )
        return frame

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"DHT22Sensor(status={self._status.value})"


def classify_bit(pulse_us: float) -> bool:
    """True if a high pulse of ``pulse_us`` was a '1' bit.

    A data bit's *value is its width*: 26-28us for '0', ~70us for '1'. The
    threshold sits between those two datasheet clusters.

    Measuring the width rather than sampling the level at a fixed delay after
    the rising edge is what makes this robust. A fixed sample point at 40us
    works only if the edge is detected to within a microsecond or two: detect
    the edge late and the sample point overshoots the 27us '0' pulse entirely,
    landing in the low period that follows and reading the bit as a '1'. That
    is a silent one-bit error, and it shows up as a checksum failure on an
    otherwise healthy sensor. A measured width shrinks by the same late
    detection but stays on the correct side of a threshold with 43us of
    margin.
    """
    if pulse_us < 0:
        raise SensorError(f"pulse width cannot be negative: {pulse_us}us")
    return pulse_us >= BIT_THRESHOLD_US


def _measure_pulse_us(
    line: Any,
    deadline: float,
    what: str,
    now: Callable[[], float],
    sleep: Callable[[float], None],
) -> float | None:
    """Width in microseconds of the high pulse starting at the next edge.

    Returns None if no rising edge arrives before the deadline, which means the
    sensor stopped talking mid-frame.

    A '0' pulse is bounded at ``ZERO_PULSE_MAX_US``, so a line *still* high
    that long after the rising edge cannot be a '0' - the bit is a '1' and the
    sensor has moved on. The wait has to stop there rather than run to the
    deadline, because the falling edge it is looking for may never come: after
    the 40th bit the sensor releases the line and the pull-up holds it high, so
    the last bit of a frame has no falling edge at all. Waiting for one would
    stall every read until the frame timed out and then discard a frame that
    was read perfectly.
    """
    if not _wait_for_level(line, 1, deadline, f"{what} rising", now, sleep):
        return None
    started = now()
    while True:
        elapsed_us = (now() - started) * 1_000_000.0
        if line.read() == 0:
            return elapsed_us
        if elapsed_us >= ZERO_PULSE_MAX_US:
            return ONE_PULSE_US
        if now() > deadline:
            return None
        # Never sleep past the point where a '0' would have ended. Landing
        # after it would find a line back at its idle high and measure a
        # width that includes the dead time, turning a '0' into a '1'.
        remaining_us = ZERO_PULSE_MAX_US - elapsed_us
        if remaining_us <= 0:
            return ONE_PULSE_US
        sleep(min(POLL_INTERVAL_US, remaining_us) / 1_000_000.0)


def _wait_for_level(
    line: Any,
    level: int,
    deadline: float,
    what: str,
    now: Callable[[], float],
    sleep: Callable[[float], None],
) -> bool:
    """Poll ``line`` until it reads ``level``. False if ``deadline`` passes.

    ``now`` and ``sleep`` are required rather than defaulted to the ``time``
    module. A default argument would bind the real functions at import time,
    so a test could replace the clock and still block on real sleeps - the
    deadline would never be reached under a fake clock that only a fake sleep
    advances.

    The poll interval is short relative to the 27us pulse we have to
    discriminate, but the deadline is what actually bounds this: on a
    descheduled host the poll granularity does not matter, only that the
    overall read eventually gives up.
    """
    while line.read() != level:
        if now() > deadline:
            LOG.debug(
                "DHT22 timeout waiting for line level",
                extra={"event_code": "SENSOR_READING", "waiting_for": what},
            )
            return False
        sleep(POLL_INTERVAL_US / 1_000_000.0)
    return True
