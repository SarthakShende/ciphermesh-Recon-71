"""Sensor behaviour.

The assertions here are properties whose absence would be a real fault, not
coverage: a DHT22 that reports a corrupt frame as a plausible temperature, a
failed read that silently yields a stale value, or a mock standing in for a
sensor that is not there.

The 1-wire protocol is tested on a machine with no GPIO at all, by driving it
from a scripted line object and an injected clock.
"""

from __future__ import annotations

import random

import pytest

from ciphermesh.config.schema import SensorConfig
from ciphermesh.constants import DHT22_MIN_SAMPLE_INTERVAL_SECONDS, SensorStatus
from ciphermesh.errors import (
    ChecksumError,
    GpioUnavailableError,
    SensorError,
    SensorNotFoundError,
    SensorRateLimitError,
    ValidationError,
)
from ciphermesh.sensors import (
    BaseSensor,
    DHT22Sensor,
    MockTemperatureSensor,
    Reading,
    build,
    decode_frame,
    describe,
    is_mock,
    sensor_types,
)
from ciphermesh.sensors import gpio as gpio_mod
from ciphermesh.sensors.dht22 import FRAME_BITS, classify_bit

# ---------------------------------------------------------------------------
# Frame decoding
# ---------------------------------------------------------------------------


def frame_bytes(humidity: int, temperature_tenths: int) -> int:
    """Build a 40-bit frame the way a DHT22 transmits it: MSB byte first."""
    hum_hi, hum_lo = humidity >> 8, humidity & 0xFF
    temp_hi, temp_lo = temperature_tenths >> 8, temperature_tenths & 0xFF
    checksum = (hum_hi + hum_lo + temp_hi + temp_lo) & 0xFF
    value = 0
    for byte in (hum_hi, hum_lo, temp_hi, temp_lo, checksum):
        value = (value << 8) | byte
    return value


def test_a_datasheet_example_decodes():
    # Datasheet Table 2: 60.0% RH, 26.3C.
    temp, humidity = decode_frame(frame_bytes(600, 263))
    assert temp == pytest.approx(26.3)
    assert humidity == pytest.approx(60.0)


def test_a_failing_checksum_is_refused():
    good = frame_bytes(600, 263)
    with pytest.raises(ChecksumError, match="checksum mismatch"):
        decode_frame(good ^ 0x01)  # corrupt the checksum byte only


def test_a_negative_temperature_decodes_as_negative():
    """The AM2302 datasheet: "when highest bit of temperature is 1, it means
    the temperature is below 0 degree Celsius", with 1000 0000 0110 0101 given
    as -10.1C. The field is sign-magnitude - the magnitude is the low 15 bits
    - not two's complement.

    This is the case that used to be refused outright, on the theory that the
    part had no negative range. The AM2302 measures -40..80C, so that made a
    node below freezing report no temperature at all, which is exactly what an
    unplugged sensor looks like.
    """
    temp, humidity = decode_frame(frame_bytes(652, 0x8000 | 101))
    assert temp == pytest.approx(-10.1), "datasheet example: 0x8065 is -10.1C"
    assert humidity == pytest.approx(65.2)


def test_the_sign_bit_is_not_twos_complement():
    """0xFFFC is -4 in two's complement and -1.2C here. Getting this backwards
    turns every sub-zero reading into a large negative number that the range
    check then rejects - the same total data loss, with a more confusing
    error."""
    frame = frame_bytes(652, 0x8000 | 12)
    assert (frame >> 16) & 0x80, "test frame must have the sign bit set"
    assert decode_frame(frame)[0] == pytest.approx(-1.2)

    # And the two differ, so this is not a test that passes either way.
    twos = ((0xFF << 8) | 0xFC) & 0xFFFF
    assert twos != (0x80 << 8) | 12


def test_the_datasheet_negative_example_survives_a_read(clock):
    """End to end through the sensor, not just the decoder: a -10.1C frame read
    off a scripted bus has to come out as a negative reading the base class
    accepts, since -10.1C is inside the configured -40..80C range."""
    device = ScriptedDHT22(bits_for(frame_bytes(652, 0x8000 | 101)), clock)
    sensor = make_sensor(device.line, clock, enforce_range=True)
    assert sensor.read().temperature_c == pytest.approx(-10.1)


def test_humidity_is_the_plain_tenths_decode():
    """The humidity field is a plain 16-bit value in tenths of a percent: 813
    means 81.3%, not 100%.

    An earlier version of this special-cased 0x032D to 100%, on the theory
    that the datasheet's "100%" was encoded that way. It is not - the field is
    a straightforward tenths value - and the special case silently clamped
    every out-of-range humidity to 100%, which made the caller's range check
    unreachable for exactly the corrupt frames it exists to catch."""
    frame = frame_bytes(813, 200)
    _, humidity = decode_frame(frame)
    assert humidity == pytest.approx(81.3)

    _, at_max = decode_frame(frame_bytes(1000, 200))
    assert at_max == pytest.approx(100.0)

    _, over_max = decode_frame(frame_bytes(1001, 200))
    assert over_max == pytest.approx(100.1), "no clamping: the range check must see it"


def test_the_bottom_of_the_temperature_range_decodes():
    temp, humidity = decode_frame(frame_bytes(0, 0))
    assert temp == 0.0
    assert humidity == 0.0


def test_a_frame_wider_than_40_bits_is_refused():
    with pytest.raises(SensorError, match="out of range"):
        decode_frame(1 << FRAME_BITS)


def test_the_bit_threshold_sits_between_the_two_datasheet_pulses():
    """A '0' is 26-28us, a '1' is ~70us. The threshold has to be far enough
    from both that ordinary scheduling jitter cannot flip a bit."""
    assert not classify_bit(26.0)
    assert not classify_bit(28.0)
    assert classify_bit(70.0)
    assert classify_bit(40.0)


def test_a_slowly_detected_edge_still_classifies_the_bit():
    """The classification must survive a host that notices the edge late.

    A fixed sample point 40us after the edge reads a '0' bit as a '1' if the
    edge is detected even 5us late: the 27us pulse is already over, so the
    sample lands in the following low period. The failure is silent - the
    frame decodes and then fails its checksum on an otherwise healthy sensor -
    so the robustness has to come from measuring the width instead."""
    # Lateness shrinks the measured width by up to the lateness itself, and no
    # further. So a '0' bit tolerates 27us of lateness and a '1' bit 30us,
    # which is the real limit: a host descheduled by more than that misreads
    # the bit. That is not fixable by sampling strategy - only by a real-time
    # kernel, or by retrying - and the checksum catches every instance of it.
    for late_by_us in (0, 5, 20, 25):
        assert not classify_bit(27.0 - late_by_us), f"0-bit misread at +{late_by_us}us"
    for late_by_us in (0, 5, 20, 29):
        assert classify_bit(70.0 - late_by_us), f"1-bit misread at +{late_by_us}us"


def test_a_negative_pulse_width_is_a_programming_error():
    with pytest.raises(SensorError, match="negative"):
        classify_bit(-1.0)


# ---------------------------------------------------------------------------
# A scripted DHT22
# ---------------------------------------------------------------------------


class FakeClock:
    """Monotonic time that only moves when told to."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ScriptedLine:
    """A GPIO line that plays a DHT22's 1-wire conversation.

    ``script`` is a list of ``(duration_us, level)`` segments replayed in
    order, starting from whatever ``initial`` says. The sensor is modelled as
    the line being pulled low and released, which is what the DHT22 actually
    does - it has no data line of its own.
    """

    def __init__(
        self,
        script: list[tuple[int, int]],
        initial: int = 0,
        clock: FakeClock | None = None,
    ) -> None:
        self._segments = list(script)
        self._level = initial
        self._reads = 0
        self._clock = clock or FakeClock()
        self._armed_at: float | None = None
        self._timeline: list[tuple[float, float, int]] = []
        self.reads = 0
        self.drives: list[int] = []
        self.closed = False

    # -- GPIO interface used by DHT22Sensor --
    def write_drive(self, value: int) -> None:
        self.drives.append(value)
        if value == 1:
            # The sensor starts answering only after the host releases, not
            # when it pulls low: the DHT22 sees the falling edge, waits out
            # the pulse, and replies once the line goes back high. Arming on
            # the drive-low would put every sample before the response.
            self._begin_response()
            self._armed_at = self._clock()

    def read(self) -> int:
        self.reads += 1
        if self._armed_at is None:
            return self._level
        # Time-based rather than tick-based: the level is a function of when
        # the line is read, so a driver that polls at any rate sees exactly
        # what real hardware would show. A tick-based stand-in has to be
        # advanced by hand in step with the driver, which is a way of
        # encoding the expected polling pattern into the test.
        elapsed = self._clock() - self._armed_at
        elapsed_us = elapsed * 1_000_000.0
        for start_us, end_us, level in self._timeline:
            if start_us <= elapsed_us < end_us:
                return level
        # Past the end of the response the sensor lets the pull-up win.
        return 1

    @property
    def clock(self) -> FakeClock:
        return self._clock

    def close(self) -> None:
        self.closed = True

    def set_script(self, script: list[tuple[int, int]]) -> None:
        self._segments = list(script)

    # -- scripting --

    def _begin_response(self) -> None:
        """After the host's start pulse, the sensor answers: low, high, then
        one low/high pair per data bit.

        Built as an absolute timeline from the moment the host pulled low, so
        ``read()`` can answer any poll without being driven in lockstep.

        An empty script means the sensor never answers at all - the line stays
        wherever the host left it. That models an absent or unpowered sensor,
        which is a different fault from one that stops talking partway through
        a frame, so the two need to be distinguishable.
        """
        self._timeline = []
        if not self._segments:
            return

        timeline: list[tuple[float, float, int]] = []
        at_us = 0.0
        # The trailing low is the sensor pulling the bus down after the 40th
        # pulse before it releases. Without it, a last bit of '0' is
        # unrepresentable: the pulse ends and the line idles high, which is
        # indistinguishable from a '1' pulse that never ends. The 40th bit
        # carries the low bit of the checksum, so half of all frames would be
        # misread.
        for duration_us, level in [
            (30, 0),
            (80, 1),
            *_bit_segments(self._segments),
            (50, 0),
        ]:
            timeline.append((at_us, at_us + duration_us, level))
            at_us += duration_us
        self._timeline = timeline

    def _queue(self, segments: list[tuple[int, int]], initial: int) -> None:
        self._begin_response()


def _bit_segments(script: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Every data bit is a ~50us low followed by a high whose width and level
    encode the bit value."""
    segments: list[tuple[int, int]] = []
    for width, level in script:
        segments.append((50, 0))
        segments.append((width, level))
    return segments


class ScriptedDHT22:
    """Builds a DHT22 conversation for a set of data bits."""

    def __init__(self, bits: list[int], clock: FakeClock) -> None:
        self.clock = clock
        self.set_bits(bits)
        self.line = ScriptedLine(self.script, clock=clock)

    def set_bits(self, bits: list[int]) -> None:
        """Re-arm the conversation.

        Every data bit is a high pulse preceded by a low one. A '1' lasts
        ~70us, a '0' ~27us, so both have the same level and differ only in
        width - which is exactly why the driver has to sample at a fixed delay
        after the rising edge instead of reading the level at the edge."""
        self.script = [(70 if bit else 27, 1) for bit in bits]
        if getattr(self, "line", None) is not None:
            self.line.set_script(self.script)

    def tick(self) -> None:
        """No-op. The line is time-driven, so it needs no manual advance."""


def make_sensor(line, clock, **kwargs) -> DHT22Sensor:
    """A DHT22 with time and sleeping injected.

    The 1-wire protocol is a sequence of sleeps and deadline checks measured in
    microseconds, so testing it needs a clock under the test's control. The
    driver takes ``monotonic``/``sleep`` as parameters for exactly that; a real
    read is unaffected because the defaults are the real ones.
    """
    return DHT22Sensor(
        line,
        frame_timeout_ms=100.0,
        min_celsius=-40.0,
        max_celsius=80.0,
        monotonic=clock,
        sleep=clock.sleep,
        **kwargs,
    )


@pytest.fixture
def clock():
    """A monotonic clock that only moves when the driver sleeps."""
    return FakeClock()


def bits_for(frame: int) -> list[int]:
    return [(frame >> (FRAME_BITS - 1 - i)) & 1 for i in range(FRAME_BITS)]


def test_a_well_formed_frame_round_trips_through_the_line(clock):
    """The end-to-end property: what decode_frame accepts, the bit-banged read
    must produce. A mismatch here means the sampling point is wrong."""
    frame = frame_bytes(600, 263)
    device = ScriptedDHT22(bits_for(frame), clock)
    sensor = make_sensor(device.line, clock)

    reading = sensor.read_raw()
    assert reading.temperature_c == pytest.approx(26.3)
    assert reading.humidity_percent == pytest.approx(60.0)
    assert reading.mock is False


def test_the_host_never_drives_the_line_high(clock):
    """Open-drain: the host may pull low or release, never push high. Driving
    high would fight the sensor's own pull-up and could damage the pin."""
    device = ScriptedDHT22(bits_for(frame_bytes(600, 263)), clock)
    sensor = make_sensor(device.line, clock)
    sensor.read_raw()
    assert set(device.line.drives) == {0, 1}
    assert device.line.drives[0] == 0, "the start signal must begin by pulling low"
    assert device.line.drives[-1] == 1, "the line must be released to input"


def test_every_frame_shape_round_trips(clock):
    """The bit reader must be correct for the whole frame, not just the one
    example the round-trip test uses.

    A driver's mistake shows up as a one-bit slip, and which bit slips depends
    on the neighbouring pulses: a fixed sample point, a poll that steps over a
    27us pulse, or a resync that latches onto the previous pulse's tail all
    corrupt some patterns and not others. Real frames span the full range, so
    a driver tested only on 26.3C/60% can be wrong on a real sensor while every
    test passes.

    The seed is fixed so a failure is reproducible; change it when a case is
    worth preserving as a named test."""
    rng = random.Random(20240917)
    for _ in range(300):
        humidity = rng.randint(0, 1000)
        # Both signs: a frame whose temperature high byte has bit 15 set is a
        # different bit pattern at the start of the temperature field, and it is
        # the pattern a sub-zero reading actually produces.
        tenths = rng.randint(0, 800)
        negative = rng.random() < 0.4
        temperature = (0x8000 | tenths) if negative else tenths
        device = ScriptedDHT22(bits_for(frame_bytes(humidity, temperature)), clock)
        sensor = make_sensor(device.line, clock, enforce_range=True)
        reading = sensor.read_raw()
        expected = tenths / 10.0
        assert reading.temperature_c == pytest.approx(-expected if negative else expected)
        assert reading.humidity_percent == pytest.approx(humidity / 10.0)
        clock.advance(DHT22_MIN_SAMPLE_INTERVAL_SECONDS)  # clear the rate limit


def test_a_sensor_that_never_answers_times_out_rather_than_hanging(clock):
    """A missing or miswired sensor must raise, eventually. The deadline is
    what guarantees that on a line that is simply stuck low."""
    line = ScriptedLine([], initial=0, clock=clock)  # never responds
    sensor = make_sensor(line, clock)

    with pytest.raises(SensorError, match="did not respond"):
        sensor.read_raw()


def test_a_frame_that_stops_midway_is_reported_as_truncated(clock):
    """A line that drops out partway through must not be reported as a bad
    checksum: the frame is short, which points at the wiring, not at bit
    corruption."""
    device = ScriptedDHT22(bits_for(frame_bytes(600, 263)), clock)
    sensor = make_sensor(device.line, clock)
    # The sensor answers, then stops after 20 of 40 bits.
    device.line.set_script(
        [(70 if bit else 27, 1) for bit in bits_for(frame_bytes(600, 263))[:20]]
    )
    with pytest.raises(SensorError, match="truncated"):
        sensor.read_raw()


def test_a_corrupt_frame_is_reported_as_a_checksum_error(clock):
    """A marginal data line produces bad checksums. The error must say so."""
    # Corrupt the checksum byte only, so the frame is well formed but wrong.
    device = ScriptedDHT22(_break_checksum(bits_for(frame_bytes(600, 263))), clock)
    sensor = make_sensor(device.line, clock, read_retries=0)
    with pytest.raises(ChecksumError):
        sensor.read()


def _break_checksum(bits: list[int]) -> list[int]:
    """Flip one data bit, leaving the checksum byte intact.

    Flipping the checksum byte itself would not work: the decoder sums the four
    data bytes and compares, so any change to that byte changes the expected
    value too. Corrupting a data byte is what a marginal line actually does."""
    broken = list(bits)
    broken[0] ^= 1
    return broken


def test_a_retry_does_not_hide_the_checksum_error_behind_the_rate_limit(clock):
    """The DHT22 needs 2s to convert, so the base class's immediate retry is
    refused by the sensor. If that rate-limit error were the one reported, an
    operator with a bad data line would be told to slow down - advice that
    fixes nothing and hides the real fault."""
    device = ScriptedDHT22(_break_checksum(bits_for(frame_bytes(600, 263))), clock)
    sensor = make_sensor(device.line, clock, read_retries=2)
    with pytest.raises(ChecksumError):
        sensor.read()
    assert "checksum" in sensor.last_error.lower()


def test_reading_twice_within_the_datasheet_interval_is_refused(clock):
    """The AM2302 needs 2s to convert. A read inside that window reliably
    returns a bad frame, so it is refused rather than converted into a
    checksum error the operator has to decode."""
    device = ScriptedDHT22(bits_for(frame_bytes(600, 263)), clock)
    sensor = make_sensor(device.line, clock)
    sensor._last_conversion = clock()
    clock.advance(DHT22_MIN_SAMPLE_INTERVAL_SECONDS / 2)
    with pytest.raises(SensorRateLimitError, match="needs"):
        sensor.read_raw()


def test_the_rate_limit_does_not_block_a_read_after_the_interval(clock):
    device = ScriptedDHT22(bits_for(frame_bytes(600, 263)), clock)
    sensor = make_sensor(device.line, clock)
    sensor._last_conversion = clock()
    clock.advance(DHT22_MIN_SAMPLE_INTERVAL_SECONDS + 0.1)
    reading = sensor.read_raw()
    assert reading.temperature_c == pytest.approx(26.3)


# ---------------------------------------------------------------------------
# Range enforcement and failure accounting
# ---------------------------------------------------------------------------


def test_an_out_of_range_reading_is_refused_not_published(clock):
    """A disconnected data line produces values a real sensor cannot make.
    Publishing one would be fabricating a measurement.

    The check lives in ``BaseSensor.read``, not in the protocol layer, so this
    has to go through ``read()`` - calling ``read_raw()`` would bypass the very
    thing under test."""
    device = ScriptedDHT22(bits_for(frame_bytes(0, 999)), clock)
    sensor = make_sensor(device.line, clock, enforce_range=True, read_retries=0)
    with pytest.raises(SensorError, match="outside the configured range"):
        sensor.read()
    assert sensor.last_reading is None, "a refused reading must not be retained"


def test_an_out_of_range_humidity_is_refused_too(clock):
    """The humidity field has its own range, and a corrupt frame can produce a
    plausible temperature with an impossible humidity."""
    # 1001 tenths is 100.1%, one step past the physical maximum. The frame is
    # valid - right length, right checksum - so only the range check can stop
    # it, which is exactly what is under test.
    device = ScriptedDHT22(bits_for(frame_bytes(1001, 200)), clock)
    sensor = make_sensor(device.line, clock, enforce_range=True, read_retries=0)
    with pytest.raises(SensorError, match="humidity"):
        sensor.read()


def test_range_checks_can_be_disabled(clock):
    device = ScriptedDHT22(bits_for(frame_bytes(0, 999)), clock)
    sensor = make_sensor(device.line, clock, enforce_range=False)
    reading = sensor.read_raw()
    assert reading.temperature_c == pytest.approx(99.9)


def test_the_status_is_not_optimistic_before_the_first_read():
    """A sensor that has never been read is DISCONNECTED, not CONNECTED. An
    optimistic status would be reported by the API before a single bit was
    sampled."""
    device = ScriptedDHT22([], FakeClock())
    sensor = make_sensor(device.line, FakeClock())
    assert sensor.status is SensorStatus.DISCONNECTED
    assert sensor.is_healthy() is False


def test_repeated_failure_flips_the_status_only_at_the_threshold(clock):
    """A single failed read is normal on a DHT22. Reporting the node offline on
    the first error would make the status useless, so the threshold is what
    distinguishes a marginal read from an absent sensor."""
    sensor = _StubSensor(
        clock, error=SensorError("no response"), failure_threshold=3
    )
    for expected in (1, 2):
        with pytest.raises(SensorError):
            sensor.read()
        assert sensor.consecutive_failures == expected, "threshold reached too early"

    with pytest.raises(SensorError):
        sensor.read()
    assert sensor.consecutive_failures == 3
    assert sensor.status is SensorStatus.DISCONNECTED
    assert sensor.is_healthy() is False


def test_a_success_after_a_failure_clears_the_error(clock):
    """The node came back. The stale error must not keep being reported, or
    the API shows a fault that no longer exists."""
    sensor = _StubSensor(clock, error=SensorError("no response"), failure_threshold=2)
    with pytest.raises(SensorError):
        sensor.read()
    assert sensor.last_error

    sensor.error = None
    reading = sensor.read()
    assert reading.temperature_c == 21.5
    assert sensor.last_error is None
    assert sensor.consecutive_failures == 0
    assert sensor.status is SensorStatus.CONNECTED


def test_a_missing_sensor_is_not_retried(clock):
    """Retrying an absent device only delays the report that the hardware is
    not there. The attempt count proves the retry loop was skipped."""
    sensor = _StubSensor(
        clock, error=SensorNotFoundError("absent"), failure_threshold=3
    )
    with pytest.raises(SensorNotFoundError):
        sensor.read()
    assert sensor.attempts == 1, "a missing device must not be retried"
    assert sensor.status is SensorStatus.DISCONNECTED


def test_a_good_read_keeps_the_sensor_connected(clock):
    sensor = _StubSensor(clock, failure_threshold=3)
    for _ in range(5):
        sensor.read()
    assert sensor.status is SensorStatus.CONNECTED
    assert sensor.consecutive_failures == 0
    assert sensor.last_reading.temperature_c == 21.5


def test_reading_a_closed_sensor_is_an_error(clock):
    device = ScriptedDHT22([], clock)
    sensor = make_sensor(device.line, clock)
    sensor.close()
    with pytest.raises(SensorError, match="closed"):
        sensor.read()


def test_close_releases_the_line_and_is_idempotent(clock):
    device = ScriptedDHT22([], clock)
    sensor = make_sensor(device.line, clock)
    sensor.close()
    sensor.close()
    assert device.line.closed is True


def test_a_non_finite_reading_is_refused_at_construction():
    with pytest.raises(SensorError, match="non-finite"):
        Reading(temperature_c=float("nan"))
    with pytest.raises(SensorError, match="non-finite"):
        Reading(temperature_c=1.0, humidity_percent=float("inf"))


# ---------------------------------------------------------------------------
# Mock sensor
# ---------------------------------------------------------------------------


def test_a_mock_is_labelled_as_one_everywhere():
    """A simulated reading must be recognisable as simulated for its whole
    life, or a test node's data is indistinguishable from a real node's."""
    sensor = MockTemperatureSensor(fixed_value=26.0)
    reading = sensor.read()
    assert reading.mock is True
    assert sensor.mock is True
    assert is_mock(sensor) is True
    assert sensor.status is SensorStatus.MOCK
    assert describe(sensor)["mock"] is True


def test_a_hardware_sensor_is_never_marked_mock(clock):
    device = ScriptedDHT22([], clock)
    assert make_sensor(device.line, clock).mock is False


def test_a_mock_is_deterministic_by_default():
    """A test that signs an event has to be able to assert on the value."""
    sensor = MockTemperatureSensor(fixed_value=26.0)
    assert [sensor.read().temperature_c for _ in range(5)] == [26.0] * 5


def test_a_mock_can_be_driven_by_a_test():
    """A test that needs a specific value - to reproduce a reading it saw in
    the field, say - has to be able to set one, or it has to fake the whole
    sensor instead."""
    sensor = MockTemperatureSensor(fixed_value=26.0, min_celsius=-40.0, max_celsius=80.0)
    sensor.set_fixed_value(-3.5)
    assert sensor.read().temperature_c == -3.5


def test_a_mock_obeys_its_range_too():
    """Range enforcement is in the base class, so it applies to a mock as well.
    A mock that could be set to an impossible value would let a test assert on
    a reading no real sensor could produce - and a mock that is checked less
    strictly than hardware tests the wrong code path."""
    sensor = MockTemperatureSensor(fixed_value=26.0, min_celsius=0.0, max_celsius=50.0)
    with pytest.raises(SensorError, match="outside the mock's own range"):
        sensor.set_fixed_value(-3.5)


def test_a_sweeping_mock_stays_inside_its_range():
    sensor = MockTemperatureSensor(fixed_value=None, sweep=True, min_celsius=0.0, max_celsius=50.0)
    values = [sensor.read().temperature_c for _ in range(200)]
    assert min(values) >= 0.0
    assert max(values) <= 50.0
    assert len(set(values)) > 1


def test_a_mock_reports_no_hardware_to_read():
    """A mock's read goes through the base class and must not claim to have
    talked to a sensor that does not exist."""
    device = ScriptedDHT22([], FakeClock())
    sensor = make_sensor(device.line, FakeClock(), mock=True)
    with pytest.raises(SensorError, match="no hardware"):
        sensor.read_raw()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_a_disabled_sensor_reports_not_configured_and_refuses_to_read():
    sensor = build(SensorConfig(enabled=False, type="dht22"))
    assert sensor.status is SensorStatus.NOT_CONFIGURED
    with pytest.raises(SensorError, match="disabled"):
        sensor.read()


def test_an_unknown_sensor_type_is_refused_with_the_valid_list():
    with pytest.raises(SensorError, match=r"unknown sensor\.type"):
        build(SensorConfig(enabled=True, type="dht99"))
    assert "dht22" in sensor_types()
    assert "mock" in sensor_types()


def test_a_hardware_sensor_with_no_gpio_backend_does_not_become_a_mock(monkeypatch):
    """The single most important property of this module.

    A Pi with no usable GPIO and a configured DHT22 must fail loudly. If this
    returned a mock instead, the node would sign and upload fabricated
    temperature readings under its real device id, and nothing downstream could
    tell them from measurements.
    """
    monkeypatch.setattr(gpio_mod, "_try_lgpio", lambda chip, pin: None)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", lambda chip, pin: None)
    with pytest.raises(SensorNotFoundError, match="no GPIO backend"):
        build(SensorConfig(enabled=True, type="dht22", gpio_pin=4))


def test_the_failure_message_names_the_thing_the_operator_must_check(monkeypatch):
    monkeypatch.setattr(gpio_mod, "_try_lgpio", lambda chip, pin: None)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", lambda chip, pin: None)
    with pytest.raises(SensorNotFoundError) as caught:
        build(SensorConfig(enabled=True, type="dht22", gpio_pin=4))
    message = str(caught.value)
    assert "gpio_pin" in message
    assert "python3-lgpio" in message
    assert "system-site-packages" in message


def test_the_configured_pin_reaches_the_backend(monkeypatch):
    """A sensor on pin 4 must be requested on pin 4. The default in the config
    is 4, so a hardcoded pin would be invisible in testing."""
    requested: list[tuple[int, int]] = []

    class FakeBackend:
        name = "fake"
        driver = object()
        description = "fake"
        precise = True

    def fake_resolve(pin: int, chip):
        requested.append((pin, chip))
        return FakeBackend(), object()

    monkeypatch.setattr("ciphermesh.sensors.gpio.resolve_pin", fake_resolve)
    monkeypatch.setattr(DHT22Sensor, "read_raw", lambda self: Reading(20.0))
    build(SensorConfig(enabled=True, type="dht22", gpio_pin=17))
    assert requested == [(17, "gpiochip0")]


def test_the_configured_chip_reaches_the_backend(monkeypatch):
    """A Raspberry Pi 5 has the header pins on chip 4, not chip 0. Opening the
    configured chip as if it were the pin number is a bug this test exists for:
    it made `gpiochip_open(4)` for a sensor on pin 4, which is a different chip
    entirely and fails with EBUSY or a silent no-op depending on the kernel."""
    requested: list[tuple[int, int]] = []

    class FakeBackend:
        name = "fake"
        driver = object()
        description = "fake"
        precise = True

    monkeypatch.setattr(
        "ciphermesh.sensors.gpio.resolve_pin",
        lambda pin, chip: (
            requested.append((pin, gpio_mod.parse_chip_number(chip)))
            or FakeBackend(),
            object(),
        ),
    )
    monkeypatch.setattr(DHT22Sensor, "read_raw", lambda self: Reading(20.0))
    build(SensorConfig(enabled=True, type="dht22", gpio_pin=17, gpio_chip="gpiochip4"))
    assert requested == [(17, 4)]


def test_a_mock_is_built_only_when_asked_for():
    sensor = build(SensorConfig(enabled=True, type="mock", mock_fixed_value=21.0))
    assert is_mock(sensor) is True
    assert sensor.read().temperature_c == 21.0


def test_am2302_is_the_same_part_as_dht22(monkeypatch):
    """They are the same sensor under two names; both must build a DHT22."""
    requested: list[int] = []

    class FakeBackend:
        name = "fake"
        driver = object()
        description = "fake"
        precise = True

    monkeypatch.setattr(
        "ciphermesh.sensors.gpio.resolve_pin",
        lambda pin, chip: (requested.append(pin) or FakeBackend(), object()),
    )
    monkeypatch.setattr(DHT22Sensor, "read_raw", lambda self: Reading(20.0))
    build(SensorConfig(enabled=True, type="AM2302", gpio_pin=4))
    assert requested == [4]


def test_describe_reports_the_reading_and_the_failure_count():
    sensor = MockTemperatureSensor(fixed_value=30.0)
    sensor.read()
    report = describe(sensor)
    assert report["status"] == SensorStatus.MOCK.value
    assert report["last_reading"]["temperature_c"] == 30.0
    assert report["consecutive_failures"] == 0


def test_describe_handles_no_sensor_at_all():
    assert describe(None)["status"] == SensorStatus.NOT_CONFIGURED.value


# ---------------------------------------------------------------------------
# GPIO chip naming
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [
        ("0", 0),
        ("gpiochip0", 0),
        ("/dev/gpiochip0", 0),
        ("4", 4),
        ("gpiochip4", 4),
        ("/dev/gpiochip4", 4),
        ("  2  ", 2),
        (3, 3),
    ],
)
def test_every_spelling_of_a_chip_name_names_the_same_chip(spelling, expected):
    """Tools that write `gpio_chip` spell it differently and all of them are in
    the wild. Reading `gpiochip0` as chip number 0 and the string "0" as chip
    number 0 has to be the same answer, or the field means two things."""
    assert gpio_mod.parse_chip_number(spelling) == expected


@pytest.mark.parametrize("bad", ["", "gpiochip", "gpiochipX", "/dev/i2c-1", "0x4", -1, True])
def test_a_chip_name_that_names_no_chip_is_rejected(bad):
    with pytest.raises(ValueError):
        gpio_mod.parse_chip_number(bad)


@pytest.mark.parametrize("spelling", ["0", "gpiochip0", "/dev/gpiochip0", "gpiochip4"])
def test_the_config_accepts_exactly_what_the_parser_accepts(spelling):
    """The parser lives in the sensors layer and the check lives in the config
    layer, because importing one from the other is a circular import. This
    asserts the two copies of the rule agree, so they cannot drift."""
    SensorConfig(enabled=True, gpio_chip=spelling).validate()


@pytest.mark.parametrize("bad", ["", "gpiochip", "nope", "/dev/i2c-1"])
def test_the_config_rejects_a_chip_name_the_parser_would_reject(bad):
    with pytest.raises(ValidationError, match=r"sensor\.gpio_chip"):
        SensorConfig(enabled=True, gpio_chip=bad).validate()


def test_interface_and_gpio_pin_may_not_contradict_each_other():
    """Both name the same pin and the template sets both, but only gpio_pin is
    acted on. A mismatch would mean editing the line that looks right and
    reading the other one."""
    with pytest.raises(ValidationError, match="have to agree"):
        SensorConfig(enabled=True, gpio_pin=4, interface="gpio:17").validate()


def test_a_non_gpio_sensor_interface_is_rejected():
    with pytest.raises(ValidationError, match=r"sensor\.interface"):
        SensorConfig(enabled=True, interface="i2c:0x48").validate()


def test_interface_may_be_left_empty():
    SensorConfig(enabled=True, gpio_pin=17, interface="").validate()


# ---------------------------------------------------------------------------
# GPIO ladder
# ---------------------------------------------------------------------------


def test_the_ladder_reports_every_rung_it_tried(monkeypatch):
    """The error has to name the mechanisms, or an operator cannot tell which
    package to install."""
    monkeypatch.setattr(gpio_mod, "_try_lgpio", lambda chip, pin: None)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", lambda chip, pin: None)
    with pytest.raises(GpioUnavailableError) as caught:
        gpio_mod.resolve(4)
    message = str(caught.value)
    assert "lgpio" in message
    assert "/dev/gpiochip0" in message
    assert "Linux 5.13" in message


def test_the_ladder_passes_the_chip_number_to_every_rung(monkeypatch):
    """Each rung receives the chip number, not the pin. These are different
    numbers and conflating them opens the wrong chip."""
    seen: list[tuple[str, int, int]] = []

    def lgpio_ok(chip, pin):
        seen.append(("lgpio", chip, pin))
        return None

    def chip_ok(chip, pin):
        seen.append(("chip", chip, pin))
        return gpio_mod.GpioBackend("gpiochip", object(), "test", False)

    monkeypatch.setattr(gpio_mod, "_try_lgpio", lgpio_ok)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", chip_ok)
    gpio_mod.resolve(17, "gpiochip4")
    assert seen == [("lgpio", 4, 17), ("chip", 4, 17)]


def test_the_ladder_prefers_lgpio_over_the_kernel_device(monkeypatch):
    """lgpio's per-call timing is tighter, so it must be tried first when
    available. A DHT22 bit is 27us; a backend with looser timing produces
    intermittent checksum errors, so the order is not arbitrary."""
    order: list[str] = []

    def lgpio_ok(chip, pin):
        order.append("lgpio")
        return gpio_mod.GpioBackend("lgpio", object(), "test", True)

    def chip_ok(chip, pin):
        order.append("chip")
        return gpio_mod.GpioBackend("gpiochip", object(), "test", False)

    monkeypatch.setattr(gpio_mod, "_try_lgpio", lgpio_ok)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", chip_ok)
    backend = gpio_mod.resolve(4)
    assert order == ["lgpio"]
    assert backend.name == "lgpio"


def test_the_ladder_falls_through_to_the_kernel_device(monkeypatch):
    monkeypatch.setattr(gpio_mod, "_try_lgpio", lambda chip, pin: None)
    backend = gpio_mod.GpioBackend("gpiochip", object(), "test", False)
    monkeypatch.setattr(gpio_mod, "_try_gpiochip", lambda chip, pin: backend)
    assert gpio_mod.resolve(4).name == "gpiochip"


def test_a_broken_lgpio_import_does_not_stop_the_ladder(monkeypatch):
    """A userland build of a kernel library raises something other than
    ImportError when it is wrong. That must degrade to the next rung, not
    crash the node."""
    import sys

    broken = type(sys)("lgpio")

    def raise_on_import(*args, **kwargs):
        raise OSError("undefined symbol: gpiochip_open")

    broken.__getattr__ = raise_on_import
    monkeypatch.setitem(sys.modules, "lgpio", broken)

    fell_through: list[str] = []
    monkeypatch.setattr(
        gpio_mod,
        "_try_gpiochip",
        lambda chip, pin: (
            fell_through.append("chip")
            or gpio_mod.GpioBackend("gpiochip", object(), "t", False)
        ),
    )
    assert gpio_mod.resolve(4).name == "gpiochip"
    assert fell_through == ["chip"]


# ---------------------------------------------------------------------------
# lgpio: the documented API, and only the documented API
# ---------------------------------------------------------------------------


class FakeLgpio:
    """Records the calls made against it, in order.

    Only the functions the real module exports are defined. Anything the code
    calls that is not here raises AttributeError, so calling a function lgpio
    does not have - as the previous implementation did - fails these tests
    instead of failing on a Pi.
    """

    SET_OPEN_DRAIN = 8  # value is irrelevant to the test, only its presence

    def __init__(self, *, level: int = 1) -> None:
        self.calls: list[tuple] = []
        self.level = level
        self.opened_chip: int | None = None
        self.claimed: tuple[int, int, int] | None = None

    def gpiochip_open(self, chip):
        self.calls.append(("open", chip))
        self.opened_chip = chip
        return 7

    def gpio_claim_output(self, handle, gpio, level, lFlags):
        self.calls.append(("claim_output", handle, gpio, level, lFlags))
        self.claimed = (handle, gpio, level)
        self.level = level
        return 0

    def gpio_write(self, handle, gpio, level):
        self.calls.append(("write", handle, gpio, level))
        self.level = level
        return 0

    def gpio_read(self, handle, gpio):
        self.calls.append(("read", handle, gpio))
        return self.level

    def gpio_free(self, handle, gpio):
        self.calls.append(("free", handle, gpio))
        return 0

    def gpiochip_close(self, handle):
        self.calls.append(("close", handle))
        return 0


def _lgpio_backend(fake: FakeLgpio) -> gpio_mod.GpioBackend:
    driver = gpio_mod._LgpioDriver(fake, chip=0, pin=4)
    return gpio_mod.GpioBackend("lgpio", driver, "test", True)


def test_the_lgpio_chip_opened_is_the_chip_not_the_pin():
    """`gpiochip_open` takes a chip number. Passing the pin opened whatever
    chip happened to have that number, so a DHT22 on pin 4 talked to
    /dev/gpiochip4 and never worked."""
    fake = FakeLgpio()
    _lgpio_backend(fake)
    assert fake.opened_chip == 0

    fake = FakeLgpio()
    gpio_mod._LgpioDriver(fake, chip=4, pin=4)
    assert fake.opened_chip == 4


def test_the_lgpio_line_is_claimed_as_an_open_drain_output_released():
    """A push-pull claim can drive the bus high, which fights the sensor and is
    a hardware fault rather than a failed read. Claiming with
    SET_OPEN_DRAIN and level 1 is 'released', which is the idle state."""
    fake = FakeLgpio()
    _lgpio_backend(fake)
    handle, gpio, level = fake.claimed
    assert (handle, gpio) == (7, 4)
    assert level == 1, "the line must start released, not driving low"
    claim = next(c for c in fake.calls if c[0] == "claim_output")
    assert claim[4] == FakeLgpio.SET_OPEN_DRAIN


def test_the_driver_line_is_open_drain():
    """A '0' is written by driving the pin low; a '1' is the pin released with
    the external pull-up doing the work. Driving it high would fight the
    sensor.

    This is the one GPIO behaviour the whole 1-wire protocol rests on, so it is
    asserted against the real call sequence, not a proxy for it."""
    fake = FakeLgpio()
    line = gpio_mod.LgpioLine(_lgpio_backend(fake), 4)
    line.write_drive(0)
    line.write_drive(1)
    writes = [c for c in fake.calls if c[0] == "write"]
    assert writes == [("write", 7, 4, 0), ("write", 7, 4, 1)]
    # The value 1 here means "released to input", not "drive high": the line was
    # claimed with SET_OPEN_DRAIN, so the kernel turns a 1 into high-impedance.
    assert all(value in (0, 1) for _, _, _, value in writes)
    assert not any(
        name in ("gpio_set_output", "gpio_set_input", "gpio_get") for name, *_ in fake.calls
    ), "the previous implementation called three functions lgpio does not export"


def test_the_driver_reports_a_high_line_as_one():
    """What the host sees is the line level, which for a released open-drain
    line is whatever the pull-up and the sensor between them put there."""
    for level in (0, 1):
        fake = FakeLgpio()
        line = gpio_mod.LgpioLine(_lgpio_backend(fake), 4)
        # Set after the claim: claiming sets the level to 1 (released), which
        # is what the driver is supposed to do.
        fake.level = level
        assert line.read() == level


def test_reading_goes_through_the_chip_handle():
    """Every lgpio call needs the handle. Dropping it reads a pin number as if
    it were a handle."""
    fake = FakeLgpio(level=1)
    line = gpio_mod.LgpioLine(_lgpio_backend(fake), 4)
    line.read()
    assert ("read", 7, 4) in fake.calls


def test_an_lgpio_without_the_open_drain_flag_is_refused():
    """Rather than guess the numeric value of a flag that is documented by name
    only, the value is read from the module. A module without it is one we
    cannot claim safely, and the ladder moves on."""

    class NoFlag:
        __file__ = "/usr/lib/python3/dist-packages/lgpio.py"
        VERSION = "0.2.2"

        def gpiochip_open(self, chip):
            raise AssertionError("must not be reached")

    with pytest.raises(GpioUnavailableError, match="SET_OPEN_DRAIN"):
        gpio_mod._LgpioDriver(NoFlag(), 0, 4)


def test_a_negative_lgpio_status_is_an_error_not_a_handle():
    """With lgpio's exception mode off, failures come back as a negative errno
    rather than an exception. Using -1 as a handle would corrupt the kernel."""

    class Failing:
        SET_OPEN_DRAIN = 8
        __file__ = "/x/lgpio.py"
        VERSION = "0.2.2"

        def gpiochip_open(self, chip):
            return -5

    with pytest.raises(GpioUnavailableError, match="status -5"):
        gpio_mod._LgpioDriver(Failing(), 0, 4)


def test_closing_the_lgpio_line_frees_the_line_and_closes_the_chip():
    fake = FakeLgpio()
    line = gpio_mod.LgpioLine(_lgpio_backend(fake), 4)
    line.close()
    names = [c[0] for c in fake.calls]
    # Free before close: closing the chip alone would release the line
    # implicitly, but relying on that leaves the order to chance.
    assert names.index("free") < names.index("close")
    assert names[-2:] == ["free", "close"]


def test_closing_the_line_also_closes_the_chip_handle_it_came_from():
    """Leaving the chip descriptor open leaks it per sensor per restart, and on
    the kernel backend that descriptor is what holds the line claimed."""
    closed: list[str] = []

    class Driver:
        def write_drive(self, value):
            pass

        def read(self):
            return 1

        def close(self):
            closed.append("chip")

    backend = gpio_mod.GpioBackend("lgpio", Driver(), "test", True)
    gpio_mod.LgpioLine(backend, 4).close()
    assert closed == ["chip"]


# ---------------------------------------------------------------------------
# kernel uAPI v2: the numbers and the struct
# ---------------------------------------------------------------------------


def test_the_ioctl_numbers_match_the_kernel_headers():
    """These are not in any Python module and a wrong one does not fail
    obviously. Each is the _IOWR encoding of the struct in
    include/uapi/linux/gpio.h.

    GET_LINE is 0x07, not 0x0B - 0x0B is the deprecated v1
    GPIO_GET_LINEINFO_UNWATCH_IOCTL, and it carries a different struct, so a
    request built for it was rejected outright."""
    assert gpio_mod._GPIO_V2_GET_LINE_IOCTL == 0xC250B407
    assert gpio_mod._GPIO_V2_LINE_GET_VALUES_IOCTL == 0xC010B40E
    assert gpio_mod._GPIO_V2_LINE_SET_VALUES_IOCTL == 0xC010B40F


def test_the_line_request_struct_has_the_kernel_layout():
    """gpio_v2_line_request is 64 offsets, a consumer label, a line config, a
    line count, an event buffer size, padding, and the fd the kernel fills in.
    sizeof() is embedded in the ioctl number, so a layout that does not match
    makes GET_LINE the wrong command and every request fails with EINVAL."""
    assert gpio_mod._LINE_REQUEST_SIZE == 592
    assert gpio_mod._LINE_VALUES.size == 16
    # Field offsets, from the declaration order in the header.
    assert gpio_mod._OFF_CONSUMER == 256
    assert gpio_mod._OFF_CONFIG == 288
    assert gpio_mod._OFF_NUM_LINES == 560
    assert gpio_mod._OFF_FD == 588
    assert gpio_mod._LINE_CONFIG_ATTRS_SIZE == 240


def test_the_request_is_packed_at_the_offsets_the_header_says():
    """A struct built to the right total size but with fields in the wrong
    places is still wrong, and still fails with EINVAL."""
    import struct as _struct

    request = bytearray(gpio_mod._LINE_REQUEST_SIZE)
    gpio_mod._LINE_OFFSETS.pack_into(request, 0, *([4] + [0] * 63))
    request[256 : 256 + len(gpio_mod.GPIO_CONSUMER)] = gpio_mod.GPIO_CONSUMER.encode()
    gpio_mod._LINE_CONFIG_HEAD.pack_into(request, 256 + 32, gpio_mod._LINE_FLAGS, 0, 0, 0, 0, 0, 0)
    gpio_mod._LINE_TAIL.pack_into(request, 560, 1, 0, 0, 0, 0, 0, 0, 0)

    assert _struct.unpack_from("=64I", request, 0)[0] == 4, "the pin is offsets[0]"
    assert request[256:].split(b"\x00")[0] == b"ciphermesh-dht22"
    flags, num_attrs = _struct.unpack_from("=Q I", request, 288)[:2]
    assert num_attrs == 0, "no per-line overrides"
    assert flags == gpio_mod._LINE_FLAGS
    assert request[320:560] == bytearray(240), "unused attrs must be zeroed"
    assert _struct.unpack_from("=7I i", request, 560)[0] == 1, "num_lines"
    assert _struct.unpack_from("=7I i", request, 560)[-1] == 0, "fd left for the kernel"


def test_the_line_is_requested_as_an_open_drain_output():
    """Not INPUT|OUTPUT. The kernel rejects that combination with EINVAL -
    gpiolib-cdev.c's gpio_v2_line_flags_validate() calls the two flags
    contradictory - so the old request could never succeed on any kernel.

    An output line can still be read: linereq_get_values() opens with "It's ok
    to read values of output lines". OPEN_DRAIN is what makes it safe, driving
    low for 0 and releasing to input for 1."""
    assert gpio_mod._LINE_FLAG_OUTPUT == 1 << 3
    assert gpio_mod._LINE_FLAG_OPEN_DRAIN == 1 << 6
    assert gpio_mod._LINE_FLAGS == (1 << 3) | (1 << 6)
    assert not gpio_mod._LINE_FLAGS & gpio_mod._LINE_FLAG_INPUT


class FakeChipFile:
    def __init__(self) -> None:
        self.fd = 99
        self.closed = False

    def fileno(self) -> int:
        return self.fd

    def close(self) -> None:
        self.closed = True


def test_the_ioctl_line_drives_and_releases_through_the_masked_value(monkeypatch):
    """``bits`` is the value and ``mask`` selects the lines. The kernel returns
    EINVAL for an empty mask, so the mask must name the one requested line.

    With OPEN_DRAIN requested, bits=0 drives the line low and bits=1 releases
    it. The old code packed the value into the mask and left the bits zero, so
    'release' set nothing at all and 'drive low' set every line it had."""
    calls: list[tuple[int, int, tuple[int, int] | None]] = []
    values_ioctls = (
        gpio_mod._GPIO_V2_LINE_GET_VALUES_IOCTL,
        gpio_mod._GPIO_V2_LINE_SET_VALUES_IOCTL,
    )

    def fake_ioctl(fd, request, arg=0):
        calls.append(
            (fd, request, _struct_unpack(arg) if request in values_ioctls else None)
        )
        if request == gpio_mod._GPIO_V2_GET_LINE_IOCTL:
            # The kernel writes the new line fd into the request buffer; 42 is
            # distinguishable from the chip's 99 so the two can be told apart.
            buf = bytearray(arg)
            gpio_mod._LINE_TAIL.pack_into(buf, gpio_mod._OFF_NUM_LINES, 1, 0, 0, 0, 0, 0, 0, 42)
            return buf
        return arg

    monkeypatch.setattr("fcntl.ioctl", fake_ioctl)
    chip = FakeChipFile()
    backend = gpio_mod.GpioBackend("gpiochip", chip, "test", False)
    line = gpio_mod.ChipIoctlLine(backend, 4)

    # The constructor releases the line, so the first thing it must do after
    # claiming it is write bits=1 - a v2 output line is requested driving low.
    sets = [c[2] for c in calls if c[1] == gpio_mod._GPIO_V2_LINE_SET_VALUES_IOCTL]
    assert sets[0] == (1, 1), "release means bits=1, mask=the requested line"

    line.write_drive(0)
    line.write_drive(1)
    sets = [c[2] for c in calls if c[1] == gpio_mod._GPIO_V2_LINE_SET_VALUES_IOCTL]
    assert sets[-2:] == [(0, 1), (1, 1)]

    # Reads go through the line fd, never the chip fd, and ask for the same
    # mask; an empty mask reads nothing and the kernel says EINVAL.
    calls.clear()
    line.read()
    gets = [c[2] for c in calls if c[1] == gpio_mod._GPIO_V2_LINE_GET_VALUES_IOCTL]
    assert gets == [(0, 1)]
    assert all(c[0] == 42 for c in calls), "the line fd is 42; the chip fd is not it"


def test_the_ioctl_line_reports_what_the_pull_up_actually_put_on_the_line(monkeypatch):
    """An output line's reported level is the real line level, so a released
    open-drain line reads the pull-up's high rather than the driven level."""
    import struct as _struct

    def fake_ioctl(fd, request, arg=0):
        if request == gpio_mod._GPIO_V2_GET_LINE_IOCTL:
            buf = bytearray(arg)
            gpio_mod._LINE_TAIL.pack_into(buf, gpio_mod._OFF_NUM_LINES, 1, 0, 0, 0, 0, 0, 0, 42)
            return buf
        if request == gpio_mod._GPIO_V2_LINE_GET_VALUES_IOCTL:
            return _struct.pack("=QQ", 1, 1)
        return arg

    monkeypatch.setattr("fcntl.ioctl", fake_ioctl)
    backend = gpio_mod.GpioBackend("gpiochip", FakeChipFile(), "test", False)
    assert gpio_mod.ChipIoctlLine(backend, 4).read() == 1


def test_closing_the_ioctl_line_closes_the_line_fd_and_the_chip(monkeypatch):
    closed: list[int] = []
    monkeypatch.setattr("os.close", lambda fd: closed.append(fd))
    monkeypatch.setattr("fcntl.ioctl", lambda fd, request, arg=0: bytearray(arg))
    chip = FakeChipFile()
    backend = gpio_mod.GpioBackend("gpiochip", chip, "test", False)
    line = gpio_mod.ChipIoctlLine(backend, 4)
    line.close()
    assert closed, "the line fd is leaked if it is not closed"
    assert chip.closed, "the chip fd is leaked if it is not closed"


def test_a_failed_line_request_closes_the_chip_it_was_given(monkeypatch):
    """The ladder opens the chip before the line exists. If claiming the line
    fails, the chip descriptor has to go back, or every failed start leaks
    one."""

    def refuse(fd, request, arg=0):
        raise OSError(16, "Device or resource busy")

    monkeypatch.setattr("fcntl.ioctl", refuse)
    chip = FakeChipFile()
    backend = gpio_mod.GpioBackend("gpiochip", chip, "test", False)
    with pytest.raises(GpioUnavailableError, match="open-drain"):
        gpio_mod.ChipIoctlLine(backend, 4)
    assert chip.closed


def test_the_backend_report_names_both_mechanisms():
    report = gpio_mod.backend_report()
    assert "lgpio" in report
    assert "/dev/gpiochip0" in report
    # The venv/system-site-packages trap is the most common cause of an
    # invisible apt install, so it is always reported.
    assert "dist-packages" in report


def _struct_unpack(buf) -> tuple[int, int]:
    import struct as _struct

    return _struct.unpack("=QQ", bytes(buf))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubSensor(BaseSensor):
    """A sensor whose read outcome is set directly.

    The failure-accounting rules belong to ``BaseSensor``, not to the DHT22, so
    testing them through a DHT22 would mean arranging a specific protocol
    failure to observe a generic retry. A stub that raises what it is told to
    isolates the policy under test.
    """

    def __init__(self, clock, *, error=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.error = error
        self.attempts = 0
        self.closed = False

    def read_raw(self) -> Reading:
        self.attempts += 1
        if self.error is not None:
            raise self.error
        return Reading(temperature_c=21.5, humidity_percent=50.0, timestamp=0.0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.closed = True
