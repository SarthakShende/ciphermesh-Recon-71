"""Event construction.

Everything that decides *what an event looks like* lives here: id rendering,
value rounding, sequence allocation, and signing. Keeping it in one place
means there is exactly one way to produce a signed event, which is what makes
"what is signed is what is displayed" a property rather than a convention.

The rule that motivates the rounding: the value is rounded **before** it is
signed, never after. A receiver recomputes the hash from the payload it
received, so any post-signature transformation of the value would make the
signed bytes and the stored bytes differ.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Callable

from ..config.schema import EventConfig
from ..constants import EventType, Unit
from ..crypto import canonical_bytes
from ..errors import EventValidationError
from ..logging_setup import get_logger
from .model import Event, SignedEvent, format_timestamp
from .sequence import SequenceAllocator

LOG = get_logger(__name__)

__all__ = ["EventFactory", "render_event_id"]


def render_event_id(
    template: str,
    *,
    device_id: str,
    sequence: int,
    moment: datetime,
    random_bytes: int = 2,
) -> str:
    """Render ``event.id_template``.

    The four placeholders are not interchangeable and none is optional:

    ``{date}``
        Readable prefix. Two nodes with the same clock still differ below.
    ``{device}``
        Makes the id attributable without a lookup.
    ``{sequence}``
        The ordering authority. A backup restored to the wrong date must not
        produce ids that collide with the originals.
    ``{random}``
        A CSPRNG suffix. This is what makes an id unguessable, so a peer
        cannot pre-compute the next id for a given device.

    ``{sequence}`` accepts a format spec such as ``{sequence:08d}``; the
    template is validated at config load, so a missing placeholder fails at
    startup rather than halfway through a reading.
    """
    if random_bytes < 1 or random_bytes > 8:
        raise EventValidationError(
            f"event.random_suffix_bytes must be between 1 and 8, got {random_bytes}"
        )
    return template.format(
        date=moment.strftime("%Y%m%d"),
        device=device_id,
        sequence=sequence,
        random=secrets.token_hex(random_bytes),
    )


class EventFactory:
    """Builds and signs outbound events for this node."""

    def __init__(
        self,
        config: EventConfig,
        *,
        device_id: str,
        key_id: str,
        signer: Callable[[dict], bytes],
        sequence: SequenceAllocator,
        device_name: str | None = None,
        location: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._device_id = device_id
        self._device_name = device_name
        self._location = location
        self._key_id = key_id
        self._signer = signer
        self._sequence = sequence
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def from_identity(
        cls,
        config: EventConfig,
        identity,
        sequence: SequenceAllocator,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> EventFactory:
        """Build a factory bound to an :class:`~ciphermesh.identity.IdentityManager`."""
        described = identity.describe()
        return cls(
            config,
            device_id=described.device_id,
            key_id=described.key_id,
            signer=identity.sign_event,
            sequence=sequence,
            device_name=described.device_name,
            location=described.location,
            clock=clock,
        )

    # -- construction -------------------------------------------------------

    def create(
        self,
        event_type: EventType,
        value: float,
        unit: Unit | None = None,
    ) -> SignedEvent:
        """Create and sign one event.

        ``unit`` defaults to the configured default unit.

        Order matters: the value is validated and rounded *before* a sequence
        is consumed, so a sensor that hands back NaN costs nothing. Once a
        number is allocated it is spent even if signing then fails - a gap is
        visible and harmless, whereas reusing a number would be an
        undetectable replay.
        """
        if not isinstance(event_type, EventType):
            raise EventValidationError(f"event type must be an EventType, got {event_type!r}")
        resolved_unit = unit if unit is not None else self._config.default_unit
        if not isinstance(resolved_unit, Unit):
            raise EventValidationError(f"unit must be a Unit, got {resolved_unit!r}")

        rounded = self._round(value)

        sequence = self._sequence.next()
        moment = self._clock()
        event_id = render_event_id(
            self._config.id_template,
            device_id=self._device_id,
            sequence=sequence,
            moment=moment,
            random_bytes=self._config.random_suffix_bytes,
        )

        event = Event(
            event_id=event_id,
            device_id=self._device_id,
            event_type=event_type,
            value=rounded,
            unit=resolved_unit,
            sequence=sequence,
            timestamp=format_timestamp(moment),
            version=self._config.version,
            device_name=self._device_name,
            location=self._location,
        )

        payload = event.canonical_payload()
        size = len(canonical_bytes(payload))
        if size > self._config.max_canonical_bytes:
            raise EventValidationError(
                f"event {event_id} canonicalises to {size} bytes, over the "
                f"{self._config.max_canonical_bytes}-byte limit. Shorten the device name "
                "or the location rather than truncating the payload."
            )

        signature = self._signer(payload)
        signed = SignedEvent(event=event, signature=signature, key_id=self._key_id)

        LOG.info(
            "event created",
            extra={
                "event_code": "EVENT_CREATED",
                "device_id": event.device_id,
                "event_id": event.event_id,
                "type": event_type.value,
                "sequence": event.sequence,
                "value": event.value,
                "unit": event.unit.value,
                "payload_bytes": size,
            },
        )
        return signed

    def create_reading(
        self,
        value: float,
        *,
        unit: Unit = Unit.CELSIUS,
        humidity: float | None = None,
    ) -> list[SignedEvent]:
        """Create the event set for one sensor sample.

        Temperature and humidity are separate events, not one event with two
        values: each gets its own sequence and its own signature, so a
        receiver can accept a temperature reading even if the humidity
        reading was lost or never existed.
        """
        events = [self.create(EventType.TEMPERATURE, value, unit)]
        if humidity is not None:
            events.append(self.create(EventType.HUMIDITY, humidity, Unit.PERCENT_RH))
        return events

    # -- helpers ------------------------------------------------------------

    def _round(self, value: float) -> float:
        """Round to the configured precision, rejecting non-finite input."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EventValidationError(f"sensor value must be a number, got {value!r}")
        numeric = float(value)
        # NaN survives every comparison below, and round(nan) is still nan, so
        # the check has to come first and be explicit.
        if numeric != numeric or numeric in (float("inf"), float("-inf")):
            raise EventValidationError(
                f"sensor returned a non-finite reading: {value!r}. The reading is "
                "discarded; no event is emitted in its place."
            )
        return round(numeric, self._config.value_decimals)

    @property
    def next_sequence(self) -> int:
        return self._sequence.peek() + 1
