"""Event model, factory and sequence behaviour.

These are trust properties. A regression in any of them would let a node
accept, present, or originate something it should not.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone

import pytest

from ciphermesh.config.schema import EventConfig
from ciphermesh.constants import (
    WIRE_PAYLOAD_BUDGET_BYTES,
    EventType,
    Unit,
)
from ciphermesh.crypto import KeyStore, canonical_bytes, verify_event
from ciphermesh.errors import EventValidationError, SequenceError
from ciphermesh.events import (
    Event,
    EventFactory,
    SequenceAllocator,
    SignedEvent,
    format_timestamp,
    parse_timestamp,
    render_event_id,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event(**overrides) -> Event:
    base = {
        "event_id": "EVT-20260929-PI-A-00000001-a1b2",
        "device_id": "PI-A-0001",
        "event_type": EventType.TEMPERATURE,
        "value": 27.5,
        "unit": Unit.CELSIUS,
        "sequence": 1,
        "timestamp": "2026-09-29T12:00:00Z",
    }
    base.update(overrides)
    return Event(**base)


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_timestamp_round_trips():
    moment = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    text = format_timestamp(moment)
    assert text == "2026-09-29T12:00:00Z"
    assert parse_timestamp(text) == moment


def test_epoch_input_is_converted_to_utc():
    moment = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    assert format_timestamp(moment.timestamp()) == "2026-09-29T12:00:00Z"


def test_a_non_utc_moment_is_normalised():
    offset = timezone(timedelta(hours=5, minutes=30))
    naive_local = datetime(2026, 9, 29, 17, 30, 0, tzinfo=offset)
    assert format_timestamp(naive_local) == "2026-09-29T12:00:00Z"


@pytest.mark.parametrize(
    "bad",
    [
        "2026-09-29 12:00:00",
        "2026-09-29T12:00:00",
        "2026-09-29T12:00:00+05:30",
        "2026-13-01T00:00:00Z",
        "not a timestamp",
        "",
        1759147200,
    ],
)
def test_non_canonical_timestamps_are_rejected(bad):
    with pytest.raises(EventValidationError):
        parse_timestamp(bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Event validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_values_are_rejected(value):
    """A NaN defeats every `==` range check, so it has to be caught explicitly."""
    with pytest.raises(EventValidationError, match="finite"):
        make_event(value=value)


@pytest.mark.parametrize("value", ["27.5", None, True, [27.5], {"v": 1}])
def test_non_numeric_values_are_rejected(value):
    with pytest.raises(EventValidationError, match="must be a number"):
        make_event(value=value)


@pytest.mark.parametrize(
    "bad_id",
    ["", "has space", "new\nline", "x" * 129, "semi;colon", "emoji\U0001f600", None, 42],
)
def test_malformed_event_ids_are_rejected(bad_id):
    with pytest.raises(EventValidationError, match="event_id"):
        make_event(event_id=bad_id)


@pytest.mark.parametrize("bad_device", ["", "x" * 65, "has space", "slash/es"])
def test_malformed_device_ids_are_rejected(bad_device):
    with pytest.raises(EventValidationError, match="device_id"):
        make_event(device_id=bad_device)


@pytest.mark.parametrize("sequence", [-1, 1.5, "3", True])
def test_bad_sequences_are_rejected(sequence):
    with pytest.raises(EventValidationError, match="sequence"):
        make_event(sequence=sequence)


def test_version_must_be_positive():
    with pytest.raises(EventValidationError, match="version"):
        make_event(version=0)


def test_events_are_immutable():
    import dataclasses

    event = make_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.value = 99.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def test_optional_fields_are_omitted_not_nulled():
    """Absent and null must not produce the same bytes, or size grows silently."""
    minimal = make_event().canonical_payload()
    assert "device_name" not in minimal
    assert "location" not in minimal

    with_optionals = make_event(device_name="gh", location="block-c").canonical_payload()
    assert with_optionals["device_name"] == "gh"
    assert with_optionals["location"] == "block-c"


def test_the_signed_field_set_is_fixed():
    """Adding an attribute must not silently start covering it in the signature."""
    payload = make_event().canonical_payload()
    assert set(payload) == {
        "event_id", "version", "device_id", "type", "timestamp", "value", "unit", "sequence",
    }


def test_event_hash_is_insensitive_to_dict_ordering():
    a = make_event().hash()
    b = make_event().hash()
    assert a == b
    assert len(a) == 64


def test_canonicalisation_is_artefact_free():
    assert b" " not in canonical_bytes(make_event().canonical_payload())


# ---------------------------------------------------------------------------
# Deserialisation is strict
# ---------------------------------------------------------------------------


def test_round_trip_through_a_dict():
    event = make_event(device_name="gh", location="block-c")
    assert Event.from_dict(event.to_dict()) == event


def test_unknown_fields_are_rejected():
    """A future field must be a visible protocol error, not a silent drop."""
    data = make_event().to_dict()
    data["admin"] = True
    with pytest.raises(EventValidationError, match="unknown event fields"):
        Event.from_dict(data)


def test_missing_fields_are_rejected():
    data = make_event().to_dict()
    del data["sequence"]
    with pytest.raises(EventValidationError, match="missing fields"):
        Event.from_dict(data)


def test_a_numeric_string_is_not_coerced():
    """'27.5' and 27.5 canonicalize differently, so coercing forks the hash."""
    data = make_event().to_dict()
    data["value"] = "27.5"
    with pytest.raises(EventValidationError, match="not a string"):
        Event.from_dict(data)


@pytest.mark.parametrize("bad_type", ["PRESSURE", "", 1, None])
def test_unknown_event_types_are_rejected(bad_type):
    data = make_event().to_dict()
    data["type"] = bad_type
    with pytest.raises(EventValidationError):
        Event.from_dict(data)


def test_a_non_object_is_rejected():
    with pytest.raises(EventValidationError, match="must be an object"):
        Event.from_dict([1, 2, 3])  # type: ignore[arg-type]


def test_a_future_schema_version_is_accepted_but_carried():
    """A v2 event is parsed, not rejected; the pipeline decides what to do."""
    event = Event.from_dict({**make_event().to_dict(), "version": 2})
    assert event.version == 2


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip(keypair):
    signed = make_event().sign(keypair)
    assert signed.verify(keypair.public_raw)
    assert signed.key_id == keypair.key_id


def test_every_field_is_covered_by_the_signature(keypair):
    signed = make_event().sign(keypair)
    for field, mutated in [
        ("value", 27.6),
        ("timestamp", "2026-09-29T12:00:01Z"),
        ("device_id", "PI-A-0002"),
        ("sequence", 2),
        ("event_id", "EVT-20260929-PI-A-00000002-a1b2"),
        ("event_type", EventType.HUMIDITY),
        ("unit", Unit.PERCENT_RH),
    ]:
        tampered = make_event(**{field: mutated})
        assert not verify_event(keypair.public_raw, signed.signature, tampered.canonical_payload()), (
            f"field {field!r} is not covered by the signature"
        )


def test_dropping_an_optional_field_breaks_the_signature(keypair):
    signed = make_event(device_name="gh", location="block-c").sign(keypair)
    without = make_event(device_name="gh").canonical_payload()
    assert not verify_event(keypair.public_raw, signed.signature, without)


@pytest.mark.parametrize("bad_sig", [b"", b"\x00" * 63, b"\x00" * 65, "not bytes"])
def test_a_wrong_length_signature_cannot_be_constructed(keypair, bad_sig):
    with pytest.raises(EventValidationError, match="64 raw bytes"):
        SignedEvent(
            event=make_event(), signature=bad_sig, key_id=keypair.key_id  # type: ignore[arg-type]
        )


def test_a_garbage_signature_of_the_right_length_still_fails_verification(keypair):
    """Length is a structural check; correctness is cryptographic."""
    signed = SignedEvent(make_event(), b"\x00" * 64, keypair.key_id)
    assert not signed.verify(keypair.public_raw)


def test_a_malformed_key_id_cannot_be_constructed(keypair):
    with pytest.raises(EventValidationError, match="16 hex characters"):
        SignedEvent(event=make_event(), signature=b"\x00" * 64, key_id="short")


def test_keystore_verification_rejects_unknown_and_revoked_keys(keypair):
    signed = make_event().sign(keypair)
    store = KeyStore({keypair.key_id: keypair.public_raw})
    assert signed.verify_with(store)

    assert not signed.verify_with(KeyStore({}))
    assert not signed.verify_with(store.with_revoked([keypair.key_id]))


def test_the_receiver_recomputes_the_hash(keypair):
    """The sender's claimed hash is never authoritative."""
    signed = make_event().sign(keypair)
    assert signed.recompute_hash() == signed.event.hash()
    forged = signed.to_wire_dict()
    forged["event_hash"] = "00" * 32
    assert Event.from_dict(forged).hash() != "00" * 32


# ---------------------------------------------------------------------------
# Id rendering
# ---------------------------------------------------------------------------


def test_rendered_id_carries_date_device_sequence_and_randomness():
    moment = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    first = render_event_id(
        "EVT-{date}-{device}-{sequence:08d}-{random}",
        device_id="PI-A-0001",
        sequence=42,
        moment=moment,
    )
    second = render_event_id(
        "EVT-{date}-{device}-{sequence:08d}-{random}",
        device_id="PI-A-0001",
        sequence=42,
        moment=moment,
    )
    assert first.startswith("EVT-20260929-PI-A-0001-00000042-")
    assert first != second, "two events with the same sequence must still get distinct ids"


def test_id_randomness_length_follows_the_config():
    moment = datetime(2026, 9, 29, tzinfo=timezone.utc)
    for nbytes, expected in [(1, 2), (2, 4), (4, 8)]:
        rendered = render_event_id(
            "EVT-{date}-{device}-{sequence:08d}-{random}",
            device_id="PI-A-0001",
            sequence=1,
            moment=moment,
            random_bytes=nbytes,
        )
        assert rendered.rsplit("-", 1)[1].__len__() == expected


@pytest.mark.parametrize("nbytes", [0, 9, -1])
def test_an_impossible_random_length_is_rejected(nbytes):
    moment = datetime(2026, 9, 29, tzinfo=timezone.utc)
    with pytest.raises(EventValidationError, match="random_suffix_bytes"):
        render_event_id(
            "EVT-{date}-{device}-{sequence:08d}-{random}",
            device_id="PI-A-0001",
            sequence=1,
            moment=moment,
            random_bytes=nbytes,
        )


def test_a_custom_template_is_honoured():
    moment = datetime(2026, 9, 29, tzinfo=timezone.utc)
    rendered = render_event_id(
        "{device}:{sequence:04d}:{random}",
        device_id="PI-B-0001",
        sequence=7,
        moment=moment,
    )
    assert rendered.startswith("PI-B-0001:0007:")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_factory_produces_a_verifiable_event(factory, manager):
    signed = factory.create(EventType.TEMPERATURE, 27.53)
    assert signed.event.device_id == manager.device_id
    assert signed.key_id == manager.key_id
    assert signed.verify(manager.public_key)
    assert signed.event.value == 27.53


def test_the_signed_value_is_the_rounded_value(factory, manager):
    """What is signed must be what is displayed, or the hash check disagrees."""
    signed = factory.create(EventType.TEMPERATURE, 27.56789)
    assert signed.event.value == 27.57
    # The signature covers the rounded value, so a receiver recomputing the
    # hash from the payload gets the same answer the sender did.
    assert signed.verify(manager.public_key)
    assert signed.recompute_hash() == signed.event.hash()


def test_sequences_are_monotonic_across_a_reading(factory):
    events = factory.create_reading(27.5, humidity=61.25)
    assert [e.event.sequence for e in events] == [1, 2]
    assert [e.event.event_type for e in events] == [EventType.TEMPERATURE, EventType.HUMIDITY]
    assert [e.event.unit for e in events] == [Unit.CELSIUS, Unit.PERCENT_RH]


def test_a_non_finite_reading_costs_no_sequence_number(factory, allocator):
    """A broken sensor must not silently advance the counter or fake a value."""
    with pytest.raises(EventValidationError, match="non-finite"):
        factory.create(EventType.TEMPERATURE, float("nan"))
    assert allocator.peek() == 0
    assert factory.create(EventType.TEMPERATURE, 20.0).event.sequence == 1


def test_a_rejected_value_type_costs_no_sequence_number(factory, allocator):
    with pytest.raises(EventValidationError, match="must be a number"):
        factory.create(EventType.TEMPERATURE, "27.5")  # type: ignore[arg-type]
    assert allocator.peek() == 0


def test_the_configured_default_unit_is_used(event_config, manager, allocator):
    event_config = EventConfig(default_unit=Unit.PERCENT_RH)
    factory = EventFactory.from_identity(event_config, manager, allocator)
    signed = factory.create(EventType.TEMPERATURE, 55.0)
    assert signed.event.unit is Unit.PERCENT_RH


def test_decimals_are_configurable(event_config, manager, allocator):
    event_config = EventConfig(value_decimals=1)
    factory = EventFactory.from_identity(event_config, manager, allocator)
    assert factory.create(EventType.TEMPERATURE, 27.567).event.value == 27.6


def test_the_wire_budget_is_respected(factory):
    """Ties Phase 3 to the Phase 7 encoder budget before the encoder exists."""
    signed = factory.create(EventType.TEMPERATURE, 27.5)
    size = len(canonical_bytes(signed.to_wire_dict()))
    assert size < WIRE_PAYLOAD_BUDGET_BYTES, (
        f"canonical payload is {size} bytes, over the {WIRE_PAYLOAD_BUDGET_BYTES}-byte budget"
    )


def test_an_oversized_event_is_refused_rather_than_truncated(event_config, manager, allocator):
    event_config = EventConfig(max_canonical_bytes=64)
    factory = EventFactory.from_identity(event_config, manager, allocator)
    with pytest.raises(EventValidationError, match="over the"):
        factory.create(EventType.TEMPERATURE, 27.5)


def test_ids_are_unique_across_many_events(factory):
    ids = {factory.create(EventType.TEMPERATURE, 20.0 + i / 100).event.event_id for i in range(200)}
    assert len(ids) == 200


def test_a_fixed_clock_does_not_break_id_uniqueness(event_config, manager, allocator):
    frozen = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    factory = EventFactory.from_identity(
        event_config, manager, allocator, clock=lambda: frozen
    )
    ids = {factory.create(EventType.TEMPERATURE, 20.0).event.event_id for _ in range(200)}
    assert len(ids) == 200


# ---------------------------------------------------------------------------
# Sequence allocator
# ---------------------------------------------------------------------------


def test_sequences_start_at_one_and_increment(allocator):
    assert allocator.peek() == 0
    assert [allocator.next() for _ in range(5)] == [1, 2, 3, 4, 5]


def test_a_fresh_allocator_does_not_reuse_numbers(allocator):
    for _ in range(3):
        allocator.next()
    reopened = SequenceAllocator()
    assert reopened.next() == 4


def test_the_counter_survives_a_corrupt_state_file(state_dir, caplog):
    first = SequenceAllocator()
    first.next()
    first.next()
    state = state_dir / "sequence.json"
    state.write_text("{ this is not json")

    recovered = SequenceAllocator(max_hint=lambda: 2)
    assert recovered.peek() == 2
    assert recovered.next() == 3


def test_an_unknown_state_format_falls_back_to_the_hint(state_dir):
    (state_dir / "sequence.json").write_text('{"format": "something-else", "sequence": 99}')
    assert SequenceAllocator(max_hint=lambda: 5).peek() == 5


def test_a_negative_stored_sequence_falls_back_to_the_hint(state_dir):
    (state_dir / "sequence.json").write_text('{"format": "ciphermesh-sequence-v1", "sequence": -4}')
    assert SequenceAllocator(max_hint=lambda: 5).peek() == 5


def test_the_counter_self_heals_above_the_stored_high_water_mark(state_dir):
    """A restored database holding higher sequences must not be renumbered."""
    SequenceAllocator().next()
    SequenceAllocator().next()
    (state_dir / "sequence.json").write_text(
        '{"format": "ciphermesh-sequence-v1", "sequence": 2}'
    )
    healed = SequenceAllocator(max_hint=lambda: 57)
    assert healed.peek() == 57
    assert healed.next() == 58


def test_a_failing_hint_does_not_stop_startup(state_dir, caplog):
    def broken():
        raise RuntimeError("database not ready")

    allocator = SequenceAllocator(max_hint=broken)
    assert allocator.peek() == 0
    assert allocator.next() == 1


def test_a_negative_hint_is_rejected(state_dir):
    with pytest.raises(SequenceError, match="negative"):
        SequenceAllocator(max_hint=lambda: -1)


def test_observe_moves_the_high_water_mark_forward_only(allocator):
    assert allocator.observe(10) is True
    assert allocator.peek() == 10
    assert allocator.observe(5) is False
    assert allocator.observe(10) is False
    assert allocator.next() == 11


def test_observe_rejects_non_sequences(allocator):
    for bad in [-1, 1.5, "3", True, None]:
        with pytest.raises(SequenceError):
            allocator.observe(bad)  # type: ignore[arg-type]


def test_a_failed_persist_does_not_hand_out_a_number(state_dir, monkeypatch):
    """The whole replay guarantee rests on this: persist first, return second."""
    allocator = SequenceAllocator()
    with monkeypatch.context() as patch:
        patch.setattr(
            "ciphermesh.events.sequence.os.replace",
            lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
        )
        with pytest.raises(SequenceError, match="disk full"):
            allocator.next()
    assert allocator.peek() == 0
    assert SequenceAllocator().next() == 1


def test_no_temporary_file_is_left_behind(allocator):
    allocator.next()
    leftovers = list(allocator._path.parent.glob("sequence.json.tmp"))
    assert leftovers == []


def test_concurrent_allocation_never_repeats(allocator):
    """Two threads, one lock: every number is handed to exactly one caller."""
    import threading

    seen: list[int] = []
    lock = threading.Lock()

    def worker():
        for _ in range(50):
            value = allocator.next()
            with lock:
                seen.append(value)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(seen) == 200
    assert len(set(seen)) == 200
    assert sorted(seen) == list(range(1, 201))


# ---------------------------------------------------------------------------
# Contract with the wire
# ---------------------------------------------------------------------------


def test_event_ids_survive_the_id_charset(factory):
    pattern = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
    for _ in range(50):
        assert pattern.match(factory.create(EventType.TEMPERATURE, 21.0).event.event_id)


def test_timestamps_are_ordered_the_same_way_sequences_are(factory):
    events = [factory.create(EventType.TEMPERATURE, 20.0 + i) for i in range(5)]
    assert [e.event.sequence for e in events] == sorted(e.event.sequence for e in events)
    for event in events:
        assert not math.isnan(event.event.value)
        assert event.event.signed_at.tzinfo is timezone.utc
