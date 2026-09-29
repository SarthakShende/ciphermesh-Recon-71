"""Sensors: the node's only source of measurements.

A sensor produces numbers. Turning those into signed events is the job of
:mod:`ciphermesh.events` and the service loop, not of the sensor itself, which
is what keeps this package testable without a Pi attached.

Importing this package never touches GPIO, so a host with no sensor hardware
can still import it and report ``NOT_CONFIGURED``.
"""

from __future__ import annotations

from .base import BaseSensor, Reading, Sensor
from .dht22 import DHT22Sensor, decode_frame
from .mock import MockTemperatureSensor
from .registry import SENSOR_TYPES, build, describe, is_mock, sensor_types

__all__ = [
    "SENSOR_TYPES",
    "BaseSensor",
    "DHT22Sensor",
    "MockTemperatureSensor",
    "Reading",
    "Sensor",
    "build",
    "decode_frame",
    "describe",
    "is_mock",
    "sensor_types",
]
