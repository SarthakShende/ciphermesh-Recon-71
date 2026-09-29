"""GPIO backends and the ladder that selects one.

The DHT22 needs to drive and sample one pin with microsecond timing. There are
two ways to do that on a Pi, and they are not equally available:

===  ==========================================================================
Rank Backend                Availability
===  ==========================================================================
1    ``lgpio`` (pip)         Fastest and most accurate. Wheels exist for
                             cp39-cp312 on aarch64 only, so a Pi on Python
                             3.13+ cannot install it.
2    ``/dev/gpiochip0``      The kernel's character device, driven directly
                             through ``ioctl``. No dependency at all, works on
                             any Python 3, but each bit costs a syscall, so
                             timing is looser.
===  ==========================================================================

(The apt ``python3-lgpio`` package is the same import as the pip wheel - see
:func:`_try_lgpio` - so it shares rank 1.)

:func:`resolve` walks the ladder and returns the first backend that initialises.
It does **not** fall back past a backend that initialises but then fails to
read - that is a wiring problem, not a missing library, and reporting it as a
missing backend would send an operator to install something they do not need.

Open-drain is the whole point
-----------------------------

The DHT22 bus is open-drain: the host and the sensor may both pull the line
low, and only an external pull-up resistor ever raises it. There is therefore
no such thing as "drive this pin high" on this bus, and a backend that
provides one will, if used, fight the sensor.

Both backends are therefore configured for open-drain *output* and mapped onto
the same two operations the DHT22 needs:

* :meth:`Line.write_drive(0)` - drive the line low.
* :meth:`Line.write_drive(1)` - release the line to input.

Neither backend is ever asked to drive the line high. That is asserted against
the real call sequence in the tests, not against a proxy for it.

Nothing here raises on import. A machine with no GPIO at all - a laptop
running the test suite, or a Pi with the sensor disabled - must be able to
import the package and report ``NOT_CONFIGURED``, not fail at import time.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Any

from ..errors import GpioUnavailableError, SensorError
from ..logging_setup import get_logger

LOG = get_logger(__name__)

#: Where the apt ``python3-lgpio`` package installs. A venv created with
#: ``--system-site-packages`` already has this on ``sys.path``; one created
#: without it does not, and the installer has to add it.
APT_DIST_PACKAGES = "/usr/lib/python3/dist-packages"

#: The Pi 4B exposes its 40 GPIOs on chip 0. Raspberry Pi 5 moved the header
#: GPIOs to chip 4, so this is configurable rather than assumed - but it is a
#: chip *number*, and confusing it with a pin number is a bug this module used
#: to have.
DEFAULT_GPIO_CHIP = 0

#: Character device for :data:`DEFAULT_GPIO_CHIP`. Present since Linux 4.x and
#: the basis of libgpiod, so effectively universal on Raspberry Pi OS.
GPIO_CHIP_DEVICE = f"/dev/gpiochip{DEFAULT_GPIO_CHIP}"

#: Kernel uAPI v2 wants a consumer label so ``gpioinfo`` can say who is holding
#: a line. 32 bytes including the terminator; anything longer is truncated.
GPIO_CONSUMER = "ciphermesh-dht22"

__all__ = [
    "ChipIoctlLine",
    "GpioBackend",
    "LgpioLine",
    "Line",
    "backend_report",
    "parse_chip_number",
    "resolve",
    "resolve_pin",
]


def parse_chip_number(name: str | int) -> int:
    """The chip *number* behind any spelling the config might carry.

    ``gpio_chip`` in the config file is a human-facing string, and every tool
    that writes one spells it differently: ``gpiochip0``, ``/dev/gpiochip0``,
    or a bare ``0``. All three name the same chip, so all three are accepted
    rather than being a silent source of a different chip than the operator
    asked for.

    Raises :class:`ValueError` on anything else. This is deliberately not
    :class:`~ciphermesh.errors.GpioUnavailableError`: a bad chip name is a
    typo in a config file, and the config layer reports that as a validation
    error rather than as missing hardware.
    """
    if isinstance(name, bool):  # bool is an int subclass; reject it explicitly.
        raise ValueError(f"invalid GPIO chip: {name!r}")
    if isinstance(name, int):
        if name < 0:
            raise ValueError(f"invalid GPIO chip number: {name}")
        return name

    text = str(name).strip()
    tail = text.rsplit("/", 1)[-1]
    if tail.startswith("gpiochip"):
        tail = tail[len("gpiochip") :]
    if not tail.isdigit():
        raise ValueError(
            f"cannot read a GPIO chip number from {name!r}; expected something "
            "like 'gpiochip0', '/dev/gpiochip0' or '0'"
        )
    return int(tail)


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GpioBackend:
    """One usable way to drive a GPIO.

    ``driver`` is the opened handle: an ``lgpio`` chip handle wrapper, or a file
    object for the kernel device. ``description`` is what the operator sees, so
    it names the mechanism and not just the outcome.
    """

    name: str
    driver: Any
    description: str
    #: Whether per-call timing is tight enough for the DHT22's 27us bit
    #: window. False does not mean the backend is unusable, only that a read
    #: may need more retries.
    precise: bool


class Line:
    """One pin, driven and sampled.

    ``write_drive(1)`` releases the line to input (the DHT22 is open-drain and
    the pull-up resistor provides the high), and ``read()`` samples it. The
    naming is slightly awkward for a reader expecting ``write(1)`` to mean
    "push high", which is exactly the point: on this bus a driven high is a
    bug.
    """

    __slots__ = ("_backend", "_pin")

    def __init__(self, backend: GpioBackend, pin: int) -> None:
        self._backend = backend
        self._pin = pin

    @property
    def pin(self) -> int:
        return self._pin

    def write_drive(self, value: int) -> None:
        raise NotImplementedError

    def read(self) -> int:
        raise NotImplementedError

    def release(self) -> None:
        """Put the line back to input, best effort.

        Called on teardown so a crashed or closed sensor cannot leave the bus
        stuck low, which would make every subsequent read - and the DHT22's own
        next conversion - fail.
        """
        try:
            self.write_drive(1)
        except Exception as exc:  # pragma: no cover - teardown
            LOG.debug("could not release GPIO line", extra={"detail": str(exc)})

    def close(self) -> None:
        """Release the line, then close the chip handle it came from.

        Both, in that order. Closing only the line would leak the chip file
        descriptor for the lifetime of the process - one per sensor, per
        restart - and on the kernel backend that descriptor is what holds the
        line claimed, so a leaked chip is also a bus stuck low.
        """
        self.release()
        driver = getattr(self._backend, "driver", None)
        closer = getattr(driver, "close", None)
        if callable(closer):
            closer()


# ---------------------------------------------------------------------------
# Rank 1: lgpio
# ---------------------------------------------------------------------------


def _lgpio_check(value: Any, what: str) -> int:
    """Turn an lgpio return code into an int, raising if it is a failure.

    lgpio is in one of two modes. With ``exceptions`` set (the default) it
    raises on failure and never returns a negative code; with it clear it
    returns the negative errno instead. Both are handled, because a deployment
    that turned exceptions off should get a clear message rather than a chip
    handle of -1 being used as if it were real.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise GpioUnavailableError(
            f"lgpio {what} returned {value!r}, which is neither a status nor an "
            "exception; this is not a working lgpio"
        )
    if value < 0:
        raise GpioUnavailableError(f"lgpio {what} failed with status {value}")
    return value


class _LgpioDriver:
    """An open ``lgpio`` chip handle with the line already claimed.

    The line is claimed once, as an open-drain output with an initial value of
    1 - that is, *released*. Claiming it released matters: the alternative is a
    claim that starts by driving the line low, and a DHT22 that sees a bus
    already pulled down when we send the start signal does not answer.
    """

    __slots__ = ("_handle", "_lgpio", "_open_drain", "_pin")

    def __init__(self, module: Any, chip: int, pin: int) -> None:
        self._lgpio = module
        self._pin = pin
        # Read the flag from the module rather than hardcoding it. The value is
        # not documented numerically anywhere, and guessing it wrong would
        # produce a push-pull output that drives the DHT22 bus high - a
        # hardware fault, not a test failure. A module that does not export the
        # constant is one we cannot use safely, and the ladder falls through.
        try:
            open_drain = int(module.SET_OPEN_DRAIN)
        except (AttributeError, TypeError, ValueError) as exc:
            raise GpioUnavailableError(
                "lgpio does not export SET_OPEN_DRAIN, so an open-drain output "
                "cannot be requested. Refusing to claim the line push-pull, "
                "which would drive the DHT22 bus high."
            ) from exc
        if open_drain <= 0:
            raise GpioUnavailableError(
                f"lgpio.SET_OPEN_DRAIN is {open_drain}, which is not a valid "
                "line flag; refusing to claim the line push-pull"
            )
        self._open_drain = open_drain

        handle = _lgpio_check(
            module.gpiochip_open(chip),
            f"gpiochip_open(gpiochip={chip})",
        )
        self._handle = handle
        try:
            # level=1 with SET_OPEN_DRAIN means "released", not "drive high".
            _lgpio_check(
                module.gpio_claim_output(handle, pin, 1, open_drain),
                f"gpio_claim_output(gpio={pin}, lFlags=SET_OPEN_DRAIN)",
            )
        except Exception:
            self.close()
            raise

    def read(self) -> int:
        return _lgpio_check(
            self._lgpio.gpio_read(self._handle, self._pin),
            f"gpio_read(gpio={self._pin})",
        )

    def write_drive(self, value: int) -> None:
        # On an open-drain output 0 is "drive low" and 1 is "release to input".
        # lgpio is configured for the bus it is on, so this is the same
        # open-drain the DHT22 datasheet describes, not a direction change.
        _lgpio_check(
            self._lgpio.gpio_write(self._handle, self._pin, 1 if value else 0),
            f"gpio_write(gpio={self._pin})",
        )

    def close(self) -> None:
        # Free before closing the chip: closing the chip alone would release the
        # line implicitly, but relying on that leaves the order to chance.
        closer = getattr(self._lgpio, "gpio_free", None)
        if callable(closer):
            try:
                closer(self._handle, self._pin)
            except Exception as exc:  # pragma: no cover - teardown
                LOG.debug("could not free GPIO line", extra={"detail": str(exc)})
        chip_closer = getattr(self._lgpio, "gpiochip_close", None)
        if callable(chip_closer):
            try:
                chip_closer(self._handle)
            except Exception as exc:  # pragma: no cover - teardown
                LOG.debug("could not close gpiochip", extra={"detail": str(exc)})


class LgpioLine(Line):
    """A pin on an ``lgpio`` chip, claimed as an open-drain output."""

    __slots__ = ()

    def write_drive(self, value: int) -> None:
        self._backend.driver.write_drive(value)

    def read(self) -> int:
        return int(self._backend.driver.read())

    def release(self) -> None:
        # Already an open-drain output, so "release" is a write, not a
        # reconfiguration. The line is only truly given back by close().
        self.write_drive(1)


def _try_lgpio(chip: int, pin: int) -> GpioBackend | None:
    """Rank 1. Returns None if lgpio is absent or unusable.

    Tiers 1 and 2 from the module docstring are the same code path: the apt
    ``python3-lgpio`` and the pip wheel expose the same ``lgpio`` module, so
    there is nothing to choose between at runtime. The distinction is kept in
    the log line because it is the first thing an operator needs to know when
    timing turns out to be marginal on a Pi that should have had wheels.
    """
    try:
        import lgpio
    except ImportError:
        return None
    except Exception as exc:
        LOG.warning(
            "lgpio import failed",
            extra={"event_code": "SENSOR_DISCONNECTED", "detail": str(exc)},
        )
        return None

    # Every attribute access is guarded, not just the import. A userland build
    # of a kernel library that resolved to the wrong .so imports cleanly and
    # then raises on first use - including on dunder lookups, if it exports
    # nothing at all. An unguarded getattr here would propagate that out of the
    # ladder and take the node down, on precisely the machine the ladder exists
    # to rescue.
    try:
        origin = getattr(lgpio, "__file__", "") or ""
        version = getattr(lgpio, "VERSION", "unknown")
    except Exception as exc:
        LOG.warning(
            "lgpio is present but unusable",
            extra={"event_code": "SENSOR_DISCONNECTED", "detail": str(exc)},
        )
        return None

    if origin.startswith(APT_DIST_PACKAGES):
        source = f"python3-lgpio (apt, {APT_DIST_PACKAGES})"
        precise = True
    else:
        source = f"lgpio {version} ({origin})"
        # lgpio's timing is good, but a userland build of a kernel library is
        # only as good as the build. Marked not-precise so a marginal DHT22
        # read is diagnosable.
        precise = False

    try:
        driver = _LgpioDriver(lgpio, chip, pin)
    except Exception as exc:
        LOG.warning(
            "could not open gpiochip via lgpio",
            extra={"event_code": "SENSOR_DISCONNECTED", "detail": str(exc)},
        )
        return None

    return GpioBackend(name="lgpio", driver=driver, description=source, precise=precise)


# ---------------------------------------------------------------------------
# Rank 2: /dev/gpiochipN via ioctl
# ---------------------------------------------------------------------------

# --- kernel uAPI v2 constants -------------------------------------------
#
# The ioctl request numbers are not in any Python module, and getting one wrong
# does not fail loudly: the kernel returns EINVAL and, if the number happens to
# match a different command, something worse. So each is derived here from the
# same _IOC encoding the kernel uses, next to the struct layout it encodes, and
# both are checked by a test against include/uapi/linux/gpio.h.

_IOC_READ, _IOC_WRITE = 2, 1
_IOC_TYPESHIFT, _IOC_SIZESHIFT, _IOC_NRSHIFT, _IOC_DIRSHIFT = 8, 16, 0, 30
_GPIO_UAPI_TYPE = "\xB4"


def _iowr(number: int, size: int) -> int:
    """``_IOWR(0xB4, number, size)`` as the kernel computes it."""
    return (
        ((_IOC_READ | _IOC_WRITE) << _IOC_DIRSHIFT)
        | (ord(_GPIO_UAPI_TYPE) << _IOC_TYPESHIFT)
        | (number << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


#: ``struct gpio_v2_line_request``, from include/uapi/linux/gpio.h:
#:
#:   __u32                  offsets[GPIO_V2_LINES_MAX];  // 64 -> 256 bytes
#:   char                   consumer[GPIO_MAX_NAME_SIZE];// 32 -> 32 bytes
#:   struct gpio_v2_line_config config;                  // 32 + 240 = 272
#:   __u32                  num_lines;                   // 4
#:   __u32                  event_buffer_size;           // 4
#:   __u32                  padding[5];                  // 20
#:   __s32                  fd;
#:
#: The ioctl number embeds sizeof(this), so the layout has to be exactly
#: right. Every field offset below is derived from the declaration order and
#: the struct's 8-byte alignment, and asserted by a test.
_LINE_REQUEST_SIZE = 592
_OFF_CONSUMER = 256
_OFF_CONFIG = 288
_OFF_NUM_LINES = 560
_OFF_FD = 588

#: ``struct gpio_v2_line_config``: flags, num_attrs, padding[5], attrs[10].
#: Each attr is id, padding, an 8-byte union; each config attr adds an 8-byte
#: mask. 16 + 8 = 24 bytes each, 10 of them = 240.
_LINE_CONFIG_ATTRS_SIZE = 240

_LINE_OFFSETS = struct.Struct("=64I")
_LINE_CONFIG_HEAD = struct.Struct("=Q I 5I")
_LINE_TAIL = struct.Struct("=7I i")
#: ``struct gpio_v2_line_values``: two u64s, ``bits`` then ``mask``.
_LINE_VALUES = struct.Struct("=QQ")

#: ``enum gpio_v2_line_flag``. Only OUTPUT and OPEN_DRAIN are wanted.
#:
#: INPUT and OUTPUT are mutually exclusive: the kernel rejects a request that
#: asks for both with EINVAL (gpiolib-cdev.c, gpio_v2_line_flags_validate), so
#: the pair is not a way to get a bidirectional line. Reading an output line is
#: allowed regardless - linereq_get_values() opens with "It's ok to read values
#: of output lines" - so OUTPUT alone both lets the line be driven and reports
#: the level the pull-up actually put on it.
#:
#: OPEN_DRAIN is what makes an output safe on a 1-wire bus: the kernel drives
#: the line low for 0 and switches it back to input for 1
#: (gpio_set_open_drain_value_commit), so the host can never source current
#: against the sensor.
_LINE_FLAG_INPUT, _LINE_FLAG_OUTPUT, _LINE_FLAG_OPEN_DRAIN = 1 << 2, 1 << 3, 1 << 6
_LINE_FLAGS = _LINE_FLAG_OUTPUT | _LINE_FLAG_OPEN_DRAIN

_GPIO_V2_GET_LINE_IOCTL = _iowr(0x07, _LINE_REQUEST_SIZE)
_GPIO_V2_LINE_GET_VALUES_IOCTL = _iowr(0x0E, _LINE_VALUES.size)
_GPIO_V2_LINE_SET_VALUES_IOCTL = _iowr(0x0F, _LINE_VALUES.size)


class ChipIoctlLine(Line):
    """A pin on ``/dev/gpiochipN``, driven with raw ``ioctl``.

    The request-line call returns a *new* file descriptor for that line, and
    every subsequent get/set must go through that descriptor, not the chip's.
    Mixing the two silently reads the wrong line, so the line fd is held
    separately and closed on teardown.
    """

    __slots__ = ("_fd",)

    def __init__(self, backend: GpioBackend, pin: int) -> None:
        super().__init__(backend, pin)
        self._fd: int | None = None
        try:
            self._request()
        except Exception:
            # The line is the last thing acquired, so if it fails nothing has
            # to be unwound except the chip fd the ladder already opened.
            self.close()
            raise
        # A v2 output line is requested at level 0, i.e. driving low. Release
        # it before handing the pin to the protocol, so an idle sensor is not
        # sitting on a bus it is holding down.
        self.write_drive(1)

    def _request(self) -> int:
        if self._fd is not None:
            return self._fd
        import fcntl

        request = bytearray(_LINE_REQUEST_SIZE)
        # offsets[0] is the pin - the kernel indexes the line by its offset
        # within the chip, so this is a chip-relative line number, not a
        # header pin. The remaining 63 slots stay zero and are not requested.
        _LINE_OFFSETS.pack_into(request, 0, *([self._pin] + [0] * 63))
        request[_OFF_CONSUMER : _OFF_CONSUMER + len(GPIO_CONSUMER)] = (
            GPIO_CONSUMER.encode()
        )
        # num_attrs is 0: no per-line overrides, the flags below are enough.
        _LINE_CONFIG_HEAD.pack_into(
            request, _OFF_CONFIG, _LINE_FLAGS, 0, 0, 0, 0, 0, 0
        )
        # num_lines=1, event_buffer_size=0 (no edge events), padding zero, and
        # an fd slot for the kernel to fill in.
        _LINE_TAIL.pack_into(request, _OFF_NUM_LINES, 1, 0, 0, 0, 0, 0, 0, 0)

        try:
            updated = fcntl.ioctl(
                self._backend.driver.fileno(), _GPIO_V2_GET_LINE_IOCTL, request
            )
        except OSError as exc:
            raise GpioUnavailableError(
                f"could not request GPIO line {self._pin} from "
                f"{GPIO_CHIP_DEVICE}: {exc}. The kernel gpio uAPI v2 interface "
                "is required (Linux 5.x or later), and open-drain output "
                "emulation specifically needs Linux 5.13 or later; earlier "
                "kernels expose only the deprecated sysfs interface, and "
                "5.6-5.12 cannot request an open-drain output. Installing "
                "lgpio is an alternative, not a workaround for an old kernel."
            ) from exc
        # The kernel writes the new line descriptor into the fd slot.
        self._fd = _LINE_TAIL.unpack_from(updated, _OFF_NUM_LINES)[-1]
        return self._fd

    def write_drive(self, value: int) -> None:
        import fcntl

        fd = self._request()
        # ``bits`` is the value and ``mask`` selects the lines. The kernel
        # returns EINVAL for an empty mask, so the mask must name the one line
        # this request owns. With OPEN_DRAIN requested, bits=0 drives the line
        # low and bits=1 releases it to input - it never sources current.
        try:
            fcntl.ioctl(
                fd, _GPIO_V2_LINE_SET_VALUES_IOCTL, _LINE_VALUES.pack(1 if value else 0, 1)
            )
        except OSError as exc:
            raise SensorError(f"GPIO set failed on pin {self._pin}: {exc}") from exc

    def read(self) -> int:
        import fcntl

        fd = self._request()
        # Same mask rule: the kernel reads only the masked lines and returns
        # their levels in ``bits``. An output line reports what is really on
        # the wire, which for a released open-drain line is the pull-up.
        try:
            values = fcntl.ioctl(
                fd, _GPIO_V2_LINE_GET_VALUES_IOCTL, _LINE_VALUES.pack(0, 1)
            )
        except OSError as exc:
            raise SensorError(f"GPIO read failed on pin {self._pin}: {exc}") from exc
        return int(_LINE_VALUES.unpack(values)[0] & 1)

    def release(self) -> None:
        try:
            self.write_drive(1)
        except Exception as exc:  # pragma: no cover - teardown
            LOG.debug("could not release GPIO line", extra={"detail": str(exc)})

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            # Closing the line fd releases the claim, which puts the line back
            # to input. The explicit release first is belt and braces for the
            # case where the line is still driving low and something else has
            # it held; it is skipped when the request never succeeded, because
            # re-running a request that just failed buys nothing.
            self.release()
            try:
                os.close(fd)
            except OSError as exc:  # pragma: no cover - teardown
                LOG.debug("could not close GPIO line fd", extra={"detail": str(exc)})
        driver = getattr(self._backend, "driver", None)
        closer = getattr(driver, "close", None)
        if callable(closer):
            closer()


def _try_gpiochip(chip: int, pin: int) -> GpioBackend | None:
    """Rank 2. Returns None if the device is absent or cannot be opened."""
    device = f"/dev/gpiochip{chip}"
    if not os.path.exists(device):
        return None
    try:
        fd = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    except OSError as exc:
        LOG.warning(
            "could not open gpiochip device",
            extra={"event_code": "SENSOR_DISCONNECTED", "detail": str(exc)},
        )
        return None
    return GpioBackend(
        name="gpiochip",
        driver=os.fdopen(fd, "r+b", buffering=0),
        description=f"{device} (kernel uAPI v2, no python dependency)",
        precise=False,
    )


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------


def resolve(
    pin: int,
    chip: str | int = DEFAULT_GPIO_CHIP,
) -> GpioBackend:
    """Return the best available GPIO backend for ``pin`` on ``chip``.

    Raises :class:`~ciphermesh.errors.GpioUnavailableError` if none can be
    initialised. Callers that want a degraded node instead should catch it and
    mark the sensor ``NOT_CONFIGURED`` - see
    :func:`ciphermesh.sensors.registry.build`.
    """
    chip_number = parse_chip_number(chip)
    for attempt in (_try_lgpio, _try_gpiochip):
        backend = attempt(chip_number, pin)
        if backend is not None:
            LOG.info(
                "gpio backend selected",
                extra={
                    "event_code": "SENSOR_CONNECTED",
                    "backend": backend.name,
                    "detail": backend.description,
                    "chip": chip_number,
                    "pin": pin,
                },
            )
            return backend

    raise GpioUnavailableError(
        f"no GPIO backend is available for pin {pin} on "
        f"/dev/gpiochip{chip_number}. Tried: the lgpio python module (pip "
        "wheel, or python3-lgpio from apt if the venv was created with "
        "--system-site-packages), then "
        f"/dev/gpiochip{chip_number} (kernel GPIO uAPI v2, needs Linux 5.13 or "
        "later for open-drain output). Neither initialised, so a DHT22 cannot "
        "be read on this host."
    )


def resolve_pin(
    pin: int,
    chip: str | int = DEFAULT_GPIO_CHIP,
) -> tuple[GpioBackend, Line]:
    """Resolve a backend and open ``pin`` on it in one step."""
    backend = resolve(pin, chip)
    return backend, _make_line(backend, pin)


def _make_line(backend: GpioBackend, pin: int) -> Line:
    if backend.name == "lgpio":
        return LgpioLine(backend, pin)
    return ChipIoctlLine(backend, pin)


def backend_report(chip: str | int = DEFAULT_GPIO_CHIP) -> dict[str, str]:
    """Describe what is available, without opening anything.

    For ``ciphermesh device`` and ``ciphermesh doctor``, so an operator can see
    which rung of the ladder this host would use before the sensor loop starts
    and possibly holds the line low.
    """
    report: dict[str, str] = {}
    try:
        import lgpio

        origin = getattr(lgpio, "__file__", "") or "unknown"
        open_drain = getattr(lgpio, "SET_OPEN_DRAIN", None)
        report["lgpio"] = (
            f"available ({origin})"
            if isinstance(open_drain, int) and open_drain > 0
            else f"present but unusable ({origin}): no SET_OPEN_DRAIN line flag"
        )
    except Exception as exc:
        report["lgpio"] = f"unavailable ({type(exc).__name__}: {exc})"

    try:
        device = f"/dev/gpiochip{parse_chip_number(chip)}"
    except ValueError as exc:
        device = f"<invalid: {exc}>"
    report[device] = "present" if os.path.exists(device) else "absent"
    report["dist-packages"] = (
        "on sys.path"
        if APT_DIST_PACKAGES in os.sys.path
        else "not on sys.path (apt python3-lgpio would be invisible; recreate "
        "the venv with --system-site-packages)"
    )
    return report
