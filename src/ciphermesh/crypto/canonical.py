"""Deterministic canonical JSON serialization.

This module is the single most security-sensitive piece of the codebase: two
nodes must produce byte-identical output for the same logical event, or
signatures will not verify. It follows the structure of RFC 8785 (JSON
Canonicalization Scheme) restricted to the types an event can contain.

The rules implemented here:

1. Only ``dict``, ``list``, ``str``, ``int``, ``float``, ``bool`` and ``None``
   are permitted. Anything else raises - notably no ``Decimal``, ``datetime``
   or custom object may leak in, because their serialization would depend on
   library internals.
2. Object keys are sorted by their UTF-16 code units, not by code point.
   These differ for characters outside the BMP, and RFC 8785 specifies
   UTF-16 ordering.
3. No insignificant whitespace: separators are ``,`` and ``:``.
4. Output is UTF-8 with non-ASCII characters emitted literally, not as
   ``\\uXXXX`` escapes.
5. Integers are emitted as-is. A float is emitted using the ECMAScript
   ``Number::toString`` algorithm over Python's shortest round-tripping
   ``repr``, and ``NaN``/``Infinity`` are rejected outright because they have
   no JSON representation and would silently break the signature.
6. Strings are escaped minimally, per RFC 8785: only ``"``, ``\\`` and the
   C0 control characters are escaped, and the short forms are used where they
   exist.

Rules 2, 5 and 6 are where naive implementations differ across platforms,
which is exactly why they are explicit here and covered by tests.
"""

from __future__ import annotations

import math
import re
from typing import Any, Mapping, Sequence

from ..errors import CanonicalizationError

#: Only these types may appear in a canonicalized structure.
ALLOWED_TYPES = (dict, list, str, int, float, bool, type(None))

#: Nesting limit. Events are flat, so this exists purely to stop a
#: pathological input from exhausting the stack.
MAX_DEPTH = 32

# ---------------------------------------------------------------------------
# String escaping
# ---------------------------------------------------------------------------

# Short escapes required by JSON. Everything else in C0 is escaped as \u00XX.
_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_ESCAPE_RE = re.compile(r'["\\\x00-\x1f]')


def _escape_char(match: re.Match[str]) -> str:
    char = match.group(0)
    short = _SHORT_ESCAPES.get(char)
    if short is not None:
        return short
    return f"\\u{ord(char):04x}"


def escape_string(value: str) -> str:
    """Escape a string into a JSON string literal, including the quotes.

    RFC 8785 escapes only what JSON requires: the quote, the backslash and
    the C0 controls. Notably it does *not* escape ``/``, DEL (0x7f) or any
    non-ASCII character - those are emitted literally and the result is
    encoded as UTF-8.
    """
    if not isinstance(value, str):
        raise CanonicalizationError(f"expected str, got {type(value).__name__}")
    if not _ESCAPE_RE.search(value):
        return f'"{value}"'
    return '"' + _ESCAPE_RE.sub(_escape_char, value) + '"'


# ---------------------------------------------------------------------------
# Number serialization
# ---------------------------------------------------------------------------


def _es6_number(value: float) -> str:
    """Serialize a float the way ECMAScript ``Number::toString`` does.

    RFC 8785 requires this form because JavaScript's JSON.stringify is the
    de-facto canonical implementation, and a verifier written in any other
    language must agree with it bit for bit.

    Python's ``repr`` already produces the shortest decimal string that round
    trips to the same double, which is the same value ECMAScript computes.
    What differs is the *formatting* of the exponent and the treatment of
    integral values, both handled below.
    """
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError(
            "NaN and Infinity have no canonical JSON representation and would "
            "silently break event signing"
        )
    if value == 0.0:
        # Normalise -0.0 to 0: they are numerically equal but would otherwise
        # produce two different canonical forms for the same value.
        return "0"

    text = repr(float(value))

    if "e" in text or "E" in text:
        mantissa, _, exponent_text = text.partition("e")
        if not exponent_text:
            mantissa, _, exponent_text = text.partition("E")
        exponent = int(exponent_text)

        # ECMAScript chooses fixed notation only when the decimal exponent
        # n satisfies -6 < n <= 21. Working in terms of |value| that is
        # 1e-6 <= |value| < 1e21 - note 1e-6 itself is fixed ("0.000001")
        # while 1e-7 is exponential ("1e-7").
        magnitude = abs(value)
        if 1e-6 <= magnitude < 1e21:
            # Re-render in plain notation.
            return _plain_notation(mantissa, exponent)

        mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
        sign = "+" if exponent >= 0 else "-"
        return f"{mantissa}e{sign}{abs(exponent)}"

    if "." not in text:
        # repr gave us an integer-valued float; JSON only distinguishes
        # integers from floats by the presence of a fractional part, and
        # 1.0 must stay 1.0 so a round trip preserves the type.
        return text + ".0"

    return text


def _plain_notation(mantissa: str, exponent: int) -> str:
    """Render ``mantissa * 10**exponent`` without an exponent."""
    if "." in mantissa:
        whole, _, fraction = mantissa.partition(".")
    else:
        whole, fraction = mantissa, ""

    digits = whole + fraction
    decimal_index = len(whole) + exponent

    if decimal_index <= 0:
        result = "0." + ("0" * -decimal_index) + digits
    elif decimal_index >= len(digits):
        result = digits + ("0" * (decimal_index - len(digits)))
    else:
        result = digits[:decimal_index] + "." + digits[decimal_index:]

    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return result or "0"


def serialize_number(value: int | float, *, is_float: bool) -> str:
    """Render an int or float in canonical form."""
    if is_float:
        return _es6_number(float(value))
    return str(int(value))


# ---------------------------------------------------------------------------
# Key ordering
# ---------------------------------------------------------------------------


def _utf16_sort_key(key: str) -> bytes:
    """Sort key reproducing RFC 8785's UTF-16 code unit ordering.

    Code point order and UTF-16 code unit order disagree for characters
    above U+FFFF: in UTF-16 those are encoded as a surrogate pair starting at
    U+D800, which sorts *before* characters in U+E000-U+FFFF. Python compares
    strings by code point, so an explicit conversion is required.

    Comparing the raw big-endian UTF-16 bytes directly gives exactly
    code-unit ordering, and ``bytes`` compares lexicographically in Python.
    """
    return key.encode("utf-16-be", errors="surrogatepass")


def sort_keys(mapping: Mapping[str, Any]) -> list[str]:
    """Return the keys of ``mapping`` in canonical order."""
    return sorted(mapping.keys(), key=_utf16_sort_key)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _serialize(value: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"structure nested deeper than {MAX_DEPTH} levels")

    if value is None:
        return "null"

    # bool must be checked before int: bool is a subclass of int, and
    # True must serialize as "true", not "1".
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return serialize_number(value, is_float=False)

    if isinstance(value, float):
        return serialize_number(value, is_float=True)

    if isinstance(value, str):
        return escape_string(value)

    if isinstance(value, Mapping):
        if not value:
            return "{}"
        parts = []
        for key in sort_keys(value):
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
            parts.append(
                escape_string(key) + ":" + _serialize(value[key], depth + 1)
            )
        return "{" + ",".join(parts) + "}"

    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        return "[" + ",".join(_serialize(item, depth + 1) for item in value) + "]"

    raise CanonicalizationError(
        f"type {type(value).__name__} cannot be canonically serialized. "
        "Convert it to dict, list, str, int, float, bool or None first. "
        "Silently coercing it would risk a value that serializes differently "
        "on another node."
    )


def canonicalize(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    return _serialize(value, 0)


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for ``value``.

    This is what gets hashed and signed. Never sign the Python object's
    ``str()`` or a plain ``json.dumps`` result: neither is stable across
    implementations.
    """
    return canonicalize(value).encode("utf-8")


def is_canonical(value: Any) -> bool:
    """True if ``value``'s current in-memory form is already canonical."""
    return _is_canonical_obj(value, 0)


def _is_canonical_obj(value: Any, depth: int) -> bool:
    if depth > MAX_DEPTH:
        return False
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        # A float is canonical when it round-trips through repr unchanged and
        # is not a value that would be re-rendered differently (e.g. 1.0 vs 1).
        return math.isfinite(value) and canonicalize(value) == _es6_number(value)
    if isinstance(value, Mapping):
        if not value:
            return True
        keys = list(value.keys())
        if keys != sort_keys(value):
            return False
        return all(
            isinstance(k, str) and _is_canonical_obj(v, depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return all(_is_canonical_obj(item, depth + 1) for item in value)
    return False


__all__ = [
    "ALLOWED_TYPES",
    "canonical_bytes",
    "canonicalize",
    "escape_string",
    "is_canonical",
    "serialize_number",
    "sort_keys",
]
