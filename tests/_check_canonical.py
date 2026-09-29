import sys

sys.path.insert(0, "src")
from ciphermesh.crypto.canonical import canonicalize as c, _es6_number as n  # noqa: E402

fails = []


def check(label, got, want):
    if got != want:
        fails.append(f"{label}: got {got!r} want {want!r}")


# --- ECMAScript Number::toString reference values -------------------------
# Thresholds: fixed notation for 1e-6 <= |x| < 1e21, exponential outside.
nums = [
    (0.0, "0"),
    (-0.0, "0"),
    (1.0, "1.0"),
    (-1.0, "-1.0"),
    (1.5, "1.5"),
    (100.0, "100.0"),
    (1e-6, "0.000001"),
    (1e-7, "1e-7"),
    (1.5e-7, "1.5e-7"),
    (1e-5, "0.00001"),
    (1e20, "100000000000000000000"),
    (1e21, "1e+21"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
    (5e-324, "5e-324"),
    (-2.5e-10, "-2.5e-10"),
    (0.1, "0.1"),
    (31.7, "31.7"),
    (-40.0, "-40.0"),
    (1e-10, "1e-10"),
]
for v, want in nums:
    check(f"num {v!r}", n(v), want)

# --- round trip ------------------------------------------------------------
for v, _ in nums:
    back = float(n(v))
    if back != v and not (v == 0 and back == 0):
        fails.append(f"roundtrip {v!r} -> {n(v)} -> {back!r}")

# --- structure -------------------------------------------------------------
check("key order", c({"b": 1, "a": 2}), '{"a":2,"b":1}')
check("float kept", c({"a": 1.0}), '{"a":1.0}')
check("neg zero", c({"a": -0.0}), '{"a":0}')
check("nested", c({"x": [1, 2, 3], "y": {}}), '{"x":[1,2,3],"y":{}}')
check("literals", c({"n": None, "t": True, "f": False}),
      '{"f":false,"n":null,"t":true}')
check("empty obj", c({}), "{}")
check("empty arr", c([]), "[]")
check("int not float", c({"a": 5}), '{"a":5}')

# --- string escaping -------------------------------------------------------
check("quote", c({"s": 'a"b'}), '{"s":"a\\"b"}')
check("backslash", c({"s": "a\\nb"}), '{"s":"a\\\\nb"}')
check("newline", c({"s": "a\nb"}), '{"s":"a\\nb"}')
check("tab", c({"s": "a\tb"}), '{"s":"a\\tb"}')
check("control", c({"s": "\x01"}), '{"s":"\\u0001"}')
check("nul", c({"s": "\x00"}), '{"s":"\\u0000"}')
check("unicode literal", c({"s": "café ☃"}), '{"s":"café ☃"}')
check("slash not escaped", c({"s": "a/b"}), '{"s":"a/b"}')
check("del not escaped", c({"s": "\x7f"}), '{"s":"\x7f"}')

# --- UTF-16 key ordering ---------------------------------------------------
# This is the case that distinguishes UTF-16 order from code point order.
# U+10000 encodes as the surrogate pair D800 DC00, so in UTF-16 order it
# sorts BEFORE U+FB33 - even though by code point U+10000 (65536) is much
# greater than U+FB33 (64307). A naive sorted() would get this backwards.
astral = "\U00010000"   # U+10000
bmp = "ﯳ"        # U+FB33

got = c({astral: 1, bmp: 2})
# Correct UTF-16 order: astral (D800..) first, then U+FB33.
check("utf16 key order", got, '{"\U00010000":1,"ﯳ":2}')
if sorted([astral, bmp]) == [astral, bmp]:
    fails.append("control: sorted() agreed with UTF-16 order, test is not discriminating")

# --- rejections ------------------------------------------------------------
for bad, label in [
    ({1: "int key"}, "int key"),
    ({"a": {1, 2}}, "set value"),
    ({"a": object()}, "object"),
    ({"a": float("nan")}, "nan"),
    ({"a": float("inf")}, "inf"),
    ({"a": b"bytes"}, "bytes"),
]:
    try:
        c(bad)
        fails.append(f"should have rejected {label}")
    except Exception:
        pass

# --- determinism across insertion order ------------------------------------
a = {"z": 1, "m": {"q": 2, "b": 3}, "a": [3, 2, 1]}
b = {"a": [3, 2, 1], "m": {"b": 3, "q": 2}, "z": 1}
if c(a) != c(b):
    fails.append("insertion order changed canonical output")

if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    raise SystemExit(1)
print(f"canonical.py: all checks passed ({len(nums) + 24} assertions)")
