"""Ed25519 signing and verification.

Design decisions worth knowing before changing anything here:

* **The private key never leaves this module's process.** Callers ask for a
  signature; they never get the raw seed back after ``generate``.
* **Key generation uses a passphrase plus a random salt, not a plain key
  file.** The 32-byte seed is derived with PBKDF2-HMAC-SHA256 so an operator
  can rotate the passphrase without regenerating the identity. A stolen
  ``identity.json`` is therefore useless without the passphrase.
* **File permissions are set to 0600/0700 at creation and re-asserted on
  load**, because the default umask on many images is 0022.
* **Verification never trusts a key bundled in the same packet** - callers
  pass in a trusted key resolved from their own keyring. That is enforced by
  :class:`KeyStore` rather than here, but the API is shaped to make the
  mistake hard.
"""

from __future__ import annotations

import base64
import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from ..errors import CryptoError, IdentityError
from .canonical import canonical_bytes
from .hashing import EVENT_DOMAIN, key_id

#: PBKDF2 iteration count for new identities. Raising this only affects
#: newly created keys; existing identity files record their own count.
PBKDF2_ITERATIONS = 480_000

#: Lower bound accepted when reading an existing identity file, so a
#: hand-edited file cannot downgrade the KDF to something brute-forceable.
MIN_PBKDF2_ITERATIONS = 100_000

SALT_BYTES = 16
SEED_BYTES = 32

#: Marker stored in identity files so a future format change is detectable
#: rather than silently mis-parsed.
IDENTITY_FORMAT = "ciphermesh-ed25519-v1"

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalised into IdentityError
        raise IdentityError("identity file contains invalid base64") from exc


def derive_seed(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive the 32-byte Ed25519 seed from a passphrase and salt."""
    if not passphrase:
        raise CryptoError("passphrase must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=SEED_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# Key pair container
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyPair:
    """An Ed25519 key pair.

    ``raw`` on the private key is deliberately not exposed through
    ``__repr__``: this class is frozen and slots-based so that accidental
    logging of the private half is limited to an explicit attribute access.
    """

    private_key: Ed25519PrivateKey
    public_raw: bytes
    key_id: str

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls.from_seed(secrets.token_bytes(SEED_BYTES))

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        if len(seed) != SEED_BYTES:
            raise CryptoError(f"seed must be {SEED_BYTES} bytes, got {len(seed)}")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public_raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(private, public_raw, key_id(public_raw))

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def sign_event(self, payload: Any) -> bytes:
        """Sign an event payload with domain separation.

        The exact bytes signed are ``EVENT_DOMAIN || canonical_json(payload)``.
        Verification must rebuild the message the same way; see
        :func:`verify_event`.
        """
        return self.sign(EVENT_DOMAIN + canonical_bytes(payload))

    def public_b64(self) -> str:
        return _b64(self.public_raw)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"KeyPair(key_id={self.key_id!r}, private=<redacted>)"


# ---------------------------------------------------------------------------
# Public key + verification
# ---------------------------------------------------------------------------


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != 32:
        raise CryptoError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(public_raw: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a raw signature, returning False instead of raising."""
    try:
        load_public_key(public_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_event(public_raw: bytes, signature: bytes, payload: Any) -> bool:
    """Verify an event signature against its domain-separated message."""
    return verify(public_raw, signature, EVENT_DOMAIN + canonical_bytes(payload))


# ---------------------------------------------------------------------------
# Keyring
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyStore:
    """Trusted public keys, indexed by key id.

    Only keys present here can verify an inbound event. A node must never
    accept the public key carried in the same message it is verifying -
    doing so would make signatures meaningless, since an attacker would
    simply sign with their own key and ship it alongside.
    """

    keys: dict[str, bytes]
    revoked: frozenset[str] = frozenset()

    @classmethod
    def from_iterable(cls, entries: Iterable[tuple[str, str]]) -> "KeyStore":
        keys: dict[str, bytes] = {}
        for expected_id, b64_key in entries:
            raw = _unb64(b64_key)
            actual_id = key_id(raw)
            if expected_id and expected_id != actual_id:
                raise IdentityError(
                    f"key id mismatch: configured {expected_id}, computed {actual_id}"
                )
            keys[actual_id] = raw
        return cls(keys)

    def add(self, raw: bytes) -> str:
        kid = key_id(raw)
        self.keys[kid] = raw
        return kid

    def with_revoked(self, revoked: Iterable[str]) -> "KeyStore":
        return KeyStore(dict(self.keys), frozenset(revoked))

    def get(self, kid: str) -> bytes | None:
        if kid in self.revoked:
            return None
        return self.keys.get(kid)

    def verify(self, kid: str, signature: bytes, payload: Any) -> bool:
        raw = self.get(kid)
        if raw is None:
            return False
        return verify_event(raw, signature, payload)

    def __len__(self) -> int:
        return len(self.keys)

    def __contains__(self, kid: object) -> bool:
        return isinstance(kid, str) and kid in self.keys and kid not in self.revoked


# ---------------------------------------------------------------------------
# On-disk identity
# ---------------------------------------------------------------------------


def _assert_secure(path: Path, want_dir: bool) -> None:
    """Refuse to use a file or directory that is group/world accessible."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return
    if want_dir:
        if not stat.S_ISDIR(mode):
            raise IdentityError(f"{path} exists but is not a directory")
        if mode & 0o077:
            raise IdentityError(
                f"identity directory {path} is group/world accessible (mode "
                f"{stat.filemode(mode)}); expected 0700. Run: chmod 700 {path}"
            )
    else:
        if stat.S_ISDIR(mode):
            raise IdentityError(f"{path} is a directory, expected a file")
        if mode & 0o077:
            raise IdentityError(
                f"private key {path} is group/world accessible (mode "
                f"{stat.filemode(mode)}); expected 0600. Run: chmod 600 {path}"
            )


def _assert_dir_secure(path: Path) -> None:
    """Enforce the 0700 rule on an identity directory.

    Called on the read path as well as the write path. Checking only on write
    would mean a node that started secure and was later loosened by a manual
    ``chmod`` or a bad restore would keep loading its key happily.
    """
    _assert_secure(path, want_dir=True)


def write_identity(keypair: KeyPair, path: Path, salt: bytes) -> None:
    """Persist salt and public key. The private seed is never written here.

    Regenerating the identity from the passphrase and salt is deliberate: the
    passphrase is the secret, and the salt is not. This means the file on
    disk contains nothing an attacker could use alone.
    """
    path = Path(path)
    _assert_secure(path.parent, want_dir=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    os.chmod(path.parent, _DIR_MODE)

    body = (
        f"format {IDENTITY_FORMAT}\n"
        f"key_id {keypair.key_id}\n"
        f"public_key {keypair.public_b64()}\n"
        f"salt {_b64(salt)}\n"
        f"kdf pbkdf2-sha256\n"
        f"iterations {PBKDF2_ITERATIONS}\n"
    )
    # Create with 0600 from the outset rather than chmod-ing afterwards, so
    # the key is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, _FILE_MODE)


def read_identity(path: Path) -> tuple[str, bytes, bytes, int]:
    """Read an identity file, returning ``(key_id, public_raw, salt, iterations)``.

    Checks that the stored key id matches the stored public key, so a
    hand-edited file cannot claim one identity while carrying another.
    """
    path = Path(path)
    _assert_secure(path, want_dir=False)
    _assert_dir_secure(path.parent)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise IdentityError(f"no identity file at {path}; run 'ciphermesh identity init'") from exc
    except OSError as exc:
        raise IdentityError(f"cannot read identity file {path}: {exc}") from exc

    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise IdentityError(f"malformed line in {path}: {line!r}")
        fields[parts[0]] = parts[1]

    fmt = fields.get("format")
    if fmt != IDENTITY_FORMAT:
        raise IdentityError(
            f"unsupported identity format {fmt!r} in {path}; expected {IDENTITY_FORMAT!r}"
        )

    kdf = fields.get("kdf")
    if kdf != "pbkdf2-sha256":
        raise IdentityError(f"unsupported key derivation function {kdf!r} in {path}")

    # Honour the iteration count recorded in the file so an identity created
    # by a build with a different cost still loads, but floor it: otherwise
    # anyone able to edit the file could set iterations=1 and defeat the KDF.
    iterations_text = fields.get("iterations")
    if iterations_text is None:
        raise IdentityError(f"identity file {path} does not record kdf iterations")
    try:
        iterations = int(iterations_text)
    except ValueError as exc:
        raise IdentityError(f"identity file {path} has non-numeric kdf iterations") from exc
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise IdentityError(
            f"identity file {path} records {iterations} PBKDF2 iterations, below the "
            f"minimum of {MIN_PBKDF2_ITERATIONS}. Refusing to derive with a weakened KDF."
        )

    public_b64 = fields.get("public_key")
    if not public_b64:
        raise IdentityError(f"identity file {path} has no public_key")
    salt_b64 = fields.get("salt")
    if not salt_b64:
        raise IdentityError(f"identity file {path} has no salt")

    public_raw = _unb64(public_b64)
    if len(public_raw) != 32:
        raise IdentityError(f"identity file {path} has a malformed public key")

    computed = key_id(public_raw)
    stored = fields.get("key_id")
    if stored and stored != computed:
        raise IdentityError(
            f"identity file {path} is inconsistent: key_id says {stored}, "
            f"public key hashes to {computed}"
        )

    return computed, public_raw, _unb64(salt_b64), iterations


def load_or_create_identity(
    path: Path,
    passphrase: str,
    *,
    salt: bytes | None = None,
) -> KeyPair:
    """Load an identity, deriving the key from ``passphrase``.

    If the file does not exist it is created, and ``salt`` must then be
    supplied. This is the single entry point used by the CLI and the node
    runtime, so both behave identically.
    """
    path = Path(path)
    if path.exists():
        stored_id, public_raw, file_salt, iterations = read_identity(path)
        derived = KeyPair.from_seed(derive_seed(passphrase, file_salt, iterations))
        if derived.key_id != stored_id:
            raise IdentityError(
                f"wrong passphrase for {path}: derived key id {derived.key_id}, "
                f"file declares {stored_id}. The passphrase is not recoverable."
            )
        if derived.public_raw != public_raw:
            raise IdentityError(
                f"identity file {path} public key does not match the derived key"
            )
        return derived

    if salt is None:
        raise IdentityError(
            f"identity file {path} does not exist; a salt is required to create one"
        )
    keypair = KeyPair.from_seed(derive_seed(passphrase, salt))
    write_identity(keypair, path, salt)
    return keypair


def constant_time_equal(a: str, b: str) -> bool:
    """Compare two secrets in constant time."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


__all__ = [
    "IDENTITY_FORMAT",
    "KeyPair",
    "KeyStore",
    "PBKDF2_ITERATIONS",
    "constant_time_equal",
    "derive_seed",
    "load_or_create_identity",
    "load_public_key",
    "read_identity",
    "verify",
    "verify_event",
    "write_identity",
]
