"""Filesystem path resolution.

All runtime state lives outside the source tree so that the application can be
upgraded or replaced without touching device identity, the database, or radio
state.

Layout on a real node::

    /etc/ciphermesh/                 configuration (root:ciphermesh, 0750)
      config.yaml                    main configuration
      ciphermesh.env                 secrets, 0640 root:ciphermesh
      reticulum/                     private Reticulum instance, 0750
        config                       rendered Reticulum native config, 0640
        storage/                     Reticulum's own state
    /var/lib/ciphermesh/             mutable state (ciphermesh:ciphermesh, 0700)
      identity/                      Ed25519 identity, 0700 / 0600
      sequence.json                  monotonic event counter
      ciphermesh.db                  SQLite database
    /var/log/ciphermesh/             file logs (only if file logging enabled)

Every path can be overridden with an environment variable so the test suite
can run entirely inside a temporary directory.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Environment variable names. The prefix is applied uniformly so tests and
#: non-root developer runs can redirect all state with one exported variable.
ENV_CONFIG_DIR = "CIPHERMESH_CONFIG_DIR"
ENV_STATE_DIR = "CIPHERMESH_STATE_DIR"
ENV_LOG_DIR = "CIPHERMESH_LOG_DIR"
ENV_APP_DIR = "CIPHERMESH_APP_DIR"

#: Defaults used when the environment does not override.
DEFAULT_CONFIG_DIR = Path("/etc/ciphermesh")
DEFAULT_STATE_DIR = Path("/var/lib/ciphermesh")
DEFAULT_LOG_DIR = Path("/var/log/ciphermesh")

#: Service account that owns runtime state on a real node.
SERVICE_USER = "ciphermesh"

CONFIG_FILENAME = "config.yaml"
ENV_FILENAME = "ciphermesh.env"
RETICULUM_DIRNAME = "reticulum"
RETICULUM_CONFIG_FILENAME = "config"
IDENTITY_DIRNAME = "identity"
DB_FILENAME = "ciphermesh.db"

#: File names inside the identity directory.
#:
#: There is no PEM private key file, and that is deliberate. The Ed25519 seed
#: is derived from an operator passphrase with PBKDF2-HMAC-SHA256 and a random
#: salt, so nothing on disk is usable without the passphrase. Writing a PEM
#: would put the raw 32-byte seed at rest, which is a strict downgrade.
#:
#:   device_identity.json         crypto artifact (salt, public key, KDF cost)
#:   device_identity.meta.json    public metadata (device id, role, created)
#:   device_ed25519.pub           public key export for the peer keyring
IDENTITY_FILENAME = "device_identity.json"
IDENTITY_META_FILENAME = "device_identity.meta.json"
PUBLIC_KEY_FILENAME = "device_ed25519.pub"

#: Monotonic sequence counter, kept outside the database so that sequence
#: allocation still works before (and after) storage is available.
SEQUENCE_FILENAME = "sequence.json"

#: Permissions.
DIR_MODE = 0o700
SECRET_FILE_MODE = 0o600
PUBLIC_FILE_MODE = 0o644
CONFIG_DIR_MODE = 0o750
CONFIG_FILE_MODE = 0o640


def _resolve(env_var: str, default: Path) -> Path:
    raw = os.environ.get(env_var)
    if raw:
        return Path(raw).expanduser()
    return default


def config_dir() -> Path:
    """Directory holding ``config.yaml``, ``ciphermesh.env`` and Reticulum state."""
    return _resolve(ENV_CONFIG_DIR, DEFAULT_CONFIG_DIR)


def state_dir() -> Path:
    """Directory holding the database, identity keys and other mutable state."""
    return _resolve(ENV_STATE_DIR, DEFAULT_STATE_DIR)


def log_dir() -> Path:
    """Directory for file-based logs."""
    return _resolve(ENV_LOG_DIR, DEFAULT_LOG_DIR)


def app_dir() -> Path:
    """Directory containing the installed source tree.

    Defaults to the repository ``src/`` parent so the CLI works both from an
    editable checkout and from the /opt installation.
    """
    override = os.environ.get(ENV_APP_DIR)
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parent.parent.parent


def config_path() -> Path:
    return config_dir() / CONFIG_FILENAME


def env_path() -> Path:
    return config_dir() / ENV_FILENAME


def reticulum_dir() -> Path:
    return config_dir() / RETICULUM_DIRNAME


def reticulum_config_path() -> Path:
    return reticulum_dir() / RETICULUM_CONFIG_FILENAME


def identity_dir() -> Path:
    return state_dir() / IDENTITY_DIRNAME


def private_key_path() -> Path:
    """The passphrase-derived identity file.

    Named for continuity with the original design; it holds no private key
    material, only the salt and the public key needed to re-derive it.
    """
    return identity_dir() / IDENTITY_FILENAME


def public_key_path() -> Path:
    return identity_dir() / PUBLIC_KEY_FILENAME


def identity_metadata_path() -> Path:
    return identity_dir() / IDENTITY_META_FILENAME


def sequence_state_path() -> Path:
    return state_dir() / SEQUENCE_FILENAME


def default_db_path() -> Path:
    return state_dir() / DB_FILENAME


def migrations_dir() -> Path:
    """Bundled SQL migrations shipped inside the installed package."""
    return Path(__file__).resolve().parent / "storage" / "migrations"


def all_dirs() -> tuple[Path, ...]:
    """Every directory that must exist before the node can start."""
    return (config_dir(), reticulum_dir(), state_dir(), identity_dir())
