"""Shared pytest fixtures.

Every test runs against a throwaway state directory so nothing here can touch
a real node's identity, and so the on-disk permission assertions mean
something.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ciphermesh import paths
from ciphermesh.constants import Role
from ciphermesh.crypto import KeyPair
from ciphermesh.events import EventFactory, SequenceAllocator
from ciphermesh.identity import IdentityManager


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Redirect every resolved path into a temporary directory."""
    config = tmp_path / "etc"
    state = tmp_path / "var"
    logs = tmp_path / "log"
    for target in (config, state, logs):
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, 0o700)
    monkeypatch.setenv(paths.ENV_CONFIG_DIR, str(config))
    monkeypatch.setenv(paths.ENV_STATE_DIR, str(state))
    monkeypatch.setenv(paths.ENV_LOG_DIR, str(logs))
    return state


@pytest.fixture
def passphrase():
    return "correct horse battery staple"


@pytest.fixture
def manager(state_dir, passphrase):
    """An IdentityManager backed by the temporary state directory."""
    return IdentityManager.open(
        passphrase,
        device_id="PI-A-0001",
        device_name="greenhouse-sensor",
        role=Role.GATEWAY_SENSOR,
        location="block-c",
    )


@pytest.fixture
def keypair():
    return KeyPair.generate()


@pytest.fixture
def allocator(state_dir):
    return SequenceAllocator()


@pytest.fixture
def event_config():
    from ciphermesh.config.schema import EventConfig

    return EventConfig()


@pytest.fixture
def factory(event_config, manager, allocator):
    return EventFactory.from_identity(event_config, manager, allocator)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(Path(path).stat().st_mode)
