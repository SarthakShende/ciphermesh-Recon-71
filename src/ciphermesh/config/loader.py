"""Configuration loading.

Responsibilities:

* Read ``/etc/ciphermesh/config.yaml`` (or ``$CIPHERMESH_CONFIG_DIR``).
* Resolve ``${VAR}`` and ``${VAR:-default}`` references from the process
  environment, which the systemd unit populates from
  ``/etc/ciphermesh/ciphermesh.env``. This is how secrets enter the system:
  they are never written into ``config.yaml`` and never committed.
* Build the frozen dataclasses in :mod:`ciphermesh.config.schema`.
* Reject unknown keys, so a typo is a startup failure rather than a silently
  ignored setting.
* Cross-validate regions and other invariants.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping, get_type_hints

import yaml

from .. import paths
from ..constants import EventType, Role, Unit
from ..errors import ConfigError, ConfigNotFoundError, RegionError, ValidationError
from . import regions as regions_mod
from .schema import (
    ApplicationConfig,
    CloudConfig,
    Config,
    DeviceConfig,
    EventConfig,
    LoraConfig,
    LoggingConfig,
    MonitoringConfig,
    ReticulumConfig,
    SecurityConfig,
    SensorConfig,
    StorageConfig,
    SyncConfig,
    is_loopback_address,
)

#: Sections mapped to their dataclass. The order here is the order in which
#: they appear in the generated example config.
SECTION_TYPES: dict[str, type] = {
    "device": DeviceConfig,
    "sensor": SensorConfig,
    "reticulum": ReticulumConfig,
    "lora": LoraConfig,
    "cloud": CloudConfig,
    "storage": StorageConfig,
    "security": SecurityConfig,
    "sync": SyncConfig,
    "monitoring": MonitoringConfig,
    "logging": LoggingConfig,
    "event": EventConfig,
    "application": ApplicationConfig,
}

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
#: A resolved reference that came from the environment. Tracked so
#: `ciphermesh config show` can display a hint instead of the value.
_ENV_SOURCES: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Environment interpolation
# ---------------------------------------------------------------------------


def expand_env(value: str, *, strict: bool = True, context: str = "") -> str:
    """Expand ``${VAR}`` and ``${VAR:-default}`` in a string.

    With ``strict=True`` an unset variable without a default is an error,
    because silently substituting an empty string for a passphrase would
    produce a link that appears configured but is not.
    """
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        default = match.group(2)
        resolved = os.environ.get(name)
        if resolved is not None:
            _ENV_SOURCES[f"{context}{name}"] = f"${{{name}}}"
            return resolved
        if default is not None:
            return default
        missing.append(name)
        return match.group(0)

    result = _ENV_PATTERN.sub(replace, value)

    if missing and strict:
        joined = ", ".join(sorted(set(missing)))
        where = f" ({context})" if context else ""
        raise ConfigError(
            f"undefined environment variable{'s' if len(set(missing)) > 1 else ''} "
            f"{joined}{where}. Define it in /etc/ciphermesh/ciphermesh.env, or "
            f"use ${{NAME:-fallback}} to provide a default."
        )
    return result


def _expand_tree(node: Any, *, strict: bool, context: str = "") -> Any:
    """Recursively expand env references in every string in a parsed tree."""
    if isinstance(node, str):
        return expand_env(node, strict=strict, context=context)
    if isinstance(node, dict):
        return {
            key: _expand_tree(value, strict=strict, context=f"{context}{key}.")
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_expand_tree(item, strict=strict, context=context) for item in node]
    return node


# ---------------------------------------------------------------------------
# Raw file access
# ---------------------------------------------------------------------------


def read_raw(config_path: Path | None = None, *, strict_env: bool = True) -> dict[str, Any]:
    """Load and env-expand the YAML config without building dataclasses."""
    path = config_path or paths.config_path()

    if not path.is_file():
        raise ConfigNotFoundError(
            f"No configuration file at {path}. Run `sudo ./install.sh` to create one, "
            f"or set ${paths.ENV_CONFIG_DIR} to a directory containing config.yaml."
        )

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Malformed YAML in {path}: {exc}") from exc

    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")

    expanded = _expand_tree(parsed, strict=strict_env)
    if not isinstance(expanded, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")
    return expanded


# ---------------------------------------------------------------------------
# Dataclass construction
# ---------------------------------------------------------------------------


def _coerce(value: Any, target: Any, key: str) -> Any:
    """Coerce a YAML scalar into the type a dataclass field expects."""
    # Optional[X] / X | None
    origin = getattr(target, "__origin__", None)
    if origin is not None:
        args = [a for a in getattr(target, "__args__", ()) if a is not type(None)]
        if value is None:
            return None
        if origin in (tuple,) and args:
            return tuple(_coerce(v, args[0], key) for v in value)
        if len(args) == 1:
            return _coerce(value, args[0], key)
        return value

    if value is None:
        if target in (str, int, float, bool):
            raise ValidationError(key, "must not be null")
        return value

    try:
        if target is bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in ("true", "yes", "on", "1"):
                    return True
                if lowered in ("false", "no", "off", "0"):
                    return False
                raise ValidationError(key, "expected a boolean", value)
            if isinstance(value, int):
                return bool(value)
            raise ValidationError(key, "expected a boolean", value)

        if target is str:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return str(value)
            if not isinstance(value, str):
                raise ValidationError(key, "expected a string", value)
            return value

        if target is int:
            if isinstance(value, bool):
                raise ValidationError(key, "expected an integer, got a boolean", value)
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value.strip(), 0)
                except ValueError:
                    pass
            if isinstance(value, float) and value.is_integer():
                return int(value)
            raise ValidationError(key, "expected an integer", value)

        if target is float:
            if isinstance(value, bool):
                raise ValidationError(key, "expected a number, got a boolean", value)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value.strip())
                except ValueError:
                    pass
            raise ValidationError(key, "expected a number", value)
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise ValidationError(key, f"could not be interpreted as {target}", value) from exc

    return value


def _build_section(section_name: str, data: Any, target: type) -> Any:
    """Instantiate a config dataclass, rejecting unknown keys."""
    if data is None:
        return target()
    if not isinstance(data, dict):
        raise ValidationError(section_name, "must be a mapping", data)

    hints = get_type_hints(target)
    valid = {f for f in target.__dataclass_fields__}  # type: ignore[attr-defined]
    unknown = set(data) - valid
    if unknown:
        raise ValidationError(
            section_name,
            "unknown option(s): " + ", ".join(sorted(unknown)) + ". Valid options: "
            + ", ".join(sorted(valid)),
        )

    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        field_type = hints.get(key, object)
        full_key = f"{section_name}.{key}"
        try:
            kwargs[key] = _coerce(value, field_type, full_key)
        except ValidationError as exc:
            exc.key = full_key
            raise
    return target(**kwargs)


def _convert_enums(config: Config) -> Config:
    """Turn the string forms of Role/Unit/EventType into enum members."""
    from dataclasses import replace

    device = replace(config.device, role=_as_enum(Role, config.device.role, "device.role"))
    event = replace(
        config.event,
        default_unit=_as_enum(Unit, config.event.default_unit, "event.default_unit"),
        default_event_type=_as_enum(
            EventType, config.event.default_event_type, "event.default_event_type"
        ),
    )
    return replace(config, device=device, event=event)


def _as_enum(enum_cls, value, key):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value).strip().upper())
    except ValueError:
        valid = ", ".join(m.value for m in enum_cls)
        raise ValidationError(key, f"must be one of: {valid}", value) from None


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def _resolve_paths(config: Config) -> Config:
    """Fill in path fields that default to the standard locations."""
    from dataclasses import replace

    storage = config.storage
    reticulum = config.reticulum

    if not storage.sqlite_path:
        storage = replace(storage, sqlite_path=str(paths.default_db_path()))
    if not reticulum.config_dir:
        reticulum = replace(reticulum, config_dir=str(paths.reticulum_dir()))

    return replace(config, storage=storage, reticulum=reticulum)


# ---------------------------------------------------------------------------
# Cross-section validation
# ---------------------------------------------------------------------------


def _validate_regions(config: Config) -> None:
    """Check LoRa RF parameters against the configured regional plan.

    Only runs when the radio is enabled on an RNode interface. An
    unsupported interface is left for :mod:`ciphermesh.lora` to report as
    UNSUPPORTED at runtime.
    """
    lora = config.lora
    if not lora.enabled or lora.interface.lower() != "rnode":
        return

    try:
        region = regions_mod.resolve(lora.region)
    except RegionError as exc:
        raise ValidationError("lora.region", str(exc)) from exc

    if not region.verified:
        raise ValidationError(
            "lora.region",
            f"region {region.code} is marked UNVERIFIED in ciphermesh/config/regions.py. "
            "Confirm the applicable limits with your regulator and add a verified "
            "entry before enabling the radio. Source note: " + region.source,
        )

    regions_mod.validate_config(
        region,
        frequency_hz=int(lora.frequency or 0),
        bandwidth_hz=int(lora.bandwidth or 0),
        spreading_factor=int(lora.spreading_factor or 0),
        coding_rate=int(lora.coding_rate or 0),
        tx_power_dbm=int(lora.tx_power or 0),
        max_tx_power_dbm=lora.max_tx_power_dbm,
    )

    channel = region.matches_channel(int(lora.frequency or 0), int(lora.bandwidth or 0))
    if channel is None and int(lora.bandwidth or 0) == 125_000:
        # In-band but not one of the plan's default channels. Permissible, but
        # worth surfacing so the operator knows they are off-plan.
        _ENV_SOURCES.setdefault(
            "lora.frequency", "off-plan frequency within the region band"
        )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def load(
    config_path: Path | None = None,
    *,
    strict_env: bool = True,
    validate: bool = True,
) -> Config:
    """Load, expand, build and validate the configuration.

    This is the function every entry point calls.
    """
    raw = read_raw(config_path, strict_env=strict_env)

    unknown_sections = set(raw) - set(SECTION_TYPES)
    if unknown_sections:
        raise ConfigError(
            "unknown top-level section(s): "
            + ", ".join(sorted(unknown_sections))
            + ". Valid sections: "
            + ", ".join(sorted(SECTION_TYPES))
        )

    if "device" not in raw:
        raise ConfigError("configuration is missing the required 'device' section")

    sections: dict[str, Any] = {}
    for name, target in SECTION_TYPES.items():
        sections[name] = _build_section(name, raw.get(name), target)

    config = Config(**sections)
    config = _convert_enums(config)
    config = _resolve_paths(config)

    if validate:
        config.validate()
        _validate_regions(config)

    _enforce_auth_policy(config)
    return config


def _enforce_auth_policy(config: Config) -> None:
    """Refuse to produce an unauthenticated API on a routable interface.

    ``MonitoringConfig.effective_auth_required`` already reports this, but a
    misconfiguration that reaches here is a hard failure rather than a
    runtime surprise, because the API is only started after config load.
    """
    monitoring = config.monitoring
    if not monitoring.enabled:
        return
    if not is_loopback_address(monitoring.bind_address) and not monitoring.auth_token:
        raise ValidationError(
            "monitoring.auth_token",
            "must be set when monitoring.bind_address is not a loopback address. "
            "Set ${CIPHERMESH_API_TOKEN} in /etc/ciphermesh/ciphermesh.env, or "
            "bind to 127.0.0.1 and use an SSH tunnel for remote access.",
        )


def load_or_defaults(
    config_path: Path | None = None,
    *,
    device_id: str = "CM-LOCAL",
    device_name: str = "CipherMesh Development Node",
    role: Role = Role.GATEWAY_SENSOR,
) -> Config:
    """Load config, falling back to a safe in-memory default when absent.

    Used by the test suite and by ``ciphermesh test`` commands that must run
    without a provisioned device. The returned config points at the
    environment-overridden paths, so it never touches ``/etc``.
    """
    try:
        return load(config_path)
    except ConfigNotFoundError:
        return _development_config(device_id, device_name, role)


def _development_config(
    device_id: str, device_name: str, role: Role
) -> Config:
    """An all-local, no-hardware configuration.

    Reticulum is disabled because starting a stack with no configured radio
    is meaningless, and the sensor defaults to mock so that ``ciphermesh
    test event`` works on a laptop.
    """
    from dataclasses import replace

    return replace(
        Config(
            device=DeviceConfig(id=device_id, name=device_name, role=role),
            sensor=SensorConfig(
                enabled=True, type="mock", interval_seconds=5.0, mock_sweep=False
            ),
            reticulum=ReticulumConfig(enabled=False),
            lora=LoraConfig(enabled=False),
            cloud=CloudConfig(enabled=False),
        ),
        storage=replace(StorageConfig(), sqlite_path=str(paths.default_db_path())),
        reticulum=replace(ReticulumConfig(enabled=False), config_dir=str(paths.reticulum_dir())),
    )


def write_example(path: Path) -> Path:
    """Write a fully commented example config. Used by ``install.sh``."""
    from .templates import render_example_config

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_example_config(), encoding="utf-8")
    return path


def env_source_hints() -> Mapping[str, str]:
    """Which values came from the environment, for display purposes."""
    return dict(_ENV_SOURCES)
