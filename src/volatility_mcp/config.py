"""Explicit local configuration, independent of any client or reporting workflow."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from .relocation import logical_path, resolved_path, mapping


class ConfigurationError(ValueError):
    """Configuration cannot safely be used; show the message to the operator."""


def absolute_path(value: str | Path) -> Path:
    """Keep venv executable paths: resolving their symlinks loses the environment."""
    return Path(os.path.abspath(Path(value).expanduser()))


def config_path(value: str | Path | None = None) -> Path:
    return absolute_path(value or os.environ.get("VOLATILITY_MCP_CONFIG") or
                         Path.home() / ".config" / "volatility-mcp" / "config.json")


def _directory(value: str | Path, label: str) -> Path:
    path = absolute_path(value)
    pair = mapping()
    if pair and any(path.is_relative_to(root) for root in pair):
        try:
            result = resolved_path(logical_path(path))
            if result.exists() and not result.is_dir():
                raise ConfigurationError(f"{label} must be a directory: {path}")
            return result
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
    if path.is_symlink():
        raise ConfigurationError(f"{label} must not be a symlink: {path}")
    if path.exists() and not path.is_dir():
        raise ConfigurationError(f"{label} must be a directory: {path}")
    # Configuration is operator-controlled. Canonicalize ancestor aliases once;
    # the backend confines all subsequent untrusted paths to this canonical root.
    return path.resolve()


@dataclass(frozen=True)
class Config:
    evidence_root: Path
    output_root: Path
    vol_python: Path
    vol_executable: Path
    symbols: Path | None = None
    cache_path: Path = Path("~/.cache/volatility-mcp/symbols")
    command_timeout: int = 300
    catalog_timeout: int = 60
    enable_xpnet: bool = True

    def __post_init__(self) -> None:
        for name in ("evidence_root", "output_root", "cache_path"):
            object.__setattr__(self, name, _directory(getattr(self, name), name))
        for name in ("vol_python", "vol_executable"):
            object.__setattr__(self, name, absolute_path(getattr(self, name)))
        if self.symbols is not None:
            object.__setattr__(self, "symbols", _directory(self.symbols, "symbols"))
        if self.evidence_root == self.output_root or self.evidence_root.is_relative_to(self.output_root):
            raise ConfigurationError("output_root must not equal or contain evidence_root. Use a separate output directory.")
        if self.cache_path == self.evidence_root or self.evidence_root.is_relative_to(self.cache_path):
            raise ConfigurationError("cache_path must not equal or contain evidence_root.")
        for name in ("command_timeout", "catalog_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
                raise ConfigurationError(f"{name} must be an integer from 1 to 86400 seconds.")
        if not isinstance(self.enable_xpnet, bool):
            raise ConfigurationError("enable_xpnet must be true or false.")

    def to_dict(self) -> dict:
        return {"schema_version": 1, **{
            name: str(value) if isinstance(value, Path) else value
            for name, value in self.__dict__.items()
        }}

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        if not isinstance(data, dict):
            raise ConfigurationError("Configuration must be a JSON object.")
        values = dict(data)
        version = values.pop("schema_version", 1)
        if version != 1:
            raise ConfigurationError(f"Unsupported configuration schema_version: {version!r}")
        unknown = set(values) - set(cls.__dataclass_fields__)
        if unknown:
            raise ConfigurationError(f"Unknown configuration fields: {', '.join(sorted(unknown))}")
        for name in ("evidence_root", "output_root", "vol_python", "vol_executable", "cache_path", "symbols"):
            if name in values and values[name] is not None and not isinstance(values[name], (str, Path)):
                raise ConfigurationError(f"{name} must be a filesystem path.")
        try:
            return cls(**values)
        except TypeError as exc:
            raise ConfigurationError(f"Missing required configuration. Run volatility-mcp setup: {exc}") from exc


def load_config(path: str | Path | None = None) -> Config:
    selected = config_path(path)
    try:
        data = json.loads(selected.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration not found: {selected}. Run 'python -m volatility_mcp setup --help' first.") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Invalid JSON configuration at {selected}: {exc}") from exc
    return Config.from_dict(data)
