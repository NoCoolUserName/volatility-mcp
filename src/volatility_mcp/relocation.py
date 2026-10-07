"""Explicit operator-approved root alias; never allow arbitrary evidence symlinks."""
from __future__ import annotations
import json
import os
from pathlib import Path

ENV = 'VOLATILITY_MCP_RELOCATION'


def mapping():
    filename = os.environ.get(ENV)
    if not filename:
        return None
    source = Path(filename)
    if not source.is_absolute() or source.stat().st_size > 8192:
        raise ValueError('Relocation configuration must be an absolute, small local file')
    record = json.loads(source.read_text())
    if not isinstance(record, dict) or set(record) != {'logical_root', 'physical_root'}:
        raise ValueError('Relocation requires exactly logical_root and physical_root')
    old, new = (Path(record[k]) for k in ('logical_root', 'physical_root'))
    if (not old.is_absolute() or not new.is_absolute() or '..' in old.parts or '..' in new.parts
            or old.is_relative_to(new) or new.is_relative_to(old)):
        raise ValueError('Relocation roots must be absolute, distinct, nonoverlapping paths')
    if new.resolve(strict=True) != new or not new.is_dir():
        raise ValueError('Relocation physical root must be a canonical directory')
    if old.parent.resolve(strict=True) != old.parent or not old.is_symlink() or old.resolve(strict=True) != new:
        raise ValueError('Relocation logical root must be the exact registered administrative alias')
    return old, new


def logical_path(path):
    path = Path(path)
    pair = mapping()
    if pair and path.is_relative_to(pair[1]):
        return pair[0] / path.relative_to(pair[1])
    return path


def check_components(path):
    path = Path(path)
    if '..' in path.parts:
        raise ValueError('Path traversal is forbidden')
    pair = mapping()
    for part in (path, *path.parents):
        if part.is_symlink() and (not pair or part != pair[0]):
            raise ValueError(f'Symlink paths are forbidden: {part}')


def resolved_path(path, *, strict=False):
    check_components(path)
    return logical_path(Path(path).resolve(strict=strict))


def environment():
    if not os.environ.get(ENV):
        return {}
    mapping()  # Fail closed if an administrator changed the alias.
    return {ENV: os.environ[ENV]}
