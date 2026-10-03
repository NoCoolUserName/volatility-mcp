#!/usr/bin/env python3
"""Prefer a verified typed ISF using only this MCP project's own symbol cache.

Run with the existing Volatility Python and administrator-configured symbols
and cache paths. No source memory image or installed ISF is changed. The single
SQL policy change disables identifiers for matching entries without any types;
their files and all other cache metadata remain intact.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import lzma
from pathlib import Path
import platform
import sqlite3
import sys


RELATIVE_ISF = Path("windows/ntkrnlpa.pdb/BD8F451F3E754ED8A34B50560CEB08E3-1.json.xz")
EXPECTED_SHA256 = "e5e5d5df0d80f8739d8cc61d33620d17a25ea62791d6a85fed12f333a50ce25f"
EXPECTED_GUID = "BD8F451F3E754ED8A34B50560CEB08E3"


def prepare(symbols_path: Path, cache_path: Path) -> dict:
    if not symbols_path.is_absolute() or not cache_path.is_absolute():
        raise ValueError("Symbol and cache paths must be absolute administrator configuration.")
    for path in (symbols_path, cache_path, symbols_path / RELATIVE_ISF):
        for current in (path, *path.parents):
            if current.is_symlink():
                raise ValueError(f"Symbol/cache paths must not contain symlinks: {current}")
    if not (symbols_path / RELATIVE_ISF).exists():
        return {"policy": "normal configured symbols; no legacy XP preference needed"}
    isf_path = symbols_path / RELATIVE_ISF
    payload = isf_path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Supplemental ISF no longer matches its reviewed official SHA-256.")
    isf = json.loads(lzma.decompress(payload))
    pdb = isf["metadata"]["windows"]["pdb"]
    if pdb["GUID"] != EXPECTED_GUID or pdb["age"] != 1 or pdb["database"] != "ntkrnlpa.pdb":
        raise ValueError("Supplemental ISF has unexpected PDB metadata.")
    if len(isf["user_types"]) != 561 or not {"_ETHREAD", "_EPROCESS"}.issubset(isf["user_types"]):
        raise ValueError("Supplemental ISF lacks the reviewed process/thread type definitions.")
    if isf["base_types"]["pointer"]["size"] != 4:
        raise ValueError("Supplemental ISF does not have the expected x86 pointer width.")

    # Import the already-installed official framework; no second Volatility install.
    from volatility3 import symbols
    from volatility3.framework import constants
    from volatility3.framework.automagic.symbol_cache import SqliteCache, WindowsIdentifier

    cache_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    constants.CACHE_PATH = str(cache_path)
    constants.OFFLINE = True  # This preparation only indexes existing local ISFs.
    defaults = list(symbols.__path__)
    symbols.__path__ = [str(symbols_path)] + [path for path in defaults if path != str(symbols_path)]
    database_path = cache_path / constants.IDENTIFIERS_FILENAME
    if database_path.is_symlink():
        raise ValueError("Project symbol database must not be a symlink.")
    manager = SqliteCache(str(database_path))
    manager.update(progress_callback=lambda *args, **kwargs: None)
    identifier = WindowsIdentifier.get_identifier(isf)
    preferred_uri = isf_path.resolve().as_uri()
    stats = manager.get_location_statistics(preferred_uri)
    if manager.get_identifier(preferred_uri) != identifier or stats is None or stats[1] != 561:
        raise ValueError("Official cache indexing did not register the verified typed supplemental ISF.")

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(cache)")}
        required_columns = {"location", "identifier", "operating_system", "stats_types", "local"}
        if not required_columns.issubset(columns):
            raise ValueError("Unsupported Volatility SQLite cache schema; preference policy was not applied.")
        schema = connection.execute("SELECT schema_version FROM database_info").fetchone()
        if schema is None or schema[0] != constants.CACHE_SQLITE_SCHEMA_VERSION:
            raise ValueError("Volatility SQLite schema version does not match the installed framework.")
        disabled = [dict(row) for row in connection.execute(
            "SELECT location, operating_system, stats_types, local FROM cache "
            "WHERE identifier = ? AND operating_system = ? AND stats_types = 0",
            (identifier, "windows"),
        )]
        connection.execute(
            "UPDATE cache SET identifier = NULL WHERE identifier = ? "
            "AND operating_system = ? AND stats_types = 0",
            (identifier, "windows"),
        )
    selected_uri = manager.find_location(identifier, "windows")
    if selected_uri != preferred_uri:
        raise ValueError(f"Cache did not select the verified full typed ISF: selected {selected_uri!r}.")
    # Assert the policy has never changed the supplemental file bytes.
    if hashlib.sha256(isf_path.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Supplemental ISF changed during cache preparation.")
    result = {
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "cache_database": str(database_path),
        "symbols_directory": str(symbols_path), "symbol_search_paths": list(symbols.__path__),
        "identifier": identifier.decode("latin-1"), "preferred_uri": preferred_uri,
        "selected_uri": selected_uri, "preferred_sha256": EXPECTED_SHA256,
        "preferred_type_count": stats[1], "disabled_zero_type_entries": disabled,
        "policy": "Clear only identifiers of zero-type entries matching the verified supplemental ISF identifier.",
        "policy_scope": "administrator-configured MCP symbol cache only",
        "existing_isf_files_modified": False, "default_user_cache_modified": False,
        "architecture": platform.machine(), "isf_target_architecture": "x86",
    }
    audit_path = cache_path / "preference.json"
    if audit_path.is_symlink():
        raise ValueError("Symbol preference audit must not be a symlink.")
    if audit_path.exists():
        previous = json.loads(audit_path.read_text())
        result["previous_preparation_at"] = previous.get("prepared_at")
        previously_disabled = previous.get("all_disabled_zero_type_locations", [])
    else:
        previously_disabled = []
    result["all_disabled_zero_type_locations"] = sorted(
        set(previously_disabled).union(item["location"] for item in disabled)
    )
    temporary = cache_path / "preference.complete.json"
    if temporary.is_symlink():
        raise ValueError("Symbol preference temporary audit must not be a symlink.")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    temporary.replace(audit_path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("symbols_path", type=Path)
    parser.add_argument("cache_path", type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.symbols_path, args.cache_path)
    except Exception as exc:
        print(f"Cannot prepare supplemental symbol cache: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
