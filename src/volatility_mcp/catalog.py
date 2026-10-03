#!/usr/bin/env python3
"""Describe the installed Volatility plugins using Volatility's own Python.

This helper deliberately runs under the existing Volatility virtual environment;
the MCP server's separate environment does not need to install Volatility again.
Only JSON is written to stdout so the caller can validate the catalog.
"""

from __future__ import annotations

import inspect
import json
import platform
import sys
from pathlib import Path
from importlib.metadata import version
from typing import Any

from volatility3 import framework, plugins
from volatility3.framework import interfaces, constants
from volatility3.framework.configuration import requirements


def option_spec(requirement: Any) -> dict[str, Any] | None:
    """Mirror Volatility's CLI handling of user-facing requirements.

    Framework modules, versions, and translation layers are resolved by
    Volatility's automagic and are not plugin command-line arguments.
    Integer arguments accept decimal and Python's base-prefixed notation; the
    server applies int(value, 0) while validating this type.
    """
    spec: dict[str, Any] = {
        "flag": "--" + requirement.name.replace("_", "-"),
        "dest": requirement.name,
        "required": not requirement.optional,
        "nargs": None,
        "type": "str",
        "action": "store",
        "choices": None,
        "help": requirement.description,
        "is_path": isinstance(requirement, requirements.URIRequirement),
    }
    type_names = {str: "str", int: "int", float: "float"}
    if isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
        if isinstance(requirement, requirements.BooleanRequirement):
            spec.update(action="store_true", nargs=0)
        else:
            value_type = requirement.instance_type
            if value_type not in type_names:
                raise TypeError(
                    f"Unsupported simple requirement type for {requirement.name}: "
                    f"{value_type!r}"
                )
            spec["type"] = type_names[value_type]
    elif isinstance(requirement, requirements.ListRequirement):
        value_type = requirement.element_type
        if value_type not in type_names:
            raise TypeError(
                f"Unsupported list requirement type for {requirement.name}: "
                f"{value_type!r}"
            )
        spec.update(
            type=type_names[value_type],
            nargs="*" if requirement.optional else "+",
        )
    elif isinstance(requirement, requirements.ChoiceRequirement):
        spec["choices"] = requirement.choices
    else:
        return None
    return spec


def build_catalog() -> dict[str, Any]:
    local_plugins = Path(__file__).resolve().parent / "plugins"
    if "--xpnet" in sys.argv and local_plugins.exists():
        if local_plugins.is_symlink() or any(path.is_symlink() for path in local_plugins.rglob("*")):
            raise ValueError("Local plugin directory/files must not be symlinks")
        plugins.__path__ = [str(local_plugins)] + constants.PLUGINS_PATH
    import_failures = framework.import_files(plugins, True)
    available: dict[str, Any] = {}
    for name, plugin in sorted(framework.list_plugins().items()):
        options = [
            spec
            for requirement in plugin.get_requirements()
            if (spec := option_spec(requirement)) is not None
        ]
        available[name] = {
            "description": inspect.getdoc(plugin) or "",
            "options": options,
            "origin": ("local_compatibility" if Path(inspect.getfile(plugin)).resolve().is_relative_to(local_plugins)
                       else "installed_volatility"),
            "plugin_version": list(plugin.version),
            "source_file": str(Path(inspect.getfile(plugin)).resolve()),
        }
    return {
        "version": version("volatility3"),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "plugins": available,
        "import_failures": import_failures,
    }


def main() -> int:
    try:
        json.dump(build_catalog(), sys.stdout, sort_keys=True, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print(f"Unable to inspect the existing Volatility installation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
