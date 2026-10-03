"""Small operator CLI. Configuration and protocol use need no report settings."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

from . import __version__
from .config import Config, ConfigurationError, absolute_path, config_path, load_config


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=timeout, check=False)


def host_architecture() -> str:
    if platform.system() == "Darwin":
        result = run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])
        if result.returncode == 0 and result.stdout.strip() == "1":
            return "arm64"
    return platform.machine()


def inspect_python(path: Path) -> dict:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ConfigurationError(f"Python executable is unavailable: {path}")
    code = (
        "import importlib.metadata,json,platform,sys; "
        "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,"
        "'base_prefix':sys.base_prefix,'architecture':platform.machine(),"
        "'python_version':platform.python_version(),'version_info':list(sys.version_info[:3]),"
        "'volatility_version':importlib.metadata.version('volatility3')}))"
    )
    result = run([str(path), "-I", "-c", code])
    if result.returncode:
        raise ConfigurationError(f"Cannot import official Volatility from {path}: {result.stderr.strip()[-1500:]}")
    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ConfigurationError(f"Unexpected Python inspection output from {path}") from exc
    if info["version_info"] < [3, 10]:
        raise ConfigurationError("Volatility requires a suitable Python interpreter (3.10 or newer).")
    if platform.system() == "Darwin" and host_architecture() == "arm64" and info["architecture"] != "arm64":
        raise ConfigurationError(f"Apple Silicon requires native arm64 Python; {path} reports {info['architecture']}.")
    return info


def validate_vol(config: Config) -> dict:
    info = inspect_python(config.vol_python)
    if not config.vol_executable.is_file() or not os.access(config.vol_executable, os.X_OK):
        raise ConfigurationError(f"Volatility executable is unavailable: {config.vol_executable}")
    # The backend invokes this exact script through the selected venv Python.
    result = run([str(config.vol_python), "-I", str(config.vol_executable), "--help"], config.catalog_timeout)
    if result.returncode != 0 or "Volatility 3" not in result.stdout + result.stderr:
        raise ConfigurationError(f"Volatility help failed (exit {result.returncode}): {(result.stderr or result.stdout)[-1500:]}")
    return info


def write_config(path: Path, config: Config) -> bool:
    """Atomic mode-0600 write, avoiding edits when the semantic config is unchanged."""
    if path.is_symlink():
        raise ConfigurationError(f"Configuration must not be a symlink: {path}")
    data = config.to_dict()
    if path.exists() and json.loads(path.read_text(encoding="utf-8")) == data:
        path.chmod(0o600)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".volatility-config-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def discover_volatility() -> tuple[Path, Path]:
    default = Path.home() / "Forensics" / "volatility-env" / "bin"
    candidates = [(default / "python", default / "vol")]
    executable = shutil.which("vol")
    if executable:
        candidates.append((Path(executable).parent / "python", Path(executable)))
    for python, vol in candidates:
        if python.is_file() and vol.is_file():
            try:
                inspect_python(python)
            except ConfigurationError:
                continue
            return absolute_path(python), absolute_path(vol)
    raise ConfigurationError("No suitable Volatility installation found. Supply --vol-python and --vol, or use --install-volatility to create an isolated installation.")


def install_volatility(destination: Path) -> tuple[Path, Path]:
    destination = absolute_path(destination)
    python, vol = destination / "bin" / "python", destination / "bin" / "vol"
    if destination.exists():
        if python.is_file() and vol.is_file():
            inspect_python(python)
            return python, vol
        raise ConfigurationError(f"Refusing to overwrite existing directory {destination}; choose an unused --vol-venv.")
    if platform.system() == "Darwin" and host_architecture() == "arm64" and platform.machine() != "arm64":
        raise ConfigurationError("Run setup with native arm64 Python before creating the Volatility environment.")
    for argv in ([sys.executable, "-m", "venv", str(destination)],
                 [str(python), "-m", "pip", "install", "--index-url", "https://pypi.org/simple", "volatility3[full]"]):
        print(f"Installing prerequisite: {' '.join(argv)}", file=sys.stderr)
        completed = subprocess.run(argv, shell=False, stdout=sys.stderr, stderr=sys.stderr, timeout=1200)
        if completed.returncode:
            raise ConfigurationError(f"Prerequisite installation failed with exit {completed.returncode}; the partial environment remains at {destination} for diagnosis.")
    inspect_python(python)
    return python, vol


def setup(args: argparse.Namespace) -> dict:
    if os.name != "posix":
        raise ConfigurationError("The current subprocess confinement uses POSIX process groups. Windows server operation is not yet supported.")
    selected = config_path(args.config)
    values = load_config(selected).to_dict() if selected.exists() else {}
    for name in ("evidence_root", "output_root", "symbols", "cache_path", "command_timeout", "catalog_timeout", "vol_python", "vol_executable"):
        value = getattr(args, name, None)
        if value is not None:
            values[name] = value
    if args.disable_xpnet:
        values["enable_xpnet"] = False
    if "vol_python" in values and "vol_executable" not in values:
        values["vol_executable"] = str(absolute_path(values["vol_python"]).parent / "vol")
    if "vol_executable" in values and "vol_python" not in values:
        values["vol_python"] = str(absolute_path(values["vol_executable"]).parent / "python")
    if "vol_python" not in values:
        if args.install_volatility:
            python, vol = install_volatility(absolute_path(args.vol_venv))
        else:
            python, vol = discover_volatility()
        values.update(vol_python=str(python), vol_executable=str(vol))
    values.setdefault("evidence_root", str(Path.home() / "Forensics" / "cases"))
    values.setdefault("output_root", str(Path.home() / "Forensics" / "outputs"))
    config = Config.from_dict(values)
    info = validate_vol(config)
    for root in (config.evidence_root, config.output_root, config.cache_path):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    changed = write_config(selected, config)
    return {"status": "configured" if changed else "already_configured", "config": str(selected),
            "settings": config.to_dict(), "volatility": info,
            "next": f"python -m volatility_mcp doctor --config {selected} --mcp"}


def decode_result(result) -> dict:
    if getattr(result, "is_error", False):
        raise ConfigurationError(f"MCP tool returned an error: {result}")
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured
    text = "\n".join(item.text for item in result.content if getattr(item, "type", "") == "text")
    return json.loads(text)


async def protocol_check(path: Path, config: Config) -> list[dict]:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
    results = []
    for mode in ("auto", "legacy"):
        transport = StdioServerParameters(command=str(absolute_path(sys.executable)),
                                           args=["-m", "volatility_mcp", "serve", "--config", str(path)])
        async with Client(transport, mode=mode, read_timeout_seconds=config.catalog_timeout + 30) as client:
            tool_list = await client.list_tools()
            names = sorted(tool.name for tool in tool_list.tools)
            expected = {"list_memory_images", "get_image_info", "list_plugins", "run_plugin", "read_output", "case_history"}
            if not expected.issubset(names):
                raise ConfigurationError(f"MCP server is missing expected tools: {sorted(expected - set(names))}")
            plugins = decode_result(await client.call_tool("list_plugins", {"query": "windows.info.Info"}))
            if plugins.get("count") != 1 or "windows.info.Info" not in json.dumps(plugins):
                raise ConfigurationError("MCP plugin discovery did not find the installed windows.info.Info plugin.")
            results.append({"mode": mode, "protocol_version": client.protocol_version,
                            "server_name": client.server_info.name, "tools": names,
                            "plugin_discovery": plugins})
    return results


def doctor(args: argparse.Namespace) -> dict:
    path = config_path(args.config)
    config = load_config(path)
    report = {"status": "ok", "project_version": __version__, "platform": platform.system(),
              "server_python": str(absolute_path(sys.executable)), "server_architecture": platform.machine(),
              "host_architecture": host_architecture(), "mcp_sdk_version": importlib.metadata.version("mcp"),
              "config": str(path), "volatility": validate_vol(config), "roots": {}}
    if os.name != "posix":
        raise ConfigurationError("This server currently requires POSIX process groups; Windows operation is not supported.")
    if platform.system() == "Darwin" and report["host_architecture"] == "arm64" and report["server_architecture"] != "arm64":
        raise ConfigurationError("The server's Python runs under emulation; recreate its environment using native arm64 Python.")
    for name in ("evidence_root", "output_root", "cache_path"):
        root = getattr(config, name)
        if not root.is_dir():
            raise ConfigurationError(f"{name} is missing: {root}; rerun setup.")
        if name != "evidence_root" and not os.access(root, os.W_OK):
            raise ConfigurationError(f"{name} is not writable: {root}")
        report["roots"][name] = str(root)
    checked = run([sys.executable, "-m", "pip", "check"])
    if checked.returncode:
        raise ConfigurationError(f"Server dependencies are inconsistent: {checked.stdout} {checked.stderr}")
    report["dependency_check"] = checked.stdout.strip()
    vol_checked = run([str(config.vol_python), "-m", "pip", "check"])
    if vol_checked.returncode:
        raise ConfigurationError(f"Volatility dependencies are inconsistent: {vol_checked.stdout} {vol_checked.stderr}")
    report["volatility_dependency_check"] = vol_checked.stdout.strip()
    if args.mcp:
        report["mcp"] = asyncio.run(protocol_check(path, config))
    return report


def _timeout_configuration(text: str, startup: int, tool: int) -> str:
    section = re.search(r"(?m)^\[mcp_servers\.volatility\][ \t]*\n", text)
    if section is None:
        raise ConfigurationError("Codex did not write the expected volatility MCP table; restore the private backup if necessary.")
    tail = text[section.end():]
    next_section = re.search(r"(?m)^\[", tail)
    end = section.end() + (next_section.start() if next_section else len(tail))
    body = text[section.end():end]
    for key, value in (("startup_timeout_sec", startup), ("tool_timeout_sec", tool)):
        match = re.search(rf"(?m)^{key}\s*=.*$", body)
        line = f"{key} = {value}"
        body = body[:match.start()] + line + body[match.end():] if match else line + "\n" + body
    return text[:section.end()] + body + text[end:]


def _client_config_bytes(path: Path) -> bytes | None:
    if path.is_symlink():
        raise ConfigurationError("Codex configuration must not be a symlink for a guarded update.")
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _guarded_client_write(path: Path, replacement: bytes | None, expected: bytes | None) -> None:
    """Avoid overwriting an observed concurrent change; replacement is atomic.

    This is an operator convenience, not a lock against a malicious local writer
    racing the final comparison and rename. Keep other config editors idle.
    """
    if _client_config_bytes(path) != expected:
        raise ConfigurationError("Codex configuration changed concurrently; refusing to overwrite the newer contents.")
    if replacement == expected:
        return
    if replacement is None:
        path.unlink()
        return
    descriptor, name = tempfile.mkstemp(prefix=".volatility-codex-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(replacement)
        if _client_config_bytes(path) != expected:
            raise ConfigurationError("Codex configuration changed concurrently; refusing to overwrite the newer contents.")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def register_codex(args: argparse.Namespace) -> dict:
    config_file = config_path(args.config)
    config = load_config(config_file)
    codex = shutil.which("codex")
    if codex is None:
        raise ConfigurationError("Codex CLI is unavailable on PATH. Install/authenticate Codex, or register the stdio command in another client.")
    # Backups are private local state, never part of the repository.
    destination = absolute_path(args.backup_dir or Path.home() / ".local" / "state" / "volatility-mcp" / "backups")
    destination = destination / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True, mode=0o700)
    destination.chmod(0o700)
    codex_home = absolute_path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    codex_config = codex_home / "config.toml"
    original_bytes = _client_config_bytes(codex_config)
    before_bytes = original_bytes or b""
    before = tomllib.loads(before_bytes.decode())
    existing = run([codex, "mcp", "get", "volatility", "--json"])
    for name, content in (("config.toml", before_bytes), ("volatility-registration.json", existing.stdout.encode()),
                          ("registration-stderr.txt", existing.stderr.encode())):
        target = destination / name
        target.write_bytes(content)
        target.chmod(0o600)
    previous = before.get("mcp_servers", {}).get("volatility", {})
    startup = max(90, config.catalog_timeout + 30, previous.get("startup_timeout_sec", 0))
    timeout = max(1800, config.command_timeout * 2 + 300, previous.get("tool_timeout_sec", 0))
    command = [str(absolute_path(sys.executable)), "-m", "volatility_mcp", "serve", "--config", str(config_file)]
    observed_bytes = original_bytes
    observation_available = True
    try:
        try:
            added = run([codex, "mcp", "add", "volatility", "--", *command])
        finally:
            observation_available = False
            observed_bytes = _client_config_bytes(codex_config)
            observation_available = True
        if added.returncode:
            raise ConfigurationError(f"Codex registration failed: {added.stderr.strip()}")
        if observed_bytes is None:
            raise ConfigurationError("Codex did not create its configuration file.")
        current = observed_bytes.decode("utf-8")
        updated = _timeout_configuration(current, startup, timeout)
        after = tomllib.loads(updated)
        for parsed in (before, after):
            parsed.get("mcp_servers", {}).pop("volatility", None)
            if parsed.get("mcp_servers") == {}:
                parsed.pop("mcp_servers")
        if before != after:
            raise ConfigurationError("Unrelated Codex settings changed during registration.")
        replacement = updated.encode("utf-8")
        _guarded_client_write(codex_config, replacement, observed_bytes)
        observed_bytes = replacement
        verification = run([codex, "mcp", "get", "volatility", "--json"])
        listing = run([codex, "mcp", "list"])
        if verification.returncode or listing.returncode:
            raise ConfigurationError(f"Codex registration verification failed: {verification.stderr} {listing.stderr}")
        registration = json.loads(verification.stdout)
        transport = registration.get("transport", {}) if isinstance(registration, dict) else {}
        if (not isinstance(transport, dict) or transport.get("type") != "stdio"
                or transport.get("command") != command[0] or transport.get("args") != command[1:]
                or registration.get("enabled") is not True):
            raise ConfigurationError("Codex verification returned a different or disabled server command.")
        if _client_config_bytes(codex_config) != observed_bytes:
            raise ConfigurationError("Codex configuration changed during verification.")
    except (Exception, KeyboardInterrupt) as exc:
        try:
            if not observation_available:
                raise ConfigurationError("Cannot read the post-command configuration; automatic restoration is unsafe.")
            _guarded_client_write(codex_config, original_bytes, observed_bytes)
        except (OSError, ConfigurationError) as restoration_error:
            raise ConfigurationError(
                f"{exc} Automatic restoration was withheld or failed: {restoration_error} "
                f"Compare the private backup at {destination} before any manual restoration.") from exc
        raise ConfigurationError(
            f"{exc or 'Registration interrupted.'} Original Codex configuration restored; "
            f"private backup: {destination}.") from exc
    return {"status": "registered", "command": command, "backup_directory": str(destination),
            "registration": registration, "mcp_list": listing.stdout.strip()}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="volatility-mcp", description=__doc__)
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("setup", help="Reuse or explicitly install Volatility and write private local configuration")
    configure.add_argument("--config")
    configure.add_argument("--vol-python")
    configure.add_argument("--vol", dest="vol_executable")
    configure.add_argument("--evidence-root")
    configure.add_argument("--output-root")
    configure.add_argument("--symbols")
    configure.add_argument("--cache-path")
    configure.add_argument("--command-timeout", type=int)
    configure.add_argument("--catalog-timeout", type=int)
    configure.add_argument("--disable-xpnet", action="store_true")
    configure.add_argument("--install-volatility", action="store_true", help="Create an isolated official Volatility install only when none is configured")
    configure.add_argument("--vol-venv", default=str(Path.home() / "Forensics" / "volatility-env"))
    diagnostic = commands.add_parser("doctor", help="Validate paths, architecture, installation, and optionally real MCP calls")
    diagnostic.add_argument("--config")
    diagnostic.add_argument("--mcp", action="store_true", help="Start fresh stdio servers in auto and legacy protocol modes")
    serving = commands.add_parser("serve", help="Run the client-neutral stdio MCP server")
    serving.add_argument("--config")
    registration = commands.add_parser("register-codex", help="Back up and update this user's volatility Codex registration")
    registration.add_argument("--config")
    registration.add_argument("--backup-dir")
    reporting = commands.add_parser("report-check", help="Validate an optional report bundle")
    reporting.add_argument("bundle", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "serve":
            from .server import create_server
            create_server(load_config(args.config)).run(transport="stdio")
            return 0
        if args.command == "report-check":
            from .reporting import check_bundle
            result = check_bundle(args.bundle)
        else:
            result = {"setup": setup, "doctor": doctor, "register-codex": register_codex}[args.command](args)
        print(json.dumps(result, indent=2))
        return 0
    except (ConfigurationError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"volatility-mcp: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("volatility-mcp: interrupted", file=sys.stderr)
        return 130
