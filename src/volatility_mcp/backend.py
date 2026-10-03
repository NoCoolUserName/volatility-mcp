"""Validated Volatility subprocesses and append-only per-run evidence artifacts."""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import platform
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time

from . import __version__
from .config import Config
from .json_rows import iter_rows
from datetime import datetime, timezone
from typing import Any
import uuid


PROJECT = Path(__file__).resolve().parent
SUPPORTED_EXTENSIONS = frozenset({".raw", ".mem", ".vmem", ".dmp", ".lime", ".dd"})
COMMAND_TIMEOUT = 300
METACHARACTERS = re.compile(r"[;&|<>`$\\\"'(){}\[\]*?!]")


class EvidenceError(ValueError):
    """An input or evidence integrity problem the caller can act on."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise EvidenceError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def validate_text(value: str, label: str, *, allow_home: bool = False) -> None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise EvidenceError(f"{label} must be a nonempty string of at most 4096 characters.")
    if METACHARACTERS.search(value) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise EvidenceError(f"{label} contains forbidden shell metacharacters or control characters.")
    if "~" in value and not (allow_home and value.startswith("~/") and "~" not in value[2:]):
        raise EvidenceError(f"{label}: only a leading ~/ home-directory abbreviation is allowed.")
    if ".." in Path(value).parts:
        raise EvidenceError(f"{label} contains path traversal (..), which is forbidden.")


def file_fingerprint(path: Path) -> dict[str, Any]:
    """Open only for reading, reject final symlinks, and detect changes while hashing."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"Not a regular file: {path}")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise EvidenceError(f"File changed while computing SHA-256: {path}. Use a stable acquisition copy.")
    return {"path": str(path), "size_bytes": after.st_size, "sha256": digest,
            "mtime_ns": after.st_mtime_ns, "device": after.st_dev, "inode": after.st_ino}


def write_json(path: Path, value: Any, *, exclusive: bool = True) -> None:
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True)
        stream.write("\n")


def excerpt(path: Path, limit: int = 2400) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    text = data[:limit].decode("utf-8", errors="replace")
    return text + ("\n[preview truncated; see complete artifact]" if len(data) > limit else "")


class VolatilityBackend:
    def __init__(self, config: Config):
        self.config = config
        self.cases = config.evidence_root
        self.outputs = config.output_root
        self.project = PROJECT
        self.vol_python = config.vol_python
        self.vol = config.vol_executable
        self.command_timeout = config.command_timeout
        self.supplemental_symbols = config.symbols
        self.symbol_cache = config.cache_path
        self.local_plugins = PROJECT / "plugins"
        self._catalog = None
        self._symbols_prepared = False
        self._symbol_preparation = None
        self._lock = threading.RLock()
        self.shutdown_event = threading.Event()
        self.session_id = uuid.uuid4().hex
        for directory in (self.cases, self.outputs, self.symbol_cache):
            self._check_components(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.cases == self.outputs or self.cases.is_relative_to(self.outputs):
            raise EvidenceError("Output root must not equal or contain the evidence root.")
        if not self.vol.is_file() or not os.access(self.vol, os.X_OK):
            raise EvidenceError(f"Volatility executable unavailable: {self.vol}. Run setup/doctor.")

    @staticmethod
    def _check_components(path: Path) -> None:
        for part in (path, *path.parents):
            if part.is_symlink():
                raise EvidenceError(f"Symlink paths are forbidden: {part}")

    def resolve_input(self, value: str, *, memory_image: bool = True) -> Path:
        validate_text(value, "Image path" if memory_image else "Input file", allow_home=True)
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.cases / candidate
        try:
            relative = candidate.relative_to(self.cases)
        except ValueError as exc:
            raise EvidenceError(f"Input must remain inside {self.cases}.") from exc
        if not relative.parts or candidate.is_relative_to(self.outputs) or relative.parts[0] == "_outputs":
            raise EvidenceError("Select a source file in cases, outside the _outputs artifact directory.")
        if "__MACOSX" in relative.parts or candidate.name.startswith("._"):
            raise EvidenceError("AppleDouble archive metadata is not a source memory image.")
        current = self.cases
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise EvidenceError(f"Symlink inputs are forbidden: {current}")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise EvidenceError(f"File does not exist: {candidate}. Put the acquisition in {self.cases}.") from exc
        if not resolved.is_relative_to(self.cases):
            raise EvidenceError(f"Resolved input escapes {self.cases}.")
        if not resolved.is_file():
            raise EvidenceError(f"Input must be a regular file: {resolved}")
        if memory_image and resolved.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise EvidenceError("Supported memory-image extensions: " + ", ".join(sorted(SUPPORTED_EXTENSIONS)))
        if not os.access(resolved, os.R_OK):
            raise EvidenceError(f"File is not readable: {resolved}. Grant your account read access.")
        return resolved

    def _safe_directory(self, directory: Path) -> Path:
        if not directory.is_relative_to(self.outputs):
            raise EvidenceError("Artifact directory escapes the configured output root.")
        self._check_components(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.resolve() != directory:
            raise EvidenceError("Artifact directory changed its resolved location.")
        return directory

    def case_directory(self, image: Path) -> Path:
        relative = str(image.relative_to(self.cases))
        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", image.stem).strip("-")[:60] or "image"
        identity = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16]
        return self.outputs / f"{slug}-{identity}"

    def catalog(self) -> dict[str, Any]:
        with self._lock:
            if self._catalog is None:
                try:
                    result = subprocess.run(
                        [str(self.vol_python), "-I", str(self.project / "catalog.py"),
                         "--xpnet" if self.config.enable_xpnet else "--official-only"],
                        shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                        timeout=self.config.catalog_timeout, cwd=self.project,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise EvidenceError(f"Plugin discovery timed out after {self.config.catalog_timeout} seconds. Check the existing vol -h.") from exc
                if result.returncode:
                    raise EvidenceError(f"Installed plugin discovery failed: {result.stderr[-2400:]}")
                self._catalog = json.loads(result.stdout)
            return self._catalog

    def list_memory_images(self) -> dict[str, Any]:
        images, skipped = [], []
        # os.walk does not follow directory symlinks. Derived dumps are excluded.
        for folder, directories, filenames in os.walk(self.cases, followlinks=False):
            directories[:] = sorted(d for d in directories if d not in {"_outputs", "__MACOSX"} and not (Path(folder) / d).is_symlink()
                                       and not (Path(folder) / d).is_relative_to(self.outputs))
            for filename in sorted(filenames):
                path = Path(folder) / filename
                if path.suffix.lower() not in SUPPORTED_EXTENSIONS or filename.startswith("._"):
                    continue
                try:
                    image = self.resolve_input(str(path))
                    record = file_fingerprint(image)
                    record["relative_path"] = str(image.relative_to(self.cases))
                    images.append(record)
                except (EvidenceError, OSError) as exc:
                    skipped.append({"path": str(path), "reason": str(exc)})
        return {"cases_directory": str(self.cases), "images": images, "count": len(images), "skipped": skipped}

    def list_plugins(self, query: str = "") -> dict[str, Any]:
        if query:
            validate_text(query, "Plugin filter")
        catalog = self.catalog()
        matched = [(name, value) for name, value in sorted(catalog["plugins"].items()) if query.lower() in name.lower()]
        plugins = [{"name": name, "description": value["description"],
                    "origin": value.get("origin", "installed_volatility"),
                    "plugin_version": value.get("plugin_version")} for name, value in matched]
        for plugin in plugins:
            if plugin["name"] in {"windows.netscan.NetScan", "windows.netstat.NetStat"}:
                plugin["compatibility_note"] = ("Known limitation in tested Volatility 2.28.2: Windows XP unsupported. "
                    "For XP x86 pool-object recovery, use the separately named local xpnet.XpNetScan addon; "
                    "it does not establish active TCP membership or traffic.")
        if len(matched) == 1:
            plugins[0]["options"] = matched[0][1]["options"]
        return {"volatility_version": catalog["version"], "architecture": catalog["architecture"],
                "total": len(catalog["plugins"]), "count": len(plugins), "plugins": plugins,
                "import_failures": catalog.get("import_failures", []),
                "installed_volatility_plugins": sum(p.get("origin", "installed_volatility") == "installed_volatility"
                                                     for p in catalog["plugins"].values()),
                "local_compatibility_plugins": sum(p.get("origin") == "local_compatibility"
                                                   for p in catalog["plugins"].values()),
                "health_scope": "Import/discovery health only; runtime support depends on guest OS, symbols and available memory."}

    def validate_arguments(self, plugin: str, arguments: list[str] | None) -> list[str]:
        validate_text(plugin, "Plugin")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", plugin):
            raise EvidenceError("Use an exact plugin name from list_plugins, for example windows.pslist.PsList.")
        specs = self.catalog()["plugins"].get(plugin)
        if specs is None:
            raise EvidenceError(f"Unknown plugin: {plugin}. Call list_plugins for installed names.")
        if arguments is None:
            arguments = []
        if not isinstance(arguments, list) or len(arguments) > 64 or any(not isinstance(item, str) for item in arguments):
            raise EvidenceError("arguments must be a list of at most 64 strings, e.g. [\"--pid\", \"123\"].")
        options = {option["flag"]: option for option in specs["options"]}
        parser = SafeArgumentParser(prog=plugin, add_help=False, allow_abbrev=False, exit_on_error=False)
        for option in options.values():
            kwargs: dict[str, Any] = {"dest": option["dest"], "required": option["required"]}
            if option["action"] == "store_true":
                kwargs["action"] = "store_true"
            else:
                kwargs["type"] = {"int": lambda value: int(value, 0), "float": float, "str": str}[option["type"]]
                if option["nargs"] is not None:
                    kwargs["nargs"] = option["nargs"]
                if option["choices"] is not None:
                    kwargs["choices"] = option["choices"]
            parser.add_argument(option["flag"], **kwargs)
        normalized, seen = [], set()
        current_option = None
        for token in arguments:
            if token.startswith("--"):
                flag, separator, value = token.partition("=")
                validate_text(flag, "Plugin option")
                if flag not in options:
                    raise EvidenceError(f"Forbidden or unknown option {flag}. Only this plugin's listed options are accepted; global flags are unavailable.")
                if flag in seen:
                    raise EvidenceError(f"Duplicate option: {flag}")
                seen.add(flag)
                current_option = options[flag]
                if separator:
                    value = self._argument_value(value, current_option,
                        registry_key=(plugin == "windows.registry.printkey.PrintKey" and flag == "--key"))
                    token = flag + "=" + value
            else:
                if current_option is None or current_option["action"] == "store_true":
                    raise EvidenceError(f"Unexpected plugin argument: {token}. Use list_plugins to inspect options.")
                token = self._argument_value(token, current_option,
                    registry_key=(plugin == "windows.registry.printkey.PrintKey" and current_option["flag"] == "--key"))
            normalized.append(token)
        try:
            parser.parse_args(normalized)
        except argparse.ArgumentError as exc:
            raise EvidenceError(f"Invalid arguments for {plugin}: {exc}. Inspect list_plugins(query={plugin!r}).") from exc
        return normalized

    def _argument_value(self, value: str, option: dict[str, Any], *, registry_key: bool = False) -> str:
        # A PrintKey key is a captured-hive name, not a host path or shell program.
        # Validate separators as path components, then retain the original bytes
        # in argv. No other option gains a backslash exception.
        validation_value = value.replace("\\", "/") if registry_key else value
        validate_text(validation_value, "Plugin option value", allow_home=option["is_path"])
        if option["is_path"]:
            return str(self.resolve_input(value, memory_image=False))
        # Non-URI values are plugin data, including paths inside the captured OS
        # (for example pagecache --find /etc/passwd), never host input filenames.
        if "://" in value or value == "..":
            raise EvidenceError("URLs and traversal are forbidden. Declared input-file options are confined to cases.")
        return value

    def _symbol_arguments(self) -> list[str]:
        """Use only administrator-configured symbols/cache; keep old typed-XP repair."""
        self._check_components(self.symbol_cache)
        args = ["--cache-path", str(self.symbol_cache)]
        if self.supplemental_symbols is None:
            return args
        self._check_components(self.supplemental_symbols)
        if not self.supplemental_symbols.is_dir():
            raise EvidenceError("Configured symbols directory is missing; fix setup or supply matching symbols.")
        if not self._symbols_prepared:
            prepared = subprocess.run(
                [str(self.vol_python), "-I", str(self.project / "prepare_symbol_cache.py"),
                 str(self.supplemental_symbols), str(self.symbol_cache)],
                shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=self.config.catalog_timeout, cwd=self.project,
            )
            if prepared.returncode:
                raise EvidenceError(f"Symbol cache preparation failed: {prepared.stderr[-2400:]}")
            self._symbol_preparation = json.loads(prepared.stdout)
            self._symbols_prepared = True
        return ["-s", str(self.supplemental_symbols), *args]

    def _plugin_arguments(self) -> list[str]:
        """Only the shipped addon; no client-controlled plugin search path."""
        if not self.config.enable_xpnet:
            return []
        self._check_components(self.local_plugins)
        if any(p.is_symlink() for p in self.local_plugins.rglob("*")):
            raise EvidenceError("Local plugin directory/files must not be symlinks.")
        return ["-p", str(self.local_plugins)]

    def _attempt(self, image: Path, plugin: str, arguments: list[str], run: Path,
                 cancel_event: threading.Event) -> dict[str, Any]:
        directory = self._safe_directory(run / "json")
        files = self._safe_directory(directory / "files")
        stdout, stderr = directory / "stdout.json", directory / "stderr.txt"
        argv = [str(self.vol_python), "-I", str(self.vol), "-q", *self._plugin_arguments(), *self._symbol_arguments(),
                "-f", str(image), "-o", str(files), "-r", "json", plugin, *arguments]
        entry = {"renderer": "json", "argv": argv, "shell": False, "started_at": utc_now(),
                 "timeout_seconds": self.command_timeout, "stdout_path": str(stdout),
                 "stderr_path": str(stderr), "files_directory": str(files)}
        if self._symbol_preparation is not None:
            entry["supplemental_symbols"] = self._symbol_preparation
        write_json(run / "command.started.json", entry)
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = None
            try:
                process = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                    stdout=out, stderr=err, cwd=files, start_new_session=True,
                    env={k: v for k, v in os.environ.items()
                         if k not in {"PYTHONPATH", "PYTHONHOME", "VOLATILITY_PLUGINS"}})
                deadline = time.monotonic() + self.command_timeout
                while process.poll() is None:
                    reason = ("cancelled" if cancel_event.is_set() or self.shutdown_event.is_set()
                              else "timeout" if time.monotonic() >= deadline else None)
                    if reason:
                        self._kill(process)
                        entry.update(status=reason, error=(
                            "Analysis cancelled; partial output retained; no negative finding." if reason == "cancelled"
                            else f"Exceeded {self.command_timeout}s; partial output retained. Use a narrower filter or raise configured timeout."))
                        break
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
                entry["returncode"] = process.wait()
                entry.setdefault("status", "success" if process.returncode == 0 else "error")
            except BaseException as exc:
                if process is not None and process.poll() is None:
                    self._kill(process)
                if not isinstance(exc, Exception):
                    raise
                entry.update(status="error", returncode=None, error=f"Cannot execute Volatility: {exc}")
        entry["completed_at"] = utc_now()
        tail = self._tail(stderr)
        if re.search(r"This version of Windows is not supported:\s*5\.1\b", tail):
            entry["failure_category"] = "unsupported_windows_xp"
        elif "Unsatisfied requirement" in tail or "symbol_table_name" in tail:
            entry["failure_category"] = "missing_symbols_or_layer"
        entry["artifacts"] = [file_fingerprint(stdout), file_fingerprint(stderr)]
        if entry["status"] == "success":
            view = directory / "output.txt"
            try:
                count, preview = 0, []
                with view.open("x", encoding="utf-8") as human:
                    human.write("Human-readable view of the saved JSON, generated without rerunning analysis.\n")
                    for row in iter_rows(stdout):
                        count += 1
                        human.write(f"\nRecord {count}\n" + json.dumps(row, indent=2, ensure_ascii=True) + "\n")
                        if count <= 5 and len(json.dumps(preview)) + len(json.dumps(row)) < 5000:
                            preview.append(row)
                entry.update(json_path=str(stdout), text_path=str(view), row_count=count,
                             json_preview=preview, preview_truncated=count > len(preview))
                entry["artifacts"].append(file_fingerprint(view))
            except (UnicodeError, ValueError) as exc:
                entry.update(status="output_error", error=f"JSON output incomplete or unsupported: {exc}. Raw output retained; analysis was not rerun.")
                if view.exists():
                    entry["artifacts"].append(file_fingerprint(view))
        for folder, dirs, names in os.walk(files, followlinks=False):
            for name in [*dirs, *names]:
                if (Path(folder) / name).is_symlink():
                    entry.update(status="output_error", error="Plugin created a symlink; output was not followed.")
            dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
            for name in sorted(names):
                item = Path(folder) / name
                if item.is_file() and not item.is_symlink():
                    entry["artifacts"].append(file_fingerprint(item))
        return entry

    @staticmethod
    def _kill(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    @staticmethod
    def _tail(path: Path) -> str:
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 8192))
            return stream.read(8192).decode("utf-8", errors="replace")

    def run_plugin(self, image: str, plugin: str, arguments: list[str] | None = None,
                   cancel_event: threading.Event | None = None) -> dict[str, Any]:
        event = cancel_event or threading.Event()
        with self._lock:
            if event.is_set() or self.shutdown_event.is_set():
                raise EvidenceError("Analysis cancelled before execution.")
            source = self.resolve_input(image)
            normalized = self.validate_arguments(plugin, arguments)
            before = file_fingerprint(source)
            case = self.case_directory(source)
            run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + uuid.uuid4().hex[:12]
            run = self._safe_directory(case / "runs" / run_id)
            manifest_path = run / "manifest.json"
            metadata = self.catalog()["plugins"][plugin]
            manifest = {"schema_version": "1.1", "server_session": self.session_id,
                        "run_id": run_id, "image": str(source),
                        "image_relative_path": str(source.relative_to(self.cases)),
                        "image_sha256_before": before["sha256"], "image_before": before,
                        "volatility_version": self.catalog()["version"], "volatility_executable": str(self.vol),
                        "volatility_python": str(self.vol_python), "volatility_python_version": self.catalog().get("python_version", "unknown"),
                        "volatility_architecture": self.catalog().get("architecture", "unknown"),
                        "server_version": __version__, "server_python_version": platform.python_version(),
                        "mcp_sdk_version": version("mcp"),
                        "plugin": plugin, "arguments": normalized, "started_at": utc_now(),
                        "status": "running", "artifact_path": str(run), "commands": [], "integrity_verified": False}
            write_json(manifest_path, manifest)
            try:
                if metadata.get("origin") == "local_compatibility":
                    self._plugin_arguments()
                    plugin_source = Path(metadata["source_file"])
                    if not plugin_source.is_relative_to(self.local_plugins):
                        raise EvidenceError("Addon source escapes fixed plugin directory.")
                    snapshot = self._safe_directory(run / "plugin-source") / plugin_source.name
                    original = file_fingerprint(plugin_source)
                    with snapshot.open("xb") as stream:
                        stream.write(plugin_source.read_bytes())
                    if file_fingerprint(snapshot)["sha256"] != original["sha256"]:
                        raise EvidenceError("Addon source changed while snapshotting.")
                    manifest["plugin_provenance"] = {"origin": "local_compatibility", "version": metadata["plugin_version"],
                                                     "source": original, "snapshot": file_fingerprint(snapshot)}
                entry = self._attempt(source, plugin, normalized, run, event)
                manifest["commands"].append(entry)
                manifest["status"] = entry["status"]
                if "plugin_provenance" in manifest:
                    original = manifest["plugin_provenance"]["source"]
                    current = file_fingerprint(Path(original["path"]))
                    manifest["plugin_provenance"]["unchanged"] = current == original
                    if current != original:
                        raise EvidenceError("Addon source changed during analysis; do not rely on this run.")
            except (Exception, KeyboardInterrupt) as exc:
                manifest.update(status="cancelled" if isinstance(exc, KeyboardInterrupt) else "error", error=str(exc))
            finally:
                try:
                    after = file_fingerprint(self.resolve_input(str(source)))
                    manifest.update(image_after=after, image_sha256_after=after["sha256"], integrity_verified=before == after)
                    if before != after:
                        manifest["status"] = "evidence_changed"
                except (OSError, EvidenceError) as exc:
                    manifest.update(status="evidence_changed", integrity_verified=False, integrity_error=str(exc))
                manifest["completed_at"] = utc_now()
                temporary = run / "manifest.complete.json"
                write_json(temporary, manifest)
                os.replace(temporary, manifest_path)
            commands = manifest["commands"]
            raw = commands[0] if commands else {}
            preview = excerpt(Path(raw.get("text_path", raw["stdout_path"]))) if raw else ""
            error = excerpt(Path(raw["stderr_path"]), 1800) if raw else ""
            error += "\n" + manifest.get("error", "") + raw.get("error", "")
            category = raw.get("failure_category")
            summary = f"{plugin}: {manifest['status']}; saved complete output and execution metadata."
            if manifest["status"] != "success":
                summary += " Incomplete/failed analysis is not a negative finding. Check saved diagnostics and matching symbols."
            if category == "unsupported_windows_xp":
                summary += " Upstream XP network layout unsupported; xpnet.XpNetScan can carve XP x86 candidates, not prove traffic."
            return {"status": manifest["status"], "run_id": run_id, "plugin": plugin, "image": str(source),
                    "image_sha256": before["sha256"], "integrity_verified": manifest["integrity_verified"],
                    "artifact_path": str(run), "manifest_path": str(manifest_path),
                    "case_output_directory": str(case), "summary": summary,
                    "preview": preview, "preview_truncated": len(preview.encode()) >= 2400,
                    "error_preview": error, "failure_category": category,
                    "plugin_origin": metadata.get("origin", "installed_volatility"),
                    "row_count": raw.get("row_count"), "json_preview": raw.get("json_preview"),
                    "json_artifact": raw.get("json_path"), "text_artifact": raw.get("text_path"),
                    "commands": [{k: v for k, v in item.items() if k not in {"artifacts", "json_preview"}}
                                 for item in commands]}

    def get_image_info(self, image: str, os_hint: str = "auto", cancel_event: threading.Event | None = None) -> dict[str, Any]:
        with self._lock:
            return self._get_image_info(image, os_hint, cancel_event)

    def _get_image_info(self, image: str, os_hint: str, cancel_event=None) -> dict[str, Any]:
        if os_hint not in {"auto", "windows", "linux", "mac"}:
            raise EvidenceError("os_hint must be auto, windows, linux, or mac.")
        source = self.resolve_input(image)
        probes = [self.run_plugin(str(source), "banners.Banners", cancel_event=cancel_event)]
        discovered: set[str] = set()
        first = probes[0]
        if first["status"] == "success" and first["integrity_verified"] and first["json_artifact"]:
            for row in iter_rows(Path(first["json_artifact"])):
                banner = row.get("Banner", "")
                if "Linux version " in banner:
                    discovered.add("linux")
                if "Darwin Kernel Version " in banner:
                    discovered.add("mac")
                if re.search(r"\.pdb\|[0-9A-Fa-f]+\|\d+", banner):
                    discovered.add("windows")
        if "windows" in discovered or os_hint == "windows" or (os_hint == "auto" and not discovered):
            probe = self.run_plugin(str(source), "windows.info.Info", cancel_event=cancel_event)
            probes.append(probe)
            if probe["status"] == "success" and probe["integrity_verified"] and probe["row_count"]:
                discovered.add("windows")
        integrity = all(probe["integrity_verified"] and probe["image_sha256"] == first["image_sha256"] for probe in probes)
        if not integrity:
            discovered.clear()
        detected = next(iter(discovered)) if len(discovered) == 1 else "mixed" if discovered else "unknown"
        return {"image": str(source), "image_sha256": first["image_sha256"], "detected_os": detected,
                "integrity_verified": integrity, "probes": probes,
                "summary": ("Evidence changed between discovery probes; do not combine their results. " if not integrity else "") +
                f"OS discovery: {detected}, based on actual Volatility output. "
                "Banners are identification clues, not proof that symbols or every plugin will work. "
                "For Linux/macOS analysis, install matching symbols in the existing Volatility symbol directory. "
                "Unknown means no usable identification was obtained; inspect the saved probe artifacts."}

    def read_output(self, path: str, offset: int = 0, limit: int = 16384) -> dict[str, Any]:
        validate_text(path, "Artifact path", allow_home=True)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 65536:
            raise EvidenceError("offset must be nonnegative and limit must be 1..65536 bytes.")
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.outputs / candidate
        if not candidate.is_relative_to(self.outputs):
            raise EvidenceError("Artifact must be inside configured output root.")
        self._check_components(candidate)
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(self.outputs):
            raise EvidenceError("Artifact escapes output root.")
        fingerprint = file_fingerprint(resolved)
        with resolved.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(limit)
        end = min(offset + len(data), fingerprint["size_bytes"])
        return {"path": str(resolved), "sha256": fingerprint["sha256"], "size_bytes": fingerprint["size_bytes"],
                "offset": offset, "next_offset": end, "truncated": end < fingerprint["size_bytes"],
                "encoding": "utf-8 with replacement; offsets are bytes", "content": data.decode("utf-8", errors="replace")}

    def case_history(self, image: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        source = self.resolve_input(image)
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            raise EvidenceError("History limit must be 1..200; offset must be nonnegative.")
        case = self.case_directory(source)
        paths = []
        if case.exists():
            self._safe_directory(case / "runs")
            paths = sorted((case / "runs").glob("*/manifest.json"), reverse=True)
        entries = []
        for path in paths[offset:offset + limit]:
            self._check_components(path)
            with path.open(encoding="utf-8") as stream:
                record = json.load(stream)
            status = record["status"]
            if status == "running" and record.get("server_session") != self.session_id:
                status = "interrupted_or_external_session"
            entries.append({key: record.get(key) for key in (
                "run_id", "plugin", "arguments", "started_at", "completed_at", "image_sha256_before",
                "image_sha256_after", "integrity_verified", "artifact_path")})
            entries[-1].update(status=status, manifest_path=str(path),
                commands=[{k: v for k, v in item.items() if k in
                           {"argv", "status", "returncode", "stdout_path", "stderr_path", "started_at", "completed_at"}}
                          for item in record.get("commands", [])])
        return {"image": str(source), "case_output_directory": str(case), "total": len(paths),
                "count": len(entries), "offset": offset, "entries": entries,
                "detail": "Read each manifest with read_output for full hashes, metadata and output locations."}
