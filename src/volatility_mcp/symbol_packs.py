"""Operator-only provisioning of pinned official symbol data; never reads evidence."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

from .config import Config, ConfigurationError
from .timestamps import utc_now

BASE_URL = 'https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/'
CHECKSUM_SOURCE = 'https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS'
# Sizes and SHA-256 from the official release. Updates require reviewed code changes.
PACKS = {
    'windows.zip': (839727133, '231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e'),
    'symbols_win-10_19041-2025_03.zip': (789065, 'abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e'),
    'mac.zip': (84808562, 'fd12c8338724b175b0c5765af3313328b700ad53de4a00b4aa50e9a8bcef9129'),
    'linux.zip': (2980184, '58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6'),
}
HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
BUNDLED_DIR = Path(__file__).parent / 'resources' / 'symbol-packs'


def bundled_source() -> Path | None:
    """Release wheels contain the packs; incomplete bundles fail closed."""
    marker = BUNDLED_DIR.parent / 'symbol-bundle.json'
    if not BUNDLED_DIR.exists() and not marker.exists():
        return None
    _safe(BUNDLED_DIR)
    _safe(marker)
    if not BUNDLED_DIR.is_dir() or not marker.is_file():
        raise ConfigurationError('Incomplete bundled symbols; reinstall the full release wheel.')
    return BUNDLED_DIR


def _https(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc not in HOSTS:
        raise ConfigurationError('Symbol download redirected outside the official HTTPS asset hosts.')


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ConfigurationError(f'Symbol provisioning paths must not contain symlinks: {component}')


def configured(config: Config) -> Config:
    """Use a persistent local data directory when no supplemental store was set."""
    return config if config.symbols else replace(config, symbols=config.cache_path / 'tables')


def _verify(path: Path, size: int, digest: str) -> None:
    _safe(path)
    if not path.is_file() or path.stat().st_size != size:
        raise ConfigurationError(f'Symbol pack size mismatch: {path.name}; preserve/move local modifications before retrying.')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != digest:
        raise ConfigurationError(f'Symbol pack SHA-256 mismatch: {path.name}; existing files are never overwritten.')
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise ConfigurationError(f'Symbol pack CRC check failed: {path.name}')
    except zipfile.BadZipFile as exc:
        raise ConfigurationError(f'Invalid symbol archive: {path.name}') from exc


def _download(name: str, target: Path, size: int) -> None:
    url = BASE_URL + name
    _https(url)
    opener = urllib.request.build_opener(_Redirect())
    deadline = time.monotonic() + 1800
    received = 0
    with opener.open(url, timeout=60) as response, target.open('wb') as output:
        _https(response.geturl())
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > size or time.monotonic() > deadline:
                raise ConfigurationError(f'Symbol download exceeded its size/time limit: {name}')
            output.write(chunk)


@contextmanager
def _lock(root: Path):
    path = root / '.symbol-packs.lock'
    _safe(path)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ConfigurationError('Symbol installation is already locked. If interrupted, confirm no installer is running before removing .symbol-packs.lock.') from exc
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        path.unlink()


def install(config: Config, packs: str = 'all', source_dir: Path | None = None) -> dict:
    """Install data while idle. Caller persists ``configured(config)`` after success.

    Existing unknown files are refused, not replaced. Completed packs survive a
    later download/index failure and are reverified on retry. No archives execute
    or extract files; Volatility reads JSON symbol tables directly from the ZIPs.
    """
    if packs not in ('windows', 'all'):
        raise ConfigurationError('Symbol packs must be windows or all.')
    bundled = False
    if source_dir is None:
        source_dir = bundled_source()
        bundled = source_dir is not None
    config = configured(config)
    root = config.symbols
    assert root is not None
    for path in (root, config.cache_path):
        _safe(path)
        for protected in (config.evidence_root, config.output_root):
            if path.is_relative_to(protected) or protected.is_relative_to(path):
                raise ConfigurationError('Symbol/cache directories must be separate from evidence and case outputs.')
    if source_dir is not None:
        source_dir = source_dir.expanduser().absolute()
        _safe(source_dir)
        if not source_dir.is_dir():
            raise ConfigurationError('Symbol source directory does not exist.')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    config.cache_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = list(PACKS) if packs == 'all' else list(PACKS)[:2]
    records = []
    with _lock(root):
        for name in names:
            size, digest = PACKS[name]
            target = root / name
            _safe(target)
            existed = target.exists()
            print(f'Verifying/installing official symbol pack: {name}', file=sys.stderr, flush=True)
            if not existed:
                if shutil.disk_usage(root).free < size + 64 * 1024 * 1024:
                    raise ConfigurationError(f'Insufficient space for {name}.')
                fd, temporary_name = tempfile.mkstemp(prefix='.symbol-download-', dir=root)
                os.close(fd)
                temporary = Path(temporary_name)
                try:
                    if source_dir is None:
                        _download(name, temporary, size)
                    else:
                        source = source_dir / name
                        _verify(source, size, digest)
                        shutil.copyfile(source, temporary)
                    _verify(temporary, size, digest)
                    # Atomic publication that refuses concurrent creation of target.
                    os.link(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
            else:
                _verify(target, size, digest)
            records.append({'name': name, 'bytes': size, 'sha256': digest,
                            'source_url': BASE_URL + name, 'status': 'verified' if existed else 'installed'})
        print('Indexing local symbol tables (may take several minutes)…', file=sys.stderr, flush=True)
        result = subprocess.run(
            [str(config.vol_python), '-I', str(Path(__file__).with_name('prepare_symbol_cache.py')),
             str(root), str(config.cache_path), '--index-all'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, timeout=1800,
        )
        if result.returncode:
            raise ConfigurationError(f'Symbol indexing failed; verified packs remain available. Retry symbols-install. {result.stderr[-2000:]}')
        receipt = {'status': 'ready', 'verified_at': utc_now(), 'symbols': str(root), 'checksum_source': CHECKSUM_SOURCE,
                   'acquisition': 'bundled' if bundled else ('local_source' if source_dir is not None else 'official_https'),
                   'packs': records, 'index': json.loads(result.stdout),
                   'scope': 'Representative official packs, not exhaustive OS/build support; no evidence was read or uploaded.'}
        audit = root / 'official-symbol-packs.receipt.txt'
        _safe(audit)
        fd, name = tempfile.mkstemp(prefix='.symbol-receipt-', dir=root)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(json.dumps(receipt, indent=2) + '\n')
            os.replace(temporary, audit)
        finally:
            temporary.unlink(missing_ok=True)
    return receipt
