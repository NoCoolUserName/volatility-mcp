"""Explicit, resumable provisioning of a pinned community Linux x86-64 catalog.

This module never reads evidence and is never called by analysis tools. Tables
remain in the configured symbol store, where normal offline Volatility indexing
makes them available to every Linux plugin.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from .config import Config, ConfigurationError
from .symbol_packs import _Redirect, _https, _lock, _safe, configured
from .timestamps import utc_now

CATALOG = Path(__file__).parent / 'resources' / 'linux-symbols.json.gz'
CATALOG_SHA256 = '9a09709cd73de9f821ec4d0583a7ed94378e1d575c6ba5e7ea2e4a074029e478'
SOURCE = 'https://github.com/Abyss-W4tcher/volatility3-symbols'
MAX_EXPANDED_BYTES = 256 * 1024 * 1024


def catalog() -> dict:
    payload = CATALOG.read_bytes()
    if hashlib.sha256(payload).hexdigest() != CATALOG_SHA256:
        raise ConfigurationError('Linux symbol catalog checksum mismatch; reinstall the package.')
    result = json.loads(gzip.decompress(payload))
    seen = set()
    for entry in result['entries']:
        path = PurePosixPath(entry['path'])
        if (path.is_absolute() or '..' in path.parts or '\\' in entry['path']
                or path.as_posix() != entry['path'] or entry['path'] in seen
                or not entry['path'].endswith('.json.xz')
                or not {'amd64', 'x86_64'}.intersection(path.parts)
                or not entry['url'].startswith(SOURCE + '/releases/download/')
                or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                or not 0 < entry['bytes'] <= 64 * 1024 * 1024
                or not entry['banner'].startswith('Linux version ')):
            raise ConfigurationError('Invalid Linux symbol catalog entry.')
        seen.add(entry['path'])
    return result


def select(banner: str | None = None) -> tuple[dict, list[dict]]:
    data = catalog()
    # The catalog omits the C terminator and final newline only. Never normalize
    # interior whitespace, compiler/build text or substitute a nearby kernel.
    entries = data['entries'] if banner is None else [
        e for e in data['entries'] if e['banner'] == banner.rstrip('\x00\r\n')]
    if not entries:
        raise ConfigurationError('No exact Linux kernel banner match in the pinned x86-64 catalog; obtain matching symbols from the kernel build.')
    return data, entries


def describe(banner: str | None = None) -> dict:
    data, entries = select(banner)
    return {'source': data['source'], 'revision': data['revision'],
            'architecture': data['architecture'], 'tables': len(entries),
            'download_bytes': sum(e['bytes'] for e in entries),
            'entries': entries if banner is not None else [],
            'scope': 'Catalog only; exact captured-kernel symbols required. Other CryptoMem architectures remain unsupported until tested.'}


def _verify(path: Path, entry: dict, *, contents: bool = True) -> None:
    _safe(path)
    if not path.is_file() or path.stat().st_size != entry['bytes']:
        raise ConfigurationError(f"Linux symbol size mismatch: {entry['path']}")
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != entry['sha256']:
        raise ConfigurationError(f"Linux symbol SHA-256 mismatch: {entry['path']}; existing files are never overwritten.")
    if not contents:
        return
    try:
        with lzma.open(path, 'rb') as stream:
            payload = stream.read(MAX_EXPANDED_BYTES + 1)
        if len(payload) > MAX_EXPANDED_BYTES:
            raise ValueError('expanded size limit exceeded')
        isf = json.loads(payload)
        pointer = isf['base_types']['pointer']
        banner = base64.b64decode(isf['symbols']['linux_banner']['constant_data'], validate=True).decode('utf-8')
        if (pointer['size'] != 8 or pointer.get('endian') != 'little'
                or 'linux' not in isf['metadata'] or not isf['user_types']
                or banner.rstrip('\x00\r\n') != entry['banner']):
            raise ValueError('architecture, types, or full kernel banner mismatch')
    except (ValueError, KeyError, TypeError, lzma.LZMAError, EOFError) as exc:
        raise ConfigurationError(f"Invalid Linux ISF {entry['path']}: {exc}") from exc


def _download(entry: dict, target: Path, stop: threading.Event) -> None:
    _https(entry['url'])
    opener = urllib.request.build_opener(_Redirect())
    deadline = time.monotonic() + 1800
    received = 0
    with opener.open(entry['url'], timeout=60) as response, target.open('wb') as output:
        _https(response.geturl())
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if stop.is_set():
                raise ConfigurationError('Linux symbol installation interrupted; verified tables can be reused on retry.')
            if received > entry['bytes'] or time.monotonic() > deadline:
                raise ConfigurationError('Linux symbol download exceeded size/time limit.')
            output.write(chunk)


def install(config: Config, *, banner: str | None = None, source_dir: Path | None = None,
            workers: int = 4) -> dict:
    """Install all catalog entries or exact banner matches, then index offline.

    A failed/interrupted run keeps completed verified tables, removes temporary
    files, and never reports ready. Retrying rehashes existing files. The lock is
    shared with official-pack provisioning. Run only while analysis is idle.
    """
    if not 1 <= workers <= 8:
        raise ConfigurationError('Linux download workers must be between 1 and 8.')
    data, entries = select(banner)
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
            raise ConfigurationError('Linux symbol source directory does not exist.')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    config.cache_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = root / 'linux' / 'community'
    _safe(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    stop = threading.Event()

    def provision(entry):
        if stop.is_set():
            raise ConfigurationError('Linux symbol installation stopped.')
        target = destination / entry['path']
        _safe(target)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        existed = target.exists()
        if existed:
            _verify(target, entry)
        else:
            fd, name = tempfile.mkstemp(prefix='.linux-download-', dir=target.parent)
            os.close(fd)
            temporary = Path(name)
            try:
                if source_dir is None:
                    _download(entry, temporary, stop)
                else:
                    source = source_dir / entry['path']
                    _verify(source, entry, contents=False)
                    shutil.copyfile(source, temporary)
                _verify(temporary, entry)
                os.link(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        return {'path': entry['path'], 'sha256': entry['sha256'], 'bytes': entry['bytes'],
                'status': 'verified' if existed else 'installed'}

    with _lock(root):
        remaining = sum(e['bytes'] for e in entries if not (destination/e['path']).exists())
        if shutil.disk_usage(root).free < remaining + 256 * 1024 * 1024:
            raise ConfigurationError(f'Insufficient disk space for Linux symbols ({remaining} bytes remaining).')
        records = []
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            for record in pool.map(provision, entries):
                records.append(record)
                if len(records) == 1 or len(records) % 100 == 0 or len(records) == len(entries):
                    print(f'Linux symbols verified: {len(records)}/{len(entries)}', file=sys.stderr, flush=True)
        except BaseException:
            stop.set()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        print('Indexing local symbols offline; a full collection may take hours…', file=sys.stderr, flush=True)
        result = subprocess.run(
            [str(config.vol_python), '-I', str(Path(__file__).with_name('prepare_symbol_cache.py')),
             str(root), str(config.cache_path), '--index-all', '--linux-catalog', str(CATALOG),
             *(['--linux-banner', banner] if banner is not None else [])],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, shell=False, timeout=21600)
        if result.returncode:
            raise ConfigurationError(f'Linux symbol indexing failed; verified tables remain. Retry symbols-install. {result.stderr[-2000:]}')
        receipt = {'status': 'ready', 'verified_at': utc_now(), 'source': data['source'],
                   'revision': data['revision'], 'catalog_sha256': CATALOG_SHA256,
                   'symbols': str(root), 'tables': records, 'index': json.loads(result.stdout),
                   'scope': 'Linux x86-64 catalog snapshot, not universal kernel coverage or real-memory validation.'}
        audit = root / 'linux-community-symbols.receipt.json'
        _safe(audit)
        fd, name = tempfile.mkstemp(prefix='.linux-receipt-', dir=root)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(receipt, stream, indent=2)
                stream.write('\n')
            os.replace(temporary, audit)
        finally:
            temporary.unlink(missing_ok=True)
    return receipt
