"""Explicit operator installation of pinned optional analysis addons.

No MCP tool or ordinary catalog request invokes this module. Upstream sources
are downloaded on opt-in, not redistributed inside this package.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import tempfile
import urllib.request

from .addon_compat import adapt, REVISION


PROFILE = Path(__file__).parent / 'resources' / 'addons.json'


def profile():
    data = json.loads(PROFILE.read_text())
    if data['schema_version'] != 1 or data['compatibility_revision'] != REVISION:
        raise ValueError('Unsupported addon profile revision')
    if not re.fullmatch('[a-z0-9-]+', data['profile']) or not all(re.fullmatch(r'[A-Za-z0-9-]+==[0-9.]+', pin) for pin in data['dependencies']):
        raise ValueError('Invalid addon profile/dependency pin')
    targets, names = set(), set()
    for source in data['sources']:
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', source['repository']) or not re.fullmatch('[0-9a-f]{40}', source['commit']):
            raise ValueError('Invalid pinned addon source')
        for item in source['files']:
            kind = item.get('kind', 'plugin')
            suffix = 'json' if kind in {'symbol', 'data'} else 'py'
            allowed = {'linux'} if kind == 'symbol' else {'windows', 'linux'}
            destination = Path(item['target'])
            identity = (kind, item['target'])
            if (kind not in {'plugin', 'symbol', 'data'}
                    or not re.fullmatch(r'(?:[A-Za-z0-9_-]+/)*[a-z_][a-z0-9_]*\.' + suffix, item['path'])
                    or len(destination.parts) != 2 or destination.parts[0] not in allowed
                    or destination.name != Path(item['path']).name or identity in targets):
                raise ValueError('Addon file must have a fixed plugin or symbol destination')
            targets.add(identity)
            if not all(re.fullmatch('[0-9a-f]{64}', item[key]) for key in ('sha256', 'installed_sha256')):
                raise ValueError('Addon hash is missing')
            if 'previous_installed_sha256' in item and not re.fullmatch('[0-9a-f]{64}', item['previous_installed_sha256']):
                raise ValueError('Previous addon hash is invalid')
        for notice in source.get('notices', []):
            if notice['path'] != 'LICENSE' or not re.fullmatch('[0-9a-f]{64}', notice['sha256']):
                raise ValueError('Invalid upstream license notice')
        for name in source['plugins']:
            if not re.fullmatch(r'(?:windows|linux)\.[a-z_][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*', name) or name in names:
                raise ValueError('Invalid or duplicate expected addon command')
            names.add(name)
    if not set(data.get('offline_plugins', [])) <= names:
        raise ValueError('Offline policy references an unknown addon')
    if not set(data.get('manual_only_plugins', [])) <= names:
        raise ValueError('Manual-only policy references an unknown addon')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(source, item):
    url = f"https://raw.githubusercontent.com/{source['repository']}/{source['commit']}/{item['path']}"
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024 or sha(raw) != item['sha256']:
        raise ValueError(f"Upstream addon hash/size mismatch: {item['path']}")
    return raw


def prepare(source, item):
    raw = fetch(source, item)
    installed = raw if item.get('kind') in {'symbol', 'data'} else adapt(
        Path(item['path']).name, raw.decode('utf-8').replace('\r\n', '\n'),
        repository=source.get('repository'), target=item.get('target')).encode()
    if item.get('kind') in {'symbol', 'data'}:
        json.loads(installed)
    if sha(installed) != item['installed_sha256']:
        raise ValueError(f"Adapted addon hash mismatch: {item['path']}")
    return raw, installed


def safe_target(root, relative):
    target = root / relative
    for part in (root, *target.parents, target):
        if part.is_symlink():
            raise ValueError('Symlink addon destinations are forbidden')
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('Addon destination escapes analyzer environment')
    return target


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(data)
        name = temporary.name
    try:
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def install(config):
    """Caller explicitly authorizes downloads and pip installs; images are untouched."""
    from .cli import inspect_python, run
    from .backend import VolatilityBackend
    data = profile()
    info = inspect_python(config.vol_python)
    if info['volatility_version'] != data['volatility_version']:
        raise ValueError('This addon profile is tested only with Volatility ' + data['volatility_version'] + '; existing Volatility was not changed')
    code = ('import json,sys,volatility3,importlib.metadata as m; from pathlib import Path; '
            'print(json.dumps({"prefix":sys.prefix,"plugins":str(Path(volatility3.__file__).parent/"framework/plugins"),'
            '"symbols":str(Path(volatility3.__file__).parent/"framework/symbols"),"packages":{d.metadata["Name"].lower().replace("_","-"):d.version for d in m.distributions()},'
            '"native":[str(Path(d.locate_file(f)).resolve()) for d in [m.distribution("volatility3")] for f in d.files or []]}))')
    result = run([str(config.vol_python), '-I', '-c', code])
    if result.returncode:
        raise ValueError('Cannot inspect analyzer environment: ' + result.stderr[-1000:])
    environment = json.loads(result.stdout)
    prefix, root = Path(environment['prefix']), Path(environment['plugins'])
    if str(prefix) == info['base_prefix'] or not root.resolve().is_relative_to(prefix.resolve()):
        raise ValueError('Addon installation requires an isolated Volatility virtual environment')
    missing = []
    for requirement in data['dependencies']:
        name, version = requirement.split('==')
        current = environment['packages'].get(name.lower())
        if current and current != version:
            raise ValueError(f'{name} {current} differs from tested pin {version}; no automatic replacement')
        if current is None:
            missing.append(requirement)
    prepared, notices = [], []
    for source in data['sources']:
        for item in source['files']:
            destination_root = Path(environment['symbols']) if item.get('kind') == 'symbol' else root
            if not destination_root.resolve().is_relative_to(prefix.resolve()):
                raise ValueError('Symbol destination escapes analyzer environment')
            target = safe_target(destination_root, item['target'])
            if str(target.resolve()) in environment['native']:
                raise ValueError('Refusing to replace an official Volatility distribution file: ' + item['target'])
            known_hashes = {item['installed_sha256'], item.get('previous_installed_sha256')}
            if target.exists() and sha(target.read_bytes()) not in known_hashes:
                raise ValueError('Unrecognized existing addon bytes; preserve and resolve manually: ' + item['target'])
            raw, installed = prepare(source, item)
            prepared.append((source, item, target, raw, installed))
        for item in source.get('notices', []):
            notices.append((source, item, fetch(source, item)))
    # Same persistent lock inode as analysis. Never unlink it or overlap a live run.
    from .relocation import check_components
    check_components(config.output_root)
    config.output_root.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(config.output_root / '.execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise ValueError('Execution lock must be a regular file')
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Analysis is active; install addons only while clients are idle') from exc
        # Recheck under the lock: downloads may have taken time, and another
        # operator could have edited a plugin since preflight.
        for _, item, target, _, _ in prepared:
            destination_root = Path(environment['symbols']) if item.get('kind') == 'symbol' else root
            safe_target(destination_root, item['target'])
            if target.exists() and sha(target.read_bytes()) not in {
                    item['installed_sha256'], item.get('previous_installed_sha256')}:
                raise ValueError('Addon changed during preflight: ' + item['target'])
        baseline = VolatilityBackend(config).list_plugins(refresh=True)
        if baseline['import_failures']:
            raise ValueError('Existing analyzer import failures; resolve before installation')
        baseline_names = {p['name'] for p in baseline['plugins']}
        if missing:
            completed = subprocess.run([str(config.vol_python), '-I', '-m', 'pip', 'install', '--no-deps',
                                        '--index-url', 'https://pypi.org/simple', *missing],
                                       shell=False, timeout=600, stdout=sys.stderr)
            if completed.returncode:
                raise ValueError('Addon dependency installation failed; plugin files were not changed')
        check = run([str(config.vol_python), '-I', '-m', 'pip', 'check'])
        if check.returncode:
            raise ValueError('Analyzer package check failed: ' + check.stdout[-2000:])
        previous = {target: target.read_bytes() if target.exists() else None for _, _, target, _, _ in prepared}
        try:
            for _, _, target, _, installed in prepared:
                write_atomic(target, installed)
            catalog = VolatilityBackend(config).list_plugins(refresh=True)
            names = {p['name'] for p in catalog['plugins']}
            expected = {name for source in data['sources'] for name in source['plugins']}
            missing_names = (expected | baseline_names) - names
            if missing_names or catalog['import_failures']:
                raise ValueError('Addon discovery failed: ' + repr(sorted(missing_names)) + '; ' + repr(catalog['import_failures']))
        except BaseException:
            for target, original in previous.items():
                if original is None:
                    target.unlink(missing_ok=True)
                else:
                    write_atomic(target, original)
            raise
        archive = safe_target(prefix, 'share/volatility-mcp/addons/' + data['profile'])
        for source, item, _, raw, _ in prepared:
            write_atomic(safe_target(archive, 'upstream/' + source['repository'] + '/' + item['path']), raw)
        for source, item, raw in notices:
            write_atomic(safe_target(archive, 'upstream/' + source['repository'] + '/' + item['path']), raw)
        receipt = {**data, 'installed_plugins': sorted(expected), 'preserved_plugins': sorted(baseline_names),
                   'verification': 'imports and requirements only; real image runtime not established',
                   'analyzer_version': info['volatility_version']}
        write_atomic(safe_target(archive, 'receipt.json'), (json.dumps(receipt, indent=2) + '\n').encode())
        return {'status': 'installed', 'profile': data['profile'], 'plugins': sorted(expected),
                'plugin_count': catalog['total'], 'import_failures': catalog['import_failures'],
                'preserved_plugin_count': len(baseline_names),
                'receipt': str(archive / 'receipt.json'), 'dependencies_added': missing,
                'limitations': 'Import/help checks do not validate forensic accuracy. No image was analyzed.'}
    finally:
        os.close(lock_fd)
