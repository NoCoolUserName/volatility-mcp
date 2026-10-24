"""Build the full release wheel with verified symbols, never private local state."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from volatility_mcp import __version__  # noqa: E402
from volatility_mcp.symbol_packs import BASE_URL, PACKS, _download, _verify  # noqa: E402


def build(output: Path, source: Path | None = None) -> Path:
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if status.strip():
        raise ValueError('Build from a clean committed checkout so provenance names exact source.')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    output = output.expanduser().absolute()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f'volatility_mcp-{__version__}-py3-none-any.whl'
    if destination.exists():
        raise ValueError(f'Refusing to replace an existing release wheel: {destination}')
    with tempfile.TemporaryDirectory(prefix='volatility-symbol-bundle-') as temporary:
        stage = Path(temporary).resolve()/'source'
        stage.mkdir()
        # Only tracked source, never this checkout's evidence, config or caches.
        for name in filter(None, files):
            original = ROOT/name
            if original.is_symlink() or not original.is_file():
                raise ValueError(f'Unexpected tracked build input: {name}')
            target = stage/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        resources = stage/'src/volatility_mcp/resources'
        packs = resources/'symbol-packs'
        packs.mkdir()
        manifest = {'schema_version': 1, 'core_version': __version__, 'source_revision': revision,
                    'source_url': f'https://github.com/NoCoolUserName/volatility-mcp/tree/{revision}',
                    'license': 'LicenseRef-Volatility-Software-License-1.0', 'packs': []}
        for name, (size, digest) in PACKS.items():
            target = packs/name
            print(f'Bundling {name}', flush=True)
            if source is None:
                _download(name, target, size)
            else:
                original = source/name
                _verify(original, size, digest)
                shutil.copyfile(original, target)
            _verify(target, size, digest)
            manifest['packs'].append({'name': name, 'bytes': size, 'sha256': digest, 'url': BASE_URL+name})
        (resources/'symbol-bundle.json').write_text(json.dumps(manifest, indent=2)+'\n')
        built = Path(temporary)/'wheel'
        subprocess.run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--wheel-dir', str(built), str(stage)], check=True)
        wheel = next(built.glob('*.whl'))
        with zipfile.ZipFile(wheel) as archive:
            for name, (size, digest) in PACKS.items():
                member = f'volatility_mcp/resources/symbol-packs/{name}'
                assert archive.getinfo(member).file_size == size
                with archive.open(member) as stream:
                    assert hashlib.file_digest(stream, 'sha256').hexdigest() == digest
            assert archive.read('volatility_mcp/resources/SYMBOL_PACK_NOTICES.md')
            assert json.loads(archive.read('volatility_mcp/resources/symbol-bundle.json')) == manifest
        shutil.copyfile(wheel, destination)
    with destination.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    (output/'SHA256SUMS').write_text(f'{digest}  {destination.name}\n')
    (output/'symbol-bundle.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'wheel': str(destination), 'bytes': destination.stat().st_size,
                      'sha256': digest, 'source_revision': revision}, indent=2))
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--symbol-source', type=Path, help='Already downloaded official ZIPs; no symbol downloads at build time')
    args = parser.parse_args()
    build(args.output_dir, args.symbol_source)
