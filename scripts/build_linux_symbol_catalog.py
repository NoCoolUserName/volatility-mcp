#!/usr/bin/env python3
"""Build reviewable catalog metadata from downloaded public upstream inventories.

Inputs: banners_plain.json and releases.json from one pinned upstream revision,
plus `gh api --paginate --slurp repos/Abyss-W4tcher/volatility3-symbols/releases?per_page=100`.
No credentials, kernel images or recovered data belong in these inputs. This is
an explicit maintainer operation, never a runtime refresh or analysis side effect.
"""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re


def build(banners: Path, releases: Path, assets: Path, revision: str, output: Path):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('A full pinned source commit is required.')
    if output.exists():
        raise ValueError('Refusing to overwrite an existing catalog; generate a new file for review.')
    reverse = defaultdict(list)
    for banner, urls in json.loads(banners.read_text()).items():
        for url in urls:
            reverse[url].append(banner)
    metadata = {a['browser_download_url']: a for page in json.loads(assets.read_text())
                for release in page for a in release['assets']}
    entries = []
    for path, url in sorted(json.loads(releases.read_text()).items()):
        if '/amd64/' not in path and '/x86_64/' not in path:
            continue
        asset = metadata[url]
        if not re.fullmatch('sha256:[0-9a-f]{64}', asset['digest']) or len(reverse[url]) != 1:
            raise ValueError(f'Missing unique banner or SHA-256: {path}')
        entries.append({'path': path, 'url': url, 'bytes': asset['size'],
                        'sha256': asset['digest'][7:], 'banner': reverse[url][0]})
    catalog = {'schema_version': 1, 'source': 'https://github.com/Abyss-W4tcher/volatility3-symbols',
               'revision': revision, 'architecture': 'x86_64', 'entries': entries}
    payload = gzip.compress((json.dumps(catalog, sort_keys=True, separators=(',', ':'))+'\n').encode(), mtime=0)
    output.write_bytes(payload)
    print(json.dumps({'tables': len(entries), 'bytes': sum(e['bytes'] for e in entries),
                      'catalog_bytes': len(payload), 'catalog_sha256': hashlib.sha256(payload).hexdigest()}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('banners', 'releases', 'assets', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    build(args.banners, args.releases, args.assets, args.revision, args.output)
