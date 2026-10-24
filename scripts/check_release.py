"""Read-only release gate: exact source, stable version, tag and existing CI."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ('ci.yml', 'code-quality.yml', 'security.yml')


def api_get(path: str):
    request = Request(
        f'https://api.github.com/repos/{os.environ["GITHUB_REPOSITORY"]}/{path}',
        headers={'Authorization': f'Bearer {os.environ["GH_TOKEN"]}',
                 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28'},
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404 and path.startswith('git/ref/tags/'):
            return None
        raise


def validate_version(version: str, runtime_version: str, revision: str, manifest=None):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Release requires a stable major.minor.patch package version.')
    if version != runtime_version:
        raise ValueError('Package and runtime versions differ.')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Release requires a full source commit SHA.')
    if manifest is not None and (
        manifest.get('core_version') != version
        or manifest.get('source_revision') != revision
    ):
        raise ValueError('Bundle manifest differs from the package version or source commit.')
    return f'v{version}'


def check_tag(tag: str, revision: str, *, require_tag=False):
    ref = api_get(f'git/ref/tags/{tag}')
    if ref is None:
        if require_tag:
            raise ValueError(f'Required release tag {tag} is missing.')
        return  # The publishing step may create this exact tag; never move one.
    obj = ref['object']
    for _ in range(8):
        if obj['type'] == 'commit':
            if obj['sha'] != revision:
                raise ValueError(f'Tag {tag} points to a different source commit.')
            return
        if obj['type'] != 'tag':
            break
        obj = api_get(f'git/tags/{obj["sha"]}')['object']
    raise ValueError(f'Tag {tag} does not resolve to a commit within eight levels.')


def check_ci(revision: str):
    for workflow in WORKFLOWS:
        runs = api_get(
            f'actions/workflows/{workflow}/runs'
            f'?head_sha={revision}&branch=main&event=push&per_page=1'
        )['workflow_runs']
        if not runs:
            raise ValueError(f'{workflow}: no main push run for the source commit.')
        run = runs[0]  # Latest run, including its current rerun attempt.
        if (run.get('head_sha'), run.get('head_branch'), run.get('event'),
            run.get('status'), run.get('conclusion')) != (
                revision, 'main', 'push', 'completed', 'success'):
            raise ValueError(f'{workflow}: latest source-commit run must complete successfully.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--require-tag', action='store_true')
    args = parser.parse_args()
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    runtime = (ROOT / 'src/volatility_mcp/__init__.py').read_text()
    match = re.search(r'^__version__ = "([^"]+)"$', runtime, re.MULTILINE)
    if match is None:
        raise ValueError('Cannot read the runtime version.')
    revision = os.environ['GITHUB_SHA']
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    tag = validate_version(metadata['project']['version'], match[1], revision, manifest)
    check_tag(tag, revision, require_tag=args.require_tag)
    check_ci(revision)
    print(f'Release gate passed: {tag} at {revision}')


if __name__ == '__main__':
    main()
