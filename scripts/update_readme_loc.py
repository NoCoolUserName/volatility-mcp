"""Keep the README's nonblank source/test line count current before each push."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXTENSIONS = {'.py', '.js', '.cjs', '.css', '.html', '.sh'}
LINE = re.compile(r'^\*[\d,]+ lines of code\*$', re.MULTILINE)


def count_lines():
    listed = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
    total = 0
    for raw in set(part for part in listed.split(b'\0') if part):
        source = ROOT / raw.decode('utf-8')
        if source.suffix not in EXTENSIONS or source.is_symlink() or not source.is_file():
            continue
        with source.open(encoding='utf-8', errors='replace') as stream:
            total += sum(bool(line.strip()) for line in stream)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Fail if README line count is stale')
    args = parser.parse_args()
    readme = ROOT / 'README.md'
    original = readme.read_text()
    label = f'*{count_lines():,} lines of code*'
    if LINE.search(original):
        updated = LINE.sub(label, original, count=1)
    else:
        updated = original.replace('# volatility-mcp\n\n', '# volatility-mcp\n\n' + label + '\n\n', 1)
        if updated == original:
            raise SystemExit('README title was not found')
    if args.check:
        if updated != original:
            raise SystemExit(f'README line count is stale; run python scripts/update_readme_loc.py (expected {label})')
    elif updated != original:
        readme.write_text(updated)
    print(label)


if __name__ == '__main__':
    main()
