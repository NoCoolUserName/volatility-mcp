"""Private directories and confined saved-artifact paths."""
from pathlib import Path
import stat
from .relocation import logical_path, check_components, resolved_path

def private_dir(path):
    path = logical_path(Path(path))
    check_components(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def safe_file(root, relative):
    root = logical_path(Path(root))
    path = Path(relative)
    if not isinstance(relative, str) or not relative or path.is_absolute() or '..' in path.parts or '\\' in relative:
        raise ValueError('Use a relative case artifact path without traversal')
    result = root / path
    check_components(result)
    if not resolved_path(result).is_relative_to(resolved_path(root)):
        raise ValueError('Artifact path escapes its case or contains a symlink')
    if result.exists() and not stat.S_ISREG(result.stat().st_mode):
        raise ValueError('Artifact must be a regular file')
    return result
