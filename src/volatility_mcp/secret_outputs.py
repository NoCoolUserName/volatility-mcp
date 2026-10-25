"""Local-only CryptoMem extraction policy, shared by all saved-output readers.

No detector or secret parser lives in core. Masking is performed by the pinned
standalone plugin before rendering; complete extraction stays outside MCP.
"""
import json
from pathlib import Path
import re

CRYPTOMEM = frozenset(f"{os_name}.cryptomem.CryptoMem" for os_name in ("windows", "linux", "mac"))
MESSAGE = "CryptoMem secret extraction is local-only; use the masked findings artifact through MCP."


def check_shareable(path, output_root):
    """Fail before reading any value, including byte pages and temporary files.

    A fixed basename also protects copies/renamed Volatility collision outputs.
    Extraction-run files directories include active .vol3 temporary files whose
    names are owned by Volatility rather than the plugin. Never expose those.
    The configured filesystem and run metadata must remain operator trusted.
    """
    path, root = Path(path), Path(output_root)
    if re.fullmatch(r"cryptomem-secrets-v[0-9]+(?:-[0-9]+)?\.jsonl", path.name):
        raise ValueError(MESSAGE)
    for run in path.parents:
        if run == root or not run.is_relative_to(root):
            break
        if run.parent.name != "runs" or not path.is_relative_to(run / "json" / "files"):
            continue
        manifest = run / "manifest.json"
        # A missing/corrupt manifest cannot establish whether raw files are safe.
        try:
            if manifest.is_symlink() or manifest.stat().st_size > 64*1024*1024:
                raise ValueError(MESSAGE)
            record = json.loads(manifest.read_text())
            masked = re.fullmatch(r"cryptomem-(?:findings-v2(?:-[0-9]+)?\.jsonl|scan-summary-v2(?:-[0-9]+)?\.json)", path.name)
            if record.get("plugin") in CRYPTOMEM and "--extract-secrets" in record.get("arguments", []) and not masked:
                raise ValueError(MESSAGE)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(MESSAGE) from exc
        break
