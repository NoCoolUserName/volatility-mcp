"""Compatibility entry point for existing local stdio registrations."""
import os
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
local = ROOT / "config.local.json"
if local.is_file():
    os.environ.setdefault("VOLATILITY_MCP_CONFIG", str(local))
relocation = ROOT / 'relocation.local.json'
if relocation.is_file():
    os.environ.setdefault('VOLATILITY_MCP_RELOCATION', str(relocation))
from volatility_mcp.server import main
if __name__ == "__main__":
    main()
