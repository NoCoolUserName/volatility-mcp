"""Compatibility launcher; no Workbench implementation or implicit installation."""
from importlib import import_module

def main(argv=None):
    try:
        module = import_module("volatility_workbench.coins")
    except ModuleNotFoundError as exc:
        if exc.name != "volatility_workbench": raise
        raise SystemExit("Workbench moved to https://github.com/NoCoolUserName/volatility-workbench. Install it, then run volatility-workbench; standalone MCP remains available.") from None
    return module.main() if argv is None else module.main(argv)

if __name__ == "__main__": main()
