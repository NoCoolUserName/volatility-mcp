"""Supported local integration surface (API revision 1); see docs/PUBLIC_API.md."""
from importlib.resources import files
from .config import Config, load_config
from .backend import VolatilityBackend, EvidenceError, file_fingerprint, SUPPORTED_EXTENSIONS
from .scoped import CaseBackend
from .server import create_server
from .cli import decode_result
from .relocation import logical_path, resolved_path, check_components, environment
from .files import private_dir, safe_file
from .reporting import check_bundle, check_citation
from .saved_evidence import source_identity
from .coverage import snapshot, set_plan, job_view, request_failures, report_summary
from .timestamps import utc_now, timestamped_id

API_VERSION = 1

def report_spec():
    """Return the authoritative report contract shipped in this core installation."""
    return files('volatility_mcp').joinpath('resources/REPORT_SPEC.md').read_text(encoding='utf-8')
