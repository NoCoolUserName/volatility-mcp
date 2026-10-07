"""Prove core wheel isolation and real MCP negotiation without Workbench."""
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import venv
ROOT=Path(__file__).resolve().parents[1]
def run(*args,**kw):subprocess.run(args,check=True,**kw)
with tempfile.TemporaryDirectory(prefix='core-package-') as temp:
    temp=Path(temp).resolve();env=temp/'venv';venv.EnvBuilder(with_pip=True).create(env)
    python=str(env/'bin/python')
    source=temp/'source';source.mkdir()
    for name in ('pyproject.toml','README.md','LICENSE','THIRD_PARTY_NOTICES.md'): shutil.copy2(ROOT/name,source/name)
    shutil.copytree(ROOT/'src',source/'src',ignore=shutil.ignore_patterns('__pycache__','*.egg-info','*.pyc'))
    run(sys.executable,'-m','pip','wheel','--no-deps','--wheel-dir',str(temp),str(source))
    run(python,'-m','pip','install','-c',str(ROOT/'requirements.lock.txt'),str(next(temp.glob('volatility_mcp-*.whl'))),cwd=temp)
    run(python,'-m','pip','check',cwd=temp)
    code=r'''
import asyncio,json,sys,importlib.util
from pathlib import Path
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.api import Config,report_spec
assert importlib.util.find_spec('volatility_workbench') is None
assert 'Executive summary' in report_spec()
root=Path.cwd();evidence=root/'evidence';evidence.mkdir()
config=Config(evidence,root/'outputs',Path(sys.executable),Path(sys.executable),cache_path=root/'cache',enable_xpnet=False)
path=root/'config.json';path.write_text(json.dumps(config.to_dict()))
async def check():
    for mode in ('legacy','auto'):
        async with Client(StdioServerParameters(command=sys.executable,args=['-m','volatility_mcp','serve','--config',str(path)]),mode=mode) as client:
            names={t.name for t in (await client.list_tools()).tools}
            assert names=={'list_memory_images','list_plugins','get_image_info','run_plugin','read_output','case_history','inspect_artifact','query_output','get_evidence','get_coverage'}
asyncio.run(check())
print('Core wheel: no Workbench, packaged contract, ten tools in both protocol modes')
'''
    run(python,'-c',code,cwd=temp)
    run(python,'-m','unittest','discover','-s',str(ROOT/'tests'),'-q',cwd=temp)
    run(python,'-m','volatility_mcp','report-check',str(ROOT/'examples/synthetic-case'),cwd=temp)
