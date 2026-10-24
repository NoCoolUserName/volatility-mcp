"""Prove core wheel isolation and real MCP negotiation without Workbench."""
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import venv
import json
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def run(*args,**kw):subprocess.run(args,check=True,**kw)
with tempfile.TemporaryDirectory(prefix='core-package-') as temp:
    temp=Path(temp).resolve();env=temp/'venv';venv.EnvBuilder(with_pip=True).create(env)
    python=str(env/'bin/python')
    source=temp/'source';source.mkdir()
    for name in ('pyproject.toml','README.md','LICENSE','THIRD_PARTY_NOTICES.md','LICENSING.md'): shutil.copy2(ROOT/name,source/name)
    shutil.copytree(ROOT/'licenses',source/'licenses')
    shutil.copytree(ROOT/'src',source/'src',ignore=shutil.ignore_patterns('__pycache__','*.egg-info','*.pyc'))
    # Tiny synthetic bundled data verifies wheel inclusion without live downloads.
    resources=source/'src/volatility_mcp/resources'
    bundled=resources/'symbol-packs';bundled.mkdir()
    for name in ('windows.zip','symbols_win-10_19041-2025_03.zip','mac.zip','linux.zip'):
        with zipfile.ZipFile(bundled/name,'w') as archive: archive.writestr('synthetic.txt','packaging fixture only')
    (resources/'symbol-bundle.json').write_text(json.dumps({'fixture':True}))
    run(sys.executable,'-m','pip','wheel','--no-deps','--wheel-dir',str(temp),str(source))
    run(python,'-m','pip','install','-c',str(ROOT/'requirements.lock.txt'),str(next(temp.glob('volatility_mcp-*.whl'))),cwd=temp)
    run(python,'-m','pip','check',cwd=temp)
    code=r'''
import asyncio,json,sys,importlib.util
from importlib.metadata import distribution
from pathlib import Path
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.api import Config,report_spec
from volatility_mcp.symbol_packs import bundled_source,PACKS
bundled=bundled_source()
assert bundled is not None and {p.name for p in bundled.glob('*.zip')}==set(PACKS)
assert (bundled.parent/'SYMBOL_PACK_NOTICES.md').is_file()
assert importlib.util.find_spec('volatility_workbench') is None
core_dist=distribution('volatility-mcp')
assert core_dist.metadata['License-Expression']=='MIT OR LicenseRef-Volatility-Software-License-1.0'
for name, marker in [('MIT.txt','MIT License'),('LicenseRef-Volatility-Software-License-1.0.txt','Volatility Software License')]:
    assert marker in core_dist.read_text('licenses/licenses/'+name)
assert 'Distributing a build' in core_dist.read_text('licenses/LICENSING.md')
notices=[f for f in core_dist.files if str(f).endswith('/licenses/DEPENDENCY_LICENSES.txt')]
assert len(notices)==1
notice_text=core_dist.locate_file(notices[0]).read_text()
assert all(name in notice_text for name in ('lorelyai/volatility3-bitlocker','HalaAli198/Go-Memory-Forensics','HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis'))
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
