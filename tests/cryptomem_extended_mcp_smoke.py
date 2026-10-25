"""Installed CryptoMem over real stdio MCP, with generated process buffers.

Usage: CORE_PYTHON tests/cryptomem_extended_mcp_smoke.py ANALYZER_PYTHON
The analyzer must have CryptoMem 0.5.0 installed. No private configuration,
acquisition, recovered value, wallet or external network service is used.
"""
import asyncio
import json
from pathlib import Path
import sys
import tempfile

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.cli import decode_result
from volatility_mcp.config import Config

PHRASE = 'abandon '*11+'about'  # Public BIP-39 vector.
XPRV = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
DATA = PHRASE.encode()+b'\0'+XPRV.encode()+b'\0txid: '+b'ab'*32+b'\0'
ARGS = ['--pid','42','--currency','btc','--detect-mnemonics','--detect-private-keys','--detect-txids','--extract-secrets']


async def check(analyzer):
    runner=Path(__file__).parent/'fixtures/synthetic_cryptomem_vol.py'
    runner.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix='cryptomem-installed-transport-') as temporary:
        root=Path(temporary); evidence=root/'evidence'; evidence.mkdir()
        (evidence/'example.raw').write_bytes(DATA)
        (evidence/'timeout.raw').write_bytes(b'SYNTHETIC TIMEOUT\n'+DATA)
        for mode,xp in (('legacy',False),('auto',True)):
            output=root/mode
            config=Config(evidence,output,Path(analyzer),runner.resolve(),cache_path=root/'cache',enable_xpnet=xp,command_timeout=5)
            path=root/'config.json';path.write_text(json.dumps(config.to_dict()))
            transport=StdioServerParameters(command=sys.executable,args=['-m','volatility_mcp','serve','--config',str(path)])
            async with Client(transport,mode=mode,read_timeout_seconds=120) as client:
                assert len((await client.list_tools()).tools)==10
                catalog=decode_result(await client.call_tool('list_plugins',{'query':'cryptomem'}))
                assert len(catalog['plugins'])==3 and not catalog['import_failures']
                for item in catalog['plugins']:
                    assert item['plugin_version']==[0,5,0] and item['manual_only']
                    run=decode_result(await client.call_tool('run_plugin',{'image':'example.raw','plugin':item['name'],'arguments':ARGS}))
                    assert run['status']=='success',run['error_preview']
                    assert run['row_count']==3 and run['integrity_verified']
                    assert '--offline' in run['commands'][0]['argv']
                    assert PHRASE not in json.dumps(run) and XPRV not in json.dumps(run)
                    assert '[REDACTED SECRET]' in json.dumps(run)
                    files=Path(run['commands'][0]['files_directory'])
                    extracted=files/'cryptomem-secrets-v1.jsonl'
                    assert extracted.stat().st_mode & 0o777==0o600
                    assert PHRASE in extracted.read_text() and XPRV in extracted.read_text()
                    for offset in (0,5,20):
                        result=await client.call_tool('read_output',{'path':str(extracted),'offset':offset,'limit':20})
                        assert result.is_error and 'local-only' in str(result)
                    for artifact in ('json/stdout.json','json/files/cryptomem-findings-v2.jsonl'):
                        result=decode_result(await client.call_tool('read_output',{'path':str(Path(run['artifact_path'])/artifact)}))
                        assert PHRASE not in json.dumps(result) and XPRV not in json.dumps(result)
                    queried=decode_result(await client.call_tool('query_output',{'image':'example.raw','run_id':run['run_id'],'artifact':'json/stdout.json'}))
                    assert PHRASE not in json.dumps(queried) and XPRV not in json.dumps(queried)
                request={'image':'timeout.raw','plugin':'linux.cryptomem.CryptoMem','arguments':ARGS}
                timed=decode_result(await client.call_tool('run_plugin',request))
                assert timed['status']=='timeout' and not timed['reuse_eligible']
                assert PHRASE not in json.dumps(timed) and XPRV not in json.dumps(timed)
                prior=set(output.glob('*/runs/*/json/files/.synthetic-ready'))
                task=asyncio.create_task(client.call_tool('run_plugin',request))
                for _ in range(500):
                    if set(output.glob('*/runs/*/json/files/.synthetic-ready'))-prior:
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError('Installed plugin did not reach synthetic cancellation point')
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                records=[]
                for _ in range(100):
                    records=[json.loads(p.read_text()) for p in output.glob('*/runs/*/manifest.json')]
                    if any(r['status']=='cancelled' for r in records):
                        break
                    await asyncio.sleep(0.05)
                assert any(r['status']=='cancelled' for r in records)
                assert PHRASE not in json.dumps(records) and XPRV not in json.dumps(records)
        print('Installed 0.5.0 detector: all three adapters over real ten-tool MCP; XP on/off; masked success/read/query; private extraction; timeout and cancellation. Synthetic buffers only.')


if __name__=='__main__':
    asyncio.run(check(sys.argv[1]))
