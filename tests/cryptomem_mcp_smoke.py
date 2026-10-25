"""Installed analyzer over real MCP; corrupt synthetic acquisition, never real RAM.

Run with the core Python: python tests/cryptomem_mcp_smoke.py CONFIG.json
The operator config supplies the installed analyzer only. All evidence/outputs
are generated under a new private temporary directory and removed afterwards.
"""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.cli import decode_result
from volatility_mcp.config import load_config


async def check(config_path):
    original = load_config(config_path)
    with tempfile.TemporaryDirectory(prefix='cryptomem-mcp-installed-') as temporary:
        root = Path(temporary)
        evidence = root / 'evidence'; evidence.mkdir()
        image = evidence / 'invalid.raw'
        image.write_bytes(b'SYNTHETIC invalid acquisition, no captured kernel\n' * 100)
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        for xp in (False, True):
            config = replace(original, evidence_root=evidence, output_root=root / f'outputs-{xp}',
                             cache_path=root / 'cache', symbols=None, enable_xpnet=xp)
            path = root / 'config.json'; path.write_text(json.dumps(config.to_dict()))
            transport = StdioServerParameters(command=sys.executable,
                args=['-m','volatility_mcp','serve','--config',str(path)])
            async with Client(transport, mode='legacy', read_timeout_seconds=120) as client:
                assert len((await client.list_tools()).tools) == 10
                catalog = decode_result(await client.call_tool('list_plugins', {'query':'cryptomem'}))
                assert {p['name'] for p in catalog['plugins']} == {
                    'linux.cryptomem.CryptoMem','windows.cryptomem.CryptoMem','mac.cryptomem.CryptoMem'}
                assert not catalog['import_failures']
                for plugin in catalog['plugins']:
                    assert plugin['manual_only']
                    assert plugin['plugin_version'] == [0,5,0]
                    result = decode_result(await client.call_tool('run_plugin', {'image':'invalid.raw',
                        'plugin':plugin['name'],'arguments':['--pid','42']}))
                    assert result['status'] == 'error', result['status']
                    assert result['integrity_verified'] and not result['reuse_eligible']
                    assert '--offline' in result['commands'][0]['argv']
                    assert 'Unsatisfied requirement' in (result['error_preview'] +
                        Path(result['commands'][0]['stdout_path']).read_text())
                    assert hashlib.sha256(image.read_bytes()).hexdigest() == before
        print('Installed CryptoMem: all three commands discovered and invoked via ten-tool MCP; '
              'XP on/off; unsatisfied kernel requirements fail; synthetic input unchanged')


if __name__ == '__main__':
    asyncio.run(check(Path(sys.argv[1])))
