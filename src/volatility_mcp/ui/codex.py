"""Replaceable Codex app-server stdio adapter; no credential handling or model API."""
from __future__ import annotations
import asyncio
import json
import os
import time


class CodexError(RuntimeError):
    pass


class CodexClient:
    def __init__(self, event, request, executable='codex'):
        self.event, self.request_handler, self.executable = event, request, executable
        self.pending = {}
        self.counter = 0
        self.proc = None
        self.tasks = set()
        self.stderr_tail = ''

    async def start(self):
        # Reuse the user's supported login/provider. Do not set API keys, provider,
        # model, CODEX_HOME, or billing configuration.
        self.proc = await asyncio.create_subprocess_exec(
            self.executable, 'app-server', '--listen', 'stdio://',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=16 * 1024 * 1024)
        self.reader = asyncio.create_task(self._read())
        self.errors = asyncio.create_task(self._stderr())
        await self.call('initialize', {'clientInfo': {'name': 'volatility_workbench',
            'title': 'Volatility Workbench', 'version': '0.1.0'},
            'capabilities': {'experimentalApi': True}})
        await self.send({'method': 'initialized', 'params': {}})

    async def send(self, message):
        if self.proc is None or self.proc.returncode is not None:
            raise CodexError('Codex app-server stopped. Restart the UI; saved case work is retained.')
        self.proc.stdin.write((json.dumps(message) + '\n').encode())
        await self.proc.stdin.drain()

    async def call(self, method, params=None, timeout=120):
        self.counter += 1
        ident = self.counter
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        try:
            await self.send({'id': ident, 'method': method, 'params': params or {}})
            return await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(ident, None)

    async def _read(self):
        try:
            while line := await self.proc.stdout.readline():
                message = json.loads(line)
                if 'method' in message:
                    if 'id' in message:
                        task = asyncio.create_task(self._request(message))
                        self.tasks.add(task)
                        task.add_done_callback(self.tasks.discard)
                    else:
                        await self.event(message['method'], message.get('params', {}))
                elif message.get('id') in self.pending:
                    future = self.pending[message['id']]
                    if not future.done():
                        if 'error' in message:
                            future.set_exception(CodexError(json.dumps(message['error'])))
                        else:
                            future.set_result(message.get('result', {}))
        except Exception as exc:
            self.stderr_tail += '\nProtocol error: ' + str(exc)
        finally:
            for future in list(self.pending.values()):
                if not future.done():
                    future.set_exception(CodexError('Codex connection closed: ' + self.stderr_tail[-2000:]))
            await self.event('workbench/disconnected', {'error': self.stderr_tail[-2000:]})

    async def _request(self, message):
        try:
            result = await self.request_handler(message)
            await self.send({'id': message['id'], 'result': result})
        except Exception as exc:
            await self.send({'id': message['id'], 'error': {'code': -32000, 'message': str(exc)}})

    async def _stderr(self):
        while data := await self.proc.stderr.read(8192):
            self.stderr_tail = (self.stderr_tail + data.decode(errors='replace'))[-16000:]

    async def close(self):
        if self.proc:
            if self.proc.returncode is None:
                self.proc.stdin.close()
                try:
                    await asyncio.wait_for(self.proc.wait(), 12)
                except asyncio.TimeoutError:
                    self.proc.terminate()
                    try:
                        await asyncio.wait_for(self.proc.wait(), 12)
                    except asyncio.TimeoutError:
                        self.proc.kill()
                        await self.proc.wait()
            for task in [self.reader, self.errors, *self.tasks]:
                task.cancel()
            await asyncio.gather(self.reader, self.errors, *self.tasks, return_exceptions=True)
