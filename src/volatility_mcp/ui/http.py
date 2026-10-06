"""Loopback HTTP transport with per-launch capability, origin checks and no uploads."""
from __future__ import annotations
import argparse
import asyncio
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
import json
from pathlib import Path
import secrets
import re
import signal
import threading
from urllib.parse import urlsplit, parse_qs
import webbrowser
from .app import Workbench
from .storage import atomic_json, private_dir, safe_file
from ..config import load_config


def runtime_fingerprint():
    """Identify installed server/UI code without reading private case data."""
    root=Path(__file__).resolve().parents[1]
    digest=hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.suffix in ('.py','.js','.css','.html'):
            digest.update(str(path.relative_to(root)).encode())
            digest.update(b'\0'+path.read_bytes()+b'\0')
    return digest.hexdigest()


def check_running_version(session, fingerprint):
    if session.get('runtime_fingerprint') != fingerprint:
        raise ValueError('An older Workbench is still running. Stop it with Ctrl-C in its Terminal window, then launch again. Refreshing the browser does not load updated server code. Completed case artifacts are preserved.')


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, app, port, loop):
        self.app, self.loop = app, loop
        self.token = secrets.token_urlsafe(32)
        super().__init__(('127.0.0.1', port), Handler)
        self.authority = '127.0.0.1:' + str(self.server_port)
        self.origin = 'http://' + self.authority


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # URLs, paths, questions and evidence must not enter access logs.

    def send(self, status, value, content_type='application/json', cookie=False):
        data = json.dumps(value).encode() if content_type=='application/json' else value
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if cookie:self.send_header('Set-Cookie','volatility_ui='+self.server.token+'; HttpOnly; SameSite=Strict; Path=/')
        self.end_headers()
        self.wfile.write(data)

    def guard(self, action=False):
        if self.headers.get('Host') != self.server.authority:
            raise PermissionError('Unrecognized Host')
        origin=self.headers.get('Origin')
        if origin and origin!=self.server.origin:
            raise PermissionError('Unrecognized browser origin')
        if action and origin!=self.server.origin:
            raise PermissionError('Actions require the local application Origin')
        if self.headers.get('Sec-Fetch-Site') in ('cross-site','same-site'):
            raise PermissionError('Cross-site requests are forbidden')

    def authenticated(self):
        cookie=SimpleCookie()
        cookie.load(self.headers.get('Cookie',''))
        actual=cookie.get('volatility_ui')
        if not actual or not secrets.compare_digest(actual.value,self.server.token):
            raise PermissionError('Open the private launch URL printed in Terminal to connect')

    def invoke(self, coro, timeout=200):
        return asyncio.run_coroutine_threadsafe(coro,self.server.loop).result(timeout)

    async def dispatch(self,path,body):
        app=self.server.app
        if path=='/api/cases':return {'cases':app.add(body['paths'],body.get('related',False),body.get('title',''),body.get('source',''))}
        if path=='/api/jobs':return app.enqueue(body['case_id'],body['kind'],body.get('text',''),body.get('request_id'))
        if path=='/api/stop':return await app.stop()
        if path=='/api/pick':return await app.native_pick()
        if path=='/api/approval':
            pending=app.approvals[body['id']]
            if pending['future'].done():raise ValueError('Approval is no longer pending')
            pending['future'].set_result(body['answer']);return {'submitted':True}
        raise ValueError('Unknown action')

    async def get_data(self,path,query):
        app=self.server.app
        one=lambda k,d='':query.get(k,[d])[0]
        if path=='/api/state':return app.snapshot()
        if path=='/api/browse':return app.browse(one('path'))
        if path=='/api/artifacts':return app.artifacts(app.case(one('case')))
        if path=='/api/citations':
            return await asyncio.to_thread(app.citations, app.case(one('case')), one('report'),
                int(one('offset','0')), one('finding') or None, int(one('index','0')))
        if path=='/api/file':return app.read_file(app.case(one('case')),one('path'),int(one('offset','0')))
        raise ValueError('Unknown route')

    def do_GET(self):
        try:
            self.guard()
            url=urlsplit(self.path)
            assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if url.path in assets:
                name,mime=assets[url.path]
                return self.send(200,(Path(__file__).parent/'static'/name).read_bytes(),mime)
            self.authenticated()
            if url.path=='/api/coin':
                query=parse_qs(url.query)
                case=self.server.app.case(query['case'][0])
                path=query['path'][0]
                if not re.fullmatch(r'(?:reports/[A-Za-z0-9_+. -]+/)?assets/coins/[a-f0-9]{64}\.(png|svg)',path):
                    raise ValueError('Invalid coin path')
                asset=safe_file(self.server.app.directory(case),path)
                if asset.stat().st_size>8*1024*1024:raise ValueError('Coin exceeds size limit')
                return self.send(200,asset.read_bytes(),'image/png' if path.endswith('.png') else 'image/svg+xml')
            self.send(200,self.invoke(self.get_data(url.path,parse_qs(url.query))))
        except PermissionError as exc:self.send(403,{'error':str(exc)})
        except (Exception,) as exc:self.send(400,{'error':str(exc)})

    def do_POST(self):
        try:
            self.guard(action=True)
            if self.headers.get('Content-Type')!='application/json':raise ValueError('JSON content type required')
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=2_000_000:raise ValueError('Invalid request size; file uploads are not supported')
            self.connection.settimeout(15)
            body=json.loads(self.rfile.read(size))
            if self.path=='/api/unlock':
                if not secrets.compare_digest(str(body.get('token','')),self.server.token):raise PermissionError('Invalid launch token')
                return self.send(200,{'connected':True},cookie=True)
            self.authenticated()
            self.send(200,self.invoke(self.dispatch(self.path,body)))
        except PermissionError as exc:self.send(403,{'error':str(exc)})
        except (Exception,) as exc:self.send(400,{'error':str(exc)})


async def serve(args):
    config=load_config(args.config)
    root=private_dir(Path(args.state_dir).expanduser().absolute() if args.state_dir else config.output_root/'workbench')
    lock=(root/'app.lock').open('a+')
    fingerprint=runtime_fingerprint()
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        session=json.loads((root/'session.json').read_text())
        check_running_version(session,fingerprint)
        print('Workbench is already running: '+session['url'])
        if not args.no_open:await asyncio.to_thread(webbrowser.open,session['url'])
        return
    app=Workbench(args.config,root,args.project)
    await app.start()
    server=Server(app,args.port,asyncio.get_running_loop())
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url=server.origin+'/#'+server.token
    atomic_json(root/'session.json',{'url':url,'runtime_fingerprint':fingerprint})
    print('Volatility Workbench: '+url,flush=True)
    print('Keep this process running. Ctrl-C stops queued and active work. Selected excerpts may reach your configured AI service.',flush=True)
    stop=asyncio.Event()
    loop=asyncio.get_running_loop()
    for signum in (signal.SIGINT,signal.SIGTERM):loop.add_signal_handler(signum,stop.set)
    try:
        if not args.no_open:await asyncio.to_thread(webbrowser.open,url)
        await stop.wait()
    finally:
        await app.close()
        await asyncio.to_thread(server.shutdown)
        server.server_close()
        lock.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description='Optional local Volatility Workbench')
    parser.add_argument('--config')
    parser.add_argument('--project',default=str(Path.cwd()),help='Repository containing the authoritative report specification')
    parser.add_argument('--state-dir',help='Private case output directory outside the repository (default: output_root/workbench)')
    parser.add_argument('--port',type=int,default=0,help='Loopback port; default chooses an available port')
    parser.add_argument('--no-open',action='store_true')
    args=parser.parse_args(argv)
    try:asyncio.run(serve(args))
    except (ValueError,OSError) as exc:parser.exit(2,str(exc)+'\n')


if __name__=='__main__':main()
