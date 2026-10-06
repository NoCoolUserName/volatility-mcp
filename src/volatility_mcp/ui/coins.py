"""Optional, local-only decorative identity assets. Never reads memory images."""
from __future__ import annotations
import argparse
import hashlib
from html import escape
import json
from pathlib import Path
import re
import shutil
import tempfile


def render_coin(label, digest):
    """Original vector companion to the silver/graphite/emerald report coins."""
    label=escape(label[:32].upper())
    traces=[]
    for i in range(12):
        angle=i*30
        reach=110+int(digest[i],16)*3
        traces.append(f'<g transform="rotate({angle} 256 256)"><path d="M238 200 V{256-reach} L226 {244-reach}"/><circle cx="226" cy="{244-reach}" r="5" fill="#126444"/></g>')
    monogram=escape(digest[:4].upper())
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512" role="img">
<title>{label} — decorative memory image identity</title>
<defs><linearGradient id="metal" x2="1" y2="1"><stop stop-color="#faf1d8"/><stop offset=".25" stop-color="#aaa79c"/><stop offset=".5" stop-color="#e5dfcd"/><stop offset=".75" stop-color="#64645e"/><stop offset="1" stop-color="#d8d3c3"/></linearGradient>
<radialGradient id="face"><stop stop-color="#353c38"/><stop offset="1" stop-color="#121715"/></radialGradient>
<filter id="relief"><feDropShadow dx="1" dy="2" stdDeviation="1" flood-opacity=".85"/></filter>
<path id="top" d="M64 256 A192 192 0 0 1 448 256"/><path id="bottom" d="M43 256 A213 213 0 0 0 469 256"/></defs>
<circle cx="256" cy="259" r="249" fill="#101310"/><circle cx="256" cy="256" r="246" fill="url(#metal)"/>
<circle cx="256" cy="256" r="240" fill="none" stroke="#383c36" stroke-width="5" stroke-dasharray="2 4"/>
<circle cx="256" cy="256" r="230" fill="url(#face)" stroke="url(#metal)" stroke-width="3"/>
<circle cx="256" cy="256" r="176" fill="url(#face)" stroke="url(#metal)" stroke-width="5"/>
<circle cx="256" cy="256" r="166" fill="none" stroke="#42694f" stroke-width="2"/>
<g fill="none" stroke="url(#metal)" stroke-width="5" filter="url(#relief)">{''.join(traces)}</g>
<rect x="191" y="191" width="130" height="130" rx="14" fill="#115334" stroke="url(#metal)" stroke-width="8" filter="url(#relief)"/>
<rect x="208" y="208" width="96" height="96" rx="9" fill="url(#face)" stroke="#94a68b" stroke-width="2"/>
<text x="256" y="270" text-anchor="middle" fill="url(#metal)" font-family="Georgia,serif" font-size="32" font-weight="bold">{monogram}</text>
<g fill="url(#metal)" font-family="Georgia,serif" font-weight="bold" text-anchor="middle" filter="url(#relief)">
<text font-size="{24 if len(label)>20 else 31}" letter-spacing="2"><textPath href="#top" startOffset="50%">{label}</textPath></text>
<text font-size="26" letter-spacing="3"><textPath href="#bottom" startOffset="50%">MEMORY FORENSICS</textPath></text></g></svg>'''.encode()


def identity(image):
    digest=image.get('sha256','')
    if not re.fullmatch('[a-f0-9]{64}',digest):
        raise ValueError('A saved SHA-256 is required; artwork never hashes evidence')
    return digest


def ensure_coin(case_dir, image):
    from .storage import private_dir, safe_file
    digest=identity(image)
    case_dir=private_dir(Path(case_dir))
    library=private_dir(case_dir.parent/'coin-library')
    record=library/digest
    if not record.exists():
        label=image.get('display_name') or Path(image['path']).name
        install(library,digest,render_coin(label,digest),'svg',label,'Local deterministic SVG renderer v1; decorative, not forensic evidence')
    meta_path=safe_file(library,digest+'/coin.json')
    meta=json.loads(meta_path.read_text())
    ext=meta['extension']
    if ext not in ('svg','png'):raise ValueError('Unsupported coin format')
    source=safe_file(library,digest+'/coin.'+ext)
    if source.stat().st_size>8*1024*1024:raise ValueError('Coin exceeds 8 MiB')
    data=source.read_bytes()
    if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=meta['asset_sha256']:
        raise ValueError('Coin asset integrity mismatch')
    relative=f'assets/coins/{digest}.{ext}'
    private_dir(case_dir/'assets/coins')
    target=safe_file(case_dir,relative)
    if not target.exists():
        with target.open('xb') as f:f.write(data)
    if target.read_bytes()!=data:raise ValueError('Existing coin differs; refusing overwrite')
    return {**meta,'path':relative,'image_id':image['id'],'image_sha256':digest}


def install(library,digest,data,ext,label,provenance):
    from .storage import private_dir
    if not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid SHA-256')
    library=private_dir(library)
    destination=library/digest
    if destination.exists():
        raise ValueError('Coin already exists; stable identities are never replaced')
    temp=Path(tempfile.mkdtemp(prefix='.coin-',dir=library))
    try:
        (temp/('coin.'+ext)).write_bytes(data)
        (temp/'coin.json').write_text(json.dumps({'label':label,'extension':ext,
            'asset_sha256':hashlib.sha256(data).hexdigest(),'provenance':provenance,
            'decorative':True},indent=2))
        temp.rename(destination)
    finally:
        if temp.exists():shutil.rmtree(temp)


def populate(case_dir, images):
    result=[]
    for image in images:
        if not image.get('sha256'):continue
        try:result.append(ensure_coin(case_dir,image))
        except Exception as exc:
            # Optional presentation must not break analysis or bundle sealing.
            result.append({'image_id':image['id'],'error':str(exc),'decorative':True})
    return result


def main():
    p=argparse.ArgumentParser(description='Populate decorative coins from saved metadata only; no analysis or image hashing')
    p.add_argument('--state-dir',required=True)
    p.add_argument('--sha256');p.add_argument('--png');p.add_argument('--label')
    p.add_argument('--provenance',default='User-selected existing decorative PNG')
    args=p.parse_args();root=Path(args.state_dir).expanduser().resolve()
    if args.png:
        if not args.sha256 or not args.label:p.error('--png requires --sha256 and --label')
        path=Path(args.png)
        if path.stat().st_size>8*1024*1024:raise ValueError('PNG exceeds 8 MiB')
        data=path.read_bytes()
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('Expected PNG')
        install(root/'coin-library',args.sha256,data,'png',args.label,args.provenance)
    else:
        state=json.loads((root/'state.json').read_text())
        for case in state['cases']:
            if not re.fullmatch('[a-f0-9]{32}',case['id']):raise ValueError('Invalid case ID')
            for coin in populate(root/case['id'],case['images']):
                print(json.dumps({'image_id':coin['image_id'],'path':coin.get('path'),'error':coin.get('error')}))


if __name__=='__main__':main()
