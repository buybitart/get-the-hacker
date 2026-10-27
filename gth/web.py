"""Local, read-only mobile view."""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit, parse_qs
from .presentation import public_state, network_view, walk_view, GLOSSARY
from .assessment import assess


def start_server(snapshot, port=8765, evidence_directory=None, network_provider=None):
    root = Path(__file__).resolve().parent.parent/'web'
    session = Path(evidence_directory).resolve() if evidence_directory is not None else None
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            if self.headers.get('Host') not in allowed:
                self.send_error(403, 'Use the local app address.'); return
            name = urlsplit(self.path).path
            proof_page = False
            if name in ('/api/state','/api/networks','/api/glossary'):
                try:
                    if name=='/api/glossary':record=GLOSSARY
                    elif name=='/api/state':record=public_state(snapshot())
                    else:
                        query=parse_qs(urlsplit(self.path).query,keep_blank_values=True,max_num_fields=8)
                        if any(k not in ('offset','limit','search','trust','signs') or len(v)!=1 for k,v in query.items()):raise ValueError('Network query is not valid.')
                        one=lambda k,default:query.get(k,[default])[0]
                        offset=int(one('offset','0'));limit=int(one('limit','100'));search=one('search','');trust=one('trust','all');sign=one('signs','0')
                        if offset<0 or not 1<=limit<=100 or len(search)>128 or trust not in ('all','trusted','unknown') or sign not in ('0','1'):raise ValueError('Network query is not valid.')
                        source=dict(snapshot());summary=assess(source)
                        if network_provider is not None:
                            record=network_provider(offset=offset,limit=limit,search=search,trust=trust,signs=sign=='1')
                        else:
                            rows=[network_view(n,source,summary) for n in source.get('networks',[]) if isinstance(n,dict)]
                            rows=[n for n in rows if search.casefold() in (n['display_name']+' '+str(n.get('bssid'))).casefold() and (trust=='all' or (n['trust']=='TRUSTED')==(trust=='trusted')) and (sign=='0' or n['attack_signs']>0)]
                            rows.sort(key=lambda n:(-(n.get('last_seen') or 0),str(n.get('bssid') or '')))
                            record={'session_id':walk_view(source,summary)['session_id'],'total':summary['networks_observed'],'filtered':len(rows),'offset':offset,'limit':limit,'networks':rows[offset:offset+limit]}
                        record['networks']=[network_view(n,source,summary) for n in record['networks']]
                    body=json.dumps(record,ensure_ascii=True,allow_nan=False).encode()
                except (ValueError,TypeError,OverflowError):
                    self.send_error(400,'Data or query is not valid.'); return
                if len(body)>2*1024*1024:
                    self.send_error(413,'Live data is too large. Use report.html.'); return
                content_type='application/json; charset=utf-8'
            elif re.fullmatch(r'/proofs/GTH-[0-9]+\.(json|html)', name) and session is not None:
                proof_dir = session/'proofs'
                file = proof_dir/name.rsplit('/', 1)[1]
                try:
                    if (proof_dir.is_symlink() or file.is_symlink()
                            or proof_dir.resolve().parent != session
                            or file.resolve().parent != proof_dir.resolve()
                            or not file.is_file()):
                        raise OSError('Proof path is not a local file.')
                    if file.stat().st_size>8*1024*1024:
                        self.send_error(413,'Proof is too large. Open the local file.'); return
                    body = file.read_bytes()
                except OSError:
                    self.send_error(404, 'Proof not found.'); return
                proof_page = True
                content_type = ('text/html' if file.suffix == '.html' else 'application/json') + '; charset=utf-8'
            else:
                files = {'/':('index.html','text/html; charset=utf-8'), '/app.js':('app.js','text/javascript; charset=utf-8'), '/walk.js':('walk.js','text/javascript; charset=utf-8'), '/style.css':('style.css','text/css; charset=utf-8'), '/manifest.webmanifest':('manifest.webmanifest','application/manifest+json'), '/icon.svg':('icon.svg','image/svg+xml'), '/sw.js':('sw.js','text/javascript; charset=utf-8'), '/viz.js':('viz.js','text/javascript; charset=utf-8')}
                if name not in files:
                    self.send_error(404, 'File not found.'); return
                file, content_type = files[name]
                body = (root/file).read_bytes()
            self.send_response(200)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            policy = ("default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                      if proof_page else "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header('Content-Security-Policy', policy)
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
