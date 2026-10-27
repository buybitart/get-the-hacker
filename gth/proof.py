"""Save a replay proof for an observed rule. This does not prove identity."""
import copy
import hashlib
from html import escape
import json
import re
from pathlib import Path, PurePosixPath
from . import __version__
from .engine import Engine
from .reports import atomic_write


def event_line(event):
    return (json.dumps(event, ensure_ascii=True, allow_nan=False)+'\n').encode('utf-8')


def proof_documents(alert, frames, config, session_name):
    """Return complete file bytes before a storage write is made."""
    if not re.fullmatch(r'GTH-[0-9]{6,12}', str(alert.get('id',''))):
        raise ValueError('Proof ID is not valid.')
    replay_config=copy.deepcopy(config)
    replay_config.setdefault('detection',{})['cooldown']=0.0
    engine=Engine(replay_config)
    matches=[]
    references=bool(frames)
    for row in frames:
        event, ref=row['event'], row.get('reference')
        references = references and isinstance(ref,dict) and ref.get('file')=='events.jsonl' and type(ref.get('line')) is int and ref['line']>0 and ref.get('sha256')==hashlib.sha256(event_line(event)).hexdigest()
        matches.extend(engine.process(event))
    replay=any(all(candidate.get(key)==alert.get(key) for key in
        ('rule_id','timestamp','source','bssid','evidence')) for candidate in matches)
    verified=bool(replay and references)
    record=dict(schema_version=1, app='Get the hacker', version=__version__,
        session=session_name, claim='Observed rule evidence. Person identity is unknown.',
        verification=dict(rule_replay='PASS' if replay else 'FAIL',
                          event_hashes='PASS' if references else 'FAIL',
                          scope='Replay the saved events with the saved rule. Hashes detect file changes. They do not prove radio origin.'),
        rule_config=config, replay_config=replay_config,
        alert={k:v for k,v in alert.items() if k not in ('proof','_proof_frames')},
        supporting_events=frames,
        limits=['The same rule code runs the replay. This is not a separate detector.',
                'No raw PCAP is stored by live mode. Frame hashes do not replace raw frames.',
                'Missing frames remain missing. A MAC address can be spoofed.',
                'A rule match does not prove hostile intent or person identity.'])
    raw=json.dumps(record,indent=2,ensure_ascii=True,allow_nan=False)+'\n'
    rows=''.join('<tr><th>'+escape(str(k))+'</th><td>'+escape(str(v))+'</td></tr>' for k,v in
        [('Event',alert['id']),('Method',alert.get('attack_method')),('Source',alert.get('source')),
         ('BSSID',alert.get('bssid')),('Channel',alert.get('channel')),('RSSI',alert.get('rssi')),
         ('Time',alert.get('timestamp')),('Frames',len(frames)),('Rule replay',record['verification']['rule_replay']),
         ('Event hashes',record['verification']['event_hashes'])])
    page='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GTH Evidence proof</title><style>body{font:16px system-ui;background:#090909;color:#fff;max-width:980px;margin:auto;padding:20px}h1{color:#ff6262}table{border-collapse:collapse;width:100%}td,th{border:1px solid #555;text-align:left;padding:8px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#ff9292}</style><h1>Evidence proof</h1><p>'+escape(record['claim'])+'</p><table>'+rows+'</table><p>'+escape(record['verification']['scope'])+'</p><p><a href="'+alert['id']+'.json">Open JSON</a></p><h2>Full evidence</h2><pre>'+escape(raw)+'</pre></html>'
    return {'json':raw.encode('utf-8'),'html':page.encode('utf-8')}, verified


def save_proof(directory, alert, frames, config, max_bytes):
    documents, verified=proof_documents(alert,frames,config,directory.name)
    size=sum(len(body) for body in documents.values())
    if size>max_bytes:
        raise RuntimeError('Proof size limit reached.')
    folder=directory/'proofs'
    folder.mkdir(exist_ok=True)
    metadata={'status':'complete' if verified else 'partial','verified':verified,'sha256':{}}
    for kind,body in documents.items():
        relative='proofs/'+alert['id']+'.'+kind
        atomic_write(directory/relative,body)
        metadata[kind+'_path']=relative
        metadata['sha256'][kind]=hashlib.sha256(body).hexdigest()
    return metadata,size


SCOPE=('Check saved file hashes, exact event lines, and rule replay. '
       'The replay uses the current GTH Engine. It is not a separate detector. '
       'Hashes do not prove radio origin. A full bundle can be changed together. '
       'Person identity and hostile intent are not proved.')
MATCH=('rule_id','source','bssid','timestamp','evidence')


def require(condition,message):
    if not condition:
        raise ValueError(message)


def pairs_unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'Duplicate JSON key: '+key)
        result[key]=value
    return result


def json_value(raw):
    def invalid(value):
        raise ValueError('Non-finite JSON value: '+value)
    return json.loads(raw,object_pairs_hook=pairs_unique,parse_constant=invalid)


def object_value(raw):
    value=json_value(raw)
    require(isinstance(value,dict),'JSON object is required.')
    return value


def safe_file(root,relative):
    require(isinstance(relative,str) and relative,'File path is missing.')
    path=PurePosixPath(relative)
    require(not path.is_absolute() and '\\' not in relative and ':' not in relative
            and all(part not in ('','.','..') for part in relative.split('/')),
            'File path is not safe.')
    target=root
    for part in path.parts:
        target=target/part
        require(not target.is_symlink(),'Symlink is not allowed: '+relative)
    require(target.is_file(),'File is missing: '+relative)
    return target


def read_rows(path):
    with path.open('rb') as stream:
        for number,raw in enumerate(stream,1):
            try:
                yield number,object_value(raw)
            except (ValueError,UnicodeError,RecursionError) as error:
                raise ValueError(f'{path.name} line {number}: {error}') from error


def index_events(path):
    offsets=[]
    with path.open('rb') as stream:
        while True:
            offset=stream.tell()
            raw=stream.readline()
            if not raw:
                break
            try:
                object_value(raw)
            except (ValueError,UnicodeError,RecursionError) as error:
                raise ValueError(f'events.jsonl line {len(offsets)+1}: {error}') from error
            offsets.append(offset)
    return offsets


def check_alert(root,alert,config,events,offsets):
    identity=alert.get('id')
    require(isinstance(identity,str) and re.fullmatch(r'GTH-[0-9]{6,12}',identity),
            'Event ID is not valid.')
    metadata=alert.get('proof')
    require(isinstance(metadata,dict),'Proof metadata is missing.')
    require(metadata.get('status')=='complete' and metadata.get('verified') is True,
            'Proof is not complete and verified.')
    hashes=metadata.get('sha256')
    require(isinstance(hashes,dict),'Proof hashes are missing.')
    documents={}
    for kind in ('json','html'):
        relative=metadata.get(kind+'_path')
        require(relative==f'proofs/{identity}.{kind}','Proof path does not match the event ID.')
        raw=safe_file(root,relative).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==hashes.get(kind),kind.upper()+' proof hash does not match.')
        documents[kind]=raw
    doc=object_value(documents['json'])
    require(doc.get('schema_version')==1,'Proof schema is not supported.')
    require(doc.get('session')==root.name,'Proof session does not match the folder.')
    require(doc.get('alert')=={key:value for key,value in alert.items() if key!='proof'},
            'Proof alert does not match alerts.jsonl.')
    require(doc.get('rule_config')==config,'Proof config does not match session.json.')
    replay_config=copy.deepcopy(config)
    replay_config.setdefault('detection',{})['cooldown']=0.0
    require(doc.get('replay_config')==replay_config,'Replay config does not match the saved config.')
    verification=doc.get('verification',{})
    require(isinstance(verification,dict) and verification.get('rule_replay')=='PASS'
            and verification.get('event_hashes')=='PASS','Saved proof checks did not pass.')
    frames=doc.get('supporting_events')
    require(isinstance(frames,list) and len(frames)>0,'Supporting events are missing.')
    engine=Engine(replay_config)
    matched=False
    seen=set()
    for row in frames:
        require(isinstance(row,dict),'Supporting event is not an object.')
        reference=row.get('reference')
        require(isinstance(reference,dict) and reference.get('file')=='events.jsonl',
                'Event source is not events.jsonl.')
        number=reference.get('line')
        require(type(number) is int and 1<=number<=len(offsets),'Event line is out of range.')
        require(number not in seen,'Supporting event line is repeated.')
        seen.add(number)
        events.seek(offsets[number-1])
        raw=events.readline()
        require(hashlib.sha256(raw).hexdigest()==reference.get('sha256'),
                f'Event line {number} hash does not match.')
        event=object_value(raw)
        require(event==row.get('event'),f'Event line {number} does not match the proof event.')
        for candidate in engine.process(event):
            if all(candidate.get(key)==alert.get(key) for key in MATCH):
                matched=True
    require(matched,'Saved events do not replay the claimed rule evidence.')
    return len(frames)


def verify_session(directory):
    result={'status':'FAIL','checked':0,'passed':0,'failed':0,'event_lines':0,
            'scope':SCOPE,'results':[],'errors':[]}
    try:
        root=Path(directory).absolute()
        require(root.is_dir(),'Session folder is missing.')
        require(not any(path.is_symlink() for path in (root,*root.parents)),
                'Session path has a symlink.')
        session_path=safe_file(root,'session.json')
        alerts_path=safe_file(root,'alerts.jsonl')
        events_path=safe_file(root,'events.jsonl')
        watched=(session_path,alerts_path,events_path)
        before={str(path):(path.stat().st_size,path.stat().st_mtime_ns) for path in watched}
        session=object_value(session_path.read_bytes())
        config=session.get('config')
        require(isinstance(config,dict),'Session config is missing.')
        Engine(config)
        offsets=index_events(events_path)
        result['event_lines']=len(offsets)
        ids=set()
        with events_path.open('rb') as events:
            for number,alert in read_rows(alerts_path):
                row={'alert_line':number,'id':alert.get('id'),'rule_id':alert.get('rule_id'),'status':'FAIL'}
                result['checked']+=1
                try:
                    require(isinstance(alert.get('id'),str),'Event ID is missing.')
                    require(alert['id'] not in ids,'Event ID is repeated in alerts.jsonl.')
                    ids.add(alert['id'])
                    row['supporting_events']=check_alert(root,alert,config,events,offsets)
                    row['status']='PASS'
                    result['passed']+=1
                except (OSError,ValueError,TypeError,KeyError,RecursionError) as error:
                    row['error']=str(error)
                    result['failed']+=1
                result['results'].append(row)
        counters=session.get('counters',{})
        require(isinstance(counters,dict),'Session counters are missing.')
        require(counters.get('alerts')==result['checked'],'Session alert count does not match alerts.jsonl.')
        require(counters.get('events')==len(offsets),'Session event count does not match events.jsonl.')
        after={str(path):(path.stat().st_size,path.stat().st_mtime_ns) for path in watched}
        require(before==after,'Session files changed during the check. Use a saved copy.')
        if not result['checked']:
            result['scope']='No event proof claims. Zero alerts do not prove a safe network. '+SCOPE
        if result['failed']==0:
            result['status']='PASS'
    except (OSError,ValueError,TypeError,KeyError,RecursionError) as error:
        result['errors'].append(str(error))
    return result


