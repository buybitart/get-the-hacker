"""Bounded session storage and live snapshots."""
import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import weakref
import threading
import time
import uuid
from collections import OrderedDict, deque
from pathlib import Path
from .assessment import assess
from .values import timestamp as valid_timestamp
from . import __version__
from .engine import Engine
from .gps import validate_fix
from .positioning import estimate_movement
from .reports import atomic_write, export_reports, html_report
from .proof import event_line, save_proof

MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')


class EvidenceLimit(RuntimeError):
    """The input evidence budget is full. This is not a decoder error."""


LIMITS = [
    'Source MAC can be spoofed or changed. It is not a person ID.',
    'A silent passive scanner cannot be seen from radio frames.',
    'Packet loss and channel coverage can hide activity.',
    'Sensor GPS is not source GPS. RSSI alone does not give a location.',
    'Field Accuracy, False Positive rate, and False Negative rate are not measured.',
]


def load_config(path):
    if not path:
        return {'trusted_aps': []}
    p = Path(path)
    if p.stat().st_size > 1024*1024:
        raise ValueError('Config file is too large.')
    data = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Config must be an object.')
    return data


def validate_event(raw):
    if not isinstance(raw, dict):
        raise ValueError('Event must be an object.')
    # Reject NaN and deep or non-JSON data before it reaches reports.
    if len(json.dumps(raw, allow_nan=False)) > 65536:
        raise ValueError('Event is too large.')
    event = dict(raw)
    for key in ('source', 'destination', 'bssid'):
        val = event.get(key)
        if val is None and key == 'bssid':
            continue
        if not isinstance(val, str) or not MAC.fullmatch(val.lower()):
            raise ValueError('Event needs valid radio addresses.')
        event[key] = val.lower()
    for key in ('timestamp',):
        val = event.get(key)
        if not valid_timestamp(val):
            raise ValueError('Event needs a valid timestamp.')
    if not isinstance(event.get('kind'), str) or len(event['kind']) > 32:
        raise ValueError('Event needs a frame kind.')
    if 'ssid' in event and (not isinstance(event['ssid'],str) or len(event['ssid']) > 128):
        raise ValueError('Bad SSID text.')
    for key,lo,hi in [('rssi',-127,0), ('channel',1,233), ('sequence',0,4095), ('fragment',0,15)]:
        val = event.get(key)
        if val is not None and (isinstance(val,bool) or not isinstance(val,int) or not lo <= val <= hi):
            raise ValueError('Bad radio metadata.')
    for key in ('retry','protected','bad_fcs'):
        if key in event and not isinstance(event[key],bool):
            raise ValueError('Radio flags must be true or false.')
    if event.get('sensor_gps') is not None:
        gps = event['sensor_gps']
        if isinstance(gps, dict) and gps.get('status') in ('unavailable','rejected'):
            event['sensor_gps'] = dict(status=gps['status'],
                reason=str(gps.get('reason') or 'No sensor GPS fix.')[:160],
                provider=gps.get('provider') if isinstance(gps.get('provider'),str) else None,
                source='sensor_gps',lat=None,lon=None,accuracy_m=None,timestamp=None)
        else:
            event['sensor_gps'] = validate_fix(gps, now=event['timestamp']) if isinstance(gps,dict) else {'status':'rejected','reason':'Bad sensor GPS.'}
    return event


def read_jsonl(path, max_line=65536):
    with Path(path).open('r',encoding='utf-8') as stream:
        while True:
            line = stream.readline(max_line+2)
            if not line:
                break
            if len(line) > max_line:
                raise ValueError('Input line is too large.')
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except (ValueError, RecursionError):
                yield None


def _release_network_cache(catalog,folder):
    if catalog is not None:
        try:catalog.close()
        except sqlite3.Error:pass
    try:folder.cleanup()
    except OSError:pass


class Session:
    def __init__(self, output, mode, config, source=None, max_bytes=268435456):
        self.directory = Path(output)/('session-'+time.strftime('%Y%m%d-%H%M%S',time.gmtime())+'-'+uuid.uuid4().hex[:8])
        self.directory.mkdir(parents=True, exist_ok=False)
        self.engine = Engine(config)
        self.lock = threading.RLock()
        self.events = (self.directory/'events.jsonl').open('w',encoding='utf-8',newline='\n')
        self.alert_log = (self.directory/'alerts.jsonl').open('w',encoding='utf-8',newline='\n')
        self.run_log = (self.directory/'run.log').open('w',encoding='utf-8',newline='\n')
        self.positions = (self.directory/'positions.jsonl').open('w',encoding='utf-8',newline='\n')
        self.telemetry_log = (self.directory/'telemetry.jsonl').open('w',encoding='utf-8',newline='\n')
        self.debug_log = (self.directory/'debug.jsonl').open('w',encoding='utf-8',newline='\n')
        self.position_history = deque(maxlen=1000)
        self.alerts = deque(maxlen=200)
        self.max_bytes, self.used_bytes = max_bytes, 0
        self.record = dict(schema_version=2, app='Get the hacker', version=__version__, author='Aliaksandr Zasinets', license='GPL-2.0-only', mode=mode, status='running', started_at=time.time(), updated_at=time.time(), last_event_at=None, source=source, config=config, counters={'packets':0,'events':0,'invalid':0,'ignored':0,'queue_drops':0,'alerts':0,'unwritten':0}, sensor_gps={'status':'unavailable','reason':'No sensor GPS fix.'}, source_estimates=[], limitations=LIMITS, accuracy_status='UNVERIFIED', validation='Runtime Evidence can be checked. Field Accuracy is not measured.')
        self.record.update(session_id=self.directory.name, alert_witnesses=[], rule_event_counts_version=1, rule_event_counts={}, capture_diagnostics={'reasons':{}, 'packet_classes':{}, 'samples':[],
                           'supported_frames':0, 'health':'waiting'}, networks=[], errors=[],
                           network_evictions=0, capture_timeline=[], capture_active=False,
                           report_state='running', report_interval_s=30,
                           debug={'records':0,'bytes':0,'max_bytes':min(16*1024*1024,max_bytes//16),
                                  'omitted_records':0,'omitted_by_stage':{},
                                  'format':'Detail stops at its budget. Omitted rows are counted.'},
                           storage={'status':'available','max_bytes':max_bytes,'used_bytes':0},
                           report_worker={'started':0,'completed':0,'failed':0})
        self.networks = OrderedDict()
        self._sensor_state = None
        self._sample_keys = set()
        self.closed = False
        self._catalog_dir = tempfile.TemporaryDirectory(prefix='gth-networks-')
        self._catalog = None
        self._network_dirty = set()
        self.record.update(networks_seen=0, network_history={'status':'available','backend':'private SQLite cache','export':'networks.jsonl','export_state':'pending'})
        try:
            self._catalog=sqlite3.connect(str(Path(self._catalog_dir.name)/'networks.sqlite3'),check_same_thread=False)
            self._catalog.execute('CREATE TABLE networks (bssid TEXT PRIMARY KEY, ssid TEXT, last_seen REAL, trusted INTEGER, signs INTEGER, data TEXT, search_key TEXT)')
            self._catalog.execute('CREATE INDEX recent_networks ON networks(last_seen DESC)')
            self._catalog.commit()
        except sqlite3.Error as exc:
            self._network_index_error(exc)
        self._network_finalizer=weakref.finalize(self,_release_network_cache,self._catalog,self._catalog_dir)
        self._started_monotonic = time.monotonic()
        self._last_packet_monotonic = None
        self._last_accepted_monotonic = None
        self._last_frame_timestamp = None
        self._report_worker = None
        self._report_error = None
        self._report_at = self._started_monotonic
        self.log('Session started.', mode=mode)
        try:
            self.checkpoint(force_report=True)
        except BaseException:
            for stream in (self.events,self.alert_log,self.run_log,self.positions,self.telemetry_log,self.debug_log):
                try:stream.close()
                except OSError:pass
            if self._catalog is not None:
                try:self._catalog.close()
                except sqlite3.Error:pass
            self._catalog_dir.cleanup();self.closed=True
            raise

    def debug(self, stage, **details):
        meta=self.record['debug']
        # Diagnostic rows must not take the space needed by event evidence.
        if meta['bytes'] >= meta['max_bytes']:
            self._omit_debug(stage)
            return False
        line = json.dumps(dict(timestamp=time.time(),stage=stage,**details),ensure_ascii=True,allow_nan=False)+'\n'
        if meta['bytes']+len(line)>meta['max_bytes'] or self.used_bytes+len(line)>self.max_bytes:
            self._omit_debug(stage)
            return False
        self.debug_log.write(line)
        self.used_bytes += len(line)
        meta['records'] += 1
        meta['bytes'] += len(line)
        return True

    def _omit_debug(self, stage):
        meta=self.record['debug']
        meta['omitted_records']+=1
        counts=meta['omitted_by_stage']
        key=stage if stage in counts or len(counts)<64 else 'other'
        counts[key]=counts.get(key,0)+1
        if 'first_omitted_at' not in meta:
            meta['first_omitted_at']=time.time()

    def _require_space(self, size, stream):
        self.record['storage'].update(max_bytes=self.max_bytes,used_bytes=self.used_bytes)
        if self.used_bytes+size>self.max_bytes:
            # Error logging may also have no space. Keep the first failed stream.
            if self.record['storage']['status']!='limit':
                self.record['storage'].update(status='limit',stream=stream,requested_bytes=size,
                                              reached_at=time.time())
            raise EvidenceLimit('Evidence limit. Start a new session.')

    def account_pending_packet(self, reason):
        """Keep a received packet visible if its processing stops before storage."""
        with self.lock:
            c=self.record['counters']
            pending=c['packets']-sum(c[k] for k in ('events','invalid','ignored','unwritten'))
            if pending>0:
                c['unwritten']+=pending
                self.record['unwritten_reason']=reason

    def log(self, message, **details):
        with self.lock:
            line = json.dumps(dict(timestamp=time.time(),message=message,**details),ensure_ascii=True,allow_nan=False)+'\n'
            self._require_space(len(line),'run.log')
            self.run_log.write(line)
            self.used_bytes += len(line)

    def position(self, estimate):
        with self.lock:
            if self.position_history and self.position_history[-1].get('timestamp') == estimate.get('timestamp') and self.position_history[-1].get('status') == estimate.get('status') and self.position_history[-1].get('source_id') == estimate.get('source_id') and self.position_history[-1].get('reason') == estimate.get('reason'):
                return
            line = json.dumps(estimate,allow_nan=False)+'\n'
            self._require_space(len(line),'positions.jsonl')
            self.positions.write(line)
            self.used_bytes += len(line)
            self.position_history.append(estimate)
            self.record['source_estimates'] = [estimate]
            valid = [p for p in self.position_history if p.get('status') == 'estimated' and p.get('source_id') == estimate.get('source_id')]
            self.record['source_movement'] = estimate_movement(valid)

    def error(self, stage, error):
        with self.lock:
            detail = dict(timestamp=time.time(), stage=stage, type=type(error).__name__,
                          message=str(error), errno=getattr(error, 'errno', None))
            self.record['errors'].append(detail)
            self.record['errors'] = self.record['errors'][-100:]
            # An evidence write error must not prevent the final error record.
            try:
                self.log('Step failed.', error=detail)
                self.debug('error', error=detail)
            except (OSError, RuntimeError):
                pass

    def sensor(self, fix):
        self.update(sensor_gps=fix)
        key = (fix.get('status'), fix.get('provider'), fix.get('reason'))
        if key != self._sensor_state:
            self._sensor_state = key
            self.log('GPS state.', sensor_gps=fix)

    def capture_observation(self, metadata):
        with self.lock:
            diag = self.record['capture_diagnostics']
            stamp=metadata.get('timestamp')
            if isinstance(stamp,(int,float)) and not isinstance(stamp,bool) and math.isfinite(stamp) and stamp>=0:
                self._last_frame_timestamp=stamp
            self.debug('packet_decode', packet=self.record['counters']['packets'], metadata=metadata)
            for field, key in [('reasons',metadata.get('reason','unknown')),
                               ('packet_classes',metadata.get('packet_class','Unknown'))]:
                values = diag[field]
                if key not in values and len(values) >= 64:
                    key = 'other'
                values[key] = values.get(key,0)+1
            if metadata.get('reason') == 'accepted':
                diag['supported_frames'] += 1
            sample_key = (metadata.get('reason'),metadata.get('packet_class'),
                          metadata.get('dot11_type'),metadata.get('dot11_subtype'))
            if sample_key not in self._sample_keys and len(diag['samples']) < 24:
                self._sample_keys.add(sample_key)
                diag['samples'].append(dict(metadata))
                self.log('Frame sample.', sample=metadata)

    def telemetry(self):
        with self.lock:
            counters = self.record['counters']
            diag = self.record['capture_diagnostics']
            now = time.monotonic()
            packet_age = now-(self._last_packet_monotonic if self._last_packet_monotonic is not None else self._started_monotonic)
            accepted_age = now-(self._last_accepted_monotonic if self._last_accepted_monotonic is not None else self._started_monotonic)
            stamp=time.time()
            capture_lag=None if self._last_frame_timestamp is None else stamp-self._last_frame_timestamp
            health = ('managed_only' if self.record['mode'] == 'managed' else
                      'no_fresh_frames' if self.record['mode']=='live' and packet_age>=15 else
                      'capture_backlog' if self.record['mode']=='live' and capture_lag is not None and capture_lag>=15 else
                      'no_wids_data' if self.record['mode']=='live' and counters['packets']>=100 and accepted_age>=15 else
                      'active' if self.engine.stats['events_accepted'] else
                      'no_wids_data' if counters['packets'] >= 100 else 'waiting')
            if health != diag['health']:
                diag['health'] = health
                self.log('Capture health.', health=health, counters=dict(counters))
            row = dict(timestamp=stamp, **counters, health=health,
                       received=self.record.get("queue",{}).get("received"),
                       sensor_gps=self.record['sensor_gps'], packet_age_s=round(packet_age,3),
                       accepted_age_s=round(accepted_age,3), engine=dict(self.engine.stats),
                       last_frame_timestamp=self._last_frame_timestamp,
                       capture_lag_s=None if capture_lag is None else round(capture_lag,3))
            diag.update(last_frame_timestamp=self._last_frame_timestamp,capture_lag_s=row['capture_lag_s'])
            if self.record.get('network_status') is not None:
                row['network_status'] = self.record['network_status']
            line = json.dumps(row, ensure_ascii=True, allow_nan=False)+'\n'
            self._require_space(len(line),'telemetry.jsonl')
            self.debug('capture_health', health=health, counters=dict(counters), engine=dict(self.engine.stats))
            self._require_space(len(line),'telemetry.jsonl')
            self.telemetry_log.write(line)
            self.used_bytes += len(line)
            self.record['capture_timeline'].append(row)
            self.record['capture_timeline'] = self.record['capture_timeline'][-720:]
            return row

    def _network(self, event):
        if event.get('kind') not in ('beacon','probe_response') or not event.get('bssid') or event.get('bad_fcs'):
            return
        key = event['bssid']
        previous = self.networks.get(key)
        if previous is None and self._catalog is not None:
            try:
                saved=self._catalog.execute('SELECT data FROM networks WHERE bssid=?',(key,)).fetchone()
                if saved:previous=json.loads(saved[0])
            except sqlite3.Error as exc:self._network_index_error(exc)
        from .networks import observation_row
        row=observation_row(previous,event,self.engine)
        self.networks[key] = row
        self._network_dirty.add(key)
        if previous is None and self._catalog is not None:
            try:
                self._store_network(row,insert=True)
                self.record['networks_seen']+=1
            except sqlite3.Error as exc:self._network_index_error(exc)
        self.networks.move_to_end(key)
        if len(self.networks) > 1024:
            old_key,old_row=self.networks.popitem(last=False)
            if self._catalog is not None:
                try:self._store_network(old_row)
                except sqlite3.Error as exc:self._network_index_error(exc)
            self._network_dirty.discard(old_key)
            self.record['network_evictions'] += 1
        if previous is None:
            self.log('Network seen.', network=row)
        self.record['networks'] = list(self.networks.values())

    def _network_index_error(self, error):
        self.record['networks_seen']=None
        self.record['network_history'].update(status='unavailable',reason='AP history cache failed. Raw frames stay in events.jsonl.')
        if self._catalog is not None:
            try:self._catalog.close()
            except sqlite3.Error:pass
        self._catalog=None
        if not any(e.get('stage')=='network_index' for e in self.record['errors']):self.error('network_index',error)

    def _store_network(self, row, insert=False):
        statement=('INSERT INTO networks(bssid,ssid,last_seen,trusted,signs,data,search_key) VALUES(?,?,?,?,?,?,?)' if insert else
                   'UPDATE networks SET ssid=?,last_seen=?,trusted=?,signs=?,data=?,search_key=? WHERE bssid=?')
        signs=sum(v.get('verified',0) for v in self.record.get('network_event_counts',{}).get(row['bssid'],{}).values())
        data=json.dumps(row,ensure_ascii=True,allow_nan=False)
        fields=(row.get('ssid') or '',row.get('last_seen'),int(row.get('baseline_status')=='match'),signs,data,((row.get('ssid') or '')+' '+row['bssid']).casefold())
        self._catalog.execute(statement,(row['bssid'],)+fields if insert else fields+(row['bssid'],))

    def _flush_networks(self):
        if self._catalog is None:return
        try:
            for key in self._network_dirty:
                if key in self.networks:self._store_network(self.networks[key])
                else:
                    cached=self._catalog.execute('SELECT data FROM networks WHERE bssid=?',(key,)).fetchone()
                    if cached:self._store_network(json.loads(cached[0]))
            self._catalog.commit();self._network_dirty.clear()
        except (sqlite3.Error,ValueError,TypeError) as exc:self._network_index_error(exc)

    def _all_network_rows(self):
        self._flush_networks()
        if self._catalog is not None:
            try:return [json.loads(r[0]) for r in self._catalog.execute('SELECT data FROM networks ORDER BY last_seen DESC,bssid')]
            except (sqlite3.Error,ValueError,TypeError) as exc:self._network_index_error(exc)
        return list(self.record.get('networks') or [])

    def network_page(self, offset=0, limit=100, search='', trust='all', signs=False):
        if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=100 or not isinstance(search,str) or len(search)>128 or trust not in ('all','trusted','unknown') or not isinstance(signs,bool):
            raise ValueError('Network query is not valid.')
        with self.lock:
            self._flush_networks()
            if self._catalog is not None:
                terms=['instr(search_key,?)>0'];args=[search.casefold()]
                if trust!='all':terms.append('trusted=?');args.append(int(trust=='trusted'))
                if signs:terms.append('signs>0')
                where=' AND '.join(terms)
                try:
                    filtered=self._catalog.execute('SELECT count(*) FROM networks WHERE '+where,args).fetchone()[0]
                    result=self._catalog.execute('SELECT data FROM networks WHERE '+where+' ORDER BY last_seen DESC,bssid LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
                    rows=[json.loads(v[0]) for v in result]
                except (sqlite3.Error,ValueError,TypeError) as exc:self._network_index_error(exc)
            if self._catalog is None:
                all_rows=self.record.get('networks') or []
                rows=[r for r in all_rows if search.casefold() in (str(r.get('ssid') or '')+' '+str(r.get('bssid') or '')).casefold() and (trust=='all' or (r.get('baseline_status')=='match')==(trust=='trusted'))]
                if signs:rows=[r for r in rows if r.get('bssid') in self.record.get('network_event_counts',{})]
                rows.sort(key=lambda r:(-r.get('last_seen',0),r.get('bssid') or ''));filtered=len(rows);rows=rows[offset:offset+limit]
            return {'session_id':self.record['session_id'],'networks':rows,'total':self.record.get('networks_seen'),'filtered':filtered,'offset':offset,'limit':limit,'history_state':self.record['network_history']['status']}

    def count(self,key,n=1):
        with self.lock:
            self.record['counters'][key] += n
            if key=='packets' and n>0:
                self._last_packet_monotonic=time.monotonic()

    def update(self, **values):
        with self.lock:
            self.record.update(values, updated_at=time.time())

    def _persist(self):
        self._flush_networks()
        self.record['engine']=self.engine.snapshot()
        self.record['storage'].update(max_bytes=self.max_bytes,used_bytes=self.used_bytes)
        atomic_write(self.directory/'session.json',json.dumps(self.record,separators=(',',':'),allow_nan=False))

    def accept(self, raw):
        try:
            event = validate_event(raw)
        except (ValueError, TypeError, RecursionError) as error:
            self.count('invalid')
            with self.lock:
                self.debug('event_validate', disposition='invalid_input', input_type=type(raw).__name__, error=str(error))
            return []
        with self.lock:
            line = json.dumps(event,ensure_ascii=True,allow_nan=False)+'\n'
            self._require_space(len(line),'events.jsonl')
            self.events.write(line)
            self.used_bytes += len(line)
            self.record['counters']['events'] += 1
            self.record['last_event_at'] = event['timestamp']
            if self.record['mode'] != 'live' and event.get('sensor_gps'):
                self.record['sensor_gps'] = event['sensor_gps']
            reference=dict(file='events.jsonl',line=self.record['counters']['events'],sha256=hashlib.sha256(line.encode('utf-8')).hexdigest())
            before=dict(self.engine.stats)
            alerts = self.engine.process(dict(event,_evidence_ref=reference))
            delta={k:v-before[k] for k,v in self.engine.stats.items() if v!=before[k]}
            disposition=next((key for key in ('invalid_events','bad_fcs','out_of_order','retries_ignored') if delta.get(key)), 'accepted')
            if disposition in ('accepted','retries_ignored'):
                self._network(event)
            if disposition=='accepted':
                self._last_accepted_monotonic=time.monotonic()
            self.debug('rule_process', disposition=disposition, event=reference, kind=event['kind'],
                       source=event['source'], bssid=event.get('bssid'), stats_delta=delta, alerts=[a['id'] for a in alerts])
            emitted = []
            for alert in alerts:
                alert = dict(alert)
                alert['source_location'] = next((p for p in self.record['source_estimates'] if p.get('status') == 'estimated' and p.get('source_id') == alert.get('source') and abs(p.get('timestamp',0)-event['timestamp']) <= 1), None)
                frames=alert.pop('_proof_frames',[])
                try:
                    self.events.flush()
                    os.fsync(self.events.fileno())
                    reserved=len(json.dumps(alert,ensure_ascii=True,allow_nan=False))+2048
                    alert['proof'],size=save_proof(self.directory,alert,frames,self.record['config'],max(0,self.max_bytes-self.used_bytes-reserved))
                    self.used_bytes+=size
                except (OSError, ValueError, RuntimeError) as exc:
                    alert['proof']={'status':'error','verified':False,'error':str(exc)}
                    self.error('proof_write',exc)
                alert_line = json.dumps(alert,ensure_ascii=True,allow_nan=False)+'\n'
                self._require_space(len(alert_line),'alerts.jsonl')
                self.alert_log.write(alert_line)
                self.used_bytes += len(alert_line)
                self.record['counters']['alerts'] += 1
                self.alerts.append(alert)
                verified=alert.get('proof',{}).get('verified') is True and alert.get('proof',{}).get('status')=='complete'
                counts=self.record['rule_event_counts'].setdefault(alert['rule_id'],{'total':0,'verified':0})
                counts['total']+=1
                if verified:
                    counts['verified']+=1
                    if alert.get('bssid') and alert.get('event_type') not in ('recon_observation','policy_observation'):
                        net=self.record.setdefault('network_event_counts',{}).setdefault(alert['bssid'],{})
                        entry=net.setdefault(alert['rule_id'],{'verified':0,'last_event':None})
                        entry.update(verified=entry['verified']+1,last_event=alert['id'])
                        self._network_dirty.add(alert['bssid'])
                    if not any(a.get('rule_id')==alert.get('rule_id') for a in self.record['alert_witnesses']):
                        self.record['alert_witnesses'].append(copy.deepcopy(alert))
                emitted.append(alert)
            self.record['updated_at'] = time.time()
            return emitted

    def snapshot(self):
        with self.lock:
            out = copy.deepcopy(self.record)
            out['alerts'] = list(self.alerts)
            out['engine'] = self.engine.snapshot()
            return out

    def public_snapshot(self):
        # Copy only the live window while holding the capture lock.
        # Full timelines and event streams remain on disk.
        with self.lock:
            source={k:v for k,v in self.record.items() if k not in ('capture_timeline','assessment','field_series')}
            source['capture_timeline']=self.record['capture_timeline'][-120:]
            out=copy.deepcopy(source)
            out['alerts']=copy.deepcopy(list(self.alerts))
            out['engine']=self.engine.snapshot()
        return out

    def wait_report(self):
        """Join the one report worker before final export or a forced snapshot."""
        worker=self._report_worker
        if worker is not None:
            worker.join()
            self._report_worker=None
            if self._report_error is not None:
                error=self._report_error
                self._report_error=None
                self.record['report_worker']['failed']+=1
                self.error('report_write',error)
            else:
                self.record['report_worker']['completed']+=1

    def _write_snapshot(self, record, boundaries):
        # Read only the bytes flushed for this snapshot. Later rows belong to
        # the next report, even while the capture thread keeps writing.
        for key,name in (('alerts','alerts.jsonl'),('position_history','positions.jsonl'),
                         ('capture_timeline','telemetry.jsonl')):
            rows=[]
            remaining=boundaries[name]
            file=self.directory/name
            if remaining>file.stat().st_size:
                raise ValueError('Report evidence row is incomplete: boundary is past the file end.')
            with file.open('rb') as stream:
                if key=='capture_timeline' and remaining>2*1024*1024:
                    offset=remaining-2*1024*1024
                    stream.seek(offset-1)
                    previous=stream.read(1)
                    remaining-=offset
                    if previous!=b'\n':
                        skipped=stream.readline(remaining)
                        remaining-=len(skipped)
                while remaining:
                    line=stream.readline(min(8*1024*1024+2,remaining))
                    if not line or not line.endswith(b'\n'):
                        raise ValueError('Report evidence row is incomplete.')
                    if len(line)>8*1024*1024:
                        raise ValueError('Report evidence row is too large.')
                    remaining-=len(line)
                    if line.strip(): rows.append(json.loads(line))
            if key=='capture_timeline':
                rows=rows[-720:]
                record['capture_timeline_scope']='Last 720 saved checks in this snapshot. Full telemetry stays in telemetry.jsonl.'
            record[key]=rows
        record['assessment']=assess(record)
        # Each file is atomic. A hard stop can leave two different snapshot times.
        atomic_write(self.directory/'report.json',json.dumps(record,indent=2,allow_nan=False))
        atomic_write(self.directory/'report.html',html_report(record))

    def checkpoint(self, force_report=False, background_report=False):
        if force_report or not background_report or (self._report_worker is not None and not self._report_worker.is_alive()):
            self.wait_report()
        with self.lock:
            for stream in (self.events,self.alert_log,self.run_log,self.positions,self.telemetry_log,self.debug_log):
                stream.flush()
                os.fsync(stream.fileno())
            self._persist()
            if (force_report or time.monotonic()>=self._report_at) and self._report_worker is None:
                self.record['generated_at']=time.time()
                self.record['report_worker']['started']+=1
                record=self.snapshot()
                record['networks']=self._all_network_rows()
                record['network_history']=copy.deepcopy(self.record['network_history'])
                record['networks_seen']=self.record['networks_seen']
                boundaries={name:os.fstat(stream.fileno()).st_size for name,stream in (
                    ('alerts.jsonl',self.alert_log),('positions.jsonl',self.positions),
                    ('telemetry.jsonl',self.telemetry_log))}
                if background_report and not force_report:
                    def write_report():
                        try:
                            self._write_snapshot(record,boundaries)
                        except Exception as exc:
                            self._report_error=exc
                    self._report_worker=threading.Thread(target=write_report,name='gth-report',daemon=True)
                    self._report_worker.start()
                else:
                    self._write_snapshot(record,boundaries)
                    self.record['report_worker']['completed']+=1
                self._report_at=time.monotonic()+self.record['report_interval_s']
                self._persist()

    def finish(self,status='complete',error=None):
        self.wait_report()
        with self.lock:
            if self.closed:
                return
            self.record.update(status=status,report_state=status,ended_at=time.time(),updated_at=time.time(),generated_at=time.time())
            self.record['capture_active'] = False
            counters=self.record['counters']
            accounted=sum(counters[key] for key in ('events','invalid','ignored','unwritten'))
            self.record['packet_accounting']={'packets':counters['packets'],'accounted':accounted,
                                               'balanced':counters['packets']==accounted,
                                               'equation':'packets = events + invalid + ignored + unwritten'}
            if self.record['mode'] == 'live':
                if self.record['storage']['status']=='limit':
                    self.record['result']='EVIDENCE LIMIT'
                elif status == 'error':
                    self.record.update(capture_available=False, result='CAPTURE ERROR')
                elif not self.record['counters']['events']:
                    self.record['result'] = 'NO WIDS DATA'
            if error:
                self.record['error'] = error
            self.record['engine'] = self.engine.snapshot()
            self.record['networks']=self._all_network_rows()
            if self._catalog is not None:self._catalog.close();self._catalog=None
            try:self._catalog_dir.cleanup()
            except OSError as exc:self.error('network_cleanup',exc)
            close_errors = []
            try:
                self.run_log.write(json.dumps({'timestamp':time.time(),'message':'Session stopped.','status':status,'error':error})+'\n')
            except OSError as exc:
                close_errors.append(('run_log_write', exc))
            finally:
                # Close every stream even if one storage write fails.
                for name, stream in [('events',self.events), ('alerts',self.alert_log),
                                     ('run',self.run_log), ('positions',self.positions),
                                     ('telemetry',self.telemetry_log), ('debug',self.debug_log)]:
                    try:
                        stream.close()
                    except OSError as exc:
                        close_errors.append((name+'_close', exc))
                self.closed = True
            if close_errors:
                self.record.update(status='error', report_state='error', error=str(close_errors[0][1]))
                if self.record['mode'] == 'live':
                    self.record.update(capture_available=False, result='CAPTURE ERROR')
                for stage, exc in close_errors:
                    self.record['errors'].append(dict(timestamp=time.time(), stage=stage,
                        type=type(exc).__name__, message=str(exc), errno=getattr(exc,'errno',None)))
            self.record['evidence_files'] = {}
            for name in ('events.jsonl','alerts.jsonl','run.log','positions.jsonl','telemetry.jsonl','debug.jsonl'):
                file = self.directory/name
                with file.open('rb') as stream:
                    digest = hashlib.file_digest(stream,'sha256').hexdigest()
                self.record['evidence_files'][name] = {'sha256':digest,'bytes':file.stat().st_size}
            catalog=self.directory/'networks.jsonl'
            atomic_write(catalog,''.join(json.dumps(r,ensure_ascii=True,allow_nan=False)+'\n' for r in self.record['networks']))
            self.record['network_history']['export_state']='complete'
            self.record['derived_files']={'networks.jsonl':{'bytes':catalog.stat().st_size,'sha256':hashlib.sha256(catalog.read_bytes()).hexdigest(),'role':'Derived AP history. Primary input stays in events.jsonl.'}}
            self._persist()
            record = dict(self.record)
            record['alerts'] = list(read_jsonl(self.directory/'alerts.jsonl', max_line=8*1024*1024))
            record['position_history'] = list(read_jsonl(self.directory/'positions.jsonl', max_line=8*1024*1024))
            record['capture_timeline'] = list(read_jsonl(self.directory/'telemetry.jsonl', max_line=8*1024*1024))
            record['capture_timeline_scope']='All saved telemetry rows at final export.'
            from .series import frame_series
            bounds=(record.get('engine') or {}).get('coverage') or {}
            record['field_series']=frame_series(read_jsonl(self.directory/'events.jsonl'),start=bounds.get('first_timestamp'),end=record.get('ended_at') if record.get('mode')=='live' else bounds.get('last_timestamp'))
            record['assessment']=assess(record)
            export_reports(record,self.directory)
            if close_errors:
                raise close_errors[0][1]


def rebuild_reports(directory):
    path = Path(directory)
    record = json.loads((path/'session.json').read_text(encoding='utf-8'))
    if record.get('status')=='running':
        record.update(report_state='recovered',capture_active=False,
                      recovery_note='Saved run has no end record. The stop cause is unknown.')
    record['alerts'] = list(read_jsonl(path/'alerts.jsonl', max_line=8*1024*1024))
    record['position_history'] = list(read_jsonl(path/'positions.jsonl', max_line=8*1024*1024)) if (path/'positions.jsonl').exists() else []
    if (path/'telemetry.jsonl').exists():
        record['capture_timeline'] = list(read_jsonl(path/'telemetry.jsonl', max_line=8*1024*1024))
        record['capture_timeline_scope']='All saved telemetry rows at final export.'
    if (path/'events.jsonl').exists():
        from .series import frame_series
        bounds=(record.get('engine') or {}).get('coverage') or {}
        record['field_series']=frame_series(read_jsonl(path/'events.jsonl'),start=bounds.get('first_timestamp'),end=record.get('ended_at') if record.get('mode')=='live' else bounds.get('last_timestamp'))
    from .networks import rebuild_history
    if (path/'events.jsonl').exists() and (record.get('network_history') or {}).get('export_state')!='complete':
        record['recovery_snapshot_networks']=record.get('networks') or []
        record['networks']=rebuild_history(read_jsonl(path/'events.jsonl'),record.get('config') or {})
        record['networks_seen']=len(record['networks'])
        record['network_history']={'status':'available','backend':'saved event replay','scope':'All accepted saved AP observations. Capture counters keep their original boundary.'}
    record['assessment']=assess(record)
    return export_reports(record,path)
