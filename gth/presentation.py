"""Bounded display data. Evidence and rule decisions keep their own scope."""
import copy
import math
from .assessment import assess

GLOSSARY = {
 'WIDS':'WIDS checks Wi-Fi frames. It saves rule events.',
 'BSSID':'BSSID is an AP radio address. It is not a person ID.',
 'SSID':'SSID is a Wi-Fi network name. Several APs can use one name.',
 'RSSI':'RSSI is received signal power in dBm. It is not distance.',
 'AP':'AP means Access Point. It gives clients a Wi-Fi link.',
 'Deauth':'Deauth ends a Wi-Fi link. A reset can also send these frames.',
 'Evil Twin':'An Evil Twin copies an AP name. GTH checks a saved AP policy.',
 'Probe':'A Probe Request asks for Wi-Fi networks. Normal clients send it.',
 'Recon':'Recon collects network data. Client search alone is not an attack.',
 'Evidence':'Evidence is saved input. Hashes help check file changes.',
 'Proof':'Proof checks a rule match on saved frames. It does not prove intent.',
 'Monitor Mode':'Monitor Mode lets an adapter receive raw Wi-Fi frames.',
 'GPS':'GPS gives the sensor position. It does not give the sender position.',
 'False Positive':'A False Positive is an alert for normal activity.',
 'PMF':'PMF protects some management frames. AP and client support is needed.',
 'Channel':'A Channel is one radio band slice. Other channels can be missed.',
 'dBm':'dBm is a power unit. A less negative RSSI means more received power.',
 'Confidence':'Confidence needs a validated model. GTH has no field score.',
}

from .values import finite

def rate_series(rows, interval=5):
    """Delta count / measured seconds. Gaps and resets stay blank."""
    out=[];previous=None
    for row in rows:
        if not isinstance(row,dict) or not finite(row.get('timestamp')):continue
        point={'timestamp':row['timestamp'],'interval_s':None,'received':None,'analyzed':None,'dropped':None}
        if previous:
            dt=row['timestamp']-previous['timestamp']
            if 0<dt<=2*interval:
                point['interval_s']=dt
                for field,key in [('received','received'),('analyzed','events'),('dropped','queue_drops')]:
                    left,right=previous.get(key),row.get(key)
                    if field=='analyzed':
                        left=(previous.get('engine') or {}).get('events_accepted')
                        right=(row.get('engine') or {}).get('events_accepted')
                    if finite(left) and finite(right) and 0<=left<=right:point[field]=(right-left)/dt
        out.append(point);previous=row
    return out

def event_rows(record):
    recent=[a for a in (record.get('alerts') or []) if isinstance(a,dict)]
    ids={a.get('id') for a in recent}
    rows=[a for a in (record.get('alert_witnesses') or [])[:9] if isinstance(a,dict) and a.get('id') not in ids]+recent
    return sorted(rows,key=lambda a:a.get('timestamp') if finite(a.get('timestamp')) else 0,reverse=True)


def activity_rows(record, limit=100):
    rows=[]
    def add(ts,kind,text,details=None):
        if finite(ts):rows.append({'timestamp':ts,'kind':kind,'text':text,'details':details})
    add(record.get('started_at'),'session','Session started')
    add(record.get('ended_at'),'session','Session ended',record.get('status'))
    last=None
    for t in record.get('capture_timeline',[]) or []:
        if isinstance(t,dict) and t.get('health')!=last:
            last=t.get('health');add(t.get('timestamp'),'health','Capture state',last)
    for e in record.get('errors',[]) or []:
        if isinstance(e,dict):add(e.get('timestamp'),'software','Step failed',e)
    for e in record.get('alerts',[]) or []:
        if isinstance(e,dict):add(e.get('timestamp'),'rule',e.get('rule_id','Rule event'),e)
    return sorted(rows,key=lambda r:r['timestamp'])[-limit:]

def public_event(alert, meaning=None):
    keys=('id','rule_id','attack_method','event_type','timestamp','source','bssid','channel','rssi','proof','source_location')
    out={k:copy.deepcopy(alert[k]) for k in keys if k in alert}
    preview={}
    for key,value in list((alert.get('evidence') if isinstance(alert.get('evidence'),dict) else {'value':str(alert.get('evidence') or '')[:512]}).items())[:20]:
        if isinstance(value,list):value=value[:12]
        if isinstance(value,str):value=value[:512]
        if isinstance(value,dict):value={str(k):v for k,v in list(value.items())[:12] if v is None or isinstance(v,(str,int,float,bool))}
        preview[key]=value
    out['evidence']=preview
    out['evidence_scope']='Live preview. Open Proof for all saved fields.'
    if meaning is not None:out['meaning']=copy.deepcopy(meaning)
    return out


def public_state(record):
    """Assess all supplied events before the display limits. Never trust old summaries."""
    assessment=assess(record)
    keys=('app','version','mode','status','session_id','data_source','started_at','ended_at','updated_at',
          'last_event_at','report_state','result','error','source','sensor_gps','source_estimates',
          'source_movement','network_status','radio_selection','capture_active','capture_diagnostics',
          'counters','queue','storage','engine','limitations','errors','rule_event_counts_version','rule_event_counts','network_event_counts','networks_seen','network_history')
    out={k:copy.deepcopy(record[k]) for k in keys if k in record}
    networks=record.get('networks') or []
    if isinstance(networks,dict):networks=list(networks.values())
    out['networks']=copy.deepcopy(sorted((n for n in networks if isinstance(n,dict)),key=lambda n:n.get('last_seen') if finite(n.get('last_seen')) else 0,reverse=True)[:100])
    means={e.get('id'):e for e in assessment.get('events',[])}
    out['alerts']=[public_event(e,means.get(e.get('id'))) for e in (record.get('alerts') or [])[-200:] if isinstance(e,dict)]
    out['visible_events']=[public_event(e,means.get(e.get('id'))) for e in event_rows(record)[:209]]
    out['alert_witnesses']=[public_event(e,means.get(e.get('id'))) for e in (record.get('alert_witnesses') or [])[:9] if isinstance(e,dict)]
    out['glossary']=GLOSSARY
    out['capture_timeline']=copy.deepcopy((record.get('capture_timeline') or [])[-120:])
    out['rates']=rate_series(out['capture_timeline'])
    out['activity']=activity_rows(record)
    for item in out['activity']:
        if item.get('kind')=='rule' and isinstance(item.get('details'),dict):item['details']=public_event(item['details'])
    out['walk']=walk_view(record,assessment)
    shown_ids={n.get('bssid') for n in out['networks']}|{n.get('bssid') for n in out['walk']['nodes']}
    if 'network_event_counts' in out:out['network_event_counts']={k:v for k,v in out['network_event_counts'].items() if k in shown_ids}
    assessment['events']=assessment['events'][-200:]
    shown={n.get('bssid') for n in out['networks']}
    assessment['networks']=[n for n in assessment['networks'] if n.get('bssid') in shown]
    assessment['evidence_refs']=assessment['evidence_refs'][:100]
    for rule in assessment['rule_results']:rule['evidence_refs']=rule['evidence_refs'][:10]
    out['assessment']=assessment
    out['session_id']=str(record.get('session_id') or ('saved-'+str(record.get('started_at','unknown'))))
    out['view_scope']={'networks_total':assessment.get('networks_observed',len(networks)),'networks_shown':len(out['networks']),
        'alerts_total':(record.get('counters') or {}).get('alerts',len(record.get('alerts') or [])),
        'alerts_shown':len(out['alerts']),'timeline_shown':len(out['capture_timeline']),
        'poll_seconds':2,'source':'Saved session' if record.get('data_source')=='saved_session' else 'Local runtime'}
    return out

# Definitions are display text. They never change a rule result.
GLOSSARY.update({
 'Wi-Fi':'Wi-Fi lets devices use a wireless network.',
 'Access Point':'An Access Point gives devices a Wi-Fi link.',
 'MAC Address':'A MAC Address is a device address. It can be changed.',
 'Frame':'A Frame is a small Wi-Fi message.',
 'Probe Request':'A Probe Request looks for Wi-Fi networks. Normal clients send it.',
 'Beacon':'A Beacon gives basic information about a Wi-Fi network.',
 'Deauthentication':'Deauthentication ends a Wi-Fi connection state. Resets can cause it.',
 'Disassociation':'Disassociation ends a Wi-Fi link.',
 'SHA-256':'SHA-256 makes a file fingerprint. It helps find file changes.',
 'Trusted':'Trusted means saved AP fields match. This is not identity proof.',
 'Unknown':'Unknown means no matching trusted AP policy was checked.',
 'EAPOL':'EAPOL carries key exchange messages. Missing messages can mean capture loss.',
 'WPS':'WPS helps devices join Wi-Fi. Setup errors can cause rejects.',
 'KARMA':'KARMA can reply to many network names. Real APs can also do this.',
 'PMKID':'PMKID is a key identifier. Its presence is not an attack.',
 'Nonce':'A Nonce is a value used in a key exchange.',
 'Authentication':'Authentication checks if a device can use a Wi-Fi service.',
 'Association':'Association lets a client join an AP.',
 'False Negative':'A False Negative means an attack sign was missed.',
})


def network_view(network, record, assessment):
    """Trust and attack Evidence have separate meanings."""
    mac=network.get('bssid')
    meaning=next((n for n in assessment.get('networks',[]) if n.get('bssid')==mac),{})
    trust='TRUSTED' if meaning.get('baseline_state',network.get('baseline_status'))=='match' else 'UNKNOWN'
    valid_ids={r.get('event_id') for r in assessment.get('evidence_refs',[]) if r.get('rule_id') not in ('active_recon','ap_policy_change')}
    count=sum(a.get('id') in valid_ids and a.get('bssid')==mac for a in event_rows(record))
    if assessment.get('hacker_activity')=='DETECTED' and (record.get('review') or {}).get('proof_check',{}).get('status')!='FAIL' and any(r.get('match_scope')=='session_index' for r in assessment.get('rule_results',[])):
        saved=(record.get('network_event_counts') or {}).get(mac,{})
        count=max(count,sum(v.get('verified',0) for v in saved.values() if isinstance(v,dict) and type(v.get('verified')) is int and v['verified']>=0))
    policy=meaning.get('baseline_state',network.get('baseline_status'))
    explanation=('Saved AP fields match the trusted list.' if trust=='TRUSTED' else
                 'Saved AP fields do not match the trusted policy. This alone is not an attack.' if policy in ('mismatch','conflict') else
                 'Some AP policy fields are missing. Trust is not assessed.' if policy=='unknown' else
                 'No matching trusted AP policy was checked. This alone is not an attack.')
    return dict(network,trust=trust,attack_signs=count,
                display_name=network.get('ssid') if isinstance(network.get('ssid'),str) and network['ssid'] else 'SSID not saved',
                seen_label='LAST SEEN',explanation=explanation)


def walk_view(record, assessment=None, now=None):
    """One display model for the terminal, local dashboard, and saved report."""
    import time
    a=assessment if assessment is not None else assess(record)
    current=time.time() if now is None else now
    saved=record.get('data_source')=='saved_session'
    synthetic=record.get('mode')=='demo' or (record.get('source') or {}).get('synthetic') is True
    live=record.get('mode') in ('live','managed') and not saved
    stamp=record.get('updated_at');diag=record.get('capture_diagnostics') or {}
    stale=live and (not finite(stamp) or not finite(current) or current-stamp>8 or stamp-current>1)
    delayed=diag.get('health') in ('capture_backlog','no_fresh_frames') or finite(diag.get('capture_lag_s')) and diag['capture_lag_s']>=15
    data_state='SAVED DATA' if saved else 'DATA NOT FRESH' if stale or delayed else 'CURRENT DATA' if live else 'SYNTHETIC DEMO' if synthetic else 'SAVED DATA'
    unavailable=record.get('mode') in ('managed','diagnostic','unavailable')
    failed=record.get('status')=='error' or record.get('result')=='CAPTURE ERROR'
    monitoring=('NOT ASSESSED' if saved or unavailable else 'CAPTURE ERROR' if failed else 'NOT ASSESSED' if stale else
                'ACTIVE' if record.get('capture_active') is True else 'STOPPED' if record.get('capture_active') is False or record.get('status') in ('complete','interrupted','partial','limited','no_evidence') else 'NOT ASSESSED')
    end=record.get('ended_at') or record.get('updated_at');start=record.get('started_at')
    seconds=max(0,int(end-start)) if finite(end) and finite(start) else None
    duration=f'{seconds//3600:02}:{seconds//60%60:02}:{seconds%60:02}' if seconds is not None else 'N/A'
    networks=record.get('networks') or []
    if isinstance(networks,dict):networks=list(networks.values())
    nodes=[network_view(n,record,a) for n in networks if isinstance(n,dict)]
    nodes.sort(key=lambda n:(-int(n['attack_signs']>0),-int(n['trust']=='TRUSTED'),-(n.get('last_seen') if finite(n.get('last_seen')) else 0),str(n.get('bssid') or '')))
    rules=[]
    for r in a.get('rule_results',[]):
        state=r['result'].replace('_',' ')
        coverage=((record.get('engine') or {}).get('coverage') or {}).get('rules',{}).get(r['rule_id'],{})
        span=a.get('observation_span_s')
        if state=='NOT ASSESSED' and monitoring=='ACTIVE' and data_state=='CURRENT DATA' and a.get('capture_quality')=='SUFFICIENT' and coverage.get('enabled') is True and (r.get('eligible_events') or 0)>0 and finite(span) and span<r['window_s'] and not coverage.get('missing_fields'):
            state='CHECKING'
        error=next((e for e in record.get('errors',[]) if isinstance(e,dict) and e.get('rule_id')==r['rule_id'] and e.get('stage') in ('rule_check','rule_process')),None)
        if error:state='ERROR'
        rules.append(dict(r,evidence_refs=r['evidence_refs'][:10],evidence_ref_count=len(r['evidence_refs']),display_state=state,error=error,
            last_window=((record.get('engine') or {}).get('rule_inputs') or {}).get(r['rule_id']),
            help='GTH checks saved Wi-Fi messages. Open Evidence for the match data.'))
    explanation={'DETECTED':'GTH found signs that match an attack rule.',
                 'NOT_DETECTED':'No attack signs were found in the checked traffic.',
                 'NOT_ASSESSED':'GTH did not receive enough complete Wi-Fi data.'}.get(a.get('hacker_activity'),'The check has no result.')
    if failed:explanation='Capture failed. Open Sensor Health for details.'
    return {'session_id':str(record.get('session_id') or 'saved-'+str(start)),
      'title':'GET THE HACKER','subtitle':'Live Wi-Fi Security Walk','monitoring':monitoring,'data_state':data_state,
      'walk_time':duration,'duration_s':seconds,'networks_seen':None if unavailable else a.get('networks_observed'),
      'attack_signs':None if unavailable else a.get('attack_indicators'),'security_result':a.get('hacker_activity','NOT_ASSESSED'),
      'explanation':explanation,'nodes':nodes[:6],'node_order':'Attack signs, trusted policy, Last Seen, BSSID.',
      'node_scope':'Lines show observed frames. This is not a location map.','checks':rules,
      'capture_quality':a.get('capture_quality'),'capture_title':a.get('capture_title'),
      'channel':a.get('observed_channel'),'interface':(record.get('source') or {}).get('interface'),
      'sensor_gps':record.get('sensor_gps') or {},'synthetic':synthetic}
