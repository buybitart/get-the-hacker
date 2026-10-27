"""One offline walk report. Shared view data drives every visible result."""
import base64
import hashlib
import html
import json
from pathlib import Path
from .presentation import GLOSSARY, walk_view, network_view, event_rows, public_event, rate_series

SECTIONS=['Overview','Walk Summary','Wi-Fi Networks','Attack Checks','Security Events','Charts','Evidence','How GTH Works','Wi-Fi Safety','Technical Details']

def teaching(name,left,middle,right):
    e=html.escape
    return '<figure><figcaption>Example only: '+e(name)+'. This is not a finding.</figcaption><svg class="teaching" viewBox="0 0 300 100" role="img" aria-label="'+e(name)+' example"><line x1="90" y1="65" x2="210" y2="65"/><text x="12" y="70">'+e(left)+'</text><text x="150" y="30" text-anchor="middle">'+e(middle)+'</text><text x="288" y="70" text-anchor="end">'+e(right)+'</text></svg></figure>'

def render(record,a,h,technical):
    esc,table,utc,proof,meaning=h
    root=Path(__file__).resolve().parent.parent/'web'
    view_record=dict(record,data_source='saved_session');view=walk_view(view_record,a)
    out=[]
    def section(i,content):out.append(f'<section data-section="{i}" id="section-{i}"><p class="eyebrow">{i:02d} / SAVED WALK</p><h2>'+SECTIONS[i-1]+'</h2>'+content+'</section>')
    state=a['hacker_activity'];data_state=state.replace('_',' ')
    primary='<div id="result-box" class="result-box" data-result="'+state+'"><h2 id="security-result">'+esc(data_state)+'</h2><p id="result-explanation">'+esc(view['explanation'])+'</p><p>'+esc(a['assessment_reason'])+'</p><p id="radio-scope">'+esc(a['coverage_scope'])+'</p></div>'
    hero='<strong id="monitoring">MONITORING '+esc(view['monitoring'])+'</strong><p id="freshness">SAVED DATA</p><p id="demo-note"'+('' if view['synthetic'] else ' hidden')+'>SYNTHETIC DEMO / Test frames only.</p><div class="walk-metrics"><article><span>Walk Time</span><strong id="walk-time">'+esc(view['walk_time'])+'</strong></article><article><span>Networks Seen</span><strong id="networks-seen">'+esc(view['networks_seen'])+'</strong></article><article><span>Attack Signs</span><strong id="attack-signs">'+esc(view['attack_signs'])+'</strong></article></div>'
    section(1,hero+primary+'<p>Source MAC is not a person ID.</p><p>Zero alerts do not show a safe network.</p>')
    derived=((record.get('review') or {}).get('derived') or {})
    counters=record.get('counters') or {};packets=counters.get('packets');ignored=counters.get('ignored')
    skip=(str(round(100*ignored/packets,2)).rstrip('0').rstrip('.')+'%') if isinstance(packets,(int,float)) and packets>0 and isinstance(ignored,(int,float)) else None
    gps=record.get('sensor_gps') or {}
    summary=table(('Field','Saved value'),[('Session ID',view['session_id']),('Start UTC',utc(record.get('started_at'))),('End UTC',utc(record.get('ended_at'))),('Last summary UTC',utc(record.get('updated_at'))),('Walk Time',view['walk_time']),('Interface',view['interface']),('Mode',record.get('mode')),('Observed channel',view['channel']),('Frames received',a['frames_received']),('Frames analyzed',a['frames_analyzed']),('Frames dropped',a['frames_dropped']),('Skipped frames',ignored),('Skip rate',skip),('Raw event rows',derived.get('event_records')),('Replay accepted frames',(derived.get('replay') or {}).get('stats',{}).get('events_accepted')),('Capture quality',a['capture_quality']),('Capture state',a['capture_title']),('Sensor GPS',gps.get('status')),('GPS detail',gps.get('reason'))])
    summary+='<p>GPS is optional. '+('GPS OFF. ' if gps.get('status')!='valid' else '')+'Sensor GPS is not source GPS.</p>'
    if not record.get('ended_at') and (record.get('storage') or {}).get('status')!='limit' and record.get('status') not in ('limited','error'):summary+='<p>No end record was saved. The stop cause is unknown.</p>'
    if derived.get('event_records') is not None and derived['event_records']!=counters.get('events'):summary+='<p>Logs have rows after the last saved summary.</p><p>Rebuilt values and original snapshot values have separate labels.</p>'
    summary+=table(('Limit',),[(x,) for x in dict.fromkeys(a['capture_limitations']+a['reasons']+a['limits'])])
    section(2,summary)
    networks=record.get('networks') or [];networks=list(networks.values()) if isinstance(networks,dict) else networks
    network_rows=[network_view(n,view_record,a) for n in networks if isinstance(n,dict)]
    section(3,'<div id="network-map" data-network-map></div><p>Lines show observed frames. This is not a location map.</p><button id="view-all" type="button">VIEW ALL NETWORKS</button><div id="all-networks" hidden><div class="filters"><label>Search <input id="network-search" type="search" maxlength="128"></label><label>Trust <select id="trust-filter"><option value="all">All</option><option value="trusted">Trusted</option><option value="unknown">Unknown</option></select></label><label class="check-label"><input id="signs-filter" type="checkbox">Attack Signs only</label></div><p id="network-scope"></p><div id="network-list"></div><div class="page-controls"><button id="previous-networks" type="button">Back</button><button id="next-networks" type="button">Next</button></div></div><details><summary>Saved AP table</summary>'+table(('SSID','BSSID','Channel','RSSI dBm','Trust','Attack Signs'),[(n['display_name'],n.get('bssid'),n.get('channel'),n.get('rssi'),n['trust'],n['attack_signs']) for n in network_rows[:100]])+'<p>Up to 100 rows are shown in this table. Search the full list above.</p></details>')
    section(4,'<h3>Attack Detection Criteria</h3><div id="attack-checks"></div>'+table(('Check','Result','Usable frames','Saved matches'),[(r['name'],r['result'].replace('_',' '),r['eligible_events'],r['match_count']) for r in a['rule_results']])+'<p>Usable frames are session totals. They are not a window peak.</p><p>Unknown trust and normal Probe Requests are not attacks.</p>')
    events=event_rows(record);means={e.get('id'):e for e in a['events']}
    section(5,'<label>Search events <input id="event-search" type="search" maxlength="128"></label><p>Search saved IDs, rules, and radio addresses.</p><div id="security-events"></div>')
    section(6,'<h3>Wi-Fi Frames Over Time</h3><p>This graph shows how many Wi-Fi messages GTH received.</p><div id="frames-chart" class="interactive-chart"></div><h3>Networks Seen Over Time</h3><p>This graph shows when GTH saw Wi-Fi networks.</p><div id="networks-chart" class="interactive-chart"></div><h3>Attack Signs Over Time</h3><p>This graph shows when GTH found attack signs.</p><div id="indicators-chart" class="interactive-chart"></div><h3>Security Checks</h3><p>This chart shows which attack checks ran.</p><div id="checks-chart"></div><h3>Wi-Fi Signal History</h3><p>This chart shows how the Wi-Fi signal changed.</p><label>AP <select id="signal-ap" aria-label="Signal AP"></select></label><div id="signal-chart" class="interactive-chart"></div><p>Missing samples stay blank. RSSI is not distance.</p><h3>Sensor Health</h3><p>This chart shows how well GTH received Wi-Fi data.</p><div id="health-chart" class="interactive-chart"></div><p>Received, analyzed, and dropped counts have different scopes.</p>')
    files=record.get('evidence_files') or {}
    evidence=table(('Evidence file','Bytes','SHA-256'),[(name,row.get('bytes'),row.get('sha256')) for name,row in files.items() if isinstance(row,dict)])
    evidence+='<p>Proof check: '+esc(a['proof_check_state'])+'. File hashes check file changes.</p><p>Hashes do not prove radio origin or person identity.</p>'
    for e in events[:100]:evidence+=proof(e,meaning(e,(record.get('review') or {}).get('proof_check')))
    section(7,evidence)
    flow='<div id="report-flow" class="flow"></div><h3>How Detection Works</h3><p>Wi-Fi Message → Read Frame → Check Rule → Rule Match?</p><p>No match needs enough data before NOT DETECTED applies.</p><p>A match saves an event and its Evidence.</p>'
    flow+=teaching('Deauth','Source','Link ends','Client')+teaching('Evil Twin','AP name','Copy uses new BSSID','Client')+teaching('Normal Probe','Client','Search asks for SSID','AP')
    flow+='<p>A silent receiver sends no frames. GTH cannot detect that receiver.</p><h3 id="glossary-title">Wi-Fi Security Dictionary</h3><div id="glossary" class="dictionary">'+''.join('<details><summary>'+esc(k)+'</summary><p>'+esc(v)+'</p></details>' for k,v in GLOSSARY.items())+'</div>'
    flow+='<h3>Detection Decision</h3><div id="detection-flow"></div>'
    section(8,flow)
    from .knowledge import advice_rows
    advice=advice_rows(a)
    section(9,table(('Rule','Action','Source','Limit'),[(r['rule_id'],r['advice'],r['sources'],r['limit']) for r in advice],empty='No event-based action applies to this session.')+'<p>Use WPA2 or WPA3. Check PMF support with the AP owner.</p><p>Turn WPS off if it is not needed.</p><p>GTH did not change AP settings.</p>')
    section(10,'<p>Use Technical View to open the detailed tables.</p><details class="technical-appendix"><summary>All technical fields and full session JSON</summary>'+technical+'</details><p>Author: Aliaksandr Zasinets. GPL-2.0-only.</p>')
    series=derived.get('field_series') or record.get('field_series') or {}
    timeline=record.get('capture_timeline') or []
    visible=timeline[-20000:]
    valid_ids={e['event_id'] for e in a['evidence_refs'] if e['rule_id'] not in ('active_recon','ap_policy_change')}
    signs=[e for e in events if e.get('id') in valid_ids];signs.sort(key=lambda e:e.get('timestamp',0))
    indicators=[{'timestamp':e['timestamp'],'count':i+1} for i,e in enumerate(signs) if isinstance(e.get('timestamp'),(int,float))]
    if not indicators and isinstance(record.get('alerts'),list) and a['attack_indicators']==0 and visible:
        indicators=[{'timestamp':visible[0]['timestamp'],'count':0},{'timestamp':visible[-1]['timestamp'],'count':0}]
    payload={'record':{'walk':view,'assessment':a,'counters':counters,'data_source':'saved_session'},
      'glossary':GLOSSARY,'networks':network_rows,'events':[public_event(e,means.get(e.get('id'))) for e in events],
      'timeline':[{k:r.get(k) for k in ('timestamp','received','packets','events','queue_drops','invalid')} for r in visible if isinstance(r,dict)],
      'rates':rate_series(visible),'series':series,'indicators':indicators,
      'check_counts':{s.replace('_',' '):sum(r['result']==s for r in a['rule_results']) for s in ('DETECTED','NOT_DETECTED','NOT_ASSESSED')},
      'chart_scope':'Charts use up to 20000 saved telemetry checks. Full input stays in JSON.'}
    data=json.dumps(payload,ensure_ascii=True,allow_nan=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    scripts='\n'.join((root/name).read_text(encoding='utf-8') for name in ('viz.js','walk.js','report.js'))
    digest=base64.b64encode(hashlib.sha256(scripts.encode()).digest()).decode()
    policy="default-src 'none'; script-src 'sha256-"+digest+"'; style-src 'unsafe-inline'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'"
    nav='<nav class="section-nav" aria-label="Report sections">'+''.join(f'<a href="#section-{i}">{i}. {name}</a>' for i,name in enumerate(SECTIONS,1))+'</nav>'
    mobile='<label class="mobile-nav">Section <select id="section-select">'+''.join(f'<option value="section-{i}">{name}</option>' for i,name in enumerate(SECTIONS,1))+'</select></label>'
    body=nav+mobile+'<main class="report-page" id="top"><header><p class="eyebrow">SAVED WALK / WIDS EVIDENCE</p><h1>GET THE HACKER</h1><p>Live Wi-Fi Security Walk</p><p>Evidence report</p></header><div class="view-controls"><button id="simple-view" aria-pressed="true">Simple View</button><button id="technical-view" aria-pressed="false">Technical View</button></div><noscript><p>JavaScript is off. Read the saved tables and Technical Details.</p></noscript>'+''.join(out)+'<a class="back-top" href="#top">Back to Top</a></main>'
    body+='<dialog id="network-dialog"><div data-dialog-body></div><button type="button" data-close-dialog>Close</button></dialog><dialog id="evidence-dialog"><div data-dialog-body></div><button type="button" data-close-dialog>Close</button></dialog><script id="chart-data" type="application/json">'+data+'</script><script type="text/javascript">'+scripts+'</script>'
    return (root/'style.css').read_text(encoding='utf-8'),'<meta http-equiv="Content-Security-Policy" content="'+policy+'">'+body
