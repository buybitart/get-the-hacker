"""Write the same evidence to JSON, HTML, and a portable PDF."""
import hashlib
import html
import json
import os
import math
import re
from pathlib import Path

from .assessment import assess, event_meaning
from .pdf_report import pdf_bytes


def atomic_write(path, data):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    if isinstance(data, str):
        data = data.encode('utf-8')
    with temp.open('wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)




from .values import count as _count


def _fmt(value):
    if value is None:
        return 'Not recorded'
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def _escape(value):
    return html.escape(_fmt(value), quote=True)


def _utc(value):
    from datetime import datetime, timezone
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='seconds')
        except (OverflowError, OSError, ValueError):
            pass
    return _fmt(value)


def coverage_result(record, assessment=None):
    result = (assessment if assessment is not None else assess(record))['capture_title']
    return 'Observed wireless events' if result == 'OBSERVED WIRELESS EVENTS' else result


def _table(headers, rows, empty='No records.'):
    head = '<thead><tr>' + ''.join('<th scope="col">' + _escape(x) + '</th>' for x in headers) + '</tr></thead>'
    body = ''.join('<tr>' + ''.join('<td data-label="' + _escape(headers[index]) + '">' + _escape(x) + '</td>' for index, x in enumerate(row)) + '</tr>' for row in rows)
    if not body:
        body = '<tr><td colspan="' + str(len(headers)) + '">' + _escape(empty) + '</td></tr>'
    table_class = ' class="wide"' if len(headers) >= 5 else ''
    return '<div class="table-wrap"><table' + table_class + '>' + head + '<tbody>' + body + '</tbody></table></div>'


def _report_state(record):
    state = record.get('report_state') or record.get('status')
    if ((record.get('storage') or {}).get('status') == 'limit' or record.get('result') == 'EVIDENCE LIMIT') and record.get('ended_at') is not None:
        return 'EVIDENCE LIMIT', 'Capture stopped at the evidence size limit. This report keeps the saved input.'
    if state in ('running', 'live'):
        return 'RUNNING SNAPSHOT', 'This is saved data. It is not final. Capture may have changed after this save.'
    if state in ('interrupted', 'cancelled', 'stopped'):
        return 'INTERRUPTED', 'This report shows the last saved data. Check the end time and capture logs.'
    if state == 'recovered':
        return 'SAVED SNAPSHOT', 'No end record was saved. This report uses saved files. The stop cause is unknown.'
    if state == 'unavailable':
        return 'UNAVAILABLE', 'No radio frames were measured. This report keeps the local radio check.'
    if state == 'complete':
        return 'COMPLETE', 'Capture has ended. This report shows the final saved data.'
    if state in ('partial', 'no_evidence'):
        return 'PARTIAL', 'Capture has ended. Check missing frames and capture limits.'
    if state == 'limited':
        return 'EVIDENCE LIMIT', 'The session reached a saved input limit. Check the storage record.'
    if state == 'error':
        return 'ERROR', 'This report keeps saved data. Check the error table.'
    return 'STATE UNKNOWN', 'The input has no known final report state.'


def _proof_links(alert, meaning=None):
    """Use saved proof paths only. Imported URLs and other event IDs are not links."""
    proof = alert.get('proof') or {}
    if not isinstance(proof, dict):
        return '<p class="proof-state">Proof missing</p>'
    if meaning and meaning.get('proof_state') in ('failed', 'unchecked'):
        state = 'Proof check failed' if meaning['proof_state'] == 'failed' else 'Proof not checked'
        return '<p class="proof-state">' + state + '</p><p>' + _escape(meaning['proof_note']) + '</p>'
    event_id = alert.get('id')
    verified = proof.get('verified') is True and proof.get('status') in ('complete', 'partial')
    safe_id = isinstance(event_id, str) and re.fullmatch(r'GTH-[0-9]{6,}', event_id)
    links = []
    if verified and safe_id:
        for kind, label in (('html', 'Read proof'), ('json', 'Proof JSON')):
            expected = 'proofs/' + event_id + '.' + kind
            if proof.get(kind + '_path') == expected:
                links.append('<a class="proof-link" href="' + expected + '">' + label + '</a>')
    state = 'Rule proof' if links else {'pending': 'Proof pending', 'error': 'Proof error'}.get(proof.get('status'), 'Proof missing')
    if links and proof.get('status') == 'partial':
        state += ' · Partial evidence'
    return '<div class="proof"><p class="proof-state">' + state + '</p>' + ''.join(links) + '<p class="muted">A proof checks rule evidence. It does not identify a person.</p></div>'


def _timeline_chart(rows, interval=5):
    """Plot measured cumulative counts. Break the path at gaps and counter resets."""
    points = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        stamp, packets = row.get('timestamp'), _count(row.get('packets'))
        if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and math.isfinite(stamp) and packets is not None:
            points.append((stamp, packets))
    if len(points) < 2:
        return '<p>Not enough timeline data for a chart.</p>'
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not math.isfinite(interval) or interval <= 0:
        interval = 5
    start, end = min(p[0] for p in points), max(p[0] for p in points)
    highest = max(p[1] for p in points) or 1
    def xy(p):
        return (36 + 684 * (p[0] - start) / (end - start or 1), 188 - 136 * p[1] / highest)
    groups, group = [], []
    for point in points:
        if group and (point[0] <= group[-1][0] or point[0] - group[-1][0] > max(10, 2 * interval) or point[1] < group[-1][1]):
            groups.append(group)
            group = []
        group.append(point)
    groups.append(group)
    result = ['<figure class="timeline-chart"><svg role="img" aria-labelledby="timeline-title timeline-desc" viewBox="0 0 756 240"><title id="timeline-title">Packets over time</title><desc id="timeline-desc">Cumulative packet count. Gaps are not joined. Full values are in the table.</desc><path class="chart-axis" d="M36 44V188H720"/><text class="chart-count" x="36" y="28">', _escape(str(highest) + ' packets (top)'), '</text><text class="chart-count" x="16" y="194">0</text>']
    for segment in groups:
        coords = ' '.join(f'{x:.2f},{y:.2f}' for x, y in map(xy, segment))
        if len(segment) > 1:
            result += ['<polyline data-series="packets" class="timeline-line" points="', coords, '"/>']
        for point in (segment[0], segment[-1]) if len(segment) > 1 else segment:
            x, y = xy(point)
            result += [f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" class="timeline-dot"><title>', _escape(_utc(point[0]) + ': ' + str(point[1]) + ' packets'), '</title></circle>']
    result += ['<text class="chart-count" x="36" y="224">', _escape(_utc(start).split('T')[-1]), '</text><text class="chart-count" x="720" y="224" text-anchor="end">', _escape(_utc(end).split('T')[-1]), '</text></svg><figcaption>Cumulative packets. Zero starts the count scale. Gaps are not joined. Full UTC dates and counts are in the table.</figcaption></figure>']
    return ''.join(result)


def _errors(record):
    rows = []
    for error in record.get('errors') or []:
        if isinstance(error, dict):
            rows.append((error.get('stage'), error.get('type'), error.get('errno'),
                         error.get('message'), _utc(error.get('timestamp'))))
        else:
            rows.append((None, None, None, error, None))
    if record.get('error') and not any(row[3] == record['error'] for row in rows):
        rows.append((None, None, None, record['error'], _utc(record.get('ended_at'))))
    return rows


def _radio_rows(record):
    selection = record.get('radio_selection') or {}
    current = selection.get('current_state') or record.get('network_status') or {}
    source = record.get('source') or {}
    check = source.get('check') or {}
    channel = current.get('channel')
    if channel is None and isinstance(check.get('interface_info'), str):
        import re
        match = re.search(r'\bchannel (\d+)\b', check['interface_info'])
        if match:
            channel = int(match.group(1))
    return [('Interface', source.get('interface') or selection.get('interface') or current.get('interface')),
            ('Mode', current.get('type') or record.get('mode')),
            ('Channel', channel), ('Frequency MHz', current.get('frequency_mhz')),
            ('Capture active', record.get('capture_active')),
            ('Session status', record.get('status'))]


def _technical_details(record, assessment):
    from . import __version__
    a=assessment;diag=record.get('capture_diagnostics') or {};stats=(record.get('engine') or {}).get('stats') or {}
    state,note=_report_state(record)
    out=['<h3>Session state</h3>',_table(('Field','Value'),_radio_rows(record)+[
        ('Report state',state),('State detail',note),('Capture version',record.get('version')),('Report version',__version__),
        ('Capture author',record.get('author')),('License',record.get('license','GPL-2.0-only')),
        ('Report UTC',_utc(record.get('generated_at'))),('Capture result',record.get('result'))])]
    counters=record.get('counters') or {}
    if (a['frames_analyzed']==0 or counters.get('events')==0) and counters.get('packets'):
        out+=['<p>NO WIDS DATA. No valid input passed WIDS checks.</p>']
    if record.get('mode')=='managed':out+=['<p>Radio frames are not measured.</p>']
    if record.get('mode')=='diagnostic' or record.get('capture_available') is False:out+=['<p>No radio frames were measured.</p>']
    out+=['<h3>Capture counts</h3>',_table(('Field','Count'),[(k,counters.get(k)) for k in ('packets','events','ignored','invalid','queue_drops','unwritten')]),
          _table(('Field','Count'),[('Unwritten',counters.get('unwritten'))])]
    out+=['<h3>Capture diagnostics</h3>',_table(('Reason','Frames'),list((diag.get('reasons') or {}).items())),
          _table(('Packet class','Frames'),list((diag.get('packet_classes') or {}).items())),
          _table(('Field','Value'),[('Accepted input',stats.get('events_accepted')),('Bad FCS',stats.get('bad_fcs')),('Invalid events',stats.get('invalid_events')),('Retries ignored',stats.get('retries_ignored'))]),
          '<h3>Engine counts</h3>',_table(('Field','Count'),list(stats.items())),
          '<h3>Capture timeline</h3><p>All saved rows are in the full JSON.</p>',
          _timeline_chart(record.get('capture_timeline') or [],record.get('telemetry_interval_s',5))]
    networks=record.get('networks') or []
    if isinstance(networks,dict):networks=networks.values()
    out+=['<h3>Saved AP policy</h3>',_table(('SSID','BSSID','Policy result'),[(n.get('ssid'),n.get('bssid'),str(n.get('baseline_status','not_recorded')).upper().replace('_',' ')) for n in networks if isinstance(n,dict)])]
    gps=record.get('sensor_gps') or {}
    out+=['<h3>'+('GPS FIX' if gps.get('status')=='valid' else 'GPS OFF')+'</h3>',_table(('Field','Value'),list(gps.items())),
          '<p>Wi-Fi capture can run without GPS.</p>',
          '<h3>Session errors</h3>',_table(('Stage','Type','Errno','Message','UTC'),_errors(record))]
    review=record.get('review') or {};proof_check=review.get('proof_check') or {}
    if proof_check:
        out+=['<h3>Proof '+('check failed' if proof_check.get('status')=='FAIL' else 'file check')+'</h3>',
              _table(('Field','Value'),[(k,proof_check.get(k)) for k in ('status','checked','passed','failed','errors')]),
              _table(('Event','Rule','Result','Detail'),[(r.get('id'),r.get('rule_id'),r.get('status'),r.get('error')) for r in proof_check.get('results',[]) if isinstance(r,dict)])]
    if review:
        out+=['<h3>Saved input review</h3>',_table(('Field','Value'),[(k,review.get(k)) for k in ('renderer_version','source_folder','source_session_sha256','source_report_sha256','scope','parse_errors')])]
    out+=['<h3>Coverage limits</h3>',_table(('Limit',),[(line,) for line in a['limits']+record.get('limitations',[])])]
    raw=json.dumps(record,indent=2,ensure_ascii=True,allow_nan=False)
    out+=['<details id="full-record"><summary>Full session record / all fields</summary><pre>',html.escape(raw),'</pre></details>']
    return ''.join(out)


def html_report(record):
    """Use one Assessment in the ten-section offline walk report."""
    from .report_page import render
    assessment=assess(record)
    css,body=render(record,assessment,(_escape,_table,_utc,_proof_links,event_meaning),_technical_details(record,assessment))
    meta,body=body.split('>',1)
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GTH Wi-Fi Walk Report</title>'+meta+'><style>'+css+'</style></head><body data-view="simple">'+body+'</body></html>'


def export_reports(record, directory):
    path = Path(directory)
    raw = json.dumps(record, indent=2, ensure_ascii=True, allow_nan=False)
    atomic_write(path/'report.json', raw+'\n')
    atomic_write(path/'report.html', html_report(record))
    atomic_write(path/'report.pdf', pdf_bytes(record))
    manifest = {name: hashlib.sha256((path/name).read_bytes()).hexdigest() for name in ('report.json','report.html','report.pdf')}
    atomic_write(path/'report-hashes.json', json.dumps(manifest,indent=2)+'\n')
    return manifest
