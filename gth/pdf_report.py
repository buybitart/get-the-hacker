"""Readable offline PDF. The full unchanged record is an attachment."""
import io
import json
import os
import re
import textwrap
from pathlib import Path
from xml.sax.saxutils import escape

from .assessment import assess


def _text(value):
    if value is None:
        return 'Not recorded'
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def sections(record):
    result = assess(record)
    rows = [('title', 'Get the hacker | Evidence report'),
            ('text', 'Author: ' + _text(record.get('author', 'Aliaksandr Zasinets'))),
            ('text', 'License: ' + _text(record.get('license', 'GPL-2.0-only'))),
            ('heading', 'HACKER ACTIVITY: ' + result['hacker_activity'].replace('_',' ')), ('text', result['assessment_reason']),
            ('text', 'Capture quality: '+result['capture_quality']), ('text',result['coverage_scope']),
            ('heading', 'Wi-Fi result: ' + result['title']), ('text', result['meaning']),
            ('text', 'Capture: ' + result['capture_title']),
            ('text', 'Report state: ' + _text(record.get('report_state') or record.get('status'))),
            ('text', 'Saved UTC: ' + _time(record.get('generated_at'))),
            ('text', 'Start UTC: ' + _time(record.get('started_at')) + ' | End UTC: ' + _time(record.get('ended_at')))]
    rows.extend(('text', reason) for reason in result['reasons'])
    if record.get('mode')=='demo' or (record.get('source') or {}).get('synthetic'):
        rows.insert(3, ('text', 'SYNTHETIC DEMO. Test frames only. This is not a field test.'))
    rows += [('heading', 'Monitor state')]
    counts = record.get('counters') or {}
    rows += [('text', label + ': ' + _text(counts.get(key))) for label, key in (
        ('Packets', 'packets'), ('Decoded frames', 'events'), ('Skipped', 'ignored'),
        ('Invalid', 'invalid'), ('Unwritten', 'unwritten'), ('Queue loss', 'queue_drops'))]
    rows.append(('text', 'Rule events: ' + str(result['rule_count']) + ' | Recon observations: ' + str(result['recon_count'])))
    source, selection = record.get('source') or {}, record.get('radio_selection') or {}
    radio = selection.get('current_state') or record.get('network_status') or {}
    channel=radio.get('channel')
    info=(source.get('check') or {}).get('interface_info')
    if channel is None and isinstance(info,str):
        match=re.search(r'\bchannel (\d+)\b',info)
        if match:channel=int(match.group(1))
    rows += [('text', 'Interface: ' + _text(source.get('interface') or selection.get('interface') or radio.get('interface'))),
             ('text', 'Mode: ' + _text(record.get('mode')) + ' | Channel: ' + _text(channel) + ' | MHz: ' + _text(radio.get('frequency_mhz'))),
             ('text', 'GPS: ' + _text((record.get('sensor_gps') or {}).get('status')) + '. GPS is optional.'),
             ('chart', ''), ('heading', 'Analysis flow'),
             ('text', 'Capture -> Decode -> Match rules -> Save proof -> Save reports'),
             ('text', 'This is a process map. It is not a network map.'),
             ('heading', 'Observed networks')]
    networks = record.get('networks') or []
    if isinstance(networks, dict):
        networks = list(networks.values())
    networks = [n for n in networks if isinstance(n, dict)]
    if not networks:
        rows.append(('text', 'No network record was saved.'))
    for network, meaning in zip(networks, result['networks']):
        rows += [('subheading', _text(network.get('ssid')) + ' | ' + _text(network.get('bssid'))),
                 ('text', 'Channel: ' + _text(network.get('channel')) + ' | MHz: ' + _text(network.get('frequency_mhz')) + ' | RSSI dBm: ' + _text(network.get('rssi'))),
                 ('text', 'Security: ' + _text(network.get('security')) + ' | Frames: ' + _text(network.get('frames'))),
                 ('text', 'Baseline: ' + meaning['baseline_state'] + ' | Event state: ' + meaning['event_state']),
                 ('text', 'Event IDs: ' + (', '.join(map(str, meaning['event_ids'])) or 'None saved'))]
    rows.append(('heading','Attack Detection Criteria'))
    for check in result['rule_results']:
        rows += [('subheading',check['name']+' / '+check['result'].replace('_',' ')),('text',check['condition']),('text',check['observed']),('text',check['reason'])]
    from .knowledge import advice_rows
    rows.append(('heading','How to Protect Your Wi-Fi'))
    advice=advice_rows(result)
    rows.extend(('text',row['advice']+' Source: '+_text(row['sources'])) for row in advice)
    if not advice:rows.append(('text','No event-based protection advice applies to this session.'))
    rows.append(('heading', 'Rule events'))
    alerts = [a for a in record.get('alerts', []) if isinstance(a, dict)]
    if not alerts:
        rows.append(('text', 'No rule alert was saved in this view.'))
    for alert, meaning in zip(alerts, result['events']):
        rows += [('event', _text(alert.get('id')) + ' | ' + _text(alert.get('attack_method') or meaning['title'])),
                 ('text', 'Result: ' + _text(alert.get('result')) + ' | Rule: ' + _text(alert.get('rule_id'))),
                 ('text', 'Source MAC: ' + _text(alert.get('source')) + ' | AP / BSSID: ' + _text(alert.get('bssid'))),
                 ('text', 'UTC: ' + _time(alert.get('timestamp')) + ' | Channel: ' + _text(alert.get('channel')) + ' | RSSI dBm: ' + _text(alert.get('rssi'))),
                 ('text', meaning['fact']), ('text', meaning['meaning']), ('text', 'Limit: ' + meaning['limit']),
                 ('text', 'Action: ' + meaning['action']), ('text', 'Proof: ' + meaning['proof_state']),
                 ('text', meaning['proof_note']),
                 ('text', 'Full evidence: report.json / alerts / ' + _text(alert.get('id')))]
    review = record.get('review') or {}
    derived=review.get('derived') or {}
    if derived:
        rows.append(('heading','Saved input review'))
        rows.append(('text','Raw saved event rows: '+_text(derived.get('event_records'))+' | Replay accepted frames: '+_text((derived.get('replay') or {}).get('stats',{}).get('events_accepted'))))
        if 'observed_networks' in derived:rows.append(('text','Raw AP BSSIDs: '+str(len(derived['observed_networks']))+'. Metadata APs: '+str(len(review.get('snapshot_networks',networks)))+'. These scopes can differ.'))
    proof_check = review.get('proof_check') or {}
    if isinstance(proof_check, dict) and proof_check:
        rows.append(('heading', 'Proof check failed' if proof_check.get('status') == 'FAIL' else 'Proof file check'))
        rows.append(('text', 'Status: ' + _text(proof_check.get('status')) + ' | Checked: ' + _text(proof_check.get('checked'))))
        rows.extend(('text', _text(error)) for error in proof_check.get('errors', []))
        rows.extend(('text', _text(error)) for error in proof_check.get('results', []) if isinstance(error, dict) and error.get('status') == 'FAIL')
    rows.append(('heading', 'Session errors'))
    errors = record.get('errors') or []
    for error in errors:
        rows.append(('text', _text(error)))
    if record.get('error'):
        rows.append(('text', _text(record['error'])))
    if not errors and not record.get('error'):
        rows.append(('text', 'No error was saved.'))
    rows.append(('heading', 'Next checks'))
    rows.extend(('text', action) for action in result['actions'])
    rows.append(('heading', 'Coverage limits'))
    rows.extend(('text', limit) for limit in result['limits'])
    rows.extend(('text', _text(limit)) for limit in record.get('limitations', []))
    rows += [('heading', 'Full technical evidence'),
             ('text', 'Full unchanged session JSON is attached as report.json.'),
             ('text', 'The attachment keeps all fields, alerts, timeline rows, and evidence hashes.'),
             ('text', 'All timeline rows: ' + str(len(record.get('capture_timeline') or []))),
             ('text', 'Read report.html for all tables. Read the proof files for rule inputs.'),
             ('text', 'Source MAC is not a person ID. Sensor GPS is not source GPS.')]
    return rows


def _time(value):
    from datetime import datetime, timezone
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='seconds')
        except (ValueError, OverflowError, OSError):
            pass
    return _text(value)


def _portable(record, raw, note):
    rows = sections(record)
    rows.insert(3, ('text', 'PDF text: ' + note))
    lines = []
    for kind, value in rows:
        if kind == 'chart':
            value = 'Packet counts are listed above. Rows can overlap. Queue loss is extra.'
        if kind in ('title', 'heading', 'event'):
            lines.append('')
        value = value.encode('ascii', 'backslashreplace').decode('ascii')
        lines.extend(textwrap.wrap(value, width=94, replace_whitespace=False, drop_whitespace=False) or [''])
    chunks = [lines[i:i+61] for i in range(0, len(lines), 61)]
    objects = [b'', b'', b'<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>']
    def obj(data):
        objects.append(data)
        return len(objects)
    pages = []
    def esc(s):
        return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
    for number, chunk in enumerate(chunks, 1):
        body = 'BT /F1 9 Tf 12 TL 32 800 Td\n' + '\n'.join('('+esc(s)+') Tj T*' for s in chunk)
        body += '\nET\nBT /F1 8 Tf 32 24 Td (Page '+str(number)+' of '+str(len(chunks))+') Tj ET'
        body = body.encode('ascii')
        content = obj(b'<< /Length '+str(len(body)).encode()+b' >>\nstream\n'+body+b'\nendstream')
        pages.append(obj(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content} 0 R >>'.encode()))
    embed = obj(_attachment(raw))
    spec = obj(f'<< /Type /Filespec /F (report.json) /EF << /F {embed} 0 R >> >>'.encode())
    objects[0] = f'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(report.json) {spec} 0 R] >> >> >>'.encode()
    objects[1] = f'<< /Type /Pages /Kids [{" ".join(str(p)+" 0 R" for p in pages)}] /Count {len(pages)} >>'.encode()
    out, offsets = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'), [0]
    for number, data in enumerate(objects, 1):
        offsets.append(len(out)); out.extend(f'{number} 0 obj\n'.encode()+data+b'\nendobj\n')
    start = len(out)
    out.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        out.extend(f'{offset:010d} 00000 n \n'.encode())
    out.extend(f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n'.encode())
    return bytes(out)


def _attachment(raw):
    return b'<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length '+str(len(raw)).encode()+b' >>\nstream\n'+raw+b'\nendstream'


def _font_path():
    prefix = os.environ.get('PREFIX', '')
    candidates = [Path(__file__).parent.parent/'fonts/DejaVuSans.ttf',
                  Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
                  Path('/usr/share/fonts/dejavu/DejaVuSans.ttf'),
                  Path(prefix)/'share/fonts/TTF/DejaVuSans.ttf' if prefix else Path('/nonexistent'),
                  Path('/system/fonts/NotoSans-Regular.ttf'),
                  Path(os.environ.get('WINDIR', 'C:/Windows'))/'Fonts/DejaVuSans.ttf',
                  Path(os.environ.get('WINDIR', 'C:/Windows'))/'Fonts/arial.ttf']
    return next((path for path in candidates if path.is_file()), None)


def _reportlab(record, raw):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfdoc, pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Flowable
    font_path = _font_path()
    if font_path is None:
        raise OSError('No local Unicode font is available.')
    font_name = 'GTHUnicode'
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
    glyphs = pdfmetrics.getFont(font_name).face.charWidths
    def safe(value):
        # Unsupported glyphs remain visible as escapes. The attachment stays exact.
        value = ''.join(c if ord(c) in glyphs or c in '\n\t' else c.encode('ascii', 'backslashreplace').decode('ascii') for c in value)
        return escape(value).replace('\n', '<br/>')
    body = ParagraphStyle('GTHBody', fontName=font_name, fontSize=10, leading=14, spaceAfter=6, splitLongWords=True)
    styles = {'text': body,
              'title': ParagraphStyle('GTHTitle', parent=body, fontSize=22, leading=28, spaceAfter=14),
              'heading': ParagraphStyle('GTHHeading', parent=body, fontSize=15, leading=20, spaceBefore=13, spaceAfter=8, keepWithNext=True),
              'subheading': ParagraphStyle('GTHSubheading', parent=body, fontSize=11, leading=15, spaceBefore=7, keepWithNext=True),
              'event': ParagraphStyle('GTHEvent', parent=body, fontSize=12, leading=16, textColor=colors.HexColor('#b00020'), spaceBefore=9, keepWithNext=True)}
    class EmbeddedJSON(pdfdoc.PDFObject):
        def format(self, document):
            return _attachment(raw)
    class ReportCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            kwargs.update(pageCompression=0, pdfVersion=(1, 4))
            super().__init__(*args, **kwargs)
            embedded = self._doc.Reference(EmbeddedJSON())
            spec = pdfdoc.PDFDictionary({'Type': pdfdoc.PDFName('Filespec'), 'F': pdfdoc.PDFString('report.json'),
                                         'EF': pdfdoc.PDFDictionary({'F': embedded})})
            self._doc.Catalog.Names = pdfdoc.PDFDictionary({'EmbeddedFiles': pdfdoc.PDFDictionary({
                'Names': pdfdoc.PDFArray([pdfdoc.PDFString('report.json'), self._doc.Reference(spec)])})})
    class PacketBars(Flowable):
        def __init__(self):
            super().__init__(); self.width=490; self.height=134
        def draw(self):
            from .assessment import measured
            counts = record.get('counters') or {}
            data = [(label, measured(counts.get(key))) for label, key in [('Packets','packets'),('Decoded','events'),('Skipped','ignored'),('Queue loss','queue_drops')]]
            maximum = max((value for _, value in data if value is not None), default=1) or 1
            self.canv.setFont(font_name, 9)
            for index, (label, value) in enumerate(data):
                y=112-25*index
                self.canv.setFillColor(colors.black); self.canv.drawString(0,y,label)
                self.canv.setFillColor(colors.HexColor('#dddddd')); self.canv.rect(90,y-2,300,10,fill=1,stroke=0)
                self.canv.setFillColor(colors.black)
                if value:
                    self.canv.rect(90,y-2,300*value/maximum,10,fill=1,stroke=0)
                self.canv.drawString(400,y,_text(value))
            self.canv.drawString(0,8,'Counts use frames. Rows can overlap. Queue loss is extra.')
    def footer(c, doc):
        c.setFont(font_name, 8); c.setFillColor(colors.HexColor('#444444'))
        c.drawString(36,22,'GTH Evidence report | Page '+str(doc.page))
    stream = io.BytesIO()
    document = SimpleDocTemplate(stream, pagesize=(595,842), rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=38,
                                 title='GTH Evidence report', author=_text(record.get('author', 'Aliaksandr Zasinets')))
    story = []
    for kind, value in sections(record):
        story.append(PacketBars() if kind == 'chart' else Paragraph(safe(value), styles.get(kind, body)))
    story.append(Spacer(1,6))
    story.append(Paragraph('PDF text: Embedded Unicode font. Missing glyphs use visible escapes.', body))
    document.build(story, onFirstPage=footer, onLaterPages=footer, canvasmaker=ReportCanvas)
    return stream.getvalue()


def pdf_bytes(record, backend='auto'):
    raw = json.dumps(record, indent=2, ensure_ascii=True, allow_nan=False).encode('ascii')
    if backend not in ('auto', 'portable', 'reportlab'):
        raise ValueError('Unknown PDF backend.')
    if backend != 'portable':
        try:
            return _reportlab(record, raw)
        except Exception as error:
            if backend == 'reportlab':
                raise
            reason = type(error).__name__ + ': ' + str(error)
            return _portable(record, raw, 'Unicode renderer unavailable (' + reason + '). Non-ASCII text uses visible escapes.')
    return _portable(record, raw, 'Portable backend selected. Non-ASCII text uses visible escapes.')
