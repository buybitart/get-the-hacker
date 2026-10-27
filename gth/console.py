"""One terminal table. A closed terminal must not stop evidence capture."""
import json
import io
import re
import os
import shutil
import sys
import textwrap
import time
from .assessment import assess
from .presentation import walk_view, event_rows, GLOSSARY


def clean(value):
    if value is None:return 'N/A'
    if isinstance(value,str):return json.dumps(value,ensure_ascii=True)[1:-1]
    return str(value)


class Console:
    def __init__(self,stream=None,defer=False):
        self.stream=stream;self.defer=defer;self.failed=False;self.last_error=None
        self.states={};self.extra={};self.finished=False;self.probed=False
        self.page='networks';self.selected=0;self.details=False;self.scroll=0
        self.all_networks=False;self.query='';self.searching=False;self.trust_filter='all';self.signs_filter=False
        self.network_provider=None;self.evidence_directory=None
        self._input_state=None;self._key_buffer='';self._escape_at=None;self._proof_cache=None;self.proof_frame=0;self._last_lines=[];self._last_size=None
        self._record={};self._network_page=None;self._page_at=0;self._final=False


    def _ansi(self):
        return bool(getattr(self.stream or sys.stdout,'isatty',lambda:False)()) and os.environ.get('TERM','xterm')!='dumb'

    def _draw(self,rows,red=False):
        if self.failed:return False
        stream=self.stream or sys.stdout
        width=max(20,min(100,shutil.get_terminal_size((80,24)).columns-1))
        left=min(24,max(8,(width-7)//2));right=width-7-left
        border='+'+'-'*(left+2)+'+'+'-'*(right+2)+'+'
        lines=['+'+'-'*(width-2)+'+','|'+ 'GET THE HACKER'.center(width-2)+'|',border]
        for key,value in rows:
            labels=textwrap.wrap(clean(key),width=left,break_long_words=True) or ['']
            values=textwrap.wrap(clean(value),width=right,break_long_words=True) or ['']
            for i in range(max(len(labels),len(values))):
                a=labels[i] if i<len(labels) else '';b=values[i] if i<len(values) else ''
                lines.append('| '+a.ljust(left)+' | '+b.ljust(right)+' |')
        lines.append(border)
        output='\n'.join(lines)+'\n'
        if self._ansi():
            output='\033[2J\033[H'+output
            if red and 'NO_COLOR' not in os.environ:output='\033[31m'+output+'\033[0m'
        try:
            stream.write(output);stream.flush();return True
        except (OSError,UnicodeError) as error:
            self.failed=True;self.last_error=error;return False

    def emit(self,tag,value,color=None):
        self.extra[tag]=value
        if self.failed:return False
        if self.defer:return True
        return self._draw(list(self.extra.items()),red=color=='31')

    def state(self,tag,value,color=None):
        self.states[tag]=value
        return self.emit(tag,value,color)

    def gps(self,fix):
        value=(f"{fix['lat']:.6f}, {fix['lon']:.6f}" if fix.get('status')=='valid' else 'No fix')
        return self.emit('Sensor GPS',value)

    def network(self,network):
        self.extra.update({'Last network':network.get('ssid') or 'Hidden SSID','BSSID':network.get('bssid'),
                           'Channel':network.get('channel'),'RSSI dBm':network.get('rssi')})
        if not self.defer:return self._draw(list(self.extra.items()))
        return True

    def event(self,alert):
        self.extra.update({'Last event':alert.get('rule_id'),'Source MAC':alert.get('source'),
                           'BSSID':alert.get('bssid'),'Channel':alert.get('channel'),'RSSI dBm':alert.get('rssi')})
        if not self.defer:return self._draw(list(self.extra.items()))
        return True

    def attach(self, session):
        self.network_provider=session.network_page
        self.evidence_directory=session.directory

    def _start_input(self):
        if self._input_state is not None or self.failed:return
        try:
            output=self.stream or sys.stdout
            if not (sys.stdin.isatty() and output.isatty() and os.isatty(output.fileno())):return
            if os.name=='nt':
                self._input_state=('windows',None)
            else:
                import termios,tty
                fd=sys.stdin.fileno();saved=termios.tcgetattr(fd);tty.setcbreak(fd)
                self._input_state=(fd,saved)
            import codecs
            self._decoder=codecs.getincrementaldecoder('utf-8')(errors='replace')
            import atexit
            atexit.register(self.close)
        except (OSError,ValueError,AttributeError,io.UnsupportedOperation):
            self._input_state=None

    def close(self):
        state=self._input_state;self._input_state=None
        if state is not None and state[0]!='windows':
            try:
                import termios
                termios.tcsetattr(state[0],termios.TCSANOW,state[1])
            except (OSError,ValueError):pass
        if self._last_lines:
            try:
                stream=self.stream or sys.stdout;stream.write('\x1b[?25h');stream.flush()
            except (OSError,UnicodeError):pass

    def _poll_input(self):
        if self._input_state is None:return
        if self._input_state[0]=='windows':
            import msvcrt
            for _ in range(32):
                if not msvcrt.kbhit():break
                key=msvcrt.getwch()
                if key in ('\x00','\xe0'):key={'H':'UP','P':'DOWN','K':'LEFT','M':'RIGHT'}.get(msvcrt.getwch(),'')
                self.handle_key(key)
            return
        import select
        fd=self._input_state[0]
        data=self._decoder.decode(os.read(fd,128)) if select.select([fd],[],[],0)[0] else ''
        self.feed_input(data)

    def feed_input(self, data, now=None):
        stamp=time.monotonic() if now is None else now
        self._key_buffer+=data
        arrows={'\x1b[A':'UP','\x1b[B':'DOWN','\x1b[C':'RIGHT','\x1b[D':'LEFT','\x1b[5~':'PAGEUP','\x1b[6~':'PAGEDOWN'}
        while self._key_buffer:
            if self._key_buffer[0]!='\x1b':
                char=self._key_buffer[0];self._key_buffer=self._key_buffer[1:];self.handle_key(char);self._escape_at=None;continue
            match=next((key for key in arrows if self._key_buffer.startswith(key)),None)
            if match:
                self._key_buffer=self._key_buffer[len(match):];self.handle_key(arrows[match]);self._escape_at=None;continue
            if any(key.startswith(self._key_buffer) for key in arrows):
                if self._escape_at is None:self._escape_at=stamp
                if stamp-self._escape_at<0.1:break
            self._key_buffer=self._key_buffer[1:];self.handle_key('ESC');self._escape_at=None

    def handle_key(self, key):
        key={'\t':'TAB','\r':'ENTER','\n':'ENTER','\x1b':'ESC','\x7f':'BACKSPACE','\b':'BACKSPACE'}.get(key,key)
        if key in ('\x03','q','Q') and not self.searching:raise KeyboardInterrupt
        if self.searching:
            if key in ('ENTER','ESC'):self.searching=False
            elif key=='BACKSPACE':self.query=self.query[:-1]
            elif len(key)==1 and key.isprintable() and len(self.query)<128:self.query+=key
            self.selected=0;self._page_at=0;return
        pages=('networks','checks','events','help')
        if key in ('1','2','3','4'):
            self.page=pages[int(key)-1];self.selected=0;self.details=False;self.scroll=0;return
        if key in ('TAB','RIGHT','LEFT'):
            self.page=pages[(pages.index(self.page)+(-1 if key=='LEFT' else 1))%4]
            self.selected=0;self.details=False;self.scroll=0;return
        if key=='ESC':self.details=False;self.scroll=0;self.searching=False;return
        if key=='ENTER':self.details=not self.details;self.scroll=0;return
        if self.page=='events' and self.details and key in ('f','b'):
            self.proof_frame=max(0,self.proof_frame+(1 if key=='f' else -1));self.scroll=0;return
        if key in ('PAGEUP','PAGEDOWN'):
            self.scroll=max(0,self.scroll+(5 if key=='PAGEDOWN' else -5));return
        if key in ('UP','DOWN'):
            step=1 if key=='DOWN' else -1
            if self.details:self.scroll=max(0,self.scroll+step)
            else:self.selected=max(0,self.selected+step)
            return
        if self.page=='networks':
            if key in ('a','A'):self.all_networks=not self.all_networks;self.selected=0
            if key=='/':self.searching=True;self.query=''
            if key in ('t','u','x'):
                self.trust_filter={'t':'trusted','u':'unknown','x':'all'}[key];self.selected=0
            if key=='s':self.signs_filter=not self.signs_filter;self.selected=0
            self._page_at=0;self._network_page=None
        if key=='?':self.page='help';self.selected=0;self.details=False

    def _network_rows(self, record, view):
        if not self.all_networks:return view['nodes'][:3]
        offset=(self.selected//20)*20
        if self.network_provider is not None and (self._network_page is None or time.monotonic()-self._page_at>5 or self._network_page.get('offset')!=offset):
            try:
                self._network_page=self.network_provider(offset=offset,limit=20,search=self.query,trust=self.trust_filter,signs=self.signs_filter)
                self._page_at=time.monotonic()
            except (OSError,ValueError,RuntimeError):self._network_page=None
        from .presentation import network_view
        if self._network_page is not None:
            a=assess(record)
            return [network_view(n,record,a) for n in self._network_page['networks']]
        a=assess(record);rows=[network_view(n,record,a) for n in record.get('networks',[]) if isinstance(n,dict)]
        rows=[n for n in rows if self.query.casefold() in (n['display_name']+' '+str(n.get('bssid'))).casefold() and (self.trust_filter=='all' or (n['trust']=='TRUSTED')==(self.trust_filter=='trusted')) and (not self.signs_filter or n['attack_signs']>0)]
        rows.sort(key=lambda n:-(n.get('last_seen') or 0));return rows[offset:offset+20]

    def _proof_text(self, event):
        proof=event.get('proof') or {}
        out=['WHAT DATA PROVES IT?',json.dumps(event.get('evidence') or {},ensure_ascii=True),
             'Event: '+str(event.get('id')),'Proof: '+str(proof.get('status') or 'not saved')]
        # Read only the current local Proof file. Never run a pager or shell.
        if self.evidence_directory is not None and re.fullmatch(r'GTH-[0-9]{6,12}',str(event.get('id') or '')):
            from pathlib import Path
            import hashlib
            name='proofs/'+event['id']+'.json';file=Path(self.evidence_directory)/name
            try:
                base=Path(self.evidence_directory).resolve()
                if proof.get('json_path')!=name or file.is_symlink() or file.parent.is_symlink() or file.resolve().parent!=base/'proofs' or file.stat().st_size>8*1024*1024:raise ValueError('Proof path is not valid.')
                signature=(str(file),file.stat().st_mtime_ns,file.stat().st_size,(proof.get('sha256') or {}).get('json'))
                if self._proof_cache is None or self._proof_cache[0]!=signature:
                    raw=file.read_bytes()
                    if hashlib.sha256(raw).hexdigest()!=signature[-1]:raise ValueError('Proof hash changed.')
                    self._proof_cache=(signature,json.loads(raw))
                doc=self._proof_cache[1];frames=doc.get('supporting_events') or []
                self.proof_frame=min(self.proof_frame,max(0,len(frames)-1))
                out+=['Saved rule replay: '+str((doc.get('verification') or {}).get('rule_replay')),
                      'Supporting frames: '+str(len(frames))]
                if frames:
                    out+=['Frame '+str(self.proof_frame+1)+' / '+str(len(frames))+' / f Next / b Back',json.dumps(frames[self.proof_frame],ensure_ascii=True)[:65536]]
            except (OSError,ValueError,TypeError):out+=['Proof file is not available. Check the saved report.']
        return out

    def render_screen(self, record, columns=80, height=24, assessment=None, report=None):
        width=max(1,min(120,columns)-1);limit=max(1,min(80,height)-1)
        a=assessment if assessment is not None else assess(record);v=walk_view(record,a)
        def wrap(value):return textwrap.wrap(clean(value),width=width,break_long_words=True,replace_whitespace=False) or ['']
        primary=v['security_result'].replace('_',' ')
        if width<24 or limit<10:
            short=[primary,'GET THE HACKER',v['data_state'],'Small screen. Use Mobile view.']
            return [line[:width] for value in short for line in wrap(value)][:limit]
        header=['GET THE HACKER'.center(width),'Live Wi-Fi Security Walk'.center(width),
                'MONITORING '+v['monitoring'],v['data_state'],
                'Walk Time '+v['walk_time'],
                'Networks Seen '+clean(v['networks_seen'])+' / Attack Signs '+clean(v['attack_signs']),
                'SECURITY RESULT: '+primary,
                'Checks '+str(len(a['rules_checked']))+'/'+str(len(a['rule_results']))+' / NOT ASSESSED '+str(len(a['rules_not_checked']))]
        if v['capture_title'] in ('NO WIFI INTERFACE','CAPTURE NOT AVAILABLE','WIDS NOT AVAILABLE','FRAMES DELAYED','NO FRESH FRAMES','EVIDENCE LIMIT','CAPTURE ERROR'):header.append(v['capture_title'])
        if v['synthetic']:header.insert(3,'SYNTHETIC DEMO')
        body=[]
        if self.page=='networks':
            rows=self._network_rows(record,v)
            if rows:
                self.selected=min(self.selected,(self._network_page.get('filtered',len(rows))-1 if self.all_networks and self._network_page else len(rows)-1))
            else:self.selected=0
            body+=['WI-FI NETWORKS AROUND YOU','GTH SENSOR','   | observed frames']
            if record.get('mode')=='managed':
                link=record.get('network_status') or {}
                body+=['LOCAL WI-FI LINK','SSID: '+clean(link.get('ssid')),'BSSID: '+clean(link.get('bssid')),'Signal: '+clean(link.get('rssi'))+' dBm','No WIDS radio frames were measured.']
            if self.all_networks:body+=['ALL NETWORKS / search: '+self.query,'Trust: '+self.trust_filter+' / Signs: '+str(self.signs_filter)]
            chosen=self.selected%20 if self.all_networks else self.selected
            if self.details and rows:
                n=rows[min(chosen,len(rows)-1)]
                body=['NETWORK DETAILS',n['display_name'],n.get('bssid'),
                      'Trust: '+n['trust'],'Channel: '+clean(n.get('channel')),'Signal: '+clean(n.get('rssi'))+' dBm',
                      'Last Seen: '+clean(n.get('last_seen')),'Attack Signs: '+str(n['attack_signs']),
                      'WHAT DOES THIS MEAN?',n['explanation'],'RSSI is not distance.']
            else:
                for i,n in enumerate(rows):
                    mark='>' if i==chosen else ' '
                    body+=[mark+' o '+n['display_name'],
                           '    '+n['trust']+(' / ATTACK SIGNS' if n['attack_signs'] else '')]
                if not rows:body+=['No AP frame was saved.']
                body+=['a VIEW ALL NETWORKS','Enter opens Network Details.']
        elif self.page=='checks':
            rows=v['checks'];self.selected=min(self.selected,max(0,len(rows)-1))
            if self.details and rows:
                r=rows[self.selected]
                body=['ATTACK CHECK: '+r['name'],'WHAT DOES GTH CHECK?',r['condition'],
                      'WHAT DID GTH SEE?',r['observed'],'Last checked group: '+json.dumps(r.get('last_window'),ensure_ascii=True),
                      'RESULT: '+r['display_state'],r['reason'],'WHAT DATA PROVES IT?',json.dumps(r['evidence_refs'],ensure_ascii=True),
                      'WHAT DOES THIS MEAN?',r['help']]
            else:
                body=['ATTACK CHECKS']+[(('> ' if i==self.selected else '  ')+r['name']+' / '+r['display_state']) for i,r in enumerate(rows)]
        elif self.page=='events':
            rows=event_rows(record);self.selected=min(self.selected,max(0,len(rows)-1))
            if self.details and rows:
                e=rows[self.selected];m=next((x for x in a['events'] if x.get('id')==e.get('id')),{})
                body=['SECURITY EVENT','WHAT HAPPENED?',m.get('fact','A rule event was saved.'),
                      'WHY DID GTH REPORT IT?',e.get('rule_id'),'BSSID: '+clean(e.get('bssid'))]+self._proof_text(e)+['WHAT SHOULD I DO?',m.get('action','Read the saved Evidence.')]
            else:body=['EVENTS / recent saved rows']+[(('> ' if i==self.selected else '  ')+str(e.get('id'))+' / '+str(e.get('rule_id'))) for i,e in enumerate(rows)]
            if not rows:body+=['No rule event was saved.','This does not prove a safe network.']
        else:
            words=list(GLOSSARY);self.selected=min(self.selected,len(words)-1)
            body=['HELP / ENTER OPENS A TERM']
            if self.details:body+=[words[self.selected],GLOSSARY[words[self.selected]],'Arrow keys scroll. Esc returns.']
            else:body +=[(('> ' if i==self.selected else '  ')+word) for i,word in enumerate(words)]
        if not self.details:body+=['Radio: '+clean(v.get('interface'))+' / CH '+clean(v.get('channel'))]
        if report:body+=['Reports: '+report]
        if self._final and self.extra.get('REPORT'):body+=['Report folder: '+str(self.extra['REPORT'])]
        flat=[line for value in body for line in wrap(value)]
        head=[line for value in header for line in wrap(value)]
        footer=(['Saved session. Open report.html.'] if self._final else
                ['1 NETWORKS  2 CHECKS  3 EVENTS  4 HELP','Tab / arrows / Enter / Esc / q Stop'] if self._input_state is not None else
                ['Read-only terminal. Use Mobile view.'])
        foot=[line for value in footer for line in wrap(value)]
        space=max(1,limit-len(head)-len(foot)-1)
        if not self.details and self.page in ('checks','events','help'):
            marker=next((i for i,line in enumerate(flat) if line.startswith('> ')),self.selected)
            if marker<self.scroll:self.scroll=marker
            elif marker>=self.scroll+space:self.scroll=marker-space+1
        self.scroll=min(self.scroll,max(0,len(flat)-space))
        visible=flat[self.scroll:self.scroll+space]
        result=head[:limit]+['-'*width]+visible+foot
        return [line[:width] for line in result[:limit]]

    def _draw_screen(self, lines, size, result):
        if self.failed:return False
        changed=self._last_size!=size or not self._last_lines
        output='\x1b[2J\x1b[H\x1b[?25l' if changed else ''
        for i in range(min(max(1,size[1]-1),len(lines) if changed else max(len(lines),len(self._last_lines)))):
            line=lines[i] if i<len(lines) else ''
            old=self._last_lines[i] if i<len(self._last_lines) else None
            if changed or line!=old:
                color=''
                if 'NO_COLOR' not in os.environ:
                    if ('SECURITY RESULT:' in line and result=='DETECTED') or 'ATTACK SIGNS' in line:color='\x1b[31m'
                    elif 'SECURITY RESULT:' in line and result=='NOT_DETECTED':color='\x1b[32m'
                    elif 'SECURITY RESULT:' in line:color='\x1b[37m'
                output+=f'\x1b[{i+1};1H\x1b[2K'+color+line+('\x1b[0m' if color else '')+'\n'
        try:
            stream=self.stream or sys.stdout;stream.write(output);stream.flush()
            self._last_lines=list(lines);self._last_size=size;return True
        except (OSError,UnicodeError) as error:
            self.failed=True;self.last_error=error;self.close();return False

    def update(self,record,final=False,report=None):
        if self.failed:return False
        if self.finished:return True
        if not self.probed and not self._ansi():
            self.probed=True
            try:
                (self.stream or sys.stdout).write('')
            except (OSError,UnicodeError) as error:
                self.failed=True;self.last_error=error;return False
        a=assess(record)
        if self._ansi():
            try:
                self._record=record;self._final=final
                self._start_input();self._poll_input()
                size=shutil.get_terminal_size((80,24))
                lines=self.render_screen(record,size.columns,size.lines,a,report)
                result=self._draw_screen(lines,(size.columns,size.lines),a['hacker_activity'])
                self.finished=final
                if final:self.close()
                return result
            except Exception as error:
                # UI faults must not stop Capture. Ctrl+C still reaches the caller.
                self.failed=True;self.last_error=error;self.close();return False
        source=record.get('source') or {};gps=record.get('sensor_gps') or {}
        start=record.get('started_at');end=record.get('ended_at',record.get('updated_at',time.time()))
        seconds=max(0,int(end-start)) if isinstance(start,(int,float)) and isinstance(end,(int,float)) else None
        duration=(f'{seconds//3600:02}:{seconds//60%60:02}:{seconds%60:02}' if seconds is not None else None)
        networks=a['networks'];trusted=sum(n['baseline_state']=='match' for n in networks)
        rows=[('Monitoring', 'STOPPED' if final else 'ACTIVE' if record.get('capture_active') else record.get('status','WAIT')),
          ('Interface',source.get('interface')),('Mode',str(record.get('mode','N/A')).upper()),
          ('Channel',a['observed_channel']),('Duration',duration),('Frames received',a['frames_received']),
          ('Frames analyzed',a['frames_analyzed']),('Frames dropped',a['frames_dropped']),
          ('Networks found',a['networks_observed']),('Trusted APs',trusted),('Unknown APs',len(networks)-trusted)]
        rows.extend((r['name'],r['result'].replace('_',' ')) for r in a['rule_results'])
        rows.extend([('HACKER ACTIVITY',a['hacker_activity'].replace('_',' ')),('Capture quality',a['capture_quality']),('Capture state',a['capture_title']),
                     ('Evidence',a['proof_check_state']),('Monitoring errors',len(record.get('errors') or [])),
                     ('Sensor GPS',f"{gps.get('lat')}, {gps.get('lon')}" if gps.get('status')=='valid' else 'No fix')])
        for key in ('Last network','BSSID','RSSI dBm','Last event','Source MAC'):
            if key in self.extra:rows.append((key,self.extra[key]))
        if 'ERROR' in self.extra:rows.append(('Error',self.extra['ERROR']))
        if 'WEB' in self.extra:rows.append(('Mobile view',self.extra['WEB']))
        if report:rows.append(('Reports',report))
        if final:rows.append(('Report folder',self.extra.get('REPORT')))
        if self._ansi() or final:
            result=self._draw(rows,red=a['hacker_activity']=='DETECTED')
        else:result=True
        self.finished=final
        return result
