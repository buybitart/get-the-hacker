"""Stream saved frame counts and AP RSSI into bounded time buckets."""
import math
import re


from .values import finite

def frame_series(events,start=None,end=None):
    width=30;bins={};first=None;last=None;invalid=0;count=0;kinds={};names={};omitted=0;seen={}
    lower=start if finite(start) else None;upper=end if finite(end) else None
    if lower is not None and upper is not None and upper>=lower:
        width*=max(1,math.ceil((upper-lower)/(719*width)))
    def empty():return {'count':0,'by_kind':{},'ap':{}}
    def merge(dst,src):
        dst['count']+=src['count']
        for k,n in src['by_kind'].items():dst['by_kind'][k]=dst['by_kind'].get(k,0)+n
        for mac,row in src['ap'].items():
            if mac not in dst['ap']:dst['ap'][mac]=dict(row)
            else:
                d=dst['ap'][mac];d['count']+=row['count'];d['sum']+=row['sum'];d['min']=min(d['min'],row['min']);d['max']=max(d['max'],row['max'])
    for e in events:
        if not isinstance(e,dict) or not finite(e.get('timestamp')) or e['timestamp']<0:
            invalid+=1;continue
        stamp=e['timestamp'];first=stamp if first is None else min(first,stamp);last=stamp if last is None else max(last,stamp)
        lo=min(first,lower) if lower is not None else first;hi=max(last,upper) if upper is not None else last
        factor=max(1,math.ceil((hi-lo)/(719*width)))
        if factor>1:
            width*=factor;old=bins;bins={}
            for key,row in old.items():merge(bins.setdefault(math.floor(key/width)*width,empty()),row)
        key=math.floor(stamp/width)*width;row=bins.setdefault(key,empty());row['count']+=1;count+=1
        kind=e.get('kind') if isinstance(e.get('kind'),str) else 'unknown'
        kinds[kind]=kinds.get(kind,0)+1;row['by_kind'][kind]=row['by_kind'].get(kind,0)+1
        mac=e.get('bssid');signal=e.get('rssi')
        usable_ap=kind in ('beacon','probe_response') and isinstance(mac,str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac) and not int(mac[:2],16)&1 and not e.get('bad_fcs')
        if usable_ap:
            entry=seen.setdefault(mac,{'bssid':mac,'first_seen':stamp,'last_seen':stamp,'ssid':e.get('ssid')})
            entry['first_seen']=min(entry['first_seen'],stamp);entry['last_seen']=max(entry['last_seen'],stamp)
            if isinstance(e.get('ssid'),str) and e['ssid']:entry['ssid']=e['ssid']
        if usable_ap and e.get('source')==mac and finite(signal) and -127<=signal<=0:
            if mac not in names:
                if len(names)>=1024:omitted+=1;continue
                names[mac]=e.get('ssid')
            state=row['ap'].setdefault(mac,{'count':0,'sum':0,'min':signal,'max':signal})
            state['count']+=1;state['sum']+=signal;state['min']=min(state['min'],signal);state['max']=max(state['max'],signal)
    buckets=[];rssi=[]
    if first is not None:
        lo=min(first,lower) if lower is not None else first;hi=max(last,upper) if upper is not None else last
        keys=list(range(int(math.floor(lo/width)*width),int(math.floor(hi/width)*width)+1,width))
        for key in keys:
            row=bins.get(key,empty());buckets.append({'timestamp':key,'end':key+width,'count':row['count'],'by_kind':row['by_kind']})
        observed={mac:[] for mac in names}
        for key in sorted(bins):
            for mac,row in bins[key]['ap'].items():
                observed[mac].append({'timestamp':key,'count':row['count'],'mean':row['sum']/row['count'],'min':row['min'],'max':row['max']})
        def missing(stamp):return {'timestamp':stamp,'count':0,'mean':None,'min':None,'max':None}
        for mac,ssid in names.items():
            points=[];samples=0;previous=None
            for point in observed[mac]:
                if previous is None and point['timestamp']>keys[0]:points.append(missing(keys[0]))
                if previous is not None and point['timestamp']-previous>width:points.append(missing(previous+width))
                points.append(point);samples+=point['count'];previous=point['timestamp']
            if previous is not None and previous<keys[-1]:points.append(missing(keys[-1]))
            rssi.append({'bssid':mac,'ssid':seen.get(mac,{}).get('ssid') or ssid,'samples':samples,'points':points})
    first_seen=sorted(seen.values(),key=lambda n:(n['first_seen'],n['bssid']))
    network_timeline=[{'timestamp':n['first_seen'],'count':i+1,'bssid':n['bssid']} for i,n in enumerate(first_seen)]
    return {'schema_version':1,'source':'events.jsonl','bucket_seconds':width,'event_count':count,'event_kinds':kinds,
            'network_count':len(seen),'network_first_seen':first_seen,'networks_seen_timeline':network_timeline,'invalid_rows':invalid,'event_buckets':buckets,'rssi_networks':rssi,'omitted_signal_samples':omitted,
            'methods':{'events':'Count every saved row by frame timestamp. Empty buckets mean no saved row.',
                       'rssi':'Use AP beacon and Probe Response RSSI. Keep mean, min, max, and sample count. One null point marks each missing range.',
                       'buckets':'Start at 30 seconds. Use a larger whole multiple if the span needs more than 720 buckets.'},
            'limits':['Missing RSSI is null. No interpolation.','RSSI is not distance.','At most 1024 AP signal series. Other raw rows stay in events.jsonl.']}
