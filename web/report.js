'use strict';
(()=>{
 const data=JSON.parse(document.getElementById('chart-data').textContent),UI=window.GTHWalk,V=window.GTHViz,$=id=>document.getElementById(id);let offset=0;
 V.dictionary(data.glossary);V.flow($('report-flow'),data.record);V.detection($('detection-flow'),data.record);
 const select=n=>UI.networkDetails($('network-dialog'),n),open=e=>UI.evidence($('evidence-dialog'),e);
 UI.map($('network-map'),data.record.walk.nodes,select);UI.checks($('attack-checks'),data.record.walk.checks);
 const events=()=>UI.eventCards($('security-events'),data.events,open,$('event-search').value);$('event-search').oninput=events;events();
 function networks(){const q=$('network-search').value.toLowerCase(),trust=$('trust-filter').value,signs=$('signs-filter').checked;const rows=data.networks.filter(n=>(n.display_name+' '+n.bssid).toLowerCase().includes(q)&&(trust==='all'||(n.trust==='TRUSTED')===(trust==='trusted'))&&(!signs||n.attack_signs>0)).sort((a,b)=>(b.last_seen||0)-(a.last_seen||0)||String(a.bssid).localeCompare(String(b.bssid)));const shown=rows.slice(offset,offset+50);UI.networks($('network-list'),shown,select);$('network-scope').textContent=shown.length+' shown / '+rows.length+' match / '+data.networks.length+' saved APs.';$('previous-networks').disabled=offset===0;$('next-networks').disabled=offset+50>=rows.length;}
 $('view-all').onclick=()=>{$('all-networks').hidden=!$('all-networks').hidden;networks();};for(const id of ['network-search','trust-filter','signs-filter'])$(id).addEventListener(id==='network-search'?'input':'change',()=>{offset=0;networks();});$('previous-networks').onclick=()=>{offset=Math.max(0,offset-50);networks();};$('next-networks').onclick=()=>{offset+=50;networks();};
 document.querySelectorAll('[data-close-dialog]').forEach(b=>b.onclick=()=>b.closest('dialog').close());
 V.chart($('frames-chart'),data.timeline,['received','packets','events'],'frames',{gap:10,monotonic:true,source:'Source: telemetry.jsonl. Counts are cumulative.'});
 V.chart($('networks-chart'),data.series.networks_seen_timeline||[],['count'],'APs',{step:true,monotonic:true,source:'Source: first saved Beacon or Probe Response for each BSSID.'});
 V.chart($('indicators-chart'),data.indicators,['count'],'saved signs',{step:true,source:'Source: saved events and verified Proof. Capture gaps can hide signs.'});
 V.bars($('checks-chart'),data.check_counts,'rules');
 V.chart($('health-chart'),data.timeline,['queue_drops','invalid'],'frames',{gap:10,monotonic:true,source:'Source: telemetry.jsonl. Queue loss and decode errors are separate counts.'});
 const signals=data.series.rssi_networks||[];signals.forEach((n,i)=>{const o=V.node('option',(n.ssid||'SSID not saved')+' / '+n.bssid);o.value=String(i);$('signal-ap').append(o);});
 function signal(){const n=signals[Number($('signal-ap').value)];V.chart($('signal-chart'),n?.points||[],['mean'],'dBm',{low:-127,high:0,gap:(data.series.bucket_seconds||30)*2,source:'Source: saved AP Beacons and Probe Responses. Each point is a bucket mean.'});}
 $('signal-ap').disabled=!signals.length;$('signal-ap').onchange=signal;signal();$('frames-chart').before(V.node('p',data.chart_scope));
 function mode(technical){document.body.dataset.view=technical?'technical':'simple';$('simple-view').setAttribute('aria-pressed',String(!technical));$('technical-view').setAttribute('aria-pressed',String(technical));document.querySelector('.technical-appendix').open=technical;const q=new URLSearchParams(location.search);q.set('view',technical?'technical':'simple');try{history.replaceState(null,'','?'+q+location.hash);}catch(_){}}
 $('simple-view').onclick=()=>mode(false);$('technical-view').onclick=()=>mode(true);if(new URLSearchParams(location.search).get('view')==='technical')mode(true);
 $('section-select').onchange=()=>{location.hash=$('section-select').value;};
 const observer=new IntersectionObserver(entries=>{for(const e of entries)if(e.isIntersecting){const id=e.target.id;document.querySelectorAll('.section-nav a').forEach(a=>a.setAttribute('aria-current',String(a.hash==='#'+id)));$('section-select').value=id;}},{rootMargin:'-10% 0px -70% 0px'});document.querySelectorAll('[data-section]').forEach(s=>observer.observe(s));document.documentElement.dataset.ready='true';
})();
