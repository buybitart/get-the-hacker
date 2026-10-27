'use strict';
(()=>{
 const UI=window.GTHWalk,V=window.GTHViz,$=id=>document.getElementById(id);
 let data=null,session=null,generation=0,offset=0,filtered=null,busy=false,timer=null,selected=null,termsReady=false,networkRequest=0,evidenceRequest=0;
 const signals=new Map();
 function tabs(name){for(const b of document.querySelectorAll('[data-page]')){const on=b.dataset.page===name;b.setAttribute('aria-selected',String(on));$('panel-'+b.dataset.page).hidden=!on;}const q=new URLSearchParams(location.search);q.set('tab',name);history.replaceState(null,'','?'+q);}
 document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>tabs(b.dataset.page));
 document.querySelectorAll('[data-close-dialog]').forEach(b=>b.onclick=()=>b.closest('dialog').close());
 const first=new URLSearchParams(location.search).get('tab');tabs(['networks','checks','events','help'].includes(first)?first:'networks');
 function signal(){const rows=selected?signals.get(selected.bssid)||[]:[];V.chart($('live-signal'),rows,['rssi'],'dBm',{low:-127,high:0,gap:10,source:'Source: actual AP observations in this browser view. This is not full radio history.'});}
 function selectNetwork(n){selected=n;UI.networkDetails($('network-dialog'),n);signal();}
 function events(){if(data)UI.eventCards($('security-events'),data.visible_events||data.alerts||[],openEvidence,$('event-search').value);}
 async function openEvidence(e){const body=UI.evidence($('evidence-dialog'),e),path=UI.safeProof(e,'json'),epoch=generation,request=++evidenceRequest;if(!path)return;
  const state=V.node('p','Checking the saved Proof file.');body.append(state);
  try{const response=await fetch('/'+path,{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error('File not available');const raw=await response.arrayBuffer();if(raw.byteLength>8*1024*1024)throw Error('File too large');if(epoch!==generation||request!==evidenceRequest)return;
   const expected=e.proof?.sha256?.json;if(expected&&crypto.subtle){const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');if(epoch!==generation||request!==evidenceRequest)return;if(hash!==expected)throw Error('Hash check failed');state.textContent='File SHA-256 matches the saved hash.';}else state.textContent='The browser did not check the file hash.';
   const doc=JSON.parse(new TextDecoder().decode(raw)),detail=V.node('details');detail.append(V.node('summary','Full saved Proof'),V.node('pre',JSON.stringify(doc,null,2)));body.append(detail);
  }catch(_){if(epoch===generation&&request===evidenceRequest)state.textContent='Proof file check failed. Keep the saved files for review.';}
 }
 async function loadNetworks(){if($('all-networks').hidden||!data)return;const request=++networkRequest,epoch=generation;const q=new URLSearchParams({offset:String(offset),limit:'50',search:$('network-search').value,trust:$('trust-filter').value,signs:$('signs-filter').checked?'1':'0'});
  try{const response=await fetch('/api/networks?'+q,{cache:'no-store',signal:AbortSignal.timeout(4000)});if(!response.ok)throw Error();const page=await response.json();if(epoch!==generation||request!==networkRequest||page.session_id!==session)return;
   filtered=page.filtered;UI.networks($('network-list'),page.networks,selectNetwork);$('network-scope').textContent=page.networks.length+' shown / '+UI.value(filtered)+' match / '+UI.value(page.total)+' APs seen. Sorted by Last Seen.'+(page.history_state==='unavailable'?' AP history is partial. Raw frames stay saved.':'');$('previous-networks').disabled=offset===0;$('next-networks').disabled=page.networks.length<50||typeof filtered==='number'&&offset+page.networks.length>=filtered;
  }catch(_){if(epoch===generation)$('network-scope').textContent='Network list is not available. Capture can still run.';}
 }
 $('view-all').onclick=()=>{$('all-networks').hidden=!$('all-networks').hidden;offset=0;loadNetworks();};
 let searchTimer;for(const id of ['network-search','trust-filter','signs-filter'])$(id).addEventListener(id==='network-search'?'input':'change',()=>{offset=0;clearTimeout(searchTimer);searchTimer=setTimeout(loadNetworks,200);});
 $('previous-networks').onclick=()=>{offset=Math.max(0,offset-50);loadNetworks();};$('next-networks').onclick=()=>{offset+=50;loadNetworks();};$('event-search').oninput=events;
 function render(record){
  const id=record.walk.session_id;if(session!==id){session=id;generation++;signals.clear();offset=0;selected=null;networkRequest++;$('network-dialog').close();$('evidence-dialog').close();V.resetCharts();$('live-signal').replaceChildren();$('live-signal')._redraw=null;$('network-list').replaceChildren();}
  data=record;$('result-box').classList.toggle('stale-result',record.walk.data_state==='DATA NOT FRESH');UI.hero(record);UI.map($('network-map'),record.walk.nodes,selectNetwork);UI.checks($('attack-checks'),record.walk.checks);events();
  if(!termsReady){UI.glossary($('glossary'),record.glossary||{});termsReady=true;}
  V.flow($('live-flow'),record);V.detection($('detection-flow'),record);
  $('sensor-health').replaceChildren(UI.fieldList([['Capture quality',record.assessment.capture_quality],['Capture state',record.assessment.capture_title],['Frames received',record.assessment.frames_received],['Frames analyzed',record.assessment.frames_analyzed],['Frames dropped',record.assessment.frames_dropped],['Queue pending',record.queue?.pending],['Capture lag s',record.capture_diagnostics?.capture_lag_s],['Rules checked',record.assessment.rules_checked.length],['Rules not assessed',record.assessment.rules_not_checked.length]]));
  if(record.mode==='managed'&&record.network_status){const link=record.network_status;$('sensor-health').append(V.node('h3','Local Wi-Fi Link'),UI.fieldList([['SSID',link.ssid],['BSSID',link.bssid],['Signal',link.rssi==null?'N/A':link.rssi+' dBm'],['Link',link.connected===true?'Connected':link.connected===false?'Not connected':'N/A']]),V.node('p','Local link only. No WIDS radio frames were measured.'));}
  const gps=record.sensor_gps||{};$('sensor-gps').textContent=gps.status==='valid'?'Sensor GPS: '+gps.lat+', '+gps.lon+' / Error '+gps.accuracy_m+' m / '+UI.time(gps.timestamp):gps.reason||'No sensor GPS fix.';
  V.chart($('live-rate'),record.rates||[],['received','analyzed','dropped'],'frames/s',{gap:10,source:'Source: saved telemetry counters. Rates use measured time intervals.'});
  for(const n of record.networks||[]){if(typeof n.rssi!=='number'||typeof n.last_seen!=='number')continue;let points=signals.get(n.bssid);if(!points){if(signals.size>=100)continue;points=[];signals.set(n.bssid,points);}if(points.at(-1)?.timestamp!==n.last_seen){points.push({timestamp:n.last_seen,rssi:n.rssi});if(points.length>120)points.shift();}}
  if(selected){const latest=record.networks.find(n=>n.bssid===selected.bssid);if(latest){const node=record.walk.nodes.find(n=>n.bssid===selected.bssid);if(node)selected=node;}if($('network-dialog').open){UI.networkDetails($('network-dialog'),selected);signal();}}
  if(!$('all-networks').hidden)loadNetworks();document.documentElement.dataset.ready='true';
 }
 async function poll(){if(busy)return;busy=true;clearTimeout(timer);try{const response=await fetch('/api/state',{cache:'no-store',signal:AbortSignal.timeout(4000)});if(!response.ok)throw Error();render(await response.json());}catch(_){$('freshness').textContent='DATA NOT FRESH';$('monitoring').textContent='MONITORING NOT ASSESSED';$('result-box').classList.add('stale-result');if(data)$('security-result').textContent='LAST RESULT: '+data.walk.security_result.replaceAll('_',' ');$('result-explanation').textContent=data?'The last saved result stays visible. The connection is lost.':'Live data is not available.';}finally{busy=false;timer=setTimeout(poll,document.hidden?10000:2000);}}
 document.addEventListener('visibilitychange',()=>{if(!document.hidden){$('freshness').textContent='DATA NOT FRESH';poll();}});
 if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});
 fetch('/api/glossary').then(r=>r.ok?r.json():{}).then(terms=>{if(!termsReady&&Object.keys(terms).length){UI.glossary($('glossary'),terms);termsReady=true;}}).catch(()=>{});
 poll();
})();
