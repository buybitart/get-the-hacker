'use strict';
window.GTHWalk=(()=>{
 const V=window.GTHViz,$=id=>document.getElementById(id),el=V.node,ns='http://www.w3.org/2000/svg';
 const value=v=>v===null||v===undefined||typeof v==='number'&&!Number.isFinite(v)?'N/A':String(v),time=V.stamp;
 const set=(id,v)=>{const n=$(id);if(n)n.textContent=value(v);};
 const svg=(tag,attrs,text)=>{const n=document.createElementNS(ns,tag);for(const[k,v]of Object.entries(attrs||{}))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;};
 function hero(data){const w=data.walk;set('monitoring','MONITORING '+w.monitoring);set('freshness',w.data_state);set('walk-time',w.walk_time);set('networks-seen',w.networks_seen);set('attack-signs',w.attack_signs);set('security-result',w.security_result.replaceAll('_',' '));set('result-explanation',w.explanation);set('radio-scope','Interface: '+value(w.interface)+' / Channel: '+value(w.channel)+' / '+value(w.capture_title));
  $('result-box')?.setAttribute('data-result',w.security_result);if($('demo-note'))$('demo-note').hidden=!w.synthetic;
 }
 function map(target,nodes,onSelect){
  const focused=document.activeElement?.closest('.ap-node')?.dataset.bssid;target.replaceChildren();const allNodes=nodes;const width=Math.max(260,target.clientWidth||340);nodes=nodes.slice(0,width<600?3:6);const cols=width<600?2:3,gap=12,cardW=(width-gap*(cols+1))/cols,rows=Math.ceil(nodes.length/cols),height=100+rows*100;
  const plot=svg('svg',{viewBox:`0 0 ${width} ${Math.max(170,height)}`,role:'img','aria-label':'Observed Wi-Fi APs. Lines show received frames. This is not a location map.'});plot.style.width='100%';plot.style.height=Math.max(170,height)+'px';
  plot.append(svg('rect',{x:width/2-65,y:10,width:130,height:42,rx:6,class:'sensor-mark'}),svg('text',{x:width/2,y:36,'text-anchor':'middle',class:'map-label'},'GTH SENSOR'));
  if(!nodes.length)plot.append(svg('text',{x:width/2,y:115,'text-anchor':'middle',class:'map-label'},'No AP frame was saved.'));
  nodes.forEach((n,i)=>{const x=gap+(i%cols)*(cardW+gap),y=90+Math.floor(i/cols)*100,cx=x+cardW/2;
   plot.append(svg('path',{d:`M${width/2} 52V68H${cx}V${y}`,class:'observation-line'}));
   const g=svg('g',{class:'ap-node'+(n.attack_signs>0?' has-signs':''),role:'button',tabindex:0,'aria-label':n.display_name+' / '+n.trust+' / Attack Signs '+n.attack_signs});
   g.dataset.bssid=n.bssid;g.append(svg('rect',{x,y,width:cardW,height:80,rx:7}),svg('title',{},n.display_name+' / '+value(n.bssid)));
   const label=svg('text',{x:cx,y:y+23,'text-anchor':'middle',class:'map-label'},n.display_name),trust=svg('text',{x:cx,y:y+45,'text-anchor':'middle',class:'map-small'},n.trust),sign=svg('text',{x:cx,y:y+64,'text-anchor':'middle',class:'map-small'},n.attack_signs>0?'ATTACK SIGNS '+n.attack_signs:'LAST SEEN');g.append(label,trust,sign);
   g.onclick=()=>onSelect(n);g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelect(n);}};plot.append(g);
   // Fit actual glyph widths. Full names stay in Network Details.
   requestAnimationFrame(()=>{let chars=Array.from(n.display_name);while(chars.length>1&&label.getComputedTextLength()>cardW-20){chars.pop();label.textContent=chars.join('')+'…';}});
  });target.append(plot,el('p',nodes.length+' APs shown. View All Networks has the full list.','report-note'));if(focused)[...plot.querySelectorAll('.ap-node')].find(g=>g.dataset.bssid===focused)?.focus({preventScroll:true});target._nodes=allNodes;target._select=onSelect;target._drawWidth=target.clientWidth;if(window.ResizeObserver&&!target._mapObserver){target._mapObserver=new ResizeObserver(()=>{if(target.clientWidth>0&&target.clientWidth!==target._drawWidth)map(target,target._nodes||[],target._select||(()=>{}));});target._mapObserver.observe(target);}
 }
 function fieldList(rows){const list=el('dl',undefined,'field-list'),aliases={'Signal':'RSSI','RSSI dBm':'RSSI','Source MAC':'MAC Address','Trust':'Trusted','Rule ID':'WIDS'};
  for(const[k,v]of rows){const box=el('div'),dt=el('dt'),term=aliases[k]||k;
   if(['SSID','BSSID','RSSI','MAC Address','Channel','Trusted','WIDS','GPS','SHA-256'].includes(term)){const b=el('button',k,'term');b.type='button';b.dataset.term=term;dt.append(b);}else dt.textContent=k;
   box.append(dt,el('dd',value(v)));list.append(box);}return list;
 }
 function networkDetails(dialog,n){
  const body=dialog.querySelector('[data-dialog-body]'),rows=[['Trust',n.trust],['BSSID',n.bssid],['Channel',n.channel],['Signal',n.rssi==null?'N/A':n.rssi+' dBm'],['Last Seen',time(n.last_seen)],['Attack Signs',n.attack_signs]];
  if(body.dataset.network===n.bssid&&body._fields){body.querySelector('h2').textContent=n.display_name;body._fields.querySelectorAll('dd').forEach((e,i)=>e.textContent=value(rows[i][1]));body._explanation.textContent=n.explanation;}
  else{body.replaceChildren(el('h2',n.display_name));const fields=fieldList(rows),p=el('p',n.explanation);body.append(fields,el('h3','WHAT DOES THIS MEAN?'),p,el('p','RSSI is not distance. An AP address can be copied.'));body.dataset.network=n.bssid;body._fields=fields;body._explanation=p;}
  if(!dialog.open)dialog.showModal();
 }
 function checks(target,rows){const open=new Set([...target.querySelectorAll('details[open]')].map(d=>d.dataset.rule));const focused=document.activeElement?.closest('[data-rule]')?.dataset.rule;target.replaceChildren();
  for(const r of rows){const d=el('details',undefined,'check-row');d.dataset.rule=r.rule_id;d.open=open.has(r.rule_id);const s=el('summary');s.append(el('span',r.name),el('strong',r.display_state,'state-'+r.display_state.replaceAll(' ','-').toLowerCase()));d.append(s,el('h3','WHAT DOES GTH CHECK?'),el('p',r.help),el('p',r.condition),el('h3','WHAT DID GTH SEE?'),el('p',r.observed));
   if(r.last_window)d.append(fieldList(Object.entries(r.last_window)));else d.append(el('p','Window values were not saved for this check.'));
   d.append(el('h3','RESULT'),el('p',r.reason),el('h3','WHAT DATA PROVES IT?'),el('p',r.evidence_ref_count+' references in the available event details.'));
   const refs=el('pre',JSON.stringify(r.evidence_refs,null,2));d.append(refs,el('p','A rule match does not identify a person.'));target.append(d);
  }
  if(focused)target.querySelector('[data-rule="'+focused+'"] summary')?.focus({preventScroll:true});
 }
 function eventCards(target,rows,onEvidence,search=''){
  target.replaceChildren();const query=search.casefold?.()??search.toLowerCase();const shown=rows.filter(e=>JSON.stringify([e.id,e.rule_id,e.bssid,e.source,e.attack_method]).toLowerCase().includes(query)).slice(0,100);
  for(const e of shown){const m=e.meaning||{},card=el('article',undefined,'event-card');card.append(el('h3',value(e.id)+' / '+value(e.attack_method||e.rule_id)),el('p',time(e.timestamp)),el('h4','WHAT HAPPENED?'),el('p',m.fact||'A rule event was saved.'),el('h4','WHY DID GTH REPORT IT?'),el('p',m.meaning||'The saved rule matched these messages.'),el('h4','WHAT DATA PROVES IT?'),el('p',m.proof_note||'Read the saved Proof status.'),el('h4','WHAT SHOULD I DO?'),el('p',m.action||'Read the saved Evidence.'));
   const b=el('button','Open Evidence');b.type='button';b.onclick=()=>onEvidence(e);card.append(b);target.append(card);
  }
  if(!shown.length)target.append(el('p',query?'No event matches this search.':'No rule event was saved. This does not prove a safe network.'));
 }
 function safeProof(event,kind){const id=String(event.id||''),path='proofs/'+id+'.'+kind;return /^GTH-[0-9]{6,12}$/.test(id)&&event.proof?.[kind+'_path']===path?path:null;}
 function evidence(dialog,event){const body=dialog.querySelector('[data-dialog-body]');body.replaceChildren(el('h2','Evidence / '+value(event.id)),el('p','Source MAC is not a person ID.'),fieldList([['Rule ID',event.rule_id],['UTC',time(event.timestamp)],['BSSID',event.bssid],['Source MAC',event.source],['Channel',event.channel],['RSSI dBm',event.rssi],['Proof status',event.meaning?.proof_state||event.proof?.status]]),el('pre',JSON.stringify(event.evidence||{},null,2)));
  for(const kind of ['json','html']){const path=safeProof(event,kind);if(path){const a=el('a',kind==='json'?'Open full Proof JSON':'Open Proof HTML','button-link');a.href=path;a.target='_blank';a.rel='noopener';body.append(a);}}
  if(!dialog.open)dialog.showModal();return body;
 }
 function networks(target,rows,onSelect){target.replaceChildren();for(const n of rows){const b=el('button',undefined,'network-list-row');b.type='button';b.append(el('strong',n.display_name),el('span',n.trust+' / Signs '+n.attack_signs),el('small',value(n.bssid)+' / '+time(n.last_seen)));b.onclick=()=>onSelect(n);target.append(b);}if(!rows.length)target.append(el('p','No network matches this filter.'));}
 function glossary(target,terms){target.replaceChildren();for(const[k,v]of Object.entries(terms)){const d=el('details');d.append(el('summary',k),el('p',v));target.append(d);}V.dictionary(terms);}
 window.addEventListener('resize',()=>document.querySelectorAll('[data-network-map]').forEach(t=>map(t,t._nodes||[],t._select||(()=>{}))));
 return {hero,map,fieldList,networkDetails,checks,eventCards,evidence,networks,glossary,safeProof,set,value,time};
})();
