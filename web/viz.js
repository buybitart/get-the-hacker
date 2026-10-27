'use strict';
window.GTHViz=(()=>{
 const ns='http://www.w3.org/2000/svg',finite=v=>typeof v==='number'&&Number.isFinite(v);
 const node=(tag,value,cls)=>{const n=document.createElement(tag);if(value!==undefined)n.textContent=value;if(cls)n.className=cls;return n;};
 const svgNode=(tag,attrs,value)=>{const n=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs||{}))n.setAttribute(k,String(v));if(value!==undefined)n.textContent=value;return n;};
 const stamp=t=>finite(t)&&Number.isFinite(new Date(t*1000).getTime())?new Date(t*1000).toISOString():'Not recorded';
 let terms={};
 function dictionary(values){
  terms=values||terms;let dlg=document.getElementById('term-dialog');
  if(!dlg){dlg=node('dialog');dlg.id='term-dialog';const h=node('h2');h.id='term-title';const p=node('p');p.id='term-text';dlg.setAttribute('aria-labelledby',h.id);const b=node('button','Close');b.type='button';b.onclick=()=>dlg.close();dlg.append(h,p,b);document.body.append(dlg);}
  if(!document.documentElement.dataset.termHandler){document.documentElement.dataset.termHandler='true';document.addEventListener('click',event=>{const b=event.target.closest?.('[data-term]');if(!b)return;document.getElementById('term-title').textContent=b.dataset.term;document.getElementById('term-text').textContent=terms[b.dataset.term]||'Read the saved rule details.';document.getElementById('term-dialog').showModal();});}
 }
 function chart(target,input,keys,unit,options={}){
  target.replaceChildren();target._redraw=null;const rows=(input||[]).filter(p=>p&&finite(p.timestamp));
  if(!rows.length||!rows.some(p=>keys.some(k=>finite(p[k])))){target.append(node('p','Data is not available for this chart.'));return;}
  const controls=node('div',undefined,'chart-controls'),range=node('select'),label=node('label','Time range '),description=node('p',undefined,'chart-point');
  for(const [v,t] of [['all','Full range'],['quarter','Last quarter']]){const o=node('option',t);o.value=v;range.append(o);}label.append(range);controls.append(label);
  const slider=node('input');slider.type='range';slider.min='0';slider.max=String(rows.length-1);slider.value=slider.max;slider.setAttribute('aria-label','Chart point');controls.append(slider);
  const svg=svgNode('svg',{role:'img','aria-label':unit+' / '+keys.join(', ')});svg.style.width='100%';svg.style.height='230px';
  target.append(controls,svg,description,node('p',(options.source||'Source: saved telemetry.')+' Unit: '+unit+'. Gaps stay blank. Tap a point or use Chart point. Lines show at most 720 sampled points.'));
  const colors=['#9ddde8','#b4c8ff','#e7edf3'];
  function selected(){const r=rows[Number(slider.value)];description.textContent=stamp(r.timestamp)+' | '+keys.map(k=>k+': '+(finite(r[k])?Number(r[k].toFixed(3))+' '+unit:'Not recorded')).join(' | ');}
  function draw(){
   const visible=range.value==='quarter'?rows.slice(Math.floor(rows.length*.75)):rows;
   const width=Math.max(250,target.clientWidth||500);target._plotWidth=target.clientWidth;const left=55,right=width-14,top=30,bottom=175;
   svg.replaceChildren();svg.setAttribute('viewBox',`0 0 ${width} 230`);
   let minimum=0,maximum=0;for(const r of visible)for(const k of keys)if(finite(r[k])){minimum=Math.min(minimum,r[k]);maximum=Math.max(maximum,r[k]);}const lo=options.low??minimum,hi=Math.max(lo+1,options.high??maximum);
   const start=visible[0].timestamp,end=visible.at(-1).timestamp,x=t=>left+(right-left)*(t-start)/(end-start||1),y=v=>bottom-(bottom-top)*(v-lo)/(hi-lo);
   svg.append(svgNode('path',{d:`M${left} ${top}V${bottom}H${right}`,fill:'none',stroke:'#7d8996'}));
   for(const [v,yy]of [[hi,top],[lo,bottom]])svg.append(svgNode('text',{x:4,y:yy,'font-size':12,fill:'currentColor'},Number(v.toFixed(2))));
   svg.append(svgNode('text',{x:left,y:205,'font-size':12,fill:'currentColor'},stamp(start).slice(11,19)),svgNode('text',{x:right,y:223,'text-anchor':'end','font-size':12,fill:'currentColor'},stamp(end).slice(11,19)));
   const stride=Math.max(1,Math.ceil((visible.length-1)/719));
   keys.forEach((k,index)=>{
    let path='',previous=null,lastTime=null,lastValue=null;
    visible.forEach((r,i)=>{if(lastTime!==null&&options.gap&&r.timestamp-lastTime>options.gap)previous=null;if(options.monotonic&&lastValue!==null&&finite(r[k])&&r[k]<lastValue)previous=null;lastTime=r.timestamp;lastValue=r[k];if(!finite(r[k])){previous=null;return;}if(i%stride&&i!==visible.length-1)return;
     const connected=previous&&r.timestamp>previous.timestamp&&(!options.gap||r.timestamp-previous.timestamp<=options.gap*stride);
     path+=(connected?(options.step?'H'+x(r.timestamp).toFixed(2)+'V'+y(r[k]).toFixed(2):'L'+x(r.timestamp).toFixed(2)+' '+y(r[k]).toFixed(2)):'M'+x(r.timestamp).toFixed(2)+' '+y(r[k]).toFixed(2));previous=r;
    });
    svg.append(svgNode('path',{d:path,fill:'none',stroke:colors[index%colors.length],'stroke-width':2}));
    const key=node('span',k);key.style.color=colors[index%colors.length];if(!controls.querySelector('[data-key="'+k+'"]')){key.dataset.key=k;controls.append(key);}
   });
   svg.onclick=e=>{const box=svg.getBoundingClientRect(),fraction=Math.max(0,Math.min(1,((e.clientX-box.left)*width/box.width-left)/(right-left)));const ts=start+fraction*(end-start);let best=0;for(let i=1;i<rows.length;i++)if(Math.abs(rows[i].timestamp-ts)<Math.abs(rows[best].timestamp-ts))best=i;slider.value=String(best);selected();};
   selected();
  }
  range.onchange=draw;slider.oninput=selected;target._redraw=draw;draw();if(window.ResizeObserver&&!target._observer){target._observer=new ResizeObserver(()=>{if(target.clientWidth>0&&target.clientWidth!==target._plotWidth)target._redraw?.();});target._observer.observe(target);}
 }
 function flow(target,record){
  target.replaceChildren();target.classList.add('flow');const a=record.assessment||{},c=record.counters||{};
  const state=record.data_source==='saved_session'?'Saved':record.capture_active===true?'Active':record.capture_active===false?'Stopped':'Not recorded';
  for(const [title,value,detail]of [
   ['Wi-Fi Frames',a.frames_received,'All channels in range are not checked. This is the recorded received count.'],
   ['Capture',state,'The adapter receives frames. Monitor Mode is needed for WIDS.'],
   ['Frame Analysis',a.frames_analyzed,'Valid decoded input enters the Engine. Skip and loss counts are separate.'],
   ['WIDS Rules',(a.rules_checked||[]).length+' checked','Each rule needs its own fields and time window.'],
   ['Security Result',(a.hacker_activity||'NOT_ASSESSED').replaceAll('_',' '),a.assessment_reason||'No complete result.'],
   ['Evidence',c.events,'These are saved event rows. Proof files apply to rule matches.']]){
    const d=node('details'),s=node('summary',title);d.append(s,node('strong',value??'Not recorded'),node('p',detail));target.append(d);
   }
 }
 function detection(target,record){
  target.replaceChildren();const a=record.assessment||{},w=record.walk||{},plot=svgNode('svg',{viewBox:'0 0 300 440',role:'group','aria-label':'Detection decision. Tap a stage for the saved data.'});plot.classList.add('decision-diagram');
  const detail=node('p','Tap a stage. Read its saved data.','decision-detail');detail.setAttribute('aria-live','polite');
  const line=(x,y,xx,yy)=>plot.append(svgNode('path',{d:`M${x} ${y}L${xx} ${yy}`,fill:'none',stroke:'#85929f','stroke-width':2}));
  const block=(x,y,width,labels,info,active=false)=>{const g=svgNode('g',{role:'button',tabindex:0,'aria-label':labels.join(' '),class:'decision-node'+(active?' current-result':'')});g.append(svgNode('rect',{x,y,width,height:48,rx:6}));labels.forEach((v,i)=>g.append(svgNode('text',{x:x+width/2,y:y+(labels.length>1?19:29)+i*17,'text-anchor':'middle','font-size':13},v)));const show=()=>{detail.textContent=info;};g.onclick=show;g.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();show();}};plot.append(g);};
  for(let y=56;y<248;y+=64)line(150,y,150,y+16);
  block(50,8,200,['Wi-Fi Message'],'Frames received: '+(a.frames_received??'Not recorded')+'. Capture can miss other channels.');
  block(50,72,200,['Read Frame'],'Frames analyzed: '+(a.frames_analyzed??'Not recorded')+'. Bad input does not enter rule checks.');
  block(50,136,200,['Check Rule'],(a.rules_checked||[]).length+' rules checked. '+(a.rules_not_checked||[]).length+' rules not assessed.');
  block(50,200,200,['Rule Match?'],'A saved, verified event is needed for DETECTED.');
  line(150,248,150,263);line(150,263,76,263);line(150,263,224,263);line(76,263,76,282);line(224,263,224,282);
  plot.append(svgNode('text',{x:65,y:277,'font-size':12,fill:'currentColor'},'No'),svgNode('text',{x:214,y:277,'font-size':12,fill:'currentColor'},'Yes'));
  block(6,284,140,['Enough Data?'],'A negative result needs valid input and enough rule time. Loss can limit this result.');
  block(160,284,134,['Save Evidence'],'Proof uses saved frame rows and SHA-256 checks. It does not identify a person.');
  line(76,332,76,356);line(224,332,224,356);
  block(6,360,140,['NOT DETECTED','or NOT ASSESSED'],a.assessment_reason||'No complete result.',w.security_result==='NOT_DETECTED'||w.security_result==='NOT_ASSESSED');
  block(160,360,134,['DETECTED'],'Attack Signs: '+(a.attack_indicators??'Not recorded')+'. Source MAC is not a person ID.',w.security_result==='DETECTED');
  target.append(plot,detail,node('p','This is a rule flow. It is not a live packet path.'));
 }
 function bars(target,values,unit){
  target.dataset.barChart='true';target._barValues=values;target._barUnit=unit;
  target.replaceChildren();const entries=Object.entries(values||{}).filter(([k,n])=>finite(n)&&n>=0).slice(0,64);
  if(!entries.length){target.append(node('p','No saved count data.'));return;}
  const width=Math.max(250,target.clientWidth||500),max=Math.max(1,...entries.map(e=>e[1]));
  const svg=svgNode('svg',{role:'img','aria-label':entries.map(([k,n])=>k+': '+n+' '+unit).join('; '),viewBox:`0 0 ${width} ${entries.length*62}`});svg.style.width='100%';svg.style.height=String(entries.length*62)+'px';
  entries.forEach(([k,n],i)=>{svg.append(svgNode('text',{x:0,y:i*62+16,fill:'currentColor','font-size':12},k+' / '+n+' '+unit),svgNode('rect',{x:0,y:i*62+26,width:(width-20)*n/max,height:14,fill:'#6cdbeb'}));});target.append(svg);
 }
 function resetCharts(){document.querySelectorAll('[data-live-chart]').forEach(e=>{e.replaceChildren();e._redraw=null;});}
 window.addEventListener('resize',()=>{document.querySelectorAll('.interactive-chart').forEach(e=>e._redraw?.());document.querySelectorAll('[data-bar-chart]').forEach(e=>bars(e,e._barValues,e._barUnit));});
 return {node,stamp,chart,bars,flow,detection,dictionary,resetCharts};
})();
