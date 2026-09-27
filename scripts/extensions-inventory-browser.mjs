// GET-only native inventory evidence. Login injected; no DOM mutation/API replay.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,readdirSync,rmSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
const output=resolve(process.argv[2]||'');
if(!process.argv[2]||process.env.GOTTH_MAIL_ACCEPTANCE_NAMESPACE!=='1')throw Error('namespace runner required');
mkdirSync(output,{mode:0o700});
let bootstrap;try{bootstrap=JSON.parse(readFileSync(0,'utf8'));}catch{throw Error('private bootstrap invalid');}
const origin=new URL(bootstrap.origin);
if(bootstrap.mode!=='inventory'||origin.protocol!=='http:'||origin.hostname!=='127.0.0.1'||!/^[a-f0-9-]{36}$/.test(bootstrap.id))throw Error('invalid inventory fixture');
const policyStage=bootstrap.policyStage;
const costStage=bootstrap.costStage;
if(costStage&&costStage!=='loader')throw Error('invalid cost stage');
let costRows=1,costBytes=0;
if(policyStage&&!['before','provisioned','after'].includes(policyStage))throw Error('unknown policy stage');
const needles=[bootstrap.session,bootstrap.csrf].filter(Boolean);
const proof={scope:'inventory GET renderer only; injected login; failure responses injected separately',gate:'RUNNING',pages:[],fallbacks:[],failures:[],responses:[],defaultSandbox:true};
let vendorRequests=0;
const storageEvents=[];
const policyRequests=[];
const historyExclusions=[];
const networkSamples=[];
const persistedObservations=[];
const policyAssets=new Map();
let failed=false,closed=false,drained=false,closing=false,passed=false,serial=0,session,buffer=Buffer.alloc(0),stderrBytes=0,scenario={},fault=null,held=null;
const pending=new Map(),interceptions=new Set();
function processes(){const out=[];for(const id of readdirSync('/proc').filter(x=>/^[0-9]+$/.test(x))){try{const comm=readFileSync('/proc/'+id+'/comm','utf8').trim();if(!['chromium','chrome_crashpad'].includes(comm))continue;const stat=readFileSync('/proc/'+id+'/stat','utf8');if(stat.slice(stat.lastIndexOf(')')+2).split(' ')[0]!=='Z')out.push(Number(id));}catch(e){if(e.code!=='ENOENT'&&e.code!=='ESRCH')throw e;}}return out;}
if(processes().length)throw Error('pre-existing browser in namespace');
const profile=mkdtempSync('/tmp/mail-inventory-browser-');
if(policyStage){
 mkdirSync(join(profile,'Default'),{mode:0o700});
 const rule=origin.origin+','+origin.origin;
 writeFileSync(join(profile,'Default','Preferences'),JSON.stringify({profile:{content_settings:{exceptions:{cookies:{[rule]:{setting:2}}}}}}),{mode:0o600,flag:'wx'});
 writeFileSync(join(profile,'First Run'),'',{mode:0o600,flag:'wx'});
 proof.policyRule={exactOriginPair:true,setting:2};
}
const browser=spawn('/usr/lib/chromium/chromium',['--headless','--remote-debugging-pipe','--disable-background-networking','--no-first-run','--no-default-browser-check','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe','pipe','pipe'],detached:true});
let resolveExit;const exited=new Promise(r=>{resolveExit=r});
function rejectPending(){for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('browser transport unavailable'));}pending.clear();}
function fail(reason){failed=true;proof.error=reason;rejectPending();}
browser.on('error',()=>{closed=true;fail('browser spawn failed')});
browser.on('exit',(code,signal)=>{closed=true;proof.browserExit={code,signal};rejectPending()});
browser.on('close',()=>{drained=true;resolveExit()});
browser.stderr.on('data',b=>{stderrBytes+=b.length});
browser.stdio[3].on('error',()=>fail('CDP write failed'));
browser.stdio[4].on('error',()=>fail('CDP read failed'));
browser.stdio[4].on('data',chunk=>{
 if(buffer.length+chunk.length>8*1024*1024){fail('CDP envelope limit');browser.kill('SIGTERM');return;}
 buffer=Buffer.concat([buffer,chunk]);let end;
 while((end=buffer.indexOf(0))!==-1){
  const packet=buffer.subarray(0,end);buffer=buffer.subarray(end+1);let m;
  try{m=JSON.parse(packet.toString('utf8'))}catch{fail('invalid CDP envelope');continue}
  if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error('CDP command failed: '+p.method)):p.resolve(m.result||{});continue;}
  if(m.method?.startsWith('DOMStorage.domStorageItem')){const p=m.params;storageEvents.push({local:p.storageId.isLocalStorage,key:p.key,oldValue:p.oldValue,newValue:p.newValue,kind:m.method});}
  if(m.method==='Runtime.bindingCalled'&&m.params.name==='inventoryHistoryObservation'){try{persistedObservations.push(JSON.parse(m.params.payload))}catch{fail('invalid history observation')}}
  if(m.method==='Browser.downloadWillBegin')fail('unexpected download');
  if(m.sessionId!==session)continue;
  if(m.method==='Fetch.requestPaused'){
   const work=intercept(m.params).catch(()=>fail('interception failed'));interceptions.add(work);work.finally(()=>interceptions.delete(work));
  }
  if(m.method==='Network.requestWillBeSent'){
   const r=m.params.request,u=new URL(r.url);
   if(policyStage)policyRequests.push({path:u.pathname,method:r.method});
   if(u.pathname==='/admin/extensions/assets/htmx-2.0.10.min.js')vendorRequests++;
   if(r.method!=='GET'||(u.protocol!=='about:'&&u.origin!==origin.origin)||Object.keys(r.headers).some(k=>k.toLowerCase()==='authorization'))fail('unexpected request authority or method');
  }
  if(m.method==='Page.backForwardCacheNotUsed')historyExclusions.push(m.params.notRestoredExplanations?.map(x=>({type:x.type,reason:x.reason}))||[]);
  if(m.method==='Network.responseReceived'){const r=m.params.response,u=new URL(r.url);if(policyStage&&u.pathname.startsWith('/admin/extensions/assets/'))policyAssets.set(u.pathname,m.params.requestId);if(u.origin===origin.origin)networkSamples.push({path:u.pathname,status:r.status,disk:!!r.fromDiskCache,worker:!!r.fromServiceWorker,mime:r.mimeType,noStore:String(Object.entries(r.headers).find(([k])=>k.toLowerCase()==='cache-control')?.[1]).includes('no-store')});}
  if(m.method==='Page.domContentEventFired'&&scenario.order)proof.orderDOMContent=true;
  if(m.method==='Network.responseReceived'&&m.params.type==='Document'){const u=new URL(m.params.response.url);if(u.origin===origin.origin)proof.responses.push({path:u.pathname,status:m.params.response.status});}
  if(m.method==='Network.loadingFailed'&&held&&m.params.requestId===held.networkId)held=null;
 }
});
function call(method,params={},target=session){
 if(closed||(failed&&!closing))return Promise.reject(Error('browser unavailable'));
 return new Promise((resolve,reject)=>{const id=++serial,timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method))},8000);pending.set(id,{resolve,reject,timer,method});browser.stdio[3].write(JSON.stringify({id,method,params,...(target?{sessionId:target}:{})})+String.fromCharCode(0));});
}
async function intercept(p){
 const u=new URL(p.request.url),response=p.responseStatusCode!==undefined||p.responseErrorReason!==undefined;
 if(response){
  if(costStage&&u.pathname==='/admin/extensions'&&p.responseStatusCode===200){
   const original=await call('Fetch.getResponseBody',{requestId:p.requestId});
   const body=original.base64Encoded?Buffer.from(original.body,'base64').toString('utf8'):original.body;
   const rows=body.match(/<article\b[\s\S]*?<\/article>/g);
   if(!rows||rows.length!==1)throw Error('cost projection fixture not exactly one source row');
   // Explicit transport-only synthetic row cardinality. Actual Go/SQL remains
   // one row; this measures loader/DOM costs, never unlimited List scalability.
   const expanded=body.replace(rows[0],rows[0].repeat(costRows));costBytes=Buffer.byteLength(expanded);
   if(costBytes>6*1024*1024)throw Error('cost fixture response exceeds equipment envelope');
   const headers=(p.responseHeaders||[]).filter(h=>!['content-length','content-encoding','transfer-encoding'].includes(h.name.toLowerCase()));
   await call('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,responseHeaders:headers,body:Buffer.from(expanded).toString('base64')});return;
  }
  if((scenario.csp||scenario.order||scenario.storageDenied)&&p.resourceType==='Document'&&p.responseStatusCode===200){const headers=(p.responseHeaders||[]).filter(h=>!['content-security-policy','content-length','content-encoding','transfer-encoding'].includes(h.name.toLowerCase()));headers.push({name:'Content-Security-Policy',value:scenario.storageDenied?"sandbox allow-scripts; default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'":scenario.order?"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'":"default-src 'none'; script-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"});const original=await call('Fetch.getResponseBody',{requestId:p.requestId});let bytes=original.base64Encoded?Buffer.from(original.body,'base64'):Buffer.from(original.body);if(scenario.order)bytes=Buffer.from(bytes.toString('utf8').replace('</body>','<img src="/admin/extensions/assets/inventory-order-probe" alt=""></body>'));if(needles.some(s=>bytes.includes(s)))throw Error('response credential leak');await call('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:p.responseStatusCode,responseHeaders:headers,body:bytes.toString('base64')});proof.cspOverrides=(proof.cspOverrides||0)+1;}
  else await call('Fetch.continueResponse',{requestId:p.requestId});
  return;
 }
 if(scenario.order&&u.pathname==='/admin/extensions/assets/inventory-order-probe'){for(let i=0;i<100&&!proof.orderDOMContent;i++)await delay(20);proof.orderIntermediate=await observe('({interactive:document.readyState==="interactive",vendorAbsent:typeof window.htmx==="undefined",ordinary:!document.querySelector("#inventory-refresh").hasAttribute("hx-get")})');await call('Fetch.failRequest',{requestId:p.requestId,errorReason:'BlockedByClient'});return;}
 if(scenario.vendorDelay&&u.pathname==='/admin/extensions/assets/htmx-2.0.10.min.js'){proof.delayedVendor=await observe('({complete:document.readyState==="complete",ordinary:!document.querySelector("#inventory-refresh").hasAttribute("hx-get")})');await delay(150);}
 if(scenario.alias&&p.resourceType==='Document') {await call('Fetch.continueRequest',{requestId:p.requestId,url:origin.origin+'/admin/extensions'});return;}
 if(scenario.block?.some(name=>u.pathname==='/admin/extensions/assets/'+name)){await call('Fetch.failRequest',{requestId:p.requestId,errorReason:'BlockedByClient'});return;}
 const hx=Object.entries(p.request.headers).some(([k,v])=>k.toLowerCase()==='hx-request'&&v==='true');
 if(fault&&hx&&u.pathname==='/admin/extensions'){
  const f=fault;fault=null;
  if(f.kind==='timeout'){held={id:p.requestId,networkId:p.networkId};return;}
  if(f.kind==='network'||f.kind==='abort'){await call('Fetch.failRequest',{requestId:p.requestId,errorReason:f.kind==='abort'?'Aborted':'ConnectionFailed'});return;}
  await call('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:f.status||200,responseHeaders:[{name:'Content-Type',value:f.mime||'text/html; charset=utf-8'},{name:'Cache-Control',value:'no-store'}],body:Buffer.from(f.status===204?'':(f.body||'injected transport failure')).toString('base64')});return;
 }
 await call('Fetch.continueRequest',{requestId:p.requestId,interceptResponse:!!costStage||!!(scenario.csp||scenario.order||scenario.storageDenied)&&p.resourceType==='Document'});
}
async function observe(expression){const r=await call('Runtime.evaluate',{expression,returnByValue:true});if(r.exceptionDetails)throw Error('read-only observation failed');return r.result.value;}
async function until(expression,limit=5000){const end=Date.now()+limit;while(Date.now()<end){if(failed)throw Error('failure latched');if(await observe(expression))return;await delay(40)}throw Error('observation deadline');}
async function key(name,code){await call('Input.dispatchKeyEvent',{type:'keyDown',key:name,code:name,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});await call('Input.dispatchKeyEvent',{type:'keyUp',key:name,code:name,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});}
async function focus(selector){for(let i=0;i<40;i++){if(await observe('document.activeElement.matches('+JSON.stringify(selector)+')'))return;await key('Tab',9)}throw Error('native keyboard focus unreachable');}
async function loaded(loader){for(let n=0;n<150;n++){if(loader&&(await call('Page.getFrameTree')).frameTree.frame.loaderId!==loader){await delay(30);continue;}if(await observe('document.readyState==="complete"'))return;await delay(30);}throw Error('navigation deadline');}
async function navigate(options={}){
 scenario=options;fault=null;
 await call('Emulation.setDeviceMetricsOverride',{width:options.width||320,height:900,deviceScaleFactor:1,mobile:false});
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:options.os||'light'},{name:'forced-colors',value:options.forced?'active':'none'}]});
 await call('Emulation.setScriptExecutionDisabled',{value:!!options.noJS});
 const r=await call('Page.navigate',{url:origin.origin+(options.path||'/admin/extensions')});await loaded(r.loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('authenticated inventory unavailable');
}
async function activateNative(selector){await focus(selector);await key('Enter',13);}
async function theme(name){const old=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await activateNative('a[href="/admin/extensions?theme='+name+'"]');for(let i=0;i<100;i++){if((await call('Page.getFrameTree')).frameTree.frame.loaderId!==old)break;await delay(30)}const current=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(current===old)throw Error('theme link did not navigate');await loaded(current);await until('document.documentElement.dataset.theme==='+JSON.stringify(name));}
function ratio(a,b){const lum=c=>{const rgb=c.match(/[\d.]+/g)?.slice(0,3).map(Number);if(!rgb||rgb.length!==3)throw Error('unexpected computed color');const x=rgb.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4});return .2126*x[0]+.7152*x[1]+.0722*x[2]};const x=lum(a),y=lum(b);return(Math.max(x,y)+.05)/(Math.min(x,y)+.05);}
async function inspect(name,expected){
 if(await observe(''+JSON.stringify(needles)+'.some(value=>document.documentElement.textContent.includes(value))'))throw Error('credential leak in document');
 await focus('#inventory-refresh');
 if(!await observe('document.querySelector("article").textContent.includes('+JSON.stringify(bootstrap.pin)+')'))throw Error('artifact projection differs from admitted fixture pin');
 const m=await observe('(()=>{const r=document.querySelector("#inventory-refresh"),a=document.querySelector("article"),b=getComputedStyle(document.body),s=getComputedStyle(a),l=getComputedStyle(r);return {width:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,theme:document.documentElement.dataset.theme,bg:b.backgroundColor,surface:s.backgroundColor,text:b.color,link:l.color,outline:l.outlineStyle,outlineWidth:l.outlineWidth,outlineColor:l.outlineColor,rows:document.querySelectorAll("article[data-extension-id]").length,labels:Array.from(document.querySelectorAll("article dt")).map(e=>e.textContent),enhanced:r.hasAttribute("hx-get"),focus:document.activeElement.id};})()');
 if(m.scroll>m.client||m.rows!==1||m.focus!=='inventory-refresh'||m.outline==='none'||parseFloat(m.outlineWidth)<3)throw Error('reflow/focus/projection failure');
 if(m.bg!==expected)throw Error('rendered theme mismatch');
 for(const label of ['Repository','Pinned artifact','Manifest digest','Grant digest','Lifecycle','Health','Enabled state','Capabilities','Interfaces','Granted secret slots (names only)','Available update','Rollback pin'])if(!m.labels.includes(label))throw Error('missing inventory field');
 m.textContrast=Math.min(ratio(m.text,m.bg),ratio(m.text,m.surface));m.linkContrast=Math.min(ratio(m.link,m.bg),ratio(m.link,m.surface));m.focusContrast=Math.min(ratio(m.outlineColor,m.bg),ratio(m.outlineColor,m.surface));
 if(m.textContrast<4.5||m.linkContrast<4.5||m.focusContrast<3)throw Error('computed contrast failure');
 const png=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});writeFileSync(join(output,name+'.png'),Buffer.from(png.data,'base64'),{mode:0o600});proof.pages.push({name,...m});
}
async function nodeID(selector){const root=(await call('DOM.getDocument',{depth:0})).root;const id=(await call('DOM.querySelector',{nodeId:root.nodeId,selector})).nodeId;return(await call('DOM.describeNode',{nodeId:id})).node.backendNodeId;}
async function nativeRefresh(){
 await focus('#inventory-refresh');const before=await nodeID('#extension-inventory > div'),frame=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
 const scroll=await observe('({x:scrollX,y:scrollY})');await key('Enter',13);
 await until('document.querySelector("#inventory-status").textContent==="Inventory refreshed."');
 const after=await nodeID('#extension-inventory > div'),state=await observe('({focus:document.activeElement.id,busy:document.querySelector("#extension-inventory").getAttribute("aria-busy"),x:scrollX,y:scrollY})');
 if(before===after||state.focus!=='inventory-refresh'||state.busy!=='false'||state.x!==scroll.x||state.y!==scroll.y||(await call('Page.getFrameTree')).frameTree.frame.loaderId!==frame)throw Error('refresh did not replace rows while preserving shell focus/scroll');
 proof.refresh={realGET:true,rowsReplaced:true,focusPreserved:true,scrollPreserved:true,documentRetained:true};
 const ax=await call('Accessibility.getFullAXTree');const link=ax.nodes.find(n=>n.role?.value==='link'&&n.name?.value==='Refresh inventory');const statusNode=ax.nodes.find(n=>n.role?.value==='status'),alertNode=ax.nodes.find(n=>n.role?.value==='alert');if(!link||!statusNode||!alertNode)throw Error('refresh/status/alert accessibility role missing');proof.accessibility={refreshRole:link.role.value,refreshName:link.name.value,statusRole:statusNode.role.value,alertRole:alertNode.role.value};
}
async function fallback(name,options){const overrides=proof.cspOverrides||0;await navigate(options);if(options.csp){proof.cspObserved=await observe('({htmx:typeof window.htmx,operative:document.querySelector("#inventory-refresh").hasAttribute("hx-get")})');if((proof.cspOverrides||0)===overrides||proof.cspObserved.htmx!=='undefined')throw Error('CSP fault not enforced by browser');}if(await observe('document.querySelector("#inventory-refresh").hasAttribute("hx-get")'))throw Error('partial-assets enhancement admitted');const old=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await activateNative('#inventory-refresh');await until('document.readyState==="complete"&&location.search==="?theme=system"');if((await call('Page.getFrameTree')).frameTree.frame.loaderId===old)throw Error('native fallback did not navigate');proof.fallbacks.push({name,nativeFullNavigation:true});}
// Native storage operations observed via CDP; seeding is explicit test setup,
// never a production API override. Only classifications are retained.
async function storageMap(){return await observe('JSON.stringify([localStorage,sessionStorage].map(s=>Object.keys(s).sort().map(k=>[k,s.getItem(k)])))');}
async function privacyMatrix(){
 const publicPaths=['/admin/extensions','/admin/extensions?theme=system','/admin/extensions?theme=light','/admin/extensions?theme=dark'];
 const sentinels=[['unrelated-local','local-sentinel'],['unrelated-session','session-sentinel'],['htmx-current-path-for-history','old-public-sentinel'],['htmx-history-cache','cache-sentinel'],['htmx:sessionStorageTest','probe-sentinel']];
 for(const [i,[key,value]] of sentinels.entries())await call('DOMStorage.setDOMStorageItem',{storageId:{securityOrigin:origin.origin,isLocalStorage:i===0},key,value});
 const baseline=await storageMap();proof.privacyFallbacks=[];
 const paths=['?unknown=STORAGE_CANARY_INVENTORY_TEST','?theme=light&unknown=STORAGE_CANARY_INVENTORY_TEST','?theme=light&theme=light','?theme=light&theme=dark','?unknown=a&unknown=b','?theme=other','?theme=','?theme','?theme=light&','?&theme=light','?unknown=a&theme=light','?%74heme=light','?theme=%6cight','?theme=light+','?theme=light%20','?theme=%00','?theme=%ZZ','?','#','#hash'].map(s=>'/admin/extensions'+s);
 for(const path of paths){
  const start=storageEvents.length,requests=vendorRequests;await navigate({path});
  const plain=await observe('typeof window.htmx==="undefined"&&!document.querySelector("#inventory-refresh").hasAttribute("hx-get")&&location.href==='+JSON.stringify(origin.origin+path));
  if(!plain||vendorRequests!==requests||await storageMap()!==baseline||storageEvents.length!==start)throw Error('fallback URL/storage-map boundary failed');
  proof.privacyFallbacks.push({case:proof.privacyFallbacks.length,urlUnchanged:true,ordinaryHTML:true,vendorRequests:0,storageEvents:0,sentinelMapsUnchanged:true});
 }
 for(const c of [{path:'/admin/%65xtensions',injected:false},{path:'/noncanonical-injected?unknown=STORAGE_CANARY_INVENTORY_TEST',injected:true}]){
  const start=storageEvents.length,requests=vendorRequests;await navigate({path:c.path,alias:c.injected});
  if(!await observe('typeof window.htmx==="undefined"&&!document.querySelector("#inventory-refresh").hasAttribute("hx-get")&&location.href==='+JSON.stringify(origin.origin+c.path))||vendorRequests!==requests||storageEvents.length!==start||await storageMap()!==baseline)throw Error('browser path mismatch guard failed');
  proof.privacyFallbacks.push({case:proof.privacyFallbacks.length,injectedUpstreamNormalization:c.injected,vendorRequests:0,sentinelMapsUnchanged:true});
 }
 proof.canonicalStorage=[];
 for(const path of publicPaths){
  const start=storageEvents.length,requests=vendorRequests;await navigate({path,vendorDelay:true});await until('document.querySelector("#inventory-refresh").hasAttribute("hx-get")');
  if(!proof.delayedVendor?.complete||!proof.delayedVendor?.ordinary)throw Error('vendor loaded before complete/guards');
  const history=await call('Page.getNavigationHistory');await nativeRefresh();const after=await call('Page.getNavigationHistory');
  if(history.currentIndex!==after.currentIndex||history.entries.length!==after.entries.length)throw Error('refresh changed browser history');
  const state=await observe('({current:sessionStorage.getItem("htmx-current-path-for-history"),probe:sessionStorage.getItem("htmx:sessionStorageTest"),cache:sessionStorage.getItem("htmx-history-cache"),local:localStorage.getItem("unrelated-local"),session:sessionStorage.getItem("unrelated-session")})');
  const events=storageEvents.slice(start);
  if(state.current!==path||state.probe!==null||state.cache!=='cache-sentinel'||state.local!=='local-sentinel'||state.session!=='session-sentinel'||vendorRequests-requests!==1)throw Error('canonical storage state differs');
  if(events.some(e=>e.local||!['htmx-current-path-for-history','htmx:sessionStorageTest'].includes(e.key)||(e.newValue!==undefined&&(e.key==='htmx:sessionStorageTest'?e.newValue!=='htmx:sessionStorageTest':!publicPaths.includes(e.newValue)))))throw Error('unreviewed native storage operation');
  if(!events.some(e=>e.key==='htmx:sessionStorageTest'&&e.newValue==='htmx:sessionStorageTest')||!events.some(e=>e.key==='htmx:sessionStorageTest'&&e.kind.endsWith('Removed')))throw Error('native transient probe not observed');
  proof.canonicalStorage.push({path,actualRefresh:true,vendorRequests:1,unrelatedMapsPreserved:true,cacheUnchanged:true,probeRemoved:true,probeCollisionDisclosed:true,events:events.length,historyUnchanged:true});
 }
 // Deliberately injected pending image holds complete AFTER DOMContentLoaded;
 // no production DOM/URL/script is rewritten to manufacture activation.
 proof.orderDOMContent=false;await navigate({order:true});await until('document.querySelector("#inventory-refresh").hasAttribute("hx-get")');
 if(!proof.orderDOMContent||!proof.orderIntermediate?.interactive||!proof.orderIntermediate?.vendorAbsent||!proof.orderIntermediate?.ordinary)throw Error('intermediate readiness guard not observed');
 proof.orderInjectedPendingImage=true;
 // Native browser storage denial via injected opaque-origin CSP sandbox, not
 // a storage API replacement. Plain fallback remains, no vendor evaluation.
 const start=storageEvents.length,requests=vendorRequests;await navigate({storageDenied:true});
 proof.storageDenied=await observe('(()=>{let denied=false;try{sessionStorage.getItem("probe")}catch(e){denied=e.name==="SecurityError"}return {denied,vendorAbsent:typeof window.htmx==="undefined",ordinary:!document.querySelector("#inventory-refresh").hasAttribute("hx-get")}})()');
 if(!proof.storageDenied.denied||!proof.storageDenied.vendorAbsent||!proof.storageDenied.ordinary||vendorRequests!==requests||storageEvents.length!==start)throw Error('native storage-denied fallback failed');
 await navigate({path:'/admin/extensions?unknown=STORAGE_CANARY_INVENTORY_TEST'});
 // Test-owned sentinel teardown, not credited to product behavior.
 for(const [i,[key]] of sentinels.entries())if(key!=='htmx-current-path-for-history'&&key!=='htmx:sessionStorageTest')await call('DOMStorage.removeDOMStorageItem',{storageId:{securityOrigin:origin.origin,isLocalStorage:i===0},key});
}
async function runPolicy(){
 proof.scope='native storage-policy denial; SERVER-SIDE INJECTED SYNTHETIC SESSION; no browser-cookie authentication';
 proof.policyRequests=policyRequests;proof.stage=policyStage;proof.version=await call('Browser.getVersion',{},null);
 const t=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:t.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:t.targetId},null);await call('Page.enable');await call('Network.enable');await call('DOMStorage.enable');
 // Browser-created favicon is outside the strict test listener allowlist. Block
 // only that auxiliary request; no inventory/asset response or CSP is rewritten.
 await call('Network.setBlockedURLs',{urls:[origin.origin+'/favicon.ico']});
 const nav=await call('Page.navigate',{url:origin.origin+'/admin/extensions'});await loaded(nav.loaderId);
 proof.nativePolicy=await observe('(()=>{const result={origin:location.origin,denials:[]};for(const name of ["localStorage","sessionStorage"]){for(const op of ["get","read","write"]){try{const s=window[name];if(op==="read")s.getItem("policy-probe");if(op==="write")s.setItem("policy-probe","synthetic");result.denials.push("allowed")}catch(e){result.denials.push(e.name)}}}return result})()');
 if(proof.nativePolicy.origin!==origin.origin||proof.nativePolicy.denials.some(x=>x!=='SecurityError'))throw Error('native nonopaque storage denial not enforced');
 proof.nativePolicy.securityOrigin=(await call('Page.getFrameTree')).frameTree.frame.securityOrigin;
 if(proof.nativePolicy.securityOrigin!==origin.origin)throw Error('opaque execution origin');
 if(policyStage!=='provisioned'){
  if(proof.responses.at(-1)?.status!==401||!await observe('document.querySelectorAll("article[data-extension-id]").length===0'))throw Error('real negative authorization failed');
  proof.real401=true;return;
 }
 if(proof.responses.at(-1)?.status!==200)throw Error('server provision did not authorize actual handler');
 await until('window.htmx?.version==="2.0.10"&&document.querySelector("#inventory-refresh").hasAttribute("hx-get")');
 proof.usableAssets=await observe('({css:["inventory-tokens-css","inventory-utilities-css"].every(id=>document.getElementById(id).sheet.cssRules.length>0),vendor:window.htmx.version,scripts:Array.from(document.scripts).filter(s=>s.src.endsWith("/htmx-2.0.10.min.js")).length,rows:document.querySelectorAll("article[data-extension-id]").length})');
 if(!proof.usableAssets.css||proof.usableAssets.scripts!==1||proof.usableAssets.rows!==1||vendorRequests!==1)throw Error('policy assets/rows incomplete');
 const history=await call('Page.getNavigationHistory');await nativeRefresh();const after=await call('Page.getNavigationHistory');
 if(history.currentIndex!==after.currentIndex||history.entries.length!==after.entries.length)throw Error('policy refresh changed history');
 proof.historyUnchanged=true;proof.vendorRequestsBeforeTheme=vendorRequests;
 proof.assetHashes=[];
 for(const [path,requestId] of policyAssets){const r=await call('Network.getResponseBody',{requestId});const bytes=r.base64Encoded?Buffer.from(r.body,'base64'):Buffer.from(r.body);proof.assetHashes.push({path,bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')});}
 if(proof.assetHashes.length!==4||proof.assetHashes.find(x=>x.path.endsWith('htmx-2.0.10.min.js'))?.sha256!=='71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de')throw Error('native policy immutable asset mismatch');
 proof.network=networkSamples.slice();
 if(proof.network.some(r=>r.status!==200||!r.noStore))throw Error('policy actual no-store response mismatch');
 proof.inspector=[];
 for(const isLocalStorage of [true,false]){try{const state=await call('DOMStorage.getDOMStorageItems',{storageId:{securityOrigin:origin.origin,isLocalStorage}});proof.inspector.push({local:isLocalStorage,available:true,entries:state.entries.length});if(state.entries.length)throw Error('policy inspector persistence')}catch(e){if(e.message==='policy inspector persistence')throw e;proof.inspector.push({local:isLocalStorage,available:false});}}
 if(storageEvents.length)throw Error('policy storage mutation observed');
 await theme('dark');await until('document.querySelector("#inventory-refresh").hasAttribute("hx-get")');
 proof.themeNavigation=await observe('document.documentElement.dataset.theme==="dark"&&document.querySelectorAll("article[data-extension-id]").length===1');
 if(!proof.themeNavigation||storageEvents.length)throw Error('policy theme navigation failed');
 proof.storageEvents=storageEvents.length;
}
async function traversed(expression){
 const end=Date.now()+5000;let stable=0;
 while(Date.now()<end){
  try{if(await observe(expression)){if(++stable===3)return;}else stable=0;}
  catch(e){if(e.message!=='CDP command failed: Runtime.evaluate')throw e;stable=0;}
  await delay(50);
 }
 throw Error('history reload did not settle');
}
async function historyMatrix(){
 await call('Fetch.disable');await call('Network.setCacheDisabled',{cacheDisabled:false});
 proof.traversal=[];
 // Observational listener only: production companion's previously registered
 // persisted handler runs first. No synthetic event or application state edit.
 await call('Runtime.enable');await call('Runtime.addBinding',{name:'inventoryHistoryObservation'});
 for(const path of ['/admin/extensions?theme=light','/admin/extensions?unknown=HISTORY_TEST']){
  await navigate({path});await observe('window.addEventListener("pageshow",event=>{if(event.persisted)window.inventoryHistoryObservation(JSON.stringify({persisted:true,rows:document.querySelectorAll("article[data-extension-id]").length,hidden:document.querySelector("#extension-inventory").hidden,status:document.querySelector("#inventory-status").textContent}))});true');const h=await call('Page.getNavigationHistory'),entry=h.entries[h.currentIndex];
  await theme('dark');await observe('window.addEventListener("pageshow",event=>{if(event.persisted)window.inventoryHistoryObservation(JSON.stringify({persisted:true,rows:document.querySelectorAll("article[data-extension-id]").length,hidden:document.querySelector("#extension-inventory").hidden,status:document.querySelector("#inventory-status").textContent}))});true');const away=await call('Page.getNavigationHistory'),forward=away.entries[away.currentIndex];
  for(const [direction,target] of [['back',entry],['forward',forward]]){
   const count=proof.responses.length,exclusions=historyExclusions.length;
   await call('Page.navigateToHistoryEntry',{entryId:target.id});
   await traversed('location.href==='+JSON.stringify(target.url)+'&&document.readyState==="complete"');
   await delay(100);
   const state=await observe('({rows:document.querySelectorAll("article[data-extension-id]").length,cache:localStorage.getItem("htmx-history-cache"),sessionCache:sessionStorage.getItem("htmx-history-cache"),kind:performance.getEntriesByType("navigation")[0]?.type})');
   if(state.rows!==1||state.cache!==null||state.sessionCache!==null)throw Error('history restored inventory cache or lost rows');
   proof.traversal.push({canonical:!path.includes('unknown'),direction,freshDocuments:proof.responses.length-count,exclusions:historyExclusions.slice(exclusions),...state});
  }
 }
 // Remove only test-owned login transport; durable session/roles remain unchanged.
 await call('Network.deleteCookies',{name:'gotth_mail_session',url:origin.origin});
 const h=await call('Page.getNavigationHistory'),count=proof.responses.length;
 await call('Page.navigateToHistoryEntry',{entryId:h.entries[h.currentIndex-1].id});
 await traversed('document.readyState==="complete"&&document.querySelectorAll("article[data-extension-id]").length===0');
 if(proof.responses.length<=count||proof.responses.at(-1).status!==401)throw Error('history auth loss did not revalidate');
 proof.historyAuthLoss={real401:true,rows:0};
 proof.historyExclusions=historyExclusions;proof.persistedObservations=persistedObservations;
 if(persistedObservations.length!==4||persistedObservations.some(x=>!x.persisted||x.rows!==0||!x.hidden||x.status!=='Reloading inventory…'))throw Error('native persisted mitigation not positively observed');
}
async function runCost(){
 proof.scope='loader/browser cost envelope; source-rendered one-row responses transport-expanded to synthetic DOM sizes; NOT List/auth/SQL scalability or speedup';
 proof.version=await call('Browser.getVersion',{},null);proof.cost=[];
 const t=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:t.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:t.targetId},null);await call('Page.enable');await call('Network.enable');
 await call('Network.setBlockedURLs',{urls:[origin.origin+'/favicon.ico']});
 await call('Fetch.enable',{patterns:[{urlPattern:origin.origin+'/*',requestStage:'Request'}]});
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});bootstrap.session='';bootstrap.csrf='';
 let stopped=false,timer,peak=0,driverPeak=0;
 const sample=()=>{let total=0;for(const pid of processes()){try{total+=Number(readFileSync('/proc/'+pid+'/status','utf8').match(/^VmRSS:\s+(\d+)/m)?.[1]||0)}catch(e){if(e.code!=='ENOENT'&&e.code!=='ESRCH')throw e;}}peak=Math.max(peak,total);driverPeak=Math.max(driverPeak,process.memoryUsage().rss);if(total*1024+driverPeak>3*1024**3)throw Error('cost memory soft envelope');};
 const tick=()=>{if(stopped)return;try{sample()}catch{fail('cost resource sample failed')}timer=setTimeout(tick,50)};tick();
 try{
  for(const cacheDisabled of [true,false]){
   await call('Network.setCacheDisabled',{cacheDisabled});
   for(const rows of [0,1,20,1000])for(let repeat=0;repeat<3;repeat++){
    costRows=rows;const first=networkSamples.length,vendors=vendorRequests;
    await navigate();await until('document.querySelector("#inventory-refresh").hasAttribute("hx-get")');
    const timing=await observe('(()=>{const n=performance.getEntriesByType("navigation")[0],v=performance.getEntriesByType("resource").find(r=>r.name.endsWith("/htmx-2.0.10.min.js"));return {htmlDOMContentMS:n.domContentLoadedEventEnd,completeMS:n.loadEventEnd,vendorStartMS:v.startTime,vendorDurationMS:v.duration,activationObservedMS:performance.now(),rows:document.querySelectorAll("article[data-extension-id]").length,scripts:Array.from(document.scripts).filter(s=>s.src.endsWith("/htmx-2.0.10.min.js")).length}})()');
    if(timing.rows!==rows||timing.scripts!==1||vendorRequests-vendors!==1||timing.vendorStartMS<timing.completeMS-2)throw Error('cost loader ordering/cardinality differs');
    const documentBytes=costBytes;await focus('#inventory-refresh');const frame=(await call('Page.getFrameTree')).frameTree.frame.loaderId;const start=Date.now();await key('Enter',13);
    await until('document.querySelector("#inventory-status").textContent==="Inventory refreshed."');
    const refreshObservedMS=Date.now()-start;
    if((await call('Page.getFrameTree')).frameTree.frame.loaderId!==frame||!await observe('document.querySelectorAll("article[data-extension-id]").length==='+rows+'&&document.querySelector("#extension-inventory").getAttribute("aria-busy")==="false"'))throw Error('cost refresh incomplete');
    sample();const responses=networkSamples.slice(first);
    if(responses.some(r=>r.status!==200||!r.noStore)||responses.filter(r=>r.path.endsWith('htmx-2.0.10.min.js')).length!==1)throw Error('cache response contract differs');
    proof.cost.push({cacheDisabled,rows,repeat,documentBytes,fragmentBytes:costBytes,...timing,refreshObservedMS,network:responses,observedBrowserRSSKiB:peak,observedDriverRSSBytes:driverPeak});
   }
  }
 }finally{stopped=true;clearTimeout(timer);proof.memory={sampleIntervalMS:50,browserRSSSumPeakKiB:peak,driverRSSPeakBytes:driverPeak,limits:'sampled RSS sum double-counts shared pages; not exact OS peak; browser and Node only, excludes Go/PG'};}
 await call('Fetch.disable');await Promise.allSettled([...interceptions]);
}
async function runMatrix(){
 if(costStage){await runCost();return;}
 if(policyStage){await runPolicy();return;}
 proof.version=await call('Browser.getVersion',{},null);
 const t=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:t.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:t.targetId},null);await call('Page.enable');await call('Page.setBypassCSP',{enabled:false});await call('DOMStorage.enable');await call('Network.enable');await call('Network.setCacheDisabled',{cacheDisabled:true});
 await call('Fetch.enable',{patterns:[{urlPattern:origin.origin+'/*',requestStage:'Request'}]});
 await call('Emulation.setScriptExecutionDisabled',{value:true});const denied=await call('Page.navigate',{url:origin.origin+'/admin/extensions'});await loaded(denied.loaderId);if(proof.responses.at(-1)?.status!==401)throw Error('unauthenticated browser not denied');
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});bootstrap.session='';bootstrap.csrf='';
 // Synthetic, noncredential canary in an actual browser location. No deletion
 // after vendor execution can satisfy this no-load/no-persistence boundary.
 const canaryPath='/admin/extensions?unknown=STORAGE_CANARY_INVENTORY_TEST';
 const vendorBefore=vendorRequests;await navigate({path:canaryPath});
 proof.privacyCanary=await observe('({urlUnchanged:location.href==='+JSON.stringify(origin.origin+canaryPath)+',vendorEvaluated:typeof window.htmx!=="undefined",operative:document.querySelector("#inventory-refresh").hasAttribute("hx-get"),canaryStored:[localStorage,sessionStorage].some(s=>Object.keys(s).some(k=>(s.getItem(k)||"").includes("STORAGE_CANARY_INVENTORY_TEST")))})');
 proof.privacyCanary.vendorRequests=vendorRequests-vendorBefore;
 if(!proof.privacyCanary.urlUnchanged||proof.privacyCanary.vendorEvaluated||proof.privacyCanary.operative||proof.privacyCanary.canaryStored||proof.privacyCanary.vendorRequests)throw Error('unknown-query privacy canary violated');
 await privacyMatrix();
 for(const c of [{name:'light-320',theme:'light',width:320,os:'dark'},{name:'dark-320',theme:'dark',width:320},{name:'system-dark-desktop',theme:'system',width:1280,os:'dark'},{name:'system-light-desktop',theme:'system',width:1280},{name:'nojs-light-desktop',theme:'light',width:1280,noJS:true,os:'dark'},{name:'nojs-dark-320',theme:'dark',width:320,noJS:true},{name:'nojs-system-dark-320',theme:'system',width:320,noJS:true,os:'dark'}]){
  await navigate(c);await theme(c.theme);const dark=c.theme==='dark'||(c.theme==='system'&&c.os==='dark');await inspect(c.name,dark?'rgb(17, 23, 34)':'rgb(244, 246, 249)');
  if(c.name==='light-320')await nativeRefresh();
 }
 await navigate({forced:true});await focus('#inventory-refresh');const forced=await observe('({active:matchMedia("(forced-colors: active)").matches,outline:getComputedStyle(document.activeElement).outlineStyle,width:getComputedStyle(document.activeElement).outlineWidth})');if(!forced.active||forced.outline==='none'||parseFloat(forced.width)<3)throw Error('forced colors focus failure');proof.forcedColors=forced;
 for(const [name,options] of [['nojs',{noJS:true}],['htmx-missing',{block:['htmx-2.0.10.min.js']}],['companion-missing',{block:['inventory.js']}],['both-scripts-missing',{block:['inventory.js','htmx-2.0.10.min.js']}],['tokens-missing',{block:['tokens.css']}],['utilities-missing',{block:['inventory.css']}],['csp-scripts-blocked',{csp:true}]])await fallback(name,options);
 for(const f of [{kind:'401',status:401},{kind:'403',status:403},{kind:'500',status:500},{kind:'503',status:503},{kind:'204',status:204},{kind:'bad-mime',mime:'application/json',body:'<!-- gotth-mail-extension-inventory-v1 -->{}'},{kind:'bad-marker',body:'<html>login</html>'},{kind:'network'},{kind:'abort'},{kind:'timeout'}]){
  await navigate();await until('document.querySelector("#inventory-refresh").hasAttribute("hx-get")');fault=f;await activateNative('#inventory-refresh');
  await until('document.querySelector("#inventory-error").textContent!==""&&document.querySelector("#extension-inventory").getAttribute("aria-busy")==="false"',f.kind==='timeout'?12500:5000);
  const state=await observe('({rows:document.querySelectorAll("article[data-extension-id]").length,reload:!document.querySelector("#inventory-reload").hidden,status:document.querySelector("#inventory-status").textContent})');
  if(!state.reload||/refreshed/i.test(state.status)||state.rows!==((f.status===401||f.status===403)?0:1)||fault!==null)throw Error('failure projection did not settle safely');proof.failures.push({kind:f.kind,...state,injected:true});
  if(f.kind==='500'){const old=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await activateNative('#inventory-reload');await until('document.querySelector("#inventory-status")?.textContent==="Inventory ready."');if((await call('Page.getFrameTree')).frameTree.frame.loaderId===old)throw Error('full reload recovery did not navigate');proof.reloadRecovery=true;}
 }
 proof.storage=await observe('(()=>{const key="htmx-current-path-for-history",value=sessionStorage.getItem(key)||"";return {local:localStorage.length,session:sessionStorage.length,knownPathKeyOnly:sessionStorage.length===1&&sessionStorage.key(0)===key,matchesCurrentPath:value===location.pathname+location.search,canonicalPublicPath:/^\\/admin\\/extensions(\\?theme=(system|light|dark))?$/.test(value),credentialValue:'+JSON.stringify(needles)+'.some(s=>value.includes(s))};})()');if(proof.storage.local!==0||proof.storage.session!==1||!proof.storage.knownPathKeyOnly||!proof.storage.matchesCurrentPath||!proof.storage.canonicalPublicPath||proof.storage.credentialValue)throw Error('unexpected browser persistence');
 const cookies=await call('Network.getCookies',{urls:[origin.origin]});proof.cookieNames=cookies.cookies.map(c=>c.name).sort();if(JSON.stringify(proof.cookieNames)!==JSON.stringify(['gotth_mail_csrf','gotth_mail_session']))throw Error('unexpected browser cookie');
 await call('Fetch.disable');await Promise.allSettled([...interceptions]);
 await historyMatrix();
}
const deadline=setTimeout(()=>fail('inventory browser deadline'),80000);
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>fail('inventory browser interrupted'));
try{await runMatrix();passed=true;}catch(e){failed=true;proof.error=e.message;}
finally{
 clearTimeout(deadline);closing=true;
 try{if(!closed)await call('Browser.close',{},null);}catch{/* close may terminate its own reply pipe */}
 await Promise.race([exited,delay(2500)]);
 if(!closed){proof.forcedShutdown=true;try{process.kill(-browser.pid,'SIGTERM')}catch(e){if(e.code!=='ESRCH')proof.signalError=true}await Promise.race([exited,delay(1500)]);}
 if(!closed){proof.forcedShutdown=true;try{process.kill(-browser.pid,'SIGKILL')}catch(e){if(e.code!=='ESRCH')proof.signalError=true}await Promise.race([exited,delay(1000)]);}
 let remaining=[];for(let i=0;i<20;i++){remaining=processes();if(!remaining.length)break;await delay(50)}
 proof.cleanup={mainExited:closed,drained,remaining:remaining.length,stderrBytes};
 proof.cleanupFailed=!closed||!drained||remaining.length>0||!!proof.forcedShutdown||!!proof.signalError;
 if(!proof.cleanupFailed)rmSync(profile,{recursive:true});
 rejectPending();browser.stdio[3].destroy();browser.stdio[4].destroy();browser.stderr.destroy();
 // Final synchronous publication barrier: late interruption/download/request
 // events can revoke provisional success until streams drain and cleanup finishes.
 if(needles.some(s=>JSON.stringify(proof).includes(s))){for(const k of Object.keys(proof))delete proof[k];proof.error='credential diagnostics rejected';failed=true;}
 proof.gate=passed&&!failed&&!proof.cleanupFailed&&drained?'PASS':'FAIL';
 if(proof.gate!=='PASS')process.exitCode=1;
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({inventoryGate:proof.gate,pages:proof.pages?.length,fallbacks:proof.fallbacks?.length,failures:proof.failures?.length,error:proof.error,cleanupFailed:!!proof.cleanupFailed}));
}
