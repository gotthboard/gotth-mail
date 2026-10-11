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
if(bootstrap.mode!=='enhanced'||origin.protocol!=='http:'||origin.hostname!=='127.0.0.1'||!/^[a-f0-9-]{36}$/.test(bootstrap.id))throw Error('invalid inventory fixture');
const needles=[bootstrap.session,bootstrap.csrf].filter(Boolean);
const expected=bootstrap.expected;
if(!Array.isArray(expected)||expected.length!==51||new Set(expected.map(x=>x[0])).size!==51||expected.some(x=>!Array.isArray(x)||x.length!==2||typeof x[0]!== 'string'||typeof x[1]!== 'string'))throw Error('independent SQL bootstrap cardinality');
const proof={scope:'single JS enhancement boundary; explicit synthetic epoch transition',gate:'RUNNING',width:320,initialTheme:'light',appJavaScript:true,defaultSandbox:true,pages:[],focus:[],history:[],responses:[],requests:{GET:0,mutation:0,vendor:0,companion:0,HX:0}};
let failed=false,closed=false,drained=false,closing=false,passed=false,serial=0,session,buffer=Buffer.alloc(0),stderrBytes=0;
const pending=new Map();
let storagePhase='setup';
const storageEvents=[],networkResponses=[];
const allowedPaths=['/admin/extensions','/admin/extensions?theme=system','/admin/extensions?theme=light','/admin/extensions?theme=dark'];
function storageEvent(method,p){
 if(typeof p.storageId.isLocalStorage!=='boolean'||(p.storageId.securityOrigin!==undefined&&p.storageId.securityOrigin!==origin.origin)){fail('foreign or malformed storage identity');return;}
 const kind=method.split('.').at(-1),key=p.key,local=p.storageId.isLocalStorage;
 const record={phase:storagePhase,kind,local,keyClass:key==='htmx-current-path-for-history'?'path':key==='htmx:sessionStorageTest'?'probe':'other'};
 storageEvents.push(record);
 if(storagePhase==='setup')return;
 if(storagePhase==='cursor'){fail('cursor storage write event');return;}
 if(local||!['domStorageItemAdded','domStorageItemUpdated','domStorageItemRemoved'].includes(kind)||!['path','probe'].includes(record.keyClass)){fail('unreviewed storage event');return;}
 if(record.keyClass==='path'){
  if(kind==='domStorageItemRemoved'||!allowedPaths.includes(p.newValue)||(p.oldValue!==undefined&&!allowedPaths.includes(p.oldValue)))fail('unreviewed history bookkeeping value');
 }else if((p.newValue!==undefined&&p.newValue!=='htmx:sessionStorageTest')||(p.oldValue!==undefined&&p.oldValue!=='htmx:sessionStorageTest'))fail('unreviewed probe value');
}
function processes(){const out=[];for(const id of readdirSync('/proc').filter(x=>/^[0-9]+$/.test(x))){try{const comm=readFileSync('/proc/'+id+'/comm','utf8').trim();if(!['chromium','chrome_crashpad'].includes(comm))continue;const stat=readFileSync('/proc/'+id+'/stat','utf8');if(stat.slice(stat.lastIndexOf(')')+2).split(' ')[0]!=='Z')out.push(Number(id));}catch(e){if(e.code!=='ENOENT'&&e.code!=='ESRCH')throw e;}}return out;}
if(processes().length)throw Error('pre-existing browser in namespace');
const profile=mkdtempSync('/tmp/mail-inventory-browser-');
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
  if(m.method==='Browser.downloadWillBegin')fail('unexpected download');
  if(m.method?.startsWith('DOMStorage.domStorage')&&m.sessionId===session)storageEvent(m.method,m.params);
  if(m.sessionId!==session)continue;
  if(m.method==='Network.requestWillBeSent'){
   const r=m.params.request,u=new URL(r.url);
   if(r.method==='GET')proof.requests.GET++;else proof.requests.mutation++;
   if(u.pathname.endsWith('/htmx-2.0.10.min.js'))proof.requests.vendor++;
   if(u.pathname.endsWith('/inventory.js'))proof.requests.companion++;
   if(Object.entries(r.headers).some(([k,v])=>k.toLowerCase()==='hx-request'&&v==='true'))proof.requests.HX++;
   if(r.method!=='GET'||(u.protocol!=='about:'&&u.origin!==origin.origin)||Object.keys(r.headers).some(k=>k.toLowerCase()==='authorization'))fail('unexpected request authority or method');
  }
  if(m.method==='Network.responseReceived'&&m.params.type==='Document'){const r=m.params.response,u=new URL(r.url);if(u.origin===origin.origin)proof.responses.push({path:u.pathname,status:r.status});}
  if(m.method==='Network.responseReceived'){const r=m.params.response,u=new URL(r.url);if(u.origin===origin.origin)networkResponses.push({phase:storagePhase,path:u.pathname,status:r.status,mime:r.mimeType,type:m.params.type});}
  if(m.method==='Runtime.exceptionThrown')fail('application script exception');
  if(m.method==='Page.backForwardCacheNotUsed')proof.historyMisses=(proof.historyMisses||0)+1;
 }
});
function call(method,params={},target=session){
 if(closed||(failed&&!closing))return Promise.reject(Error('browser unavailable'));
 return new Promise((resolve,reject)=>{const id=++serial,timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method))},8000);pending.set(id,{resolve,reject,timer,method});browser.stdio[3].write(JSON.stringify({id,method,params,...(target?{sessionId:target}:{})})+String.fromCharCode(0));});
}
async function observe(expression){const r=await call('Runtime.evaluate',{expression,returnByValue:true});if(r.exceptionDetails)throw Error('read-only observation failed');return r.result.value;}
async function until(expression,limit=5000){const end=Date.now()+limit;while(Date.now()<end){if(failed)throw Error('failure latched');if(await observe(expression))return;await delay(40)}throw Error('observation deadline');}
async function key(name,code){await call('Input.dispatchKeyEvent',{type:'keyDown',key:name,code:name,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});await call('Input.dispatchKeyEvent',{type:'keyUp',key:name,code:name,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});}
async function focus(selector){for(let i=0;i<128;i++){if(await observe('document.activeElement.matches('+JSON.stringify(selector)+')'))return;await key('Tab',9)}throw Error('native keyboard focus unreachable');}
async function loaded(loader){for(let n=0;n<150;n++){if(loader&&(await call('Page.getFrameTree')).frameTree.frame.loaderId!==loader){await delay(30);continue;}if(await observe('document.readyState==="complete"'))return;await delay(30);}throw Error('navigation deadline');}

async function activate(selector,label){
 if(!await observe('document.querySelectorAll('+JSON.stringify(selector)+').length===1'))throw Error('pagination control cardinality: '+label);
 await focus(selector);
 const state=await observe('(()=>{const e=document.activeElement,s=getComputedStyle(e),r=e.getBoundingClientRect();return {link:e.tagName==="A",visible:s.display!=="none"&&s.visibility!=="hidden"&&r.width>0&&r.height>0,inView:r.top>=0&&r.bottom<=innerHeight&&r.left>=0&&r.right<=innerWidth,outline:s.outlineStyle,outlineWidth:s.outlineWidth};})()');
 if(!state.link||!state.visible||!state.inView||state.outline==='none'||parseFloat(state.outlineWidth)<3)throw Error('pagination native focus visibility: '+label);
 proof.focus.push({label,nativeTab:true,...state});
 const old=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
 await key('Enter',13);
 let current=old;
 for(let i=0;i<150;i++){current=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(current!==old)break;await delay(30)}
 if(current===old)throw Error('pagination native Enter did not navigate: '+label);
 await loaded(current);
 if(proof.responses.at(-1)?.status!==200)throw Error('pagination native response status');
}

const currentPath='/admin/extensions?theme=light';
const expectedCursor='v1.'+Buffer.from(expected[49][1],'utf8').toString('base64url');
const reduced=expected.filter(x=>x[1]!=='page.entry001');
if(reduced.length!==50)throw Error('independent removal cardinality');
async function storageSnapshot(){return await observe('JSON.stringify([localStorage,sessionStorage].map(s=>Object.keys(s).sort().map(k=>[k,s.getItem(k)])))');}
function assertStorage(snapshot){
 const want=[[['fixture-local','local-sentinel']],[['fixture-session','session-sentinel'],['htmx-current-path-for-history',currentPath]]];
 if(snapshot!==JSON.stringify(want))throw Error('persistent storage outside declared bookkeeping');
}
async function nodeID(selector){const root=(await call('DOM.getDocument',{depth:0})).root;const id=(await call('DOM.querySelector',{nodeId:root.nodeId,selector})).nodeId;if(!id)throw Error('required node absent');return(await call('DOM.describeNode',{nodeId:id})).node.backendNodeId;}
async function inspect(label,cursor,afterTransition=false){
 const got=await observe('(()=>{const r=document.querySelector("#inventory-refresh");return {path:location.pathname,query:location.search,theme:document.documentElement.dataset.theme,ready:document.readyState,rows:Array.from(document.querySelectorAll("article[data-extension-id]")).map(e=>[e.dataset.extensionId,e.querySelector("h2 a").textContent]),next:!!document.querySelector("#inventory-next"),first:!!document.querySelector("#inventory-first"),enhanced:r.hasAttribute("hx-get"),vendor:typeof window.htmx!=="undefined",version:window.htmx?.version||"",historyDisabled:window.htmx?.config.historyEnabled===false,cacheDisabled:window.htmx?.config.historyCacheSize===0,companionScripts:Array.from(document.scripts).filter(s=>s.src.endsWith("/inventory.js")).length,vendorScripts:Array.from(document.scripts).filter(s=>s.src.endsWith("/htmx-2.0.10.min.js")).length,companionResources:performance.getEntriesByType("resource").filter(r=>r.name.endsWith("/inventory.js")).length};})()');
 const q=new URLSearchParams(got.query),want=cursor?expected.slice(50):afterTransition?reduced:expected.slice(0,50);
 if(got.path!=='/admin/extensions'||q.get('theme')!=='light'||(q.get('after')||'')!==(cursor?expectedCursor:'')||got.theme!=='light'||got.ready!=='complete'||JSON.stringify(got.rows)!==JSON.stringify(want)||got.next!==(!cursor&&!afterTransition)||got.first!==cursor||got.companionScripts!==1||got.companionResources!==1)throw Error('enhancement page projection: '+label);
 if(cursor?(got.enhanced||got.vendor||got.vendorScripts!==0):(!got.enhanced||!got.vendor||got.version!=='2.0.10'||!got.historyDisabled||!got.cacheDisabled||got.vendorScripts!==1))throw Error('enhancement eligibility: '+label);
 if(await observe(''+JSON.stringify(needles)+'.some(value=>document.documentElement.textContent.includes(value))'))throw Error('document credential leak');
 proof.pages.push({label,rows:got.rows.length,next:got.next,first:got.first,cursor,enhanced:got.enhanced,companionLoaded:true,vendorScripts:got.vendorScripts,sqlMembershipAndOrder:true,membershipSHA256:createHash('sha256').update(JSON.stringify(got.rows)).digest('hex')});
}
async function runEnhanced(){
 proof.version=await call('Browser.getVersion',{},null);
 const target=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:target.targetId},null);await call('Page.enable');await call('Page.setBypassCSP',{enabled:false});await call('Network.enable');await call('Runtime.enable');await call('DOMStorage.enable');await call('Network.setCacheDisabled',{cacheDisabled:true});
 await call('Emulation.setDeviceMetricsOverride',{width:320,height:900,deviceScaleFactor:1,mobile:false});await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});await call('Emulation.setScriptExecutionDisabled',{value:false});
 const denied=await call('Page.navigate',{url:origin.origin+currentPath});await loaded(denied.loaderId);if(proof.responses.at(-1)?.status!==401)throw Error('unauthenticated denial missing');
 // Explicit unrelated sentinel SETUP through native CDP, not a storage API override.
 for(const [local,key,value] of [[true,'fixture-local','local-sentinel'],[false,'fixture-session','session-sentinel']])await call('DOMStorage.setDOMStorageItem',{storageId:{securityOrigin:origin.origin,isLocalStorage:local},key,value});
 const setup=await storageSnapshot();if(setup!==JSON.stringify([[['fixture-local','local-sentinel']],[['fixture-session','session-sentinel']]]))throw Error('storage setup mismatch');
 storagePhase='canonical';
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});bootstrap.session='';bootstrap.csrf='';
 const first=await call('Page.navigate',{url:origin.origin+currentPath});await loaded(first.loaderId);await until('window.htmx?.version==="2.0.10"&&document.querySelector("#inventory-refresh").hasAttribute("hx-get")');await inspect('initial-51',false);
 const canonical=await storageSnapshot();assertStorage(canonical);
 const observed=storageEvents.filter(e=>e.phase==='canonical');
 if(!observed.some(e=>e.keyClass==='probe'&&e.kind==='domStorageItemAdded')||!observed.some(e=>e.keyClass==='probe'&&e.kind==='domStorageItemRemoved')||!observed.some(e=>e.keyClass==='path'))throw Error('storage transient observation unavailable');
 proof.storageVisibility={probeAdded:true,probeRemoved:true,currentPathWrite:true,unrelatedSentinelsPreserved:true};
 const cursorStart=storageEvents.length,vendorStart=proof.requests.vendor,companionStart=proof.requests.companion;
 storagePhase='cursor';await activate('#inventory-next','native-cursor-next');await inspect('cursor-native',true);
 if(await storageSnapshot()!==canonical||proof.requests.vendor!==vendorStart||proof.requests.companion!==companionStart+1)throw Error('cursor initial storage/vendor boundary');
 await activate('#inventory-refresh','native-cursor-refresh');await inspect('cursor-native-refreshed',true);
 if(await storageSnapshot()!==canonical||proof.requests.vendor!==vendorStart||proof.requests.companion!==companionStart+2||storageEvents.length!==cursorStart)throw Error('cursor refresh storage/vendor boundary');
 proof.cursor={nativeNavigations:2,companionLoads:2,vendorLoads:0,storageEvents:0,persistentMapsUnchanged:true,positionRetained:true};
 storagePhase='canonical';await activate('#inventory-first','native-first-return');await until('window.htmx?.version==="2.0.10"&&document.querySelector("#inventory-refresh").hasAttribute("hx-get")');await inspect('before-transition-51',false);assertStorage(await storageSnapshot());
 const frame=(await call('Page.getFrameTree')).frameTree.frame.loaderId,history=await call('Page.getNavigationHistory');
 const shell=await nodeID('main'),region=await nodeID('#extension-inventory'),rows=await nodeID('#extension-inventory > div'),nav=await nodeID('#extension-inventory > nav');
 await focus('#inventory-refresh');await key('Enter',13);
 await until('document.querySelector("#inventory-status").textContent==="Inventory refreshed."&&document.querySelector("#extension-inventory").getAttribute("aria-busy")==="false"&&!document.querySelector("#inventory-next")');
 await inspect('after-explicit-fixture-transition-50',false,true);
 const newHistory=await call('Page.getNavigationHistory');
 const settled=await observe('({focus:document.activeElement.id,error:document.querySelector("#inventory-error").textContent,reloadHidden:document.querySelector("#inventory-reload").hidden,stale:document.querySelector("#extension-inventory").hasAttribute("data-stale"),disabled:document.querySelector("#inventory-refresh").hasAttribute("aria-disabled")})');
 if((await call('Page.getFrameTree')).frameTree.frame.loaderId!==frame||await nodeID('main')!==shell||await nodeID('#extension-inventory')!==region||await nodeID('#extension-inventory > div')===rows||await nodeID('#extension-inventory > nav')===nav||history.currentIndex!==newHistory.currentIndex||history.entries.length!==newHistory.entries.length||settled.focus!=='inventory-refresh'||settled.error!==''||!settled.reloadHidden||settled.stale||settled.disabled||proof.requests.HX!==1)throw Error('fragment swap shell/rows/pager/settled state');
 assertStorage(await storageSnapshot());
 proof.swap={explicitFixtureTransition:'51 to50 by test-only deletion before real HX handler',browserSQLMutation:false,realHX:1,rowsReplaced:true,pagerReplaced:true,nextRemoved:true,regionRetained:true,shellRetained:true,loaderRetained:true,historyUnchanged:true,settled:true,sqlExpectedMembership:true};
 proof.storageScope='Native DOMStorage events before navigation through drain; fixed canonical bookkeeping and transient probe allowed. Native browser URL history intentionally not erased; no HTMX cursor/history-cache storage.';
 proof.coverageGaps=['other engines/widths','full fault matrix/accessibility','live concurrency','performance','target-collation applicability','deployment'];
}

const deadline=setTimeout(()=>fail('enhancement browser deadline'),80000);
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>fail('enhancement browser interrupted'));
try{await runEnhanced();passed=true;}catch(e){failed=true;proof.error=e.message;}
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
 proof.storageEvents=storageEvents;proof.networkResponses=networkResponses;
 proof.gate=passed&&!failed&&!proof.cleanupFailed&&drained&&proof.browserExit?.code===0&&!proof.browserExit?.signal?'PASS':'FAIL';
 if(proof.gate!=='PASS')process.exitCode=1;
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({enhancementGate:proof.gate,pages:proof.pages?.length,error:proof.error,cleanupFailed:!!proof.cleanupFailed}));
}
