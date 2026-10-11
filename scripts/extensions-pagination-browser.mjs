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
const permissionsMode=bootstrap.mode==='permissions';
if((!permissionsMode&&bootstrap.mode!=='pagination')||origin.protocol!=='http:'||origin.hostname!=='127.0.0.1'||!/^[a-f0-9-]{36}$/.test(bootstrap.id))throw Error('invalid inventory fixture');
const needles=[bootstrap.session,bootstrap.csrf].filter(Boolean);
const expected=bootstrap.expected;
if(!Array.isArray(expected)||expected.length!==(permissionsMode?1:101)||new Set(expected.map(x=>x[0])).size!==(permissionsMode?1:101)||expected.some(x=>!Array.isArray(x)||x.length!==2||typeof x[0]!== 'string'||typeof x[1]!== 'string'))throw Error('independent SQL bootstrap cardinality');
const proof={scope:permissionsMode?'native readonly permission paging; SQL/login setup synthetic':'single native no-JavaScript pagination workflow; synthetic SQL and login setup',gate:'RUNNING',width:320,initialTheme:'light',appJavaScript:false,defaultSandbox:true,pages:[],focus:[],history:[],responses:[],requests:{GET:0,mutation:0,vendor:0}};
let failed=false,closed=false,drained=false,closing=false,passed=false,serial=0,session,buffer=Buffer.alloc(0),stderrBytes=0;
const pending=new Map();
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
  if(m.sessionId!==session)continue;
  if(m.method==='Network.requestWillBeSent'){
   const r=m.params.request,u=new URL(r.url);
   if(r.method==='GET')proof.requests.GET++;else proof.requests.mutation++;
   if(u.pathname.endsWith('/htmx-2.0.10.min.js'))proof.requests.vendor++;
   if(r.method!=='GET'||(u.protocol!=='about:'&&u.origin!==origin.origin)||Object.keys(r.headers).some(k=>k.toLowerCase()==='authorization'))fail('unexpected request authority or method');
  }
  if(m.method==='Network.responseReceived'&&m.params.type==='Document'){const r=m.params.response,u=new URL(r.url);if(u.origin===origin.origin)proof.responses.push({path:u.pathname,status:r.status});}
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

function cursor(page){return page===0?'':'v1.'+Buffer.from(expected[page*50-1][1],'utf8').toString('base64url');}
async function inspect(page,theme,label){
 const got=await observe('(()=>{const nav=document.querySelector("#extension-inventory > nav");return {path:location.pathname,query:location.search,theme:document.documentElement.dataset.theme,ready:document.readyState,rows:Array.from(document.querySelectorAll("article[data-extension-id]")).map(e=>[e.dataset.extensionId,e.querySelector("h2 a").textContent]),first:!!document.querySelector("#inventory-first"),next:!!document.querySelector("#inventory-next"),nav:!!nav,navVisible:!!nav&&getComputedStyle(nav).display!=="none",width:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,busy:document.querySelector("#extension-inventory").getAttribute("aria-busy"),enhanced:document.querySelector("#inventory-refresh").hasAttribute("hx-get"),vendor:typeof window.htmx!=="undefined"};})()');
 const q=new URLSearchParams(got.query),want=expected.slice(page*50,page*50+50);
 if(got.path!=='/admin/extensions'||q.get('theme')!==theme||(q.get('after')||'')!==cursor(page)||q.getAll('after').length!==(page===0?0:1)||got.theme!==theme||got.ready!=='complete'||JSON.stringify(got.rows)!==JSON.stringify(want)||got.first!==(page>0)||got.next!==(page<2)||!got.nav||!got.navVisible||got.busy!=='false'||got.enhanced||got.vendor)throw Error('pagination page projection mismatch: '+label);
 if(got.width!==320||got.scroll>got.client)throw Error('pagination horizontal overflow: '+label);
 if(await observe(''+JSON.stringify(needles)+'.some(value=>document.documentElement.textContent.includes(value))'))throw Error('credential leak in document');
 proof.pages.push({label,page:page+1,theme,rows:got.rows.length,sqlMembershipAndOrder:true,membershipSHA256:createHash('sha256').update(JSON.stringify(got.rows)).digest('hex'),first:got.first,next:got.next,navVisible:got.navVisible,width:got.width,client:got.client,scroll:got.scroll,ordinaryHTML:true});
 return got.rows;
}
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
async function history(direction,page,theme){
 const old=await call('Page.getNavigationHistory'),index=old.currentIndex+direction,target=old.entries[index];
 if(!target)throw Error('pagination native history entry absent');
 await call('Page.navigateToHistoryEntry',{entryId:target.id});
 let ready=false;
 for(let i=0;i<150;i++){
  const h=await call('Page.getNavigationHistory');
  if(h.currentIndex===index&&h.entries[index]?.id===target.id&&await observe('document.readyState==="complete"&&location.href==='+JSON.stringify(target.url))){ready=true;break;}
  await delay(30);
 }
 if(!ready)throw Error('pagination history navigation incomplete');
 if(permissionsMode)await inspectPermissions(page,theme,direction<0?'history-back':'history-forward');else await inspect(page,theme,direction<0?'history-back':'history-forward');
 proof.history.push({direction:direction<0?'Back':'Forward',mechanism:'CDP Page.navigateToHistoryEntry',entryIdentity:true,indexDelta:direction,keyboardShortcut:false});
}
async function runPagination(){
 proof.version=await call('Browser.getVersion',{},null);
 const target=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:target.targetId},null);await call('Page.enable');await call('Page.setBypassCSP',{enabled:false});await call('Network.enable');
 await call('Emulation.setDeviceMetricsOverride',{width:320,height:900,deviceScaleFactor:1,mobile:false});
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});
 await call('Emulation.setScriptExecutionDisabled',{value:true});
 const denied=await call('Page.navigate',{url:origin.origin+'/admin/extensions?theme=light'});await loaded(denied.loaderId);
 if(proof.responses.at(-1)?.status!==401)throw Error('unauthenticated browser not denied');proof.unauthenticatedDenied=true;
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});bootstrap.session='';bootstrap.csrf='';
 const first=await call('Page.navigate',{url:origin.origin+'/admin/extensions?theme=light'});await loaded(first.loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('initial authenticated inventory unavailable');
 let traversed=await inspect(0,'light','initial-first');
 await activate('#inventory-next','first-next');traversed.push(...await inspect(1,'light','middle'));
 await activate('#inventory-next','middle-next');traversed.push(...await inspect(2,'light','last'));
 if(JSON.stringify(traversed)!==JSON.stringify(expected)||new Set(traversed.map(x=>x[0])).size!==101)throw Error('pagination traversal duplicate/omission');
 proof.traversal={counts:[50,50,1],total:101,unique:101,sqlOrder:true,exactMembership:true,nextAbsentAtEnd:true};
 await history(-1,1,'light');await history(1,2,'light');await history(-1,1,'light');
 for(const theme of ['dark','system','light']){
  await activate('nav[aria-label="Inventory theme"] a[href*="theme='+theme+'"]','middle-theme-'+theme);
  await inspect(1,theme,'middle-theme-'+theme);
 }
 await activate('#inventory-refresh','middle-refresh');await inspect(1,'light','middle-refreshed');
 await activate('#inventory-first','first-light');await inspect(0,'light','first-light');
 await activate('#inventory-next','middle-again');await inspect(1,'light','middle-again');
 await activate('nav[aria-label="Inventory theme"] a[href*="theme=dark"]','middle-dark');await inspect(1,'dark','middle-dark');
 await activate('nav[aria-label="Breadcrumb"] a[href^="/admin/extensions"]','breadcrumb-dark');await inspect(0,'dark','breadcrumb-dark-first');
 await activate('#inventory-next','dark-middle');await inspect(1,'dark','dark-middle');
 await activate('#inventory-first','first-dark');await inspect(0,'dark','first-dark');
 if(proof.requests.mutation!==0||proof.requests.vendor!==0)throw Error('pagination unexpected mutation/vendor');
 proof.historySemantics='native history entry navigation; GET counts observational; no BFCache guarantee';
 proof.coverageGaps=['JS-on cursor/vendor/storage','first-page HX navigation refresh','other engines/widths','full accessibility','live concurrency','performance','actual deployment domain'];
}


// Test-only DOM observation costs O(D+V) for scanned DOM/full form value bytes;
// browser layout/CDP serialization are delegated. No application JS or DOM writes.
async function inspectPermissions(page,theme,label){
 const got=await observe('(()=>({path:location.pathname,query:location.search,theme:document.documentElement.dataset.theme,rows:Array.from(document.querySelectorAll("#permissions li")).map(e=>[e.dataset.permissionCategory,e.textContent]),previous:!!document.querySelector("#permissions-previous"),next:!!document.querySelector("#permissions-next"),forms:["capabilities","interfaces","secret_slots"].map(n=>document.querySelector("input[name="+n+"]").value),actions:Array.from(document.querySelectorAll("form")).map(f=>f.getAttribute("action")),passwordsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),width:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,vendor:typeof window.htmx!=="undefined"}))()');
 const categories=['capabilities','interfaces','secret_slots'],grants=bootstrap.grants;
 const want=grants.flatMap((list,i)=>list.map(v=>[categories[i],v])).slice((page-1)*25,page*25),q=new URLSearchParams(got.query);
 if(got.path!=='/admin/extensions/'+bootstrap.id||q.get('theme')!==theme||(q.get('permissions_page')||'1')!==String(page)||got.theme!==theme||JSON.stringify(got.rows)!==JSON.stringify(want)||got.previous!==(page>1)||got.next!==(page<4)||got.vendor||!got.passwordsBlank)throw Error('permissions projection/privacy: '+label);
 if(got.forms.some((value,i)=>value!==grants[i].join(','))||got.actions.some(a=>a!=='/admin/extensions/'+bootstrap.id+'?theme='+theme))throw Error('permissions truncated form or changed action');
 if(got.width!==320||got.scroll>got.client)throw Error('permissions horizontal overflow');
 if(await observe(''+JSON.stringify(needles)+'.some(value=>document.documentElement.textContent.includes(value))'))throw Error('permissions credential text');
 proof.pages.push({label,page,theme,entries:got.rows.length,exactCategoryOrder:true,completeUpdateInputs:true,actionURLUnchanged:true,passwordsBlank:true,membershipSHA256:createHash('sha256').update(JSON.stringify(got.rows)).digest('hex'),width:got.width,client:got.client,scroll:got.scroll});
 return got.rows;
}
// One finite workflow; existing CDP/native keyboard/history and drain mechanisms.
async function runPermissions(){
 if(!Array.isArray(bootstrap.grants)||bootstrap.grants.length!==3||bootstrap.grants.some(x=>!Array.isArray(x)||x.length!==26||x.some(v=>typeof v!=='string')))throw Error('permissions fixture grants');
 proof.version=await call('Browser.getVersion',{},null);
 const target=await call('Target.createTarget',{url:'about:blank'},null);session=(await call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:target.targetId},null);await call('Page.enable');await call('Page.setBypassCSP',{enabled:false});await call('Network.enable');
 await call('Emulation.setDeviceMetricsOverride',{width:320,height:900,deviceScaleFactor:1,mobile:false});
 await call('Emulation.setScriptExecutionDisabled',{value:true});
 const denied=await call('Page.navigate',{url:origin.origin+'/admin/extensions?theme=light'});await loaded(denied.loaderId);if(proof.responses.at(-1)?.status!==401)throw Error('permissions auth denial');proof.unauthenticatedDenied=true;
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});bootstrap.session='';bootstrap.csrf='';
 const first=await call('Page.navigate',{url:origin.origin+'/admin/extensions?theme=light'});await loaded(first.loaderId);
 const inventory=await observe('(()=>{const row=document.querySelector('+JSON.stringify('article[data-extension-id="'+bootstrap.id+'"]')+');return {counts:Array.from(row.querySelectorAll("[data-permission-count]")).map(e=>[e.dataset.permissionCount,e.textContent.trim()]),href:row.querySelector("[data-permissions-link]").getAttribute("href"),expanded:row.querySelectorAll("li").length};})()');
 if(JSON.stringify(inventory.counts)!==JSON.stringify([['capabilities','26'],['interfaces','26'],['secret_slots','26']])||inventory.href!=='/admin/extensions/'+bootstrap.id+'?theme=light#permissions'||inventory.expanded!==0)throw Error('inventory permissions counts/link');
 proof.inventory={counts:[26,26,26],noExpandedLists:true,correctDetailLink:true};
 await activate('a[data-permissions-link]','view-permissions');let traversed=await inspectPermissions(1,'light','first');
 await activate('#permissions-next','next2');traversed.push(...await inspectPermissions(2,'light','second'));
 await history(-1,1,'light');await history(1,2,'light');
 await activate('#permissions-previous','previous1');await inspectPermissions(1,'light','previous-first');
 await activate('#permissions-next','next2-again');await inspectPermissions(2,'light','second-again');
 await activate('nav[aria-label="Detail theme"] a[href*="theme=dark"]','theme-dark');await inspectPermissions(2,'dark','second-dark');
 await activate('#permissions-next','next3');traversed.push(...await inspectPermissions(3,'dark','third'));
 await activate('#permissions-next','next4');traversed.push(...await inspectPermissions(4,'dark','last'));
 const categories=['capabilities','interfaces','secret_slots'];const expectedGrants=bootstrap.grants.flatMap((list,i)=>list.map(v=>[categories[i],v]));
 if(JSON.stringify(traversed)!==JSON.stringify(expectedGrants))throw Error('permissions missing/duplicate traversal');
 await activate('#permissions-previous','previous3');await inspectPermissions(3,'dark','previous-third');
 if(proof.requests.mutation!==0||proof.requests.vendor!==0)throw Error('permissions mutation/vendor');
 proof.traversal={counts:[25,25,25,3],total:78,exactCategoryAndOccurrenceOrder:true};
 proof.coverageGaps=['other engines','CSS-disabled','live concurrent changes','real identity login','full UI completion','performance bounds'];
}

const deadline=setTimeout(()=>fail('pagination browser deadline'),80000);
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>fail('pagination browser interrupted'));
try{if(permissionsMode)await runPermissions();else await runPagination();passed=true;}catch(e){failed=true;proof.error=e.message;}
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
 proof.gate=passed&&!failed&&!proof.cleanupFailed&&drained&&proof.browserExit?.code===0&&!proof.browserExit?.signal?'PASS':'FAIL';
 if(proof.gate!=='PASS')process.exitCode=1;
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({paginationGate:proof.gate,pages:proof.pages?.length,error:proof.error,cleanupFailed:!!proof.cleanupFailed}));
}
