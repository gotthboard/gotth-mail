// Test-only first live navigation gate. No app scripts, DOM writes, or form actions.
import {spawn} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,readdirSync,rmSync,statSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join,resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
const output=resolve(process.argv[2] || '');
if(!process.argv[2] || process.env.GOTTH_MAIL_ACCEPTANCE_NAMESPACE!=='1') throw Error('namespace runner required');
mkdirSync(output,{mode:0o700}); // no overwrite of an existing evidence run
const bootstrap=JSON.parse(readFileSync(0,'utf8'));
const auditMode=bootstrap.mode==='audit';
const credentialNeedles=auditMode?[bootstrap.session,bootstrap.csrf]:[];
const origin=new URL(bootstrap.origin);
if(origin.protocol!=='http:' || origin.hostname!=='127.0.0.1' || !/^[a-f0-9-]{36}$/.test(bootstrap.id)) throw Error('invalid fixture origin/id');
const proof={scope:'first live navigation only',width:320,theme:'light',appJavaScript:false,defaultSandbox:true,diagnostics:'read-only Runtime.evaluate; native CDP keyboard actions',pages:[],focus:[],responses:[]};
function chromeProcesses(){
 const result=[];
 for(const id of readdirSync('/proc').filter(x=>/^[0-9]+$/.test(x))){
  try{
   const comm=readFileSync('/proc/'+id+'/comm','utf8').trim();
   if(!['chromium','chrome_crashpad'].includes(comm))continue;
   const stat=readFileSync('/proc/'+id+'/stat','utf8');
   const state=stat.slice(stat.lastIndexOf(')')+2).split(' ')[0];
   if(state!=='Z')result.push({pid:Number(id),comm,state});
  }catch(e){if(e.code!=='ENOENT' && e.code!=='ESRCH')throw e;}
 }
 return result;
}
if(chromeProcesses().length)throw Error('namespace already has a browser');
const profile=mkdtempSync('/tmp/mail-browser-');
const downloads=auditMode?mkdtempSync('/tmp/mail-download-'):null;
let download,downloadProgress;
if(auditMode){proof.scope='native audit download only';proof.firstGate='NOT_RUN';}
const browser=spawn('/usr/lib/chromium/chromium',['--headless','--remote-debugging-pipe','--disable-background-networking','--no-first-run','--no-default-browser-check','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe','pipe','pipe'],detached:true});
let closed=false,drained=false,closing=false,interrupted=false,serial=0,session,buffer=Buffer.alloc(0),stderrBytes=0;
const pending=new Map();
let resolveExit;
const exited=new Promise(r=>{resolveExit=r;});
function rejectPending(reason){for(const entry of pending.values()){clearTimeout(entry.timer);entry.reject(reason);}pending.clear();}
browser.on('error',()=>{closed=true;proof.spawnError=true;rejectPending(Error('browser spawn failed'));});
browser.on('exit',(code,signal)=>{closed=true;proof.browserExit={code,signal};rejectPending(Error('browser exited'));});
// ChildProcess close follows exit AND closure of its stdio streams.
browser.on('close',()=>{drained=true;resolveExit();});
browser.stderr.on('data',b=>{stderrBytes+=b.length;}); // never retain unfiltered browser output
browser.stdio[3].on('error',()=>rejectPending(Error('CDP write failed')));
browser.stdio[4].on('error',()=>rejectPending(Error('CDP read failed')));
browser.stdio[4].on('data',chunk=>{
 if(buffer.length+chunk.length>8*1024*1024){rejectPending(Error('CDP envelope limit'));browser.kill('SIGTERM');return;}
 buffer=Buffer.concat([buffer,chunk]);
 let end;
 while((end=buffer.indexOf(0))!==-1){
  const packet=buffer.subarray(0,end);buffer=buffer.subarray(end+1);
  let message;try{message=JSON.parse(packet.toString('utf8'));}catch{rejectPending(Error('invalid CDP envelope'));continue;}
  if(message.id && pending.has(message.id)){
   const entry=pending.get(message.id);pending.delete(message.id);clearTimeout(entry.timer);
   if(message.error)entry.reject(Error('CDP command failed: '+entry.method));else entry.resolve(message.result || {});
  }else if(message.method==='Browser.downloadWillBegin'){
   if(download){rejectPending(Error('unexpected extra download'));interrupted=true;}
   download=message.params;
  }else if(message.method==='Browser.downloadProgress'){
   if(download && message.params.guid===download.guid)downloadProgress=message.params;
  }else if(message.method==='Network.responseReceived' && message.sessionId===session && message.params.type==='Document'){
   const u=new URL(message.params.response.url);
   if(u.origin===origin.origin)proof.responses.push({path:u.pathname,status:message.params.response.status});
  }
 }
});
function call(method,params={},target=session){
 if(closed || (interrupted&&!closing))return Promise.reject(Error('browser unavailable'));
 return new Promise((resolve,reject)=>{
  const id=++serial;
  const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout: '+method));},8000);
  pending.set(id,{resolve,reject,timer,method});
  browser.stdio[3].write(JSON.stringify({id,method,params,...(target?{sessionId:target}:{})})+'\0');
 });
}
const timer=setTimeout(()=>{interrupted=true;rejectPending(Error('driver overall deadline'));},65000);
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{interrupted=true;rejectPending(Error('driver interrupted'));});
async function observe(expression){
 const result=await call('Runtime.evaluate',{expression,returnByValue:true});
 if(result.exceptionDetails)throw Error('read-only observation failed');
 return result.result.value;
}
async function loaded(path,loader){
 for(let i=0;i<80;i++){
  if(interrupted)throw Error('driver interrupted');
  if(loader && (await call('Page.getFrameTree')).frameTree.frame.loaderId!==loader){await delay(50);continue;}
  const state=await observe('({path:location.pathname,ready:document.readyState})');
  if(state.path===path && state.ready==='complete')return;
  await delay(50);
 }
 throw Error('navigation deadline');
}
async function key(key,code){
 await call('Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});
 await call('Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code});
}
async function inspectPage(name){
 const metrics=await observe('({path:location.pathname,viewport:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,overflow:Array.from(document.querySelectorAll("h1,li,dd,code,input,select,button")).map(e=>({tag:e.tagName,left:e.getBoundingClientRect().left,right:e.getBoundingClientRect().right})).filter(x=>x.left<0||x.right>innerWidth).slice(0,30)})');
 const shot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
 writeFileSync(join(output,name+'.png'),Buffer.from(shot.data,'base64'),{mode:0o600});
 proof.pages.push({name,...metrics});
 if(metrics.viewport!==320)throw Error('viewport setup failed');
 if(metrics.scroll>metrics.client || metrics.overflow.length){proof.productRed='320px reflow: '+name;throw Error('product reflow red');}
}
try{
 proof.version=await call('Browser.getVersion',{},null);
 const target=await call('Target.createTarget',{url:'about:blank'},null);
 session=(await call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:target.targetId},null);
 await call('Page.enable');await call('Network.enable');
 await call('Emulation.setDeviceMetricsOverride',{width:320,height:800,deviceScaleFactor:1,mobile:false});
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});
 await call('Emulation.setScriptExecutionDisabled',{value:true});
 const list='/admin/extensions';
 await loaded(list,(await call('Page.navigate',{url:origin.origin+list})).loaderId);
 if(proof.responses.at(-1)?.status!==401)throw Error('unauthenticated browser not denied');
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});
 bootstrap.session='';bootstrap.csrf='';
 const detail=list+'/'+bootstrap.id;
 if(auditMode){
  await call('Browser.setDownloadBehavior',{behavior:'allowAndName',downloadPath:downloads,eventsEnabled:true},null);
  await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
  if(proof.responses.at(-1)?.status!==200)throw Error('authenticated detail failed');
  const auditPath=detail+'/audit';
  let reached=false;
  for(let i=0;i<100;i++){
   await key('Tab',9);
   const focus=await observe('({tag:document.activeElement.tagName,href:document.activeElement.getAttribute("href")})');
   if(focus.tag==='A' && focus.href===auditPath){proof.auditTabs=i+1;reached=true;break;}
  }
  if(!reached)throw Error('audit link unreachable by native keyboard');
  await key('Enter',13);
  for(let i=0;i<100 && downloadProgress?.state!=='completed';i++){
   if(interrupted || downloadProgress?.state==='canceled')throw Error('audit download interrupted');
   await delay(50);
  }
  if(interrupted || downloadProgress?.state!=='completed' || download?.url!==origin.origin+auditPath || download.suggestedFilename!=='extension-audit.jsonl' || !/^[a-f0-9-]{36}$/.test(download.guid))throw Error('audit download did not complete as expected');
  const path=join(downloads,download.guid);
  const size=statSync(path).size;
  if(size===0 || size>1024*1024 || size!==downloadProgress.receivedBytes)throw Error('audit attachment size mismatch or fixture limit');
  const bytes=readFileSync(path);const raw=bytes.toString('utf8');
  if(credentialNeedles.some(s=>s && raw.includes(s)))throw Error('audit attachment exposed fixture credentials');
  if(!raw.endsWith('\n'))throw Error('audit attachment missing final line ending');
  let events;try{events=raw.trimEnd().split('\n').map(line=>JSON.parse(line));}catch{throw Error('invalid audit JSONL attachment');}
  const expected=JSON.parse(bootstrap.audit_expected);
  if(events.length!==expected.length || events.some((row,i)=>row.ID!==expected[i].id || row.Action!==expected[i].action || row.Resource?.Type!=='extension' || row.Resource.ID!==bootstrap.id))throw Error('audit attachment differs from independent SQL scope/order');
  proof.audit={state:'completed',bytes:size,events:events.length,sha256:createHash('sha256').update(bytes).digest('hex'),independentSQLMatch:true,credentialLeak:false};
  proof.auditGate='PASS';
 }else{
 await loaded(list,(await call('Page.navigate',{url:origin.origin+list})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('authenticated inventory failed');
 await inspectPage('inventory');
 let found=false;
 for(let i=0;i<20;i++){
  await key('Tab',9);
  const focus=await observe('({tag:document.activeElement.tagName,href:document.activeElement.getAttribute("href"),outline:getComputedStyle(document.activeElement).outlineStyle})');
  proof.focus.push(focus);
  if(focus.tag==='A' && focus.href===detail){found=true;break;}
 }
 if(!found){proof.productRed='detail link unreachable by keyboard';throw Error('product keyboard red');}
 await key('Enter',13);await loaded(detail);
 if(proof.responses.at(-1)?.status!==200)throw Error('detail navigation failed');
 await inspectPage('detail');
 proof.firstGate='PASS';
 }
}catch(e){if(auditMode)proof.auditGate='FAIL';else proof.firstGate=proof.productRed?'PRODUCT_RED':'EQUIPMENT_FAILURE';proof.error=e.message;process.exitCode=1;}
finally{
 clearTimeout(timer);closing=true;
 try{if(!closed)await call('Browser.close',{},null);}catch{/* shutdown may close pipe before reply */}
 await Promise.race([exited,delay(2500)]);
 if(!closed){proof.forcedShutdown=true;try{process.kill(-browser.pid,'SIGTERM');}catch(e){if(e.code!=='ESRCH')proof.signalError=true;}await Promise.race([exited,delay(1500)]);}
 if(!closed){proof.forcedShutdown=true;try{process.kill(-browser.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')proof.signalError=true;}await Promise.race([exited,delay(1000)]);}
 let remaining=[];
 for(let i=0;i<20;i++){remaining=chromeProcesses();if(!remaining.length)break;await delay(50);}
 proof.cleanup={mainExited:closed,remaining,unfilteredStderrBytes:stderrBytes};
 if(!closed || remaining.length || proof.forcedShutdown || proof.signalError){proof.cleanupFailed=true;process.exitCode=1;}else {rmSync(profile,{recursive:true});if(downloads)rmSync(downloads,{recursive:true});}
 rejectPending(Error('driver closed'));browser.stdio[3].destroy();browser.stdio[4].destroy();browser.stderr.destroy();
 // No await between this final latch and proof publication: late events cannot restore PASS.
 if(auditMode && (interrupted || !drained)){proof.auditGate='FAIL';proof.error='audit interrupted or event stream not drained before proof';process.exitCode=1;}
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({firstGate:proof.firstGate,auditGate:proof.auditGate,audit:proof.audit,productRed:proof.productRed,cleanupFailed:!!proof.cleanupFailed,pages:proof.pages.map(x=>({name:x.name,client:x.client,scroll:x.scroll}))}));
}
