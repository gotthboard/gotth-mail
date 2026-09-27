// Test-only bounded native browser gates. No app scripts or DOM mutations.
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
const configurationMode=bootstrap.mode==='configuration';
if(!['navigation','audit','configuration'].includes(bootstrap.mode || 'navigation'))throw Error('unknown browser mode');
const credentialNeedles=(auditMode||configurationMode)?[bootstrap.session,bootstrap.csrf,...(configurationMode?[bootstrap.secret]:[])]:[];
let configurationPosts=0;
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
if(configurationMode){proof.scope='native initial configuration only; not renderer acceptance';proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.configuration={};}
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
   if(configurationMode || download){rejectPending(Error('unexpected download'));interrupted=true;}
   download=message.params;
  }else if(message.method==='Browser.downloadProgress'){
   if(download && message.params.guid===download.guid)downloadProgress=message.params;
  }else if(configurationMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   configurationPosts++; // never retain headers or body
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
// Only native input changes controls. All Runtime.evaluate expressions are observations.
function configurationRed(reason){proof.productRed=reason;throw Error(reason);}
async function focusConfiguration(selector){
 for(let i=0;i<100;i++){
  if(await observe('document.activeElement.matches('+JSON.stringify(selector)+')'))return;
  await key('Tab',9);
 }
 configurationRed('configuration control unreachable by native Tab');
}
async function typeConfiguration(text){
 for(const ch of text)await call('Input.dispatchKeyEvent',{type:'char',text:ch,key:ch});
}
// Chromium 151 HTMLElement::HandleKeyboardActivation activates Enter on keypress CR,
// not a bare keyDown/keyUp. Keep the admitted navigation/audit helper unchanged.
async function configurationEnter(){
 await call('Input.dispatchKeyEvent',{type:'rawKeyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
 await call('Input.dispatchKeyEvent',{type:'char',key:'Enter',code:'Enter',text:'\r',unmodifiedText:'\r',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
 await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
}
async function submitConfiguration(selector,detail){
 await focusConfiguration(selector);
 const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
 await configurationEnter();
 let loader;
 for(let i=0;i<100;i++){
  loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
  if(loader!==prior)break;
  await delay(50);
 }
 if(loader===prior)configurationRed('valid native configuration submit did not navigate');
 await loaded(detail,loader);
 if(proof.responses.at(-1)?.status!==200)throw Error('configuration response failed; inspect independent Go oracle');
}
async function runConfiguration(detail){
 if(typeof bootstrap.endpoint!=='string' || !bootstrap.endpoint.startsWith('https://127.0.0.1:') || !/^[a-f0-9]{64}$/.test(bootstrap.secret))throw Error('invalid private configuration fixture inputs');
 const preview='#configuration>form:first-of-type';
 const apply='#configuration>form:nth-of-type(2)';
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('initial configuration detail unavailable');
 for(const [name,value] of [['webhook.endpoint',bootstrap.endpoint],['webhook.timeout-seconds','2'],['webhook.hmac-key',bootstrap.secret]]){
  const selector=preview+' [name="field.'+name+'"]';
  if(!await observe('document.querySelector('+JSON.stringify(selector)+')?.value===""'))configurationRed('initial configuration control not blank');
  await focusConfiguration(selector);await typeConfiguration(value);
 }
 const typed=await observe('(()=>{const f=document.querySelector("#configuration>form");return {endpoint:f.elements["field.webhook.endpoint"].value,timeout:f.elements["field.webhook.timeout-seconds"].value,secret:f.elements["field.webhook.hmac-key"].value,valid:Array.from(f.elements).every(e=>!e.willValidate||e.validity.valid)};})()');
 if(typed.endpoint!==bootstrap.endpoint || typed.timeout!=='2' || typed.secret!==bootstrap.secret)throw Error('native typing equipment did not supply expected inputs');
 proof.configuration.typedInputsMatch=true;proof.configuration.initialValidity=typed.valid;typed.secret='';
 if(!typed.valid)configurationRed('initial expected configuration fails native validity');
 await submitConfiguration(preview+' button[value="configure-preview"]',detail);
 if(configurationPosts!==1)throw Error('unexpected preview POST count');
 const observed=await observe('(()=>{const forms=document.querySelectorAll("#configuration>form");const a=forms[1];return {forms:forms.length,endpoint:forms[0]?.elements["field.webhook.endpoint"]?.value,timeout:forms[0]?.elements["field.webhook.timeout-seconds"]?.value,previewSecret:forms[0]?.elements["field.webhook.hmac-key"]?.value,applySecret:a?.elements["field.webhook.hmac-key"]?.value,acceptedEndpoint:a?.elements["field.webhook.endpoint"]?.value,acceptedTimeout:a?.elements["field.webhook.timeout-seconds"]?.value,summary:Array.from(document.querySelectorAll("#configuration-reviewed dd")).map(e=>e.textContent),confirmation:a?.elements.confirmation?.value,phrase:a?.querySelector("p>code")?.textContent};})()');
 if(observed.forms!==2 || observed.endpoint!==bootstrap.endpoint || observed.timeout!=='2' || observed.acceptedEndpoint!==bootstrap.endpoint || observed.acceptedTimeout!=='2' || observed.previewSecret!=='' || observed.applySecret!=='' || observed.confirmation!=='' || JSON.stringify(observed.summary)!==JSON.stringify([bootstrap.endpoint,'2']) || !/^confirm-[a-f0-9]{32}$/.test(observed.phrase))configurationRed('reviewed native configuration target mismatch');
 proof.configuration.previewAccepted=true;proof.configuration.secretControlsBlank=true;
 await focusConfiguration(apply+' [name="field.webhook.hmac-key"]');await typeConfiguration(bootstrap.secret);
 await focusConfiguration(apply+' button[value="configure-apply"]');
 const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
 await configurationEnter();await delay(250);
 const denied=await observe('({name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,value:document.activeElement.value})');
 if(configurationPosts!==1 || (await call('Page.getFrameTree')).frameTree.frame.loaderId!==prior || denied.name!=='confirmation' || denied.missing!==true || denied.value!=='')configurationRed('blank configuration confirmation did not block native submit');
 proof.configuration.blankConfirmationBlocked=true;
 await typeConfiguration(observed.phrase); // native validation focused the ordinary confirmation input
 credentialNeedles.push(observed.phrase);observed.phrase='';
 await submitConfiguration(apply+' button[value="configure-apply"]',detail);
 if(configurationPosts!==2)throw Error('unexpected apply POST count');
 proof.configuration.applyAccepted=true;
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId); // ordinary GET reload, never replay POST
 if(proof.responses.at(-1)?.status!==200)throw Error('configuration reload failed');
 const persisted=await observe('({endpoint:document.querySelector("#configuration form").elements["field.webhook.endpoint"].value,timeout:document.querySelector("#configuration form").elements["field.webhook.timeout-seconds"].value,secretsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),secretStatus:document.querySelector("#secrets").textContent,forms:document.querySelectorAll("#configuration>form").length})');
 if(persisted.endpoint!==bootstrap.endpoint || persisted.timeout!=='2' || !persisted.secretsBlank || !persisted.secretStatus.includes('webhook.hmac-key: configured (value hidden)') || persisted.forms!==1)configurationRed('configured native reload mismatch');
 proof.configuration.reloadPersisted=true;proof.configuration.posts=configurationPosts;
 proof.configurationGate='PASS';bootstrap.secret='';
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
 if(configurationMode){
  await runConfiguration(detail);
 }else if(auditMode){
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
}catch(e){if(configurationMode)proof.configurationGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(auditMode)proof.auditGate='FAIL';else proof.firstGate=proof.productRed?'PRODUCT_RED':'EQUIPMENT_FAILURE';proof.error=e.message;process.exitCode=1;}
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
 if(configurationMode && (interrupted || !drained || proof.cleanupFailed)){proof.configurationGate='FAIL';proof.error='configuration interrupted or cleanup incomplete';process.exitCode=1;}
 if(configurationMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.configurationGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['configurationGate','error'].includes(k))delete proof[k];}
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({firstGate:proof.firstGate,auditGate:proof.auditGate,configurationGate:proof.configurationGate,audit:proof.audit,productRed:proof.productRed,cleanupFailed:!!proof.cleanupFailed,pages:(proof.pages||[]).map(x=>({name:x.name,client:x.client,scroll:x.scroll}))}));
}
