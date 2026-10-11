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
const detailThemeMode=bootstrap.mode==='detail-theme';
const auditMode=bootstrap.mode==='audit';
const configurationNoCSS=bootstrap.mode==='configuration-no-css';
const configurationMode=bootstrap.mode==='configuration'||configurationNoCSS;
const recoveryNoCSS=bootstrap.mode==='secrets-delete-recovery-no-css';
const recoverySecretsMode=bootstrap.mode==='secrets-delete-recovery'||recoveryNoCSS;
const cssDenialMode=configurationNoCSS||recoveryNoCSS;
const secretsMode=bootstrap.mode==='secrets-delete'||recoverySecretsMode;
const uninstallMode=bootstrap.mode==='uninstall';
const connectionMode=bootstrap.mode==='connection-test';
const activationMode=bootstrap.mode==='activation';
const updateMode=bootstrap.mode==='update';
const rollbackMode=bootstrap.mode==='rollback';
if(!['configuration-no-css','detail-theme','navigation','audit','configuration','secrets-delete','secrets-delete-recovery','secrets-delete-recovery-no-css','uninstall','connection-test','activation','update','rollback'].includes(bootstrap.mode || 'navigation'))throw Error('unknown browser mode');
const credentialNeedles=(detailThemeMode||auditMode||uninstallMode||secretsMode||configurationMode||connectionMode||activationMode||updateMode||rollbackMode)?[bootstrap.session,bootstrap.csrf,...((configurationMode||secretsMode||uninstallMode)?[bootstrap.secret]:[])]:[];
let secretsPosts=0,uninstallPosts=0;
let configurationPosts=0,connectionPosts=0,activationPosts=0,updatePosts=0,rollbackPosts=0;
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
if(detailThemeMode){proof.scope='native detail themes only; initial unconfigured fixture';proof.firstGate='NOT_RUN';proof.scriptRequests=0;}
if(auditMode){proof.scope='native audit download only';proof.firstGate='NOT_RUN';}
if(uninstallMode){proof.scope='native D4 uninstall '+bootstrap.phase+' phase; inter-phase secret removal is service SETUP';proof.phase=bootstrap.phase;proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.uninstall={};}
if(secretsMode){proof.scope='native D3 secret deletion only; configured setup injected';proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.secrets={};}
if(cssDenialMode)proof.cssDenial={injected:true,reason:'inspector with exact empty or net::ERR_BLOCKED_BY_CLIENT errorText',acceptedErrorForms:{empty:0,blockedByClient:0},attempts:{'/admin/extensions/assets/detail.css':0,'/admin/extensions/assets/tokens.css':0},blocked:{'/admin/extensions/assets/detail.css':0,'/admin/extensions/assets/tokens.css':0},checkpoints:0};
if(configurationMode){proof.scope='native initial configuration only; not renderer acceptance';proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.configuration={};}
if(connectionMode){proof.scope='native Test only; configured setup and login injected; not renderer acceptance';proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.configurationGate='NOT_RUN';}
if(activationMode){proof.scope='native Enable then Disable only; configured/tested setup and login injected; not renderer acceptance';proof.firstGate='NOT_RUN';proof.auditGate='NOT_RUN';proof.configurationGate='NOT_RUN';proof.connectionGate='NOT_RUN';}
if(updateMode){proof.scope='native update only; B execution separately checked after browser exit';for(const k of ['firstGate','auditGate','configurationGate','connectionGate','activationGate'])proof[k]='NOT_RUN';}
if(rollbackMode){proof.scope='native rollback only; restored A execution separately checked after browser exit';for(const k of ['firstGate','auditGate','configurationGate','connectionGate','activationGate','updateGate'])proof[k]='NOT_RUN';}
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
  if(cssDenialMode && message.sessionId===session)observeConfigurationCSS(message);
  if(message.id && pending.has(message.id)){
   const entry=pending.get(message.id);pending.delete(message.id);clearTimeout(entry.timer);
   if(message.error)entry.reject(Error('CDP command failed: '+entry.method));else entry.resolve(message.result || {});
  }else if(message.method==='Browser.downloadWillBegin'){
   if(detailThemeMode || uninstallMode || secretsMode || configurationMode || connectionMode || activationMode || updateMode || rollbackMode || download){rejectPending(Error('unexpected download'));interrupted=true;}
   download=message.params;
  }else if(message.method==='Browser.downloadProgress'){
   if(download && message.params.guid===download.guid)downloadProgress=message.params;
  }else if(detailThemeMode && message.method==='Network.requestWillBeSent' && message.sessionId===session){
   if(message.params.type==='Script'||message.params.request.method!=='GET'){proof.scriptRequests++;rejectPending(Error('theme script/mutation request'));interrupted=true;}
  }else if(uninstallMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   uninstallPosts++;
  }else if(secretsMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   secretsPosts++; // count only, never retain credentials/body
  }else if(rollbackMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   rollbackPosts++;
  }else if(updateMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   updatePosts++;
  }else if(activationMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   activationPosts++;
  }else if(connectionMode && message.method==='Network.requestWillBeSent' && message.sessionId===session && message.params.request.method==='POST'){
   connectionPosts++;
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
// not a bare keyDown/keyUp. Shared by native form buttons; navigation/audit stays unchanged.
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


async function runUninstall(detail){
 if(!['retained','empty'].includes(bootstrap.phase)||!/^[a-f0-9-]{36}$/.test(bootstrap.survivor))throw Error('D4 phase/target bootstrap');
 const preview='#rollback button[value="uninstall-preview"]',apply='#rollback button[value="uninstall-apply"]',confirmation='#rollback form:has(button[value="uninstall-apply"]) input[name="confirmation"]';
 const control=async selector=>{
  const state=await observe('(()=>{const nodes=document.querySelectorAll('+JSON.stringify(selector)+');const e=nodes[0];return {count:nodes.length,connected:!!e?.isConnected,disabled:!!e?.disabled,owned:!!e && (e.tagName==="A" || !!e.form)};})()');
  if(state.count!==1||!state.connected||state.disabled||!state.owned)throw Error('D4 fixture/control preflight failed');
 };
 const focus=async selector=>{await control(selector);await focusConfiguration(selector);};
 const submit=async selector=>{await control(selector);await submitConfiguration(selector,detail);};
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('D4 initial detail unavailable');
 await submit(preview);if(uninstallPosts!==1)throw Error('D4 initial Preview count');proof.uninstall.previewAccepted=true;
 if(bootstrap.phase==='retained'){
  await control(apply);await control(confirmation);
  if(!await observe('document.querySelector('+JSON.stringify(confirmation)+')?.value===""'))throw Error('D4 confirmation not blank');
  await focus(preview);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();let loader=prior;
  for(let i=0;i<100;i++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
  if(loader===prior){const blocked=await observe('({expected:document.activeElement.matches('+JSON.stringify(confirmation)+'),name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,valueBlank:document.activeElement.value===""})');proof.uninstall.repreviewBlocked=blocked;proof.uninstall.posts=uninstallPosts;if(uninstallPosts===1 && blocked.expected && blocked.name==='confirmation' && blocked.missing && blocked.valueBlank)configurationRed('D4 re-preview blocked by shared confirmation constraint');throw Error('D4 re-preview did not navigate without proved shared constraint');}
  await loaded(detail,loader);if(uninstallPosts!==2||proof.responses.at(-1)?.status!==200)throw Error('D4 re-preview response');proof.uninstall.repreviewAccepted=true;
  const ownership=await observe('(()=>{const p=document.querySelector('+JSON.stringify(preview)+'),a=document.querySelector('+JSON.stringify(apply)+'),c=document.querySelector('+JSON.stringify(confirmation)+');return {separate:p.form!==a.form,previewRequired:Array.from(p.form.elements).filter(e=>e.required).length,required:c.required,blank:c.value==="",labeled:c.labels.length===1};})()');
  if(!ownership.separate||ownership.previewRequired!==0||!ownership.required||!ownership.blank||!ownership.labeled)configurationRed('D4 native form ownership');
  await focus(apply);const before=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();await delay(250);
  const invalid=await observe('({name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,blank:document.activeElement.value===""})');
  if(uninstallPosts!==2||(await call('Page.getFrameTree')).frameTree.frame.loaderId!==before||invalid.name!=='confirmation'||!invalid.missing||!invalid.blank)configurationRed('D4 blank Apply not blocked');proof.uninstall.blankApplyBlocked=true;
  await focus(confirmation);await typeConfiguration('wrong-nonblank');await submit(apply);
  if(uninstallPosts!==3||!await observe('!!document.querySelector("[role=alert]") && !document.querySelector('+JSON.stringify(confirmation)+')'))configurationRed('D4 wrong confirmation not denied');proof.uninstall.wrongDenied=true;
  await submit(preview);if(uninstallPosts!==4)throw Error('D4 fresh Preview count');proof.uninstall.freshPreviewAfterDenial=true;
 }
 await control(apply);await control(confirmation);
 const phrase=await observe('document.querySelector('+JSON.stringify(apply)+').form.querySelector("p>code").textContent');if(!/^confirm-[a-f0-9]{32}$/.test(phrase))throw Error('D4 rendered phrase missing');
 credentialNeedles.push(phrase);await focus(confirmation);await typeConfiguration(phrase);await submit(apply);
 if(bootstrap.phase==='retained'){
  if(uninstallPosts!==5||!await observe('!!document.querySelector("[role=alert]") && !document.querySelector('+JSON.stringify(confirmation)+') && !!document.querySelector('+JSON.stringify(preview)+') && document.querySelectorAll("#secrets>ul>li").length===0'))configurationRed('D4 retained-secret refusal not visible');
  proof.uninstall.correctPhraseRetainedDenied=true;proof.uninstall.emptyCurrentStatuses=true;
 }else{
  if(uninstallPosts!==2)throw Error('D4 exactly two POSTs required');
  const receipt=await observe('({title:document.querySelector("h1")?.textContent,status:document.querySelector("p[role=status]")?.textContent,forms:document.forms.length,inputs:document.querySelectorAll("input").length,dead:document.body.textContent.includes('+JSON.stringify(bootstrap.id)+'),empty:document.body.textContent.includes("No extensions installed"),theme:document.documentElement.dataset.theme,styles:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(l=>l.sheet).map(l=>new URL(l.href).pathname).sort()})');
  if(receipt.title!=='Extension uninstalled'||receipt.status!=='Selected extension uninstalled. Other installed extensions are unchanged.'||receipt.forms!==0||receipt.inputs!==0||receipt.dead||receipt.empty||receipt.theme!=='system'||JSON.stringify(receipt.styles)!==JSON.stringify(['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css']))configurationRed('D4 actual receipt mismatch');proof.uninstall.receiptVerified=true;
  const back='main>p>a[href="/admin/extensions?theme=system"]';await focus(back);await configurationEnter();await loaded('/admin/extensions');
  const inventory=await observe('({survivor:!!document.querySelector('+JSON.stringify('a[href="/admin/extensions/'+bootstrap.survivor+'"]')+'),chosen:!!document.querySelector('+JSON.stringify('a[href="'+detail+'"]')+'),styles:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(l=>l.sheet).map(l=>new URL(l.href).pathname).sort()})');
  if(proof.responses.at(-1)?.status!==200||!inventory.survivor||inventory.chosen||JSON.stringify(inventory.styles)!==JSON.stringify(['/admin/extensions/assets/inventory.css','/admin/extensions/assets/tokens.css']))configurationRed('D4 native inventory return mismatch');proof.uninstall.inventoryReturn=true;
  await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);if(proof.responses.at(-1)?.status!==404)configurationRed('D4 ordinary old detail not404');proof.uninstall.oldDetail404=true;
 }
 proof.uninstall.posts=uninstallPosts;proof.uninstallGate='PASS';bootstrap.secret='';
}

// Single recovery branch; read-only observations, existing native keyboard helpers.
async function runRecoverySecrets(detail){
 const preview='button[value="secrets-delete-preview"]',apply='button[value="secrets-delete-apply"]',confirmation='form:has(button[value="secrets-delete-apply"]) input[name="confirmation"]',refresh='nav[aria-label="Recovery theme"] a:last-child';
 proof.scope='native recovery secret deletion'+(recoveryNoCSS?' CSS-blocked workflow; CSSOM rule counts may be UNKNOWN':'')+'; injected login/SQL corruption are SETUP';
 const projection=async()=>observe('({recovery:document.querySelector("h1")?.textContent.includes("Extension recovery"),normal:!!document.querySelector("#configuration"),canary:document.body.textContent.includes("recovery-metadata-canary"),theme:document.documentElement.dataset.theme,scripts:document.scripts.length,width:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,styles:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(e=>e.sheet).map(e=>new URL(e.href).pathname).sort(),controls:Array.from(document.querySelectorAll("main button,main input:not([type=hidden])")).map(e=>{const r=e.getBoundingClientRect();return {tag:e.tagName,width:r.width,height:r.height,left:r.left,right:r.right}})})');
 const inspect=async(name)=>{
  const p=await projection();proof.secrets[name]=p;
  if(!p.recovery||p.normal||p.canary||p.theme!=='light'||p.scripts!==0)configurationRed('recovery projection mismatch');
  if(p.width!==320)throw Error('recovery viewport equipment');
  if(!recoveryNoCSS&&(p.scroll>p.client||p.controls.some(c=>c.left<0||c.right>p.client+.5)))configurationRed('recovery 320px reflow');
  if(!recoveryNoCSS&&!configurationStylesMatch(p.styles,false))configurationRed('recovery stylesheet missing');
 };
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail+'?theme=light'})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('recovery initial response unavailable');
 await inspect('initial');if(recoveryNoCSS)await configurationNoCSSCheckpoint(1);
 if(!await observe('document.querySelectorAll('+JSON.stringify(preview)+').length===1'))throw Error('recovery preview selector not unique');
 await focusConfiguration(preview);
 proof.secrets.previewFocus=await observe('(()=>{const e=document.activeElement,c=getComputedStyle(e);return {visible:e.matches(":focus-visible"),width:c.outlineWidth,style:c.outlineStyle,color:c.outlineColor,accent:getComputedStyle(document.querySelector("a")).color}})()');
 const f=proof.secrets.previewFocus;
 if(!recoveryNoCSS&&(!f.visible||f.width!=='3px'||f.style!=='solid'||f.color!==f.accent))configurationRed('recovery documented accent 3px keyboard focus missing');
 if(recoveryNoCSS&&(!f.visible||parseFloat(f.width)<=0||['none','hidden'].includes(f.style)))configurationRed('recovery native focus indicator absent');
 await submitConfiguration(preview,detail);if(secretsPosts!==1)throw Error('recovery Preview count');proof.secrets.previewAccepted=true;
 const owned=await observe('(()=>{const p=document.querySelector('+JSON.stringify(preview)+'),a=document.querySelector('+JSON.stringify(apply)+'),c=document.querySelector('+JSON.stringify(confirmation)+');return {unique:document.querySelectorAll('+JSON.stringify(apply)+').length===1&&document.querySelectorAll('+JSON.stringify(confirmation)+').length===1,separate:p.form!==a.form,required:c.required,blank:c.value==="",labels:c.labels.length,previewRequired:Array.from(p.form.elements).some(e=>e.required)}})()');
 if(!owned.unique)throw Error('recovery confirmation selector not unique');
 if(!owned.separate||!owned.required||!owned.blank||owned.labels!==1||owned.previewRequired)configurationRed('recovery native form ownership');
 await inspect('preview');if(recoveryNoCSS)await configurationNoCSSCheckpoint(2);
 await focusConfiguration(apply);const before=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();await delay(250);
 const blank=await observe('({name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,blank:document.activeElement.value===""})');
 if(secretsPosts!==1||(await call('Page.getFrameTree')).frameTree.frame.loaderId!==before||blank.name!=='confirmation'||!blank.missing||!blank.blank)configurationRed('recovery blank required Apply not blocked');proof.secrets.blankApplyBlocked=true;
 const phrase=await observe('document.querySelector('+JSON.stringify(apply)+').form.querySelector("p>code").textContent');if(!/^confirm-[a-f0-9]{32}$/.test(phrase))throw Error('recovery visible phrase missing');
 await focusConfiguration(confirmation);await typeConfiguration(phrase);await submitConfiguration(apply,detail);if(secretsPosts!==2)throw Error('recovery Apply count');proof.secrets.applyAccepted=true;if(recoveryNoCSS)await configurationNoCSSCheckpoint(3);
 if(!await observe('document.querySelectorAll('+JSON.stringify(refresh)+').length===1&&document.querySelector('+JSON.stringify(refresh)+').textContent==="Refresh current state"'))throw Error('recovery refresh selector');
 await focusConfiguration(refresh);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();let loader=prior;
 for(let n=0;n<100;n++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
 if(loader===prior)configurationRed('recovery refresh link did not navigate');await loaded(detail,loader);await inspect('refreshed');if(recoveryNoCSS)await configurationNoCSSCheckpoint(4);
 if(secretsPosts!==2||proof.responses.at(-1)?.status!==200||await observe('!!document.querySelector('+JSON.stringify(apply)+')'))configurationRed('recovery refresh projection');
 proof.secrets.posts=secretsPosts;proof.secrets.refreshCommitted=true;proof.secretsGate='PASS';bootstrap.secret='';
}

async function runSecrets(detail){
 if(recoverySecretsMode)return runRecoverySecrets(detail);
 const preview='#secrets button[value="secrets-delete-preview"]',apply='#secrets button[value="secrets-delete-apply"]',confirmation='#secrets input[name="confirmation"]';
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('D3 initial detail unavailable');
 await submitConfiguration(preview,detail);
 if(secretsPosts!==1)throw Error('D3 first Preview POST count');
 proof.secrets.previewAccepted=true;
 // Do the actual re-preview before label/style checks: legacy shared required
 // confirmation must encounter the real browser constraint, not a synthetic RED.
 if(!await observe('document.querySelector('+JSON.stringify(confirmation)+')?.value===""'))throw Error('D3 first confirmation not blank');
 await focusConfiguration(preview);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();
 let loader=prior;for(let i=0;i<100;i++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
 if(loader===prior){proof.secrets.repreviewBlocked=await observe('({name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,valueBlank:document.activeElement.value===""})');proof.secrets.posts=secretsPosts;configurationRed('D3 re-preview blocked by shared confirmation constraint');}
 await loaded(detail,loader);if(secretsPosts!==2||proof.responses.at(-1)?.status!==200)throw Error('D3 re-preview response');proof.secrets.repreviewAccepted=true;
 const ownership=await observe('(()=>{const p=document.querySelector('+JSON.stringify(preview)+'),a=document.querySelector('+JSON.stringify(apply)+'),c=document.querySelector('+JSON.stringify(confirmation)+');return {separate:p.form!==a.form,previewRequired:Array.from(p.form.elements).filter(e=>e.required).length,confirmationRequired:c.required,blank:c.value==="",labeled:c.labels.length===1};})()');
 if(!ownership.separate||ownership.previewRequired!==0||!ownership.confirmationRequired||!ownership.blank||!ownership.labeled)configurationRed('D3 separate native forms mismatch');
 await focusConfiguration(apply);const blankLoader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();await delay(250);
 const blank=await observe('({name:document.activeElement.name,missing:document.activeElement.validity?.valueMissing,blank:document.activeElement.value===""})');
 if(secretsPosts!==2||(await call('Page.getFrameTree')).frameTree.frame.loaderId!==blankLoader||blank.name!=='confirmation'||!blank.missing||!blank.blank)configurationRed('D3 blank Apply not blocked');proof.secrets.blankApplyBlocked=true;
 await focusConfiguration(confirmation);await typeConfiguration('wrong-nonblank');await submitConfiguration(apply,detail);
 if(secretsPosts!==3||!await observe('!!document.querySelector("[role=alert]") && !document.querySelector("#secrets input[name=confirmation]")'))configurationRed('D3 wrong confirmation not visibly denied');proof.secrets.wrongDenied=true;
 await submitConfiguration(preview,detail);if(secretsPosts!==4)throw Error('D3 fresh Preview count');proof.secrets.freshPreviewAfterDenial=true;
 const phrase=await observe('document.querySelector('+JSON.stringify(apply)+').form.querySelector("p>code").textContent');if(!/^confirm-[a-f0-9]{32}$/.test(phrase))throw Error('D3 phrase missing');
 await focusConfiguration(confirmation);await typeConfiguration(phrase);await submitConfiguration(apply,detail);if(secretsPosts!==5)throw Error('D3 exact five POSTs missing');proof.secrets.applyAccepted=true;
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 const final=await observe('({slots:Array.from(document.querySelectorAll("#secrets>ul>li")).map(li=>({slot:li.querySelector("code")?.textContent,state:Array.from(li.childNodes).filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join("").replace(/^\\s*:\\s*/,"").trim()})),blank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),required:document.querySelector("#configuration input[type=password]")?.required,preview:!!document.querySelector('+JSON.stringify(preview)+'),apply:!!document.querySelector('+JSON.stringify(apply)+'),styles:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(l=>l.sheet).map(l=>new URL(l.href).pathname).sort()})');
 if(proof.responses.at(-1)?.status!==200||JSON.stringify(final.slots)!==JSON.stringify([{slot:'webhook.hmac-key',state:'Not configured'}])||!final.blank||!final.required||!final.preview||final.apply||JSON.stringify(final.styles)!==JSON.stringify(['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css']))configurationRed('D3 unconfigured reload mismatch');
 proof.secrets.reloadUnconfigured=true;proof.secrets.requiredSecretRestored=true;proof.secrets.stylesheetsLoaded=final.styles;proof.secrets.posts=secretsPosts;proof.secretsGate='PASS';bootstrap.secret='';
}

// Exact two-resource transport fault; IDs remain private, diagnostics are counts/paths only.
const configurationCSSPaths=['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css'];
const deniedCSS=new Map();
const blockedCSSIDs=new Set();
function configurationStylesMatch(paths,noCSS){
 return noCSS?paths.length===0:JSON.stringify(paths)===JSON.stringify(configurationCSSPaths);
}
let configurationCSSEventOrder=0;
function configurationCSSFailure(message){
 // Closed diagnostic vocabulary only; arbitrary protocol text is never retained.
 if(!proof.cssDenial.firstFailure){
  const p=message.params,path=deniedCSS.get(p.requestId);
  const known=(v,values)=>v===undefined?'absent':values.includes(v)?v:'unknown';
  proof.cssDenial.firstFailure={code:'CSS_EVENT_MISMATCH',event:{
   method:known(message.method,['Network.requestWillBeSent','Network.loadingFailed','Network.responseReceived','Network.loadingFinished']),
   resourceType:known(p.type,['Document','Stylesheet','Image','Media','Font','Script','TextTrack','XHR','Fetch','Prefetch','EventSource','WebSocket','Manifest','SignedExchange','Ping','CSPViolationReport','Preflight','FedCM','Other']),
   blockedReason:known(p.blockedReason,['other','csp','mixed-content','origin','inspector','integrity','subresource-filter','content-type','coep-frame-resource-needs-coep-header','coop-sandboxed-iframe-cannot-navigate-to-coop-page','corp-not-same-origin','corp-not-same-origin-after-defaulted-to-same-origin-by-coep','corp-not-same-site']),
   errorClass:p.errorText===''?'empty':known(p.errorText,['net::ERR_BLOCKED_BY_CLIENT','net::ERR_FAILED','net::ERR_ABORTED']),
   cssPath:configurationCSSPaths.includes(path)?path:null,requestCorrelated:!!path,
   order:configurationCSSEventOrder,pending:Math.min(deniedCSS.size,9),
   attempts:configurationCSSPaths.map(p=>proof.cssDenial.attempts[p]),blocked:configurationCSSPaths.map(p=>proof.cssDenial.blocked[p])}};
 }
 interrupted=true;rejectPending(Error('configuration CSS denial/request mismatch'));
}
function observeConfigurationCSS(message){
 if(['Network.requestWillBeSent','Network.loadingFailed','Network.responseReceived','Network.loadingFinished'].includes(message.method))configurationCSSEventOrder=Math.min(configurationCSSEventOrder+1,1000);
 const p=message.params;
 if(message.method==='Network.requestWillBeSent'){
  const u=new URL(p.request.url),detail='/admin/extensions/'+bootstrap.id;
  if(u.origin!==origin.origin||u.username||u.password||u.hash){configurationCSSFailure(message);return;}
  // CDP ResourceType Other/Image are the non-script favicon resource classes.
  if(u.pathname==='/favicon.ico'&&!u.search&&p.request.method==='GET'&&['Other','Image'].includes(p.type))return;
  const css=configurationCSSPaths.includes(u.pathname);
  if(css){
   if(u.search||p.request.method!=='GET'||p.type!=='Stylesheet'||deniedCSS.has(p.requestId)||proof.cssDenial.attempts[u.pathname]>=4){configurationCSSFailure(message);return;}
   proof.cssDenial.attempts[u.pathname]++;deniedCSS.set(p.requestId,u.pathname);return;
  }
  if(p.type!=='Document'||!((u.pathname==='/admin/extensions'&&!u.search&&p.request.method==='GET')||(u.pathname===detail&&['','?theme=system','?theme=light','?theme=dark'].includes(u.search)&&['GET','POST'].includes(p.request.method))))configurationCSSFailure(message);
 }else if(message.method==='Network.loadingFailed'){
  const path=deniedCSS.get(p.requestId);
  if(!path||p.type!=='Stylesheet'||p.blockedReason!=='inspector'||(p.errorText!==''&&p.errorText!=='net::ERR_BLOCKED_BY_CLIENT')){configurationCSSFailure(message);return;}
  deniedCSS.delete(p.requestId);blockedCSSIDs.add(p.requestId);proof.cssDenial.blocked[path]++;
  proof.cssDenial.acceptedErrorForms[p.errorText===''?'empty':'blockedByClient']++;
 }else if((message.method==='Network.responseReceived'&&p.type==='Stylesheet')||(message.method==='Network.loadingFinished'&&(deniedCSS.has(p.requestId)||blockedCSSIDs.has(p.requestId))))configurationCSSFailure(message);
}
async function configurationNoCSSCheckpoint(n){
 const cssom=await observe('(()=>{const paths=["/admin/extensions/assets/detail.css","/admin/extensions/assets/tokens.css"],links=Array.from(document.querySelectorAll("link[rel~=stylesheet]"));const exact=links.length===2&&paths.every(path=>links.filter(l=>l.href===location.origin+path).length===1);const unexpected=!!document.querySelectorAll("style, [style]").length||document.adoptedStyleSheets.length!==0||Array.from(document.styleSheets).some(s=>!links.includes(s.ownerNode));return {exact,unexpected,links:links.slice(0,2).map(l=>{const path=paths.find(p=>l.href===location.origin+p)||null,s=l.sheet;let readable=false,rules=null,error="none";if(s!==null){try{rules=s.cssRules.length;readable=true;}catch(e){error=e.name==="SecurityError"?"SecurityError":"unknown";}}return {path,associated:s!==null,readable,rules:Number.isSafeInteger(rules)?Math.min(rules,100000):null,error};})};})()');
 if(!proof.cssDenial.cssom)proof.cssDenial.cssom=[];
 if(proof.cssDenial.cssom.length<4)proof.cssDenial.cssom.push(cssom);
 if(!cssom||cssom.exact!==true||cssom.unexpected!==false||!Array.isArray(cssom.links)||cssom.links.length!==2||configurationCSSPaths.some(p=>cssom.links.filter(l=>l&&l.path===p).length!==1)||cssom.links.some(l=>!((l.associated===false&&l.readable===false&&l.rules===null&&l.error==='none')||(l.associated===true&&l.readable===true&&l.rules===0&&l.error==='none')||(recoveryNoCSS&&l.associated===true&&l.readable===false&&l.rules===null&&l.error==='SecurityError')))||deniedCSS.size||configurationCSSPaths.some(p=>proof.cssDenial.attempts[p]!==n||proof.cssDenial.blocked[p]!==n))throw Error('configuration CSS denial not positively observed');
 proof.cssDenial.checkpoints++;
}
async function runConfiguration(detail){
 if(typeof bootstrap.endpoint!=='string' || !bootstrap.endpoint.startsWith('https://127.0.0.1:') || !/^[a-f0-9]{64}$/.test(bootstrap.secret))throw Error('invalid private configuration fixture inputs');
 const preview='#configuration>form:first-of-type';
 const apply='#configuration>form:nth-of-type(2)';
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('initial configuration detail unavailable');
 if(configurationNoCSS){
  await configurationNoCSSCheckpoint(1);
  const semantics=await observe('(()=>{const f=document.querySelector("#configuration>form"),e=f.elements;return e["field.webhook.endpoint"].required&&!e["field.webhook.timeout-seconds"].required&&e["field.webhook.hmac-key"].required&&e["field.webhook.endpoint"].type==="text"&&e["field.webhook.timeout-seconds"].type==="number"&&e["field.webhook.hmac-key"].type==="password"&&Array.from(f.elements).every(e=>e.form===f)})()');
  if(!semantics)throw Error('no-CSS required/default/control ownership mismatch');proof.cssDenial.nativeSemantics=true;
 }

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
 if(configurationNoCSS)await configurationNoCSSCheckpoint(2);
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
 if(configurationNoCSS)await configurationNoCSSCheckpoint(3);
 proof.configuration.applyAccepted=true;
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId); // ordinary GET reload, never replay POST
 if(proof.responses.at(-1)?.status!==200)throw Error('configuration reload failed');
 const persisted=await observe('({endpoint:document.querySelector("#configuration form").elements["field.webhook.endpoint"].value,timeout:document.querySelector("#configuration form").elements["field.webhook.timeout-seconds"].value,secretsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),secretStatus:Array.from(document.querySelectorAll("#secrets>ul>li")).map(li=>({slot:li.querySelector("code")?.textContent,state:Array.from(li.childNodes).filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join("").replace(/^\\s*:\\s*/,"").trim()})),stylesheets:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(l=>l.sheet).map(l=>new URL(l.href).pathname).sort(),forms:document.querySelectorAll("#configuration>form").length})');
 if(persisted.endpoint!==bootstrap.endpoint || persisted.timeout!=='2' || !persisted.secretsBlank || persisted.secretStatus.filter(s=>s.slot==='webhook.hmac-key' && s.state==='Configured').length!==1 || persisted.secretStatus.filter(s=>s.slot==='webhook.hmac-key').length!==1 || (!configurationNoCSS&&!configurationStylesMatch(persisted.stylesheets,false)) || persisted.forms!==1)configurationRed('configured native reload mismatch');
 if(configurationNoCSS)await configurationNoCSSCheckpoint(4);
 proof.configuration.reloadPersisted=true;proof.configuration.stylesheetsLoaded=persisted.stylesheets;proof.configuration.posts=configurationPosts;
 proof.configurationGate='PASS';bootstrap.secret='';
}
async function runConnectionTest(detail){
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('configured Test detail unavailable');
 const styles=await observe('Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(l=>l.sheet).map(l=>new URL(l.href).pathname).sort()');
 if(JSON.stringify(styles)!==JSON.stringify(['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css']))throw Error('Test detail stylesheets not loaded');
 const before=await observe('({health:document.querySelector("#health")?.textContent,secretsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value==="")})');
 if(!before.health?.includes('tested revision 0; configuration revision 2') || !before.secretsBlank)throw Error('configured Test setup projection mismatch');
 // Reuse only admitted native keyboard mechanics, never the configuration flow.
 await focusConfiguration('#overview button[value="test"]');
 const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
 await configurationEnter();
 let loader;
 for(let i=0;i<200;i++){
  loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
  if(loader!==prior)break;
  await delay(50);
 }
 if(loader===prior){proof.productRed='native Test button did not navigate';throw Error(proof.productRed);}
 await loaded(detail,loader);
 if(proof.responses.at(-1)?.status!==200)throw Error('Test response failed; inspect independent Go oracle');
 const after=await observe('({status:document.querySelector("p[role=status]")?.textContent,health:document.querySelector("#health")?.textContent,secretsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value==="")})');
 if(connectionPosts!==1 || after.status!=='extension operation accepted' || !after.health?.includes('extension.ready; tested revision 2; configuration revision 2') || !after.secretsBlank){proof.productRed='native Test result projection mismatch';throw Error(proof.productRed);}
 proof.connection={posts:connectionPosts,readyProjection:true,passwordControlsBlank:true,stylesheetsLoaded:styles};
 proof.connectionGate='PASS';
}
async function runActivation(detail){
 const projection=async()=>observe('({status:document.querySelector("p[role=status]")?.textContent,health:document.querySelector("#health")?.textContent,values:Array.from(document.querySelectorAll("#overview dd")).map(e=>e.textContent),secretsBlank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),disable:!!document.querySelector("#overview button[value=disable]")})');
 const valid=(p,enabled)=>p.health?.includes('extension.ready; tested revision 2; configuration revision 2') && p.secretsBlank && p.values?.at(-2)===(enabled?'ready':'stopped') && p.values?.at(-1)===(enabled?'true / true':'false / false') && p.disable===enabled;
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200 || !valid(await projection(),false))throw Error('activation setup projection mismatch');
 for(const [index,action] of ['enable','disable'].entries()){
  await focusConfiguration('#overview button[value="'+action+'"]');
  const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;
  await configurationEnter();
  let loader;
  for(let i=0;i<200;i++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
  if(loader===prior){proof.productRed='native activation button did not navigate';throw Error(proof.productRed);}
  await loaded(detail,loader);
  if(proof.responses.at(-1)?.status!==200)throw Error('activation response failed; inspect independent Go oracle');
  const after=await projection();
  if(activationPosts!==index+1 || after.status!=='extension operation accepted' || !valid(after,index===0)){proof.productRed='native activation projection mismatch';throw Error(proof.productRed);}
 }
 proof.activation={posts:activationPosts,enabledThenDisabled:true,readinessRetained:true,passwordControlsBlank:true};proof.activationGate='PASS';
}
async function runUpdate(detail){
 const target=JSON.parse(bootstrap.update_target);
 const fields=['artifact_pin','manifest_sha256','grant_sha256','session_sha256'];
 const enter=async selector=>{
  await focusConfiguration(selector);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();let loader;
  for(let n=0;n<200;n++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
  if(loader===prior){proof.productRed='native update did not navigate';throw Error(proof.productRed);}
  await loaded(detail,loader);if(proof.responses.at(-1)?.status!==200)throw Error('update response rejected by independent oracle');
 };
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('update detail missing');
 const initial=await observe('({health:document.querySelector("#health").textContent,permissions:Array.from(document.querySelectorAll("#versions form:first-of-type input")).filter(e=>["capabilities","interfaces","secret_slots"].includes(e.name)).map(e=>[e.name,e.value]),blank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value==="")})');
 if(!initial.blank || !initial.health.includes('tested revision 2; configuration revision 2') || initial.permissions.some(([k,v])=>v!==target[k].join(',')))throw Error('update setup projection mismatch');
 for(const name of fields){await focusConfiguration('#versions form:first-of-type input[name="'+name+'"]');await typeConfiguration(target[name]);}
 await enter('#versions button[value="update-preview"]');
 const observed=await observe('(()=>{const forms=document.querySelectorAll("#versions form"),f=forms[1];return {count:forms.length,values:Array.from(f.querySelectorAll("dd code")).map(e=>e.textContent),names:Array.from(f.elements).map(e=>e.name).sort(),phrase:Array.from(f.querySelectorAll("p code")).map(e=>e.textContent).find(s=>/^confirm-[a-f0-9]{32}$/.test(s)),siblingBlank:Array.from(forms[0].querySelectorAll("input[required]")).every(e=>e.value===""),confirmationRequired:f.elements.confirmation.required}})()');
 if(updatePosts!==1 || observed.count!==2 || !observed.siblingBlank || !observed.confirmationRequired || observed.values.some((v,i)=>v!==target[fields[i]]) || observed.values.length!==4 || JSON.stringify(observed.names)!==JSON.stringify(['action','confirmation','csrf_token','preview_id']) || !observed.phrase)throw Error('update native form ownership/target mismatch');
 await focusConfiguration('#versions button[value="update-apply"]');
 const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();await delay(200);
 if(updatePosts!==1 || (await call('Page.getFrameTree')).frameTree.frame.loaderId!==prior)throw Error('blank update confirmation submitted');
 await focusConfiguration('#versions form:nth-of-type(2) input[name="confirmation"]');await typeConfiguration(observed.phrase);credentialNeedles.push(observed.phrase);observed.phrase='';
 await enter('#versions button[value="update-apply"]');
 if(updatePosts!==2)throw Error('update POST count mismatch');
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 const after=await observe('({health:document.querySelector("#health").textContent,pin:document.querySelectorAll("#overview dd code")[0].textContent,versions:document.querySelector("#versions").textContent,blank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value===""),forms:document.querySelectorAll("#versions form").length})');
 if(proof.responses.at(-1)?.status!==200 || after.pin!==target.artifact_pin || !after.health.includes('extension.unknown; tested revision 0; configuration revision 3') || !after.blank || after.forms!==1 || !after.versions.includes('sha256:5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a'))throw Error('update persisted projection mismatch');
 proof.update={posts:updatePosts,blankConfirmationBlocked:true,siblingRequiredFieldsUntouched:true,reloaded:true,passwordControlsBlank:true};proof.updateGate='PASS';
}
async function runRollback(detail){
 const button='#rollback button[value="rollback"]',input='#rollback form:first-of-type input[name="confirmation"]';
 const expected='rollback gotth.mail.notification.webhook to sha256:5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a';
 const projection=async()=>observe('({phrase:document.querySelector("#rollback form:first-of-type p code")?.textContent,required:document.querySelector("#rollback form:first-of-type input[name=confirmation]")?.required,names:Array.from(document.querySelector("#rollback form:first-of-type").elements).map(e=>e.name).sort(),health:document.querySelector("#health").textContent,status:document.querySelector("p[role=status]")?.textContent,pin:document.querySelectorAll("#overview dd code")[0].textContent,blank:Array.from(document.querySelectorAll("input[type=password]")).every(e=>e.value==="")})');
 const submit=async()=>{await focusConfiguration(button);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();let loader;for(let n=0;n<200;n++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}if(loader===prior){proof.productRed='native rollback did not navigate';throw Error(proof.productRed);}await loaded(detail,loader);if(proof.responses.at(-1)?.status!==200)throw Error('rollback independent response failed');};
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 let page=await projection();
 if(page.phrase!==expected || !page.required || !page.blank || !page.health.includes('extension.ready; tested revision 4; configuration revision 4') || JSON.stringify(page.names)!==JSON.stringify(['action','confirmation','csrf_token']))throw Error('rollback setup/form mismatch');
 await focusConfiguration(button);const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await configurationEnter();await delay(200);
 if(rollbackPosts!==0 || (await call('Page.getFrameTree')).frameTree.frame.loaderId!==prior)throw Error('blank rollback submitted');
 await focusConfiguration(input);await typeConfiguration('wrong-confirmation');await submit();page=await projection();
 if(rollbackPosts!==1 || page.status==='extension operation accepted' || page.phrase!==expected || !page.health.includes('tested revision 4; configuration revision 4'))throw Error('wrong rollback not denied');
 await focusConfiguration(input);await call('Input.dispatchKeyEvent',{type:'rawKeyDown',key:'a',code:'KeyA',modifiers:2,windowsVirtualKeyCode:65});await call('Input.dispatchKeyEvent',{type:'keyUp',key:'a',code:'KeyA',modifiers:2,windowsVirtualKeyCode:65});await key('Backspace',8);await typeConfiguration(page.phrase);await submit();
 page=await projection();if(rollbackPosts!==2 || page.status!=='extension operation accepted')throw Error('rollback not accepted');
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);page=await projection();
 if(page.pin!=='sha256:5cb6043ca200acfa67d4c6a85e0c1ba070c51dc550cacca7ce538021c8d9e83a' || !page.health.includes('extension.unknown; tested revision 0; configuration revision 5') || !page.blank)throw Error('rollback persisted projection mismatch');
 proof.rollback={posts:rollbackPosts,blankBlocked:true,wrongDenied:true,reloaded:true,passwordControlsBlank:true};proof.rollbackGate='PASS';
}
// One fixed no-script theme sequence at two widths, not a general matrix runner.
async function runDetailTheme(detail){
 proof.themeStates=[];
 let ownership;
 const sample=async(width,theme,osTheme)=>{
  const expected=theme==='system'?osTheme:theme;
  // Expected scalar palette independently read from presentation/tokens.go.
  const colors=expected==='dark'?['rgb(17, 23, 34)','rgb(238, 244, 251)','rgb(24, 34, 48)']:['rgb(244, 246, 249)','rgb(23, 32, 51)','rgb(255, 255, 255)'];
  const state=await observe('(()=>{const forms=Array.from(document.forms),controls=Array.from(document.querySelectorAll("main input:not([type=hidden]),main select,main button")),sections=["overview","configuration","secrets","permissions","health","audit","versions","rollback"],client=document.documentElement.clientWidth,b=getComputedStyle(document.body);return {theme:document.documentElement.dataset.theme,width:innerWidth,client,scroll:document.documentElement.scrollWidth,body:[b.backgroundColor,b.color],controls:controls.map(e=>{const c=getComputedStyle(e);return [c.backgroundColor,c.color]}),sections:sections.every(id=>document.querySelectorAll("section#"+id).length===1)&&document.querySelectorAll("main section").length===8,audit:document.querySelector("#audit a")?.getAttribute("href"),actions:forms.map(f=>f.getAttribute("action")),formsOK:forms.length===5&&forms.every(f=>f.method==="post"&&f.querySelectorAll("input[type=hidden][name=csrf_token]").length===1&&Array.from(f.elements).every(e=>e.form===f)),ownership:JSON.stringify(forms.map(f=>Array.from(f.elements).map(e=>[e.tagName,e.name,e.type,!!e.required,!!e.disabled,e.labels?.length||0]))),required:Array.from(document.querySelectorAll("#configuration input:not([type=hidden])")).map(e=>[e.name,e.type,e.required]),passwordsBlank:controls.filter(e=>e.type==="password").every(e=>e.value===""),overflow:Array.from(document.querySelectorAll("main,main *,input,select,button")).filter(e=>e.getClientRects().length&&e.getBoundingClientRect().width>0).filter(e=>{const r=e.getBoundingClientRect();return r.left<0||r.right>client+.5}).length,scripts:document.scripts.length,storageEmpty:localStorage.length===0&&sessionStorage.length===0,cookieNames:document.cookie.split(";").map(s=>s.trim().split("=")[0]).sort(),styles:Array.from(document.querySelectorAll("link[rel=stylesheet]")).filter(e=>e.sheet).map(e=>new URL(e.href).pathname).sort()}})()');
  const requirements=[['field.webhook.endpoint','text',true],['field.webhook.timeout-seconds','number',false],['field.webhook.hmac-key','password',true]];
  proof.themeStates.push({width:state.width,theme:state.theme,osTheme,palette:expected,body:state.body,controlColors:Array.from(new Set(state.controls.map(c=>JSON.stringify(c)))).map(c=>JSON.parse(c)),controls:state.controls.length,client:state.client,scroll:state.scroll,overflow:state.overflow,sectionsComplete:state.sections,formsValid:state.formsOK,formSemanticsUnchanged:!ownership||ownership===state.ownership,requirementsMatch:JSON.stringify(state.required)===JSON.stringify(requirements),actionsMatch:state.actions.every(a=>a===detail+'?theme='+theme),auditMatch:state.audit===detail+'/audit',stylesLoaded:state.styles.length,noScript:state.scripts===0,noStoredPreference:state.storageEmpty});
  if(state.theme!==theme||state.width!==width||state.scroll>state.client||state.overflow||!state.sections||!state.formsOK||!state.passwordsBlank||state.scripts||!state.storageEmpty||JSON.stringify(state.cookieNames)!==JSON.stringify(['gotth_mail_csrf','gotth_mail_session'])||state.audit!==detail+'/audit'||state.actions.some(a=>a!==detail+'?theme='+theme)||JSON.stringify(state.required)!==JSON.stringify(requirements)||state.styles.join(',')!=='/admin/extensions/assets/detail.css,/admin/extensions/assets/tokens.css'||state.body[0]!==colors[0]||state.body[1]!==colors[1]||!state.controls.length||state.controls.some(c=>c[0]!==colors[2]||c[1]!==colors[1])||(ownership&&ownership!==state.ownership)){
   proof.productRed='detail theme/geometry/form contract mismatch';throw Error(proof.productRed);
  }
  ownership=state.ownership;

 };
 const media=async value=>{await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value}]});await delay(80);};
 const choose=async theme=>{
  await focusConfiguration('nav[aria-label="Detail theme"] a[href="'+detail+'?theme='+theme+'#permissions"]');
  const prior=(await call('Page.getFrameTree')).frameTree.frame.loaderId;await key('Enter',13);
  let loader;for(let i=0;i<100;i++){loader=(await call('Page.getFrameTree')).frameTree.frame.loaderId;if(loader!==prior)break;await delay(50);}
  if(loader===prior)throw Error('native theme link did not navigate');await loaded(detail,loader);
  if(proof.responses.at(-1)?.status!==200)throw Error('theme response failed');
 };
 await loaded(detail,(await call('Page.navigate',{url:origin.origin+detail})).loaderId);
 if(proof.responses.at(-1)?.status!==200)throw Error('initial theme detail failed');
 // Positive initial state precedes every new media/viewport adjustment.
 for(const width of [320,1280]){
  if(width===1280){await call('Emulation.setDeviceMetricsOverride',{width,height:800,deviceScaleFactor:1,mobile:false});await delay(80);}
  await sample(width,'system','light');
  await choose('dark');await sample(width,'dark','light');
  await media('dark');await sample(width,'dark','dark');
  await choose('light');await sample(width,'light','dark');
  await choose('system');await sample(width,'system','dark');
  await media('light');await sample(width,'system','light');
 }
 proof.detailThemeGate='PASS';
}
try{
 proof.version=await call('Browser.getVersion',{},null);
 const target=await call('Target.createTarget',{url:'about:blank'},null);
 session=(await call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
 await call('Target.activateTarget',{targetId:target.targetId},null);
 await call('Page.enable');await call('Network.enable');
 if(cssDenialMode)await call('Network.setBlockedURLs',{urls:configurationCSSPaths.map(p=>origin.origin+p)});
 await call('Emulation.setDeviceMetricsOverride',{width:320,height:800,deviceScaleFactor:1,mobile:false});
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});
 await call('Emulation.setScriptExecutionDisabled',{value:true});
 const list='/admin/extensions';
 const initial=detailThemeMode?list+'/'+bootstrap.id:list;
 await loaded(initial,(await call('Page.navigate',{url:origin.origin+initial})).loaderId);
 if(proof.responses.at(-1)?.status!==401)throw Error('unauthenticated browser not denied');
 await call('Network.setCookies',{cookies:[{name:'gotth_mail_session',value:bootstrap.session,url:origin.origin,path:'/'},{name:'gotth_mail_csrf',value:bootstrap.csrf,url:origin.origin,path:'/'}]});
 bootstrap.session='';bootstrap.csrf='';
 const detail=list+'/'+bootstrap.id;
 if(detailThemeMode){
  await runDetailTheme(detail);
 }else if(uninstallMode){
  await runUninstall(detail);
 }else if(secretsMode){
  await runSecrets(detail);
 }else if(rollbackMode){
  await runRollback(detail);
 }else if(updateMode){
  await runUpdate(detail);
 }else if(activationMode){
  await runActivation(detail);
 }else if(connectionMode){
  await runConnectionTest(detail);
 }else if(configurationMode){
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
}catch(e){if(cssDenialMode&&!proof.cssDenial.firstFailure)proof.cssDenial.firstFailure={code:'CSS_FLOW_FAILURE'};if(detailThemeMode)proof.detailThemeGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(uninstallMode)proof.uninstallGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(secretsMode)proof.secretsGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(rollbackMode)proof.rollbackGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(updateMode)proof.updateGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(activationMode)proof.activationGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(connectionMode)proof.connectionGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(configurationMode)proof.configurationGate=proof.productRed?'PRODUCT_RED':'FAIL';else if(auditMode)proof.auditGate='FAIL';else proof.firstGate=proof.productRed?'PRODUCT_RED':'EQUIPMENT_FAILURE';proof.error=e.message;process.exitCode=1;}
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
 if(uninstallMode && (interrupted || !drained || proof.cleanupFailed)){proof.uninstallGate='FAIL';proof.error='D4 interrupted/cleanup incomplete';process.exitCode=1;}
 if(uninstallMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.uninstallGate='FAIL';proof.error='D4 retained credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['uninstallGate','error'].includes(k))delete proof[k];}
 if(cssDenialMode && (deniedCSS.size || proof.cssDenial.checkpoints!==4 || configurationCSSPaths.some(p=>proof.cssDenial.attempts[p]!==4||proof.cssDenial.blocked[p]!==4)))interrupted=true;
 if(secretsMode && (interrupted || !drained || proof.cleanupFailed)){proof.secretsGate='FAIL';proof.error='D3 interrupted/cleanup incomplete';process.exitCode=1;}
 if(secretsMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.secretsGate='FAIL';proof.error='D3 retained credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['secretsGate','error'].includes(k))delete proof[k];}
 if(configurationMode && (interrupted || !drained || proof.cleanupFailed)){proof.configurationGate='FAIL';proof.error='configuration interrupted or cleanup incomplete';process.exitCode=1;}
 if(configurationMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.configurationGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['configurationGate','error'].includes(k))delete proof[k];}
 if(connectionMode && (interrupted || !drained || proof.cleanupFailed)){proof.connectionGate='FAIL';proof.error='connection-test interrupted or cleanup incomplete';process.exitCode=1;}
 if(connectionMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.connectionGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['connectionGate','error'].includes(k))delete proof[k];}
 if(activationMode && (interrupted || !drained || proof.cleanupFailed)){proof.activationGate='FAIL';proof.error='activation interrupted or cleanup incomplete';process.exitCode=1;}
 if(activationMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.activationGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['activationGate','error'].includes(k))delete proof[k];}
 if(updateMode && (interrupted || !drained || proof.cleanupFailed)){proof.updateGate='FAIL';proof.error='update interrupted or cleanup incomplete';process.exitCode=1;}
 if(updateMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.updateGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['updateGate','error'].includes(k))delete proof[k];}
 if(rollbackMode && (interrupted || !drained || proof.cleanupFailed)){proof.rollbackGate='FAIL';proof.error='rollback interrupted or cleanup incomplete';process.exitCode=1;}
 if(rollbackMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.rollbackGate='FAIL';proof.error='retained diagnostic credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['rollbackGate','error'].includes(k))delete proof[k];}
 if(detailThemeMode && (interrupted || !drained || proof.cleanupFailed || proof.scriptRequests)){proof.detailThemeGate='FAIL';proof.error='detail-theme interrupted or cleanup incomplete';process.exitCode=1;}
 if(detailThemeMode && credentialNeedles.some(s=>s && JSON.stringify(proof).includes(s))){proof.detailThemeGate='FAIL';proof.error='theme retained credential leak';process.exitCode=1;for(const k of Object.keys(proof))if(!['detailThemeGate','error'].includes(k))delete proof[k];}
 writeFileSync(join(output,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({detailThemeGate:proof.detailThemeGate,firstGate:proof.firstGate,auditGate:proof.auditGate,uninstallGate:proof.uninstallGate,secretsGate:proof.secretsGate,configurationGate:proof.configurationGate,connectionGate:proof.connectionGate,activationGate:proof.activationGate,updateGate:proof.updateGate,rollbackGate:proof.rollbackGate,audit:proof.audit,productRed:proof.productRed,cleanupFailed:!!proof.cleanupFailed,pages:(proof.pages||[]).map(x=>({name:x.name,client:x.client,scroll:x.scroll}))}));
}
