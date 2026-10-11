// Test the real driver's asynchronous shutdown path with controlled CDP events.
// VM is an execution fixture, not a security boundary. No real browser or host writes.
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join,resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
const source=readFileSync(process.argv[2] || new URL('./extensions-browser-smoke.mjs',import.meta.url),'utf8');
// Stub the current single-line imports; this exercises the driver body, not module loading.
const body=source.replace(/^import .* from .*;\r?$/gm,'');
const id='11111111-1111-4111-8111-111111111111';
const guid='22222222-2222-4222-8222-222222222222';
const origin='http://127.0.0.1:12345';
const detail='/admin/extensions/'+id;
const row={ID:'event-one',Action:'extension.install',Resource:{Type:'extension',ID:id}};
const bytes=Buffer.from(JSON.stringify(row)+'\n');
let failures=0;
for(const mode of ['secrets-delete-recovery','secrets-delete-recovery-no-css','configuration-no-css','detail-theme','audit','configuration','connection-test','activation','update','rollback'])for(const scenario of ['normal','duplicate-close','signal-close','duplicate-after-exit','undrained',...(mode==='secrets-delete-recovery-no-css'?['missing-css-at-drain','first-css-event','privacy-first-css']:[])]){
 const proc=new EventEmitter();Object.assign(proc,{argv:['node','driver','/evidence'],env:{GOTTH_MAIL_ACCEPTANCE_NAMESPACE:'1'},kill(){throw Error('unexpected forced shutdown');}});
 const stream=()=>Object.assign(new EventEmitter(),{destroyed:false,destroy(){this.destroyed=true;}});
 const browser=new EventEmitter();Object.assign(browser,{pid:123,stdio:[null,null,stream(),stream(),stream()],stderr:stream(),kill(){throw Error('unexpected kill');}});
 const frame={guid,url:origin+detail+'/audit',suggestedFilename:'extension-audit.jsonl'};
 const packet=value=>{if(!browser.stdio[4].destroyed)browser.stdio[4].emit('data',Buffer.from(JSON.stringify(value)+'\0'));};
 const duplicate=()=>packet({method:'Browser.downloadWillBegin',params:frame});
 let current='',authed=false,serial=0,proof;
 const removed=[];
 browser.stdio[3].write=wire=>{
  const q=JSON.parse(wire.slice(0,-1));
  queueMicrotask(()=>{
   let result={};
   if(q.method==='Browser.close'){
    if(scenario==='duplicate-close')duplicate();
    if(scenario==='signal-close')proc.emit('SIGTERM');
    browser.emit('exit',0,null);
    if(scenario==='duplicate-after-exit')setImmediate(()=>{duplicate();browser.emit('close',0,null);});
    else if(scenario!=='undrained')browser.emit('close',0,null);
    return;
   }
   if(q.method==='Target.createTarget')result={targetId:'target'};
   if(q.method==='Target.attachToTarget')result={sessionId:'session'};
   if(q.method==='Network.setCookies')authed=true;
   if(q.method==='Page.navigate'){
    current=new URL(q.params.url).pathname;result={loaderId:'loader'};
    packet({method:'Network.responseReceived',sessionId:'session',params:{type:'Document',response:{url:q.params.url,status:authed?200:401}}});
   }
   if(q.method==='Page.getFrameTree')result={frameTree:{frame:{loaderId:'loader'}}};
   if(q.method==='Runtime.evaluate')result={result:{value:q.params.expression.includes('location.pathname')?{path:current,ready:'complete'}:{tag:'A',href:detail+'/audit'}}};
   if(q.method==='Input.dispatchKeyEvent' && q.params.key==='Enter' && q.params.type==='keyDown'){
    duplicate();packet({method:'Browser.downloadProgress',params:{guid,state:'completed',receivedBytes:bytes.length}});
   }
   packet({id:q.id,result});
  });
 };
 const bootstrap={origin,id,session:'fixture-session',csrf:'fixture-csrf',mode,audit_expected:JSON.stringify([{id:row.ID,action:row.Action}])};
 const context={spawn:()=>browser,readFileSync:p=>p===0?JSON.stringify(bootstrap):bytes,
  writeFileSync:(p,data)=>{assert.equal(p,'/evidence/proof.json');proof=JSON.parse(data);},
  mkdirSync:()=>{},mkdtempSync:p=>p+(++serial),readdirSync:()=>[],rmSync:p=>removed.push(p),statSync:()=>({size:bytes.length}),
  createHash,join,resolve,URL,Buffer,process:proc,setTimeout,clearTimeout,
  delay:()=>new Promise(r=>setImmediate(r)),console:{log:()=>{}}};
 // Native form/action sequences are stubbed here; actual driver shutdown/latching
 // is exercised. Real configuration/Test evidence is separate.
 const diagnosticStub=['first-css-event','privacy-first-css'].includes(scenario)?'async function runSecrets(){observeConfigurationCSS({method:"Network.loadingFailed",params:{requestId:"private-id",type:"Stylesheet",blockedReason:"inspector",errorText:"net::ERR_FAILED"}});if('+JSON.stringify(scenario==='privacy-first-css')+')proof.cssDenial.firstFailure.event.errorClass=credentialNeedles[0];throw Error("diagnostic synthetic interruption");}\n':null;
 const stub=diagnosticStub || (mode.startsWith('secrets-delete-recovery')?'async function runSecrets(){proof.secretsGate="PASS";if(recoveryNoCSS){proof.cssDenial.checkpoints='+(scenario==='missing-css-at-drain'?3:4)+';for(const p of configurationCSSPaths){proof.cssDenial.attempts[p]=4;proof.cssDenial.blocked[p]=4;}}}\n':mode==='configuration-no-css'?'async function runConfiguration(){proof.configurationGate="PASS";proof.cssDenial.checkpoints=4;for(const p of configurationCSSPaths){proof.cssDenial.attempts[p]=4;proof.cssDenial.blocked[p]=4;}}\n':mode==='detail-theme'?'async function runDetailTheme(){proof.detailThemeGate="PASS";}\n':mode==='configuration'?'async function runConfiguration(){proof.configurationGate="PASS";}\n':mode==='rollback'?'async function runRollback(){proof.rollbackGate="PASS";}\n':mode==='update'?'async function runUpdate(){proof.updateGate="PASS";}\n':mode==='activation'?'async function runActivation(){proof.activationGate="PASS";}\n':'async function runConnectionTest(){proof.connectionGate="PASS";}\n');
 const exercised=mode==='audit'?body:body.slice(0,body.indexOf('async function runConfiguration('))+stub+body.slice(body.indexOf("try{\n proof.version="));
 await runInNewContext('(async()=>{"use strict";\n'+exercised+'\n})()',context,{timeout:1000});
 try{
  assert.equal(mode.startsWith('secrets-delete-recovery')?proof.secretsGate:mode==='detail-theme'?proof.detailThemeGate:mode==='audit'?proof.auditGate:(mode==='configuration'||mode==='configuration-no-css')?proof.configurationGate:mode==='rollback'?proof.rollbackGate:mode==='update'?proof.updateGate:mode==='activation'?proof.activationGate:proof.connectionGate,scenario==='normal'?'PASS':'FAIL');
  assert.equal(proc.exitCode || 0,scenario==='normal'?0:1);
  if(scenario==='privacy-first-css'){assert.equal(proof.error,'D3 retained credential leak');assert.deepEqual(Object.keys(proof).sort(),['error','secretsGate']);console.log('PASS privacy overrides first CSS diagnostic');continue;}
  if(scenario==='first-css-event'){assert.equal(proof.cssDenial.firstFailure.code,'CSS_EVENT_MISMATCH');assert.equal(proof.cssDenial.firstFailure.event.errorClass,'net::ERR_FAILED');assert.equal(proof.cssDenial.firstFailure.event.order,2);assert.equal(proof.cssDenial.firstFailure.event.requestCorrelated,false);assert(!JSON.stringify(proof).includes('private-id'));}
  assert.equal(proof.cleanup.mainExited,true);
  assert.equal(proof.cleanup.remaining.length,0);
  assert.equal(removed.length,mode==='audit'?2:1,'private cleanup must survive failure');
  if(scenario!=='normal')assert.equal(proof.error,mode.startsWith('secrets-delete-recovery')?'D3 interrupted/cleanup incomplete':mode==='detail-theme'?'detail-theme interrupted or cleanup incomplete':mode==='audit'?'audit interrupted or event stream not drained before proof':(mode==='configuration'||mode==='configuration-no-css')?'configuration interrupted or cleanup incomplete':mode==='rollback'?'rollback interrupted or cleanup incomplete':mode==='update'?'update interrupted or cleanup incomplete':mode==='activation'?'activation interrupted or cleanup incomplete':'connection-test interrupted or cleanup incomplete');
  console.log('PASS '+mode+' '+scenario);
 }catch(e){failures++;console.error('FAIL '+scenario+': '+e.message);}
}
// Exercise the actual small native Enter helper, not a copied event algorithm.
const enterStart=body.indexOf('async function configurationEnter(){');
const enterEnd=body.indexOf('async function submitConfiguration(',enterStart);
assert(enterStart>=0 && enterEnd>enterStart,'configuration Enter helper missing');
const nativeEvents=[];
await runInNewContext('(async()=>{'+body.slice(enterStart,enterEnd)+'await configurationEnter();})()',{call:async(method,params)=>nativeEvents.push({method,...params})});
assert.deepEqual(nativeEvents.map(e=>e.type),['rawKeyDown','char','keyUp']);
assert(nativeEvents.every(e=>e.method==='Input.dispatchKeyEvent' && e.key==='Enter'));
assert.equal(nativeEvents[1].text,'\r');
assert.equal(nativeEvents[1].unmodifiedText,'\r');
console.log('PASS native Enter CR contract');
// Controlled oracle regression: execute the ACTUAL sample validator, not a copy.
// Pinned metadata default10 plus extensionFields Required && Default==nil means
// timeout is not HTML-required. This synthetic state is NOT browser/theme proof.
const themeStart=body.indexOf('async function runDetailTheme(');
const sampleStart=body.indexOf(' const sample=async',themeStart);
const sampleEnd=body.indexOf(' const media=async',sampleStart);
assert(themeStart>=0&&sampleStart>themeStart&&sampleEnd>sampleStart);
const sampleSource=body.slice(sampleStart,sampleEnd);
for(const scenario of ['default-backed-timeout','wrong-timeout-required','missing-endpoint-required','missing-hmac-required']){
 const required=[['field.webhook.endpoint','text',true],['field.webhook.timeout-seconds','number',false],['field.webhook.hmac-key','password',true]];
 if(scenario==='wrong-timeout-required')required[1][2]=true;
 if(scenario==='missing-endpoint-required')required[0][2]=false;
 if(scenario==='missing-hmac-required')required[2][2]=false;
 const state={theme:'system',width:320,client:305,scroll:305,overflow:0,sections:true,formsOK:true,passwordsBlank:true,scripts:0,storageEmpty:true,cookieNames:['gotth_mail_csrf','gotth_mail_session'],audit:detail+'/audit',actions:Array(5).fill(detail+'?theme=system'),required,styles:['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css'],body:['rgb(244, 246, 249)','rgb(23, 32, 51)'],controls:[['rgb(255, 255, 255)','rgb(23, 32, 51)']],ownership:'fixed-independent-form-fingerprint'};
 let accepted=true;
 try{await runInNewContext('(async()=>{let ownership;'+sampleSource+'await sample(320,"system","light");})()',{observe:async()=>state,detail,proof:{themeStates:[]}});}catch(e){accepted=false;assert.equal(e.message,'detail theme/geometry/form contract mismatch');}
 try{assert.equal(accepted,scenario==='default-backed-timeout');console.log('PASS actual theme oracle '+scenario);}catch(e){failures++;console.error('FAIL actual theme oracle '+scenario);}
}
// Actual CSS observer + stylesheet predicate; controlled protocol, not transport proof.
const cssStart=body.indexOf('const configurationCSSPaths=');
const cssEnd=body.indexOf('async function runConfiguration(',cssStart);
assert(cssStart>=0&&cssEnd>cssStart);
// Execute actual checkpoint AND read-only DOM expression under paired denials.
for(const scenario of ['null-sheet','empty-sheet','nonempty-sheet','unreadable-sheet','recovery-security','unknown-error','foreign-node','missing-node','duplicate-node','style-element','inline-style','foreign-sheet','adopted-sheet']){
 const paths=['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css'];
 const links=paths.map(path=>({href:origin+path,sheet:null}));
 if(scenario!=='null-sheet')for(const link of links){link.sheet={cssRules:[]};link.sheet.ownerNode=link;}
 if(scenario==='nonempty-sheet')links[0].sheet.cssRules=[{}];
 if(['unreadable-sheet','recovery-security','unknown-error'].includes(scenario))Object.defineProperty(links[0].sheet,'cssRules',{get(){throw Object.assign(Error('private-error'),{name:scenario==='unknown-error'?'UnknownError':'SecurityError'});}});
 if(scenario==='foreign-node')links[0].href='https://foreign.invalid/secret';
 if(scenario==='missing-node')links.pop();if(scenario==='duplicate-node')links.push(links[0]);
 const document={querySelectorAll:selector=>selector==='link[rel~=stylesheet]'||selector==='link[rel=stylesheet]'?links:selector==='style, [style]'&&['style-element','inline-style'].includes(scenario)?[{}]:[],styleSheets:links.map(l=>l.sheet).filter(Boolean),adoptedStyleSheets:scenario==='adopted-sheet'?[{}]:[]};
 if(scenario==='foreign-sheet')document.styleSheets.push({ownerNode:{}});
 const cp=Object.fromEntries(paths.map(p=>[p,1]));const proof={cssDenial:{attempts:{...cp},blocked:{...cp},checkpoints:0}};
 const ctx={URL,origin:new URL(origin),bootstrap:{id},proof,recoveryNoCSS:scenario!=='unreadable-sheet',interrupted:false,rejectPending:()=>{},observe:async expression=>runInNewContext(expression,{document,URL,location:new URL(origin)}),scenario,assert};
 const code=body.slice(cssStart,cssEnd)+"let accepted=true;try{await configurationNoCSSCheckpoint(1);}catch{accepted=false;}assert.equal(accepted,['null-sheet','empty-sheet','recovery-security'].includes(scenario));";
 await runInNewContext('(async()=>{'+code+'})()',ctx);
 assert(!JSON.stringify(proof).includes('private-error'));assert(!JSON.stringify(proof).includes('foreign.invalid'));
 console.log('PASS actual CSSOM checkpoint '+scenario);
}
// Malformed observational samples must not coerce into recovery acceptance.
for(const scenario of ['null-sample','missing-exact','null-unexpected','missing-links','duplicate-path','missing-associated','null-readable','missing-rules','false-rules','unknown-error','security-zero','null-link']){
 const paths=['/admin/extensions/assets/detail.css','/admin/extensions/assets/tokens.css'];
 let sample={exact:true,unexpected:false,links:paths.map(path=>({path,associated:true,readable:false,rules:null,error:'SecurityError'}))};
 if(scenario==='null-sample')sample=null;
 if(scenario==='missing-exact')delete sample.exact;
 if(scenario==='null-unexpected')sample.unexpected=null;
 if(scenario==='missing-links')delete sample.links;
 if(scenario==='duplicate-path')sample.links[1].path=paths[0];
 if(scenario==='missing-associated')delete sample.links[0].associated;
 if(scenario==='null-readable')sample.links[0].readable=null;
 if(scenario==='missing-rules')delete sample.links[0].rules;
 if(scenario==='false-rules')sample.links[0].rules=false;
 if(scenario==='unknown-error')sample.links[0].error='unknown';
 if(scenario==='security-zero')sample.links[0].rules=0;
 if(scenario==='null-link')sample.links[0]=null;
 const cp=Object.fromEntries(paths.map(p=>[p,1]));const proof={cssDenial:{attempts:{...cp},blocked:{...cp},checkpoints:0}};
 const ctx={URL,origin:new URL(origin),bootstrap:{id},proof,recoveryNoCSS:true,interrupted:false,rejectPending:()=>{},observe:async()=>sample,assert};
 await runInNewContext('(async()=>{'+body.slice(cssStart,cssEnd)+'let accepted=true;try{await configurationNoCSSCheckpoint(1);}catch{accepted=false;}assert.equal(accepted,false);})()',ctx);
 console.log('PASS malformed recovery CSSOM '+scenario);
}
for(const scenario of ['paired','paired-empty','empty-wrong-reason','empty-wrong-type','empty-unknown-id','missing-error','null-error','number-error','boolean-error','object-error','array-error','aborted-error','unknown-error','missing-path','wrong-reason','wrong-error','unknown-id','foreign-origin','extra-query','script','css-response','late-finish','duplicate-failure']){
 const cp={'/admin/extensions/assets/detail.css':0,'/admin/extensions/assets/tokens.css':0};
 const proof={cssDenial:{acceptedErrorForms:{empty:0,blockedByClient:0},attempts:{...cp},blocked:{...cp},checkpoints:0}};
 const ctx={URL,origin:new URL(origin),bootstrap:{id},proof,recoveryNoCSS:false,interrupted:false,rejectPending:()=>{},observe:async()=>({exact:true,unexpected:false,links:Object.keys(cp).map(path=>({path,associated:false,readable:false,rules:null,error:"none"}))}),scenario,assert};
 const exercise=body.slice(cssStart,cssEnd)+`
 const paths=configurationCSSPaths;
 assert(configurationStylesMatch(paths,false));assert(!configurationStylesMatch([],false));assert(!configurationStylesMatch([paths[0]],false));assert(configurationStylesMatch([],true));assert(!configurationStylesMatch(paths,true));
 for(let i=0;i<2;i++){
  if(scenario==='missing-path'&&i===1)continue;
  let url=origin.origin+paths[i],type='Stylesheet';
  if(i===0&&scenario==='foreign-origin')url='http://other'+paths[i];
  if(i===0&&scenario==='extra-query')url+='?x=1';
  if(i===0&&scenario==='script')type='Script';
  observeConfigurationCSS({method:'Network.requestWillBeSent',params:{requestId:String(i),type,request:{url,method:'GET'}}});
  if(i===0&&scenario==='css-response')observeConfigurationCSS({method:'Network.responseReceived',params:{requestId:String(i),type:'Stylesheet'}});
  const event={method:'Network.loadingFailed',params:{requestId:(i===0&&scenario==='unknown-id')?'absent':String(i),type:'Stylesheet',blockedReason:(i===0&&scenario==='wrong-reason')?'csp':'inspector',errorText:(i===0&&scenario==='wrong-error')?'net::ERR_FAILED':'net::ERR_BLOCKED_BY_CLIENT'}};
  if(scenario==='paired-empty'||scenario.startsWith('empty-'))event.params.errorText='';
  if(i===0){
   if(scenario==='empty-wrong-reason')event.params.blockedReason='csp';
   if(scenario==='empty-wrong-type')event.params.type='Document';
   if(scenario==='empty-unknown-id')event.params.requestId='absent';
   if(scenario==='missing-error')delete event.params.errorText;
   if(scenario==='null-error')event.params.errorText=null;
   if(scenario==='number-error')event.params.errorText=0;
   if(scenario==='boolean-error')event.params.errorText=false;
   if(scenario==='object-error')event.params.errorText={};
   if(scenario==='array-error')event.params.errorText=[];
   if(scenario==='aborted-error')event.params.errorText='net::ERR_ABORTED';
   if(scenario==='unknown-error')event.params.errorText='private-unretained-error';
  }
  observeConfigurationCSS(event);
  if(i===0&&scenario==='duplicate-failure')observeConfigurationCSS(event);
  if(i===0&&scenario==='late-finish')observeConfigurationCSS({method:'Network.loadingFinished',params:{requestId:String(i)}});
 }
 let positive=true;try{await configurationNoCSSCheckpoint(1);}catch{positive=false;}
 assert.equal(!interrupted&&positive,['paired','paired-empty'].includes(scenario));
 if(scenario==='paired'||scenario==='paired-empty'){
  assert.equal(proof.cssDenial.acceptedErrorForms.empty,scenario==='paired-empty'?2:0);
  assert.equal(proof.cssDenial.acceptedErrorForms.blockedByClient,scenario==='paired'?2:0);
 }
 if(scenario.startsWith('empty-'))assert.equal(proof.cssDenial.firstFailure.event.errorClass,'empty');
 if(scenario==='unknown-error')assert(!JSON.stringify(proof).includes('private-unretained-error'));

 `;
 await runInNewContext('(async()=>{'+exercise+'})()',ctx);
 console.log('PASS exact CSS denial observer '+scenario);
}
// Exact favicon admission does not change CSS attempts/blocked/checkpoint credit.
for(const scenario of ['Other','Image','query','method','foreign','prefix','script']){
 const cp={'/admin/extensions/assets/detail.css':0,'/admin/extensions/assets/tokens.css':0};const proof={cssDenial:{acceptedErrorForms:{empty:0,blockedByClient:0},attempts:{...cp},blocked:{...cp},checkpoints:0}};
 const before=JSON.stringify(proof);const ctx={URL,origin:new URL(origin),bootstrap:{id},proof,recoveryNoCSS:false,interrupted:false,rejectPending:()=>{},observe:async()=>({exact:true,unexpected:false,links:Object.keys(cp).map(path=>({path,associated:false,readable:false,rules:null,error:"none"}))})};
 let url=origin+'/favicon.ico',method='GET',type=['Other','Image'].includes(scenario)?scenario:'Other';
 if(scenario==='query')url+='?x=1';if(scenario==='method')method='POST';if(scenario==='foreign')url='http://other/favicon.ico';if(scenario==='prefix')url+='/x';if(scenario==='script')type='Script';
 ctx.event={method:'Network.requestWillBeSent',params:{requestId:'icon',type,request:{url,method}}};
 await runInNewContext('(async()=>{'+body.slice(cssStart,cssEnd)+'observeConfigurationCSS(event);})()',ctx);
 assert.equal(ctx.interrupted,!['Other','Image'].includes(scenario));assert.equal(JSON.stringify(proof.cssDenial.attempts),JSON.stringify(cp));assert.equal(JSON.stringify(proof.cssDenial.blocked),JSON.stringify(cp));if(['Other','Image'].includes(scenario))assert.equal(JSON.stringify(proof),before);else assert.equal(proof.cssDenial.firstFailure.code,'CSS_EVENT_MISMATCH');console.log('PASS exact favicon no-credit '+scenario);
}
if(failures)process.exitCode=1;
