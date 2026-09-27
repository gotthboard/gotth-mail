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
for(const scenario of ['normal','duplicate-close','signal-close','duplicate-after-exit','undrained']){
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
 const bootstrap={origin,id,session:'fixture-session',csrf:'fixture-csrf',mode:'audit',audit_expected:JSON.stringify([{id:row.ID,action:row.Action}])};
 const context={spawn:()=>browser,readFileSync:p=>p===0?JSON.stringify(bootstrap):bytes,
  writeFileSync:(p,data)=>{assert.equal(p,'/evidence/proof.json');proof=JSON.parse(data);},
  mkdirSync:()=>{},mkdtempSync:p=>p+(++serial),readdirSync:()=>[],rmSync:p=>removed.push(p),statSync:()=>({size:bytes.length}),
  createHash,join,resolve,URL,Buffer,process:proc,setTimeout,clearTimeout,
  delay:()=>new Promise(r=>setImmediate(r)),console:{log:()=>{}}};
 await runInNewContext('(async()=>{"use strict";\n'+body+'\n})()',context,{timeout:1000});
 try{
  assert.equal(proof.auditGate,scenario==='normal'?'PASS':'FAIL');
  assert.equal(proc.exitCode || 0,scenario==='normal'?0:1);
  assert.equal(proof.cleanup.mainExited,true);
  assert.equal(proof.cleanup.remaining.length,0);
  assert.equal(removed.length,2,'private profile/download cleanup must survive failure');
  if(scenario!=='normal')assert.equal(proof.error,'audit interrupted or event stream not drained before proof');
  console.log('PASS '+scenario);
 }catch(e){failures++;console.error('FAIL '+scenario+': '+e.message);}
}
if(failures)process.exitCode=1;
