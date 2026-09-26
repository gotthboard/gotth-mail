// Captured native preview, not live login. No non-secret field is rewritten.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';
const [input, output, expectation] = process.argv.slice(2);
if (!input || !output || !['red','green'].includes(expectation)) throw new Error('usage: CAPTURE_DIR NEW_OUTPUT_DIR red|green');
const out=resolve(output); mkdirSync(out,{mode:0o700});
const results=[];
for (const name of ['initial-true','edit-false','edit-true-defaults','rotation']) {
 const original=readFileSync(join(input,name+'.html'),'utf8');
 const expected=JSON.parse(readFileSync(join(input,name+'-expected.json'),'utf8'));
 const script=`
const button=document.querySelector('button[value="configure-apply"]');
const form=button.form;
const secret=form.querySelector('input[type="password"]');
const secretBlank=secret.value==='';
const confirmation=form.querySelector('input[name="confirmation"]');
const repreviewBlockedByConfirmation=!confirmation.checkValidity();
confirmation.value=Array.from(form.querySelectorAll('code')).map(n=>n.textContent).find(v=>v.startsWith('confirm-'));
// A disposable stand-in tests native initial-secret validation, not backend binding.
// The independent route test re-enters its actual random preview-bound secret.
if(secret.required) secret.value='test-only-secret-reentry';
const valid=form.checkValidity();
const values={};
for(const [key,value] of new FormData(form,button)) {
 if(key===secret.name) continue;
 (values[key]??=[]).push(value);
}
let submitted=0;
form.addEventListener('submit',event=>{event.preventDefault();submitted++;});
button.click();
const proof=document.createElement('pre');proof.id='native-proof';
// Encode JSON so HTML escaping of ampersands/angle brackets cannot alter the oracle.
proof.textContent=encodeURIComponent(JSON.stringify({valid,submitted,values,secretBlank,noValidate:form.noValidate,formNoValidate:button.formNoValidate,repreviewBlockedByConfirmation}));
document.body.appendChild(proof);
`;
 const instrumented=join(out,name+'-instrumented.html');
 if(!original.includes('</body>'))throw new Error('capture missing body');
 writeFileSync(instrumented,original.replace('</body>','<script>'+script+'</script></body>'),{mode:0o600});
 const profile=mkdtempSync(join(out,'profile-'));
 try {
  const run=spawnSync('chromium',['--headless','--disable-background-networking','--no-first-run','--no-default-browser-check','--user-data-dir='+profile,'--dump-dom',pathToFileURL(instrumented).href],{encoding:'utf8',timeout:60000,maxBuffer:2<<20});
  writeFileSync(join(out,name+'-stderr.log'),run.stderr||'',{mode:0o600});
  writeFileSync(join(out,name+'-dom.html'),run.stdout||'',{mode:0o600});
  if(run.error||run.status!==0)throw new Error('Chromium failed: '+(run.error?.message||run.status));
  const match=run.stdout.match(new RegExp('<pre id="native-proof">([^<]+)</pre>'));
  if(!match)throw new Error('proof missing');
  const proof=JSON.parse(decodeURIComponent(match[1]));
  results.push({name,...proof,exactControls:isDeepStrictEqual(proof.values,expected)});
 } finally {rmSync(profile,{recursive:true});}
}
writeFileSync(join(out,'proof.json'),JSON.stringify({expectation,defaultSandbox:true,limitation:'captured HTML; route SQL is independent; no nonsecret edits',results},null,2)+String.fromCharCode(10),{mode:0o600});
console.log(JSON.stringify(results.map(({values,...summary})=>summary)));
if(results.some(p=>!p.secretBlank||p.noValidate||p.formNoValidate))throw new Error('secret reflection or validation bypass');
if(expectation==='green' && results.some(p=>!p.valid||p.submitted!==1||!p.exactControls))throw new Error('native roundtrip failed');
if(expectation==='red' && results.some(p=>p.exactControls))throw new Error('expected-red mismatch absent');
