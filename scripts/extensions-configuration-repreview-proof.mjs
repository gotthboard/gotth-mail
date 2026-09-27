// Actual native re-preview clicks on captured HTML, not live login.
// Edit only Preview controls; never rewrite the accepted Apply configuration.
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
const preview=document.querySelector('button[value="configure-preview"]');
const apply=document.querySelector('button[value="configure-apply"]');
const editForm=preview.form, applyForm=apply.form;
const confirmation=applyForm.querySelector('input[name="confirmation"]');
const secretBlank=Array.from(document.querySelectorAll('input[type="password"]')).every(n=>n.value==='');
const summary=applyForm.querySelector('#configuration-reviewed');
const summaryBefore=summary?.textContent;
const reviewedValues={};
for(const term of summary?.querySelectorAll("dt")||[]) reviewedValues[term.querySelector("code").textContent]=term.nextElementSibling.textContent;
for(const secret of document.querySelectorAll('input[type="password"]')) if(secret.required) secret.value='test-only-reentry';
const text=editForm.querySelector('[name="field.config.text"]');
text.value='ordinary edited value';
let repreviewSubmitted=0, applySubmitted=0, previewValues;
const entries=(form,button)=>{const values={};for(const [k,v] of new FormData(form,button)){if(k==='field.config.key')continue;(values[k]??=[]).push(v);}return values;};
document.addEventListener('submit',event=>{event.preventDefault();if(event.submitter===preview){repreviewSubmitted++;previewValues=entries(editForm,preview);}if(event.submitter===apply)applySubmitted++;});
const confirmationBlank=confirmation.value==='';
preview.click();
const validPreviewClicks=repreviewSubmitted;
text.value=''; // invalid ordinary required control must still block Preview
preview.click();
const invalidPreviewBlocked=repreviewSubmitted===validPreviewClicks;
apply.click();
const blankApplyBlocked=applySubmitted===0;
confirmation.value=Array.from(applyForm.querySelectorAll('code')).map(n=>n.textContent).find(v=>v.startsWith('confirm-'));
const values=entries(applyForm,apply);
// Even invalid, newly edited Preview controls must not contaminate accepted Apply.
apply.click();
const proof=document.createElement('pre');proof.id='native-proof';
proof.textContent=encodeURIComponent(JSON.stringify({secretBlank,confirmationBlank,separate:editForm!==applyForm,repreviewSubmitted,previewValues,invalidPreviewBlocked,blankApplyBlocked,applySubmitted,values,summaryStable:!!summary && summaryBefore===summary.textContent,summaryText:summary?.textContent,reviewedValues,noValidate:editForm.noValidate||applyForm.noValidate,formNoValidate:preview.formNoValidate||apply.formNoValidate}));
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
  const expectedSummary={};
  for(const [key,value] of Object.entries(expected)) if(key.startsWith('field.')) expectedSummary[key.slice(6)]=value[0]||'Not set';
  expectedSummary['config.flag']=expected['field.config.flag'] ? 'true' : 'false';
  results.push({name,...proof,exactControls:isDeepStrictEqual(proof.values,expected),exactSummary:isDeepStrictEqual(proof.reviewedValues,expectedSummary)});
 } finally {rmSync(profile,{recursive:true});}
}
writeFileSync(join(out,'proof.json'),JSON.stringify({expectation,defaultSandbox:true,limitation:'captured HTML; route SQL independent; no accepted Apply configuration edits',results},null,2)+String.fromCharCode(10),{mode:0o600});
console.log(JSON.stringify(results.map(({values,previewValues,summaryText,reviewedValues,...summary})=>summary)));
if(results.some(p=>!p.secretBlank||p.noValidate||p.formNoValidate))throw new Error('secret reflection or validation bypass');
if(expectation==='green' && results.some(p=>!p.separate||p.repreviewSubmitted!==1||!p.invalidPreviewBlocked||!p.blankApplyBlocked||p.applySubmitted!==1||!p.exactControls||!p.summaryStable||!p.exactSummary||p.previewValues?.confirmation!==undefined||p.previewValues?.['field.config.text']?.[0]!=='ordinary edited value'))throw new Error('native re-preview isolation failed');
if(expectation==='red' && results.some(p=>p.repreviewSubmitted!==0||!p.confirmationBlank))throw new Error('expected native re-preview obstruction absent');
