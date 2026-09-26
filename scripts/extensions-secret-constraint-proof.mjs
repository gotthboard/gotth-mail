// Native constraint proof on captured route HTML, NOT a live authenticated browser flow.
// Instrumentation fills ordinary non-secret controls, observes click/submit, then
// prevents navigation after submit. Validation attributes and secret values stay unchanged.
import { readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const [input, output, expectation] = process.argv.slice(2);
if (!input || !output || !['blocked', 'valid'].includes(expectation)) {
  throw new Error('usage: node extensions-secret-constraint-proof.mjs CAPTURE_DIR NEW_OUTPUT_DIR blocked|valid');
}
const out = resolve(output);
mkdirSync(out, { mode: 0o700 }); // no overwrite of frozen evidence
const results = [];
for (const [name, action] of [['configured-detail', 'configure-preview'], ['configured-preview', 'configure-apply']]) {
  const original = readFileSync(join(input, name + '.html'), 'utf8');
  const script = `<script>
const button=document.querySelector('button[value="ACTION"]');
const form=button.form;
const secret=form.querySelector('input[type="password"]');
const endpoint=form.querySelector('input[name="field.webhook.endpoint"]');
const confirmation=form.querySelector('input[name="confirmation"]');
endpoint.value='https://example.test/changed';
if(confirmation) confirmation.value=Array.from(form.querySelectorAll('code')).map(n=>n.textContent).find(v=>v.startsWith('confirm-'));
const before=form.checkValidity();
let submitted=0;
form.addEventListener('submit',event=>{event.preventDefault();submitted++;});
button.click();
const proof=document.createElement('pre');proof.id='native-proof';
proof.textContent=JSON.stringify({valid:before,submitted,secretRequired:secret.required,secretBlank:secret.value==='',secretDisabled:secret.disabled,noValidate:form.noValidate,formNoValidate:button.formNoValidate});
document.body.appendChild(proof);
</script>`.replace('ACTION', action);
  const instrumented = join(out, name + '-instrumented.html');
  if (!original.includes('</body>')) throw new Error('captured route body missing');
  writeFileSync(instrumented, original.replace('</body>', script + '</body>'), { mode: 0o600 });
  const profile = mkdtempSync(join(out, 'profile-'));
  try {
    const run = spawnSync('chromium', ['--headless', '--disable-background-networking', '--no-first-run', '--no-default-browser-check', '--user-data-dir=' + profile, '--dump-dom', pathToFileURL(instrumented).href], { encoding: 'utf8', timeout: 60000, maxBuffer: 2 << 20 });
    writeFileSync(join(out, name + '-stderr.log'), run.stderr || '', { mode: 0o600 });
    writeFileSync(join(out, name + '-dom.html'), run.stdout || '', { mode: 0o600 });
    if (run.error || run.status !== 0) throw new Error('Chromium failed: ' + (run.error?.message || run.status));
    const match = run.stdout.match(new RegExp('<pre id="native-proof">([^<]+)</pre>'));
    if (!match) throw new Error('native constraint proof absent');
    const proof = JSON.parse(match[1]);
    results.push({ name, ...proof });
    const valid = expectation === 'valid';
    if (proof.valid !== valid || proof.submitted !== (valid ? 1 : 0) || proof.secretRequired === valid || !proof.secretBlank || proof.secretDisabled || proof.noValidate || proof.formNoValidate) throw new Error('unexpected native validation result');
  } finally {
    // Exact temporary profile created above, child has exited; no unrelated cleanup.
    rmSync(profile, { recursive: true });
  }
}
writeFileSync(join(out, 'proof.json'), JSON.stringify({ expectation, defaultSandbox: true, limitation: 'captured HTML with test-only click/submit instrumentation; no live session or SQL browser flow', results }, null, 2) + String.fromCharCode(10), { mode: 0o600 });
console.log(JSON.stringify(results));
