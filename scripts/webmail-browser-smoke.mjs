#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const chromium = process.env.CHROMIUM || 'chromium';
const temp = await mkdtemp(path.join(os.tmpdir(), 'gotth-mail-browser-'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    server.close(error => error ? reject(error) : resolve(port));
  });
});
const appPort = await freePort();
const debugPort = await freePort();
const base = 'http://127.0.0.1:' + appPort;
let goTest;
let chrome;

async function waitHTTP(url, attempts = 100) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url, { redirect: 'manual' });
      if (response.status < 500) return response;
    } catch (_) {}
    await sleep(100);
  }
  throw new Error('timeout waiting for ' + url);
}

class CDP {
  constructor(url) {
    this.id = 0;
    this.pending = new Map();
    this.events = new Map();
    this.socket = new WebSocket(url);
    this.socket.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const pending = this.pending.get(message.id);
        this.pending.delete(message.id);
        message.error ? pending.reject(new Error(message.error.message)) : pending.resolve(message.result);
      } else if (message.method && this.events.has(message.method)) {
        for (const resolve of this.events.get(message.method).splice(0)) resolve(message.params);
      }
    };
  }
  ready() { return new Promise((resolve, reject) => { this.socket.onopen = resolve; this.socket.onerror = reject; }); }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
  event(method) { return new Promise(resolve => { if (!this.events.has(method)) this.events.set(method, []); this.events.get(method).push(resolve); }); }
  close() { this.socket.close(); }
}

async function evaluate(cdp, expression) {
  const result = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'browser evaluation failed');
  return result.result.value;
}

async function waitFor(cdp, expression, label) {
  for (let i = 0; i < 100; i++) {
    if (await evaluate(cdp, expression)) return;
    await sleep(100);
  }
  throw new Error('timeout waiting for ' + label);
}

try {
  goTest = spawn('go', ['test', './internal/api', '-run', '^TestWebmailBrowserFixture$', '-count=1'], {
    cwd: root,
    env: { ...process.env, GOTTH_MAIL_BROWSER_FIXTURE_ADDR: '127.0.0.1:' + appPort },
    stdio: ['ignore', 'inherit', 'inherit']
  });
  await waitHTTP(base + '/__browser_start');
  chrome = spawn(chromium, ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + debugPort, '--user-data-dir=' + temp, 'about:blank'], { stdio: ['ignore', 'ignore', 'inherit'] });
  await waitHTTP('http://127.0.0.1:' + debugPort + '/json/version');
  const targets = await (await fetch('http://127.0.0.1:' + debugPort + '/json/list')).json();
  const target = targets.find(item => item.type === 'page');
  if (!target) throw new Error('Chromium page target unavailable');
  const cdp = new CDP(target.webSocketDebuggerUrl);
  await cdp.ready();
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  const loaded = cdp.event('Page.loadEventFired');
  await cdp.send('Page.navigate', { url: base + '/__browser_start' });
  await loaded;
  await waitFor(cdp, "document.querySelectorAll('.message-row').length===1 && document.getElementById('account-label').textContent==='browser@example.test'", 'authenticated message list');
  const panes = await evaluate(cdp, "['folder-pane','list-pane','reader-pane'].every(id=>!!document.getElementById(id))");
  if (!panes) throw new Error('three-pane structure missing');
  const footer = await evaluate(cdp, "(function(){var el=document.querySelector('.gotth-footer');if(!el)return false;var style=getComputedStyle(el);return el.textContent.includes('Powered by GOTTH Mail')&&el.textContent.includes('Version: dev')&&/Page: \\d+ms/.test(el.textContent)&&/Template: \\d+ms/.test(el.textContent)&&style.display==='flex'&&style.justifyContent==='flex-start'&&style.minHeight==='104px'&&style.backgroundColor==='rgb(5, 8, 23)'&&style.borderTopWidth==='1px'})()");
  if (!footer) throw new Error('canonical GOTTH footer missing or incorrectly styled');
  if (!(await evaluate(cdp, "document.querySelector('.folder-button').textContent.includes('2 unread') && document.querySelector('.message-row').classList.contains('has-attachment')"))) throw new Error('unread count or attachment state missing');
  const folderRequests = await evaluate(cdp, "performance.getEntriesByType('resource').filter(function(entry){return entry.name.endsWith('/api/v1/webmail/folders')}).length");
  await evaluate(cdp, "document.querySelector('.message-row').click()");
  await waitFor(cdp, "getComputedStyle(document.getElementById('empty-reader')).display==='none' && getComputedStyle(document.getElementById('message-reader')).display!=='none' && document.getElementById('message-body').textContent.includes('Safe browser message body')", 'message reader without stale placeholder');
  await waitFor(cdp, "performance.getEntriesByType('resource').filter(function(entry){return entry.name.endsWith('/api/v1/webmail/folders')}).length>" + folderRequests, 'folder state refresh after mark read');
  await evaluate(cdp, "document.querySelector('[data-command=forward]').click()");
  if (!(await evaluate(cdp, "document.getElementById('composer').open && document.querySelectorAll('#compose-existing-list button').length===1"))) throw new Error('forward attachment state missing');
  await evaluate(cdp, "document.querySelector('#compose-existing-list button').click()");
  if (!(await evaluate(cdp, "document.getElementById('compose-existing').hidden"))) throw new Error('forward attachment removal failed');
  await evaluate(cdp, "document.getElementById('composer').close()");
  await evaluate(cdp, "document.querySelector('.message-row').dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,clientX:20,clientY:20}))");
  if (!(await evaluate(cdp, "!document.getElementById('context-menu').hidden"))) throw new Error('keyboard-equivalent context menu missing');
  await evaluate(cdp, "document.querySelector('.commandbar [data-command=reply_all]').click()");
  if (!(await evaluate(cdp, "document.getElementById('composer').open && document.getElementById('compose-to').value==='sender@example.test' && document.getElementById('compose-cc').value.includes('colleague@example.test')"))) throw new Error('reply-all recipient selection failed');
  await evaluate(cdp, "document.getElementById('composer').close()");
  await evaluate(cdp, "document.querySelector('[data-command=new]').click()");
  if (!(await evaluate(cdp, "document.getElementById('compose-subject').value===''"))) throw new Error('new message inherited selected subject');
  await evaluate(cdp, "document.getElementById('compose-to').value='recipient@example.test';document.getElementById('compose-subject').value='Browser composed';document.getElementById('compose-body').value='Browser composed body';document.getElementById('compose-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))");
  await waitFor(cdp, "!document.getElementById('composer').open && document.getElementById('status').textContent==='Message sent with exact-sender OpenPGP signature'", 'signed compose/send');
  await evaluate(cdp, "document.querySelector('[data-command=new]').click();document.getElementById('compose-to').value='draft-recipient@example.test';document.getElementById('compose-subject').value='Browser saved draft';document.getElementById('compose-body').value='Saved draft body';document.getElementById('save-draft').click()");
  await waitFor(cdp, "!document.getElementById('composer').open && document.getElementById('status').textContent==='Draft saved'", 'save draft');
  await evaluate(cdp, "document.querySelector('[data-command=drafts]').click()");
  await waitFor(cdp, "document.getElementById('draft-list-dialog').open && document.querySelectorAll('#saved-drafts button').length===1", 'saved draft list');
  await evaluate(cdp, "document.querySelector('#saved-drafts button').click()");
  await waitFor(cdp, "document.getElementById('composer').open && document.getElementById('compose-draft-id').value!==''", 'saved draft detail');
  if (!(await evaluate(cdp, "document.getElementById('composer').open && document.getElementById('compose-draft-id').value!=='' && document.getElementById('compose-to').value==='draft-recipient@example.test' && document.getElementById('compose-subject').value==='Browser saved draft'"))) throw new Error('saved draft did not reopen for editing');
  await evaluate(cdp, "document.getElementById('compose-subject').value='Browser edited draft';document.getElementById('save-draft').click()");
  await waitFor(cdp, "!document.getElementById('composer').open && document.getElementById('status').textContent==='Draft saved'", 'update draft');
  await evaluate(cdp, "document.querySelector('[data-command=drafts]').click()");
  await waitFor(cdp, "document.getElementById('draft-list-dialog').open && document.querySelector('#saved-drafts button').textContent.includes('Browser edited draft')", 'updated draft list');
  await evaluate(cdp, "document.querySelector('#saved-drafts button').click()");
  await waitFor(cdp, "document.getElementById('composer').open && document.getElementById('compose-subject').value==='Browser edited draft'", 'updated draft detail');
  await evaluate(cdp, "document.getElementById('compose-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))");
  await waitFor(cdp, "!document.getElementById('composer').open && document.getElementById('status').textContent==='Message sent with exact-sender OpenPGP signature'", 'send saved draft');
  await evaluate(cdp, "document.querySelector('[data-command=drafts]').click()");
  await waitFor(cdp, "document.getElementById('draft-list-dialog').open && document.querySelectorAll('#saved-drafts button').length===0", 'sent draft removed from editable list');
  await evaluate(cdp, "document.getElementById('draft-list-dialog').close()");
  await evaluate(cdp, "var p=document.getElementById('pane-placement');p.value='below';p.dispatchEvent(new Event('change',{bubbles:true}));document.getElementById('theme-toggle').click()");
  const preferences = await evaluate(cdp, "document.getElementById('mail-app').classList.contains('pane-below') && document.documentElement.dataset.theme==='dark'");
  if (!preferences) throw new Error('pane placement or dark theme failed');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 980, height: 1180, deviceScaleFactor: 1, mobile: true });
  const tablet = await evaluate(cdp, "matchMedia('(max-width:1024px)').matches && getComputedStyle(document.querySelector('.viewbar')).display==='none' && getComputedStyle(document.querySelector('.mobile-heading button')).display!=='none' && document.documentElement.scrollWidth===document.documentElement.clientWidth");
  if (!tablet) throw new Error('tablet layout did not collapse to bounded drill-down');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await evaluate(cdp, "document.querySelector('.folder-button').click()");
  const mobile = await evaluate(cdp, "(function(){var search=document.getElementById('search-form').getBoundingClientRect();var actions=document.querySelector('.command-actions').getBoundingClientRect();var account=document.querySelector('.account').getBoundingClientRect();var brand=document.querySelector('.brand').getBoundingClientRect();return document.body.dataset.mobileView==='messages' && getComputedStyle(document.getElementById('folder-pane')).display==='none' && getComputedStyle(document.querySelector('[data-command=reply]')).display!=='none' && getComputedStyle(document.getElementById('search-form')).display!=='none' && search.left>=0 && search.right<=innerWidth && search.top>=actions.bottom && account.top>=brand.bottom && document.documentElement.scrollWidth===document.documentElement.clientWidth && getComputedStyle(document.querySelector('.gotth-footer')).display==='flex'})()");
  if (!mobile) throw new Error('mobile folder-to-list drill-down failed');
  if (!(await evaluate(cdp, "window.htmx && window.htmx.version==='2.0.10'"))) throw new Error('pinned HTMX runtime missing');
  const mobileScrollBeforeOpen = await evaluate(cdp, 'scrollY');
  const mobileFragmentRequestsBefore = await evaluate(cdp, "performance.getEntriesByType('resource').filter(function(entry){return entry.name.includes('/webmail/fragments/message?')}).length");
  await evaluate(cdp, "window.__mobileMessageList=document.getElementById('message-list')");
  await evaluate(cdp, "document.querySelector('.message-row').click()");
  await waitFor(cdp, "document.body.dataset.mobileView==='reader' && document.getElementById('message-body').textContent.includes('Safe browser message body')", 'HTMX message-reader swap');
  const mobileReader = await evaluate(cdp, `(function(){
    var list=document.getElementById('list-pane');
    var reader=document.getElementById('reader-pane');
    var box=reader.getBoundingClientRect();
    var fragmentRequests=performance.getEntriesByType('resource').filter(function(entry){return entry.name.includes('/webmail/fragments/message?')}).length;
    var empty=document.getElementById('empty-reader');
    var message=document.getElementById('message-reader');
    return fragmentRequests>${mobileFragmentRequestsBefore} && empty.hidden && getComputedStyle(empty).display==='none' && empty.getClientRects().length===0 && getComputedStyle(message).display!=='none' && message.getClientRects().length===1 && getComputedStyle(list).display==='none' && getComputedStyle(reader).display!=='none' && box.top>=0 && box.left>=0 && box.right<=innerWidth && scrollY===${mobileScrollBeforeOpen} && document.documentElement.scrollWidth===document.documentElement.clientWidth;
  })()`);
  if (!mobileReader) throw new Error('message reader was not swapped into the bounded mobile viewport');
  await evaluate(cdp, "document.querySelector('#reader-pane [data-mobile-back=messages]').click()");
  if (!(await evaluate(cdp, "document.body.dataset.mobileView==='messages' && getComputedStyle(document.getElementById('list-pane')).display!=='none' && window.__mobileMessageList===document.getElementById('message-list') && document.activeElement.matches('.message-row[aria-selected=true]')"))) throw new Error('mobile reader back navigation lost the message list or selected focus');
  await evaluate(cdp, "document.querySelector('[data-command=new]').click()");
  const composer = await evaluate(cdp, "(function(){var dialog=document.getElementById('composer').getBoundingClientRect();var form=document.getElementById('compose-form');return document.getElementById('composer').open && dialog.left>=0 && dialog.right<=innerWidth && dialog.top>=0 && dialog.bottom<=innerHeight && ['auto','scroll'].includes(getComputedStyle(form).overflowY)})()");
  if (!composer) throw new Error('mobile composer did not stay bounded and scrollable');
  cdp.close();
  await fetch(base + '/__browser_done');
  const code = await new Promise(resolve => goTest.once('exit', resolve));
  if (code !== 0) throw new Error('browser fixture test failed with exit ' + code);
  console.log('webmail browser smoke passed');
} finally {
  if (chrome && chrome.exitCode === null) {
    chrome.kill('SIGTERM');
    await Promise.race([new Promise(resolve => chrome.once('exit', resolve)), sleep(3000)]);
  }
  if (goTest && goTest.exitCode === null) {
    goTest.kill('SIGTERM');
    await Promise.race([new Promise(resolve => goTest.once('exit', resolve)), sleep(3000)]);
  }
  await rm(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
