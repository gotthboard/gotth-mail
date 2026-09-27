/* Host-owned optional enhancement. Initial HTML always has an ordinary href.
 * Initialization touches a fixed set of shell nodes: O(1), Omega(1), Theta(1)
 * local work/storage; HTMX processing and DOM operations have delegated costs.
 * No row projection, browser persistence, polling or mutation API is introduced.
 */
(function () {
 'use strict';
 const refresh = document.getElementById('inventory-refresh');
 const reload = document.getElementById('inventory-reload');
 const region = document.getElementById('extension-inventory');
 const status = document.getElementById('inventory-status');
 const error = document.getElementById('inventory-error');
 if (!refresh || !reload || !region || !status || !error) return;
 const config = {allowEval:false,allowScriptTags:false,selfRequestsOnly:true,includeIndicatorStyles:false,historyEnabled:false,historyCacheSize:0,historyRestoreAsHxRequest:false,allowNestedOobSwaps:false,timeout:10000};
 let inserted = false;

 // Four literal full-URL comparisons, no normalization. For URL/origin bytes U,
 // time O(U), Omega(1), auxiliary O(U), Omega(1); no tight bound across failures.
 function canonical() {
  const origin = window.location.origin, href = window.location.href;
  return ['/admin/extensions','/admin/extensions?theme=system','/admin/extensions?theme=light','/admin/extensions?theme=dark'].some(path => href === origin + path);
 }

 // Fixed shell/meta/CSS checks. Time O(M+U+C), Omega(1), space O(M+U),
 // Omega(1); no tight bound across failures. M meta bytes, U URL bytes; C
 // delegated CSSOM access. Never inspects rows or creates browser storage.
 function ready() {
  if (!canonical() || document.readyState !== 'complete' || document.body.getAttribute('hx-history') !== 'false') return false;
  for (const node of [refresh,reload,region,status,error]) if (document.getElementById(node.id) !== node) return false;
  const meta = document.querySelector('meta[name="htmx-config"]');
  try {
   const declared = JSON.parse(meta.getAttribute('content'));
   for (const key of Object.keys(config)) if (declared[key] !== config[key]) return false;
  } catch (_) { return false; }
  if (!/^\/admin\/extensions\?theme=(system|light|dark)$/.test(refresh.getAttribute('href') || '')) return false;
  for (const pair of [['inventory-tokens-css','/admin/extensions/assets/tokens.css'],['inventory-utilities-css','/admin/extensions/assets/inventory.css']]) {
   const link = document.getElementById(pair[0]);
   try {
    if (!link || link.getAttribute('href') !== pair[1] || link.rel !== 'stylesheet' || link.disabled || !link.sheet || !link.sheet.cssRules.length || link.href !== window.location.origin + pair[1]) return false;
   } catch (_) { return false; }
  }
  return true;
 }

 // Fixed config/function checks plus ready() costs above; no row traversal.
 // Time O(M+U+C), Omega(1); space O(M+U), Omega(1), no tight failure bound.
 function vendorReady() {
  const htmx = window.htmx;
  if (!ready() || !htmx || htmx.version !== '2.0.10' || typeof htmx.process !== 'function' || !htmx.config) return false;
  return Object.keys(config).every(key => htmx.config[key] === config[key]);
 }
 const marker = '<!-- gotth-mail-extension-inventory-v1 -->';
 let active = null;

 // Completion: O(D+S) time, Omega(1); auxiliary O(S), Omega(1), no tight
 // bound for delegated DOM cleanup S. D removed DOM nodes on authorization
 // loss; other paths touch only fixed shell nodes. No response is reflected.
 function finish(ok, unauthorized) {
  if (active) window.clearTimeout(active.timer);
  active = null;
  region.setAttribute('aria-busy', 'false');
  refresh.removeAttribute('aria-disabled');
  reload.hidden = ok;
  if (ok) {
   region.hidden = false;
   region.removeAttribute('data-stale');
   status.textContent = 'Inventory refreshed.';
   error.textContent = '';
  } else {
   if (unauthorized) { region.replaceChildren(); region.hidden = true; }
   region.setAttribute('data-stale', 'true');
   status.textContent = unauthorized ? 'Inventory unavailable.' : 'Inventory stale.';
   error.textContent = unauthorized ? 'Authorization required. Reload the full inventory.' : 'Refresh failed. Previous results may be stale; reload the full inventory.';
  }
 }

 // Correlation costs O(1), Omega(1), Theta(1) time/space, independent of rows.
 function matches(event) { return active && event.detail && event.detail.xhr === active.xhr; }

 // Pinned HTMX ae() overwrites detail.elt at each dispatch (beforeSwap uses
 // the region), while requestConfig.elt preserves the initiating control.
 // Fixed identity check: O(1), Omega(1), Theta(1) time and auxiliary space.
 function owned(event) { return event.detail && event.detail.requestConfig && event.detail.requestConfig.elt === refresh; }

 // Gate costs O(H), Omega(1) time/space; no tight bound across failures.
 // H response-header bytes. Body prefix comparison is bounded; HTMX already
 // owns the full response buffer and subsequent DOM parsing (not a byte cap).
 function acceptable(detail) {
  try {
   const xhr = detail.xhr;
   const mime = (xhr.getResponseHeader('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
   // beforeOnLoad precedes HTMX's header commands in the pinned2.0.10 source.
   const commands = xhr.getAllResponseHeaders().split(String.fromCharCode(10)).some(line => line.trimStart().toLowerCase().startsWith('hx-'));
   return detail.target === region && xhr.status === 200 && mime === 'text/html' && !commands && typeof xhr.responseText === 'string' && xhr.responseText.startsWith(marker);
  } catch (_) { return false; }
 }

 // All callbacks are installed BEFORE any operative hx-get is added. Their
 // local work is constant except the named header gate / DOM-clear operations.
 document.body.addEventListener('htmx:beforeRequest', function (event) {
  const detail = event.detail;
  if (!detail || detail.elt !== refresh) return;
  if (!vendorReady() || active || detail.target !== region || !detail.xhr) { event.preventDefault(); return; }
  const operation = {xhr:detail.xhr, accepted:false, timer:0};
  active = operation;
  region.setAttribute('aria-busy', 'true');
  refresh.setAttribute('aria-disabled', 'true');
  error.textContent = '';
  status.textContent = 'Refreshing inventory…';
  operation.timer = window.setTimeout(function () {
   if (active !== operation) return;
   // Retire state BEFORE abort: abort fires synchronous terminal callbacks.
   // No state writes after abort may clobber a newly started operation.
   finish(false, false);
   operation.xhr.abort();
  }, 11000);
 });
 document.body.addEventListener('htmx:beforeOnLoad', function (event) {
  if (!owned(event)) return;
  if (!matches(event)) { event.preventDefault(); return; }
  if (!acceptable(event.detail)) {
   event.preventDefault();
   finish(false, event.detail.xhr.status === 401 || event.detail.xhr.status === 403);
  }
 });
 document.body.addEventListener('htmx:beforeSwap', function (event) {
  if (!owned(event)) return;
  if (!matches(event)) { event.detail.shouldSwap = false; event.preventDefault(); return; }
  if (!acceptable(event.detail) || event.detail.shouldSwap !== true) {
   event.detail.shouldSwap = false;
   event.preventDefault();
   finish(false, event.detail.xhr.status === 401 || event.detail.xhr.status === 403);
   return;
  }
  active.accepted = true;
 });
 document.body.addEventListener('htmx:afterSwap', function (event) {
  if (!matches(event)) return;
  if (active.accepted && event.detail.target === region && document.getElementById('extension-inventory') === region) finish(true, false);
  else finish(false, false);
 });
 document.body.addEventListener('htmx:afterRequest', function (event) {
  if (!matches(event)) return;
  const operation = active;
  // Pinned HTMX performs its default synchronous swap before afterRequest.
  // Defer one task so sendAbort/sendError/timeout also get their terminal turn.
  window.setTimeout(function () { if (active === operation) finish(false, false); }, 0);
 });
 for (const name of ['htmx:sendError','htmx:sendAbort','htmx:timeout','htmx:swapError','htmx:onLoadError','htmx:responseError']) {
  document.body.addEventListener(name, function (event) { if (matches(event)) finish(false, false); });
 }
 window.addEventListener('pageshow', function (event) {
  if (!event.persisted) return;
  if (active) window.clearTimeout(active.timer);
  active = null;
  region.replaceChildren();
  region.hidden = true;
  region.setAttribute('aria-busy', 'false');
  refresh.removeAttribute('aria-disabled');
  status.textContent = 'Reloading inventory…';
  error.textContent = '';
  window.location.reload(); // Mitigates stale BFCache restoration, not pre-event paint.
 });

 // Activation: O(C+P) time, Omega(1), auxiliary O(1+S), Omega(1), no tight
 // bound for browser/HTMX processing P/S. C fixed CSS/config checks; no row scan
 // here (only the fixed refresh link is passed to HTMX).
 function enable() {
  const htmx = window.htmx;
  if (!vendorReady()) return;
  const href = refresh.getAttribute('href');
  const attributes = ['hx-get','hx-target','hx-swap','hx-sync'];
  refresh.setAttribute('hx-get', href);
  refresh.setAttribute('hx-target', '#extension-inventory');
  refresh.setAttribute('hx-swap', 'innerHTML');
  refresh.setAttribute('hx-sync', 'this:drop');
  try { htmx.process(refresh); }
  catch (_) {
   for (const name of attributes) refresh.removeAttribute(name);
   // Discard any partially installed HTMX listeners, retaining native href.
   const focused = document.activeElement === refresh;
   const fallback = refresh.cloneNode(true);
   refresh.replaceWith(fallback);
   if (focused) fallback.focus({preventScroll:true});
  }
 }
 // Loader: at most one append. Local costs are ready() plus constant DOM
 // setup; O(M+U+C+D), Omega(1) time, O(M+U+S), Omega(1) space, no tight bound
 // for delegated DOM/network/vendor D/S. Vendor writes ONLY reviewed public
 // current-path bookkeeping and its fixed transient availability probe.
 function load() {
  if (inserted || !ready() || window.htmx) return;
  inserted = true;
  const script = document.createElement('script');
  script.src = '/admin/extensions/assets/htmx-2.0.10.min.js';
  script.addEventListener('load', enable, {once:true});
  script.addEventListener('error', function () { /* Ordinary href remains. */ }, {once:true});
  document.head.appendChild(script);
 }
 // Dynamic pinned HTMX initializes synchronously only at complete. Never
 // append in the after-DOMContentLoaded/before-complete interval.
 if (document.readyState !== 'complete') window.addEventListener('load', load, {once:true});
 else load();
})();
