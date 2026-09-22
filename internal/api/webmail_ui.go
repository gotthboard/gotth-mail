package api

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/webmail"
)

func webmailSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; trusted-types default; require-trusted-types-for 'script'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

func serveWebmailAsset(w http.ResponseWriter, r *http.Request, contentType, body string) {
	if !method(w, r, http.MethodGet) {
		return
	}
	webmailSecurityHeaders(w)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

func renderWebmailApp(pageStarted time.Time, release string) string {
	templateStarted := time.Now()
	var body strings.Builder
	body.Grow(len(webmailAppHTML) + 320)
	body.WriteString(webmailAppHTML)
	templateMilliseconds := time.Since(templateStarted).Milliseconds()
	pageMilliseconds := time.Since(pageStarted).Milliseconds()
	body.WriteString(`  <footer class="gotth-footer" aria-label="Application information">
    <span>Powered by <strong class="gotth-footer-product">GOTTH Mail</strong></span>
    <span>Version: <strong>`)
	body.WriteString(html.EscapeString(release))
	body.WriteString(`</strong></span>
    <span>Page: <strong>`)
	body.WriteString(strconv.FormatInt(pageMilliseconds, 10))
	body.WriteString(`ms</strong></span>
    <span>Template: <strong>`)
	body.WriteString(strconv.FormatInt(templateMilliseconds, 10))
	body.WriteString(`ms</strong></span>
  </footer>
</body>
</html>`)
	return body.String()
}

func renderWebmailMessageFragment(message webmail.Message, folder string) (string, error) {
	contextJSON, err := json.Marshal(struct {
		ID, From, To, Cc, Subject string
		Date                      time.Time
		Flags                     []string
		Attachments               []webmail.Attachment
	}{
		ID:          message.ID,
		From:        message.From,
		To:          message.To,
		Cc:          message.Cc,
		Subject:     message.Subject,
		Date:        message.Date,
		Flags:       message.Flags,
		Attachments: message.Attachments,
	})
	if err != nil {
		return "", err
	}
	var body strings.Builder
	body.Grow(len(message.BodyText) + len(contextJSON) + 1024)
	body.WriteString(`<!--gotth-mail-message-fragment--><div class="pane-heading mobile-heading"><button type="button" data-mobile-back="messages">Messages</button><h1>Message</h1></div><div id="empty-reader" class="empty-state" hidden><strong>Select a message</strong><span>Message content appears here.</span></div><div id="message-reader"><header class="message-header"><h2 id="message-subject">`)
	body.WriteString(html.EscapeString(message.Subject))
	body.WriteString(`</h2><dl><dt>From</dt><dd id="message-from">`)
	body.WriteString(html.EscapeString(message.From))
	body.WriteString(`</dd><dt>To</dt><dd id="message-to">`)
	body.WriteString(html.EscapeString(message.To))
	body.WriteString(`</dd><dt>CC</dt><dd id="message-cc">`)
	body.WriteString(html.EscapeString(message.Cc))
	body.WriteString(`</dd><dt>Received</dt><dd id="message-date" data-message-date="`)
	body.WriteString(html.EscapeString(message.Date.Format(time.RFC3339)))
	body.WriteString(`">`)
	body.WriteString(html.EscapeString(message.Date.Format(time.RFC3339)))
	body.WriteString(`</dd></dl></header><pre id="message-body" class="message-body">`)
	messageBody := message.BodyText
	if messageBody == "" {
		// Client.Read stores HTML mail as an already-escaped text rendering. Keep
		// that representation intact so the server fragment matches the previous
		// textContent behavior and never interprets message markup.
		messageBody = message.BodyHTML
	}
	body.WriteString(html.EscapeString(messageBody))
	body.WriteString(`</pre>`)
	if len(message.Attachments) > 0 {
		body.WriteString(`<section id="attachment-section"><h3>Attachments</h3><ul id="attachment-list">`)
		for index, attachment := range message.Attachments {
			query := url.Values{"folder": {folder}, "id": {message.ID}, "index": {strconv.Itoa(index)}}
			body.WriteString(`<li><a href="/api/v1/webmail/attachment?`)
			body.WriteString(html.EscapeString(query.Encode()))
			body.WriteString(`">`)
			name := attachment.Filename
			if name == "" {
				name = "attachment"
			}
			body.WriteString(html.EscapeString(name))
			body.WriteString(` (`)
			body.WriteString(strconv.FormatInt(attachment.Size, 10))
			body.WriteString(` bytes)</a></li>`)
		}
		body.WriteString(`</ul></section>`)
	}
	body.WriteString(`<template id="message-context">`)
	body.Write(contextJSON)
	body.WriteString(`</template></div>`)
	return body.String(), nil
}

const webmailAppHTML = `<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="htmx-config" content='{"allowEval":false,"allowScriptTags":false,"historyCacheSize":0,"historyEnabled":false,"includeIndicatorStyles":false,"selfRequestsOnly":true}'>
  <title>GOTTH Mail</title>
  <link rel="stylesheet" href="/webmail/assets/app.css">
  <script src="/webmail/assets/trusted-html.js" defer></script>
  <script src="/webmail/assets/htmx-2.0.10.min.js" defer></script>
  <script src="/webmail/assets/app.js" defer></script>
</head>
<body data-mobile-view="folders">
  <a class="skip-link" href="#message-list">Skip to messages</a>
  <header class="topbar">
    <div class="brand" aria-label="GOTTH Mail"><span class="brand-mark" aria-hidden="true">G</span><strong>GOTTH Mail</strong></div>
    <div class="account"><span id="account-label">Not signed in</span><span id="signature-label" class="signature"></span></div>
    <div class="top-actions">
      <button id="theme-toggle" class="quiet" type="button" aria-label="Toggle light and dark theme">Theme</button>
      <a id="sign-in" class="button-link" href="/api/v1/oidc/login?mode=redirect&amp;redirect=/webmail">Sign in</a>
    </div>
  </header>

  <nav class="commandbar" aria-label="Mail commands">
    <div class="command-actions">
      <button type="button" data-command="new" class="primary">New message</button>
      <button type="button" data-command="reply" disabled>Reply</button>
      <button type="button" data-command="reply_all" disabled>Reply all</button>
      <button type="button" data-command="forward" disabled>Forward</button>
      <button type="button" data-command="delete" disabled>Delete</button>
      <button type="button" data-command="move" disabled>Move</button>
      <button type="button" data-command="read" disabled>Mark read</button>
      <button type="button" data-command="unread" disabled>Mark unread</button>
      <button type="button" data-command="flag" disabled>Flag</button>
      <button type="button" data-command="drafts">Saved drafts</button>
      <button type="button" data-command="refresh">Refresh</button>
      <button type="button" data-command="rules" disabled title="Rules are unavailable because no Sieve service is configured">Rules unavailable</button>
    </div>
    <form id="search-form" role="search">
      <label class="sr-only" for="search-input">Search current folder</label>
      <input id="search-input" name="q" type="search" maxlength="200" placeholder="Search this folder">
      <button type="submit">Search</button>
    </form>
  </nav>

  <section class="viewbar" aria-label="Reading pane settings">
    <label>Reading pane
      <select id="pane-placement">
        <option value="right">Right</option>
        <option value="below">Below</option>
        <option value="off">Off</option>
      </select>
    </label>
    <label>Folder width <input id="folder-width" type="range" min="180" max="360" step="10" value="240"></label>
    <label>List width <input id="list-width" type="range" min="320" max="720" step="20" value="440"></label>
  </section>

  <main id="mail-app" class="mail-app pane-right">
    <aside id="folder-pane" class="folder-pane" aria-label="Mail folders">
      <div class="pane-heading"><h1>Folders</h1></div>
      <div id="folder-list" role="listbox" aria-label="Folders" tabindex="0"></div>
      <div class="quota" aria-label="Mailbox quota"><div><span>Storage</span><span id="quota-text">Unavailable</span></div><progress id="quota-progress" max="100" value="0">0%</progress></div>
    </aside>

    <section id="list-pane" class="list-pane" aria-label="Message list">
      <div class="pane-heading mobile-heading"><button type="button" data-mobile-back="folders">Folders</button><h1 id="folder-title">Inbox</h1></div>
      <div class="list-columns" role="row">
        <button type="button" data-sort="From" aria-sort="none">From</button>
        <button type="button" data-sort="Subject" aria-sort="none">Subject</button>
        <button type="button" data-sort="Date" aria-sort="descending">Received</button>
      </div>
      <div id="message-list" role="listbox" aria-label="Messages" tabindex="0" aria-busy="true"></div>
      <button id="load-more" type="button" hidden>Load more</button>
    </section>

    <article id="reader-pane" class="reader-pane" aria-label="Reading pane" tabindex="-1">
      <div class="pane-heading mobile-heading"><button type="button" data-mobile-back="messages">Messages</button><h1>Message</h1></div>
      <div id="empty-reader" class="empty-state"><strong>Select a message</strong><span>Mail content is rendered as conservative text. Remote images and active HTML stay blocked.</span></div>
      <div id="message-reader" hidden>
        <header class="message-header">
          <h2 id="message-subject"></h2>
          <dl><dt>From</dt><dd id="message-from"></dd><dt>To</dt><dd id="message-to"></dd><dt>CC</dt><dd id="message-cc"></dd><dt>Received</dt><dd id="message-date"></dd></dl>
        </header>
        <pre id="message-body" class="message-body"></pre>
        <section id="attachment-section" hidden><h3>Attachments</h3><ul id="attachment-list"></ul></section>
      </div>
    </article>
  </main>

  <div id="context-menu" class="context-menu" role="menu" hidden>
    <button role="menuitem" type="button" data-command="reply">Reply</button>
    <button role="menuitem" type="button" data-command="reply_all">Reply all</button>
    <button role="menuitem" type="button" data-command="forward">Forward</button>
    <button role="menuitem" type="button" data-command="read">Mark read</button>
    <button role="menuitem" type="button" data-command="flag">Flag</button>
    <button role="menuitem" type="button" data-command="delete">Delete</button>
  </div>

  <dialog id="composer" aria-labelledby="composer-title">
    <form id="compose-form">
      <header><h2 id="composer-title">New message</h2><button id="close-compose" type="button" aria-label="Close composer">Close</button></header>
      <input id="compose-draft-id" type="hidden">
      <input id="compose-reply-to" type="hidden"><input id="compose-forward-of" type="hidden">
      <label>From <input id="compose-from" readonly></label>
      <label>To <input id="compose-to" type="email" required autocomplete="off"></label>
      <label>CC <input id="compose-cc" type="text" autocomplete="off" placeholder="Comma-separated addresses"></label>
      <label>BCC <input id="compose-bcc" type="text" autocomplete="off" placeholder="Comma-separated addresses"></label>
      <label>Subject <input id="compose-subject" maxlength="998"></label>
      <label class="body-label">Message <textarea id="compose-body" required></textarea></label>
      <label>Attachments <input id="compose-files" type="file" multiple></label>
      <section id="compose-existing" hidden><strong>Included attachments</strong><ul id="compose-existing-list"></ul></section>
      <p class="compose-note">Every sent message is OpenPGP/MIME signed as <span id="compose-signature"></span>. There is no unsigned-send bypass.</p>
      <footer><button id="save-draft" type="button">Save draft</button><button class="primary" type="submit">Send</button></footer>
    </form>
  </dialog>

  <dialog id="draft-list-dialog" aria-labelledby="draft-list-title">
    <section class="draft-list">
      <header><h2 id="draft-list-title">Saved drafts</h2><button id="close-drafts" type="button">Close</button></header>
      <div id="saved-drafts" role="list"></div>
    </section>
  </dialog>

  <div id="status" role="status" aria-live="polite">Loading webmail…</div>
`

const webmailAppCSS = `
:root{--bg:#f4f6f9;--surface:#fff;--surface-2:#edf2f7;--text:#172033;--muted:#596579;--line:#c6cfdb;--accent:#175ea8;--accent-2:#0d4d8d;--focus:#ffb000;--danger:#a3212b;--folder-width:240px;--list-width:440px;color-scheme:light}
html[data-theme="dark"]{--bg:#111722;--surface:#182230;--surface-2:#202d3d;--text:#eef4fb;--muted:#b0bfd0;--line:#405064;--accent:#69adf0;--accent-2:#8bc2f5;--focus:#ffd166;--danger:#ff8e96;color-scheme:dark}
*{box-sizing:border-box}html,body{height:100%;margin:0}body{background:var(--bg);color:var(--text);font:14px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;grid-template-rows:auto auto auto minmax(0,1fr) auto auto;overflow:hidden}button,input,select,textarea{font:inherit;color:inherit}button,.button-link{border:1px solid var(--line);background:var(--surface);padding:.45rem .7rem;border-radius:3px;text-decoration:none;cursor:pointer}button:hover,.button-link:hover{background:var(--surface-2)}button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,[tabindex]:focus-visible{outline:3px solid var(--focus);outline-offset:1px}button:disabled{opacity:.48;cursor:not-allowed}.primary{background:var(--accent);border-color:var(--accent);color:#fff}.primary:hover{background:var(--accent-2)}.quiet{background:transparent}.skip-link{position:fixed;left:.5rem;top:-4rem;background:var(--surface);padding:.6rem;z-index:50}.skip-link:focus{top:.5rem}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.topbar{height:48px;background:var(--accent-2);color:#fff;display:flex;align-items:center;padding:0 .75rem;gap:1rem}.brand{display:flex;align-items:center;gap:.55rem;font-size:16px}.brand-mark{display:grid;place-items:center;width:28px;height:28px;border:2px solid currentColor;border-radius:4px;font-weight:800}.account{display:flex;gap:.75rem;min-width:0;flex:1}.signature{opacity:.78;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.top-actions{display:flex;align-items:center;gap:.5rem}.topbar .quiet,.topbar .button-link{border-color:#ffffff66;color:#fff}
.commandbar{min-height:46px;display:flex;align-items:center;gap:.35rem;padding:.4rem .6rem;background:var(--surface);border-bottom:1px solid var(--line);overflow:hidden}.command-actions{display:flex;align-items:center;gap:.35rem;min-width:0;overflow-x:auto;overscroll-behavior-inline:contain;scrollbar-gutter:stable}.command-actions button{flex:0 0 auto}.commandbar form{margin-left:auto;display:flex;flex:0 0 250px;min-width:0}.commandbar input{width:100%;min-width:0;border:1px solid var(--line);background:var(--surface);padding:.45rem}.viewbar{display:flex;gap:1.25rem;align-items:center;padding:.25rem .75rem;background:var(--surface-2);border-bottom:1px solid var(--line);color:var(--muted)}.viewbar label{display:flex;align-items:center;gap:.4rem}.viewbar input[type="range"]{width:110px}
.mail-app{min-height:0;display:grid;background:var(--surface)}.pane-right{grid-template-columns:min(var(--folder-width),28vw) min(var(--list-width),42vw) minmax(260px,1fr)}.pane-below{grid-template-columns:min(var(--folder-width),32vw) minmax(0,1fr);grid-template-rows:minmax(220px,46%) minmax(250px,1fr)}.pane-below .folder-pane{grid-row:1/3}.pane-below .reader-pane{grid-column:2;grid-row:2}.pane-off{grid-template-columns:min(var(--folder-width),32vw) minmax(0,1fr)}.pane-off .reader-pane{display:none}.folder-pane,.list-pane,.reader-pane{min-width:0;min-height:0;background:var(--surface);overflow:auto}.folder-pane,.list-pane{border-right:1px solid var(--line)}.pane-heading{height:42px;display:flex;align-items:center;gap:.5rem;padding:0 .75rem;border-bottom:1px solid var(--line);background:var(--surface-2)}.pane-heading h1{font-size:14px;margin:0}.mobile-heading button{display:none}
#folder-list{padding:.35rem}.folder-button{display:flex;width:100%;border:0;background:transparent;justify-content:space-between;text-align:left;padding:.48rem .55rem}.folder-button[aria-selected="true"]{background:var(--accent);color:#fff;font-weight:700}.quota{position:sticky;bottom:0;background:var(--surface);border-top:1px solid var(--line);padding:.7rem}.quota div{display:flex;justify-content:space-between;color:var(--muted);font-size:12px}.quota progress{width:100%;accent-color:var(--accent)}
.list-columns{height:34px;display:grid;grid-template-columns:1fr 2fr 110px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);z-index:2}.list-columns button{border:0;border-right:1px solid var(--line);border-radius:0;text-align:left;padding:.3rem .5rem;background:var(--surface-2);font-size:12px;font-weight:700}.message-row{width:100%;display:grid;grid-template-columns:1fr 2fr 110px;gap:0;border:0;border-bottom:1px solid var(--line);border-radius:0;background:var(--surface);padding:0;text-align:left;min-height:48px}.message-row>span{padding:.42rem .5rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.message-row[aria-selected="true"]{box-shadow:inset 4px 0 var(--accent);background:var(--surface-2)}.message-row.unread{font-weight:750}.message-row.flagged .subject:before{content:"Flagged · ";color:var(--danger)}.message-row.has-attachment .subject:after{content:" · Attachment";font-size:11px;color:var(--muted)}#load-more{margin:.6rem}
.reader-pane{max-width:100%;padding-bottom:2rem}.empty-state{height:100%;display:grid;place-content:center;text-align:center;gap:.5rem;color:var(--muted);padding:2rem}.empty-state strong{font-size:18px;color:var(--text)}.message-header{padding:1rem 1.2rem;border-bottom:1px solid var(--line)}.message-header h2{margin:0 0 .8rem;font-size:20px;overflow-wrap:anywhere}.message-header dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.2rem .65rem;margin:0}.message-header dt{font-weight:700}.message-header dd{min-width:0;margin:0;overflow-wrap:anywhere}.message-body{max-width:100%;margin:0;padding:1.2rem;white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}.reader-pane h3,#attachment-list{margin-left:1.2rem;margin-right:1.2rem}
.context-menu{position:fixed;z-index:30;min-width:150px;background:var(--surface);border:1px solid var(--line);box-shadow:0 8px 24px #0004;padding:.25rem}.context-menu button{display:block;width:100%;border:0;text-align:left}
dialog{width:min(760px,calc(100vw - 2rem));height:min(720px,calc(100vh - 2rem));border:1px solid var(--line);background:var(--surface);color:var(--text);padding:0;box-shadow:0 18px 60px #0007}dialog::backdrop{background:#08111dcc}#compose-form{height:100%;display:grid;grid-template-rows:auto repeat(5,auto) minmax(180px,1fr) auto auto auto;gap:.5rem;padding:1rem}#compose-form header,#compose-form footer{display:flex;justify-content:space-between;align-items:center}#compose-form h2{margin:0}#compose-form label{display:grid;grid-template-columns:76px 1fr;align-items:center;gap:.5rem}#compose-form input,#compose-form textarea{border:1px solid var(--line);background:var(--surface);padding:.45rem}.body-label{min-height:0;align-items:stretch!important}.body-label textarea{resize:none}.compose-note{color:var(--muted);font-size:12px;margin:.25rem 0}#compose-form footer{justify-content:flex-end;gap:.5rem}
.draft-list{padding:1rem}.draft-list header{display:flex;justify-content:space-between;align-items:center}.draft-list h2{margin:0}.draft-list button[role="listitem"]{display:grid;width:100%;grid-template-columns:1fr 2fr auto;text-align:left;margin-top:.4rem}.draft-list .empty-state{height:auto}.draft-state{color:var(--muted)}#compose-existing{max-height:90px;overflow:auto;color:var(--muted)}#compose-existing ul{margin:.25rem 0}
#status{min-height:28px;padding:.35rem .75rem;background:var(--surface-2);border-top:1px solid var(--line);color:var(--muted)}#status.error{color:var(--danger);font-weight:700}
.gotth-footer{min-height:104px;display:flex;align-items:center;justify-content:flex-start;gap:.5rem 1.25rem;flex-wrap:wrap;padding:1.4rem clamp(1rem,10vw,7.5rem);background:#050817;border-top:1px solid #262b3b;color:#9da8bd}.gotth-footer strong{color:#f4f6fb}.gotth-footer .gotth-footer-product{color:#f28b8f}
@media(max-width:1024px){body{grid-template-rows:auto auto minmax(0,1fr) auto auto}.viewbar{display:none}.topbar{height:auto;min-height:48px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.35rem .75rem;padding-block:.45rem}.account{grid-column:1/-1;grid-row:2;min-width:0}.account #account-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.signature{display:none}.top-actions{grid-column:2;grid-row:1}.commandbar{min-height:0;display:grid;grid-template-columns:minmax(0,1fr);gap:.35rem;padding:.35rem}.command-actions{width:100%}.commandbar form{margin:0;display:flex;flex-basis:auto;width:100%}.mail-app,.pane-right,.pane-below,.pane-off{display:block}.folder-pane,.list-pane,.reader-pane{width:100%;height:100%;border:0}.mobile-heading button{display:inline-block}.list-columns{grid-template-columns:minmax(0,1fr) minmax(0,1.5fr) 84px}.message-row{grid-template-columns:minmax(0,1fr) minmax(0,1.5fr) 84px;min-height:52px}body[data-mobile-view="folders"] .list-pane,body[data-mobile-view="folders"] .reader-pane{display:none}body[data-mobile-view="messages"] .folder-pane,body[data-mobile-view="messages"] .reader-pane{display:none}body[data-mobile-view="reader"] .folder-pane,body[data-mobile-view="reader"] .list-pane{display:none}.commandbar button{min-height:40px}.folder-button{min-height:44px}dialog{inset:0;width:100%;height:100%;max-width:none;max-height:none;margin:0}#compose-form{height:auto;min-height:100%;overflow:auto;grid-template-rows:auto repeat(5,auto) minmax(160px,1fr) auto auto auto}#compose-form label{grid-template-columns:1fr;gap:.15rem}.body-label textarea{min-height:10rem}.draft-list button[role="listitem"]{grid-template-columns:1fr;gap:.2rem}.gotth-footer{min-height:72px;padding:.75rem 1rem;font-size:12px}}
@media(max-width:380px){.brand strong{font-size:14px}.topbar{padding-inline:.5rem}.list-columns,.message-row{grid-template-columns:minmax(0,1fr) minmax(0,1.35fr) 72px}.message-row>span,.list-columns button{padding-inline:.35rem}.gotth-footer{column-gap:.8rem}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
`

const webmailTrustedHTMLJS = `(function(){
'use strict';
if(!window.trustedTypes)return;
var prefix='<body><template class="internal-htmx-wrapper">';
var suffix='</template></body>';
var marker='<!--gotth-mail-message-fragment-->';
window.trustedTypes.createPolicy('default',{createHTML:function(value){
  value=String(value);
  if(!value.startsWith(prefix+marker)||!value.endsWith(suffix))throw new TypeError('Rejected untrusted HTMX fragment');
  return value;
}});
})();
`

const webmailAppJS = `
(function(){
'use strict';
var state={mailbox:'',fingerprint:'',folder:'INBOX',folders:[],folderDetails:[],messages:[],selected:null,next:'',sort:'Date',direction:-1,context:null,composeAttachments:[]};
function byId(id){return document.getElementById(id)}
function cookie(name){var prefix=name+'=';var parts=document.cookie.split(';');for(var i=0;i<parts.length;i++){var part=parts[i].trim();if(part.indexOf(prefix)===0)return decodeURIComponent(part.slice(prefix.length))}return ''}
function setStatus(text,error){var el=byId('status');el.textContent=text;el.classList.toggle('error',!!error)}
async function api(path,options){options=options||{};options.credentials='same-origin';options.headers=options.headers||{};if(options.method&&options.method!=='GET'){options.headers['Content-Type']='application/json';var csrf=cookie('gotth_mail_csrf');if(csrf)options.headers['X-CSRF-Token']=csrf}var response=await fetch(path,options);if(!response.ok){var text=(await response.text()).trim();var error=new Error(text||('Request failed ('+response.status+')'));error.status=response.status;throw error}var type=response.headers.get('content-type')||'';return type.indexOf('application/json')>=0?response.json():response.text()}
function encode(value){return encodeURIComponent(value)}
function hasFlag(message,flag){return (message.Flags||[]).some(function(value){return value.toLowerCase()===flag.toLowerCase()})}
function displayDate(value){var date=new Date(value);return isNaN(date.getTime())?value:date.toLocaleString()}
function selectedSummary(){return state.messages.find(function(message){return message.ID===state.selected})||null}
function updateCommands(){var active=!!state.selected;document.querySelectorAll('[data-command]').forEach(function(button){var command=button.dataset.command;if(['reply','reply_all','forward','delete','move','read','unread','flag'].indexOf(command)>=0)button.disabled=!active})}
function selectFolder(folder){state.folder=folder;state.selected=null;state.next='';document.querySelectorAll('.folder-button').forEach(function(button){button.setAttribute('aria-selected',String(button.dataset.folder===folder))});byId('folder-title').textContent=folder;document.body.dataset.mobileView='messages';loadMessages(false)}
function renderFolders(){var list=byId('folder-list');list.replaceChildren();state.folders.forEach(function(folder){var button=document.createElement('button');button.type='button';button.className='folder-button';button.dataset.folder=folder;button.setAttribute('role','option');button.setAttribute('aria-selected',String(folder===state.folder));var name=document.createElement('span');name.textContent=folder;button.appendChild(name);var detail=state.folderDetails.find(function(item){return item.Name===folder});if(detail&&detail.Unread>0){var count=document.createElement('span');count.textContent=detail.Unread+' unread';count.setAttribute('aria-label',detail.Unread+' unread messages');button.appendChild(count)}button.addEventListener('click',function(){selectFolder(folder)});list.appendChild(button)})}
async function loadFolders(){var result=await api('/api/v1/webmail/folders');state.folders=result.folders||[];state.folderDetails=result.folder_details||[];if(state.folders.indexOf(state.folder)<0&&state.folders.length)state.folder=state.folders[0];byId('folder-title').textContent=state.folder;renderFolders()}
async function loadQuota(){var result=await api('/api/v1/webmail/quota');var used=result.used_bytes||0;var limit=result.limit_bytes||0;var percent=limit?Math.min(100,Math.round(used*100/limit)):0;byId('quota-progress').value=percent;byId('quota-text').textContent=(used/1048576).toFixed(1)+' / '+(limit/1048576).toFixed(1)+' MB'}
function sortedMessages(){var messages=state.messages.slice();var key=state.sort;messages.sort(function(a,b){var av=String(a[key]||'').toLowerCase();var bv=String(b[key]||'').toLowerCase();return av<bv?-state.direction:av>bv?state.direction:0});return messages}
function renderMessages(){var list=byId('message-list');list.replaceChildren();sortedMessages().forEach(function(message){var row=document.createElement('button');row.type='button';row.className='message-row';if(!hasFlag(message,'\\Seen'))row.classList.add('unread');if(hasFlag(message,'\\Flagged'))row.classList.add('flagged');if(message.HasAttachments)row.classList.add('has-attachment');row.dataset.id=message.ID;row.setAttribute('role','option');row.setAttribute('aria-selected',String(message.ID===state.selected));row.setAttribute('hx-get','/webmail/fragments/message?folder='+encode(state.folder)+'&id='+encode(message.ID));row.setAttribute('hx-target','#reader-pane');row.setAttribute('hx-swap','innerHTML');row.setAttribute('hx-sync','#reader-pane:replace');var from=document.createElement('span');from.className='from';from.textContent=message.From||'(unknown sender)';var subject=document.createElement('span');subject.className='subject';subject.textContent=message.Subject||'(no subject)';var date=document.createElement('span');date.className='date';date.textContent=displayDate(message.Date);row.append(from,subject,date);row.addEventListener('click',function(){state.selected=message.ID;document.querySelectorAll('.message-row').forEach(function(item){item.setAttribute('aria-selected',String(item.dataset.id===state.selected))});updateCommands();setStatus('Opening message…',false)});row.addEventListener('contextmenu',function(event){event.preventDefault();state.selected=message.ID;renderMessages();openContext(event.clientX,event.clientY)});row.addEventListener('keydown',function(event){if(event.key==='F10'&&event.shiftKey){event.preventDefault();state.selected=message.ID;renderMessages();var box=row.getBoundingClientRect();openContext(box.left+20,box.top+20)}});list.appendChild(row);if(window.htmx)window.htmx.process(row)});list.setAttribute('aria-busy','false');byId('load-more').hidden=!state.next;updateCommands()}
async function loadMessages(append){try{byId('message-list').setAttribute('aria-busy','true');var query='?folder='+encode(state.folder)+'&limit=50';var search=byId('search-input').value.trim();if(search)query+='&q='+encode(search);if(append&&state.next)query+='&cursor='+encode(state.next);var result=await api('/api/v1/webmail/messages'+query);state.messages=append?state.messages.concat(result.Messages||[]):(result.Messages||[]);state.next=result.NextCursor||'';renderMessages();setStatus(state.messages.length+' messages in '+state.folder,false)}catch(error){handleError(error)}}
function setComposeAttachments(attachments){state.composeAttachments=(attachments||[]).slice();var section=byId('compose-existing');var list=byId('compose-existing-list');list.replaceChildren();section.hidden=state.composeAttachments.length===0;state.composeAttachments.forEach(function(attachment,index){var item=document.createElement('li');var label=document.createElement('span');label.textContent=(attachment.Filename||'attachment')+' ('+(attachment.Size||0)+' bytes)';var remove=document.createElement('button');remove.type='button';remove.textContent='Remove';remove.setAttribute('aria-label','Remove '+(attachment.Filename||'attachment'));remove.addEventListener('click',function(){var next=state.composeAttachments.slice();next.splice(index,1);setComposeAttachments(next)});item.append(label,' ',remove);list.appendChild(item)})}
async function messageAction(action,destination,quiet){if(!state.selected)return;try{var body={action:action};if(destination)body.destination=destination;await api('/api/v1/webmail/message?folder='+encode(state.folder)+'&id='+encode(state.selected),{method:'POST',body:JSON.stringify(body)});var removesFromFolder=action==='delete'||action==='move';if(removesFromFolder){state.selected=null;state.context=null;byId('message-reader').hidden=true;byId('empty-reader').hidden=false}var refreshes=[loadMessages(false),loadFolders()];if(action==='delete')refreshes.push(loadQuota());await Promise.all(refreshes);if(!quiet)setStatus('Message action completed',false)}catch(error){handleError(error)}}
function addresses(value){return value.split(',').map(function(item){return item.trim()}).filter(Boolean)}
function bareAddress(value){var match=String(value||'').match(/<([^<>]+)>/);return match?match[1]:String(value||'').trim()}
function extractAddresses(value){return (String(value||'').match(/[A-Z0-9.!#$%&'*+\/=?^_{|}~-]+@[A-Z0-9.-]+/gi)||[]).map(function(item){return item.toLowerCase()})}
function showComposer(){var dialog=byId('composer');if(dialog.showModal)dialog.showModal();else dialog.setAttribute('open','');byId('compose-to').focus()}
function openComposer(mode){var message=state.context;var replying=mode==='reply'||mode==='reply_all';var related=replying||mode==='forward';byId('composer-title').textContent=mode==='reply_all'?'Reply all':mode==='reply'?'Reply':mode==='forward'?'Forward':'New message';byId('compose-draft-id').value='';byId('compose-from').value=state.mailbox;var recipients=[];if(replying&&message){recipients=extractAddresses(message.From);if(mode==='reply_all')recipients=recipients.concat(extractAddresses(message.To),extractAddresses(message.Cc));recipients=recipients.filter(function(item,index,array){return item!==state.mailbox.toLowerCase()&&array.indexOf(item)===index})}byId('compose-to').value=recipients[0]||'';byId('compose-cc').value=recipients.slice(1).join(', ');byId('compose-bcc').value='';byId('compose-subject').value=related&&message?(replying?'Re: ':'Fwd: ')+String(message.Subject||''):'';byId('compose-body').value=message&&mode==='forward'?('\n\n--- Forwarded message ---\n'+(message.BodyText||message.BodyHTML||'')):message&&replying?('\n\nOn '+displayDate(message.Date)+', '+message.From+' wrote:\n'+String(message.BodyText||'').split('\n').map(function(line){return '> '+line}).join('\n')):'';byId('compose-reply-to').value=replying&&message?message.ID:'';byId('compose-forward-of').value=mode==='forward'&&message?message.ID:'';byId('compose-files').value='';setComposeAttachments(mode==='forward'&&message?message.Attachments:[]);showComposer()}
async function fileAttachments(){var files=Array.prototype.slice.call(byId('compose-files').files||[]);var total=files.reduce(function(sum,file){return sum+file.size},0);if(total>700000)throw new Error('Attachments are limited to 700 KB per draft in this alpha');return Promise.all(files.map(function(file){return new Promise(function(resolve,reject){var reader=new FileReader();reader.onerror=function(){reject(new Error('Unable to read attachment'))};reader.onload=function(){var value=String(reader.result||'');resolve({Filename:file.name,ContentType:file.type||'application/octet-stream',Size:file.size,Content:value.split(',')[1]||''})};reader.readAsDataURL(file)})}))}
async function saveDraft(send){try{setStatus(send?'Signing and sending…':'Saving draft…',false);var attachments=state.composeAttachments.concat(await fileAttachments());var total=attachments.reduce(function(sum,attachment){return sum+(attachment.Size||0)},0);if(total>700000)throw new Error('Attachments are limited to 700 KB per draft in this alpha');var draft={From:state.mailbox,To:byId('compose-to').value.trim(),Cc:addresses(byId('compose-cc').value),Bcc:addresses(byId('compose-bcc').value),Subject:byId('compose-subject').value,Body:byId('compose-body').value,ReplyTo:byId('compose-reply-to').value,ForwardOf:byId('compose-forward-of').value,SigningFingerprint:state.fingerprint,Attachments:attachments};var draftID=byId('compose-draft-id').value;var saved=await api(draftID?'/api/v1/webmail/drafts/'+encode(draftID):'/api/v1/webmail/drafts',{method:draftID?'PUT':'POST',body:JSON.stringify(draft)});if(send){await api('/api/v1/webmail/drafts/'+encode(saved.ID)+'/submit',{method:'POST',body:'{}'})}byId('composer').close();if(send)await loadMessages(false);setStatus(send?'Message sent with exact-sender OpenPGP signature':'Draft saved',false)}catch(error){handleError(error)}}
function editDraft(draft){byId('draft-list-dialog').close();byId('composer-title').textContent='Edit draft';byId('compose-draft-id').value=draft.ID;byId('compose-from').value=state.mailbox;byId('compose-to').value=draft.To||'';byId('compose-cc').value=(draft.Cc||[]).join(', ');byId('compose-bcc').value=(draft.Bcc||[]).join(', ');byId('compose-subject').value=draft.Subject||'';byId('compose-body').value=draft.Body||'';byId('compose-reply-to').value=draft.ReplyTo||'';byId('compose-forward-of').value=draft.ForwardOf||'';byId('compose-files').value='';setComposeAttachments(draft.Attachments||[]);showComposer()}
async function openDrafts(){try{var result=await api('/api/v1/webmail/drafts');var list=byId('saved-drafts');list.replaceChildren();var drafts=result.drafts||[];if(!drafts.length){var empty=document.createElement('p');empty.className='empty-state';empty.textContent='No saved drafts';list.appendChild(empty)}drafts.forEach(function(draft){var button=document.createElement('button');button.type='button';button.setAttribute('role','listitem');var to=document.createElement('span');to.textContent=draft.To||'(no recipient)';var subject=document.createElement('span');subject.textContent=draft.Subject||'(no subject)';var status=document.createElement('span');status.className='draft-state';status.textContent=draft.State||'draft';button.append(to,subject,status);button.addEventListener('click',async function(){try{editDraft(await api('/api/v1/webmail/drafts/'+encode(draft.ID)))}catch(error){handleError(error)}});list.appendChild(button)});var dialog=byId('draft-list-dialog');if(dialog.showModal)dialog.showModal();else dialog.setAttribute('open','')}catch(error){handleError(error)}}
function openContext(x,y){var menu=byId('context-menu');menu.hidden=false;menu.style.left=Math.min(x,window.innerWidth-170)+'px';menu.style.top=Math.min(y,window.innerHeight-210)+'px';var first=menu.querySelector('button');if(first)first.focus()}
function closeContext(){byId('context-menu').hidden=true}
async function runCommand(command){closeContext();if(command==='new')return openComposer('new');if(command==='reply')return openComposer('reply');if(command==='reply_all')return openComposer('reply_all');if(command==='forward')return openComposer('forward');if(command==='drafts')return openDrafts();if(command==='delete'){if(confirm('Delete the selected message?'))return messageAction('delete')}if(command==='move'){var destination=prompt('Move to folder:',state.folders.find(function(folder){return folder!==state.folder})||'');if(destination)return messageAction('move',destination)}if(command==='read')return messageAction('mark_read');if(command==='unread')return messageAction('mark_unread');if(command==='flag')return messageAction(hasFlag(selectedSummary()||{},'\\Flagged')?'unflag':'flag');if(command==='refresh')return Promise.all([loadMessages(false),loadFolders(),loadQuota()])}
function handleError(error){if(error.status===401){byId('sign-in').hidden=false;setStatus('Sign in with your bound GOTTH Mail account to use webmail.',true)}else setStatus(error.message||'Webmail request failed',true)}
function handleHTMXError(event){var xhr=event.detail&&event.detail.xhr;var error=new Error(xhr&&xhr.responseText?xhr.responseText.trim():'Unable to open message');if(xhr)error.status=xhr.status;handleError(error)}
function applyPreferences(){var theme=localStorage.getItem('gotth-mail-theme')||'light';document.documentElement.dataset.theme=theme;var placement=localStorage.getItem('gotth-mail-pane')||'right';byId('pane-placement').value=placement;setPane(placement);['folder','list'].forEach(function(name){var input=byId(name+'-width');var saved=localStorage.getItem('gotth-mail-'+name+'-width');if(saved)input.value=saved;document.documentElement.style.setProperty('--'+name+'-width',input.value+'px')})}
function setPane(value){var app=byId('mail-app');app.classList.remove('pane-right','pane-below','pane-off');app.classList.add('pane-'+value);localStorage.setItem('gotth-mail-pane',value)}
function bind(){document.querySelectorAll('[data-command]').forEach(function(button){button.addEventListener('click',function(){runCommand(button.dataset.command)})});document.querySelectorAll('[data-sort]').forEach(function(button){button.addEventListener('click',function(){var key=button.dataset.sort;if(state.sort===key)state.direction*=-1;else{state.sort=key;state.direction=key==='Date'?-1:1}document.querySelectorAll('[data-sort]').forEach(function(item){item.setAttribute('aria-sort',item.dataset.sort===state.sort?(state.direction>0?'ascending':'descending'):'none')});renderMessages()})});byId('search-form').addEventListener('submit',function(event){event.preventDefault();loadMessages(false)});byId('load-more').addEventListener('click',function(){loadMessages(true)});byId('compose-form').addEventListener('submit',function(event){event.preventDefault();saveDraft(true)});byId('save-draft').addEventListener('click',function(){saveDraft(false)});byId('close-compose').addEventListener('click',function(){byId('composer').close()});byId('close-drafts').addEventListener('click',function(){byId('draft-list-dialog').close()});byId('theme-toggle').addEventListener('click',function(){var theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;localStorage.setItem('gotth-mail-theme',theme)});byId('pane-placement').addEventListener('change',function(event){setPane(event.target.value)});['folder','list'].forEach(function(name){byId(name+'-width').addEventListener('input',function(event){document.documentElement.style.setProperty('--'+name+'-width',event.target.value+'px');localStorage.setItem('gotth-mail-'+name+'-width',event.target.value)})});document.addEventListener('click',function(event){var back=event.target.closest('[data-mobile-back]');if(back){document.body.dataset.mobileView=back.dataset.mobileBack;var selected=document.querySelector('.message-row[aria-selected="true"]');if(selected)selected.focus()}if(!byId('context-menu').contains(event.target))closeContext()});document.body.addEventListener('htmx:afterSwap',function(event){if(event.detail.target.id!=='reader-pane')return;try{var contextNode=byId('message-context');var context=JSON.parse(contextNode.content.textContent);context.BodyText=byId('message-body').textContent;state.context=context;var date=byId('message-date');if(date)date.textContent=displayDate(date.dataset.messageDate);document.body.dataset.mobileView='reader';byId('reader-pane').focus();setStatus('Opened '+(context.Subject||'message'),false);if(!hasFlag(selectedSummary()||{},'\\Seen'))messageAction('mark_read',null,true)}catch(error){handleError(error)}});document.body.addEventListener('htmx:responseError',handleHTMXError);document.body.addEventListener('htmx:swapError',handleHTMXError);document.addEventListener('keydown',function(event){var tag=(event.target.tagName||'').toLowerCase();if(tag==='input'||tag==='textarea'||tag==='select')return;var rows=Array.prototype.slice.call(document.querySelectorAll('.message-row'));var index=rows.findIndex(function(row){return row.dataset.id===state.selected});if(event.key==='ArrowDown'&&rows.length){event.preventDefault();rows[Math.min(rows.length-1,index+1)].click()}else if(event.key==='ArrowUp'&&rows.length){event.preventDefault();rows[Math.max(0,index<0?0:index-1)].click()}else if(event.key==='n')runCommand('new');else if(event.key==='r'&&state.selected)runCommand('reply');else if(event.key==='f'&&state.selected)runCommand('forward');else if(event.key==='Delete'&&state.selected)runCommand('delete')})}
async function start(){bind();applyPreferences();try{var identity=await api('/api/v1/webmail/identity');state.mailbox=identity.mailbox;state.fingerprint=identity.signing_fingerprint;byId('account-label').textContent=state.mailbox;byId('signature-label').textContent='OpenPGP '+state.fingerprint.slice(-16);byId('compose-signature').textContent=state.mailbox+' · '+state.fingerprint;byId('sign-in').hidden=true;await Promise.all([loadFolders(),loadQuota()]);await loadMessages(false)}catch(error){handleError(error)}}
start();
})();
`
