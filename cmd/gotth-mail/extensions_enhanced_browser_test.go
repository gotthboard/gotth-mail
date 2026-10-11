package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// One test-only workflow; synthetic setup is not a browser mutation.
// Four-table snapshots cost O(total fixture bytes), not a product resource bound.
func runEnhancedPaginationBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	t.Helper()
	_, err := f.DB.Exec("INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,lifecycle,health_code,created_at,updated_at) SELECT md5(('browser-page-'||g)::text)::uuid,'gotth-mail','page.entry'||lpad(g::text,3,'0'),'https://github.com/gotthboard/gotth-extension-page','sha256:'||repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),jsonb_build_object('fields',jsonb_build_array()),'stopped','extension.ready',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,50) g")
	acceptanceCheck(t, err)
	var encoding, collate, ctype string
	acceptanceCheck(t, f.DB.QueryRow("SELECT pg_encoding_to_char(encoding),datcollate,datctype FROM pg_database WHERE datname=current_database()").Scan(&encoding, &collate, &ctype))
	t.Logf("enhanced pagination fixture encoding=%s collate=%s ctype=%s", encoding, collate, ctype)
	// Independent SQL order/membership, never the page service or rendered output.
	rows, err := f.DB.Query("SELECT instance_id::text,extension_id FROM extension_instances WHERE product='gotth-mail' ORDER BY extension_id")
	acceptanceCheck(t, err)
	defer rows.Close()
	var expected [][2]string
	for rows.Next() {
		var item [2]string
		acceptanceCheck(t, rows.Scan(&item[0], &item[1]))
		expected = append(expected, item)
	}
	acceptanceCheck(t, rows.Err())
	acceptanceCheck(t, rows.Close())
	if len(expected) != 51 {
		t.Fatal("enhanced pagination setup cardinality")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	// Predict the exact next epoch BEFORE fixture mutation, independently of rendering.
	after := before
	acceptanceCheck(t, f.DB.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM extension_instances x WHERE extension_id <> 'page.entry001'").Scan(&after[0]))
	phase, hxReads, cursorReads := 0, 0, 0
	expectedCursor := "v1." + base64.RawURLEncoding.EncodeToString([]byte(expected[49][1]))
	t.Logf("enhancement SETUP epochs before=%x expected-after=%x; one selected synthetic row will be removed at first HX read barrier", sha256.Sum256([]byte(before[0])), sha256.Sum256([]byte(after[0])))
	quiet := func(ctx context.Context) error {
		state, e := configurationSnapshot(ctx, f.DB)
		want := before
		if phase == 1 {
			want = after
		}
		if e != nil || state != want {
			return errors.New("enhanced pagination authoritative SQL changed")
		}
		return (&configurationBrowserOracle{f: f}).quiet()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	var mu sync.Mutex
	failure := ""
	pages, unauth, mutations, bearers := 0, 0, 0, 0
	assets := map[string]int{}
	srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func(reason string) {
			if failure == "" {
				failure = reason
			}
			http.Error(w, "enhanced pagination fixture failed", 500)
		}
		if failure != "" {
			fail(failure)
			return
		}
		if r.Method != "GET" {
			mutations++
			fail("enhanced pagination unexpected mutation")
			return
		}
		if r.Header.Get("Authorization") != "" {
			bearers++
			fail("enhanced pagination bearer forbidden")
			return
		}
		if r.Host != listener.Addr().String() || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.RawPath != "" {
			fail("enhanced pagination unexpected request boundary")
			return
		}
		document := r.URL.Path == "/admin/extensions"
		asset := r.URL.Path == "/admin/extensions/assets/tokens.css" || r.URL.Path == "/admin/extensions/assets/inventory.css" || r.URL.Path == "/admin/extensions/assets/inventory.js" || r.URL.Path == "/admin/extensions/assets/htmx-2.0.10.min.js"
		favicon := r.URL.Path == "/favicon.ico"
		if !document && !asset && !favicon {
			fail("enhanced pagination unexpected path")
			return
		}
		if !document && r.URL.RawQuery != "" {
			fail("enhanced pagination asset query")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if e := quiet(ctx); e != nil {
			fail(e.Error())
			return
		}
		hx := r.Header.Get("HX-Request") == "true"
		if document {
			query, e := url.ParseQuery(r.URL.RawQuery)
			if e != nil || len(query["theme"]) != 1 || query.Get("theme") != "light" || len(query["after"]) > 1 {
				fail("enhancement unexpected query")
				return
			}
			for key := range query {
				if key != "theme" && key != "after" {
					fail("enhancement unexpected query key")
					return
				}
			}
			cursor := query.Get("after")
			if cursor != "" && cursor != expectedCursor {
				fail("enhancement unexpected cursor")
				return
			}
			cookie, e := r.Cookie("gotth_mail_session")
			authenticated := e == nil && cookie.Value == f.Session
			if hx {
				if !authenticated || cursor != "" || phase != 0 || hxReads != 0 || cursorReads < 2 {
					fail("enhancement unexpected HX epoch")
					return
				}
				// Explicit fixture SETUP, NOT an application/browser mutation. No new endpoint.
				result, e := f.DB.ExecContext(ctx, "DELETE FROM extension_instances WHERE extension_id='page.entry001'")
				if e != nil {
					fail("enhancement fixture transition failed")
					return
				}
				count, e := result.RowsAffected()
				if e != nil || count != 1 {
					fail("enhancement fixture transition cardinality")
					return
				}
				phase = 1
				hxReads++
				if e = quiet(ctx); e != nil {
					fail(e.Error())
					return
				}
			} else if authenticated && cursor != "" {
				cursorReads++
			}
		} else if r.Header.Get("HX-Request") != "" {
			fail("enhancement unexpected HX asset")
			return
		}
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, r.WithContext(ctx))
		body := rec.Body.Bytes()
		if len(body) > 1<<20 {
			fail("enhanced pagination response size")
			return
		}
		for _, secret := range []string{f.Session, f.CSRF, f.Secret} {
			if secret != "" && bytes.Contains(body, []byte(secret)) {
				fail("enhanced pagination response private leak")
				return
			}
		}
		want := 200
		if favicon {
			want = 404
		}
		if document {
			c, e := r.Cookie("gotth_mail_session")
			if e != nil || c.Value != f.Session {
				want = 401
				unauth++
			} else {
				pages++
			}
			if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
				fail("enhanced pagination document cache")
				return
			}
		}
		if rec.Code != want {
			fail("enhanced pagination status")
			return
		}
		if hx && (rec.Code != 200 || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || !bytes.HasPrefix(body, []byte("<!-- gotth-mail-extension-inventory-v1 -->"))) {
			fail("enhancement marker/MIME/status")
			return
		}
		if asset {
			assets[r.URL.Path]++
		}
		if e := quiet(ctx); e != nil {
			fail(e.Error())
			return
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		if _, e := w.Write(body); e != nil {
			fail("enhanced pagination transport write")
		}
	})}
	served := make(chan error, 1)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if e := srv.Shutdown(ctx); e != nil {
				t.Error("enhanced pagination HTTP shutdown")
				_ = srv.Close()
			}
			if e := <-served; e != nil && e != http.ErrServerClosed {
				t.Error("enhanced pagination HTTP serve")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	raw, err := json.Marshal(map[string]any{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": "enhanced", "expected": expected})
	acceptanceCheck(t, err)
	runctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	cmd := exec.CommandContext(runctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"))
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	runErr := cmd.Run()
	clear(raw)
	shutdown()
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := quiet(ctx); e != nil {
		t.Error(e.Error())
	}
	if failure != "" {
		t.Error(failure)
	}
	if runErr != nil {
		t.Errorf("enhanced pagination browser failed: %v", runErr)
	}
	if phase != 1 || hxReads != 1 || cursorReads < 2 || unauth != 1 || pages < 3 || mutations != 0 || bearers != 0 || assets["/admin/extensions/assets/tokens.css"] == 0 || assets["/admin/extensions/assets/inventory.css"] == 0 {
		t.Error("enhanced pagination observed request coverage")
	}
	proof, e := os.ReadFile(filepath.Join(os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"), "proof.json"))
	if e != nil {
		t.Error("enhanced pagination safe proof absent")
		return
	}
	for _, secret := range []string{f.Session, f.CSRF, f.Secret} {
		if secret != "" && bytes.Contains(proof, []byte(secret)) {
			t.Error("enhanced pagination proof private leak")
		}
	}
	var result struct{ Gate string }
	if json.Unmarshal(proof, &result) != nil || result.Gate != "PASS" {
		t.Error("enhanced pagination driver proof not PASS")
	}
	t.Logf("enhancement SETUP transitions=1 HXreads=%d cursorReads=%d; observed GETs=%d unauth=%d mutations=%d bearer=%d; SQL four-table invariant=%t receiver/runtime quiet=%t; auth setup injected", hxReads, cursorReads, pages, unauth, mutations, bearers, !t.Failed(), !t.Failed())
}
