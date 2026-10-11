package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
// Permission-mode setup adds78 synthetic grant names before the readonly baseline;
// response checks cost O(body+snapshot bytes), with SQL/runtime costs delegated.
// Existing inventory mode remains101 rows and rejects all detail/form bodies.
func runPaginationBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	t.Helper()
	permissionsMode := os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "permissions"
	var grants [3][]string
	var err error
	if permissionsMode {
		var encoded [3]string
		for k := range grants {
			for i := 0; i < 26; i++ {
				grants[k] = append(grants[k], fmt.Sprintf("permissions.g%d.p%02d", k, i))
			}
			data, e := json.Marshal(grants[k])
			acceptanceCheck(t, e)
			encoded[k] = string(data)
		}
		_, err = f.DB.Exec("UPDATE extension_instances SET capabilities_json=$1::jsonb,interfaces_json=$2::jsonb,secret_slots_json=$3::jsonb WHERE instance_id=$4", encoded[0], encoded[1], encoded[2], f.ID)
	} else {
		_, err = f.DB.Exec("INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,lifecycle,health_code,created_at,updated_at) SELECT md5(('browser-page-'||g)::text)::uuid,'gotth-mail','page.entry'||lpad(g::text,3,'0'),'https://github.com/gotthboard/gotth-extension-page','sha256:'||repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),jsonb_build_object('fields',jsonb_build_array()),'stopped','extension.ready',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,100) g")
	}
	acceptanceCheck(t, err)
	var encoding, collate, ctype string
	acceptanceCheck(t, f.DB.QueryRow("SELECT pg_encoding_to_char(encoding),datcollate,datctype FROM pg_database WHERE datname=current_database()").Scan(&encoding, &collate, &ctype))
	t.Logf("pagination fixture encoding=%s collate=%s ctype=%s", encoding, collate, ctype)
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
	wantRows := 101
	if permissionsMode {
		wantRows = 1
	}
	if len(expected) != wantRows {
		t.Fatal("pagination setup cardinality")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	quiet := func(ctx context.Context) error {
		state, e := configurationSnapshot(ctx, f.DB)
		if e != nil || state != before {
			return errors.New("pagination authoritative SQL changed")
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
			http.Error(w, "pagination fixture failed", 500)
		}
		if failure != "" {
			fail(failure)
			return
		}
		if r.Method != "GET" {
			mutations++
			fail("pagination unexpected mutation")
			return
		}
		if r.Header.Get("Authorization") != "" {
			bearers++
			fail("pagination bearer forbidden")
			return
		}
		if r.Host != listener.Addr().String() || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.RawPath != "" || r.Header.Get("HX-Request") != "" {
			fail("pagination unexpected request boundary")
			return
		}
		detail := permissionsMode && r.URL.Path == "/admin/extensions/"+f.ID
		document := r.URL.Path == "/admin/extensions" || detail
		asset := r.URL.Path == "/admin/extensions/assets/tokens.css" || r.URL.Path == "/admin/extensions/assets/inventory.css" || r.URL.Path == "/admin/extensions/assets/inventory.js" || (permissionsMode && r.URL.Path == "/admin/extensions/assets/detail.css")
		favicon := r.URL.Path == "/favicon.ico"
		if !document && !asset && !favicon {
			fail("pagination unexpected path")
			return
		}
		if !document && r.URL.RawQuery != "" {
			fail("pagination asset query")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if e := quiet(ctx); e != nil {
			fail(e.Error())
			return
		}
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, r.WithContext(ctx))
		body := rec.Body.Bytes()
		if len(body) > 1<<20 {
			fail("pagination response size")
			return
		}
		clean := body
		if detail {
			clean = bytes.ReplaceAll(body, []byte(fmt.Sprintf("name=%q value=%q", "csrf_token", f.CSRF)), []byte("expected-csrf"))
		}
		for _, secret := range []string{f.Session, f.CSRF, f.Secret} {
			if secret != "" && bytes.Contains(clean, []byte(secret)) {
				fail("pagination response private leak")
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
				fail("pagination document cache")
				return
			}
		}
		if rec.Code != want {
			fail("pagination status")
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
			fail("pagination transport write")
		}
	})}
	served := make(chan error, 1)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if e := srv.Shutdown(ctx); e != nil {
				t.Error("pagination HTTP shutdown")
				_ = srv.Close()
			}
			if e := <-served; e != nil && e != http.ErrServerClosed {
				t.Error("pagination HTTP serve")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	raw, err := json.Marshal(map[string]any{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": os.Getenv("GOTTH_MAIL_BROWSER_MODE"), "expected": expected, "grants": grants})
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
		t.Errorf("pagination browser failed: %v", runErr)
	}
	if unauth != 1 || pages < 3 || mutations != 0 || bearers != 0 || assets["/admin/extensions/assets/tokens.css"] == 0 || assets["/admin/extensions/assets/inventory.css"] == 0 {
		t.Error("pagination observed request coverage")
	}
	if permissionsMode && assets["/admin/extensions/assets/detail.css"] == 0 {
		t.Error("permissions detail CSS unobserved")
	}
	proof, e := os.ReadFile(filepath.Join(os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"), "proof.json"))
	if e != nil {
		t.Error("pagination safe proof absent")
		return
	}
	for _, secret := range []string{f.Session, f.CSRF, f.Secret} {
		if secret != "" && bytes.Contains(proof, []byte(secret)) {
			t.Error("pagination proof private leak")
		}
	}
	var result struct{ Gate string }
	if json.Unmarshal(proof, &result) != nil || result.Gate != "PASS" {
		t.Error("pagination driver proof not PASS")
	}
	t.Logf("pagination observed GETs=%d unauth=%d mutations=%d bearer=%d; SQL four-table invariant=%t receiver/runtime quiet=%t; auth setup injected", pages, unauth, mutations, bearers, !t.Failed(), !t.Failed())
}
