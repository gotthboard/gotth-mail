package main

// Bounded live-browser gates; routing and delivery admission remain outside this fixture.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
)

type acceptanceBrowserStart struct {
	TestRuntime                                                    *nativeTestRuntime
	Handler                                                        http.Handler
	DB                                                             *sql.DB
	ID, Session, CSRF                                              string
	Current                                                        func() extensionsadmin.Instance
	EmptyRuntime                                                   func()
	Requests                                                       func() int32
	Endpoint, Secret, MasterFile, RuntimeRoot, Executable, ActorID string
}

func TestExtensionAcceptanceBrowserFixture(t *testing.T) {
	driver := os.Getenv("GOTTH_MAIL_BROWSER_DRIVER")
	if driver == "" {
		t.Skip("opt-in live browser equipment; use browser runner")
	}
	for _, name := range []string{"GOTTH_MAIL_ACCEPTANCE_ARCHIVE", "GOTTH_MAIL_ACCEPTANCE_CERT", "GOTTH_MAIL_ACCEPTANCE_KEY", "GOTTH_MAIL_BROWSER_OUTPUT"} {
		if os.Getenv(name) == "" {
			t.Fatalf("required browser prerequisite %s missing", name)
		}
	}
	acceptanceLifecycleDriver(t, false, func(f acceptanceBrowserStart) {
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "connection-test" {
			runConnectionBrowser(t, f, driver)
			return
		}
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "configuration" {
			runConfigurationBrowser(t, f, driver)
			return
		}
		// SQL material remains in memory; only equality is retained, never row contents.
		snapshot := func() []string {
			var state []string
			for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events"} {
				var value string
				err := f.DB.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM " + table + " x").Scan(&value)
				acceptanceCheck(t, err)
				state = append(state, value)
			}
			return state
		}
		before := snapshot()
		initial := f.Current()
		f.EmptyRuntime()
		var authorization, posts atomic.Int32
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		acceptanceCheck(t, err)
		// Cleanup is independent of assertions and registered before Serve or driver launch.
		srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				authorization.Add(1)
				http.Error(w, "browser bearer forbidden", 400)
				return
			}
			if r.Method != "GET" {
				posts.Add(1)
			}
			f.Handler.ServeHTTP(w, r)
		})}
		served := make(chan error, 1)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Errorf("HTTP shutdown: %v", err)
				if e := srv.Close(); e != nil {
					t.Errorf("HTTP close: %v", e)
				}
			}
			if err := <-served; err != nil && err != http.ErrServerClosed {
				t.Errorf("HTTP serve: %v", err)
			}
		})
		go func() { served <- srv.Serve(listener) }()
		mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE")
		if mode == "" {
			mode = "navigation"
		}
		if mode != "navigation" && mode != "audit" {
			t.Fatal("unknown browser mode")
		}
		input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": mode}
		if mode == "audit" {
			// Independent SQL identifiers, not the production reader/exporter output.
			rows, err := f.DB.Query("SELECT id::text, action FROM audit_events WHERE resource_type = 'extension' AND resource_id = $1 ORDER BY timestamp DESC, id DESC LIMIT 1000", f.ID)
			acceptanceCheck(t, err)
			defer rows.Close() // also release rows if an oracle assertion fails
			var expected []map[string]string
			for rows.Next() {
				var id, action string
				acceptanceCheck(t, rows.Scan(&id, &action))
				expected = append(expected, map[string]string{"id": id, "action": action})
			}
			acceptanceCheck(t, rows.Err())
			acceptanceCheck(t, rows.Close())
			if len(expected) == 0 {
				t.Fatal("audit fixture must contain events")
			}
			encoded, err := json.Marshal(expected)
			acceptanceCheck(t, err)
			input["audit_expected"] = string(encoded)
		}
		bootstrap, err := json.Marshal(input)
		acceptanceCheck(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"))
		cmd.Stdin = bytes.NewReader(bootstrap)        // private inherited pipe; no persisted bootstrap file
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // driver emits only whitelist diagnostics
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 20 * time.Second
		err = cmd.Run()
		if !reflect.DeepEqual(before, snapshot()) || !reflect.DeepEqual(initial, f.Current()) {
			t.Error("browser GET changed durable state")
		}
		if authorization.Load() != 0 || posts.Load() != 0 || f.Requests() != 0 {
			t.Error("initial navigation caused bearer injection, mutation, or receiver traffic")
		}
		f.EmptyRuntime()
		if !t.Failed() {
			t.Log("independent oracle: durable state unchanged, no POST/bearer/receiver traffic, runtime empty")
		}
		if err != nil {
			t.Fatalf("browser first gate: %v (see sanitized proof)", err)
		}
		t.Logf("browser %s gate only; lifecycle/matrix remains open", mode)
	})
}

// Configuration observations stay in Go memory. No SQL/secret/error payload is logged.
type configurationBrowserOracle struct {
	f                          acceptanceBrowserStart
	mu                         sync.Mutex
	phase, reloads, posts      int
	failure                    string
	baseline, preview, applied [4]string
	key                        []byte
}

func configurationSnapshot(ctx context.Context, db *sql.DB) ([4]string, error) {
	var state [4]string
	for i, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events"} {
		if err := db.QueryRowContext(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM "+table+" x").Scan(&state[i]); err != nil {
			return state, errors.New("SQL snapshot failed")
		}
	}
	return state, nil
}

func (o *configurationBrowserOracle) quiet() error {
	entries, err := os.ReadDir(o.f.RuntimeRoot)
	if err != nil || len(entries) != 0 {
		return errors.New("runtime not empty")
	}
	processes, err := filepath.Glob("/proc/[0-9]*/exe")
	if err != nil {
		return errors.New("process inventory failed")
	}
	for _, path := range processes {
		target, err := os.Readlink(path)
		if err == nil && (target == o.f.Executable || target == o.f.Executable+" (deleted)") {
			return errors.New("unexpected managed child")
		}
	}
	if o.f.Requests() != 0 {
		return errors.New("unexpected receiver traffic")
	}
	return nil
}

func (o *configurationBrowserOracle) check(ctx context.Context, phase int) error {
	if err := o.quiet(); err != nil {
		return err
	}
	state, err := configurationSnapshot(ctx, o.f.DB)
	if err != nil {
		return err
	}
	if phase == 0 {
		if state != o.baseline {
			return errors.New("GET changed initial SQL")
		}
		return nil
	}
	if phase == 3 {
		if state != o.applied {
			return errors.New("reload changed applied SQL")
		}
		return nil
	}
	var rows [4][]map[string]any
	for i := range state {
		if json.Unmarshal([]byte(state[i]), &rows[i]) != nil {
			return errors.New("SQL snapshot decoding failed")
		}
		if strings.Contains(state[i], o.f.Secret) || strings.Contains(state[i], o.f.Session) || strings.Contains(state[i], o.f.CSRF) {
			return errors.New("SQL plaintext credential leak")
		}
	}
	if len(rows[0]) != 1 || len(rows[2]) != 1 {
		return errors.New("unexpected instance/preview cardinality")
	}
	p := rows[2][0]
	expected := map[string]any{"webhook.endpoint": o.f.Endpoint, "webhook.timeout-seconds": float64(2)}
	if p["instance_id"] != o.f.ID || p["actor_type"] != "oidc_subject" || p["actor_id"] != o.f.ActorID || p["base_revision"] != float64(1) || p["operation"] != "configure" || !reflect.DeepEqual(p["payload_json"], expected) {
		return errors.New("preview SQL binding mismatch")
	}
	if phase == 1 {
		if p["consumed_at"] != nil || state[0] != o.baseline[0] || state[1] != o.baseline[1] || state[3] != o.baseline[3] {
			return errors.New("preview mutated authoritative state")
		}
		o.preview = state
		return nil
	}
	if phase != 2 {
		return errors.New("unknown oracle phase")
	}
	var oldPreview []map[string]any
	if json.Unmarshal([]byte(o.preview[2]), &oldPreview) != nil || len(oldPreview) != 1 || p["consumed_at"] == nil {
		return errors.New("preview not consumed")
	}
	delete(p, "consumed_at")
	delete(oldPreview[0], "consumed_at")
	if !reflect.DeepEqual(p, oldPreview[0]) {
		return errors.New("apply replaced preview")
	}
	instance := rows[0][0]
	if !reflect.DeepEqual(instance["configuration_json"], expected) || instance["configuration_revision"] != float64(2) || instance["tested_revision"] != nil || instance["lifecycle"] != "stopped" || instance["health_code"] != "extension.unknown" || instance["enabled"] != false || instance["routed"] != false {
		return errors.New("applied configuration mismatch")
	}
	var oldInstance []map[string]any
	if json.Unmarshal([]byte(o.baseline[0]), &oldInstance) != nil || len(oldInstance) != 1 {
		return errors.New("invalid baseline instance")
	}
	for _, field := range []string{"configuration_json", "configuration_revision", "tested_revision", "lifecycle", "health_code", "updated_at"} {
		delete(instance, field)
		delete(oldInstance[0], field)
	}
	if !reflect.DeepEqual(instance, oldInstance[0]) {
		return errors.New("apply changed unrelated instance state")
	}
	if len(rows[1]) != 1 {
		return errors.New("secret cardinality mismatch")
	}
	var nonce, ciphertext []byte
	var configured, rotated time.Time
	var slot string
	var version int
	if err := o.f.DB.QueryRowContext(ctx, "SELECT slot, nonce, ciphertext, key_version, configured_at, rotated_at FROM extension_secrets WHERE instance_id=$1", o.f.ID).Scan(&slot, &nonce, &ciphertext, &version, &configured, &rotated); err != nil {
		return errors.New("encrypted secret query failed")
	}
	if slot != "webhook.hmac-key" || len(nonce) != 12 || version != 1 || configured.IsZero() || !configured.Equal(rotated) {
		return errors.New("secret metadata mismatch")
	}
	block, err := aes.NewCipher(o.key)
	if err != nil {
		return errors.New("oracle AES key invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("oracle GCM initialization failed")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(o.f.ID+"\x00"+slot))
	if err != nil || !bytes.Equal(plaintext, []byte(o.f.Secret)) {
		clear(plaintext)
		return errors.New("independent secret decryption mismatch")
	}
	clear(plaintext)
	var oldAudit []map[string]any
	if json.Unmarshal([]byte(o.baseline[3]), &oldAudit) != nil || len(oldAudit) != 1 || len(rows[3]) != 2 {
		return errors.New("audit cardinality mismatch")
	}
	var added map[string]any
	for _, event := range rows[3] {
		if event["id"] == oldAudit[0]["id"] {
			if !reflect.DeepEqual(event, oldAudit[0]) {
				return errors.New("prior audit changed")
			}
		} else if added == nil {
			added = event
		} else {
			return errors.New("prior audit missing")
		}
	}
	if added == nil || added["actor_type"] != "oidc_subject" || added["actor_id"] != o.f.ActorID || added["action"] != "extension.configure" || added["resource_type"] != "extension" || added["resource_id"] != o.f.ID || added["result"] != "success" {
		return errors.New("configuration audit mismatch")
	}
	after, ok := added["after_redacted_json"].(string)
	if !ok {
		return errors.New("audit payload missing")
	}
	var auditValue map[string]any
	if json.Unmarshal([]byte(after), &auditValue) != nil || !reflect.DeepEqual(auditValue, map[string]any{"configuration_revision": float64(2), "configured_secret_slots": "[REDACTED]"}) {
		return errors.New("audit revision/slot mismatch")
	}
	o.applied = state
	return nil
}

// Response completion is the phase barrier; no testing.Fatal or fixture mutation
// occurs on this goroutine. The mutex orders requests and final observations.
func (o *configurationBrowserOracle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fail := func(reason string) {
		if o.failure == "" {
			o.failure = reason
		}
		http.Error(w, "configuration fixture failed", 500)
	}
	if o.failure != "" {
		fail(o.failure)
		return
	}
	if r.Header.Get("Authorization") != "" {
		fail("browser bearer forbidden")
		return
	}
	if o.phase < 0 || o.phase > 2 {
		fail("unknown configuration oracle phase")
		return
	}
	detail := "/admin/extensions/" + o.f.ID
	next := o.phase
	favicon := r.Method == "GET" && r.URL.Path == "/favicon.ico"
	if r.URL.RawQuery != "" || (r.URL.Path != detail && r.URL.Path != "/admin/extensions" && !favicon) {
		fail("unexpected browser route")
		return
	}
	switch r.Method {
	case "GET":
		if o.phase == 1 && !favicon {
			fail("unexpected GET before apply")
			return
		}
	case "POST":
		o.posts++
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.URL.Path != detail || r.ParseForm() != nil {
			fail("unexpected browser POST")
			return
		}
		action := r.PostForm.Get("action")
		if o.phase == 0 && action == "configure-preview" {
			next = 1
		} else if o.phase == 1 && action == "configure-apply" {
			next = 2
		} else {
			fail("unexpected configuration phase/action")
			return
		}
	default:
		fail("unexpected browser method")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	o.f.Handler.ServeHTTP(rec, r.WithContext(ctx))
	body := rec.Body.Bytes()
	if len(body) > 1<<20 || bytes.Contains(body, []byte(o.f.Secret)) || bytes.Contains(body, []byte(o.f.Session)) {
		fail("response secret leak or fixture size exceeded")
		return
	}
	expectedStatus := 200
	if r.URL.Path == "/admin/extensions" {
		expectedStatus = 401
	}
	if favicon {
		expectedStatus = 404
	}
	if rec.Code != expectedStatus {
		fail("unexpected application status")
		return
	}
	checkPhase := next
	if o.phase == 2 && r.Method == "GET" {
		checkPhase = 3
	}
	if err := o.check(ctx, checkPhase); err != nil {
		fail(err.Error())
		return
	}
	if r.Method == "POST" && !bytes.Contains(body, []byte("extension operation accepted")) {
		fail("application operation not accepted")
		return
	}
	o.phase = next
	if checkPhase == 3 && !favicon {
		o.reloads++
	}
	for name, values := range rec.Header() {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

func runConfigurationBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	raw, err := os.ReadFile(f.MasterFile)
	acceptanceCheck(t, err)
	key, err := hex.DecodeString(string(raw))
	clear(raw)
	acceptanceCheck(t, err)
	defer clear(key)
	o := &configurationBrowserOracle{f: f, key: key}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	o.baseline, err = configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	acceptanceCheck(t, o.quiet())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	srv := &http.Server{Handler: o, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	served := make(chan error, 1)
	// Independent cleanup runs even if a phase assertion or driver fails.
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Error("configuration HTTP shutdown failed")
				_ = srv.Close()
			}
			if err := <-served; err != nil && err != http.ErrServerClosed {
				t.Error("configuration HTTP serve failed")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": "configuration", "endpoint": f.Endpoint, "secret": f.Secret}
	bootstrap, err := json.Marshal(input)
	acceptanceCheck(t, err)
	runctx, runcancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer runcancel()
	cmd := exec.CommandContext(runctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"))
	cmd.Stdin = bytes.NewReader(bootstrap)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	runErr := cmd.Run()
	clear(bootstrap)
	shutdown() // drain all handlers before checking final state or clearing the oracle key
	o.mu.Lock()
	if o.failure != "" {
		t.Error(o.failure)
	}
	if o.phase != 2 || o.posts != 2 || o.reloads < 1 {
		t.Errorf("configuration sequence incomplete: phase=%d posts=%d reloads=%d", o.phase, o.posts, o.reloads)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	phase := o.phase
	if phase == 2 {
		phase = 3
	}
	if err := o.check(ctx, phase); err != nil {
		t.Error(err.Error())
	}
	cancel()
	o.mu.Unlock()
	if runErr != nil {
		t.Errorf("configuration browser failed: %v (sanitized proof)", runErr)
	}
	if !t.Failed() {
		t.Log("PASS native configuration: independent SQL preview/apply/reload, AES-GCM, audit, no bearer/receiver/child, response privacy; login injected; renderer/B1 not admitted")
	}
}

func TestConfigurationBrowserBarrierRejectsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		phase                    int
		bearer                   bool
	}{
		{"unknown-state", "GET", "/admin/extensions/id", "", 99, false},
		{"action", "POST", "/admin/extensions/id", "action=enable", 0, false},
		{"phase", "POST", "/admin/extensions/id", "action=configure-apply", 0, false},
		{"replay", "POST", "/admin/extensions/id", "action=configure-apply", 2, false},
		{"method", "DELETE", "/admin/extensions/id", "", 0, false},
		{"route", "GET", "/unknown", "", 0, false},
		{"query", "GET", "/admin/extensions/id?override=1", "", 0, false},
		{"bearer", "GET", "/admin/extensions/id", "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			o := &configurationBrowserOracle{phase: tc.phase, f: acceptanceBrowserStart{ID: "id", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { invoked = true })}}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer synthetic")
			}
			w := httptest.NewRecorder()
			o.ServeHTTP(w, r)
			if w.Code != 500 || o.failure == "" || invoked {
				t.Fatal("invalid action crossed fixture boundary")
			}
		})
	}
}

// Test-only passive observer: every runtime result and effect comes from the real
// delegate. Observation errors latch independently, never bypassing Probe/Stop.
type nativeTestRuntime struct {
	extensionsadmin.Runtime
	mu                                         sync.Mutex
	root, executable, pid, dir, token, failure string
	expectedSHA                                [32]byte
	sequence                                   []string
	liveStart, liveProbe, stopped              bool
}

func (r *nativeTestRuntime) record(err error) {
	if err != nil && r.failure == "" {
		r.failure = err.Error()
	}
}
func (r *nativeTestRuntime) live() error {
	entries, err := os.ReadDir(r.root)
	if err != nil || len(entries) != 1 {
		return errors.New("expected one private runtime directory")
	}
	dir := filepath.Join(r.root, entries[0].Name())
	if r.dir != "" && r.dir != dir {
		return errors.New("runtime directory changed during Test")
	}
	for _, name := range []string{"", "secrets", "config.json", "binding.json", "service.token", "secrets/webhook.hmac-key", "extension.sock"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("runtime path missing or not private")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return errors.New("runtime path ownership mismatch")
		}
		if name == "extension.sock" && info.Mode()&os.ModeSocket == 0 {
			return errors.New("runtime socket missing")
		}
		if (name == "" || name == "secrets") && !info.IsDir() {
			return errors.New("runtime directory type mismatch")
		}
		if name != "" && name != "secrets" && name != "extension.sock" && !info.Mode().IsRegular() {
			return errors.New("runtime file type mismatch")
		}
	}
	paths, err := filepath.Glob("/proc/[0-9]*/exe")
	if err != nil {
		return errors.New("child inventory failed")
	}
	found := ""
	for _, path := range paths {
		target, err := os.Readlink(path)
		if err != nil || target != r.executable {
			continue
		}
		if found != "" {
			return errors.New("multiple pinned children")
		}
		found = filepath.Base(filepath.Dir(path))
		file, err := os.Open(path)
		if err != nil {
			return errors.New("live executable open failed")
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(file, (12<<20)+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || n > 12<<20 || !bytes.Equal(hash.Sum(nil), r.expectedSHA[:]) {
			return errors.New("live executable digest mismatch")
		}
		stat, err := os.ReadFile(filepath.Join("/proc", found, "stat"))
		if err != nil {
			return errors.New("child state unavailable")
		}
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 {
			return errors.New("child state malformed")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 3 || fields[0] == "Z" || fields[2] != found {
			return errors.New("child dead or process group mismatch")
		}
		cwd, err := os.Readlink(filepath.Join("/proc", found, "cwd"))
		if err != nil || cwd != dir {
			return errors.New("child runtime directory mismatch")
		}
	}
	if found == "" || (r.pid != "" && r.pid != found) {
		return errors.New("pinned child absent or changed")
	}
	r.pid, r.dir = found, dir
	tokenFile, err := os.Open(filepath.Join(dir, "service.token"))
	if err != nil {
		return errors.New("runtime privacy canary unavailable")
	}
	token, err := io.ReadAll(io.LimitReader(tokenFile, 65))
	closeErr := tokenFile.Close()
	if err != nil || closeErr != nil || len(token) != 64 {
		return errors.New("runtime privacy canary invalid")
	}
	if _, err := hex.DecodeString(string(token)); err != nil {
		return errors.New("runtime privacy canary encoding invalid")
	}
	if r.token != "" && r.token != string(token) {
		return errors.New("runtime token changed during Test")
	}
	r.token = string(token)
	clear(token)
	return nil
}
func (r *nativeTestRuntime) absent() error {
	entries, err := os.ReadDir(r.root)
	if err != nil || len(entries) != 0 {
		return errors.New("runtime directory remains after Stop")
	}
	if r.pid != "" {
		if _, err := os.Stat(filepath.Join("/proc", r.pid)); !os.IsNotExist(err) {
			return errors.New("observed child remains after Stop")
		}
	}
	if r.dir != "" {
		if _, err := os.Lstat(r.dir); !os.IsNotExist(err) {
			return errors.New("observed socket directory remains")
		}
	}
	return nil
}
func (r *nativeTestRuntime) Start(ctx context.Context, i extensionsadmin.Instance, secrets map[string][]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence = append(r.sequence, "start")
	err := r.Runtime.Start(ctx, i, secrets)
	if err != nil {
		r.record(errors.New("real Start failed"))
		return err
	}
	observation := r.live()
	r.record(observation)
	r.liveStart = observation == nil
	return err
}
func (r *nativeTestRuntime) Probe(ctx context.Context, i extensionsadmin.Instance) (extensionsadmin.Health, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence = append(r.sequence, "probe")
	health, err := r.Runtime.Probe(ctx, i)
	if err != nil || !health.Healthy || health.Code != "extension.ready" {
		r.record(errors.New("real Probe not ready"))
	}
	observation := r.live()
	r.record(observation)
	r.liveProbe = err == nil && health.Healthy && health.Code == "extension.ready" && observation == nil
	return health, err
}
func (r *nativeTestRuntime) Stop(ctx context.Context, i extensionsadmin.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence = append(r.sequence, "stop")
	err := r.Runtime.Stop(ctx, i)
	if err != nil {
		r.record(errors.New("real Stop failed"))
	}
	observation := r.absent()
	r.record(observation)
	r.stopped = err == nil && observation == nil
	return err
}
func (r *nativeTestRuntime) AdmitRouting(ctx context.Context, i extensionsadmin.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record(errors.New("unexpected routing admission"))
	return r.Runtime.AdmitRouting(ctx, i)
}
func (r *nativeTestRuntime) RevokeRouting(ctx context.Context, i extensionsadmin.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record(errors.New("unexpected routing revocation"))
	return r.Runtime.RevokeRouting(ctx, i)
}

// Check only Test's SQL delta; the already-admitted configure pair is SETUP.
func connectionSQL(before, after [4]string, actor, id string) error {
	if before[1] != after[1] || before[2] != after[2] {
		return errors.New("Test changed secrets or operation previews")
	}
	var oldRows, newRows, oldAudit, newAudit []map[string]any
	if json.Unmarshal([]byte(before[0]), &oldRows) != nil || json.Unmarshal([]byte(after[0]), &newRows) != nil || len(oldRows) != 1 || len(newRows) != 1 {
		return errors.New("Test instance cardinality mismatch")
	}
	old, row := oldRows[0], newRows[0]
	if old["configuration_revision"] != float64(2) || old["tested_revision"] != nil || old["enabled"] != false || old["routed"] != false || row["tested_revision"] != old["configuration_revision"] || row["health_code"] != "extension.ready" || row["lifecycle"] != "stopped" {
		return errors.New("Test readiness delta mismatch")
	}
	for _, field := range []string{"tested_revision", "health_code", "lifecycle", "updated_at"} {
		delete(old, field)
		delete(row, field)
	}
	if !reflect.DeepEqual(old, row) {
		return errors.New("Test changed configuration or authority")
	}
	if json.Unmarshal([]byte(before[3]), &oldAudit) != nil || json.Unmarshal([]byte(after[3]), &newAudit) != nil || len(oldAudit) != 2 || len(newAudit) != 3 {
		return errors.New("Test audit cardinality mismatch")
	}
	prior := map[any]map[string]any{}
	for _, event := range oldAudit {
		prior[event["id"]] = event
	}
	var added map[string]any
	for _, event := range newAudit {
		if old, ok := prior[event["id"]]; ok {
			if !reflect.DeepEqual(old, event) {
				return errors.New("prior audit changed")
			}
			delete(prior, event["id"])
		} else if added == nil {
			added = event
		} else {
			return errors.New("extra Test audit")
		}
	}
	if len(prior) != 0 || added == nil || added["action"] != "extension.test" || added["actor_type"] != "oidc_subject" || added["actor_id"] != actor || added["resource_type"] != "extension" || added["resource_id"] != id || added["result"] != "success" {
		return errors.New("Test audit binding mismatch")
	}
	payload, ok := added["after_redacted_json"].(string)
	if !ok {
		return errors.New("Test audit payload absent")
	}
	var values map[string]any
	if json.Unmarshal([]byte(payload), &values) != nil || !reflect.DeepEqual(values, map[string]any{"configuration_revision": float64(2), "health_code": "extension.ready"}) {
		return errors.New("Test audit payload mismatch")
	}
	return nil
}

func runConnectionBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	if f.TestRuntime == nil {
		t.Fatal("missing real runtime observer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	acceptanceCheck(t, f.TestRuntime.absent())
	var mu sync.Mutex
	posts := 0
	failure := ""
	var applied [4]string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func(reason string) {
			if failure == "" {
				failure = reason
			}
			http.Error(w, "connection-test fixture failed", 500)
		}
		if failure != "" {
			fail(failure)
			return
		}
		detail := "/admin/extensions/" + f.ID
		if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			fail("unexpected authority or query")
			return
		}
		if r.URL.Path != detail && r.URL.Path != "/admin/extensions" && r.URL.Path != "/favicon.ico" {
			fail("unexpected connection-test route")
			return
		}
		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if posts != 0 || r.URL.Path != detail || r.ParseForm() != nil || r.PostForm.Get("action") != "test" {
				fail("unexpected connection-test action or phase")
				return
			}
			posts++
		} else if r.Method != "GET" {
			fail("unexpected connection-test method")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, r.WithContext(ctx))
		f.TestRuntime.mu.Lock()
		defer f.TestRuntime.mu.Unlock()
		body := rec.Body.Bytes()
		for _, needle := range []string{f.Secret, f.Session, f.TestRuntime.token} {
			if needle != "" && bytes.Contains(body, []byte(needle)) {
				fail("Test response private value leak")
				return
			}
		}
		if len(body) > 1<<20 {
			fail("Test response fixture size exceeded")
			return
		}
		expected := 200
		if r.URL.Path == "/admin/extensions" {
			expected = 401
		}
		if r.URL.Path == "/favicon.ico" {
			expected = 404
		}
		if rec.Code != expected {
			fail("unexpected Test response status")
			return
		}
		state, err := configurationSnapshot(ctx, f.DB)
		if err != nil {
			fail(err.Error())
			return
		}
		if f.Requests() != 0 {
			fail("Test reached webhook receiver")
			return
		}
		if err := f.TestRuntime.absent(); err != nil {
			fail(err.Error())
			return
		}
		if posts == 0 {
			if state != before || len(f.TestRuntime.sequence) != 0 {
				fail("GET changed configured state")
				return
			}
		} else {
			if f.TestRuntime.failure != "" {
				fail(f.TestRuntime.failure)
				return
			}
			if !reflect.DeepEqual(f.TestRuntime.sequence, []string{"start", "probe", "stop"}) || !f.TestRuntime.liveStart || !f.TestRuntime.liveProbe || !f.TestRuntime.stopped {
				fail("positive real Test runtime proof incomplete")
				return
			}
			if r.Method == "POST" {
				if err := connectionSQL(before, state, f.ActorID, f.ID); err != nil {
					fail(err.Error())
					return
				}
				if !bytes.Contains(body, []byte("extension operation accepted")) {
					fail("Test action not accepted")
					return
				}
				applied = state
			} else if state != applied {
				fail("GET changed tested state")
				return
			}
		}
		for _, table := range state {
			for _, needle := range []string{f.Secret, f.Session, f.CSRF, f.TestRuntime.token} {
				if needle != "" && strings.Contains(table, needle) {
					fail("Test SQL private value leak")
					return
				}
			}
		}
		for name, values := range rec.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 10 * time.Second}
	served := make(chan error, 1)
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Error("Test HTTP shutdown failed")
				_ = srv.Close()
			}
			if err := <-served; err != nil && err != http.ErrServerClosed {
				t.Error("Test HTTP serve failed")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": "connection-test"}
	bootstrap, err := json.Marshal(input)
	acceptanceCheck(t, err)
	runctx, runcancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer runcancel()
	cmd := exec.CommandContext(runctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"))
	cmd.Stdin = bytes.NewReader(bootstrap)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	runErr := cmd.Run()
	clear(bootstrap)
	shutdown()
	mu.Lock()
	defer mu.Unlock()
	f.TestRuntime.mu.Lock()
	defer f.TestRuntime.mu.Unlock()
	if failure != "" {
		t.Error(failure)
	}
	if posts != 1 || f.TestRuntime.failure != "" || !reflect.DeepEqual(f.TestRuntime.sequence, []string{"start", "probe", "stop"}) || !f.TestRuntime.liveStart || !f.TestRuntime.liveProbe || !f.TestRuntime.stopped {
		t.Error("native Test or positive runtime sequence incomplete")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	state, err := configurationSnapshot(ctx, f.DB)
	cancel()
	if err != nil || state != applied {
		t.Error("final tested SQL mismatch")
	}
	if err := f.TestRuntime.absent(); err != nil {
		t.Error(err.Error())
	}
	if f.Requests() != 0 {
		t.Error("receiver not quiet")
	}
	// Only the whitelist proof is read; no transport dumps are retained.
	proof, err := os.ReadFile(filepath.Join(os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"), "proof.json"))
	if err != nil {
		t.Error("browser proof absent")
	} else {
		for _, needle := range []string{f.Secret, f.Session, f.CSRF, f.TestRuntime.token} {
			if needle != "" && bytes.Contains(proof, []byte(needle)) {
				t.Error("browser proof private value leak")
			}
		}
	}
	if runErr != nil {
		t.Errorf("native Test browser failed: %v", runErr)
	}
	if !t.Failed() {
		t.Logf("PASS native Test: one POST; Start/Probe/Stop real child pid=%s executable_sha256=%x private socket; stopped/disabled/unrouted; SQL/audit/secret retention/privacy; receiver quiet; login injected", f.TestRuntime.pid, f.TestRuntime.expectedSHA)
	}
}

// Synthetic delegate verifies observer transparency only; it is not runtime proof.
type nativeTestDelegate struct {
	calls  []string
	result error
	health extensionsadmin.Health
}

func (d *nativeTestDelegate) Start(context.Context, extensionsadmin.Instance, map[string][]byte) error {
	d.calls = append(d.calls, "start")
	return d.result
}
func (d *nativeTestDelegate) Probe(context.Context, extensionsadmin.Instance) (extensionsadmin.Health, error) {
	d.calls = append(d.calls, "probe")
	return d.health, d.result
}
func (d *nativeTestDelegate) Stop(context.Context, extensionsadmin.Instance) error {
	d.calls = append(d.calls, "stop")
	return d.result
}
func (d *nativeTestDelegate) AdmitRouting(context.Context, extensionsadmin.Instance) error {
	d.calls = append(d.calls, "admit")
	return d.result
}
func (d *nativeTestDelegate) RevokeRouting(context.Context, extensionsadmin.Instance) error {
	d.calls = append(d.calls, "revoke")
	return d.result
}
func TestNativeTestObserverPreservesDelegate(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-fake-success", true: "original-errors"}[failed], func(t *testing.T) {
			var expected error
			if failed {
				expected = errors.New("synthetic delegate failure")
			}
			d := &nativeTestDelegate{result: expected, health: extensionsadmin.Health{Healthy: true, Code: "extension.ready"}}
			r := &nativeTestRuntime{Runtime: d, root: "/nonexistent-native-test-observer"}
			ctx := context.Background()
			i := extensionsadmin.Instance{}
			if err := r.Start(ctx, i, nil); err != expected {
				t.Fatal("observer replaced Start result")
			}
			h, err := r.Probe(ctx, i)
			if err != expected || h != d.health {
				t.Fatal("observer replaced Probe result")
			}
			if err := r.Stop(ctx, i); err != expected {
				t.Fatal("observer replaced Stop result")
			}
			if !reflect.DeepEqual(d.calls, []string{"start", "probe", "stop"}) || r.failure == "" || r.liveStart || r.liveProbe || r.stopped {
				t.Fatal("missing positive OS proof was accepted or delegation suppressed")
			}
			if err := r.AdmitRouting(ctx, i); err != expected {
				t.Fatal("admit result changed")
			}
			if err := r.RevokeRouting(ctx, i); err != expected {
				t.Fatal("revoke result changed")
			}
			if !reflect.DeepEqual(d.calls, []string{"start", "probe", "stop", "admit", "revoke"}) {
				t.Fatal("unexpected routing call did not delegate")
			}
		})
	}
}
func TestNativeTestSQLDelta(t *testing.T) {
	encode := func(v any) string { b, err := json.Marshal(v); acceptanceCheck(t, err); return string(b) }
	for _, kind := range []string{"valid", "configuration", "authority", "secret", "preview", "audit", "readiness"} {
		t.Run(kind, func(t *testing.T) {
			old := map[string]any{"configuration_revision": 2, "tested_revision": nil, "enabled": false, "routed": false, "configuration_json": map[string]any{"endpoint": "fixed"}, "health_code": "extension.unknown", "lifecycle": "stopped", "updated_at": "before"}
			next := map[string]any{}
			for k, v := range old {
				next[k] = v
			}
			next["tested_revision"] = 2
			next["health_code"] = "extension.ready"
			next["updated_at"] = "after"
			prior := []map[string]any{{"id": "install"}, {"id": "configure"}}
			event := map[string]any{"id": "test", "action": "extension.test", "actor_type": "oidc_subject", "actor_id": "actor", "resource_type": "extension", "resource_id": "instance", "result": "success", "after_redacted_json": encode(map[string]any{"configuration_revision": 2, "health_code": "extension.ready"})}
			before := [4]string{encode([]any{old}), "encrypted", "consumed", encode(prior)}
			after := [4]string{"", "encrypted", "consumed", ""}
			switch kind {
			case "configuration":
				next["configuration_json"] = "changed"
			case "authority":
				next["enabled"] = true
			case "secret":
				after[1] = "rotated"
			case "preview":
				after[2] = "new"
			case "audit":
				event["actor_id"] = "other"
			case "readiness":
				next["tested_revision"] = 1
			}
			after[0] = encode([]any{next})
			after[3] = encode([]any{prior[0], prior[1], event})
			err := connectionSQL(before, after, "actor", "instance")
			if (err == nil) != (kind == "valid") {
				t.Fatal("SQL delta oracle accepted corruption or rejected valid delta")
			}
		})
	}
}
