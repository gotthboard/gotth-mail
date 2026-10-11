package main

// Bounded live-browser gates; delivery and release admission remain outside this fixture.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestNativeUpdatePreviewOracle(t *testing.T) {
	encode := func(v any) string { b, e := json.Marshal(v); acceptanceCheck(t, e); return string(b) }
	for _, kind := range []string{"valid", "actor", "target", "hash", "confirmation", "expiry", "secret", "revision", "consumed", "audit"} {
		t.Run(kind, func(t *testing.T) {
			key := bytes.Repeat([]byte{7}, 32)
			phrase := "confirm-" + strings.Repeat("a", 32)
			target := extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + acceptanceArchiveBSHA}
			raw, _ := json.Marshal(target)
			hash := sha256.Sum256(raw)
			var payload any
			_ = json.Unmarshal(raw, &payload)
			base := map[string]any{"artifact_pin": "sha256:" + acceptanceArchiveSHA, "configuration_revision": 2, "tested_revision": 2, "health_code": "extension.ready", "lifecycle": "stopped", "enabled": false, "routed": false}
			prior := map[string]any{"id": "setup"}
			created := time.Now().UTC().Truncate(time.Microsecond)
			layout := "2006-01-02T15:04:05.999999999"
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte("extension-preview-confirmation\x00"))
			mac.Write([]byte(phrase))
			empty := hmac.New(sha256.New, key)
			p := map[string]any{"id": "preview", "instance_id": "id", "actor_type": "oidc_subject", "actor_id": "actor", "operation": "update", "base_revision": 2, "payload_json": payload, "payload_sha256": hex.EncodeToString(hash[:]), "confirmation_sha256": hex.EncodeToString(mac.Sum(nil)), "secret_binding_sha256": hex.EncodeToString(empty.Sum(nil)), "created_at": created.Format(layout), "expires_at": created.Add(10 * time.Minute).Format(layout)}
			before := [4]string{encode([]any{base}), "[{}]", encode([]any{prior}), "[{},{},{}]"}
			after := before
			switch kind {
			case "actor":
				p["actor_id"] = "wrong"
			case "target":
				p["payload_json"] = nil
			case "hash":
				p["payload_sha256"] = "wrong"
			case "confirmation":
				p["confirmation_sha256"] = "wrong"
			case "expiry":
				p["expires_at"] = created.Format(layout)
			case "secret":
				after[1] = "[]"
			case "revision":
				p["base_revision"] = 3
			case "consumed":
				p["consumed_at"] = "now"
			case "audit":
				after[3] = "[]"
			}
			after[2] = encode([]any{prior, p})
			u := &nativeUpdateOracle{key: key, baseline: before, f: acceptanceBrowserStart{ID: "id", ActorID: "actor", Update: &nativeUpdateSetup{Target: target}}}
			if (u.check(context.Background(), 1, after, []byte("<code>"+phrase+"</code>")) == nil) != (kind == "valid") {
				t.Fatal("preview oracle corruption mismatch")
			}
		})
	}
}

// Update-only SQL/crypto oracle; values stay in memory.
type nativeUpdateOracle struct {
	f                 acceptanceBrowserStart
	key               []byte
	baseline, preview [4]string
}

func (u *nativeUpdateOracle) quiet(ctx context.Context) error {
	for _, exe := range []string{u.f.Executable, u.f.Update.Executable} {
		f := u.f
		f.Executable = exe
		if err := (&configurationBrowserOracle{f: f}).quiet(); err != nil {
			return err
		}
	}
	return (&nativeTestRuntime{routeHealth: u.f.Update.Route}).route(ctx, false)
}
func updateRows(state [4]string) ([4][]map[string]any, error) {
	var rows [4][]map[string]any
	for i := range state {
		if json.Unmarshal([]byte(state[i]), &rows[i]) != nil {
			return rows, errors.New("update SQL decode")
		}
	}
	if len(rows[0]) != 1 {
		return rows, errors.New("update instance count")
	}
	return rows, nil
}
func updateAudit(before, after string, actor, id, action string, payload map[string]any) error {
	var old, rows []map[string]any
	if json.Unmarshal([]byte(before), &old) != nil || json.Unmarshal([]byte(after), &rows) != nil || len(rows) != len(old)+1 {
		return errors.New("update audit count")
	}
	remaining := map[any]map[string]any{}
	for _, e := range old {
		remaining[e["id"]] = e
	}
	var added map[string]any
	for _, e := range rows {
		if p, ok := remaining[e["id"]]; ok {
			if !reflect.DeepEqual(p, e) {
				return errors.New("prior audit changed")
			}
			delete(remaining, e["id"])
		} else if added == nil {
			added = e
		} else {
			return errors.New("extra audit")
		}
	}
	if len(remaining) != 0 || added == nil || added["actor_type"] != "oidc_subject" || added["actor_id"] != actor || added["resource_type"] != "extension" || added["resource_id"] != id || added["action"] != action || added["result"] != "success" {
		return errors.New("update audit binding")
	}
	raw, ok := added["after_redacted_json"].(string)
	var got map[string]any
	if !ok || json.Unmarshal([]byte(raw), &got) != nil || !reflect.DeepEqual(got, payload) {
		return errors.New("update audit payload")
	}
	return nil
}
func (u *nativeUpdateOracle) check(ctx context.Context, phase int, state [4]string, body []byte) error {
	old, err := updateRows(u.baseline)
	if err != nil {
		return err
	}
	rows, err := updateRows(state)
	if err != nil {
		return err
	}
	if state[1] != u.baseline[1] || len(old[1]) != 1 || len(old[2]) != 1 || len(old[3]) != 3 {
		return errors.New("update baseline/secret mismatch")
	}
	base := old[0][0]
	if base["artifact_pin"] != "sha256:"+acceptanceArchiveSHA || base["configuration_revision"] != float64(2) || base["tested_revision"] != float64(2) || base["health_code"] != "extension.ready" || base["lifecycle"] != "stopped" || base["enabled"] != false || base["routed"] != false {
		return errors.New("update A setup")
	}
	if len(rows[2]) != 2 {
		return errors.New("update preview count")
	}
	var p map[string]any
	foundPrior := false
	for _, candidate := range rows[2] {
		if candidate["id"] == old[2][0]["id"] {
			foundPrior = true
			if !reflect.DeepEqual(candidate, old[2][0]) {
				return errors.New("setup preview changed")
			}
		} else {
			p = candidate
		}
	}
	if !foundPrior || p == nil || p["instance_id"] != u.f.ID || p["actor_type"] != "oidc_subject" || p["actor_id"] != u.f.ActorID || p["operation"] != "update" || p["base_revision"] != float64(2) {
		return errors.New("update preview binding")
	}
	payload, err := json.Marshal(u.f.Update.Target)
	if err != nil {
		return errors.New("target encoding")
	}
	var target any
	_ = json.Unmarshal(payload, &target)
	digest := sha256.Sum256(payload)
	if !reflect.DeepEqual(p["payload_json"], target) || p["payload_sha256"] != hex.EncodeToString(digest[:]) {
		return errors.New("update target/hash")
	}
	for _, field := range []string{"privilege_diff_json", "configuration_diff_json", "secret_slot_diff_json"} {
		if p[field] != nil {
			if a, ok := p[field].([]any); !ok || len(a) != 0 {
				return errors.New("unexpected update diff")
			}
		}
	}
	if phase == 1 {
		if state[0] != u.baseline[0] || state[3] != u.baseline[3] || p["consumed_at"] != nil {
			return errors.New("preview mutated authority")
		}
		match := regexp.MustCompile("<code>(confirm-[a-f0-9]{32})</code>").FindSubmatch(body)
		if len(match) != 2 {
			return errors.New("update confirmation absent")
		}
		mac := hmac.New(sha256.New, u.key)
		mac.Write([]byte("extension-preview-confirmation\x00"))
		mac.Write(match[1])
		empty := hmac.New(sha256.New, u.key)
		if p["confirmation_sha256"] != hex.EncodeToString(mac.Sum(nil)) || p["secret_binding_sha256"] != hex.EncodeToString(empty.Sum(nil)) {
			return errors.New("preview crypto binding")
		}
		created, cok := p["created_at"].(string)
		expires, eok := p["expires_at"].(string)
		ct, ce := time.Parse("2006-01-02T15:04:05.999999999", created)
		et, ee := time.Parse("2006-01-02T15:04:05.999999999", expires)
		if !cok || !eok || ce != nil || ee != nil || et.Sub(ct) != 10*time.Minute || !et.After(time.Now()) {
			return errors.New("preview expiry")
		}
		u.preview = state
		return nil
	}
	if phase != 2 {
		return errors.New("unknown update phase")
	}
	preview, err := updateRows(u.preview)
	if err != nil {
		return err
	}
	var previous map[string]any
	for _, v := range preview[2] {
		if v["id"] == p["id"] {
			previous = v
		}
	}
	if previous == nil || p["consumed_at"] == nil {
		return errors.New("preview not consumed")
	}
	delete(p, "consumed_at")
	delete(previous, "consumed_at")
	if !reflect.DeepEqual(p, previous) {
		return errors.New("consumed preview changed")
	}
	row := rows[0][0]
	targetB := u.f.Update.Target
	expected := map[string]any{"artifact_pin": targetB.ArtifactPin, "manifest_sha256": targetB.ManifestDigest, "grant_sha256": targetB.GrantDigest, "session_sha256": targetB.SessionDigest, "previous_artifact_pin": base["artifact_pin"], "available_update_pin": nil, "configuration_revision": float64(3), "tested_revision": nil, "health_code": "extension.unknown", "lifecycle": "stopped"}
	snapshot := map[string]any{}
	for to, from := range map[string]string{"artifact_pin": "artifact_pin", "manifest_sha256": "manifest_sha256", "grant_sha256": "grant_sha256", "session_sha256": "session_sha256", "capabilities": "capabilities_json", "interfaces": "interfaces_json", "secret_slots": "secret_slots_json", "metadata": "metadata_json", "configuration": "configuration_json"} {
		snapshot[to] = base[from]
	}
	expected["previous_version_json"] = snapshot
	for field, want := range expected {
		if !reflect.DeepEqual(row[field], want) {
			return errors.New("update instance/snapshot delta")
		}
		delete(row, field)
		delete(base, field)
	}
	delete(row, "updated_at")
	delete(base, "updated_at")
	if !reflect.DeepEqual(row, base) {
		return errors.New("update unrelated authority/configuration")
	}
	if err := updateAudit(u.baseline[3], state[3], u.f.ActorID, u.f.ID, "extension.update", map[string]any{"from": "sha256:" + acceptanceArchiveSHA, "to": targetB.ArtifactPin, "privilege_diff": p["privilege_diff_json"], "configuration_diff": p["configuration_diff_json"], "secret_slot_diff": "[REDACTED]"}); err != nil {
		return err
	}
	return u.secret(ctx)
}
func (u *nativeUpdateOracle) secret(ctx context.Context) error {
	var nonce, ciphertext []byte
	var slot string
	if err := u.f.DB.QueryRowContext(ctx, "SELECT slot,nonce,ciphertext FROM extension_secrets WHERE instance_id=$1", u.f.ID).Scan(&slot, &nonce, &ciphertext); err != nil {
		return errors.New("update secret query")
	}
	block, err := aes.NewCipher(u.key)
	if err != nil {
		return errors.New("update AES key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("update GCM")
	}
	if len(nonce) != gcm.NonceSize() {
		return errors.New("update AES nonce")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(u.f.ID+"\x00"+slot))
	defer clear(plain)
	if err != nil || slot != "webhook.hmac-key" || !bytes.Equal(plain, []byte(u.f.Secret)) {
		return errors.New("update secret authentication")
	}
	return nil
}
func (u *nativeUpdateOracle) testB(t *testing.T, before [4]string) error {
	label, revision, exe, digest := "B", float64(3), u.f.Update.Executable, u.f.Update.SHA
	if u.f.Update.RollbackA[0] != "" {
		label, revision, exe, digest = "restored A", 5, u.f.Executable, u.f.TestRuntime.expectedSHA
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := u.quiet(ctx); err != nil {
		return err
	}
	r := &nativeTestRuntime{Runtime: u.f.TestRuntime.Runtime, root: u.f.RuntimeRoot, executable: exe, expectedSHA: digest}
	if err := u.f.Update.TestB(ctx, r); err != nil {
		return errors.New("nonbrowser B Service.Test failed")
	}
	if err := r.phase(ctx, 1); err != nil {
		return err
	}
	if err := u.quiet(ctx); err != nil {
		return err
	}
	state, err := configurationSnapshot(ctx, u.f.DB)
	if err != nil {
		return err
	}
	old, err := updateRows(before)
	if err != nil {
		return err
	}
	rows, err := updateRows(state)
	if err != nil {
		return err
	}
	if before[1] != state[1] || before[2] != state[2] {
		return errors.New("B Test changed secret/preview")
	}
	row, base := rows[0][0], old[0][0]
	if row["tested_revision"] != revision || row["health_code"] != "extension.ready" {
		return errors.New("B readiness mismatch")
	}
	for _, f := range []string{"tested_revision", "health_code", "updated_at"} {
		delete(row, f)
		delete(base, f)
	}
	if !reflect.DeepEqual(row, base) {
		return errors.New("B Test changed authority")
	}
	if err := updateAudit(before[3], state[3], u.f.ActorID, u.f.ID, "extension.test", map[string]any{"configuration_revision": revision, "health_code": "extension.ready"}); err != nil {
		return err
	}
	for _, table := range state {
		for _, needle := range []string{u.f.Secret, u.f.Session, u.f.CSRF, r.token} {
			if needle != "" && strings.Contains(table, needle) {
				return errors.New("B SQL private leak")
			}
		}
	}
	if err := u.secret(ctx); err != nil {
		return err
	}
	t.Logf("PASS nonbrowser %s only: pid=%s executable_sha256=%x Start/Probe/Stop; private socket removed; revision/tested=%v; route absent receiver0", label, r.pid, r.expectedSHA, revision)
	return nil
}

// Independent snapshot projection from captured SQL, never stored previous JSON.
func rollbackVersion(row map[string]any) map[string]any {
	out := map[string]any{}
	for to, from := range map[string]string{"artifact_pin": "artifact_pin", "manifest_sha256": "manifest_sha256", "grant_sha256": "grant_sha256", "session_sha256": "session_sha256", "capabilities": "capabilities_json", "interfaces": "interfaces_json", "secret_slots": "secret_slots_json", "metadata": "metadata_json", "configuration": "configuration_json"} {
		out[to] = row[from]
	}
	return out
}
func rollbackSetup(a, b [4]string) error {
	left, err := updateRows(a)
	if err != nil {
		return err
	}
	right, err := updateRows(b)
	if err != nil {
		return err
	}
	ar, br := left[0][0], right[0][0]
	ac, aok := ar["configuration_json"].(map[string]any)
	bc, bok := br["configuration_json"].(map[string]any)
	if !aok || !bok || bc["webhook.endpoint"] != ac["webhook.endpoint"].(string)+"/rollback-b" || ac["webhook.timeout-seconds"] != float64(2) || bc["webhook.timeout-seconds"] != float64(1) {
		return errors.New("rollback setup configurations not distinct")
	}
	if ar["artifact_pin"] != "sha256:"+acceptanceArchiveSHA || br["artifact_pin"] != "sha256:"+acceptanceArchiveBSHA || ar["configuration_revision"] != float64(2) || ar["tested_revision"] != float64(2) || br["configuration_revision"] != float64(4) || br["tested_revision"] != float64(4) || br["enabled"] != false || br["routed"] != false || br["lifecycle"] != "stopped" || br["health_code"] != "extension.ready" || !reflect.DeepEqual(br["previous_version_json"], rollbackVersion(ar)) || br["previous_artifact_pin"] != ar["artifact_pin"] {
		return errors.New("rollback setup snapshot/readiness")
	}
	if len(left[1]) != 1 || len(right[1]) != 1 || reflect.DeepEqual(left[1][0]["ciphertext"], right[1][0]["ciphertext"]) || len(right[2]) != 3 || len(left[3]) != 3 || len(right[3]) != 6 {
		return errors.New("rollback setup rotation/counts")
	}
	return nil
}
func rollbackSQL(a, b, after [4]string, actor, id string, success bool) error {
	if !success {
		if after != b {
			return errors.New("denied rollback mutated SQL")
		}
		return nil
	}
	if b[1] != after[1] || b[2] != after[2] {
		return errors.New("rollback changed secret/preview")
	}
	left, err := updateRows(a)
	if err != nil {
		return err
	}
	prior, err := updateRows(b)
	if err != nil {
		return err
	}
	rows, err := updateRows(after)
	if err != nil {
		return err
	}
	ar, br, row := left[0][0], prior[0][0], rows[0][0]
	expected := map[string]any{}
	for _, field := range []string{"artifact_pin", "manifest_sha256", "grant_sha256", "session_sha256", "capabilities_json", "interfaces_json", "secret_slots_json", "metadata_json", "configuration_json"} {
		expected[field] = ar[field]
	}
	expected["previous_artifact_pin"] = br["artifact_pin"]
	expected["previous_version_json"] = rollbackVersion(br)
	expected["configuration_revision"] = br["configuration_revision"].(float64) + 1
	expected["tested_revision"] = nil
	expected["health_code"] = "extension.unknown"
	expected["lifecycle"] = "stopped"
	for field, want := range expected {
		if !reflect.DeepEqual(row[field], want) {
			return errors.New("rollback restoration/snapshot mismatch")
		}
		delete(row, field)
		delete(br, field)
	}
	delete(row, "updated_at")
	delete(br, "updated_at")
	if !reflect.DeepEqual(row, br) {
		return errors.New("rollback unrelated authority changed")
	}
	if err := updateAudit(b[3], after[3], actor, id, "extension.rollback", map[string]any{"artifact_pin": ar["artifact_pin"]}); err != nil {
		return err
	}
	var events, old []map[string]any
	_ = json.Unmarshal([]byte(after[3]), &events)
	_ = json.Unmarshal([]byte(b[3]), &old)
	ids := map[any]bool{}
	for _, e := range old {
		ids[e["id"]] = true
	}
	for _, e := range events {
		if !ids[e["id"]] {
			raw, ok := e["before_redacted_json"].(string)
			var payload map[string]any
			if !ok || json.Unmarshal([]byte(raw), &payload) != nil || !reflect.DeepEqual(payload, map[string]any{"artifact_pin": "sha256:" + acceptanceArchiveBSHA}) {
				return errors.New("rollback before audit pin")
			}
		}
	}
	return nil
}
func TestNativeRollbackDelta(t *testing.T) {
	encode := func(v any) string { b, e := json.Marshal(v); acceptanceCheck(t, e); return string(b) }
	for _, kind := range []string{"valid", "configuration", "metadata", "grant", "session", "permissions", "previous", "revision", "ready", "secret", "preview", "audit-before", "audit-after", "actor", "denial"} {
		t.Run(kind, func(t *testing.T) {
			ar := map[string]any{"artifact_pin": "sha256:" + acceptanceArchiveSHA, "configuration_revision": float64(2), "configuration_json": "A", "metadata_json": "metaA", "grant_sha256": "grantA", "session_sha256": "sessionA", "capabilities_json": "capsA", "interfaces_json": "interface", "secret_slots_json": "slots", "manifest_sha256": "manifestA", "enabled": false, "routed": false, "lifecycle": "stopped", "tested_revision": float64(2), "health_code": "extension.ready"}
			br := map[string]any{}
			for k, v := range ar {
				br[k] = v
			}
			br["artifact_pin"] = "sha256:" + acceptanceArchiveBSHA
			br["configuration_revision"] = float64(4)
			br["configuration_json"] = "B"
			br["tested_revision"] = float64(4)
			row := map[string]any{}
			for k, v := range ar {
				row[k] = v
			}
			row["configuration_revision"] = float64(5)
			row["tested_revision"] = nil
			row["health_code"] = "extension.unknown"
			row["previous_artifact_pin"] = br["artifact_pin"]
			row["previous_version_json"] = rollbackVersion(br)
			event := map[string]any{"id": "new", "action": "extension.rollback", "actor_type": "oidc_subject", "actor_id": "actor", "resource_type": "extension", "resource_id": "id", "result": "success", "before_redacted_json": encode(map[string]any{"artifact_pin": br["artifact_pin"]}), "after_redacted_json": encode(map[string]any{"artifact_pin": ar["artifact_pin"]})}
			a := [4]string{encode([]any{ar}), "[]", "[]", "[]"}
			b := [4]string{encode([]any{br}), `[ {"ciphertext":"rotated"} ]`, `[ {"id":"preview"} ]`, "[]"}
			after := [4]string{"", b[1], b[2], ""}
			switch kind {
			case "configuration":
				row["configuration_json"] = "B"
			case "metadata":
				row["metadata_json"] = "B"
			case "grant":
				row["grant_sha256"] = "B"
			case "session":
				row["session_sha256"] = "B"
			case "permissions":
				row["capabilities_json"] = "B"
			case "previous":
				row["previous_version_json"] = rollbackVersion(ar)
			case "revision":
				row["configuration_revision"] = 4
			case "ready":
				row["tested_revision"] = 4
			case "secret":
				after[1] = "old"
			case "preview":
				after[2] = "changed"
			case "audit-before":
				event["before_redacted_json"] = "{}"
			case "audit-after":
				event["after_redacted_json"] = "{}"
			case "actor":
				event["actor_id"] = "other"
			}
			after[0] = encode([]any{row})
			after[3] = encode([]any{event})
			err := rollbackSQL(a, b, after, "actor", "id", kind != "denial")
			if (err == nil) != (kind == "valid") {
				t.Fatalf("rollback delta corruption mismatch: %v", err)
			}
			if rollbackSQL(a, b, b, "actor", "id", false) != nil {
				t.Fatal("unchanged denial rejected")
			}
		})
	}
}
func TestNativeCombinedDecision(t *testing.T) {
	failure := errors.New("postcondition failure")
	for _, native := range []bool{false, true} {
		for _, err := range []error{nil, failure} {
			got := nativeCombinedResult(native, err)
			if (got == nil) != (native && err == nil) {
				t.Fatal("combined success accepted incomplete evidence")
			}
			if native && err != nil && got != err {
				t.Fatal("postcondition error replaced")
			}
		}
	}
}

// Pure decision used by the measured combined gate, not a product fault injection.
func nativeCombinedResult(native bool, postcondition error) error {
	if !native {
		return errors.New("native proof failed")
	}
	return postcondition
}

type nativeUpdateSetup struct {
	RollbackA  [4]string
	Target     extensionsadmin.UpdateInput
	Executable string
	SHA        [32]byte
	Route      func(context.Context) (plugin.HealthResponse, error)
	TestB      func(context.Context, *nativeTestRuntime) error
}

type acceptanceBrowserStart struct {
	Update                                                         *nativeUpdateSetup
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
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "enhanced" {
			runEnhancedPaginationBrowser(t, f, driver)
			return
		}
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "permissions" {
			runPaginationBrowser(t, f, driver)
			return
		}
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "pagination" {
			runPaginationBrowser(t, f, driver)
			return
		}
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "detail-theme" {
			runDetailThemeBrowser(t, f, driver)
			return
		}
		if mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE"); mode == "connection-test" || mode == "activation" || mode == "update" || mode == "rollback" {
			runConnectionBrowser(t, f, driver)
			return
		}
		if os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "uninstall" {
			runUninstallBrowser(t, f, driver)
			return
		}
		if mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE"); mode == "secrets-delete" || (mode == "secrets-delete-recovery" || mode == "secrets-delete-recovery-no-css") {
			runSecretsBrowser(t, f, driver)
			return
		}
		if mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE"); mode == "configuration" || mode == "configuration-no-css" {
			runConfigurationBrowser(t, f, driver)
			return
		}
		inventoryMode := os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "inventory"
		// SQL material remains in memory; only equality is retained, never row contents.
		snapshot := func() []string {
			var state []string
			tables := []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events"}
			if inventoryMode {
				tables = append(tables, "sessions", "identity_refs", "role_bindings")
			}
			for _, table := range tables {
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
		var inventoryRefreshes, costRefreshes atomic.Int32
		var costPhase atomic.Bool
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
				if inventoryMode {
					http.Error(w, "inventory fixture permits GET only", 400)
					return
				}
			}
			if inventoryMode && r.URL.Path == "/admin/extensions" && r.Header.Get("HX-Request") == "true" {
				if costPhase.Load() {
					costRefreshes.Add(1)
				} else {
					inventoryRefreshes.Add(1)
				}
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
		if mode != "navigation" && mode != "audit" && mode != "inventory" {
			t.Fatal("unknown browser mode")
		}
		input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": mode}
		if inventoryMode {
			input["pin"] = "sha256:" + acceptanceArchiveSHA
		}
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
		if inventoryMode && err == nil {
			runInventoryPolicyBrowser(t, f, driver)
			if !t.Failed() {
				costPhase.Store(true)
				input["costStage"] = "loader"
				raw, marshalErr := json.Marshal(input)
				acceptanceCheck(t, marshalErr)
				costCtx, costCancel := context.WithTimeout(context.Background(), 90*time.Second)
				costCmd := exec.CommandContext(costCtx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT")+"-cost")
				costCmd.Stdin = bytes.NewReader(raw)
				costCmd.Stdout, costCmd.Stderr = os.Stdout, os.Stderr
				costCmd.Cancel = func() error { return costCmd.Process.Signal(syscall.SIGTERM) }
				costCmd.WaitDelay = 20 * time.Second
				costErr := costCmd.Run()
				costCancel()
				costPhase.Store(false)
				if costErr != nil {
					t.Errorf("loader cost driver failed: %v", costErr)
				}
				if costErr == nil && costRefreshes.Load() != 24 {
					t.Error("separate loader refresh count differs")
				}
				t.Logf("loader-only additional actual HX GETs %d; original five-refresh oracle unchanged", costRefreshes.Load())
			}
		}
		if !reflect.DeepEqual(before, snapshot()) || !reflect.DeepEqual(initial, f.Current()) {
			t.Error("browser GET changed durable state")
		}
		if authorization.Load() != 0 || posts.Load() != 0 || f.Requests() != 0 {
			t.Error("initial navigation caused bearer injection, mutation, or receiver traffic")
		}
		// Four exact canonical URLs plus the retained light-theme refresh.
		if inventoryMode && err == nil && inventoryRefreshes.Load() != 5 {
			t.Error("native inventory refresh count differs from independent server oracle")
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
	noCSS                      bool
	authority                  string
	f                          acceptanceBrowserStart
	mu                         sync.Mutex
	phase, reloads, posts      int
	failure                    string
	baseline, preview, applied [4]string
	key                        []byte
	stylesheets                [2]bool
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
	asset := -1
	if r.URL.Path == "/admin/extensions/assets/tokens.css" {
		asset = 0
	}
	if r.URL.Path == "/admin/extensions/assets/detail.css" {
		asset = 1
	}
	if o.noCSS && (asset >= 0 || r.Host != o.authority || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.ForceQuery) {
		fail("no-CSS request crossed transport boundary")
		return
	}
	queryOK := r.URL.RawQuery == ""
	if r.URL.Path == detail {
		switch r.URL.RawQuery {
		case "theme=system", "theme=light", "theme=dark":
			queryOK = true
		}
	}
	if !queryOK || (asset >= 0 && r.Method != "GET") || (r.URL.Path != detail && r.URL.Path != "/admin/extensions" && !favicon && asset < 0) {
		fail("unexpected browser route")
		return
	}
	switch r.Method {
	case "GET":
		if o.phase == 1 && !favicon && asset < 0 {
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
	if asset >= 0 && (rec.Header().Get("Content-Type") != "text/css; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff") {
		fail("CSS MIME/privacy mismatch")
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
	if asset >= 0 {
		o.stylesheets[asset] = true
	}
	o.phase = next
	if checkPhase == 3 && r.URL.Path == detail {
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
	noCSS := os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "configuration-no-css"
	o := &configurationBrowserOracle{f: f, key: key, noCSS: noCSS}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	o.baseline, err = configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	acceptanceCheck(t, o.quiet())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	o.authority = listener.Addr().String()
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
	input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": os.Getenv("GOTTH_MAIL_BROWSER_MODE"), "endpoint": f.Endpoint, "secret": f.Secret}
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
	if o.noCSS {
		if o.stylesheets != [2]bool{} {
			t.Error("blocked CSS reached configuration server")
		}
	} else if o.stylesheets != [2]bool{true, true} {
		t.Error("both configuration stylesheets must load")
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
		t.Logf("PASS native configuration noCSS=%t: independent SQL preview/apply/reload, AES-GCM, audit, no bearer/receiver/child, response privacy; login injected; renderer/B1 not admitted", o.noCSS)
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
	routeHealth                                func(context.Context) (plugin.HealthResponse, error)
	admitted, revokedLive                      bool
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
	r.step("start")
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
	r.step("probe")
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
	r.step("stop")
	err := r.Runtime.Stop(ctx, i)
	if err != nil {
		r.record(errors.New("real Stop failed"))
	}
	observation := r.absent()
	r.record(observation)
	r.stopped = err == nil && observation == nil
	return err
}

// Activation uses the real public Health method with the fixed supported ID.
// An arbitrary error is NOT evidence of route absence.
func (r *nativeTestRuntime) route(ctx context.Context, active bool) error {
	if r.routeHealth == nil {
		return errors.New("routing observation missing")
	}
	h, err := r.routeHealth(ctx)
	if active {
		if err == nil && h.Healthy && h.Message == "extension.ready" {
			return nil
		}
	} else if err != nil && err.Error() == "configured extension not found" && reflect.DeepEqual(h, plugin.HealthResponse{}) {
		return nil
	}
	return errors.New("active-route Health observation mismatch")
}
func (r *nativeTestRuntime) step(name string) {
	r.sequence = append(r.sequence, name)
	expected := []string{"start", "probe", "stop"}
	if r.routeHealth != nil {
		expected = []string{"start", "probe", "admit", "revoke", "stop"}
	}
	if len(r.sequence) > len(expected) || !reflect.DeepEqual(r.sequence, expected[:len(r.sequence)]) {
		r.record(errors.New("unexpected runtime sequence"))
	}
}
func (r *nativeTestRuntime) AdmitRouting(ctx context.Context, i extensionsadmin.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.step("admit")
	if r.routeHealth == nil {
		r.record(errors.New("unexpected routing admission"))
		return r.Runtime.AdmitRouting(ctx, i)
	}
	r.record(r.route(ctx, false))
	err := r.Runtime.AdmitRouting(ctx, i)
	if err != nil {
		r.record(errors.New("real AdmitRouting failed"))
	}
	live, route := r.live(), r.route(ctx, true)
	r.record(live)
	r.record(route)
	r.admitted = err == nil && live == nil && route == nil
	return err
}
func (r *nativeTestRuntime) RevokeRouting(ctx context.Context, i extensionsadmin.Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.step("revoke")
	if r.routeHealth == nil {
		r.record(errors.New("unexpected routing revocation"))
		return r.Runtime.RevokeRouting(ctx, i)
	}
	err := r.Runtime.RevokeRouting(ctx, i)
	if err != nil {
		r.record(errors.New("real RevokeRouting failed"))
	}
	// Critically observe route removal while the SAME child/socket are still live,
	// before returning control to Service.Disable's Stop call.
	route, live := r.route(ctx, false), r.live()
	r.record(route)
	r.record(live)
	r.revokedLive = err == nil && route == nil && live == nil
	return err
}

// Called under observer lock (or before installing the HTTP server).
func (r *nativeTestRuntime) phase(ctx context.Context, posts int) error {
	if r.failure != "" {
		return errors.New(r.failure)
	}
	expected := []string{"start", "probe", "stop"}
	if r.routeHealth != nil {
		if posts < 0 || posts > 2 {
			return errors.New("unknown activation phase")
		}
		if err := r.route(ctx, posts == 1); err != nil {
			return err
		}
		expected = []string{"start", "probe", "admit", "revoke", "stop"}
		if posts == 1 {
			expected = expected[:3]
			if err := r.live(); err != nil {
				return err
			}
		}
		if posts > 0 && !r.admitted {
			return errors.New("routing admission not independently observed")
		}
		if posts == 2 && !r.revokedLive {
			return errors.New("revocation before Stop not independently observed")
		}
	} else if posts < 0 || posts > 1 {
		return errors.New("unknown Test phase")
	}
	if posts == 0 {
		expected = nil
	}
	if !reflect.DeepEqual(r.sequence, expected) {
		return errors.New("runtime sequence incomplete")
	}
	if posts > 0 && (!r.liveStart || !r.liveProbe) {
		return errors.New("positive child proof incomplete")
	}
	if r.routeHealth == nil || posts != 1 {
		if err := r.absent(); err != nil {
			return err
		}
		if posts > 0 && !r.stopped {
			return errors.New("Stop proof incomplete")
		}
	}
	return nil
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

// Compare one activation transition, preserving every field not explicitly changed.
func activationSQL(before, after [4]string, actor, id string, enable bool) error {
	if before[1] != after[1] || before[2] != after[2] {
		return errors.New("activation changed secrets or previews")
	}
	var oldRows, rows, prior, events []map[string]any
	if json.Unmarshal([]byte(before[0]), &oldRows) != nil || json.Unmarshal([]byte(after[0]), &rows) != nil || len(oldRows) != 1 || len(rows) != 1 {
		return errors.New("activation instance cardinality")
	}
	old, row := oldRows[0], rows[0]
	from, to := "ready", "stopped"
	count, action := 4, "extension.disable"
	payload := map[string]any{"enabled": false, "routed": false}
	if enable {
		from, to = "stopped", "ready"
		count, action = 3, "extension.enable"
		payload = map[string]any{"routed": true, "health_code": "extension.ready"}
	}
	if old["configuration_revision"] != float64(2) || old["tested_revision"] != float64(2) || old["health_code"] != "extension.ready" || old["enabled"] != !enable || old["routed"] != !enable || old["lifecycle"] != from || row["enabled"] != enable || row["routed"] != enable || row["lifecycle"] != to {
		return errors.New("activation state delta mismatch")
	}
	for _, field := range []string{"enabled", "routed", "lifecycle", "updated_at"} {
		delete(old, field)
		delete(row, field)
	}
	if !reflect.DeepEqual(old, row) {
		return errors.New("activation changed configuration, readiness or authority")
	}
	if json.Unmarshal([]byte(before[3]), &prior) != nil || json.Unmarshal([]byte(after[3]), &events) != nil || len(prior) != count || len(events) != count+1 {
		return errors.New("activation audit cardinality")
	}
	remaining := map[any]map[string]any{}
	for _, event := range prior {
		remaining[event["id"]] = event
	}
	var added map[string]any
	for _, event := range events {
		if previous, ok := remaining[event["id"]]; ok {
			if !reflect.DeepEqual(previous, event) {
				return errors.New("activation changed prior audit")
			}
			delete(remaining, event["id"])
		} else if added == nil {
			added = event
		} else {
			return errors.New("extra activation audit")
		}
	}
	if len(remaining) != 0 || added == nil || added["action"] != action || added["actor_type"] != "oidc_subject" || added["actor_id"] != actor || added["resource_type"] != "extension" || added["resource_id"] != id || added["result"] != "success" {
		return errors.New("activation audit binding mismatch")
	}
	raw, ok := added["after_redacted_json"].(string)
	var got map[string]any
	if !ok || json.Unmarshal([]byte(raw), &got) != nil || !reflect.DeepEqual(got, payload) {
		return errors.New("activation audit payload mismatch")
	}
	return nil
}

func runConnectionBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE")
	activation := mode == "activation"
	rollback := mode == "rollback"
	update := mode == "update" || rollback
	var u *nativeUpdateOracle
	if update {
		if f.Update == nil {
			t.Fatal("missing verified B setup")
		}
		raw, err := os.ReadFile(f.MasterFile)
		acceptanceCheck(t, err)
		key, err := hex.DecodeString(string(raw))
		clear(raw)
		acceptanceCheck(t, err)
		defer clear(key)
		u = &nativeUpdateOracle{f: f, key: key}
	}
	actions := []string{"test"}
	if activation {
		actions = []string{"enable", "disable"}
	}
	if update {
		actions = []string{"update-preview", "update-apply"}
		if rollback {
			actions = []string{"rollback", "rollback"}
		}
	}
	if f.TestRuntime == nil {
		t.Fatal("missing real runtime observer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	acceptanceCheck(t, f.TestRuntime.phase(ctx, 0))
	cancel()
	var mu sync.Mutex
	posts := 0
	failure := ""
	applied := before
	if update {
		u.baseline = before
		if rollback {
			acceptanceCheck(t, rollbackSetup(f.Update.RollbackA, before))
			acceptanceCheck(t, u.secret(context.Background()))
		}
		acceptanceCheck(t, u.quiet(context.Background()))
	}
	reloads := 0
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
		if err := connectionBrowserRequest(r, detail); err != nil {
			fail(err.Error())
			return
		}
		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if posts >= len(actions) || r.URL.Path != detail || r.ParseForm() != nil || len(r.PostForm["action"]) != 1 || r.PostForm.Get("action") != actions[posts] {
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
		if err := connectionBrowserAssetResponse(r, rec); err != nil {
			fail(err.Error())
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
		runtimePhase := posts
		if update {
			runtimePhase = 0
		}
		if err := f.TestRuntime.phase(ctx, runtimePhase); err != nil {
			fail(err.Error())
			return
		}
		if posts == 0 {
			if state != before || len(f.TestRuntime.sequence) != 0 {
				fail("GET changed configured state")
				return
			}
		} else {
			if r.Method == "POST" {
				var delta error
				if update {
					if rollback {
						delta = rollbackSQL(f.Update.RollbackA, before, state, f.ActorID, f.ID, posts == 2)
						if delta == nil {
							delta = u.secret(ctx)
						}
					} else {
						delta = u.check(ctx, posts, state, body)
					}
				} else if activation {
					delta = activationSQL(applied, state, f.ActorID, f.ID, posts == 1)
				} else {
					delta = connectionSQL(before, state, f.ActorID, f.ID)
				}
				if delta != nil {
					fail(delta.Error())
					return
				}
				accepted := bytes.Contains(body, []byte("extension operation accepted"))
				if accepted == (rollback && posts == 1) {
					fail("native lifecycle acceptance/denial mismatch")
					return
				}
				applied = state
			} else if state != applied {
				fail("GET changed tested state")
				return
			}
		}
		if update {
			if err := u.quiet(ctx); err != nil {
				fail(err.Error())
				return
			}
			if posts == 2 && r.Method == "GET" && r.URL.Path == detail {
				reloads++
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
	input := map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": mode}
	if update {
		target, err := json.Marshal(f.Update.Target)
		acceptanceCheck(t, err)
		input["update_target"] = string(target)
	}
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
	if posts != len(actions) {
		t.Error("native lifecycle POST sequence incomplete")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	state, err := configurationSnapshot(ctx, f.DB)
	finalPhase := posts
	if update {
		finalPhase = 0
	}
	if phaseErr := f.TestRuntime.phase(ctx, finalPhase); phaseErr != nil {
		t.Error(phaseErr.Error())
	}
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
	if update && !t.Failed() {
		if reloads < 1 {
			t.Error("update reload missing")
			return
		}
		var diagnostic struct {
			UpdateGate   string
			RollbackGate string
			BrowserExit  struct{ Code int }
			Cleanup      struct {
				MainExited bool
				Remaining  []any
			}
		}
		decodeErr := json.Unmarshal(proof, &diagnostic)
		gate := diagnostic.UpdateGate
		if rollback {
			gate = diagnostic.RollbackGate
		}
		if decodeErr != nil || gate != "PASS" || !diagnostic.Cleanup.MainExited || len(diagnostic.Cleanup.Remaining) != 0 || diagnostic.BrowserExit.Code != 0 {
			t.Error("native update proof incomplete")
			return
		}
		t.Logf("native %s SQL/proof frozen; browser/HTTP stopped; separate execution NOT YET proven", mode)
		if err := nativeCombinedResult(gate == "PASS", u.testB(t, applied)); err != nil {
			t.Error(err.Error())
			return
		}
		t.Logf("PASS combined native %s/reload plus separately labeled nonbrowser Service.Test; no routing/delivery credit", mode)
		return
	}
	if !t.Failed() {
		t.Logf("PASS native %s: posts=%d; positive ordered runtime and route observations; real child pid=%s executable_sha256=%x private socket; stopped/disabled/unrouted; SQL/audit/secret retention/privacy; receiver quiet; login injected", mode, posts, f.TestRuntime.pid, f.TestRuntime.expectedSHA)
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

func TestNativeActivationRouteOracle(t *testing.T) {
	for _, tc := range []struct {
		name             string
		active, healthy  bool
		message, failure string
		pass             bool
	}{
		{"absent", false, false, "", "configured extension not found", true},
		{"active", true, true, "extension.ready", "", true},
		{"timeout", false, false, "", "context deadline exceeded", false},
		{"blocked", false, false, "extension.runtime-blocked", "configured extension not found", false},
		{"unhealthy", true, false, "extension.ready", "", false},
		{"auth-error", true, true, "extension.ready", "unauthenticated", false},
		{"wrong-code", true, true, "extension.unknown", "", false},
		{"nil-negative", false, false, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &nativeTestRuntime{routeHealth: func(context.Context) (plugin.HealthResponse, error) {
				var err error
				if tc.failure != "" {
					err = errors.New(tc.failure)
				}
				return plugin.HealthResponse{Healthy: tc.healthy, Message: tc.message}, err
			}}
			if (r.route(context.Background(), tc.active) == nil) != tc.pass {
				t.Fatal("route oracle accepted wrong evidence")
			}
		})
	}
}
func TestNativeActivationObserverPreservesDelegate(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "observation-fails", true: "delegate-fails"}[failed], func(t *testing.T) {
			var want error
			if failed {
				want = errors.New("synthetic failure")
			}
			d := &nativeTestDelegate{result: want, health: extensionsadmin.Health{Healthy: true, Code: "extension.ready"}}
			r := &nativeTestRuntime{Runtime: d, root: "/nonexistent-native-activation", routeHealth: func(context.Context) (plugin.HealthResponse, error) {
				return plugin.HealthResponse{}, errors.New("configured extension not found")
			}}
			ctx := context.Background()
			i := extensionsadmin.Instance{}
			if r.Start(ctx, i, nil) != want {
				t.Fatal("Start changed")
			}
			h, err := r.Probe(ctx, i)
			if h != d.health || err != want {
				t.Fatal("Probe changed")
			}
			if r.AdmitRouting(ctx, i) != want || r.RevokeRouting(ctx, i) != want || r.Stop(ctx, i) != want {
				t.Fatal("routing/cleanup result changed")
			}
			if !reflect.DeepEqual(d.calls, []string{"start", "probe", "admit", "revoke", "stop"}) || r.failure == "" || r.admitted || r.revokedLive || r.stopped {
				t.Fatal("observation fabricated or cleanup suppressed")
			}
		})
	}
	for _, sequence := range [][]string{{"start", "probe", "admit", "revoke", "stop"}, {"start", "probe", "stop", "revoke"}, {"admit"}, {"start", "start"}, {"start", "probe", "admit", "revoke", "stop", "stop"}} {
		r := &nativeTestRuntime{routeHealth: func(context.Context) (plugin.HealthResponse, error) { return plugin.HealthResponse{}, nil }}
		for _, call := range sequence {
			r.step(call)
		}
		if (r.failure == "") != reflect.DeepEqual(sequence, []string{"start", "probe", "admit", "revoke", "stop"}) {
			t.Fatal("sequence guard mismatch")
		}
	}
}
func TestNativeActivationSQLDelta(t *testing.T) {
	encode := func(v any) string { b, err := json.Marshal(v); acceptanceCheck(t, err); return string(b) }
	for _, enable := range []bool{true, false} {
		for _, kind := range []string{"valid", "configuration", "grant", "readiness", "health", "secret", "preview", "enabled", "routed", "lifecycle", "actor", "resource", "action", "payload", "prior-audit", "extra-audit"} {
			t.Run(map[bool]string{true: "enable/", false: "disable/"}[enable]+kind, func(t *testing.T) {
				from, to := "ready", "stopped"
				action := "extension.disable"
				count := 4
				payload := map[string]any{"enabled": false, "routed": false}
				if enable {
					from, to = "stopped", "ready"
					action = "extension.enable"
					count = 3
					payload = map[string]any{"routed": true, "health_code": "extension.ready"}
				}
				old := map[string]any{"configuration_revision": 2, "tested_revision": 2, "health_code": "extension.ready", "enabled": !enable, "routed": !enable, "lifecycle": from, "configuration_json": "fixed", "grant_digest": "bound", "updated_at": "before"}
				row := map[string]any{}
				for k, v := range old {
					row[k] = v
				}
				row["enabled"] = enable
				row["routed"] = enable
				row["lifecycle"] = to
				row["updated_at"] = "after"
				prior := []any{}
				for n := 0; n < count; n++ {
					prior = append(prior, map[string]any{"id": n, "action": "setup"})
				}
				event := map[string]any{"id": 99, "action": action, "actor_type": "oidc_subject", "actor_id": "actor", "resource_type": "extension", "resource_id": "instance", "result": "success", "after_redacted_json": encode(payload)}
				before := [4]string{encode([]any{old}), "ciphertext", "consumed", encode(prior)}
				after := [4]string{"", "ciphertext", "consumed", ""}
				switch kind {
				case "configuration":
					row["configuration_json"] = "changed"
				case "grant":
					row["grant_digest"] = "changed"
				case "readiness":
					row["tested_revision"] = nil
				case "health":
					row["health_code"] = "changed"
				case "secret":
					after[1] = "changed"
				case "preview":
					after[2] = "changed"
				case "enabled":
					row["enabled"] = !enable
				case "routed":
					row["routed"] = !enable
				case "lifecycle":
					row["lifecycle"] = from
				case "actor":
					event["actor_id"] = "other"
				case "resource":
					event["resource_id"] = "other"
				case "action":
					event["action"] = "extension.test"
				case "payload":
					event["after_redacted_json"] = "{}"
				case "prior-audit":
					prior[0] = map[string]any{"id": 0, "action": "changed"}
				}
				events := append(prior, event)
				if kind == "extra-audit" {
					events = append(events, event)
				}
				after[0] = encode([]any{row})
				after[3] = encode(events)
				if (activationSQL(before, after, "actor", "instance", enable) == nil) != (kind == "valid") {
					t.Fatal("activation SQL accepted corruption or rejected valid transition")
				}
			})
		}
	}
}

func TestInventoryBrowserRunnerMode(t *testing.T) {
	script := "../../scripts/extensions-browser-acceptance.sh"
	// Missing paths stop before tools: supported mode reaches path validation1,
	// while an unrecognized mode or forbidden sixth argument returns usage2.
	cmd := exec.Command("bash", script, "/missing-binary", "/missing-archive", "/missing-pg", "/missing-output", "inventory")
	err := cmd.Run()
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 1 {
		t.Fatalf("inventory mode not admitted by argument parser: %v", err)
	}
	cmd = exec.Command("bash", script, "/missing-binary", "/missing-archive", "/missing-pg", "/missing-output", "inventory", "/extra-B")
	err = cmd.Run()
	if !errors.As(err, &status) || status.ExitCode() != 2 {
		t.Fatal("inventory accepted sixth argument")
	}
}

func TestInventoryBrowserCloseout(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		if os.Getenv("GOTTH_RENDERER_REQUIRE_NODE") == "1" {
			t.Fatal(err)
		}
		t.Skip("Node test equipment unavailable")
	}
	const harness = `const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events'),path=require('node:path');
const original=fs.readFileSync(process.argv[1],'utf8');assert.equal(original.split('await runMatrix();').length,2);
const source=original.replace('await runMatrix();','/* only the matrix is omitted in this synthetic closeout test */');
for(const mode of ['normal','signal','data-after-exit','non-get-after-exit','undrained']){
 let proof,removed=false;const child=new EventEmitter(),proc=new EventEmitter();child.pid=100;
 child.stderr=new EventEmitter();child.stderr.destroy=()=>{};
 child.stdio=[null,null,child.stderr,new EventEmitter(),new EventEmitter()];for(const p of child.stdio.slice(3))p.destroy=()=>{};
 child.stdio[3].write=data=>{const request=JSON.parse(data.slice(0,-1));assert.equal(request.method,'Browser.close');queueMicrotask(()=>{
  if(mode==='signal')proc.emit('SIGTERM');child.emit('exit',0,null);
  if(mode==='data-after-exit')child.stdio[4].emit('data',Buffer.from(JSON.stringify({method:'Browser.downloadWillBegin',params:{}})+String.fromCharCode(0)));
  if(mode==='non-get-after-exit')child.stdio[4].emit('data',Buffer.from(JSON.stringify({method:'Network.requestWillBeSent',params:{request:{url:'http://127.0.0.1:123/admin/extensions',method:'POST',headers:{}}}})+String.fromCharCode(0)));
  if(mode!=='undrained')child.emit('close',0,null);
 });return true};
 child.kill=()=>{};proc.argv=['node','driver','/evidence'];proc.env={GOTTH_MAIL_ACCEPTANCE_NAMESPACE:'1'};proc.kill=()=>{};
 const mockFS={readFileSync(p){if(p===0)return JSON.stringify({origin:'http://127.0.0.1:123',mode:'inventory',id:'00000000-0000-4000-8000-000000000001',session:'private-session',csrf:'private-csrf'});throw Error('unexpected file read')},writeFileSync(p,s){proof=JSON.parse(s)},mkdirSync(){},mkdtempSync(){return '/tmp/private-profile'},readdirSync(){return []},rmSync(){removed=true}};
 const context=vm.createContext({process:proc,Buffer,URL,console:{log(){}},setTimeout,clearTimeout});const module=new vm.SourceTextModule(source,{context});
 await module.link(async name=>{let exports;if(name==='node:crypto')exports={createHash:require('node:crypto').createHash};else if(name==='node:child_process')exports={spawn:()=>child};else if(name==='node:fs')exports=mockFS;else if(name==='node:path')exports={join:path.join,resolve:path.resolve};else if(name==='node:timers/promises')exports={setTimeout:()=>new Promise(r=>setTimeout(r,2))};else throw Error('unexpected import');return new vm.SyntheticModule(Object.keys(exports),function(){for(const [k,v]of Object.entries(exports))this.setExport(k,v)},{context})});
 await module.evaluate();assert.equal(proof.gate,mode==='normal'?'PASS':'FAIL');assert.equal(removed,mode!=='undrained');if(mode!=='normal')assert.equal(proc.exitCode,1);assert(!JSON.stringify(proof).includes('private-session'));
}
console.log('PASS actual driver handlers/publication: normal, close signal, late data/non-GET after exit, missing stdio drain; synthetic matrix omitted, not physical proof');
`
	cmd := exec.Command("node", "--experimental-vm-modules", "--input-type=module", "-e", "import {createRequire} from \"node:module\"; const require=createRequire(import.meta.url);\n"+harness, "../../scripts/extensions-inventory-browser.mjs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("closeout harness: %v\n%s", err, out)
	}
	t.Log(string(out))
}

// Dedicated test equipment; never installed in the production router.
// Phase is Go-owned and changed only between fully drained driver invocations.
type inventoryPolicyHandler struct {
	handler                                 http.Handler
	host, session, csrf                     string
	provision                               atomic.Bool
	cookies, authorization, methods, routes atomic.Int32
	injections, full, hx                    atomic.Int32
}

func (o *inventoryPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Header["Cookie"]; ok {
		o.cookies.Add(1)
		http.Error(w, "browser cookie forbidden", 400)
		return
	}
	if _, ok := r.Header["Authorization"]; ok {
		o.authorization.Add(1)
		http.Error(w, "browser authorization forbidden", 400)
		return
	}
	if r.Method != http.MethodGet {
		o.methods.Add(1)
		http.Error(w, "GET only", 400)
		return
	}
	inventory := false
	switch r.RequestURI {
	case "/admin/extensions", "/admin/extensions?theme=system", "/admin/extensions?theme=light", "/admin/extensions?theme=dark":
		inventory = true
	case "/admin/extensions/assets/tokens.css", "/admin/extensions/assets/inventory.css", "/admin/extensions/assets/inventory.js", "/admin/extensions/assets/htmx-2.0.10.min.js":
	default:
		o.routes.Add(1)
		http.NotFound(w, r)
		return
	}
	if r.Host != o.host || r.URL.IsAbs() {
		o.routes.Add(1)
		http.NotFound(w, r)
		return
	}
	if inventory {
		if r.Header.Get("HX-Request") == "true" {
			o.hx.Add(1)
		} else {
			o.full.Add(1)
		}
		if o.provision.Load() {
			r = r.Clone(r.Context())
			r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: o.session})
			r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: o.csrf})
			o.injections.Add(1)
		}
	}
	o.handler.ServeHTTP(w, r)
}

func TestInventoryPolicyHandler(t *testing.T) {
	for _, tc := range []struct {
		name, method, uri, header, host string
		enabled, admitted, injected     bool
	}{
		{name: "negative", method: "GET", uri: "/admin/extensions", admitted: true},
		{name: "provisioned", method: "GET", uri: "/admin/extensions?theme=light", enabled: true, admitted: true, injected: true},
		{name: "asset", method: "GET", uri: "/admin/extensions/assets/inventory.js", enabled: true, admitted: true},
		{name: "cookie", method: "GET", uri: "/admin/extensions", header: "Cookie"},
		{name: "authorization", method: "GET", uri: "/admin/extensions", header: "Authorization"},
		{name: "post", method: "POST", uri: "/admin/extensions"},
		{name: "host", method: "GET", uri: "/admin/extensions", host: "other"},
		{name: "detail", method: "GET", uri: "/admin/extensions/id"},
		{name: "query", method: "GET", uri: "/admin/extensions?unknown=x"},
		{name: "encoded", method: "GET", uri: "/admin/%65xtensions"},
		{name: "delimiter", method: "GET", uri: "/admin/extensions?"},
		{name: "absolute", method: "GET", uri: "http://127.0.0.1:123/admin/extensions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			o := &inventoryPolicyHandler{host: "127.0.0.1:123", session: "synthetic-session", csrf: "synthetic-csrf"}
			o.provision.Store(tc.enabled)
			o.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				cookies := r.Cookies()
				if tc.injected {
					if len(cookies) != 2 || cookies[0].Value != o.session || cookies[1].Value != o.csrf {
						t.Error("injected pair differs")
					}
				} else if len(cookies) != 0 {
					t.Error("unexpected injection")
				}
			})
			r := httptest.NewRequest(tc.method, tc.uri, nil)
			r.Host = o.host
			if tc.host != "" {
				r.Host = tc.host
			}
			if tc.header != "" {
				r.Header[tc.header] = []string{""}
			}
			o.ServeHTTP(httptest.NewRecorder(), r)
			if called != tc.admitted || len(r.Cookies()) != 0 {
				t.Fatal("guard or request-clone boundary violated")
			}
		})
	}
}

func runInventoryPolicyBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	// Preserve actual handler paired-cookie denial, independent of the wrapper.
	for _, wrong := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/admin/extensions", nil)
		r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: f.Session})
		if wrong {
			r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: "invalid-synthetic-pair"})
		}
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, r)
		if rec.Code != 401 || bytes.Contains(rec.Body.Bytes(), []byte("data-extension-id")) {
			t.Fatal("real paired-cookie negative regression")
		}
	}
	t.Log("real handler missing-pair and wrong-pair denied401")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	o := &inventoryPolicyHandler{handler: f.Handler, host: listener.Addr().String(), session: f.Session, csrf: f.CSRF}
	srv := &http.Server{Handler: o, ReadHeaderTimeout: 3 * time.Second}
	served := make(chan error, 1)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Error("policy listener shutdown")
			_ = srv.Close()
		}
		if err := <-served; err != nil && err != http.ErrServerClosed {
			t.Error("policy listener serve")
		}
	})
	go func() { served <- srv.Serve(listener) }()
	// One shared 90s budget for all three bounded policy driver invocations.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, stage := range []string{"before", "provisioned", "after"} {
		o.provision.Store(stage == "provisioned")
		input := map[string]string{"origin": "http://" + o.host, "id": f.ID, "pin": "sha256:" + acceptanceArchiveSHA, "mode": "inventory", "policyStage": stage}
		raw, err := json.Marshal(input)
		acceptanceCheck(t, err)
		cmd := exec.CommandContext(ctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT")+"-policy-"+stage)
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 20 * time.Second
		if err := cmd.Run(); err != nil {
			t.Errorf("policy %s driver failed: %v", stage, err)
			break
		}
	}
	o.provision.Store(false)
	if o.cookies.Load() != 0 || o.authorization.Load() != 0 || o.methods.Load() != 0 || o.routes.Load() != 0 {
		t.Error("policy listener request boundary violation")
	}
	if !t.Failed() && (o.full.Load() != 4 || o.hx.Load() != 1 || o.injections.Load() != 3) {
		t.Error("policy separate full/HX/injection counts differ")
	}
	t.Logf("policy counters full %d HX %d injected %d cookie %d bearer %d methods %d routes %d", o.full.Load(), o.hx.Load(), o.injections.Load(), o.cookies.Load(), o.authorization.Load(), o.methods.Load(), o.routes.Load())
}

// Closed request-policy regression: a delegated response sentinel proves allowed
// requests crossed the route guard; no SQL acceptance is inferred from it.
func TestConfigurationBrowserRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		phase              int
		allow              bool
	}{
		{"empty", "GET", "/admin/extensions/id", 0, true},
		{"system", "POST", "/admin/extensions/id?theme=system", 0, true},
		{"light", "POST", "/admin/extensions/id?theme=light", 0, true},
		{"dark", "POST", "/admin/extensions/id?theme=dark", 0, true},
		{"tokens", "GET", "/admin/extensions/assets/tokens.css", 0, true},
		{"detail-css-preview", "GET", "/admin/extensions/assets/detail.css", 1, true},
		{"tokens-after", "GET", "/admin/extensions/assets/tokens.css", 2, true},
		{"unknown-theme", "GET", "/admin/extensions/id?theme=other", 0, false},
		{"duplicate", "GET", "/admin/extensions/id?theme=dark&theme=dark", 0, false},
		{"mixed", "GET", "/admin/extensions/id?theme=dark&action=enable", 0, false},
		{"encoded", "GET", "/admin/extensions/id?%74heme=dark", 0, false},
		{"authority", "GET", "/admin/extensions/id?csrf_token=secret", 0, false},
		{"inventory-query", "GET", "/admin/extensions?theme=dark", 0, false},
		{"favicon-query", "GET", "/favicon.ico?theme=dark", 0, false},
		{"asset-query", "GET", "/admin/extensions/assets/detail.css?theme=dark", 0, false},
		{"asset-post", "POST", "/admin/extensions/assets/detail.css", 0, false},
		{"asset-head", "HEAD", "/admin/extensions/assets/tokens.css", 0, false},
		{"asset-prefix", "GET", "/admin/extensions/assets/detail.css/extra", 0, false},
		{"vendor", "GET", "/admin/extensions/assets/htmx.js", 0, false},
		{"page-beforeapply", "GET", "/admin/extensions/id?theme=dark", 1, false},
		{"inventory-beforeapply", "GET", "/admin/extensions", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			o := &configurationBrowserOracle{phase: tc.phase, f: acceptanceBrowserStart{ID: "id", Secret: "private-canary", Session: "session-canary", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				_, _ = io.WriteString(w, "private-canary")
			})}}
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("action=configure-preview"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			o.ServeHTTP(w, req)
			if invoked != tc.allow || w.Code != 500 || o.failure == "" {
				t.Fatal("closed policy mismatch")
			}
			if tc.allow && o.failure != "response secret leak or fixture size exceeded" {
				t.Fatal("allowed request skipped response privacy barrier")
			}
			if o.phase != tc.phase || o.reloads != 0 {
				t.Fatal("rejected/asset request advanced phase")
			}
		})
	}
}

func TestConfigurationBrowserCSSBarrier(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	baseline, err := configurationSnapshot(context.Background(), db)
	acceptanceCheck(t, err)
	for _, tc := range []struct {
		name                       string
		phase                      int
		status                     int
		mime, cache, nosniff, body string
		bearer, ok                 bool
	}{
		{"initial", 0, 200, "text/css; charset=utf-8", "no-store", "nosniff", "body{}", false, true},
		{"after-apply", 2, 200, "text/css; charset=utf-8", "no-store", "nosniff", "body{}", false, true},
		{"wrong-status", 0, 404, "text/css; charset=utf-8", "no-store", "nosniff", "body{}", false, false},
		{"wrong-MIME", 0, 200, "text/html", "no-store", "nosniff", "body{}", false, false},
		{"cache", 0, 200, "text/css; charset=utf-8", "public", "nosniff", "body{}", false, false},
		{"sniff", 0, 200, "text/css; charset=utf-8", "no-store", "", "body{}", false, false},
		{"secret", 0, 200, "text/css; charset=utf-8", "no-store", "nosniff", "secret-canary", false, false},
		{"session", 0, 200, "text/css; charset=utf-8", "no-store", "nosniff", "session-canary", false, false},
		{"size", 0, 200, "text/css; charset=utf-8", "no-store", "nosniff", strings.Repeat("x", (1<<20)+1), false, false},
		{"bearer", 0, 200, "text/css; charset=utf-8", "no-store", "nosniff", "body{}", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &configurationBrowserOracle{phase: tc.phase, baseline: baseline, applied: baseline, f: acceptanceBrowserStart{ID: "id", DB: db, Secret: "secret-canary", Session: "session-canary", RuntimeRoot: t.TempDir(), Executable: "/nonexistent/fixture", Requests: func() int32 { return 0 }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.mime)
				w.Header().Set("Cache-Control", tc.cache)
				w.Header().Set("X-Content-Type-Options", tc.nosniff)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})}}
			for _, path := range []string{"/admin/extensions/assets/tokens.css", "/admin/extensions/assets/detail.css"} {
				r := httptest.NewRequest("GET", path, nil)
				if tc.bearer {
					r.Header.Set("Authorization", "Bearer synthetic")
				}
				w := httptest.NewRecorder()
				o.ServeHTTP(w, r)
				if (w.Code == 200) != tc.ok {
					t.Fatal("CSS gate mismatch")
				}
			}
			if o.phase != tc.phase || o.posts != 0 || o.reloads != 0 {
				t.Fatal("CSS credited phase/post/reload")
			}
			if tc.ok && o.stylesheets != [2]bool{true, true} {
				t.Fatal("successful CSS not recorded")
			}
			if !tc.ok && o.stylesheets != [2]bool{} {
				t.Fatal("failed CSS credited")
			}
			after, err := configurationSnapshot(context.Background(), db)
			acceptanceCheck(t, err)
			if baseline != after {
				t.Fatal("CSS changed SQL")
			}
		})
	}
}

// SETUP only: configure through the service, add an independently encrypted
// retained slot and an unrelated configured instance. No native-action credit.
func secretsBrowserSetup(t *testing.T, f acceptanceBrowserStart, key []byte) {
	t.Helper()
	ctx := context.Background()
	svc, err := extensionsadmin.NewService(f.DB, key, nil)
	acceptanceCheck(t, err)
	actor := audit.ActorRef{Type: "oidc_subject", ID: f.ActorID}
	input := extensionsadmin.ConfigureInput{Configuration: map[string]any{"webhook.endpoint": f.Endpoint, "webhook.timeout-seconds": 2}, Secrets: map[string]string{"webhook.hmac-key": f.Secret}}
	configure := func(id string) {
		p, e := svc.PreviewConfigure(ctx, actor, id, input)
		acceptanceCheck(t, e)
		_, e = svc.ApplyConfigure(ctx, actor, id, p.ID, p.Confirmation, input)
		acceptanceCheck(t, e)
	}
	configure(f.ID)
	item := f.Current()
	other := acceptanceUUID(t)
	_, err = svc.Install(ctx, actor, extensionsadmin.InstallRequest{InstanceID: other, ExtensionID: "notification.d3-survivor", Repository: item.Repository, ArtifactPin: item.ArtifactPin, ManifestDigest: item.ManifestDigest, GrantDigest: item.GrantDigest, SessionDigest: item.SessionDigest, Capabilities: item.Capabilities, Interfaces: item.Interfaces, SecretSlots: item.SecretSlots, Metadata: item.Metadata})
	acceptanceCheck(t, err)
	configure(other)
	_, err = svc.PreviewDeleteSecrets(ctx, actor, other)
	acceptanceCheck(t, err)
	block, err := aes.NewCipher(key)
	acceptanceCheck(t, err)
	gcm, err := cipher.NewGCM(block)
	acceptanceCheck(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	acceptanceCheck(t, err)
	slot := "retained.d3-key"
	encrypted := gcm.Seal(nil, nonce, []byte(f.Secret), []byte(f.ID+"\x00"+slot))
	_, err = f.DB.Exec("INSERT INTO extension_secrets(instance_id,slot,nonce,ciphertext,key_version,configured_at,rotated_at) VALUES($1,$2,$3,$4,1,now(),now())", f.ID, slot, nonce, encrypted)
	acceptanceCheck(t, err)
	_, err = f.DB.Exec("UPDATE extension_instances SET tested_revision=configuration_revision,health_code='extension.ready' WHERE instance_id=$1", f.ID)
	acceptanceCheck(t, err)
	var count int
	acceptanceCheck(t, f.DB.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", f.ID).Scan(&count))
	if count != 2 || item.Enabled || item.Routed {
		t.Fatal("D3 setup not disabled/current+retained")
	}
}

// Concrete fixed four-table comparison; all decoded row material stays in memory.
// Time O(B+N*N), space O(B+N), excluding JSON delegates; not a production abstraction.
func secretsBrowserDelta(before, after [4]string, action, actor, id, previewID, phrase string, key []byte) error {
	var a, b [4][]map[string]any
	for i := range a {
		if json.Unmarshal([]byte(before[i]), &a[i]) != nil || json.Unmarshal([]byte(after[i]), &b[i]) != nil {
			return errors.New("D3 SQL decode")
		}
	}
	if action == "denied" || action == "read" {
		if before != after {
			return errors.New("D3 denial/read mutated SQL")
		}
		return nil
	}
	if action == "preview" {
		for _, i := range []int{0, 1, 3} {
			if before[i] != after[i] {
				return errors.New("D3 preview authoritative mutation")
			}
		}
		if len(b[2]) != len(a[2])+1 {
			return errors.New("D3 preview cardinality")
		}
		old := map[string]map[string]any{}
		for _, r := range a[2] {
			old[r["id"].(string)] = r
		}
		var added map[string]any
		for _, r := range b[2] {
			if prior, ok := old[r["id"].(string)]; ok {
				if !reflect.DeepEqual(prior, r) {
					return errors.New("D3 prior preview changed")
				}
				delete(old, r["id"].(string))
			} else {
				if added != nil {
					return errors.New("D3 extra preview")
				}
				added = r
			}
		}
		if len(old) != 0 || added == nil || added["id"] != previewID || added["instance_id"] != id || added["operation"] != "delete_secrets" || added["actor_type"] != "oidc_subject" || added["actor_id"] != actor || added["consumed_at"] != nil || !reflect.DeepEqual(added["payload_json"], map[string]any{}) {
			return errors.New("D3 preview binding")
		}
		var revision any
		for _, r := range a[0] {
			if r["instance_id"] == id {
				revision = r["configuration_revision"]
			}
		}
		digest := sha256.Sum256([]byte("{}"))
		mac := hmac.New(sha256.New, key)
		empty := hex.EncodeToString(mac.Sum(nil))
		mac.Write([]byte("extension-preview-confirmation\x00" + phrase))
		if revision == nil || added["base_revision"] != revision || added["payload_sha256"] != hex.EncodeToString(digest[:]) || added["secret_binding_sha256"] != empty || added["confirmation_sha256"] != hex.EncodeToString(mac.Sum(nil)) {
			return errors.New("D3 preview digest")
		}
		created, e1 := time.Parse("2006-01-02T15:04:05.999999", added["created_at"].(string))
		expires, e2 := time.Parse("2006-01-02T15:04:05.999999", added["expires_at"].(string))
		if e1 != nil || e2 != nil || !expires.After(time.Now().UTC()) || !expires.After(created) {
			return errors.New("D3 preview expiry")
		}
		return nil
	}
	if action != "apply" {
		return errors.New("D3 unknown delta")
	}
	if len(a[0]) != 2 || len(b[0]) != 2 {
		return errors.New("D3 registry cardinality")
	}
	chosen := false
	for _, r := range b[0] {
		var prior map[string]any
		for _, p := range a[0] {
			if p["instance_id"] == r["instance_id"] {
				prior = p
			}
		}
		if prior == nil {
			return errors.New("D3 registry identity")
		}
		if r["instance_id"] == id {
			chosen = true
			if prior["enabled"] != false || prior["routed"] != false || r["configuration_revision"] != prior["configuration_revision"].(float64)+1 || r["tested_revision"] != nil || r["health_code"] != "extension.unknown" {
				return errors.New("D3 revision/health")
			}
			for _, k := range []string{"configuration_revision", "tested_revision", "health_code", "updated_at"} {
				delete(prior, k)
				delete(r, k)
			}
		}
		if !reflect.DeepEqual(prior, r) {
			return errors.New("D3 registry/survivor changed")
		}
	}
	if !chosen {
		return errors.New("D3 chosen registry missing")
	}
	survivors := []map[string]any{}
	removed := 0
	for _, r := range a[1] {
		if r["instance_id"] == id {
			removed++
		} else {
			survivors = append(survivors, r)
		}
	}
	if removed != 2 || !reflect.DeepEqual(survivors, b[1]) {
		return errors.New("D3 current/retained/survivor secrets")
	}
	if len(a[2]) != len(b[2]) {
		return errors.New("D3 preview count changed")
	}
	consumed := false
	for _, r := range b[2] {
		var prior map[string]any
		for _, p := range a[2] {
			if p["id"] == r["id"] {
				prior = p
			}
		}
		if prior == nil {
			return errors.New("D3 preview replaced")
		}
		if r["id"] == previewID {
			consumed = true
			if prior["consumed_at"] != nil || r["consumed_at"] == nil {
				return errors.New("D3 preview consumption")
			}
			delete(prior, "consumed_at")
			delete(r, "consumed_at")
		}
		if !reflect.DeepEqual(prior, r) {
			return errors.New("D3 older preview changed")
		}
	}
	if !consumed {
		return errors.New("D3 selected preview missing")
	}
	return updateAudit(before[3], after[3], actor, id, "extension.secrets.delete", map[string]any{"deleted_secret_slots": "[REDACTED]"})
}

// Fixed identity-table oracle; JSON stays in memory. O(B) time/space plus SQL.
func recoveryIdentitySnapshot(ctx context.Context, db *sql.DB) ([4]string, error) {
	var out [4]string
	for i, table := range []string{"tokens", "sessions", "identity_refs", "role_bindings"} {
		if err := db.QueryRowContext(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb)::text FROM "+table+" t").Scan(&out[i]); err != nil {
			return out, errors.New("recovery identity snapshot")
		}
	}
	return out, nil
}

type secretsBrowserOracle struct {
	recovery       bool
	noCSS          bool
	authority      string
	identity       [4]string
	f              acceptanceBrowserStart
	key            []byte
	mu             sync.Mutex
	posts, reloads int
	failure        string
	state          [4]string
	styles         [2]bool
	previewID      string
}

func (o *secretsBrowserOracle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fail := func(s string) {
		if o.failure == "" {
			o.failure = s
		}
		http.Error(w, "secret deletion fixture failed", 500)
	}
	if o.failure != "" {
		fail(o.failure)
		return
	}
	if r.Header.Get("Authorization") != "" {
		fail("D3 bearer forbidden")
		return
	}
	detail := "/admin/extensions/" + o.f.ID
	asset := -1
	if r.URL.Path == "/admin/extensions/assets/tokens.css" {
		asset = 0
	}
	if r.URL.Path == "/admin/extensions/assets/detail.css" {
		asset = 1
	}
	if o.noCSS && (asset >= 0 || r.Host != o.authority || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.ForceQuery) {
		fail("recovery no-CSS request crossed transport boundary")
		return
	}
	queryOK := r.URL.RawQuery == ""
	if r.URL.Path == detail {
		switch r.URL.RawQuery {
		case "theme=system", "theme=light", "theme=dark":
			queryOK = true
		}
	}
	favicon := r.URL.Path == "/favicon.ico" && r.Method == "GET"
	if !queryOK || (asset >= 0 && r.Method != "GET") || (r.URL.Path != detail && r.URL.Path != "/admin/extensions" && !favicon && asset < 0) {
		fail("D3 unexpected route")
		return
	}
	action := "read"
	previewID := ""
	if r.Method == "POST" {
		limit := 5
		if o.recovery {
			limit = 2
		}
		if r.URL.Path != detail || o.posts >= limit {
			fail("D3 unexpected POST")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.ParseForm() != nil {
			fail("D3 bad form")
			return
		}
		sequence := []string{"secrets-delete-preview", "secrets-delete-preview", "secrets-delete-apply", "secrets-delete-preview", "secrets-delete-apply"}
		if o.recovery {
			sequence = []string{"secrets-delete-preview", "secrets-delete-apply"}
		}
		expected := sequence[o.posts]
		if r.PostForm.Get("action") != expected {
			fail("D3 unexpected action/phase")
			return
		}
		action = "preview"
		if !o.recovery && o.posts == 2 {
			action = "denied"
		}
		if (!o.recovery && o.posts == 4) || (o.recovery && o.posts == 1) {
			action = "apply"
		}
		previewID = r.PostForm.Get("preview_id")
		if action != "preview" && (o.previewID == "" || previewID != o.previewID) {
			fail("D3 Apply preview not latest rendered")
			return
		}
	} else if r.Method != "GET" || (o.posts > 0 && ((!o.recovery && o.posts < 5) || (o.recovery && o.posts < 2)) && asset < 0 && !favicon) {
		fail("D3 unexpected GET/method")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	o.f.Handler.ServeHTTP(rec, r.WithContext(ctx))
	body := rec.Body.Bytes()
	if len(body) > 1<<20 || bytes.Contains(body, []byte(o.f.Secret)) || bytes.Contains(body, []byte(o.f.Session)) {
		fail("D3 response privacy")
		return
	}
	want := 200
	if r.URL.Path == "/admin/extensions" {
		want = 401
	}
	if favicon {
		want = 404
	}
	if rec.Code != want {
		fail("D3 response status")
		return
	}
	if asset >= 0 && (rec.Header().Get("Content-Type") != "text/css; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff") {
		fail("D3 CSS privacy")
		return
	}
	phrase := ""
	if action == "preview" {
		p := regexp.MustCompile("name=\"preview_id\" value=\"([^\"]+)\"").FindSubmatch(body)
		c := regexp.MustCompile("<code>(confirm-[a-f0-9]{32})</code>").FindSubmatch(body)
		if len(p) != 2 || len(c) != 2 {
			fail("D3 rendered preview missing")
			return
		}
		previewID = string(p[1])
		phrase = string(c[1])
	}
	state, err := configurationSnapshot(ctx, o.f.DB)
	if err != nil {
		fail(err.Error())
		return
	}
	if o.recovery {
		identity, e := recoveryIdentitySnapshot(ctx, o.f.DB)
		if e != nil || identity != o.identity {
			fail("recovery identity mutation")
			return
		}
		if r.URL.Path == detail && (!bytes.Contains(body, []byte("Extension recovery")) || bytes.Contains(body, []byte("recovery-metadata-canary")) || bytes.Contains(body, []byte(`id="configuration"`))) {
			fail("recovery projection")
			return
		}
	}
	if err = secretsBrowserDelta(o.state, state, action, o.f.ActorID, o.f.ID, previewID, phrase, o.key); err != nil {
		fail(err.Error())
		return
	}
	for _, s := range state {
		for _, v := range []string{o.f.Secret, o.f.Session, o.f.CSRF} {
			if v != "" && strings.Contains(s, v) {
				fail("D3 SQL plaintext leak")
				return
			}
		}
	}
	quiet := configurationBrowserOracle{f: o.f}
	if err = quiet.quiet(); err != nil {
		fail(err.Error())
		return
	}
	if r.Method == "POST" {
		accepted := bytes.Contains(body, []byte("extension operation accepted"))
		if accepted == (action == "denied") {
			fail("D3 acceptance/denial projection")
			return
		}
		o.posts++
	}
	if asset >= 0 {
		o.styles[asset] = true
	}
	if r.Method == "GET" && r.URL.Path == detail && ((!o.recovery && o.posts == 5) || (o.recovery && o.posts == 2)) {
		o.reloads++
	}
	if action == "preview" {
		o.previewID = previewID
	}
	o.state = state
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

func runSecretsBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	raw, err := os.ReadFile(f.MasterFile)
	acceptanceCheck(t, err)
	key, err := hex.DecodeString(string(raw))
	clear(raw)
	acceptanceCheck(t, err)
	defer clear(key)
	secretsBrowserSetup(t, f, key)
	noCSS := os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "secrets-delete-recovery-no-css"
	recovery := os.Getenv("GOTTH_MAIL_BROWSER_MODE") == "secrets-delete-recovery" || noCSS
	if recovery {
		// SETUP only: independently authenticate both seeded secret rows in memory.
		block, e := aes.NewCipher(key)
		acceptanceCheck(t, e)
		gcm, e := cipher.NewGCM(block)
		acceptanceCheck(t, e)
		rows, e := f.DB.Query("SELECT slot,nonce,ciphertext FROM extension_secrets WHERE instance_id=$1", f.ID)
		acceptanceCheck(t, e)
		count := 0
		for rows.Next() {
			var slot string
			var nonce, ciphertext []byte
			acceptanceCheck(t, rows.Scan(&slot, &nonce, &ciphertext))
			plain, e := gcm.Open(nil, nonce, ciphertext, []byte(f.ID+"\x00"+slot))
			valid := e == nil && bytes.Equal(plain, []byte(f.Secret))
			clear(plain)
			if !valid {
				rows.Close()
				t.Fatal("recovery setup secret authentication")
			}
			count++
		}
		acceptanceCheck(t, rows.Err())
		acceptanceCheck(t, rows.Close())
		if count != 2 {
			t.Fatal("recovery setup secret count")
		}
		_, e = f.DB.Exec(`UPDATE extension_instances SET metadata_json=jsonb_set(jsonb_set(metadata_json,'{fields,0,kind}','"unknown"'::jsonb),'{fields,0,label}','"recovery-metadata-canary"'::jsonb) WHERE instance_id=$1`, f.ID)
		acceptanceCheck(t, e)
	}
	state, err := configurationSnapshot(context.Background(), f.DB)
	acceptanceCheck(t, err)
	o := &secretsBrowserOracle{f: f, key: key, state: state, recovery: recovery, noCSS: noCSS}
	if recovery {
		o.identity, err = recoveryIdentitySnapshot(context.Background(), f.DB)
		acceptanceCheck(t, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	o.authority = listener.Addr().String()
	srv := &http.Server{Handler: o, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	served := make(chan error, 1)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Error("D3 HTTP shutdown")
				_ = srv.Close()
			}
			if err := <-served; err != nil && err != http.ErrServerClosed {
				t.Error("D3 serve")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	bootstrap, err := json.Marshal(map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": os.Getenv("GOTTH_MAIL_BROWSER_MODE"), "secret": f.Secret})
	acceptanceCheck(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"))
	cmd.Stdin = bytes.NewReader(bootstrap)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	runErr := cmd.Run()
	clear(bootstrap)
	shutdown()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failure != "" {
		t.Error(o.failure)
	}
	expectedPosts := 5
	if recovery {
		expectedPosts = 2
	}
	wantStyles := [2]bool{true, true}
	if noCSS {
		wantStyles = [2]bool{}
	}
	if o.posts != expectedPosts || o.reloads < 1 || o.styles != wantStyles {
		t.Errorf("D3 incomplete posts=%d reloads=%d CSS=%v", o.posts, o.reloads, o.styles)
	}
	after, err := configurationSnapshot(context.Background(), f.DB)
	if err != nil || after != o.state {
		t.Error("D3 final state drift")
	}
	quiet := configurationBrowserOracle{f: f}
	if err = quiet.quiet(); err != nil {
		t.Error(err)
	}
	if recovery {
		identity, e := recoveryIdentitySnapshot(context.Background(), f.DB)
		if e != nil || identity != o.identity {
			t.Error("recovery final identity mutation")
		}
	}
	if runErr != nil {
		t.Errorf("D3 browser failed: %v (safe proof)", runErr)
	}
	if !t.Failed() {
		if recovery {
			t.Log("PASS native recovery two POSTs, blank required denial, refresh, eight-table delta and independently authenticated setup, runtime zero")
			return
		}
		t.Log("PASS native D3 five POSTs, re-preview isolation, required denial, wrong phrase unchanged, all chosen secrets deleted, survivor/registry preserved, exact revision/preview/audit, zero runtime/receiver")
	}
}

func TestSecretsBrowserRunnerMode(t *testing.T) {
	for _, mode := range []string{"secrets-delete", "secrets-delete-recovery", "secrets-delete-recovery-no-css"} {
		for _, extra := range []bool{false, true} {
			args := []string{"../../scripts/extensions-browser-acceptance.sh", "/missing-binary", "/missing-archive", "/missing-pg", "/missing-output", mode}
			want := 1
			if extra {
				args = append(args, "/extra")
				want = 2
			}
			err := exec.Command("bash", args...).Run()
			var e *exec.ExitError
			if !errors.As(err, &e) || e.ExitCode() != want {
				t.Fatal("D3 runner mode contract")
			}
		}
	}
}

func TestSecretsBrowserDelta(t *testing.T) {
	encode := func(v any) string { b, e := json.Marshal(v); acceptanceCheck(t, e); return string(b) }
	for _, kind := range []string{"valid", "registry", "survivor", "secret", "revision", "tested", "health", "preview", "older", "actor", "audit", "audit-payload"} {
		t.Run(kind, func(t *testing.T) {
			chosen := map[string]any{"instance_id": "chosen", "configuration_revision": 2, "tested_revision": 2, "health_code": "extension.ready", "enabled": false, "routed": false, "lifecycle": "stopped", "configuration_json": map[string]any{"endpoint": "fixed"}}
			other := map[string]any{"instance_id": "other", "configuration_revision": 2, "configuration_json": "survivor"}
			previews := []map[string]any{{"id": "old", "consumed_at": nil}, {"id": "chosen-preview", "consumed_at": nil}}
			survivor := map[string]any{"instance_id": "other", "slot": "current", "ciphertext": "fixed"}
			before := [4]string{encode([]any{chosen, other}), encode([]any{map[string]any{"instance_id": "chosen", "slot": "current"}, map[string]any{"instance_id": "chosen", "slot": "retained"}, survivor}), encode(previews), "[]"}
			chosen["configuration_revision"] = 3
			chosen["tested_revision"] = nil
			chosen["health_code"] = "extension.unknown"
			chosen["updated_at"] = "later"
			previews[1]["consumed_at"] = "later"
			event := map[string]any{"id": "event", "actor_type": "oidc_subject", "actor_id": "actor", "resource_type": "extension", "resource_id": "chosen", "action": "extension.secrets.delete", "result": "success", "after_redacted_json": encode(map[string]any{"deleted_secret_slots": "[REDACTED]"})}
			after := [4]string{encode([]any{chosen, other}), encode([]any{survivor}), encode(previews), encode([]any{event})}
			switch kind {
			case "registry":
				chosen["configuration_json"] = "changed"
			case "survivor":
				other["configuration_json"] = "changed"
			case "secret":
				after[1] = before[1]
			case "revision":
				chosen["configuration_revision"] = 4
			case "tested":
				chosen["tested_revision"] = 2
			case "health":
				chosen["health_code"] = "extension.ready"
			case "preview":
				previews[1]["consumed_at"] = nil
			case "older":
				previews[0]["consumed_at"] = "later"
			case "actor":
				event["actor_id"] = "other"
			case "audit":
				event["action"] = "extension.uninstall"
			case "audit-payload":
				event["after_redacted_json"] = "{}"
			}
			after[0] = encode([]any{chosen, other})
			after[2] = encode(previews)
			after[3] = encode([]any{event})
			if (secretsBrowserDelta(before, after, "apply", "actor", "chosen", "chosen-preview", "", nil) == nil) != (kind == "valid") {
				t.Fatal("D3 apply delta corruption mismatch")
			}
			if secretsBrowserDelta(before, before, "denied", "actor", "chosen", "", "", nil) != nil || secretsBrowserDelta(before, after, "denied", "actor", "chosen", "", "", nil) == nil {
				t.Fatal("D3 denial exact snapshot mismatch")
			}
		})
	}
	key := bytes.Repeat([]byte{7}, 32)
	phrase := "confirm-" + strings.Repeat("a", 32)
	for _, kind := range []string{"valid", "actor", "target", "operation", "revision", "payload", "hash", "secretbinding", "confirmation", "expired", "consumed", "older", "authoritative"} {
		t.Run("preview-"+kind, func(t *testing.T) {
			digest := sha256.Sum256([]byte("{}"))
			mac := hmac.New(sha256.New, key)
			empty := hex.EncodeToString(mac.Sum(nil))
			mac.Write([]byte("extension-preview-confirmation\x00" + phrase))
			row := map[string]any{"id": "new", "instance_id": "chosen", "operation": "delete_secrets", "actor_type": "oidc_subject", "actor_id": "actor", "base_revision": 2, "payload_json": map[string]any{}, "payload_sha256": hex.EncodeToString(digest[:]), "secret_binding_sha256": empty, "confirmation_sha256": hex.EncodeToString(mac.Sum(nil)), "consumed_at": nil, "created_at": time.Now().UTC().Format("2006-01-02T15:04:05.999999"), "expires_at": time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.999999")}
			old := map[string]any{"id": "old", "consumed_at": nil}
			before := [4]string{encode([]any{map[string]any{"instance_id": "chosen", "configuration_revision": 2}}), "[]", encode([]any{old}), "[]"}
			after := before
			switch kind {
			case "actor":
				row["actor_id"] = "other"
			case "target":
				row["instance_id"] = "other"
			case "operation":
				row["operation"] = "uninstall"
			case "revision":
				row["base_revision"] = 3
			case "payload":
				row["payload_json"] = map[string]any{"bad": true}
			case "hash":
				row["payload_sha256"] = "bad"
			case "secretbinding":
				row["secret_binding_sha256"] = "bad"
			case "confirmation":
				row["confirmation_sha256"] = "bad"
			case "expired":
				row["expires_at"] = "2000-01-01T00:00:00"
			case "consumed":
				row["consumed_at"] = "later"
			case "older":
				old["consumed_at"] = "later"
			case "authoritative":
				after[1] = "[{}]"
			}
			after[2] = encode([]any{old, row})
			if (secretsBrowserDelta(before, after, "preview", "actor", "chosen", "new", phrase, key) == nil) != (kind == "valid") {
				t.Fatal("D3 preview corruption mismatch")
			}
		})
	}
}

func TestSecretsBrowserRejectsUnexpected(t *testing.T) {
	// Client-injected denial must keep both assets outside the real handler.
	for _, path := range []string{"/admin/extensions/assets/detail.css", "/admin/extensions/assets/tokens.css"} {
		invoked := false
		o := &secretsBrowserOracle{recovery: true, noCSS: true, authority: "127.0.0.1:1234", f: acceptanceBrowserStart{ID: "id", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { invoked = true })}}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://127.0.0.1:1234"+path, nil)
		r.URL.Scheme = ""
		r.URL.Host = ""
		o.ServeHTTP(w, r)
		if w.Code != 500 || invoked || o.failure != "recovery no-CSS request crossed transport boundary" || o.posts != 0 || o.styles != [2]bool{} {
			t.Fatal("recovery CSS crossed denial boundary")
		}
	}
	for _, tc := range []struct {
		method, path, body string
		posts              int
	}{
		{"POST", "/admin/extensions/id", "action=uninstall-apply", 0},
		{"POST", "/admin/extensions/id", "action=secrets-delete-apply", 0},
		{"POST", "/admin/extensions/id", "action=secrets-delete-preview", 5},
		{"GET", "/admin/extensions/id?theme=dark&theme=light", "", 0},
		{"GET", "/admin/extensions/id?csrf_token=x", "", 0},
		{"GET", "/admin/extensions/id", "", 1},
		{"POST", "/admin/extensions/assets/detail.css", "", 0},
		{"GET", "/admin/extensions/assets/detail.css?theme=dark", "", 0},
		{"GET", "/admin/extensions/assets/evil.js", "", 0},
	} {
		invoked := false
		o := &secretsBrowserOracle{posts: tc.posts, f: acceptanceBrowserStart{ID: "id", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { invoked = true })}}
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		o.ServeHTTP(w, r)
		if w.Code != 500 || o.failure == "" || invoked || o.posts != tc.posts {
			t.Fatal("D3 forbidden request crossed barrier")
		}
	}
}

// D4 concrete four-table delta; time O(B+N), space O(B+N) including decoded rows.
func uninstallBrowserDelta(before, after [4]string, action, actor, id, previewID, phrase string, key []byte, auditBefore string) error {
	var a, b [4][]map[string]any
	for i := range a {
		if json.Unmarshal([]byte(before[i]), &a[i]) != nil || json.Unmarshal([]byte(after[i]), &b[i]) != nil {
			return errors.New("D4 SQL decode")
		}
	}
	if action == "denied" || action == "read" {
		if before != after {
			return errors.New("D4 denial/read mutated SQL")
		}
		return nil
	}
	if action == "preview" {
		for _, i := range []int{0, 1, 3} {
			if before[i] != after[i] {
				return errors.New("D4 preview authoritative mutation")
			}
		}
		if len(b[2]) != len(a[2])+1 {
			return errors.New("D4 preview cardinality")
		}
		old := map[string]map[string]any{}
		for _, r := range a[2] {
			old[r["id"].(string)] = r
		}
		var added map[string]any
		for _, r := range b[2] {
			if prior, ok := old[r["id"].(string)]; ok {
				if !reflect.DeepEqual(prior, r) {
					return errors.New("D4 prior preview changed")
				}
				delete(old, r["id"].(string))
			} else {
				if added != nil {
					return errors.New("D4 extra preview")
				}
				added = r
			}
		}
		if len(old) != 0 || added == nil || added["id"] != previewID || added["instance_id"] != id || added["operation"] != "uninstall" || added["actor_type"] != "oidc_subject" || added["actor_id"] != actor || added["consumed_at"] != nil || !reflect.DeepEqual(added["payload_json"], map[string]any{}) {
			return errors.New("D4 preview binding")
		}
		var revision any
		for _, r := range a[0] {
			if r["instance_id"] == id {
				revision = r["configuration_revision"]
			}
		}
		digest := sha256.Sum256([]byte("{}"))
		mac := hmac.New(sha256.New, key)
		empty := hex.EncodeToString(mac.Sum(nil))
		mac.Write([]byte("extension-preview-confirmation\x00" + phrase))
		if revision == nil || added["base_revision"] != revision || added["payload_sha256"] != hex.EncodeToString(digest[:]) || added["secret_binding_sha256"] != empty || added["confirmation_sha256"] != hex.EncodeToString(mac.Sum(nil)) {
			return errors.New("D4 preview digest")
		}
		created, e1 := time.Parse("2006-01-02T15:04:05.999999", added["created_at"].(string))
		expires, e2 := time.Parse("2006-01-02T15:04:05.999999", added["expires_at"].(string))
		if e1 != nil || e2 != nil || !expires.After(time.Now().UTC()) || !expires.After(created) {
			return errors.New("D4 preview expiry")
		}
		return nil
	}
	if action != "apply" {
		return errors.New("D4 unknown delta")
	}
	for _, table := range []int{0, 1, 2} {
		expected := []map[string]any{}
		removed := 0
		for _, r := range a[table] {
			if r["instance_id"] == id {
				removed++
				if table == 1 {
					return errors.New("D4 retained secrets before uninstall")
				}
			} else {
				expected = append(expected, r)
			}
		}
		if table == 0 && removed != 1 {
			return errors.New("D4 chosen registry absent before")
		}
		if table == 2 && removed < 1 {
			return errors.New("D4 uninstall preview absent before")
		}
		if !reflect.DeepEqual(expected, b[table]) {
			return errors.New("D4 target cascade/survivor mismatch")
		}
	}
	if len(b[3]) != len(a[3])+1 {
		return errors.New("D4 audit cardinality")
	}
	old := map[any]map[string]any{}
	for _, e := range a[3] {
		old[e["id"]] = e
	}
	var event map[string]any
	for _, e := range b[3] {
		if prior, ok := old[e["id"]]; ok {
			if !reflect.DeepEqual(prior, e) {
				return errors.New("D4 prior audit changed")
			}
			delete(old, e["id"])
		} else {
			if event != nil {
				return errors.New("D4 extra audit")
			}
			event = e
		}
	}
	if len(old) != 0 || event == nil || event["actor_type"] != "oidc_subject" || event["actor_id"] != actor || event["resource_type"] != "extension" || event["resource_id"] != id || event["action"] != "extension.uninstall" || event["result"] != "success" || event["after_redacted_json"] != "null" {
		return errors.New("D4 audit binding")
	}
	var expected, got any
	raw, ok := event["before_redacted_json"].(string)
	if !ok || json.Unmarshal([]byte(auditBefore), &expected) != nil || json.Unmarshal([]byte(raw), &got) != nil || !reflect.DeepEqual(expected, got) {
		return errors.New("D4 audit prior projection")
	}
	return nil
}

// Explicit D4 setup, not browser credit. Current statuses are empty, while two
// valid encrypted rows remain. Metadata and grants remove the same secret fields.
func uninstallBrowserSetup(t *testing.T, f acceptanceBrowserStart, key []byte) string {
	t.Helper()
	secretsBrowserSetup(t, f, key)
	item := f.Current()
	fields := []extensionsadmin.Field{}
	for _, field := range item.Metadata.Fields {
		if field.Kind != extensionsadmin.FieldSecret {
			fields = append(fields, field)
		}
	}
	item.Metadata.Fields = fields
	acceptanceCheck(t, extensionsadmin.ValidateMetadata(item.Metadata))
	_, err := extensionsadmin.ValidateConfiguration(item.Metadata, item.Configuration, nil)
	acceptanceCheck(t, err)
	metadata, err := json.Marshal(item.Metadata)
	acceptanceCheck(t, err)
	_, err = f.DB.Exec("UPDATE extension_instances SET metadata_json=$1,secret_slots_json='[]'::jsonb WHERE instance_id=$2", metadata, f.ID)
	acceptanceCheck(t, err)
	item = f.Current()
	if len(item.Secrets) != 0 || len(item.SecretSlots) != 0 || item.Enabled || item.Routed {
		t.Fatal("D4 empty current statuses setup")
	}
	var count int
	acceptanceCheck(t, f.DB.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", f.ID).Scan(&count))
	if count != 2 {
		t.Fatal("D4 retained rows setup")
	}
	var survivor string
	acceptanceCheck(t, f.DB.QueryRow("SELECT instance_id::text FROM extension_instances WHERE instance_id<>$1", f.ID).Scan(&survivor))
	return survivor
}

type uninstallBrowserOracle struct {
	f                                     acceptanceBrowserStart
	key                                   []byte
	mu                                    sync.Mutex
	phase, previewID, phrase, auditBefore string
	posts, inventory, notFound            int
	failure                               string
	state                                 [4]string
	styles                                [3]bool
}

func (o *uninstallBrowserOracle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fail := func(s string) {
		if o.failure == "" {
			o.failure = s
		}
		http.Error(w, "uninstall fixture failed", 500)
	}
	if o.failure != "" {
		fail(o.failure)
		return
	}
	if r.Header.Get("Authorization") != "" {
		fail("D4 bearer forbidden")
		return
	}
	detail := "/admin/extensions/" + o.f.ID
	list := r.URL.Path == "/admin/extensions"
	asset := -1
	switch r.URL.Path {
	case "/admin/extensions/assets/tokens.css":
		asset = 0
	case "/admin/extensions/assets/detail.css":
		asset = 1
	case "/admin/extensions/assets/inventory.css":
		asset = 2
	case "/admin/extensions/assets/inventory.js":
		asset = 3
	}
	queryOK := r.URL.RawQuery == ""
	if r.URL.Path == detail || list {
		switch r.URL.RawQuery {
		case "theme=system", "theme=light", "theme=dark":
			queryOK = true
		}
	}
	favicon := r.URL.Path == "/favicon.ico" && r.Method == "GET"
	if !queryOK || (asset >= 0 && r.Method != "GET") || (asset >= 2 && (o.phase != "empty" || o.posts != 2)) || (r.URL.Path != detail && !list && !favicon && asset < 0) {
		fail("D4 unexpected route")
		return
	}
	action := "read"
	pid := ""
	targetPosts := 5
	if o.phase == "empty" {
		targetPosts = 2
	}
	if r.Method == "POST" {
		if r.URL.Path != detail || o.posts >= targetPosts {
			fail("D4 unexpected POST")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.ParseForm() != nil {
			fail("D4 bad form")
			return
		}
		actions := []string{"uninstall-preview", "uninstall-preview", "uninstall-apply", "uninstall-preview", "uninstall-apply"}
		if o.phase == "empty" {
			actions = []string{"uninstall-preview", "uninstall-apply"}
		}
		if r.PostForm.Get("action") != actions[o.posts] {
			fail("D4 action phase")
			return
		}
		action = "preview"
		if r.PostForm.Get("action") == "uninstall-apply" {
			pid = r.PostForm.Get("preview_id")
			if pid == "" || pid != o.previewID {
				fail("D4 selected preview binding")
				return
			}
			action = "denied"
			if o.phase == "empty" {
				action = "apply"
			}
			if (o.phase == "empty" || o.posts == 4) && r.PostForm.Get("confirmation") != o.phrase {
				fail("D4 correct phrase not actually submitted")
				return
			}
			if o.phase == "retained" && o.posts == 2 && (r.PostForm.Get("confirmation") == "" || r.PostForm.Get("confirmation") == o.phrase) {
				fail("D4 wrong nonblank phrase not exercised")
				return
			}
		}
	} else if r.Method != "GET" || (o.posts > 0 && o.posts < targetPosts && asset < 0 && !favicon) {
		fail("D4 unexpected GET/method")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	o.f.Handler.ServeHTTP(rec, r.WithContext(ctx))
	body := rec.Body.Bytes()
	if len(body) > 1<<20 || bytes.Contains(body, []byte(o.f.Secret)) || bytes.Contains(body, []byte(o.f.Session)) {
		fail("D4 response privacy")
		return
	}
	want := 200
	if list && o.posts == 0 {
		want = 401
	}
	if favicon {
		want = 404
	}
	oldDetail := r.Method == "GET" && r.URL.Path == detail && o.phase == "empty" && o.posts == 2
	if oldDetail {
		want = 404
	}
	if rec.Code != want {
		fail("D4 response status")
		return
	}
	if asset >= 0 {
		mime := "text/css; charset=utf-8"
		if asset == 3 {
			mime = "text/javascript; charset=utf-8"
		}
		if rec.Header().Get("Content-Type") != mime || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			fail("D4 asset MIME/privacy")
			return
		}
	}
	phrase := ""
	if action == "preview" {
		p := regexp.MustCompile("name=\"preview_id\" value=\"([^\"]+)\"").FindSubmatch(body)
		c := regexp.MustCompile("<code>(confirm-[a-f0-9]{32})</code>").FindSubmatch(body)
		if len(p) != 2 || len(c) != 2 {
			fail("D4 rendered preview absent")
			return
		}
		pid = string(p[1])
		phrase = string(c[1])
	}
	state, err := configurationSnapshot(ctx, o.f.DB)
	if err != nil {
		fail(err.Error())
		return
	}
	if err = uninstallBrowserDelta(o.state, state, action, o.f.ActorID, o.f.ID, pid, phrase, o.key, o.auditBefore); err != nil {
		fail(err.Error())
		return
	}
	for _, table := range state {
		for _, secret := range []string{o.f.Secret, o.f.Session, o.f.CSRF} {
			if secret != "" && strings.Contains(table, secret) {
				fail("D4 SQL privacy")
				return
			}
		}
	}
	quiet := configurationBrowserOracle{f: o.f}
	if err = quiet.quiet(); err != nil {
		fail(err.Error())
		return
	}
	if action == "apply" {
		if !bytes.Contains(body, []byte("Selected extension uninstalled. Other installed extensions are unchanged.")) {
			fail("D4 terminal receipt missing")
			return
		}
		for _, forbidden := range []string{"<form", "<input", "No extensions installed", o.f.ID, o.f.CSRF, pid, o.phrase} {
			if forbidden != "" && bytes.Contains(body, []byte(forbidden)) {
				fail("D4 terminal leaked stale/form material")
				return
			}
		}
	} else if r.Method == "POST" {
		accepted := bytes.Contains(body, []byte("extension operation accepted"))
		if accepted == (action == "denied") {
			fail("D4 acceptance/denial projection")
			return
		}
	}
	if r.Method == "POST" {
		o.posts++
	}
	if action == "preview" {
		o.previewID = pid
		o.phrase = phrase
	}
	if asset >= 0 && asset < 3 {
		o.styles[asset] = true
	}
	if list && want == 200 && o.phase == "empty" && o.posts == 2 {
		o.inventory++
	}
	if oldDetail {
		o.notFound++
	}
	o.state = state
	for k, vs := range rec.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

func runUninstallBrowserPhase(t *testing.T, f acceptanceBrowserStart, key []byte, driver, phase, survivor string) {
	state, err := configurationSnapshot(context.Background(), f.DB)
	acceptanceCheck(t, err)
	item := f.Current()
	item.Secrets = nil
	payload, err := json.Marshal(audit.Redact(item))
	acceptanceCheck(t, err)
	o := &uninstallBrowserOracle{f: f, key: key, phase: phase, state: state, auditBefore: string(payload)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	srv := &http.Server{Handler: o, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	served := make(chan error, 1)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				t.Error("D4 HTTP shutdown")
				_ = srv.Close()
			}
			if err := <-served; err != nil && err != http.ErrServerClosed {
				t.Error("D4 HTTP serve")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	bootstrap, err := json.Marshal(map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": "uninstall", "phase": phase, "survivor": survivor, "secret": f.Secret})
	acceptanceCheck(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", driver, os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT")+"-"+phase)
	cmd.Stdin = bytes.NewReader(bootstrap)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	runErr := cmd.Run()
	clear(bootstrap)
	shutdown()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failure != "" {
		t.Error(o.failure)
	}
	expected := 5
	if phase == "empty" {
		expected = 2
	}
	if o.posts != expected {
		t.Errorf("D4 phase %s incomplete posts=%d", phase, o.posts)
	}
	if o.styles[0] != true || o.styles[1] != true {
		t.Error("D4 detail CSS incomplete")
	}
	if phase == "empty" && (!o.styles[2] || o.inventory < 1 || o.notFound < 1) {
		t.Error("D4 terminal/inventory/404 incomplete")
	}
	after, err := configurationSnapshot(context.Background(), f.DB)
	if err != nil || after != o.state {
		t.Error("D4 postdrain state drift")
	}
	quiet := configurationBrowserOracle{f: f}
	if err = quiet.quiet(); err != nil {
		t.Error(err)
	}
	if runErr != nil {
		t.Errorf("D4 %s browser failed: %v (safe proof)", phase, runErr)
	}
	if !t.Failed() {
		t.Logf("PASS native D4 %s exact POSTs=%d, SQL/audit/preview/survivor/runtime barriers", phase, expected)
	}
}

func runUninstallBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	raw, err := os.ReadFile(f.MasterFile)
	acceptanceCheck(t, err)
	key, err := hex.DecodeString(string(raw))
	clear(raw)
	acceptanceCheck(t, err)
	defer clear(key)
	survivor := uninstallBrowserSetup(t, f, key)
	if !t.Run("retained-secret-refusal", func(t *testing.T) { runUninstallBrowserPhase(t, f, key, driver, "retained", survivor) }) {
		return
	}
	// Browser A and HTTP handlers have exited/drained. Service deletion is SETUP,
	// independently checked, not part of a continuous native delete/uninstall flow.
	svc, err := extensionsadmin.NewService(f.DB, key, nil)
	acceptanceCheck(t, err)
	actor := audit.ActorRef{Type: "oidc_subject", ID: f.ActorID}
	ctx := context.Background()
	before, err := configurationSnapshot(ctx, f.DB)
	acceptanceCheck(t, err)
	preview, err := svc.PreviewDeleteSecrets(ctx, actor, f.ID)
	acceptanceCheck(t, err)
	prepared, err := configurationSnapshot(ctx, f.DB)
	acceptanceCheck(t, err)
	acceptanceCheck(t, secretsBrowserDelta(before, prepared, "preview", f.ActorID, f.ID, preview.ID, preview.Confirmation, key))
	_, err = svc.ApplyDeleteSecrets(ctx, actor, f.ID, preview.ID, preview.Confirmation)
	acceptanceCheck(t, err)
	after, err := configurationSnapshot(ctx, f.DB)
	acceptanceCheck(t, err)
	acceptanceCheck(t, secretsBrowserDelta(prepared, after, "apply", f.ActorID, f.ID, preview.ID, "", key))
	t.Log("D4 inter-phase service DeleteSecrets SETUP verified; no native deletion credit")
	t.Run("empty-secret-uninstall", func(t *testing.T) { runUninstallBrowserPhase(t, f, key, driver, "empty", survivor) })
}

func TestUninstallBrowserRunnerMode(t *testing.T) {
	for _, extra := range []bool{false, true} {
		args := []string{"../../scripts/extensions-browser-acceptance.sh", "/missing-binary", "/missing-archive", "/missing-pg", "/missing-output", "uninstall"}
		want := 1
		if extra {
			args = append(args, "/extra")
			want = 2
		}
		err := exec.Command("bash", args...).Run()
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ExitCode() != want {
			t.Fatal("D4 runner argument contract")
		}
	}
}

func TestUninstallCleanupAbsence(t *testing.T) {
	for _, kind := range []string{"installed", "verified-absent", "missing-audit", "wrong-actor", "lookup-error"} {
		t.Run(kind, func(t *testing.T) {
			db := testpg.DB(t, store.MigrateSQL)
			id := acceptanceUUID(t)
			actor := audit.ActorRef{Type: "oidc_subject", ID: "cleanup-actor"}
			ctx := context.Background()
			svc, err := extensionsadmin.NewService(db, bytes.Repeat([]byte{1}, 32), nil)
			acceptanceCheck(t, err)
			_, err = svc.Install(ctx, actor, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.cleanup", Repository: "https://github.com/gotthboard/gotth-extension-cleanup", ArtifactPin: "sha256:" + strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64), GrantDigest: strings.Repeat("c", 64), SessionDigest: strings.Repeat("d", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
			acceptanceCheck(t, err)
			if kind != "installed" && kind != "lookup-error" {
				p, e := svc.PreviewUninstall(ctx, actor, id)
				acceptanceCheck(t, e)
				acceptanceCheck(t, svc.ApplyUninstall(ctx, actor, id, p.ID, p.Confirmation))
			}
			if kind == "missing-audit" {
				_, err = db.Exec("DELETE FROM audit_events WHERE action='extension.uninstall'")
				acceptanceCheck(t, err)
			}
			if kind == "wrong-actor" {
				actor.ID = "different"
			}
			if kind == "lookup-error" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			absent, err := acceptanceUninstallAbsent(ctx, db, id, actor.ID)
			if kind == "installed" {
				if absent || err != nil {
					t.Fatal("installed must Disable")
				}
			} else if kind == "verified-absent" {
				if !absent || err != nil {
					t.Fatal("proven absent not admitted")
				}
			} else if absent || err == nil {
				t.Fatal("uncertain absence did not fail closed")
			}
		})
	}
}

func TestUninstallBrowserDelta(t *testing.T) {
	encode := func(v any) string { b, e := json.Marshal(v); acceptanceCheck(t, e); return string(b) }
	for _, kind := range []string{"valid", "registry", "survivor", "secrets", "preview", "old-preview", "audit-count", "actor", "target", "action", "result", "before", "after", "prior-audit"} {
		t.Run(kind, func(t *testing.T) {
			survivor := map[string]any{"instance_id": "other", "configuration": "unchanged"}
			secret := map[string]any{"instance_id": "other", "ciphertext": "fixed"}
			preview := map[string]any{"instance_id": "other", "id": "other-preview", "consumed_at": nil}
			prior := map[string]any{"id": "prior", "action": "extension.configure"}
			chosen := map[string]any{"instance_id": "chosen", "enabled": false}
			before := [4]string{encode([]any{chosen, survivor}), encode([]any{secret}), encode([]any{map[string]any{"instance_id": "chosen", "id": "old"}, map[string]any{"instance_id": "chosen", "id": "new"}, preview}), encode([]any{prior})}
			payload := encode(chosen)
			event := map[string]any{"id": "new-event", "actor_type": "oidc_subject", "actor_id": "actor", "resource_type": "extension", "resource_id": "chosen", "action": "extension.uninstall", "result": "success", "before_redacted_json": payload, "after_redacted_json": "null"}
			after := [4]string{encode([]any{survivor}), encode([]any{secret}), encode([]any{preview}), ""}
			switch kind {
			case "registry":
				after[0] = before[0]
			case "survivor":
				after[0] = "[]"
			case "secrets":
				after[1] = "[]"
			case "preview":
				after[2] = before[2]
			case "old-preview":
				after[2] = encode([]any{preview, map[string]any{"instance_id": "chosen", "id": "old"}})
			case "actor":
				event["actor_id"] = "wrong"
			case "target":
				event["resource_id"] = "other"
			case "action":
				event["action"] = "extension.disable"
			case "result":
				event["result"] = "denied"
			case "before":
				event["before_redacted_json"] = "{}"
			case "after":
				event["after_redacted_json"] = "{}"
			case "prior-audit":
				prior["action"] = "changed"
			}
			after[3] = encode([]any{prior, event})
			if kind == "audit-count" {
				after[3] = encode([]any{prior, event, event})
			}
			if (uninstallBrowserDelta(before, after, "apply", "actor", "chosen", "new", "", nil, payload) == nil) != (kind == "valid") {
				t.Fatal("D4 cascade/audit corruption mismatch")
			}
			if uninstallBrowserDelta(before, before, "denied", "actor", "chosen", "", "", nil, payload) != nil || uninstallBrowserDelta(before, after, "denied", "actor", "chosen", "", "", nil, payload) == nil {
				t.Fatal("D4 denial must preserve all state")
			}
		})
	}
}

func TestUninstallBrowserRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		method, path, body, phase string
		posts                     int
	}{
		{"POST", "/admin/extensions/id", "action=uninstall-apply", "retained", 0},
		{"POST", "/admin/extensions/id", "action=uninstall-preview", "retained", 5},
		{"POST", "/admin/extensions/id", "action=uninstall-apply&preview_id=other&confirmation=wrong", "empty", 1},
		{"GET", "/admin/extensions/id?theme=dark&theme=light", "", "retained", 0},
		{"GET", "/admin/extensions/id?unexpected=authority", "", "retained", 0},
		{"GET", "/admin/extensions/id", "", "retained", 1},
		{"POST", "/admin/extensions/assets/detail.css", "", "retained", 0},
		{"GET", "/admin/extensions/assets/inventory.js", "", "retained", 0},
		{"GET", "/admin/extensions/assets/htmx-2.0.10.min.js", "", "empty", 2},
		{"GET", "/admin/extensions/assets/inventory.css?theme=dark", "", "empty", 2},
	} {
		invoked := false
		o := &uninstallBrowserOracle{phase: tc.phase, posts: tc.posts, previewID: "expected", f: acceptanceBrowserStart{ID: "id", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { invoked = true })}}
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		o.ServeHTTP(w, r)
		if w.Code != 500 || o.failure == "" || invoked || o.posts != tc.posts || o.inventory != 0 || o.notFound != 0 {
			t.Fatal("D4 rejected request crossed barrier")
		}
	}
}

// Shared Test/activation/update/rollback fixture policy, not a production router.
// Fixed path/query comparisons: O(B) time, O(1) auxiliary space.
func connectionBrowserRequest(r *http.Request, detail string) error {
	if r.Header.Get("Authorization") != "" {
		return errors.New("unexpected authority")
	}
	if r.URL.Path == "/admin/extensions/assets/tokens.css" || r.URL.Path == "/admin/extensions/assets/detail.css" {
		if r.Method != "GET" || r.URL.RawQuery != "" {
			return errors.New("unexpected lifecycle asset method/query")
		}
		return nil
	}
	if r.URL.Path != detail && r.URL.Path != "/admin/extensions" && r.URL.Path != "/favicon.ico" {
		return errors.New("unexpected connection-test route")
	}
	if r.URL.RawQuery != "" {
		if r.URL.Path != detail {
			return errors.New("unexpected query outside detail")
		}
		switch r.URL.RawQuery {
		case "theme=system", "theme=light", "theme=dark":
		default:
			return errors.New("unexpected detail query")
		}
	}
	return nil
}
func connectionBrowserAssetResponse(r *http.Request, rec *httptest.ResponseRecorder) error {
	if r.URL.Path != "/admin/extensions/assets/tokens.css" && r.URL.Path != "/admin/extensions/assets/detail.css" {
		return nil
	}
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/css; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		return errors.New("lifecycle asset status/MIME/privacy")
	}
	return nil
}
func TestConnectionBrowserRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		bearer, ok         bool
	}{
		{"detail", "GET", "/admin/extensions/id", false, true},
		{"post-theme", "POST", "/admin/extensions/id?theme=system", false, true},
		{"light", "GET", "/admin/extensions/id?theme=light", false, true},
		{"dark", "GET", "/admin/extensions/id?theme=dark", false, true},
		{"tokens", "GET", "/admin/extensions/assets/tokens.css", false, true},
		{"detail-css", "GET", "/admin/extensions/assets/detail.css", false, true},
		{"inventory", "GET", "/admin/extensions", false, true},
		{"favicon", "GET", "/favicon.ico", false, true},
		{"arbitrary-query", "GET", "/admin/extensions/id?unexpected=1", false, false},
		{"duplicate-theme", "GET", "/admin/extensions/id?theme=dark&theme=light", false, false},
		{"encoded-theme", "GET", "/admin/extensions/id?theme=%64ark", false, false},
		{"theme-case", "GET", "/admin/extensions/id?theme=DARK", false, false},
		{"inventory-query", "GET", "/admin/extensions?theme=light", false, false},
		{"favicon-query", "GET", "/favicon.ico?theme=light", false, false},
		{"asset-query", "GET", "/admin/extensions/assets/detail.css?theme=light", false, false},
		{"asset-post", "POST", "/admin/extensions/assets/detail.css", false, false},
		{"asset-head", "HEAD", "/admin/extensions/assets/tokens.css", false, false},
		{"arbitrary-asset", "GET", "/admin/extensions/assets/inventory.js", false, false},
		{"bearer", "GET", "/admin/extensions/id", true, false},
		{"route", "GET", "/unrelated", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer fixture")
			}
			if (connectionBrowserRequest(r, "/admin/extensions/id") == nil) != tc.ok {
				t.Fatal("closed lifecycle request policy mismatch")
			}
		})
	}
}

func TestConnectionBrowserAssetResponse(t *testing.T) {
	for _, kind := range []string{"valid", "status", "mime", "cache", "sniff"} {
		t.Run(kind, func(t *testing.T) {
			for _, path := range []string{"/admin/extensions/assets/tokens.css", "/admin/extensions/assets/detail.css"} {
				r := httptest.NewRequest("GET", path, nil)
				rec := httptest.NewRecorder()
				rec.Header().Set("Content-Type", "text/css; charset=utf-8")
				rec.Header().Set("Cache-Control", "no-store")
				rec.Header().Set("X-Content-Type-Options", "nosniff")
				switch kind {
				case "status":
					rec.Code = 401
				case "mime":
					rec.Header().Set("Content-Type", "text/html")
				case "cache":
					rec.Header().Set("Cache-Control", "public")
				case "sniff":
					rec.Header().Del("X-Content-Type-Options")
				}
				if (connectionBrowserAssetResponse(r, rec) == nil) != (kind == "valid") {
					t.Fatal("CSS response guard mismatch")
				}
			}
		})
	}
}

// Closed test-only admission; production query compatibility is not changed.
func detailThemeRequest(r *http.Request, detail, authority string) (bool, error) {
	if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Host != authority || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.ForceQuery {
		return false, errors.New("theme request authority/method")
	}
	if r.URL.Path == "/admin/extensions/assets/tokens.css" || r.URL.Path == "/admin/extensions/assets/detail.css" {
		if r.URL.RawQuery != "" {
			return false, errors.New("theme asset query")
		}
		return true, nil
	}
	if r.URL.Path != detail {
		return false, errors.New("theme path")
	}
	switch r.URL.RawQuery {
	case "", "theme=system", "theme=light", "theme=dark":
		return false, nil
	}
	return false, errors.New("theme query")
}
func TestDetailThemeRequest(t *testing.T) {
	const d = "/admin/extensions/11111111-1111-4111-8111-111111111111"
	for _, tc := range []struct {
		url   string
		good  bool
		asset bool
	}{{d, true, false}, {d + "?theme=system", true, false}, {d + "?theme=light", true, false}, {d + "?theme=dark", true, false}, {"/admin/extensions/assets/tokens.css", true, true}, {"/admin/extensions/assets/detail.css", true, true}, {d + "?theme=dark&theme=light", false, false}, {d + "?theme=%64ark", false, false}, {d + "?theme=dark&x=1", false, false}, {d + "?", false, false}, {d + "/audit", false, false}, {d + "/other", false, false}, {"/admin/extensions", false, false}, {"/admin/extensions/assets/detail.css?x=1", false, false}, {"/admin/extensions/assets/inventory.js", false, false}} {
		t.Run(tc.url, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			r.Host = "127.0.0.1:1234"
			a, e := detailThemeRequest(r, d, r.Host)
			if (e == nil) != tc.good || (e == nil && a != tc.asset) {
				t.Fatal("request classification")
			}
		})
	}
	for _, bad := range []string{"method", "bearer", "authority", "absolute", "fragment", "rawpath"} {
		t.Run(bad, func(t *testing.T) {
			r := httptest.NewRequest("GET", d, nil)
			r.Host = "127.0.0.1:1234"
			switch bad {
			case "method":
				r.Method = "POST"
			case "bearer":
				r.Header.Set("Authorization", "Bearer fixture")
			case "authority":
				r.Host = "other"
			case "absolute":
				r.URL.Host = "other"
			case "fragment":
				r.URL.Fragment = "x"
			case "rawpath":
				r.URL.RawPath = d
			}
			if _, e := detailThemeRequest(r, d, "127.0.0.1:1234"); e == nil {
				t.Fatal("admitted invalid request")
			}
		})
	}
}

// One initial read-only fixture, serialized response/state barriers and final drain.
func runDetailThemeBrowser(t *testing.T, f acceptanceBrowserStart, driver string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := configurationSnapshot(ctx, f.DB)
	cancel()
	acceptanceCheck(t, err)
	f.EmptyRuntime()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	acceptanceCheck(t, err)
	detail := "/admin/extensions/" + f.ID
	var mu sync.Mutex
	failure := ""
	pages, unauth, posts, bearers := 0, 0, 0, 0
	assets := map[string]int{}
	quiet := func(ctx context.Context) error {
		state, e := configurationSnapshot(ctx, f.DB)
		if e != nil || state != before {
			return errors.New("theme changed SQL")
		}
		entries, e := os.ReadDir(f.RuntimeRoot)
		if e != nil || len(entries) != 0 || f.Requests() != 0 {
			return errors.New("theme runtime/receiver changed")
		}
		return nil
	}
	srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fail := func(reason string) {
			if failure == "" {
				failure = reason
			}
			http.Error(w, "theme fixture failed", 500)
		}
		if failure != "" {
			fail(failure)
			return
		}
		if r.Method != "GET" {
			posts++
		}
		if r.Header.Get("Authorization") != "" {
			bearers++
		}
		asset, e := detailThemeRequest(r, detail, listener.Addr().String())
		if e != nil {
			fail(e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if e = quiet(ctx); e != nil {
			fail(e.Error())
			return
		}
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, r.WithContext(ctx))
		body := rec.Body.Bytes()
		if len(body) > 1<<20 || len(rec.Header().Values("Set-Cookie")) != 0 {
			fail("theme response size/persistence")
			return
		}
		clean := string(body)
		if !asset {
			clean = strings.ReplaceAll(clean, `name="csrf_token" value="`+f.CSRF+`"`, "expected-csrf")
		}
		for _, s := range []string{f.Secret, f.Session, f.CSRF} {
			if s != "" && strings.Contains(clean, s) {
				fail("theme response private leak")
				return
			}
		}
		if asset {
			if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/css; charset=utf-8" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
				fail("theme CSS response")
				return
			}
			assets[r.URL.Path]++
		} else {
			authenticated := false
			if c, e := r.Cookie("gotth_mail_session"); e == nil && c.Value == f.Session {
				authenticated = true
			}
			want := 401
			if authenticated {
				want = 200
			}
			if rec.Code != want || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'none'") {
				fail("theme document auth/status/privacy")
				return
			}
			if authenticated {
				if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || strings.Contains(strings.ToLower(clean), "<script") {
					fail("theme document script/MIME")
					return
				}
				pages++
			} else {
				unauth++
			}
		}
		if e = quiet(ctx); e != nil {
			fail(e.Error())
			return
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})}
	served := make(chan error, 1)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if e := srv.Shutdown(ctx); e != nil {
				t.Error("theme HTTP shutdown")
				_ = srv.Close()
			}
			if e := <-served; e != nil && e != http.ErrServerClosed {
				t.Error("theme HTTP serve")
			}
		})
	}
	t.Cleanup(shutdown)
	go func() { served <- srv.Serve(listener) }()
	raw, err := json.Marshal(map[string]string{"origin": "http://" + listener.Addr().String(), "id": f.ID, "session": f.Session, "csrf": f.CSRF, "mode": "detail-theme"})
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
	shutdown() // Browser exit AND HTTP drain precede final state/admission.
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
		t.Errorf("detail-theme driver: %v", runErr)
	}
	if pages != 7 || unauth != 1 || posts != 0 || bearers != 0 || assets["/admin/extensions/assets/tokens.css"] != 7 || assets["/admin/extensions/assets/detail.css"] != 7 {
		t.Errorf("theme request counts pages=%d unauth=%d posts=%d bearers=%d styles=%d/%d", pages, unauth, posts, bearers, assets["/admin/extensions/assets/tokens.css"], assets["/admin/extensions/assets/detail.css"])
	}
	proof, e := os.ReadFile(filepath.Join(os.Getenv("GOTTH_MAIL_BROWSER_OUTPUT"), "proof.json"))
	if e != nil {
		t.Error("theme proof absent")
		return
	}
	for _, s := range []string{f.Secret, f.Session, f.CSRF} {
		if s != "" && bytes.Contains(proof, []byte(s)) {
			t.Error("theme proof private leak")
		}
	}
	var p struct {
		DetailThemeGate string
		ThemeStates     []json.RawMessage
		BrowserExit     struct{ Code int }
		Cleanup         struct {
			MainExited bool
			Remaining  []any
		}
	}
	if json.Unmarshal(proof, &p) != nil || p.DetailThemeGate != "PASS" || len(p.ThemeStates) != 12 || !p.Cleanup.MainExited || len(p.Cleanup.Remaining) != 0 || p.BrowserExit.Code != 0 {
		t.Error("theme proof incomplete")
	}
	if !t.Failed() {
		t.Log("PASS detail-theme only: 12 states, 7 authenticated GETs, 14 exact CSS GETs, no POST/bearer/SQL/runtime/receiver changes; browser and HTTP drained")
	}
}

func TestConfigurationNoCSSServerDenial(t *testing.T) {
	for _, path := range []string{"/admin/extensions/assets/tokens.css", "/admin/extensions/assets/detail.css", "/favicon.ico?x=1", "/favicon.ico/more", "/admin/extensions/id?theme=system&x=1"} {
		t.Run(path, func(t *testing.T) {
			invoked := false
			o := &configurationBrowserOracle{noCSS: true, authority: "127.0.0.1:1234", f: acceptanceBrowserStart{ID: "id", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { invoked = true })}}
			r := httptest.NewRequest("GET", path, nil)
			r.Host = o.authority
			w := httptest.NewRecorder()
			o.ServeHTTP(w, r)
			if w.Code != 500 || o.failure == "" || invoked || o.stylesheets != [2]bool{} {
				t.Fatal("no-CSS request reached handler")
			}
		})
	}
}

// Admission probe only: deliberate downstream non404 stops before SQL. Real404/SQL
// preservation is checked by the same oracle in the physical action, not this seam.
func TestConfigurationNoCSSFaviconAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, method, host string
		allowed            bool
	}{{"exact", "GET", "127.0.0.1:1234", true}, {"method", "POST", "127.0.0.1:1234", false}, {"foreign", "GET", "other", false}} {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			o := &configurationBrowserOracle{noCSS: true, authority: "127.0.0.1:1234", f: acceptanceBrowserStart{ID: "id", Secret: "fixture-secret-canary", Session: "fixture-session-canary", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { invoked = true; w.WriteHeader(403) })}}
			r := httptest.NewRequest(tc.method, "/favicon.ico", nil)
			r.Host = tc.host
			w := httptest.NewRecorder()
			o.ServeHTTP(w, r)
			if invoked != tc.allowed || o.phase != 0 || o.posts != 0 || o.reloads != 0 || o.stylesheets != [2]bool{} {
				t.Fatal("favicon admission/credit changed")
			}
			if tc.allowed && o.failure != "unexpected application status" {
				t.Fatal("favicon response guard not reached")
			}
		})
	}
}
