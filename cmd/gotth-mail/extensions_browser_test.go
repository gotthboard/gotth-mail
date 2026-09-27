package main

// Bounded live-browser gates; delivery and release admission remain outside this fixture.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
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
		if mode := os.Getenv("GOTTH_MAIL_BROWSER_MODE"); mode == "connection-test" || mode == "activation" || mode == "update" || mode == "rollback" {
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
