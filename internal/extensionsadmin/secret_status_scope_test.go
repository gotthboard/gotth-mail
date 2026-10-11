package extensionsadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

// This semantic contract is intended to pass before and after query filtering.
func TestSecretStatusScope(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal("service setup")
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "secret-status-scope"}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	initial := now
	svc.Now = func() time.Time { return now }
	metadata := Metadata{Schema: MetadataSchema, Fields: []Field{
		{Name: "secret.active", Label: "Active", Kind: FieldSecret},
		{Name: "secret.absent", Label: "Absent", Kind: FieldSecret},
		{Name: "secret.retired", Label: "Retired", Kind: FieldSecret},
	}}
	ids := []string{"aaaaaaaa-aaaa-4aaa-8aaa-000000000001", "bbbbbbbb-bbbb-4bbb-8bbb-000000000002"}
	for i, id := range ids {
		now = initial.Add(time.Duration(i) * time.Minute)
		_, e := svc.Install(ctx, actor, InstallRequest{InstanceID: id, ExtensionID: []string{"scope.first", "scope.second"}[i], Repository: "https://github.com/gotthboard/gotth-extension-scope", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: metadata, SecretSlots: []string{"secret.active", "secret.absent", "secret.retired"}})
		if e != nil {
			t.Fatal("install fixture")
		}
		input := ConfigureInput{Configuration: map[string]any{}, Secrets: map[string]string{"secret.active": "synthetic-active", "secret.retired": "synthetic-retired"}}
		preview, e := svc.PreviewConfigure(ctx, actor, id, input)
		if e != nil {
			t.Fatal("configure preview")
		}
		_, e = svc.ApplyConfigure(ctx, actor, id, preview.ID, preview.Confirmation, input)
		if e != nil {
			t.Fatal("configure apply")
		}
	}
	now = initial.Add(2 * time.Minute)
	update := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: Metadata{Schema: MetadataSchema, Fields: metadata.Fields[:2]}, SecretSlots: []string{"secret.active", "secret.absent"}}
	preview, err := svc.PreviewUpdate(ctx, actor, ids[0], update)
	if err != nil {
		t.Fatal("retire preview")
	}
	a, err := svc.ApplyUpdate(ctx, actor, ids[0], preview.ID, preview.Confirmation)
	if err != nil {
		t.Fatal("retire apply")
	}
	want := []SecretStatus{{Slot: "secret.absent"}, {Slot: "secret.active", Configured: true, RotatedAt: initial}}
	if mismatch := secretStatusScopeMismatch(a.Secrets, want); mismatch != "" {
		t.Fatal("current projection: " + mismatch)
	}
	wantOther := []SecretStatus{{Slot: "secret.absent"}, {Slot: "secret.active", Configured: true, RotatedAt: initial.Add(time.Minute)}, {Slot: "secret.retired", Configured: true, RotatedAt: initial.Add(time.Minute)}}
	var otherInstance, otherSecrets string
	if err = db.QueryRow("SELECT to_jsonb(i)::text FROM extension_instances i WHERE instance_id=$1", ids[1]).Scan(&otherInstance); err != nil {
		t.Fatal("other instance snapshot")
	}
	if err = db.QueryRow("SELECT jsonb_agg(to_jsonb(s) ORDER BY slot)::text FROM extension_secrets s WHERE instance_id=$1", ids[1]).Scan(&otherSecrets); err != nil {
		t.Fatal("other secret snapshot")
	}
	before := targetSnapshot(t, db)
	t.Run("read-order-isolation-and-empty", func(t *testing.T) {
		got, e := svc.Get(ctx, ids[0])
		if e != nil {
			t.Fatal("Get error")
		}
		if mismatch := secretStatusScopeMismatch(got.Secrets, want); mismatch != "" {
			t.Fatal("Get status: " + mismatch)
		}
		list, e := svc.List(ctx)
		if e != nil || len(list) != 2 {
			t.Fatal("List error/count")
		}
		if mismatch := secretStatusScopeMismatch(list[0].Secrets, want); mismatch != "" {
			t.Fatal("List first status: " + mismatch)
		}
		if mismatch := secretStatusScopeMismatch(list[1].Secrets, wantOther); mismatch != "" {
			t.Fatal("List other status: " + mismatch)
		}
		direct := Instance{InstanceID: ids[0], SecretSlots: []string{"secret.active", "secret.absent"}}
		if e = svc.loadSecretStatus(ctx, &direct); e != nil {
			t.Fatal("loaded grant error")
		}
		if mismatch := secretStatusScopeMismatch(direct.Secrets, []SecretStatus{want[1], want[0]}); mismatch != "" {
			t.Fatal("loaded grant order: " + mismatch)
		}
		for _, slots := range [][]string{nil, {}} {
			direct.SecretSlots = slots
			if e = svc.loadSecretStatus(ctx, &direct); e != nil || direct.Secrets == nil || len(direct.Secrets) != 0 {
				t.Fatal("non-nil empty status")
			}
		}
		targetUnchanged(t, db, before)
	})
	t.Run("rotation-empty-update-rollback-retention-delete", func(t *testing.T) {
		var retiredBefore, retiredAfter string
		if e := db.QueryRow("SELECT to_jsonb(s)::text FROM extension_secrets s WHERE instance_id=$1 AND slot='secret.retired'", ids[0]).Scan(&retiredBefore); e != nil {
			t.Fatal("retired snapshot")
		}
		now = initial.Add(3 * time.Minute)
		input := ConfigureInput{Configuration: map[string]any{}, Secrets: map[string]string{"secret.active": "synthetic-rotation"}}
		p, e := svc.PreviewConfigure(ctx, actor, ids[0], input)
		if e != nil {
			t.Fatal("rotation preview")
		}
		got, e := svc.ApplyConfigure(ctx, actor, ids[0], p.ID, p.Confirmation, input)
		if e != nil || len(got.Secrets) != 2 || !got.Secrets[1].RotatedAt.Equal(now) {
			t.Fatal("rotation timestamp")
		}
		if e = db.QueryRow("SELECT to_jsonb(s)::text FROM extension_secrets s WHERE instance_id=$1 AND slot='secret.retired'", ids[0]).Scan(&retiredAfter); e != nil || retiredAfter != retiredBefore {
			t.Fatal("rotation changed retired row")
		}
		empty := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("9", 64), ManifestDigest: strings.Repeat("a", 64), GrantDigest: strings.Repeat("b", 64), SessionDigest: strings.Repeat("c", 64), Metadata: Metadata{Schema: MetadataSchema, Fields: []Field{}}, SecretSlots: []string{}}
		now = initial.Add(4 * time.Minute)
		p, e = svc.PreviewUpdate(ctx, actor, ids[0], empty)
		if e != nil {
			t.Fatal("empty update preview")
		}
		retained := targetSnapshot(t, db)["extension_secrets"]
		got, e = svc.ApplyUpdate(ctx, actor, ids[0], p.ID, p.Confirmation)
		if e != nil || got.Secrets == nil || len(got.Secrets) != 0 {
			t.Fatal("empty update projection")
		}
		if targetSnapshot(t, db)["extension_secrets"] != retained {
			t.Fatal("empty update removed retained secrets")
		}
		uninstall, e := svc.PreviewUninstall(ctx, actor, ids[0])
		if e != nil {
			t.Fatal("retained uninstall preview")
		}
		denied := targetSnapshot(t, db)
		if e = svc.ApplyUninstall(ctx, actor, ids[0], uninstall.ID, uninstall.Confirmation); !errors.Is(e, ErrConflict) {
			t.Fatal("retained uninstall must conflict")
		}
		targetUnchanged(t, db, denied)
		got, e = svc.Rollback(ctx, actor, ids[0], "rollback scope.first to "+update.ArtifactPin)
		if e != nil || len(got.Secrets) != 2 || !got.Secrets[1].Configured || !got.Secrets[1].RotatedAt.Equal(initial.Add(3*time.Minute)) {
			t.Fatal("rollback restored status")
		}
		if targetSnapshot(t, db)["extension_secrets"] != retained {
			t.Fatal("rollback changed retained rows")
		}
		p, e = svc.PreviewUpdate(ctx, actor, ids[0], empty)
		if e != nil {
			t.Fatal("second empty preview")
		}
		if _, e = svc.ApplyUpdate(ctx, actor, ids[0], p.ID, p.Confirmation); e != nil {
			t.Fatal("second empty apply")
		}
		p, e = svc.PreviewDeleteSecrets(ctx, actor, ids[0])
		if e != nil {
			t.Fatal("delete preview")
		}
		got, e = svc.ApplyDeleteSecrets(ctx, actor, ids[0], p.ID, p.Confirmation)
		if e != nil || got.Secrets == nil || len(got.Secrets) != 0 {
			t.Fatal("delete empty-grant result")
		}
		var count int
		if e = db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", ids[0]).Scan(&count); e != nil || count != 0 {
			t.Fatal("delete must remove ALL retained A rows")
		}
		p, e = svc.PreviewUninstall(ctx, actor, ids[0])
		if e != nil {
			t.Fatal("final uninstall preview")
		}
		if e = svc.ApplyUninstall(ctx, actor, ids[0], p.ID, p.Confirmation); e != nil {
			t.Fatal("final uninstall")
		}
		if _, e = svc.Get(ctx, ids[0]); !errors.Is(e, ErrNotFound) {
			t.Fatal("uninstalled instance visible")
		}
		var bInstance, bSecrets string
		if e = db.QueryRow("SELECT to_jsonb(i)::text FROM extension_instances i WHERE instance_id=$1", ids[1]).Scan(&bInstance); e != nil || bInstance != otherInstance {
			t.Fatal("other instance changed")
		}
		if e = db.QueryRow("SELECT jsonb_agg(to_jsonb(s) ORDER BY slot)::text FROM extension_secrets s WHERE instance_id=$1", ids[1]).Scan(&bSecrets); e != nil || bSecrets != otherSecrets {
			t.Fatal("other secrets changed")
		}
	})
	t.Run("errors-even-empty", func(t *testing.T) {
		before := targetSnapshot(t, db)
		for _, slots := range [][]string{nil, {}, {"secret.active"}} {
			direct := Instance{InstanceID: ids[1], SecretSlots: slots}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if e := svc.loadSecretStatus(canceled, &direct); !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation swallowed")
			}
			direct.InstanceID = "invalid"
			if e := svc.loadSecretStatus(ctx, &direct); e == nil {
				t.Fatal("SQL error swallowed")
			}
		}
		targetUnchanged(t, db, before)
		if e := db.Close(); e != nil {
			t.Fatal("close fixture DB")
		}
		for _, slots := range [][]string{nil, {}, {"secret.active"}} {
			direct := Instance{InstanceID: ids[1], SecretSlots: slots}
			if e := svc.loadSecretStatus(ctx, &direct); e == nil {
				t.Fatal("closed DB swallowed")
			}
		}
	})
	if len(runtime.calls) != 0 {
		t.Fatal("unexpected runtime call")
	}
}

func secretStatusScopeMismatch(got, want []SecretStatus) string {
	if len(got) != len(want) {
		return "length"
	}
	for i := range want {
		if got[i].Slot != want[i].Slot {
			return "slot/order"
		}
		if got[i].Configured != want[i].Configured {
			return "configured"
		}
		if want[i].Configured {
			if !got[i].RotatedAt.Equal(want[i].RotatedAt) {
				return "configured timestamp"
			}
		} else if !got[i].RotatedAt.IsZero() {
			return "absent timestamp"
		}
	}
	return ""
}

func TestSecretStatusScopeTimestampOracle(t *testing.T) {
	instant := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	want := []SecretStatus{{Slot: "secret.absent"}, {Slot: "secret.active", Configured: true, RotatedAt: instant}}
	for _, tc := range []struct {
		name     string
		change   func([]SecretStatus) []SecretStatus
		mismatch string
	}{
		{"same", func(s []SecretStatus) []SecretStatus { return s }, ""},
		{"fixed-zero-zone", func(s []SecretStatus) []SecretStatus { s[1].RotatedAt = instant.In(time.FixedZone("", 0)); return s }, ""},
		{"fixed-offset-zone", func(s []SecretStatus) []SecretStatus {
			s[1].RotatedAt = instant.In(time.FixedZone("offset", 3600))
			return s
		}, ""},
		{"length", func(s []SecretStatus) []SecretStatus { return s[:1] }, "length"},
		{"order", func(s []SecretStatus) []SecretStatus { s[0], s[1] = s[1], s[0]; return s }, "slot/order"},
		{"slot", func(s []SecretStatus) []SecretStatus { s[0].Slot = "secret.other"; return s }, "slot/order"},
		{"configured", func(s []SecretStatus) []SecretStatus { s[1].Configured = false; return s }, "configured"},
		{"nanosecond", func(s []SecretStatus) []SecretStatus { s[1].RotatedAt = instant.Add(time.Nanosecond); return s }, "configured timestamp"},
		{"missing-configured-time", func(s []SecretStatus) []SecretStatus { s[1].RotatedAt = time.Time{}; return s }, "configured timestamp"},
		{"nonzero-absent-time", func(s []SecretStatus) []SecretStatus { s[0].RotatedAt = instant; return s }, "absent timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.change(append([]SecretStatus(nil), want...))
			if mismatch := secretStatusScopeMismatch(got, want); mismatch != tc.mismatch {
				t.Fatalf("oracle category: got %q, want %q", mismatch, tc.mismatch)
			}
		})
	}
}

// Fixture-only retained rows and infinity timestamps are not production writes.
// Plans prove returned-row reduction, not latency or bounded database work.
func TestSecretStatusScopePlansAndInfinity(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), &recordingRuntime{})
	if err != nil {
		t.Fatal("plan service setup")
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "secret-status-plan"}
	instant := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return instant }
	id := "aaaaaaaa-aaaa-4aaa-8aaa-000000000003"
	slots := []string{"secret.absent", "secret.active"}
	_, err = svc.Install(ctx, actor, InstallRequest{InstanceID: id, ExtensionID: "scope.plans", Repository: "https://github.com/gotthboard/gotth-extension-scope", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: slots, Metadata: Metadata{Schema: MetadataSchema, Fields: []Field{{Name: "secret.absent", Label: "Absent", Kind: FieldSecret}, {Name: "secret.active", Label: "Active", Kind: FieldSecret}}}})
	if err != nil {
		t.Fatal("plan install")
	}
	input := ConfigureInput{Configuration: map[string]any{}, Secrets: map[string]string{"secret.active": "synthetic-plan"}}
	p, err := svc.PreviewConfigure(ctx, actor, id, input)
	if err != nil {
		t.Fatal("plan configure preview")
	}
	if _, err = svc.ApplyConfigure(ctx, actor, id, p.ID, p.Confirmation, input); err != nil {
		t.Fatal("plan configure apply")
	}
	const oldQuery = `SELECT slot, rotated_at FROM extension_secrets WHERE instance_id=$1 ORDER BY slot`
	want := []SecretStatus{{Slot: "secret.absent"}, {Slot: "secret.active", Configured: true, RotatedAt: instant}}
	for _, retained := range []int{0, 1024} {
		t.Run(fmt.Sprintf("retained-%d", retained), func(t *testing.T) {
			if retained != 0 {
				// Clone synthetic fixture bytes only; never decrypt or log stored values.
				result, e := db.ExecContext(ctx, `INSERT INTO extension_secrets(instance_id,slot,nonce,ciphertext,key_version,configured_at,rotated_at) SELECT s.instance_id,'retired.' || g::text,s.nonce,s.ciphertext,s.key_version,s.configured_at,s.rotated_at FROM extension_secrets s CROSS JOIN generate_series(1,$2::integer) g WHERE s.instance_id=$1 AND s.slot='secret.active'`, id, retained)
				if e != nil {
					t.Fatal("retained fixture insert")
				}
				count, e := result.RowsAffected()
				if e != nil || count != int64(retained) {
					t.Fatal("retained fixture count")
				}
			}
			var matched, total int
			if e := db.QueryRowContext(ctx, "SELECT count(*), count(*) FILTER (WHERE slot=ANY($2::text[])) FROM extension_secrets WHERE instance_id=$1", id, postgresTextArray(slots)).Scan(&total, &matched); e != nil || matched != 1 || total != matched+retained {
				t.Fatal("fixture matched/total count")
			}
			before := targetSnapshot(t, db)
			for _, query := range []struct {
				name, sql string
				args      []any
				rows      int
			}{
				{"old", oldQuery, []any{id}, matched + retained},
				{"current", secretStatusQuery, []any{id, postgresTextArray(slots)}, matched},
			} {
				var raw []byte
				if e := db.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query.sql, query.args...).Scan(&raw); e != nil {
					t.Fatal("paired plan execution: " + query.name)
				}
				var plan []struct {
					Plan struct {
						Rows  int `json:"Actual Rows"`
						Loops int `json:"Actual Loops"`
					}
				}
				if e := json.Unmarshal(raw, &plan); e != nil || len(plan) != 1 || plan[0].Plan.Rows != query.rows || plan[0].Plan.Loops != 1 {
					t.Fatal("paired plan root rows/loops: " + query.name)
				}
				t.Logf("paired-plan retained=%d matched=%d query=%s sql=%q args=%v plan=%s", retained, matched, query.name, query.sql, query.args, raw)
			}
			direct := Instance{InstanceID: id, SecretSlots: slots}
			if e := svc.loadSecretStatus(ctx, &direct); e != nil {
				t.Fatal("plan projection load")
			}
			if mismatch := secretStatusScopeMismatch(direct.Secrets, want); mismatch != "" {
				t.Fatal("plan projection: " + mismatch)
			}
			targetUnchanged(t, db, before)
		})
	}
	t.Run("retired-infinity-is-omitted", func(t *testing.T) {
		if _, e := db.ExecContext(ctx, "UPDATE extension_secrets SET rotated_at='infinity' WHERE instance_id=$1 AND slot='retired.1'", id); e != nil {
			t.Fatal("retired infinity fixture")
		}
		before := targetSnapshot(t, db)
		// Old selection encounters the SQL-valid but non-production infinity row.
		rows, e := db.QueryContext(ctx, oldQuery, id)
		if e != nil {
			t.Fatal("old infinity query")
		}
		scanFailed := false
		for rows.Next() {
			var slot string
			var rotated time.Time
			if rows.Scan(&slot, &rotated) != nil {
				scanFailed = true
				break
			}
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		if !scanFailed || rowsErr != nil || closeErr != nil {
			t.Fatal("old infinity scan contract")
		}
		direct := Instance{InstanceID: id, SecretSlots: slots}
		if e = svc.loadSecretStatus(ctx, &direct); e != nil {
			t.Fatal("retired infinity not omitted")
		}
		if mismatch := secretStatusScopeMismatch(direct.Secrets, want); mismatch != "" {
			t.Fatal("retired infinity projection: " + mismatch)
		}
		targetUnchanged(t, db, before)
	})
	t.Run("current-infinity-still-errors", func(t *testing.T) {
		if _, e := db.ExecContext(ctx, "UPDATE extension_secrets SET rotated_at='infinity' WHERE instance_id=$1 AND slot='secret.active'", id); e != nil {
			t.Fatal("current infinity fixture")
		}
		before := targetSnapshot(t, db)
		direct := Instance{InstanceID: id, SecretSlots: slots}
		if e := svc.loadSecretStatus(ctx, &direct); e == nil {
			t.Fatal("current infinity scan error swallowed")
		}
		targetUnchanged(t, db, before)
	})
}
