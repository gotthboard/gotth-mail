package extensionsadmin

import (
	"context"
	"errors"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"github.com/lib/pq"
	"strings"
	"testing"
	"time"
)

// Safe behavioral red: only42 bytes, never the known oversized diagnostic path.
func TestInstanceBoundaryRejectsBeforeUUIDParser(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	db.SetMaxOpenConns(1)
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), &recordingRuntime{})
	if err != nil {
		t.Fatal("fixture")
	}
	actor := audit.ActorRef{Type: "api_token", ID: "boundary"}
	for _, op := range []string{"get", "rollback"} {
		t.Run(op, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			before := targetSnapshot(t, db)
			if op == "get" {
				_, err = svc.Get(ctx, strings.Repeat("a", 42))
			} else {
				_, err = svc.Rollback(ctx, actor, strings.Repeat("a", 42), "rollback notification.boundary to sha256:"+strings.Repeat("1", 64))
			}
			var pe *pq.Error
			if err == nil || errors.As(err, &pe) || errors.Is(err, ErrConfirmation) {
				t.Errorf("impossible UUID reached parser or wrong error class: %T", err)
			}
			targetUnchanged(t, db, before)
			if err := db.PingContext(ctx); err != nil {
				t.Error("pool unusable")
			}
		})
	}
}

func TestInstanceBoundaryCompatibility(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	db.SetMaxOpenConns(1)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	runtime := &recordingRuntime{health: Health{Healthy: true, Code: "extension.ready"}}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	actor := audit.ActorRef{Type: "api_token", ID: "boundary"}
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	original, err := svc.Install(context.Background(), actor, InstallRequest{InstanceID: id, ExtensionID: "notification.boundary", Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: Metadata{Schema: MetadataSchema}})
	check(err)
	// Braces plus six/seven optional hyphens: exact40/41 native representations.
	aliases := []string{"{aaaaaaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}", "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"}
	for i, alias := range aliases {
		if len(alias) != 40+i {
			t.Fatal("alias fixture length")
		}
		got, err := svc.Get(context.Background(), alias)
		check(err)
		if got.InstanceID != id {
			t.Fatal("alias identity")
		}
	}
	var pid int
	check(db.QueryRow("SELECT pg_backend_pid()").Scan(&pid))
	for _, op := range []string{"get", "rollback"} {
		t.Run(op, func(t *testing.T) {
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("fixture type=%T", err)
				}
			}
			call := func(ctx context.Context, id string) error {
				if op == "get" {
					_, err := svc.Get(ctx, id)
					return err
				}
				_, err := svc.Rollback(ctx, actor, id, "rollback notification.boundary to "+original.ArtifactPin)
				return err
			}
			before := targetSnapshot(t, db)
			for _, size := range []int{42, 65536} {
				err := call(context.Background(), strings.Repeat("a", size))
				var pe *pq.Error
				if err == nil || errors.As(err, &pe) || errors.Is(err, ErrConfirmation) || err.Error() != "invalid extension instance ID" {
					t.Errorf("guard class type=%T", err)
				}
			}
			err := call(context.Background(), "invalid")
			var pe *pq.Error
			if !errors.As(err, &pe) || pe.Code != "22P02" {
				t.Error("short-invalid SQL error changed")
			}
			if !errors.Is(call(context.Background(), "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), ErrNotFound) {
				t.Error("absent distinction")
			}
			var same int
			check(db.QueryRow("SELECT pg_backend_pid()").Scan(&same))
			if same != pid {
				t.Error("single pool backend replaced")
			}
			tx, err := db.Begin()
			check(err)
			check(tx.QueryRow("SELECT pg_backend_pid()").Scan(&same))
			check(tx.Rollback())
			if same != pid {
				t.Error("transaction backend changed")
			}
			targetUnchanged(t, db, before)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if !errors.Is(call(ctx, id), context.Canceled) {
				t.Error("short cancelled precedence")
			}
			if op == "rollback" {
				if !errors.Is(call(ctx, strings.Repeat("a", 42)), context.Canceled) {
					t.Error("BeginTx precedence changed")
				}
			} else if err := call(ctx, strings.Repeat("a", 42)); err == nil || errors.Is(err, context.Canceled) {
				t.Error("Get long early precedence absent")
			}
		})
	}
	if len(runtime.calls) != 0 {
		t.Fatal("denial runtime effect")
	}
	// Real update establishes valid rollback confirmation and snapshot, not vacuous denial.
	update := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: original.Metadata}
	p, err := svc.PreviewUpdate(context.Background(), actor, id, update)
	check(err)
	_, err = svc.ApplyUpdate(context.Background(), actor, id, p.ID, p.Confirmation)
	check(err)
	before := targetSnapshot(t, db)
	_, err = svc.Rollback(context.Background(), actor, id, "wrong")
	if !errors.Is(err, ErrConfirmation) {
		t.Error("rollback confirmation changed")
	}
	targetUnchanged(t, db, before)
	got, err := svc.Rollback(context.Background(), actor, aliases[1], "rollback notification.boundary to "+original.ArtifactPin)
	check(err)
	if got.ArtifactPin != original.ArtifactPin || got.ConfigurationRev != 3 {
		t.Error("rollback result")
	}
	_, err = svc.Test(context.Background(), actor, aliases[0])
	check(err)
	_, err = svc.Enable(context.Background(), actor, aliases[1])
	check(err)
	_, err = svc.Disable(context.Background(), actor, aliases[0])
	check(err)
	if len(runtime.calls) == 0 {
		t.Fatal("positive lifecycle vacuous")
	}
	_, actorErr := svc.Rollback(context.Background(), audit.ActorRef{}, strings.Repeat("a", 42), "")
	if actorErr == nil || actorErr.Error() == "invalid extension instance ID" {
		t.Error("actor precedence changed")
	}
	check(db.Close())
	_, shortErr := svc.Get(context.Background(), id)
	if shortErr == nil || errors.Is(shortErr, ErrConfirmation) || errors.Is(shortErr, ErrNotFound) {
		t.Error("closedDB short operational error")
	}
	_, longErr := svc.Get(context.Background(), strings.Repeat("a", 42))
	if longErr == nil || longErr.Error() != "invalid extension instance ID" {
		t.Error("long Get precedence")
	}
	_, rollbackErr := svc.Rollback(context.Background(), actor, strings.Repeat("a", 42), "")
	if rollbackErr == nil || rollbackErr.Error() != shortErr.Error() {
		t.Error("closedDB BeginTx precedence")
	}
}
