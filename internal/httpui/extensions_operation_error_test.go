package httpui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestExtensionOperationErrorRoute(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recoveryRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000028"
	actor := audit.ActorRef{Type: "local_admin", ID: "fixture"}
	_, err = svc.Install(context.Background(), actor, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.error", Repository: "https://github.com/gotthboard/gotth-extension-error", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "config.note", Label: "Note", Kind: extensionsadmin.FieldString}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE extension_instances SET configuration_json='{"config.note":"stored-value"}'::jsonb WHERE instance_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	item, err := svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	target := extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: item.ManifestDigest, GrantDigest: item.GrantDigest, SessionDigest: item.SessionDigest, Metadata: item.Metadata}
	preview, err := svc.PreviewUpdate(context.Background(), actor, id, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ApplyUpdate(context.Background(), actor, id, preview.ID, preview.Confirmation); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const sid, csrf = "error-session", "error-csrf"
	bound := authn.BoundSession{Session: authn.Session{ID: sid, IdentityRefID: "admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), identity.NewService("example.test"), authz.StaticAuthorizer{}, uiSessionStore{bound: bound}, func() time.Time { return now }, svc)
	request := func(action string) *httptest.ResponseRecorder {
		req := formReq(http.MethodPost, "/admin/extensions/"+id, url.Values{"action": {action}, "csrf_token": {csrf}, "confirmation": {"wrong"}, "field.config.note": {"submitted-value"}}, "")
		withIdentityCookies(req, sid, csrf)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	const private = "PRIVATE-operation-canary-7bd239"
	const fallback = "Extension operation could not be confirmed. Check current state before retrying."
	for _, tc := range []struct {
		name, action, want string
		fault              error
		calls              []string
	}{
		{"private-runtime", "test", fallback, errors.New(private), []string{"start", "probe", "stop"}},
		{"wrapped-runtime", "test", "extension runtime unauthenticated", fmt.Errorf(private+": %w", extensionsadmin.ErrUnauthenticated), []string{"start", "probe", "stop"}},
		{"rollback-confirmation", "rollback", "extension confirmation rejected", nil, nil},
		{"invalid-action", "invalid", fallback, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := targetUISnapshot(t, db)
			runtime.calls = nil
			runtime.probeErr = tc.fault
			res := request(tc.action)
			body := res.Body.String()
			if res.Code != 200 {
				t.Error("action denial HTTP compatibility changed")
			}
			if !reflect.DeepEqual(runtime.calls, tc.calls) {
				t.Error("unexpected service runtime effects")
			}
			if !reflect.DeepEqual(before, targetUISnapshot(t, db)) {
				t.Error("unexpected durable effects in precommit denial fixture")
			}
			if strings.Contains(body, private) {
				t.Error("private operation error leaked")
			}
			if !strings.Contains(body, tc.want) || !strings.Contains(body, `role="alert"`) || strings.Contains(body, "extension operation accepted") {
				t.Error("safe visible failure missing")
			}
			if !strings.Contains(body, `name="field.config.note" value="stored-value"`) || strings.Contains(body, "submitted-value") || !strings.Contains(body, "notification.error") {
				t.Error("pre-action item/field restoration lost")
			}
			if tc.action == "rollback" && !strings.Contains(body, "Check the confirmation required for this operation.") {
				t.Error("rollback-compatible confirmation help missing")
			}
		})
	}
	runtime.probeErr = nil
	runtime.calls = nil
	res := request("test")
	if res.Code != 200 || !strings.Contains(res.Body.String(), `<p role="status">extension operation accepted</p>`) || !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "stop"}) {
		t.Error("successful action status/effects changed")
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.test'", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("successful test audit missing")
	}
}

// Error must never be called even for unrecognized errors.
type operationOpaqueError struct{}

func (operationOpaqueError) Error() string { panic("raw Error called") }

func TestExtensionOperationErrorMessage(t *testing.T) {
	const fallback = "Extension operation could not be confirmed. Check current state before retrying."
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"unknown", errors.New("private diagnostic"), fallback},
		{"safe-generic", errors.New("invalid integer extension field"), fallback},
		{"sentinel-text-is-not-identity", errors.New("extension confirmation rejected"), fallback},
		{"no-error-method", operationOpaqueError{}, fallback},
		{"unavailable", extensionsadmin.ErrUnavailable, "extension administrator unavailable. Check current state before retrying."},
		{"not-found", extensionsadmin.ErrNotFound, "extension instance not found. Check current state before retrying."},
		{"conflict", extensionsadmin.ErrConflict, "extension state conflict. Check current state before retrying."},
		{"confirmation", extensionsadmin.ErrConfirmation, "extension confirmation rejected. Check the confirmation required for this operation. Check current state before retrying."},
		{"unauthenticated", extensionsadmin.ErrUnauthenticated, "extension runtime unauthenticated. Check current state before retrying."},
		{"unhealthy", extensionsadmin.ErrUnhealthy, "extension runtime unhealthy. Check current state before retrying."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extensionOperationErrorMessage(tc.err); got != tc.want {
				t.Error("wrong fixed error projection")
			}
			if tc.err != nil {
				// Wrapping and joining must not disclose the diagnostic sibling/prefix.
				for _, wrapped := range []error{fmt.Errorf("PRIVATE-prefix: %w", tc.err), errors.Join(errors.New("PRIVATE-sibling"), tc.err)} {
					if got := extensionOperationErrorMessage(wrapped); got != tc.want {
						t.Error("wrapped error projection changed")
					}
				}
			}
		})
	}
}
