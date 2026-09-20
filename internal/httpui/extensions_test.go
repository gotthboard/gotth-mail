package httpui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestExtensionUIUsesMailOwnedMarkupAndNeverRendersSecret(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	service, err := extensionsadmin.NewService(db, []byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := service.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{
		InstanceID:     "00000000-0000-4000-8000-000000000018",
		ExtensionID:    "notification.telegram",
		Repository:     "https://github.com/gotthboard/gotth-extension-telegram",
		ArtifactPin:    "sha256:" + strings.Repeat("1", 64),
		ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64),
		Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, SecretSlots: []string{"telegram.bot-token"},
		Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "telegram.chat-id", Label: "Chat ID", Kind: extensionsadmin.FieldString, Required: true}, {Name: "telegram.bot-token", Label: "Bot token", Kind: extensionsadmin.FieldSecret, Required: true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("extension-admin", "api_token", "extension-admin-secret", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	handler := HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, nil, nil, service)

	request := httptest.NewRequest(http.MethodGet, "/admin/extensions/"+instance.InstanceID, nil)
	request.Header.Set("Authorization", "Bearer extension-admin-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", response.Code, response.Body.String())
	}
	for _, section := range []string{"Overview", "Configuration", "Secrets", "Permissions", "Health", "Audit", "Versions", "Rollback"} {
		if !strings.Contains(response.Body.String(), section) {
			t.Fatalf("missing section %q", section)
		}
	}

	form := url.Values{"action": {"configure-preview"}, "field.telegram.chat-id": {"12345"}, "field.telegram.bot-token": {"must-not-render"}}
	request = httptest.NewRequest(http.MethodPost, "/admin/extensions/"+instance.InstanceID, strings.NewReader(form.Encode()))
	request.Header.Set("Authorization", "Bearer extension-admin-secret")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Re-enter all changed secrets") {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-render") {
		t.Fatal("write-only secret rendered into extension UI")
	}

	now := time.Date(2026, 9, 19, 19, 0, 0, 0, time.UTC)
	const sessionID = "extension-admin-session"
	const csrf = "extension-admin-csrf"
	sessions := uiSessionStore{bound: authn.BoundSession{Session: authn.Session{ID: sessionID, IdentityRefID: "identity-admin", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), CSRFSecretHash: csrfHash(csrf)}, Mailbox: "admin@example.test", Roles: []authz.RoleAssignment{{Role: authz.RoleGlobalAdmin}}}}
	handler = HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, sessions, func() time.Time { return now }, service)
	request = httptest.NewRequest(http.MethodGet, "/admin/extensions/"+instance.InstanceID, nil)
	withIdentityCookies(request, sessionID, csrf)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name="csrf_token" value="`+csrf+`"`) {
		t.Fatalf("OIDC admin detail status=%d body=%s", response.Code, response.Body.String())
	}

	request = formReq(http.MethodPost, "/admin/extensions/"+instance.InstanceID, url.Values{"action": {"configure-preview"}, "field.telegram.chat-id": {"12345"}, "field.telegram.bot-token": {"still-secret"}}, "")
	withIdentityCookies(request, sessionID, csrf)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", response.Code, response.Body.String())
	}
	request = formReq(http.MethodPost, "/admin/extensions/"+instance.InstanceID, url.Values{"action": {"configure-preview"}, "csrf_token": {csrf}, "field.telegram.chat-id": {"12345"}, "field.telegram.bot-token": {"still-secret"}}, "")
	withIdentityCookies(request, sessionID, csrf)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Re-enter all changed secrets") || strings.Contains(response.Body.String(), "still-secret") {
		t.Fatalf("OIDC CSRF preview status=%d body=%s", response.Code, response.Body.String())
	}
}
