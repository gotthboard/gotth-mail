package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestExtensionAPIFailsClosedAndKeepsSecretsWriteOnly(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	service, err := extensionsadmin.NewService(db, []byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := service.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{
		InstanceID: "00000000-0000-4000-8000-000000000019", ExtensionID: "notification.telegram", Repository: "https://github.com/gotthboard/gotth-extension-telegram", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, SecretSlots: []string{"telegram.bot-token"}, Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema, Fields: []extensionsadmin.Field{{Name: "telegram.chat-id", Label: "Chat ID", Kind: extensionsadmin.FieldString, Required: true}, {Name: "telegram.bot-token", Label: "Bot token", Kind: extensionsadmin.FieldSecret, Required: true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("extension-admin", "api_token", "extension-api-secret", "ops:admin"); err != nil {
		t.Fatal(err)
	}
	handler := (Server{Identity: ids, Authz: authz.StaticAuthorizer{}, Extensions: service}).Handler()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/extensions", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/extensions", nil)
	request.Header.Set("Authorization", "Bearer extension-api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), instance.InstanceID) {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}

	body := []byte(`{"configuration":{"telegram.chat-id":"12345"},"secrets":{"telegram.bot-token":"must-not-escape"}}`)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/extensions/"+instance.InstanceID+"/configure/preview", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer extension-api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"operation":"configure"`) {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-escape") {
		t.Fatal("write-only secret escaped API preview")
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/extensions/"+instance.InstanceID+"/configure/preview", strings.NewReader(`{"configuration":{},"unknown":true}`))
	request.Header.Set("Authorization", "Bearer extension-api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON status=%d body=%s", response.Code, response.Body.String())
	}
}
