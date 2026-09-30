package api

import (
	"context"
	"encoding/json"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestInstanceBoundaryAPI(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture type=%T", err)
		}
	}
	ids, err := identity.NewSQLService(context.Background(), db, "example.test")
	check(err)
	check(ids.AddTokenWithScopes("boundary", "api_token", "boundary-fixture", "ops:admin:gotth-mail"))
	check(ids.AddTokenWithScopes("narrow", "api_token", "boundary-narrow", "ops:admin:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	runtime := &targetAPIRuntime{}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	_, err = svc.Install(context.Background(), audit.ActorRef{Type: "local_admin", ID: "fixture"}, extensionsadmin.InstallRequest{InstanceID: id, ExtensionID: "notification.boundary", Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	check(err)
	h := (Server{Identity: ids, Authz: authz.StaticAuthorizer{}, Extensions: svc}).Handler()
	update, err := json.Marshal(extensionsadmin.UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: extensionsadmin.Metadata{Schema: extensionsadmin.MetadataSchema}})
	check(err)
	for _, op := range []string{"get", "configure/preview", "update/preview", "secrets/delete/preview", "uninstall/preview", "test", "enable", "disable", "rollback"} {
		t.Run(op, func(t *testing.T) {
			request := func(target, credential, body string) *httptest.ResponseRecorder {
				method := "POST"
				path := "/api/v1/extensions/" + target
				if op == "get" {
					method = "GET"
				} else {
					path += "/" + op
				}
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				if credential != "" {
					r.Header.Set("Authorization", "Bearer "+credential)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			body := "{}"
			if op == "update/preview" {
				body = string(update)
			}
			if op == "rollback" {
				body = "{\"confirmation\":\"rollback notification.boundary to sha256:" + strings.Repeat("1", 64) + "\"}"
			}
			before := apiTargetSnapshot(t, db)
			for _, target := range []string{strings.Repeat("a", 42), strings.Repeat("a", 65536), "invalid", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
				want := 400
				if strings.HasPrefix(target, "bbbb") {
					want = 404
				}
				w := request(target, "boundary-fixture", body)
				if w.Code != want {
					t.Errorf("initial status=%d want=%d", w.Code, want)
				}
				if strings.Contains(w.Body.String(), target) {
					t.Error("raw id reflected")
				}
				if !reflect.DeepEqual(before, apiTargetSnapshot(t, db)) || runtime.calls != 0 {
					t.Fatal("initial denial effect")
				}
			}
			if request(strings.Repeat("a", 42), "", body).Code != 401 || request(strings.Repeat("a", 42), "boundary-narrow", body).Code != 403 {
				t.Error("API product gate ordering")
			}
			if op == "configure/preview" || op == "update/preview" || op == "rollback" {
				w := request(id, "boundary-fixture", "{}")
				if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid extension") {
					t.Error("strict body parsing changed")
				}
			}
			if !reflect.DeepEqual(before, apiTargetSnapshot(t, db)) || runtime.calls != 0 {
				t.Error("auth/body denial effect")
			}
			if op == "get" {
				for _, alias := range []string{"{aaaaaaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}", "{aaaa-aaaa-aaaa-4aaa-8aaa-aaaa-aaaa-aaaa}"} {
					if request(alias, "boundary-fixture", body).Code != 200 {
						t.Error("native alias Get denied")
					}
				}
			}
		})
	}
}
