package main

import (
	"database/sql"
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureIdentityRuntimeIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, []byte(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://auth.example/application/o/gotth-mail/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(identityruntime.ConfigFileEnv, path)
	t.Setenv(identityruntime.IssuerEnv, " https://auth.example/application/o/gotth-mail/// ")
	db := new(sql.DB)
	s := api.Server{OIDCStore: authn.SQLStore{DB: db}}
	if err := configureIdentityRuntimeFromEnv(&s); err != nil {
		t.Fatal(err)
	}
	got := s.OIDCStore.(authn.SQLStore)
	if got.DB != db || got.CurrentIssuer != "https://auth.example/application/o/gotth-mail/" || s.CurrentIssuer != got.CurrentIssuer {
		t.Fatal("configured authority not shared")
	}
	t.Setenv(identityruntime.IssuerEnv, "https://wrong.example/")
	if err := configureIdentityRuntimeFromEnv(&api.Server{}); err == nil {
		t.Fatal("mismatch admitted")
	}
	t.Setenv(identityruntime.ConfigFileEnv, "")
	s = api.Server{OIDCStore: authn.SQLStore{DB: db}}
	if err := configureIdentityRuntimeFromEnv(&s); err != nil || s.CurrentIssuer != "" || s.OIDCStore.(authn.SQLStore).CurrentIssuer != "" {
		t.Fatal("env-only group authority")
	}
}
