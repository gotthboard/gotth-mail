package main

import (
	"os"
	"path/filepath"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
)

func TestConfigureDNSPlansFromEnvLoadsPublicPlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-plan.json")
	document := `{"plans":[{"domain":"Example.Test","mail_host":"MAIL.Example.Test","mail_ip":"192.0.2.10","ptr_expected":"mail.example.test","dkim_selector":"Mail","dkim_public_key_txt":"v=DKIM1; k=rsa; p=public","mta_sts":true}]}`
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_DNS_PLAN_FILE", path)
	server := api.Server{}
	if err := configureDNSPlansFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	plan, ok := server.DNSPlans["example.test"]
	if !ok || plan.MailHost != "mail.example.test" || plan.MailIP != "192.0.2.10" || plan.DKIMSelector != "mail" {
		t.Fatalf("unexpected normalized DNS plan: %#v", server.DNSPlans)
	}
}

func TestConfigureDNSPlansFromEnvRejectsUnsafeOrAmbiguousFiles(t *testing.T) {
	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dns-plan.json")
		if err := os.WriteFile(path, []byte(`{"plans":[{"domain":"example.test","mail_host":"mail.example.test","dkim_selector":"mail","private_key":"forbidden"}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOTTH_MAIL_DNS_PLAN_FILE", path)
		if err := configureDNSPlansFromEnv(&api.Server{}); err == nil {
			t.Fatal("unknown field was accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		link := filepath.Join(dir, "link.json")
		if err := os.WriteFile(target, []byte(`{"plans":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOTTH_MAIL_DNS_PLAN_FILE", link)
		if err := configureDNSPlansFromEnv(&api.Server{}); err == nil {
			t.Fatal("symlink DNS plan was accepted")
		}
	})
	t.Run("duplicate domain", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dns-plan.json")
		document := `{"plans":[{"domain":"example.test","mail_host":"mail.example.test","dkim_selector":"mail"},{"domain":"EXAMPLE.TEST","mail_host":"mail.example.test","dkim_selector":"mail"}]}`
		if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOTTH_MAIL_DNS_PLAN_FILE", path)
		if err := configureDNSPlansFromEnv(&api.Server{}); err == nil {
			t.Fatal("duplicate DNS plan was accepted")
		}
	})
}
