package main

import (
	"strings"
	"testing"
)

func TestCLIGroupRoleClosedFlags(t *testing.T) {
	base := []string{"identity", "group-role", "preview", "--config", "config.yaml", "--operation", "admit", "--issuer", "https://auth.example/application/o/gotth-mail/", "--scim-actor", "actor", "--group-id", "opaque", "--role", "domain_manager", "--domain", "example.test"}
	r, e := groupRoleRequest(base)
	if e != nil || r.SCIMActor != "actor" || r.GroupID != "opaque" {
		t.Fatal(r, e)
	}
	for _, extra := range [][]string{{"--scope", "chosen"}, {"--issuer", "duplicate"}, {"--base-url", "https://other.example"}, {"--subject", "user"}, {"--mailbox", "a@example.test"}, {"--unknown", "x"}, {"--confirm", strings.Repeat("0", 64)}, {"--domain"}, {"--group-id", ""}} {
		args := append(append([]string(nil), base...), extra...)
		if _, e = groupRoleRequest(args); e == nil {
			t.Fatalf("closed flags admitted %v", extra)
		}
	}
	for _, args := range [][]string{nil, {"identity", "group-role"}, {"identity", "group-role", "unknown"}} {
		if _, e = groupRoleRequest(args); e == nil {
			t.Fatal("invalid mode admitted")
		}
	}
	apply := append([]string(nil), base...)
	apply[2] = "apply"
	if _, e = groupRoleRequest(apply); e == nil {
		t.Fatal("unconfirmed apply admitted parser")
	}
	apply = append(apply, "--confirm", strings.Repeat("0", 64))
	if _, e = groupRoleRequest(apply); e != nil {
		t.Fatal(e)
	}
}

func TestCLIGroupAllRolesDomainShape(t *testing.T) {
	base := []string{"identity", "group-role", "preview", "--config", "c", "--operation", "admit", "--issuer", "https://auth.example/application/o/gotth-mail/", "--scim-actor", "actor", "--group-id", "g", "--role", "global_admin"}
	if r, e := groupRoleRequest(base); e != nil || r.Domain != "" {
		t.Fatal(r, e)
	}
	for _, domain := range []string{"", "example.test"} {
		if _, e := groupRoleRequest(append(append([]string(nil), base...), "--domain", domain)); e == nil {
			t.Fatal("global explicit domain accepted")
		}
	}
	for _, role := range []string{"domain_manager", "scoped_domain_access"} {
		a := append([]string(nil), base...)
		a[14] = role
		if _, e := groupRoleRequest(a); e == nil {
			t.Fatal("scoped missingdomain")
		}
		if _, e := groupRoleRequest(append(a, "--domain", "example.test")); e != nil {
			t.Fatal(e)
		}
	}
}

func TestCLIGroupRolePreservesNormalizedRole(t *testing.T) {
	for _, role := range []string{"domain_manager", "scoped_domain_access", "global_admin"} {
		a := []string{"identity", "group-role", "preview", "--config", "c", "--operation", "admit", "--issuer", "https://auth.example/application/o/gotth-mail/", "--scim-actor", "actor", "--group-id", "g", "--role", " " + role + " "}
		if role != "global_admin" {
			a = append(a, "--domain", "example.test")
		}
		if _, e := groupRoleRequest(a); e != nil {
			t.Fatal("service role normalization regressed", role, e)
		}
	}
}
