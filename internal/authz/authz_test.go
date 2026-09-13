package authz

import (
	"context"
	"testing"
)

func TestExplainPoliciesForActorClasses(t *testing.T) {
	az := StaticAuthorizer{Mappings: []RoleMapping{
		{AuthentikGroup: "admins", Role: RoleGlobalAdmin, Verified: true},
		{AuthentikGroup: "domain-managers", Role: RoleDomainManager, Domain: "example.test", Verified: true},
		{AuthentikGroup: "domain-example", Role: RoleScopedDomainAccess, Domain: "example.test", Verified: true},
	}}
	cases := []struct {
		name string
		a    Actor
		act  Action
		r    Resource
		want bool
	}{
		{"local", Actor{Type: "local_admin"}, "anything", Resource{Type: "system", ID: "x"}, true},
		{"break glass ok", Actor{Type: "break_glass"}, "bootstrap:create-admin", Resource{Type: "system", ID: "x"}, true},
		{"break glass deny", Actor{Type: "break_glass"}, "domain:delete", Resource{Type: "domain", ID: "example.test"}, false},
		{"api token", Actor{Type: "api_token", Scopes: []string{"status:read"}}, "status:read", Resource{Type: "system", ID: "x"}, true},
		{"plugin deny", Actor{Type: "plugin_service"}, "policy:grant", Resource{Type: "system", ID: "x"}, false},
		{"system ok", Actor{Type: "system"}, "system:reconcile", Resource{Type: "system", ID: "x"}, true},
		{"scim ok", Actor{Type: "scim_client"}, "scim:user.create", Resource{Type: "domain", ID: "example.test"}, true},
		{"scim deny", Actor{Type: "scim_client"}, "policy:grant", Resource{Type: "system", ID: "x"}, false},
		{"oidc status", Actor{Type: "oidc_subject", Groups: []string{}}, "status:read", Resource{Type: "system", ID: "x"}, true},
		{"oidc global", Actor{Type: "oidc_subject", Groups: []string{"admins"}}, "domain:delete", Resource{Type: "domain", ID: "example.test"}, true},
		{"oidc domain manager", Actor{Type: "oidc_subject", Groups: []string{"domain-managers"}}, "mailbox:create", Resource{Type: "mailbox", ID: "user@example.test"}, true},
		{"oidc scoped read", Actor{Type: "oidc_subject", Groups: []string{"domain-example"}}, "mailbox:read", Resource{Type: "mailbox", ID: "user@example.test"}, true},
		{"oidc scoped deny write", Actor{Type: "oidc_subject", Groups: []string{"domain-example"}}, "mailbox:create", Resource{Type: "mailbox", ID: "user@example.test"}, false},
		{"oidc no mapping deny", Actor{Type: "oidc_subject", Groups: []string{"other"}}, "mailbox:create", Resource{Type: "mailbox", ID: "user@example.test"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, err := az.Explain(context.Background(), tc.a, tc.act, tc.r)
			if err != nil {
				t.Fatal(err)
			}
			if ex.Decision.Allow != tc.want {
				t.Fatalf("allow=%v want %v reason=%s", ex.Decision.Allow, tc.want, ex.Decision.Reason)
			}
			if len(ex.Steps) == 0 {
				t.Fatal("missing steps")
			}
			if tc.want && len(ex.MatchedRules) == 0 {
				t.Fatal("allow missing matched rules")
			}
			if !tc.want && len(ex.MissingRequirements) == 0 {
				t.Fatal("deny missing requirements")
			}
		})
	}
}

func TestValidateRoleMappingsDoctorProblems(t *testing.T) {
	problems := ValidateRoleMappings([]RoleMapping{
		{AuthentikGroup: "admins", Role: RoleGlobalAdmin, Verified: true},
		{AuthentikGroup: "", Role: RoleDomainManager, Domain: "missing.test", Verified: false},
	}, []string{"example.test"})
	want := map[string]bool{"authentik_group_required": true, "unknown_domain:missing.test": true, "mapping_unverified:": true, "missing_required_mapping:scoped_domain_access": true}
	for _, p := range problems {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing problems %#v from %#v", want, problems)
	}
}

func TestAuthentikAdminsGroupMapsToGlobalAdmin(t *testing.T) {
	az := StaticAuthorizer{Mappings: []RoleMapping{{AuthentikGroup: "gotth-mail-admins", Role: RoleGlobalAdmin, Verified: true}}}
	dec, err := az.Decide(context.Background(), Actor{Type: "oidc_subject", ID: "Dan", Groups: []string{"gotth-mail-admins"}}, "mailbox:create", Resource{Type: "mailbox", ID: "user@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow || dec.Reason != "global admin role matched" {
		t.Fatalf("decision=%#v", dec)
	}
}
