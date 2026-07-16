package authz

import (
	"context"
	"testing"
)

func TestExplainPolicies(t *testing.T) {
	az := StaticAuthorizer{}
	cases := []struct {
		a    Actor
		act  Action
		want bool
	}{{Actor{Type: "local_admin"}, "anything", true}, {Actor{Type: "break_glass"}, "bootstrap:create-admin", true}, {Actor{Type: "break_glass"}, "domain:delete", false}, {Actor{Type: "api_token", Scopes: []string{"status:read"}}, "status:read", true}, {Actor{Type: "plugin_service"}, "policy:grant", false}, {Actor{Type: "oidc_subject"}, "status:read", false}}
	for _, tc := range cases {
		ex, err := az.Explain(context.Background(), tc.a, tc.act, Resource{Type: "system", ID: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if ex.Decision.Allow != tc.want {
			t.Fatalf("%s got %v want %v (%s)", tc.a.Type, ex.Decision.Allow, tc.want, ex.Decision.Reason)
		}
		if len(ex.Steps) == 0 {
			t.Fatal("missing explanation steps")
		}
	}
}
