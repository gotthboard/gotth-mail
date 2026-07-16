package authz

import (
	"context"
	"strings"
)

type Actor struct {
	Type, ID string
	Scopes   []string
}
type Action string
type Resource struct{ Type, ID string }
type Decision struct {
	Allow  bool
	Reason string
}
type Explanation struct {
	Decision Decision
	Steps    []string
}
type Authorizer interface {
	Decide(context.Context, Actor, Action, Resource) (Decision, error)
	Explain(context.Context, Actor, Action, Resource) (Explanation, error)
}

type StaticAuthorizer struct{}

func (StaticAuthorizer) Decide(ctx context.Context, a Actor, act Action, r Resource) (Decision, error) {
	switch a.Type {
	case "local_admin":
		return Decision{true, "local admin may administer all resources"}, nil
	case "break_glass":
		if strings.HasPrefix(string(act), "bootstrap:") || strings.HasPrefix(string(act), "recovery:") {
			return Decision{true, "break-glass limited to bootstrap/recovery"}, nil
		}
		return Decision{false, "break-glass denied outside bootstrap/recovery"}, nil
	case "api_token":
		for _, s := range a.Scopes {
			if s == string(act) || s == "*" {
				return Decision{true, "api token scope matched"}, nil
			}
		}
		return Decision{false, "api token scope missing"}, nil
	case "plugin_service":
		if strings.HasPrefix(string(act), "plugin:") && !strings.Contains(string(act), "grant") && !strings.Contains(string(act), "policy") {
			return Decision{true, "plugin service limited to plugin actions"}, nil
		}
		return Decision{false, "plugin service cannot mutate core policy or grant roles"}, nil
	case "oidc_subject", "scim_client":
		return Decision{false, "identity actor is placeholder until v2"}, nil
	default:
		return Decision{false, "unknown actor type"}, nil
	}
}
func (s StaticAuthorizer) Explain(ctx context.Context, a Actor, act Action, r Resource) (Explanation, error) {
	d, err := s.Decide(ctx, a, act, r)
	return Explanation{Decision: d, Steps: []string{"load actor", "match v0 static policy", d.Reason}}, err
}
