package authz

import (
	"context"
	"strings"
)

type Actor struct {
	Type, ID string
	Scopes   []string
	Groups   []string
}
type Action string
type Resource struct{ Type, ID string }
type Decision struct {
	Allow  bool
	Reason string
}
type Explanation struct {
	Decision            Decision
	Steps               []string
	MatchedRules        []string
	MissingRequirements []string
}
type Authorizer interface {
	Decide(context.Context, Actor, Action, Resource) (Decision, error)
	Explain(context.Context, Actor, Action, Resource) (Explanation, error)
}

type Role string

const (
	RoleGlobalAdmin        Role = "global_admin"
	RoleDomainManager      Role = "domain_manager"
	RoleScopedDomainAccess Role = "scoped_domain_access"
)

type RoleMapping struct {
	AuthentikGroup string
	Role           Role
	Domain         string
	Verified       bool
}

type StaticAuthorizer struct{ Mappings []RoleMapping }

func (s StaticAuthorizer) Decide(ctx context.Context, a Actor, act Action, r Resource) (Decision, error) {
	ex, err := s.Explain(ctx, a, act, r)
	return ex.Decision, err
}
func (s StaticAuthorizer) Explain(ctx context.Context, a Actor, act Action, r Resource) (Explanation, error) {
	ex := Explanation{Steps: []string{"load actor", "load resource", "evaluate policy"}}
	allow := func(reason string, rules ...string) (Explanation, error) {
		ex.Decision = Decision{true, reason}
		ex.MatchedRules = append(ex.MatchedRules, rules...)
		ex.Steps = append(ex.Steps, reason)
		return ex, nil
	}
	deny := func(reason string, missing ...string) (Explanation, error) {
		ex.Decision = Decision{false, reason}
		ex.MissingRequirements = append(ex.MissingRequirements, missing...)
		ex.Steps = append(ex.Steps, reason)
		return ex, nil
	}
	switch a.Type {
	case "local_admin":
		return allow("local admin may administer all resources", "local_admin:all")
	case "break_glass":
		if hasPrefix(act, "bootstrap:") || hasPrefix(act, "recovery:") {
			return allow("break-glass limited to bootstrap/recovery", "break_glass:bootstrap_recovery")
		}
		return deny("break-glass denied outside bootstrap/recovery", "bootstrap_or_recovery_action")
	case "api_token":
		for _, scope := range a.Scopes {
			if scope == string(act) || scope == "*" {
				return allow("api token scope matched", "api_token:scope:"+scope)
			}
		}
		return deny("api token scope missing", "matching_api_scope")
	case "plugin_service":
		if hasPrefix(act, "plugin:") && !strings.Contains(string(act), "grant") && !strings.Contains(string(act), "policy") {
			return allow("plugin service limited to plugin actions", "plugin_service:plugin_action")
		}
		return deny("plugin service cannot mutate core policy or grant roles", "non_policy_plugin_action")
	case "system":
		if hasPrefix(act, "system:") || hasPrefix(act, "notification:") {
			return allow("system actor limited to system actions", "system:system_action")
		}
		return deny("system actor denied for user/admin action", "system_action")
	case "scim_client":
		if hasPrefix(act, "scim:") || hasPrefix(act, "mailbox:provision") {
			return allow("SCIM client limited to provisioning actions", "scim_client:provisioning")
		}
		return deny("SCIM client denied outside provisioning", "scim_or_provisioning_action")
	case "oidc_subject":
		return s.explainOIDC(ex, a, act, r)
	default:
		return deny("unknown actor type", "known_actor_type")
	}
}

func (s StaticAuthorizer) explainOIDC(ex Explanation, a Actor, act Action, r Resource) (Explanation, error) {
	roles := s.rolesFor(a)
	if roles[RoleGlobalAdmin]["*"] {
		ex.Decision = Decision{true, "global admin role matched"}
		ex.MatchedRules = []string{"oidc:global_admin"}
		ex.Steps = append(ex.Steps, "global admin role matched")
		return ex, nil
	}
	if hasPrefix(act, "status:") || hasPrefix(act, "doctor:") {
		ex.Decision = Decision{true, "OIDC subject may read bounded status"}
		ex.MatchedRules = []string{"oidc:status_read"}
		ex.Steps = append(ex.Steps, "bounded read allowed")
		return ex, nil
	}
	domain := resourceDomain(r)
	if roles[RoleDomainManager][domain] && (hasPrefix(act, "domain:") || hasPrefix(act, "mailbox:") || hasPrefix(act, "alias:")) {
		ex.Decision = Decision{true, "domain manager role matched"}
		ex.MatchedRules = []string{"oidc:domain_manager:" + domain}
		ex.Steps = append(ex.Steps, "domain manager role matched")
		return ex, nil
	}
	if roles[RoleScopedDomainAccess][domain] && (hasPrefix(act, "mailbox:read") || hasPrefix(act, "alias:read") || hasPrefix(act, "domain:read")) {
		ex.Decision = Decision{true, "scoped domain access role matched"}
		ex.MatchedRules = []string{"oidc:scoped_domain_access:" + domain}
		ex.Steps = append(ex.Steps, "scoped domain access role matched")
		return ex, nil
	}
	ex.Decision = Decision{false, "OIDC subject lacks required Authentik role mapping"}
	ex.MissingRequirements = []string{"global_admin_or_domain_mapping"}
	ex.Steps = append(ex.Steps, "no matching Authentik role mapping")
	return ex, nil
}

func (s StaticAuthorizer) rolesFor(a Actor) map[Role]map[string]bool {
	out := map[Role]map[string]bool{RoleGlobalAdmin: {}, RoleDomainManager: {}, RoleScopedDomainAccess: {}}
	groups := map[string]bool{}
	for _, g := range a.Groups {
		groups[g] = true
	}
	for _, m := range s.Mappings {
		if !m.Verified || !groups[m.AuthentikGroup] {
			continue
		}
		domain := m.Domain
		if domain == "" {
			domain = "*"
		}
		out[m.Role][domain] = true
	}
	return out
}

func ValidateRoleMappings(ms []RoleMapping, knownDomains []string) []string {
	known := map[string]bool{}
	for _, d := range knownDomains {
		known[strings.ToLower(d)] = true
	}
	var problems []string
	seenRequired := map[Role]bool{}
	for _, m := range ms {
		if strings.TrimSpace(m.AuthentikGroup) == "" {
			problems = append(problems, "authentik_group_required")
		}
		switch m.Role {
		case RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess:
			seenRequired[m.Role] = true
		default:
			problems = append(problems, "unknown_role:"+string(m.Role))
		}
		if (m.Role == RoleDomainManager || m.Role == RoleScopedDomainAccess) && m.Domain != "" && !known[strings.ToLower(m.Domain)] {
			problems = append(problems, "unknown_domain:"+m.Domain)
		}
		if !m.Verified {
			problems = append(problems, "mapping_unverified:"+m.AuthentikGroup)
		}
	}
	for _, r := range []Role{RoleGlobalAdmin, RoleDomainManager, RoleScopedDomainAccess} {
		if !seenRequired[r] {
			problems = append(problems, "missing_required_mapping:"+string(r))
		}
	}
	return problems
}

func hasPrefix(a Action, p string) bool { return strings.HasPrefix(string(a), p) }
func resourceDomain(r Resource) string {
	if r.Type == "domain" {
		return strings.ToLower(r.ID)
	}
	if i := strings.LastIndex(r.ID, "@"); i >= 0 {
		return strings.ToLower(r.ID[i+1:])
	}
	return strings.ToLower(r.ID)
}
