package main

import (
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"strings"
)

// groupRoleRequest is a closed flag boundary independent of legacy commands.
// Complexity: n arguments, B bytes scanned at their boundaries: time O(n+B),
// Omega(n), no uniform tight Theta; auxiliary O(1), Omega(1), Theta(1) for the
// fixed eight-flag set storing string headers, not copies. No SQL/file/network.
func groupRoleRequest(args []string) (rolebinding.GroupRequest, error) {
	if len(args) < 3 || (args[2] != "preview" && args[2] != "apply") {
		return rolebinding.GroupRequest{}, fmt.Errorf("group-role requires preview or apply")
	}
	allowed := map[string]bool{"--config": true, "--operation": true, "--issuer": true, "--scim-actor": true, "--group-id": true, "--role": true, "--domain": true, "--confirm": true}
	values := make(map[string]string, len(allowed))
	for i := 3; i < len(args); i += 2 {
		if i+1 >= len(args) || !allowed[args[i]] || values[args[i]] != "" || strings.HasPrefix(args[i+1], "--") || strings.TrimSpace(args[i+1]) == "" {
			return rolebinding.GroupRequest{}, fmt.Errorf("invalid or duplicate group-role flag")
		}
		values[args[i]] = args[i+1]
	}
	for _, key := range []string{"--config", "--operation", "--issuer", "--scim-actor", "--group-id", "--role"} {
		if values[key] == "" {
			return rolebinding.GroupRequest{}, fmt.Errorf("%s required", key)
		}
	}
	switch strings.TrimSpace(values["--role"]) {
	case rolebinding.RoleGlobalAdmin:
		if _, present := values["--domain"]; present {
			return rolebinding.GroupRequest{}, fmt.Errorf("global_admin must omit --domain")
		}
	case rolebinding.RoleDomainManager, rolebinding.RoleScopedDomainAccess:
		if values["--domain"] == "" {
			return rolebinding.GroupRequest{}, fmt.Errorf("scoped role requires --domain")
		}
	default:
		return rolebinding.GroupRequest{}, fmt.Errorf("invalid role")
	}
	if args[2] == "preview" && values["--confirm"] != "" {
		return rolebinding.GroupRequest{}, fmt.Errorf("--confirm is valid only for apply")
	}
	if args[2] == "apply" && values["--confirm"] == "" {
		return rolebinding.GroupRequest{}, fmt.Errorf("--confirm <preview-digest> required")
	}
	return rolebinding.GroupRequest{Operation: values["--operation"], Issuer: values["--issuer"], SCIMActor: values["--scim-actor"], GroupID: values["--group-id"], Role: values["--role"], Domain: values["--domain"]}, nil
}
