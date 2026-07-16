package authn

import "errors"

type AuthentikConfig struct {
	Enabled                                                       bool
	BaseURL, OIDCClientID, SCIMBaseURL                            string
	GlobalAdminGroup, DomainManagerGroup, ScopedDomainGroupPrefix string
}

func (c AuthentikConfig) Validate() error {
	if !c.Enabled {
		return errors.New("authentik is required in v0")
	}
	if c.BaseURL == "" || c.OIDCClientID == "" || c.SCIMBaseURL == "" {
		return errors.New("authentik base, oidc, and scim settings required")
	}
	if c.GlobalAdminGroup == "" || c.DomainManagerGroup == "" || c.ScopedDomainGroupPrefix == "" {
		return errors.New("authentik role mappings required")
	}
	return nil
}
func BootstrapAvailable(authentikHealthy bool) bool { return true }
