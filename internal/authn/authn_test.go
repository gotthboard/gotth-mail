package authn

import "testing"

func TestAuthentikConfigAndBootstrap(t *testing.T) {
	c := AuthentikConfig{Enabled: true, BaseURL: "https://auth.example.test", OIDCClientID: "gotth-mail", SCIMBaseURL: "https://auth.example.test/scim", GlobalAdminGroup: "admins", DomainManagerGroup: "managers", ScopedDomainGroupPrefix: "domain-"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !BootstrapAvailable(false) {
		t.Fatal("bootstrap must not depend on authentik health")
	}
}
func TestAuthentikRequired(t *testing.T) {
	if err := (AuthentikConfig{}).Validate(); err == nil {
		t.Fatal("expected invalid empty authentik config")
	}
}
