package config

import "testing"

const good = `server:
  public_url: "https://mail.example.test"
  listen: ":8080"
  environment: "development"
database:
  dsn: "postgres://db"
tls:
  mode: "manual"
  cert_path: "cert.pem"
  key_path: "key.pem"
authentik:
  enabled: true
  base_url: "https://auth.example.test"
  oidc_client_id: "gotth-mail"
  scim_base_url: "https://auth.example.test/scim"
roles:
  global_admin_group: "admins"
  domain_manager_group: "managers"
  scoped_domain_group_prefix: "domain-"
render:
  staging_dir: "var/staged"
  applied_dir: "var/applied"
  override_dir: "var/overrides"
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "stub:v0"
    endpoint: "dns:9443"
`

func TestParseValidateGoodConfig(t *testing.T) {
	c, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Plugins[0].Seam != "dns" {
		t.Fatalf("plugin not parsed: %#v", c.Plugins[0])
	}
}
func TestRejectUnknownTopLevel(t *testing.T) {
	_, err := Parse(good + "surprise:\n  x: y\n")
	if err == nil {
		t.Fatal("expected unknown top-level rejection")
	}
}
func TestRejectUnknownPluginKey(t *testing.T) {
	_, err := Parse(good + "  - name: \"bad\"\n    seam: \"dns\"\n    image: \"stub:v0\"\n    endpoint: \"dns:9443\"\n    docker_socket: true\n")
	if err == nil {
		t.Fatal("expected unknown plugin key rejection")
	}
}
func TestRejectProductionDevSelfSigned(t *testing.T) {
	c, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	c.Server.Environment = "production"
	c.TLS.Mode = "dev_self_signed"
	if err := c.Validate(); err == nil {
		t.Fatal("expected production dev_self_signed rejection")
	}
}
func TestRejectInvalidPluginSeam(t *testing.T) {
	c, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	c.Plugins[0].Seam = "docker-socket"
	if err := c.Validate(); err == nil {
		t.Fatal("expected plugin seam rejection")
	}
}
func TestRejectGeneratedOverrideOverlap(t *testing.T) {
	c, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	c.Render.OverrideDirs = []string{"var/staged/manual"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected overlap rejection")
	}
}
