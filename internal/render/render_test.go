package render

import (
	"forgejo/gotthboard/gotth-mail/internal/config"
	"strings"
	"testing"
)

func cfg() config.Config {
	c, _ := config.Parse(`server:
  public_url: "https://mail.example.test"
  listen: ":8080"
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
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "stub:v0"
    endpoint: "dns:9443"
`)
	return c
}
func TestRenderDeterministicAndGenerated(t *testing.T) {
	a := Render(cfg())
	b := Render(cfg())
	if a.ID != b.ID {
		t.Fatalf("non-deterministic ids %s %s", a.ID, b.ID)
	}
	for _, f := range a.Files {
		if !strings.HasPrefix(f.Content, Header) {
			t.Fatalf("missing generated header in %s", f.Path)
		}
	}
}
func TestDiff(t *testing.T) {
	d := Diff(Set{}, Render(cfg()))
	if len(d) == 0 || !strings.HasPrefix(d[0], "add ") {
		t.Fatalf("bad diff: %#v", d)
	}
}

func TestRenderIncludesDaemonConfigWithSourceHeader(t *testing.T) {
	s := Render(cfg())
	want := map[string]bool{
		"front/nginx.conf":        false,
		"postfix/gotth-mail.conf": false,
		"dovecot/gotth-mail.conf": false,
		"rspamd/gotth-mail.conf":  false,
		"webmail/provider.conf":   false,
	}
	for _, f := range s.Files {
		if _, ok := want[f.Path]; ok {
			want[f.Path] = true
			if !strings.Contains(f.Content, "generated_config_set="+s.ID) || !strings.Contains(f.Content, "input_hash="+s.InputHash) {
				t.Fatalf("missing source header in %s: %q", f.Path, f.Content)
			}
		}
	}
	for path, ok := range want {
		if !ok {
			t.Fatalf("missing daemon config %s", path)
		}
	}
}
