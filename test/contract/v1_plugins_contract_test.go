package contract

import (
	"os"
	"strings"
	"testing"
)

func TestV1ReferenceComposeIncludesFirstPluginContainers(t *testing.T) {
	b, err := os.ReadFile("../../compose/reference/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"external-webmail-plugin:", "manual-dns-plugin:", "cert-plugin:", "backup-plugin:", "GMF_PLUGIN_NAME: external-webmail", "GMF_PLUGIN_NAME: manual-dns-export", "GMF_PLUGIN_NAME: manual-letsencrypt-cert", "GMF_PLUGIN_NAME: local-filesystem-backup"} {
		if !strings.Contains(s, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	if strings.Contains(s, "/var/run/docker.sock") {
		t.Fatal("plugin containers must not mount Docker socket")
	}
}

func TestDockerImageBuildsPluginRunner(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "go build -o /out/gmf-plugin ./cmd/gmf-plugin") || !strings.Contains(s, "COPY --from=build /out/gmf-plugin /usr/local/bin/gmf-plugin") {
		t.Fatal("Dockerfile must build and copy gmf-plugin")
	}
}

func TestV1ReferenceComposeIncludesRealDaemonRuntime(t *testing.T) {
	b, err := os.ReadFile("../../compose/reference/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"postfix:", "dovecot:", "rspamd:", "webmail:", "postfix start-fg", "dovecot -F", "rspamd -f", "maildata:", "dkimdata:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("compose missing runtime marker %q", want)
		}
	}
}

func TestReferenceRuntimeSmokeScriptCoversMailFlow(t *testing.T) {
	b, err := os.ReadFile("../../scripts/reference-runtime-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"RCPT TO:<alias@example.test>", "find /mail/example.test/smoke/new", "a login smoke@example.test smoke-secret", "GopherMailForge smoke", "rspamadm configtest", "/internal/v1/postfix/recipients/smoke@example.test", "/internal/v1/rspamd/dkim/example.test"} {
		if !strings.Contains(s, want) {
			t.Fatalf("smoke script missing %q", want)
		}
	}
}
