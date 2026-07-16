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
	var combined strings.Builder
	for _, path := range []string{
		"../../compose/reference/docker-compose.yml",
		"../../compose/reference/postfix/main.cf",
		"../../compose/reference/rspamd/local.d/dkim_signing.conf",
		"../../compose/reference/rspamd/local.d/worker-proxy.inc",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined.Write(b)
		combined.WriteByte('\n')
	}
	s := combined.String()
	for _, want := range []string{"postfix:", "dovecot:", "rspamd:", "webmail:", "postfix start-fg", "dovecot -F", "rspamd -f", "roundcube/roundcubemail", "ROUNDCUBEMAIL_DEFAULT_HOST", "check_policy_service inet:gophermailforge:10025", "smtpd_milters = inet:rspamd:11332", "bind_socket = \"*:11332\"", "/internal/v1/postfix/aliases/alias@example.test", "/internal/v1/dovecot/passdb", "/internal/v1/rspamd/signing-decision", "maildata:", "dkimdata:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("reference runtime missing marker %q", want)
		}
	}
}

func TestReferenceRuntimeSmokeScriptCoversMailFlow(t *testing.T) {
	b, err := os.ReadFile("../../scripts/reference-runtime-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"RCPT TO:<nobody@example.test>", "recipient unknown", "RCPT TO:<alias@example.test>", "find /mail/example.test/smoke/new", "a login smoke@example.test smoke-secret", "GopherMailForge smoke", "roundcube_token", "?_task=mail&_mbox=INBOX", "?_task=mail&_action=list", "^DKIM-Signature:", "rspamadm configtest", "postfix policy recipient=alias@example.test decision=ok", "/internal/v1/postfix/recipients/smoke@example.test", "/internal/v1/rspamd/dkim/example.test"} {
		if !strings.Contains(s, want) {
			t.Fatalf("smoke script missing %q", want)
		}
	}
}
