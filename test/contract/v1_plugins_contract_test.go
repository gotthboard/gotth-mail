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
	for _, want := range []string{"external-webmail-plugin:", "manual-dns-plugin:", "cert-plugin:", "backup-plugin:", "GOTTH_MAIL_PLUGIN_NAME: external-webmail", "GOTTH_MAIL_PLUGIN_NAME: manual-dns-export", "GOTTH_MAIL_PLUGIN_NAME: manual-letsencrypt-cert", "GOTTH_MAIL_PLUGIN_NAME: local-filesystem-backup"} {
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
	if !strings.Contains(s, "go build -o /out/gotth-mail-plugin ./cmd/gotth-mail-plugin") || !strings.Contains(s, "COPY --from=build /out/gotth-mail-plugin /usr/local/bin/gotth-mail-plugin") {
		t.Fatal("Dockerfile must build and copy gotth-mail-plugin")
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
	for _, want := range []string{"postfix:", "dovecot:", "rspamd:", "webmail:", "postfix start-fg", "dovecot -F", "rspamd -f", "roundcube/roundcubemail", "ROUNDCUBEMAIL_DEFAULT_HOST", "check_policy_service inet:gotth-mail:10025", "smtpd_milters = inet:rspamd:11332", "bind_socket = \"*:11332\"", "/internal/v1/postfix/aliases/alias@example.test", "/internal/v1/dovecot/passdb", "/internal/v1/rspamd/signing-decision", "maildata:", "dkimdata:"} {
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
	for _, want := range []string{"RCPT TO:<nobody@example.test>", "recipient unknown", "RCPT TO:<alias@example.test>", "find /mail/example.test/smoke/new", "a login smoke@example.test smoke-secret", "GOTTH Mail smoke", "roundcube_token", "?_task=mail&_mbox=INBOX", "?_task=mail&_action=list", "acme_not_configured_reference_manual_mode", "\"category\":\"plugin\"", "^DKIM-Signature:", "rspamadm configtest", "postfix policy recipient=alias@example.test decision=ok", "/internal/v1/postfix/recipients/smoke@example.test", "/internal/v1/rspamd/dkim/example.test"} {
		if !strings.Contains(s, want) {
			t.Fatalf("smoke script missing %q", want)
		}
	}
}

func TestV1MailAdminUIScreensExist(t *testing.T) {
	b, err := os.ReadFile("../../internal/httpui/httpui.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"Domain CRUD", "User CRUD", "Alias CRUD", "DNS/DKIM screens", "Doctor screens", "Plugin status/config screens", "Lookup debugger UI", "/admin/domains", "/admin/users", "/admin/aliases"} {
		if !strings.Contains(s, want) {
			t.Fatalf("mail admin UI missing %q", want)
		}
	}
}

func TestV1CLIDoctorCommandExists(t *testing.T) {
	b, err := os.ReadFile("../../cmd/gotth-mailctl/main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"case \"doctor\"", "--format", "json.NewEncoder", "unsupported doctor format"} {
		if !strings.Contains(s, want) {
			t.Fatalf("gotth-mailctl doctor missing %q", want)
		}
	}
}

func TestV1PluginSeamSpecificServicesExist(t *testing.T) {
	b, err := os.ReadFile("../../internal/plugin/seams.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"ExportDNSZone", "RequestCertificate", "VerifyBackup", "WebmailProviderConfig", "acme_not_configured_reference_manual_mode"} {
		if !strings.Contains(s, want) {
			t.Fatalf("plugin seam service missing %q", want)
		}
	}
}
