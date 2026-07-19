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
	for _, want := range []string{"external-webmail-plugin:", "manual-dns-plugin:", "cert-plugin:", "backup-plugin:", "notification-plugin:", "GMF_PLUGIN_NAME: external-webmail", "GMF_PLUGIN_NAME: manual-dns-export", "GMF_PLUGIN_NAME: manual-letsencrypt-cert", "GMF_PLUGIN_NAME: local-filesystem-backup", "GMF_PLUGIN_NAME: telegram-notification-sink"} {
		if !strings.Contains(s, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	if strings.Contains(s, "/var/run/docker.sock") {
		t.Fatal("plugin containers must not mount Docker socket")
	}
}

func TestReferenceComposeIncludesContainerizedMailuImportFixture(t *testing.T) {
	b, err := os.ReadFile("../../compose/reference/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"test-runner:", "target: build", "mailu-redis:", "mailu-admin:", "profiles: [\"mailu-import\"]", "ghcr.io/mailu/admin:2.0", "REDIS_HOST: mailu-redis", "mailu-data:", "mailu-dkim:", "mailu-redis:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized Mailu fixture missing %q", want)
		}
	}
	b, err = os.ReadFile("../../scripts/containerized-mailu-import-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s = string(b)
	for _, want := range []string{"--profile mailu-import", "flask mailu config-export --secrets --json", "mktemp -d", "go test -count=1 ./internal/ops ./internal/api", "containerized Mailu import smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized Mailu smoke missing %q", want)
		}
	}
	if strings.Contains(s, "test/fixtures/mailu/config-export-secrets.json >") || strings.Contains(s, "test/fixtures/mailu/config-export.json >") {
		t.Fatal("containerized smoke must not overwrite checked-in fixtures")
	}
}

func TestReferenceComposeIncludesContainerizedWebmailSMTPSmoke(t *testing.T) {
	b, err := os.ReadFile("../../scripts/containerized-webmail-smtp-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"gophermailforge postfix dovecot rspamd", "GMF_LIVE_SMTP_ADDR=postfix:25", "TestNetSMTPSubmitterLiveComposePostfix", "TestOpenPGPMIMESignerProducesVerifiableExactSenderSignature", "TestOpenPGPMIMEVerifierRejectsTamperedSignedPart", "find /mail/example.test/smoke/new", "containerized webmail SMTP smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized webmail SMTP smoke missing %q", want)
		}
	}
}

func TestReferenceComposeIncludesContainerizedWebmailIMAPSmoke(t *testing.T) {
	b, err := os.ReadFile("../../scripts/containerized-webmail-imap-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"gophermailforge postfix dovecot rspamd", "GMF_LIVE_IMAP_ADDR=dovecot:143", "GMF_LIVE_IMAP_USER=smoke@example.test", "GMF_LIVE_IMAP_PASSWORD=smoke-secret", "TestNetIMAPClientLiveComposeDovecot", "containerized webmail IMAP smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized webmail IMAP smoke missing %q", want)
		}
	}
}

func TestReferenceComposeIncludesContainerizedCustomWebmailUISmoke(t *testing.T) {
	b, err := os.ReadFile("../../scripts/containerized-webmail-ui-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"gophermailforge", "GMF_LIVE_WEBMAIL_UI_URL=http://gophermailforge:8080", "TestLiveContainerWebmailShellReachable", "containerized custom webmail UI smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized custom webmail UI smoke missing %q", want)
		}
	}
}

func TestReferenceComposeIncludesContainerizedNotificationPluginSmoke(t *testing.T) {
	b, err := os.ReadFile("../../scripts/containerized-notification-plugin-smoke.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"notification-plugin", "GMF_LIVE_PLUGIN_ENDPOINT=notification-plugin:9443", "GMF_LIVE_PLUGIN_NAME=telegram-notification-sink", "GMF_LIVE_PLUGIN_TOKEN=dev-plugin-token", "TestLivePluginControlOverGRPC", "TestLiveNotificationBackendOverGRPC", "TestRuntimeCommandProvider", "TestTelegramReceiver", "TestApprovalExecutor", "containerized notification plugin gRPC/backend smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized notification plugin smoke missing %q", want)
		}
	}
}

func TestContainerSmokesRebuildTestRunner(t *testing.T) {
	for _, path := range []string{
		"../../scripts/containerized-mailu-import-smoke.sh",
		"../../scripts/containerized-webmail-smtp-smoke.sh",
		"../../scripts/containerized-webmail-imap-smoke.sh",
		"../../scripts/containerized-webmail-ui-smoke.sh",
		"../../scripts/containerized-notification-plugin-smoke.sh",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `build test-runner`) {
			t.Fatalf("%s must rebuild test-runner before running containerized tests", path)
		}
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
	for _, want := range []string{"RCPT TO:<nobody@example.test>", "recipient unknown", "RCPT TO:<alias@example.test>", "find /mail/example.test/smoke/new", "a login smoke@example.test smoke-secret", "GopherMailForge smoke", "roundcube_token", "?_task=mail&_mbox=INBOX", "?_task=mail&_action=list", "acme_not_configured_reference_manual_mode", "\"category\":\"plugin\"", "^DKIM-Signature:", "rspamadm configtest", "postfix policy recipient=alias@example.test decision=ok", "/internal/v1/postfix/recipients/smoke@example.test", "/internal/v1/rspamd/dkim/example.test"} {
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
	b, err := os.ReadFile("../../cmd/gmf/main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"case \"doctor\"", "--format", "json.NewEncoder", "unsupported doctor format"} {
		if !strings.Contains(s, want) {
			t.Fatalf("gmf doctor missing %q", want)
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
