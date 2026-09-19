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
	for _, want := range []string{"external-webmail-plugin:", "manual-dns-plugin:", "cert-plugin:", "backup-plugin:", "notification-plugin:", "GOTTH_MAIL_PLUGIN_NAME: external-webmail", "GOTTH_MAIL_PLUGIN_NAME: manual-dns-export", "GOTTH_MAIL_PLUGIN_NAME: manual-letsencrypt-cert", "GOTTH_MAIL_PLUGIN_NAME: local-filesystem-backup", "GOTTH_MAIL_PLUGIN_NAME: telegram-notification-sink"} {
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
	for _, want := range []string{"gotth-mail postfix dovecot rspamd", "GOTTH_MAIL_LIVE_SMTP_ADDR=postfix:25", "TestNetSMTPSubmitterLiveComposePostfix", "TestOpenPGPMIMESignerProducesVerifiableExactSenderSignature", "TestOpenPGPMIMEVerifierRejectsTamperedSignedPart", "find /mail/example.test/smoke/new", "containerized webmail SMTP smoke passed"} {
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
	for _, want := range []string{"gotth-mail postfix dovecot rspamd", "GOTTH_MAIL_LIVE_IMAP_ADDR=dovecot:143", "GOTTH_MAIL_LIVE_IMAP_USER=smoke@example.test", "GOTTH_MAIL_LIVE_IMAP_PASSWORD=smoke-secret", "TestNetIMAPClientLiveComposeDovecot", "containerized webmail IMAP smoke passed"} {
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
	for _, want := range []string{"gotth-mail", "GOTTH_MAIL_LIVE_WEBMAIL_UI_URL=http://gotth-mail:8080", "TestLiveContainerWebmailShellReachable", "containerized custom webmail UI smoke passed"} {
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
	for _, want := range []string{"notification-plugin", "GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT=unix:///run/gotth-mail-plugins/telegram.sock", "GOTTH_MAIL_LIVE_PLUGIN_NAME=telegram-notification-sink", "GOTTH_MAIL_LIVE_PLUGIN_TOKEN=dev-plugin-token", "TestLivePluginControlOverGRPC", "TestLiveNotificationBackendOverGRPC", "TestRuntimeCommandProvider", "TestTelegramReceiver", "TestApprovalExecutor", `go test -list "^TestSignedEmailBackend"`, `grep -qx "TestSignedEmailBackendSendsOnlyOpenPGPMIMESignedAlert"`, `grep -qx "TestSignedEmailBackendFailsClosedWithoutSignerOrMatchingIdentity"`, `go test -list "^TestSignedEmailNotificationSinkGRPC"`, `grep -qx "TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt"`, "TestSignedEmailBackend.*", "TestSignedEmailNotificationSinkGRPC.*", "go test -v -count=1", "containerized notification plugin gRPC/backend smoke passed"} {
		if !strings.Contains(s, want) {
			t.Fatalf("containerized notification plugin smoke missing %q", want)
		}
	}
	build := `$DOCKER compose -p "$PROJECT" -f "$COMPOSE" build test-runner`
	loop := `for i in $(seq 1 90); do`
	probe := `$DOCKER compose -p "$PROJECT" -f "$COMPOSE" run --rm -T --no-deps test-runner sh -lc 'test -S /run/gotth-mail-plugins/telegram.sock'`
	listTests := `go test -list "^TestSignedEmailBackend"`
	grepSend := `grep -qx "TestSignedEmailBackendSendsOnlyOpenPGPMIMESignedAlert"`
	grepFailClosed := `grep -qx "TestSignedEmailBackendFailsClosedWithoutSignerOrMatchingIdentity"`
	listRuntime := `go test -list "^TestSignedEmailNotificationSinkGRPC"`
	grepRuntime := `grep -qx "TestSignedEmailNotificationSinkGRPCDeliversCryptographicallyVerifiedSMTPAndRejectsPrompt"`
	runTests := "go test -v -count=1"
	buildAt, loopAt, probeAt := strings.Index(s, build), strings.Index(s, loop), strings.Index(s, probe)
	listAt, grepSendAt, grepFailClosedAt, listRuntimeAt, grepRuntimeAt, runAt := strings.Index(s, listTests), strings.Index(s, grepSend), strings.Index(s, grepFailClosed), strings.Index(s, listRuntime), strings.Index(s, grepRuntime), strings.Index(s, runTests)
	if strings.Count(s, build) != 1 || strings.Count(s, "\n"+build+"\n") != 1 || buildAt < 0 || loopAt < 0 || probeAt < 0 || !(buildAt < loopAt && loopAt < probeAt) {
		t.Fatalf("test-runner build must be one standalone fatal command before readiness loop: build=%d loop=%d probe=%d", buildAt, loopAt, probeAt)
	}
	loopEnd := strings.Index(s[loopAt:], "\ndone\n")
	if loopEnd < 0 {
		t.Fatal("notification smoke readiness loop missing done")
	}
	if strings.Contains(s[loopAt:loopAt+loopEnd], "build test-runner") {
		t.Fatal("test-runner build must not execute inside readiness loop")
	}
	if !strings.Contains(s, `PROJECT=${GOTTH_MAIL_NOTIFICATION_PLUGIN_SMOKE_PROJECT:-gotth-mail-notification-plugin-smoke-$(date +%s)-$$}`) {
		t.Fatal("notification smoke must use a unique default Compose project")
	}
	finalCleanup := `$DOCKER compose -p "$PROJECT" -f "$COMPOSE" down -v --remove-orphans`
	cleanupAt := strings.LastIndex(s, finalCleanup)
	markerAt := strings.LastIndex(s, `echo "containerized notification plugin gRPC/backend smoke passed"`)
	if cleanupAt < 0 || markerAt < 0 || cleanupAt >= markerAt || strings.Contains(s[cleanupAt:markerAt], "|| true") {
		t.Fatalf("notification smoke must prove final cleanup before its success marker: cleanup=%d marker=%d", cleanupAt, markerAt)
	}
	if listAt < 0 || grepSendAt < 0 || grepFailClosedAt < 0 || listRuntimeAt < 0 || grepRuntimeAt < 0 || runAt < 0 || !(listAt < grepSendAt && grepSendAt < runAt && listAt < grepFailClosedAt && grepFailClosedAt < runAt && listRuntimeAt < grepRuntimeAt && grepRuntimeAt < runAt) {
		t.Fatalf("signed-email test discovery and exact-name checks must precede verbose focused tests: backend-list=%d send=%d fail-closed=%d runtime-list=%d runtime=%d run=%d", listAt, grepSendAt, grepFailClosedAt, listRuntimeAt, grepRuntimeAt, runAt)
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
