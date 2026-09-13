package contract

import (
	"os"
	"strings"
	"testing"
)

func TestReferenceComposeExposesOptInSignedEmailNotificationPlugin(t *testing.T) {
	b, err := os.ReadFile("../../compose/reference/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(b)
	for _, want := range []string{
		"signed-email-notification-plugin:",
		`profiles: ["signed-email-notification"]`,
		"GOTTH_MAIL_PLUGIN_NAME: signed-email-notification-sink",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_FROM:",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_TO:",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SIGNING_FINGERPRINT:",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_PRIVATE_KEY_FILE: /run/secrets/notification-signing-key.asc",
		"GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_ADDR: ${GOTTH_MAIL_NOTIFICATION_EMAIL_SMTP_ADDR:-postfix:25}",
		"source: ${GOTTH_MAIL_NOTIFICATION_EMAIL_PRIVATE_KEY_SOURCE:-./secrets/notification-signing-key.asc}",
		"target: /run/secrets/notification-signing-key.asc",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("reference Compose signed-email profile missing %q", want)
		}
	}
	serviceAt := strings.Index(compose, "  signed-email-notification-plugin:")
	if serviceAt < 0 {
		t.Fatal("signed-email notification service not found")
	}
	volumesAt := strings.Index(compose[serviceAt:], "\nvolumes:")
	if volumesAt < 0 {
		t.Fatal("signed-email notification service bounds not found")
	}
	service := compose[serviceAt : serviceAt+volumesAt]
	if strings.Contains(service, "ports:") {
		t.Fatal("opt-in signed-email plugin must remain internal-only")
	}
}
