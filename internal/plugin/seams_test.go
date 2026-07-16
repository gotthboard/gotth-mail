package plugin

import (
	"context"
	"testing"
	"time"
)

func TestFirstMechanismPluginSeamSpecificServices(t *testing.T) {
	r := FirstMechanismPlugins("tok")
	req := Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)}
	if z, err := r.ExportDNSZone(context.Background(), FirstDNSName, req, "Example.Test", []string{"MX 10 mail.example.test."}); err != nil || z.Domain != "example.test" || len(z.Records) != 1 {
		t.Fatalf("dns export = %#v err=%v", z, err)
	}
	if cert, err := r.RequestCertificate(context.Background(), FirstCertName, req, CertificateRequest{Domain: "example.test", Mode: "manual"}); err != nil || cert.Issued || cert.Reason != "acme_not_configured_reference_manual_mode" {
		t.Fatalf("cert result = %#v err=%v", cert, err)
	}
	if b, err := r.VerifyBackup(context.Background(), FirstBackupName, req, "/backup"); err != nil || !b.Writable {
		t.Fatalf("backup verify = %#v err=%v", b, err)
	}
	if w, err := r.WebmailProviderConfig(context.Background(), FirstWebmailName, req); err != nil || w.Provider != "roundcube" || w.IMAPHost == "" || w.SMTPHost == "" {
		t.Fatalf("webmail config = %#v err=%v", w, err)
	}
}

func TestSeamSpecificServicesRejectWrongPlugin(t *testing.T) {
	r := FirstMechanismPlugins("tok")
	req := Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)}
	if _, err := r.ExportDNSZone(context.Background(), FirstCertName, req, "example.test", []string{"MX"}); err == nil {
		t.Fatal("wrong seam accepted")
	}
	bad := req
	bad.ServiceToken = "wrong"
	if _, err := r.WebmailProviderConfig(context.Background(), FirstWebmailName, bad); err == nil {
		t.Fatal("bad token accepted")
	}
}
