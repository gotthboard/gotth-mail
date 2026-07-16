package diag

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestDNSReadinessExactPresentMissingMismatchUnsupported(t *testing.T) {
	plan := DomainDNSPlan{Domain: "example.test", MailHost: "mail.example.test", DKIMSelector: "mail", DKIMPublicKeyTXT: "v=DKIM1; k=rsa; p=abc", DMARCReportAddress: "mailto:dmarc@example.test", TLSRPTReportAddress: "mailto:tlsrpt@example.test"}
	observed := StaticDNS{
		key("MX", "example.test"):                   {"10 mail.example.test."},
		key("TXT", "example.test"):                  {"v=spf1 mx ~all"},
		key("TXT", "mail._domainkey.example.test"):  {"v=DKIM1; k=rsa; p=abc"},
		key("TXT", "_dmarc.example.test"):           {"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.test"},
		key("SRV", "_submission._tcp.example.test"): {"0 1 587 mail.example.test."},
		key("TXT", "_mta-sts.example.test"):         {"v=STSv1; id=1"},
		key("TXT", "_smtp._tls.example.test"):       {"v=TLSRPTv1; rua=mailto:tlsrpt@example.test"},
	}
	checks := DNSReadiness(plan, observed)
	byFamily := map[string]DNSRecordCheck{}
	for _, c := range checks {
		byFamily[c.Family] = c
	}
	if byFamily["MX"].Status != Present {
		t.Fatalf("MX got %#v", byFamily["MX"])
	}
	if byFamily["SPF"].Status != Mismatch || byFamily["SPF"].Remediation == "" || byFamily["SPF"].Observed[0] != "v=spf1 mx ~all" {
		t.Fatalf("SPF got %#v", byFamily["SPF"])
	}
	if byFamily["TLSA"].Status != Unsupported {
		t.Fatalf("TLSA got %#v", byFamily["TLSA"])
	}

	plan.TLSAEnabled = true
	plan.TLSAExpected = "3 1 1 abc"
	checks = DNSReadiness(plan, observed)
	for _, c := range checks {
		if c.Family == "TLSA" && c.Status != Missing {
			t.Fatalf("enabled TLSA got %#v", c)
		}
	}
}

func TestMTASTSAndTLSRPTGeneration(t *testing.T) {
	policy := MTASTSPolicy("example.test", "mail.example.test.", 86400)
	if policy != "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n" {
		t.Fatalf("policy=%q", policy)
	}
	if got := TLSRPTRecord("mailto:tlsrpt@example.test"); got != "v=TLSRPTv1; rua=mailto:tlsrpt@example.test" {
		t.Fatalf("tlsrpt=%q", got)
	}
}

func TestCertificateChecks(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	pemBytes := testCert(t, now.Add(-time.Hour), now.Add(48*time.Hour), []string{"mail.example.test"})
	if got := CheckCertificatePEM(pemBytes, now, []string{"mail.example.test"}, 24*time.Hour); got.Status != CertOK {
		t.Fatalf("cert ok got %#v", got)
	}
	if got := CheckCertificatePEM(pemBytes, now, []string{"imap.example.test"}, 24*time.Hour); got.Status != CertFail || got.Reason != "certificate_san_mismatch" {
		t.Fatalf("san mismatch got %#v", got)
	}
	if got := CheckCertificatePEM(pemBytes, now.Add(36*time.Hour), []string{"mail.example.test"}, 24*time.Hour); got.Status != CertWarn || got.Reason != "certificate_expiring_soon" {
		t.Fatalf("warn got %#v", got)
	}
	if got := CheckCertificatePEM(pemBytes, now.Add(72*time.Hour), []string{"mail.example.test"}, 24*time.Hour); got.Status != CertFail || got.Reason != "certificate_expired" {
		t.Fatalf("expired got %#v", got)
	}
}

func TestACMEFailureIsLoudAndActionable(t *testing.T) {
	got := ACMEFailure("dns_challenge_failed", "missing A record for mail.example.test")
	if got.OK || got.ErrorCode != "dns_challenge_failed" || got.Message == "" {
		t.Fatalf("acme failure got %#v", got)
	}
}

func testCert(t *testing.T, notBefore, notAfter time.Time, dnsNames []string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsNames[0]}, NotBefore: notBefore, NotAfter: notAfter, DNSNames: dnsNames, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
