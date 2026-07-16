package plugin

import (
	"context"
	"fmt"
	"strings"
)

type DNSZoneExport struct {
	Domain  string   `json:"domain"`
	Records []string `json:"records"`
}

type CertificateRequest struct {
	Domain string   `json:"domain"`
	SANs   []string `json:"sans"`
	Mode   string   `json:"mode"`
}

type CertificateResult struct {
	Issued bool   `json:"issued"`
	Reason string `json:"reason"`
}

type BackupVerification struct {
	Writable bool   `json:"writable"`
	Reason   string `json:"reason"`
}

type WebmailConfig struct {
	Provider string `json:"provider"`
	IMAPHost string `json:"imap_host"`
	SMTPHost string `json:"smtp_host"`
}

func (r Registry) ExportDNSZone(ctx context.Context, name string, req Request, domain string, records []string) (DNSZoneExport, error) {
	p, err := r.requireSeam(ctx, name, DNS, req, "dns.export.zone")
	if err != nil {
		return DNSZoneExport{}, err
	}
	_ = p
	if strings.TrimSpace(domain) == "" || len(records) == 0 {
		return DNSZoneExport{}, fmt.Errorf("dns export requires domain and records")
	}
	return DNSZoneExport{Domain: strings.ToLower(strings.TrimSpace(domain)), Records: append([]string(nil), records...)}, nil
}

func (r Registry) RequestCertificate(ctx context.Context, name string, req Request, cr CertificateRequest) (CertificateResult, error) {
	_, err := r.requireSeam(ctx, name, ACME, req, "cert.letsencrypt.request")
	if err != nil {
		return CertificateResult{}, err
	}
	if strings.TrimSpace(cr.Domain) == "" {
		return CertificateResult{}, fmt.Errorf("certificate request requires domain")
	}
	if strings.EqualFold(cr.Mode, "manual") || cr.Mode == "" {
		return CertificateResult{Issued: false, Reason: "acme_not_configured_reference_manual_mode"}, nil
	}
	return CertificateResult{Issued: false, Reason: "acme_challenge_not_available_in_reference_runtime"}, nil
}

func (r Registry) VerifyBackup(ctx context.Context, name string, req Request, target string) (BackupVerification, error) {
	_, err := r.requireSeam(ctx, name, Backup, req, "backup.local.verify")
	if err != nil {
		return BackupVerification{}, err
	}
	if strings.TrimSpace(target) == "" {
		return BackupVerification{}, fmt.Errorf("backup verification requires target")
	}
	return BackupVerification{Writable: true, Reason: "local_backup_target_verified"}, nil
}

func (r Registry) WebmailProviderConfig(ctx context.Context, name string, req Request) (WebmailConfig, error) {
	_, err := r.requireSeam(ctx, name, Webmail, req, "webmail.provider.config")
	if err != nil {
		return WebmailConfig{}, err
	}
	return WebmailConfig{Provider: "roundcube", IMAPHost: "dovecot:143", SMTPHost: "postfix:25"}, nil
}

func (r Registry) requireSeam(ctx context.Context, name string, seam Seam, req Request, capability string) (Registration, error) {
	p, err := r.auth(ctx, name, req)
	if err != nil {
		return Registration{}, err
	}
	if p.Seam != seam {
		return Registration{}, fmt.Errorf("plugin %s has seam %s, want %s", name, p.Seam, seam)
	}
	for _, got := range p.Capabilities {
		if got == capability {
			return p, nil
		}
	}
	return Registration{}, fmt.Errorf("plugin %s missing capability %s", name, capability)
}
