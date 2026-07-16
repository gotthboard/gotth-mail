package diag

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RecordStatus string

const (
	Present     RecordStatus = "present"
	Missing     RecordStatus = "missing"
	Mismatch    RecordStatus = "mismatch"
	NotChecked  RecordStatus = "not_checked"
	Unsupported RecordStatus = "unsupported"
)

type DNSRecordCheck struct {
	Family      string       `json:"family"`
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Expected    []string     `json:"expected"`
	Observed    []string     `json:"observed"`
	Status      RecordStatus `json:"status"`
	Remediation string       `json:"remediation"`
}

type DomainDNSPlan struct {
	Domain                string
	MailHost              string
	DKIMSelector          string
	DKIMPublicKeyTXT      string
	DMARCReportAddress    string
	AutoconfigHost        string
	AutodiscoverHost      string
	MTASTS                bool
	TLSRPTReportAddress   string
	TLSAExpected          string
	TLSAEnabled           bool
	UnsupportedRecordNote map[string]string
}

type DNSResolver interface {
	LookupTXT(name string) ([]string, error)
	LookupMX(name string) ([]string, error)
	LookupSRV(name string) ([]string, error)
	LookupTLSA(name string) ([]string, error)
}

type StaticDNS map[string][]string

func (s StaticDNS) LookupTXT(name string) ([]string, error) {
	return append([]string(nil), s[key("TXT", name)]...), nil
}
func (s StaticDNS) LookupMX(name string) ([]string, error) {
	return append([]string(nil), s[key("MX", name)]...), nil
}
func (s StaticDNS) LookupSRV(name string) ([]string, error) {
	return append([]string(nil), s[key("SRV", name)]...), nil
}
func (s StaticDNS) LookupTLSA(name string) ([]string, error) {
	return append([]string(nil), s[key("TLSA", name)]...), nil
}
func key(typ, name string) string { return typ + ":" + strings.ToLower(strings.TrimSuffix(name, ".")) }

func DNSReadiness(plan DomainDNSPlan, r DNSResolver) []DNSRecordCheck {
	d := strings.ToLower(plan.Domain)
	mailHost := plan.MailHost
	if mailHost == "" {
		mailHost = "mail." + d
	}
	dmarcReport := plan.DMARCReportAddress
	if dmarcReport == "" {
		dmarcReport = "mailto:dmarc@" + d
	}
	tlsRpt := plan.TLSRPTReportAddress
	if tlsRpt == "" {
		tlsRpt = "mailto:tlsrpt@" + d
	}
	checks := []DNSRecordCheck{
		check(r.LookupMX, "MX", d, "MX", []string{"10 " + mailHost + "."}),
		check(r.LookupTXT, "SPF", d, "TXT", []string{"v=spf1 mx -all"}),
		check(r.LookupTXT, "DKIM", plan.DKIMSelector+"._domainkey."+d, "TXT", []string{plan.DKIMPublicKeyTXT}),
		check(r.LookupTXT, "DMARC", "_dmarc."+d, "TXT", []string{"v=DMARC1; p=quarantine; rua=" + dmarcReport}),
		check(r.LookupSRV, "SRV/autoconfig", "_submission._tcp."+d, "SRV", []string{"0 1 587 " + mailHost + "."}),
		check(r.LookupTXT, "MTA-STS", "_mta-sts."+d, "TXT", []string{"v=STSv1; id=1"}),
		check(r.LookupTXT, "TLS-RPT", "_smtp._tls."+d, "TXT", []string{"v=TLSRPTv1; rua=" + tlsRpt}),
	}
	if plan.AutoconfigHost != "" {
		checks = append(checks, check(r.LookupSRV, "SRV/autoconfig", "_autoconfig._tcp."+d, "SRV", []string{"0 1 443 " + plan.AutoconfigHost + "."}))
	}
	if plan.AutodiscoverHost != "" {
		checks = append(checks, check(r.LookupSRV, "SRV/autodiscover", "_autodiscover._tcp."+d, "SRV", []string{"0 1 443 " + plan.AutodiscoverHost + "."}))
	}
	if plan.TLSAEnabled {
		checks = append(checks, check(r.LookupTLSA, "TLSA", "_25._tcp."+mailHost, "TLSA", []string{plan.TLSAExpected}))
	} else {
		checks = append(checks, DNSRecordCheck{Family: "TLSA", Name: "_25._tcp." + mailHost, Type: "TLSA", Status: Unsupported, Remediation: "TLSA/DANE is not enabled for this deployment policy"})
	}
	for i := range checks {
		if checks[i].Status != Unsupported && (len(checks[i].Expected) == 0 || checks[i].Expected[0] == "") {
			checks[i].Status = NotChecked
			checks[i].Remediation = "required input missing; cannot compute expected value"
		}
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Family+checks[i].Name < checks[j].Family+checks[j].Name })
	return checks
}

func check(lookup func(string) ([]string, error), family, name, typ string, expected []string) DNSRecordCheck {
	observed, err := lookup(name)
	c := DNSRecordCheck{Family: family, Name: strings.ToLower(strings.TrimSuffix(name, ".")), Type: typ, Expected: normalize(expected), Observed: normalize(observed)}
	if err != nil {
		c.Status = NotChecked
		c.Remediation = "DNS lookup failed: " + err.Error()
		return c
	}
	if len(c.Observed) == 0 {
		c.Status = Missing
		c.Remediation = fmt.Sprintf("create %s %s with value %s", c.Type, c.Name, strings.Join(c.Expected, "; "))
		return c
	}
	if equalSet(c.Expected, c.Observed) {
		c.Status = Present
		return c
	}
	c.Status = Mismatch
	c.Remediation = fmt.Sprintf("replace %s %s value %s with %s", c.Type, c.Name, strings.Join(c.Observed, "; "), strings.Join(c.Expected, "; "))
	return c
}

func normalize(v []string) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		x = strings.Join(strings.Fields(strings.TrimSpace(x)), " ")
		if x != "" {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type CertStatus string

const (
	CertOK      CertStatus = "ok"
	CertWarn    CertStatus = "warn"
	CertFail    CertStatus = "fail"
	CertUnknown CertStatus = "unknown"
)

type CertCheck struct {
	Status      CertStatus `json:"status"`
	Reason      string     `json:"reason"`
	NotAfter    time.Time  `json:"not_after,omitempty"`
	MissingSANs []string   `json:"missing_sans,omitempty"`
}

func CheckCertificatePEM(pemBytes []byte, now time.Time, requiredSANs []string, warnBefore time.Duration) CertCheck {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return CertCheck{Status: CertFail, Reason: "certificate_pem_invalid"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertCheck{Status: CertFail, Reason: "certificate_parse_failed"}
	}
	out := CertCheck{Status: CertOK, Reason: "certificate_valid", NotAfter: cert.NotAfter}
	if now.After(cert.NotAfter) {
		out.Status, out.Reason = CertFail, "certificate_expired"
	}
	if out.Status == CertOK && now.Add(warnBefore).After(cert.NotAfter) {
		out.Status, out.Reason = CertWarn, "certificate_expiring_soon"
	}
	for _, san := range requiredSANs {
		if err := cert.VerifyHostname(san); err != nil {
			out.MissingSANs = append(out.MissingSANs, san)
		}
	}
	if len(out.MissingSANs) > 0 {
		out.Status, out.Reason = CertFail, "certificate_san_mismatch"
	}
	return out
}

func MTASTSPolicy(domain, mx string, maxAgeSeconds int) string {
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 604800
	}
	return fmt.Sprintf("version: STSv1\nmode: enforce\nmx: %s\nmax_age: %d\n", strings.TrimSuffix(mx, "."), maxAgeSeconds)
}

func TLSRPTRecord(reportURI string) string {
	if reportURI == "" {
		return ""
	}
	return "v=TLSRPTv1; rua=" + reportURI
}

type ACMEResult struct {
	OK          bool   `json:"ok"`
	Certificate string `json:"certificate,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	Message     string `json:"message,omitempty"`
}

func ACMEFailure(code, detail string) ACMEResult {
	if code == "" {
		code = "acme_failed"
	}
	return ACMEResult{OK: false, ErrorCode: code, Message: "ACME issuance failed: " + detail}
}
