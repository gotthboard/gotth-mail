package diag

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
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
	Domain                string            `json:"domain"`
	MailHost              string            `json:"mail_host"`
	MailIP                string            `json:"mail_ip,omitempty"`
	PTRExpected           string            `json:"ptr_expected,omitempty"`
	DKIMSelector          string            `json:"dkim_selector"`
	DKIMPublicKeyTXT      string            `json:"dkim_public_key_txt,omitempty"`
	DMARCReportAddress    string            `json:"dmarc_report_address,omitempty"`
	AutoconfigHost        string            `json:"autoconfig_host,omitempty"`
	AutodiscoverHost      string            `json:"autodiscover_host,omitempty"`
	MTASTS                bool              `json:"mta_sts"`
	TLSRPTReportAddress   string            `json:"tls_rpt_report_address,omitempty"`
	TLSAExpected          string            `json:"tlsa_expected,omitempty"`
	TLSAEnabled           bool              `json:"tlsa_enabled"`
	UnsupportedRecordNote map[string]string `json:"unsupported_record_note,omitempty"`
}

type DNSResolver interface {
	LookupA(name string) ([]string, error)
	LookupPTR(address string) ([]string, error)
	LookupTXT(name string) ([]string, error)
	LookupMX(name string) ([]string, error)
	LookupSRV(name string) ([]string, error)
	LookupTLSA(name string) ([]string, error)
}

type StaticDNS map[string][]string

func (s StaticDNS) LookupA(name string) ([]string, error) {
	return append([]string(nil), s[key("A", name)]...), nil
}
func (s StaticDNS) LookupPTR(address string) ([]string, error) {
	return append([]string(nil), s[key("PTR", address)]...), nil
}
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

// NetDNS resolves public DNS with a bounded per-query timeout. It deliberately
// implements only the record families used by the administrator readiness
// view; TLSA remains an explicit unsupported boundary in the standard library.
type NetDNS struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

func (r NetDNS) context() (context.Context, context.CancelFunc) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (r NetDNS) resolver() *net.Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func (r NetDNS) LookupA(name string) ([]string, error) {
	ctx, cancel := r.context()
	defer cancel()
	addresses, err := r.resolver().LookupHost(ctx, name)
	if err != nil {
		return nil, dnsLookupError(err)
	}
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	return out, nil
}

func (r NetDNS) LookupPTR(address string) ([]string, error) {
	ctx, cancel := r.context()
	defer cancel()
	values, err := r.resolver().LookupAddr(ctx, address)
	return values, dnsLookupError(err)
}

func (r NetDNS) LookupTXT(name string) ([]string, error) {
	ctx, cancel := r.context()
	defer cancel()
	values, err := r.resolver().LookupTXT(ctx, name)
	return values, dnsLookupError(err)
}

func (r NetDNS) LookupMX(name string) ([]string, error) {
	ctx, cancel := r.context()
	defer cancel()
	records, err := r.resolver().LookupMX(ctx, name)
	if err != nil {
		return nil, dnsLookupError(err)
	}
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, fmt.Sprintf("%d %s", record.Pref, record.Host))
	}
	return out, nil
}

func (r NetDNS) LookupSRV(name string) ([]string, error) {
	ctx, cancel := r.context()
	defer cancel()
	_, records, err := r.resolver().LookupSRV(ctx, "", "", name)
	if err != nil {
		return nil, dnsLookupError(err)
	}
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, fmt.Sprintf("%d %d %d %s", record.Priority, record.Weight, record.Port, record.Target))
	}
	return out, nil
}

func (NetDNS) LookupTLSA(string) ([]string, error) {
	return nil, fmt.Errorf("TLSA lookup is unsupported by the configured resolver")
}

func dnsLookupError(err error) error {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return nil
	}
	return err
}

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
	jobs := []func() DNSRecordCheck{
		func() DNSRecordCheck { return check(r.LookupMX, "MX", d, "MX", []string{"10 " + mailHost + "."}) },
		func() DNSRecordCheck { return check(r.LookupTXT, "SPF", d, "TXT", []string{"v=spf1 mx -all"}) },
		func() DNSRecordCheck {
			return check(r.LookupTXT, "DKIM", plan.DKIMSelector+"._domainkey."+d, "TXT", []string{plan.DKIMPublicKeyTXT})
		},
		func() DNSRecordCheck {
			return check(r.LookupTXT, "DMARC", "_dmarc."+d, "TXT", []string{"v=DMARC1; p=quarantine; rua=" + dmarcReport})
		},
		func() DNSRecordCheck {
			return check(r.LookupSRV, "SRV/autoconfig", "_submission._tcp."+d, "SRV", []string{"0 1 587 " + mailHost + "."})
		},
		func() DNSRecordCheck {
			return check(r.LookupTXT, "TLS-RPT", "_smtp._tls."+d, "TXT", []string{"v=TLSRPTv1; rua=" + tlsRpt})
		},
	}
	var fixed []DNSRecordCheck
	if plan.MTASTS {
		jobs = append(jobs, func() DNSRecordCheck {
			return check(r.LookupTXT, "MTA-STS", "_mta-sts."+d, "TXT", []string{"v=STSv1; id=1"})
		})
	} else {
		fixed = append(fixed, DNSRecordCheck{Family: "MTA-STS", Name: "_mta-sts." + d, Type: "TXT", Status: Unsupported, Remediation: "MTA-STS is not enabled for this deployment policy"})
	}
	if plan.MailIP != "" {
		jobs = append(jobs, func() DNSRecordCheck { return check(r.LookupA, "A", mailHost, "A", []string{plan.MailIP}) })
	}
	if plan.MailIP != "" && plan.PTRExpected != "" {
		jobs = append(jobs, func() DNSRecordCheck {
			return check(r.LookupPTR, "PTR", plan.MailIP, "PTR", []string{strings.TrimSuffix(plan.PTRExpected, ".") + "."})
		})
	}
	if plan.AutoconfigHost != "" {
		jobs = append(jobs, func() DNSRecordCheck {
			return check(r.LookupSRV, "SRV/autoconfig", "_autoconfig._tcp."+d, "SRV", []string{"0 1 443 " + plan.AutoconfigHost + "."})
		})
	}
	if plan.AutodiscoverHost != "" {
		jobs = append(jobs, func() DNSRecordCheck {
			return check(r.LookupSRV, "SRV/autodiscover", "_autodiscover._tcp."+d, "SRV", []string{"0 1 443 " + plan.AutodiscoverHost + "."})
		})
	}
	if plan.TLSAEnabled {
		jobs = append(jobs, func() DNSRecordCheck {
			return check(r.LookupTLSA, "TLSA", "_25._tcp."+mailHost, "TLSA", []string{plan.TLSAExpected})
		})
	} else {
		fixed = append(fixed, DNSRecordCheck{Family: "TLSA", Name: "_25._tcp." + mailHost, Type: "TLSA", Status: Unsupported, Remediation: "TLSA/DANE is not enabled for this deployment policy"})
	}
	checks := make([]DNSRecordCheck, len(jobs))
	var wait sync.WaitGroup
	wait.Add(len(jobs))
	for i := range jobs {
		go func(index int) {
			defer wait.Done()
			checks[index] = jobs[index]()
		}(i)
	}
	wait.Wait()
	checks = append(checks, fixed...)
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
