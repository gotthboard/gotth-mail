package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"os"
	"strings"
)

// configuredDoctor is an explicitly local read surface. It neither bootstraps DB
// nor verifies a provider; report failures retain legacy exit0 semantics.
// Complexity: B config/inventory/output bytes, Q/S SQL and F local file costs:
// time O(B+Q+F), Omega(B), tight Theta not established; auxiliary O(B+S), Omega(B),
// tight Theta not established. Reader has a fixed earlier-cancel-aware deadline.
func configuredDoctor(args []string) error {
	seen := map[string]bool{}
	format := "text"
	for i := 1; i < len(args); i += 2 {
		if i+1 >= len(args) || (args[i] != "--config" && args[i] != "--format") || seen[args[i]] || strings.TrimSpace(args[i+1]) == "" {
			return fmt.Errorf("invalid configured doctor flags")
		}
		seen[args[i]] = true
		if args[i] == "--format" {
			format = strings.ToLower(args[i+1])
		}
	}
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported doctor format")
	}
	c, err := loadValidatedConfig(args)
	if err != nil {
		return fmt.Errorf("configured doctor configuration is invalid or unavailable")
	}
	issuer, authorityErr := identityruntime.LoadIssuer(os.Getenv(identityruntime.ConfigFileEnv))
	db, err := sql.Open("postgres", c.Database.DSN)
	if err != nil {
		db = nil
	}
	if db != nil {
		defer db.Close()
	}
	report, details := ops.DoctorLocal(context.Background(), ops.DoctorInput{Identity: &ops.IdentityDiagnostic{DB: db, CurrentIssuer: issuer, AuthorityInvalid: authorityErr != nil}, ConfigOK: true, AuthentikOK: c.Authentik.Enabled, CertCheck: diag.CertCheck{Status: diag.CertUnknown, Reason: "not_inspected"}, CorrelationID: "cli-doctor"})
	// This local command has no deployed daemon/webmail clients. Do not turn
	// an empty in-process service into a claim about their actual runtime health.
	report.Status = ops.Warn
	for i := range report.Checks {
		check := &report.Checks[i]
		if check.Category == "webmail" || check.Category == "daemon" {
			check.Status = ops.Warn
			check.Reason = "not_inspected_in_configured_cli"
		}
		if check.Status == ops.Fail {
			report.Status = ops.Fail
		}
	}
	if format == "json" {
		return json.NewEncoder(os.Stdout).Encode(struct {
			ops.DoctorReport
			IdentityDetails *ops.IdentityHealth `json:"identity_details"`
		}{report, details})
	}
	fmt.Println("status:", report.Status)
	for _, check := range report.Checks {
		fmt.Printf("%s/%s: %s (%s)\n", check.Category, check.Name, check.Status, check.Reason)
	}
	// JSON-encode tuple details even in text mode to escape control characters.
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	fmt.Printf("local identity details: %s\n", b)
	return nil
}
