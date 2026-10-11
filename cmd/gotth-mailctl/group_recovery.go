package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"os"
	"strings"
	"time"
)

// recoveryFlags is a closed, local-only boundary. O(B) time/O(1) auxiliary
// space for B argument bytes; Omega(1) errors, no uniform tight bound.
func recoveryFlags(args []string) (string, error) {
	if len(args) < 3 || (args[2] != "preview" && args[2] != "apply") {
		return "", errors.New("group-feature-disable requires preview or apply")
	}
	seen := map[string]bool{}
	confirmation := ""
	for i := 3; i < len(args); i += 2 {
		if i+1 >= len(args) || (args[i] != "--config" && args[i] != "--confirm") || seen[args[i]] || strings.TrimSpace(args[i+1]) == "" || strings.HasPrefix(args[i+1], "--") {
			return "", errors.New("invalid group-feature-disable flags")
		}
		seen[args[i]] = true
		if args[i] == "--confirm" {
			confirmation = args[i+1]
		}
	}
	if !seen["--config"] || args[2] == "preview" && seen["--confirm"] || args[2] == "apply" && !seen["--confirm"] {
		return "", errors.New("config and mode-appropriate confirmation required")
	}
	return confirmation, nil
}

// runGroupRecovery uses no issuer file, migration or inferred fence. Errors
// deliberately omit config/SQL data; failed apply always requires inspection.
// O(B+Q) time/O(B+S) space, Omega(1) early errors; delegated recovery Q/S includes
// snapshot/projection costs. No uniform tight bound, no retry or background work.
func runGroupRecovery(args []string) error {
	confirmation, e := recoveryFlags(args)
	if e != nil {
		return e
	}
	cfg, e := loadValidatedConfig(args)
	if e != nil {
		return errors.New("group-feature-disable configuration invalid or unavailable")
	}
	db, e := sql.Open("postgres", cfg.Database.DSN)
	if e != nil {
		return errors.New("group-feature-disable database unavailable")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := rolebinding.GroupRecoveryService{DB: db}
	var value any
	if args[2] == "preview" {
		value, e = s.Preview(ctx)
	} else {
		value, e = s.Apply(ctx, confirmation)
	}
	if e != nil {
		return fmt.Errorf("group-feature-disable %s failed; inspect state before fresh preview; no automatic retry", args[2])
	}
	return json.NewEncoder(os.Stdout).Encode(value)
}
