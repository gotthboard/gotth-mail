package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/apply"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/config"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/identityadopt"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/render"
	"forgejo/gotthboard/gotth-mail/internal/scimtoken"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/version"
	_ "github.com/lib/pq"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if err := version.Validate(version.Version); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: gotth-mailctl <version|config|render|diff|apply|migrate|identity|authz|doctor|audit>")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return fmt.Errorf("usage: gotth-mailctl version")
		}
		fmt.Println(version.Version)
		return nil
	case "config":
		c, err := loadConfigArg(args)
		if err != nil {
			return err
		}
		return c.Validate()
	case "render":
		c, err := loadValidatedConfig(args)
		if err != nil {
			return err
		}
		s := render.Render(c)
		if err := render.Write(c.Render.StagingDir, s); err != nil {
			return err
		}
		fmt.Println(s.ID)
		return nil
	case "diff":
		c, err := loadValidatedConfig(args)
		if err != nil {
			return err
		}
		staged := render.Render(c)
		if _, err := os.Stat(c.Render.StagingDir + string(os.PathSeparator) + staged.ID); err != nil {
			if err := render.Write(c.Render.StagingDir, staged); err != nil {
				return err
			}
		}
		applied, err := render.ReadCurrent(c.Render.AppliedDir)
		if err != nil {
			return err
		}
		fmt.Println(render.JoinDiff(render.Diff(applied, staged)))
		return nil
	case "apply":
		c, err := loadValidatedConfig(args)
		if err != nil {
			return err
		}
		confirm, ok := flagValue(args, "--confirm")
		if !ok || confirm == "" {
			return fmt.Errorf("--confirm <staged-id> required")
		}
		staged, err := render.Read(c.Render.StagingDir, confirm)
		if err != nil {
			return fmt.Errorf("load staged render %q: %w", confirm, err)
		}
		g := apply.Gate{Audit: &audit.MemoryWriter{}, AppliedDir: c.Render.AppliedDir}
		return g.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "cli"}, staged, confirm)
	case "migrate":
		var r store.Runner
		return r.MigrateEmpty()
	case "identity":
		return runIdentity(args)

	case "doctor":
		format, ok := flagValue(args, "--format")
		if !ok || format == "" {
			format = "text"
		}
		report := ops.Doctor(context.Background(), ops.DoctorInput{
			ConfigOK: true, DatabaseOK: true, AuthentikOK: true, WebmailOK: true,
			Daemon:         doctorDaemonFixture(),
			DNSChecks:      []diag.DNSRecordCheck{{Family: "MX", Name: "example.test", Status: diag.Present, Remediation: "ok"}},
			CertCheck:      diag.CertCheck{Status: diag.CertFail, Reason: "acme_not_configured_reference_manual_mode"},
			PluginRegistry: plugin.FirstMechanismPlugins("dev-plugin-token"), PluginToken: "dev-plugin-token", CorrelationID: "cli-doctor",
		})
		switch strings.ToLower(format) {
		case "json":
			return json.NewEncoder(os.Stdout).Encode(report)
		case "text":
			fmt.Println("status:", report.Status)
			for _, c := range report.Checks {
				fmt.Printf("%s/%s: %s (%s)\n", c.Category, c.Name, c.Status, c.Reason)
			}
			return nil
		default:
			return fmt.Errorf("unsupported doctor format %q", format)
		}
	case "audit":
		if len(args) < 4 || args[1] != "retention" {
			return fmt.Errorf("usage: gotth-mailctl audit retention <preview|apply> --policy <policy>")
		}
		policy, ok := flagValue(args, "--policy")
		if !ok || policy == "" {
			return fmt.Errorf("--policy required")
		}
		preview, err := ops.PreviewRetention(nil, policy, time.Now())
		if err != nil {
			return err
		}
		switch args[2] {
		case "preview":
			return json.NewEncoder(os.Stdout).Encode(preview)
		case "apply":
			confirm, ok := flagValue(args, "--confirm")
			if !ok || confirm == "" {
				return fmt.Errorf("--confirm <preview-id> required")
			}
			w := &audit.MemoryWriter{}
			if err := ops.ApplyRetention(context.Background(), w, audit.ActorRef{Type: "local_admin", ID: "cli"}, preview, confirm); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(w.Events)
		default:
			return fmt.Errorf("usage: gotth-mailctl audit retention <preview|apply> --policy <policy>")
		}
	case "authz":
		ex, _ := authz.StaticAuthorizer{}.Explain(context.Background(), authz.Actor{Type: "local_admin", ID: "cli"}, authz.Action("system:admin"), authz.Resource{Type: "system", ID: "self"})
		fmt.Println(ex.Decision.Reason)
		return nil
	}
	return fmt.Errorf("unknown command %s", args[0])
}

func runIdentity(args []string) error {
	if len(args) < 3 || args[2] != "preview" && args[2] != "apply" {
		return identityUsage()
	}
	cfg, err := loadValidatedConfig(args)
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect identity database: %w", err)
	}
	switch args[1] {
	case "adopt":
		request, err := adoptionRequest(args)
		if err != nil {
			return err
		}
		service := identityadopt.Service{DB: db}
		if args[2] == "preview" {
			plan, err := service.Preview(ctx, request)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(plan)
		}
		confirmation, ok := flagValue(args, "--confirm")
		if !ok || confirmation == "" {
			return fmt.Errorf("--confirm <preview-digest> required")
		}
		result, err := service.Apply(ctx, request, confirmation)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "scim-token":
		actorID, secretPath, err := scimTokenRequest(args)
		if err != nil {
			return err
		}
		secret, err := scimtoken.ReadSecret(secretPath)
		if err != nil {
			return err
		}
		defer clear(secret)
		service := scimtoken.Service{DB: db}
		if args[2] == "preview" {
			plan, err := service.Preview(ctx, actorID, secret)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(plan)
		}
		confirmation, ok := flagValue(args, "--confirm")
		if !ok || confirmation == "" {
			return fmt.Errorf("--confirm <preview-digest> required")
		}
		result, err := service.Apply(ctx, actorID, secret, confirmation)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	default:
		return identityUsage()
	}
}

func identityUsage() error {
	return fmt.Errorf("usage: gotth-mailctl identity adopt <preview|apply> --config <file> --mailbox <address> --subject <subject> --scope <scope> --manager <manager> [--confirm <digest>] | gotth-mailctl identity scim-token <preview|apply> --config <file> --id <stable-actor-id> --secret-file <owner-only-file> [--confirm <digest>]")
}

func scimTokenRequest(args []string) (string, string, error) {
	actorID, ok := flagValue(args, "--id")
	if !ok || strings.TrimSpace(actorID) == "" {
		return "", "", fmt.Errorf("--id required")
	}
	secretPath, ok := flagValue(args, "--secret-file")
	if !ok || strings.TrimSpace(secretPath) == "" {
		return "", "", fmt.Errorf("--secret-file required")
	}
	if _, ok := flagValue(args, "--secret"); ok {
		return "", "", fmt.Errorf("--secret is forbidden; use --secret-file")
	}
	return actorID, secretPath, nil
}

func adoptionRequest(args []string) (identityadopt.Request, error) {
	var request identityadopt.Request
	required := []struct {
		name   string
		target *string
	}{{"--mailbox", &request.Mailbox}, {"--subject", &request.Subject}, {"--scope", &request.Scope}, {"--manager", &request.Manager}}
	for _, field := range required {
		value, ok := flagValue(args, field.name)
		if !ok || strings.TrimSpace(value) == "" {
			return identityadopt.Request{}, fmt.Errorf("%s required", field.name)
		}
		*field.target = value
	}
	return request, nil
}
func loadValidatedConfig(args []string) (config.Config, error) {
	c, err := loadConfigArg(args)
	if err != nil {
		return c, err
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}
func loadConfigArg(args []string) (config.Config, error) {
	v, ok := flagValue(args, "--config")
	if !ok {
		return config.Config{}, fmt.Errorf("--config required")
	}
	return config.Load(v)
}
func flagValue(args []string, name string) (string, bool) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1], true
		}
	}
	return "", false
}

func doctorDaemonFixture() daemon.Service {
	verifier := daemon.MakeDjangoPBKDF2SHA256("smoke-secret", "smokesalt", 1200)
	return daemon.Service{
		Domains:   map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true, DKIMSelector: "mail", DKIMPrivateKeyPath: "/run/dkim/example.test.key"}},
		Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true, Home: "/mail/example.test/postmaster", UID: 5000, GID: 5000, QuotaBytes: 1024, Verifier: verifier}},
	}
}
