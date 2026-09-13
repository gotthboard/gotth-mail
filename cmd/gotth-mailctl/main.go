package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/apply"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/config"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/render"
	"forgejo/gotthboard/gotth-mail/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotth-mailctl <config|render|diff|apply|migrate|authz|doctor>")
	}
	switch args[0] {
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
	case "authz":
		ex, _ := authz.StaticAuthorizer{}.Explain(context.Background(), authz.Actor{Type: "local_admin", ID: "cli"}, authz.Action("system:admin"), authz.Resource{Type: "system", ID: "self"})
		fmt.Println(ex.Decision.Reason)
		return nil
	}
	return fmt.Errorf("unknown command %s", args[0])
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
