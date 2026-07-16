package main

import (
	"context"
	"fmt"
	"os"

	"forgejo/linus/gophermailforge/internal/apply"
	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/config"
	"forgejo/linus/gophermailforge/internal/render"
	"forgejo/linus/gophermailforge/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gmf <config|render|diff|apply|migrate|authz>")
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
