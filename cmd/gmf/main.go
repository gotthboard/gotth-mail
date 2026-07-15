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
		c, err := loadConfigArg(args)
		if err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		s := render.Render(c)
		fmt.Println(s.ID)
		return nil
	case "diff":
		c, err := loadConfigArg(args)
		if err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		fmt.Println(render.JoinDiff(render.Diff(render.Set{}, render.Render(c))))
		return nil
	case "apply":
		c, err := loadConfigArg(args)
		if err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		staged := render.Render(c)
		g := apply.Gate{Audit: &audit.MemoryWriter{}}
		return g.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "cli"}, staged, staged.ID)
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
func loadConfigArg(args []string) (config.Config, error) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" {
			return config.Load(args[i+1])
		}
	}
	return config.Config{}, fmt.Errorf("--config required")
}
