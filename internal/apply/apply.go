package apply

import (
	"context"
	"errors"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/render"
)

type Gate struct {
	Audit      audit.Writer
	Applied    *render.Set
	AppliedDir string
}

func (g *Gate) Apply(ctx context.Context, actor audit.ActorRef, staged render.Set, confirm string) error {
	if confirm == "" || confirm != staged.ID {
		return errors.New("explicit staged-id confirmation required")
	}
	before := ""
	if g.Applied != nil {
		before = g.Applied.ID
	}
	if g.AppliedDir != "" {
		current, err := render.ReadCurrent(g.AppliedDir)
		if err != nil {
			return err
		}
		before = current.ID
		if err := render.MarkApplied(g.AppliedDir, staged); err != nil {
			return err
		}
	}
	g.Applied = &staged
	if g.Audit != nil {
		return g.Audit.Write(ctx, audit.Event{Actor: actor, Action: "config.apply", Resource: audit.ResourceRef{Type: "generated_config_set", ID: staged.ID}, BeforeRedacted: map[string]any{"set": before}, AfterRedacted: map[string]any{"set": staged.ID}, Result: "success"})
	}
	return nil
}
