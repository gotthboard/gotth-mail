package notifyruntime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
)

type RuntimeCommandProvider struct {
	Doctor         *ops.DoctorReport
	Queue          QueueController
	Daemon         *daemon.Service
	Backup         *ops.Backup
	Snapshot       *ops.SnapshotView
	Plugins        plugin.Registry
	DoctorLookup   func(context.Context) (ops.DoctorReport, error)
	BackupLookup   func(context.Context) (ops.Backup, bool, error)
	SnapshotLookup func(context.Context) (ops.SnapshotView, bool, error)
	DomainLookup   func(context.Context) (DomainCounts, error)
	PluginLookup   func(context.Context) ([]PluginHealth, error)
}

type DomainCounts struct {
	EnabledDomains, DisabledDomains, EnabledMailboxes, EnabledAliases int
}

type PluginHealth struct {
	Name             string
	Seam             plugin.Seam
	Enabled, Healthy bool
}

func (p RuntimeCommandProvider) Summary(ctx context.Context, cmd notification.ReadOnlyCommand) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch cmd {
	case notification.CommandDoctorSummary:
		return p.doctorSummary(ctx)
	case notification.CommandQueueSummary:
		return p.queueSummary(ctx)
	case notification.CommandDomainHealth:
		return p.domainSummary(ctx)
	case notification.CommandBackupStatus:
		return p.backupSummary(ctx)
	case notification.CommandDeploymentStatus:
		return p.deploymentSummary(ctx)
	case notification.CommandPluginHealth:
		return p.pluginSummary(ctx)
	default:
		return "", errors.New("unsupported notification command")
	}
}

func (p RuntimeCommandProvider) doctorSummary(ctx context.Context) (string, error) {
	report := p.Doctor
	if p.DoctorLookup != nil {
		got, err := p.DoctorLookup(ctx)
		if err != nil {
			return "", err
		}
		report = &got
	}
	if report == nil {
		return "doctor status unavailable", nil
	}
	fail, warn := 0, 0
	for _, c := range report.Checks {
		switch c.Status {
		case ops.Fail:
			fail++
		case ops.Warn:
			warn++
		}
	}
	return fmt.Sprintf("doctor status=%s checks=%d fail=%d warn=%d", report.Status, len(report.Checks), fail, warn), nil
}

func (p RuntimeCommandProvider) queueSummary(ctx context.Context) (string, error) {
	if p.Queue == nil {
		return "queue status unavailable", nil
	}
	summary, err := p.Queue.Snapshot(ctx, "")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("queue active=%d deferred=%d held=%d total=%d", summary.Active, summary.Deferred, summary.Held, summary.Total), nil
}

func (p RuntimeCommandProvider) domainSummary(ctx context.Context) (string, error) {
	if p.DomainLookup != nil {
		counts, err := p.DomainLookup(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("domains enabled=%d disabled=%d mailboxes=%d aliases=%d", counts.EnabledDomains, counts.DisabledDomains, counts.EnabledMailboxes, counts.EnabledAliases), nil
	}
	if p.Daemon == nil {
		return "domain health unavailable", nil
	}
	enabledDomains, disabledDomains := countEnabledDomains(p.Daemon.Domains)
	enabledMailboxes := 0
	for _, m := range p.Daemon.Mailboxes {
		if m.Enabled {
			enabledMailboxes++
		}
	}
	enabledAliases := 0
	for _, a := range p.Daemon.Aliases {
		if a.Enabled {
			enabledAliases++
		}
	}
	return fmt.Sprintf("domains enabled=%d disabled=%d mailboxes=%d aliases=%d", enabledDomains, disabledDomains, enabledMailboxes, enabledAliases), nil
}

func (p RuntimeCommandProvider) backupSummary(ctx context.Context) (string, error) {
	backup := p.Backup
	if p.BackupLookup != nil {
		got, ok, err := p.BackupLookup(ctx)
		if err != nil {
			return "", err
		}
		if ok {
			backup = &got
		}
	}
	if backup == nil {
		return "backup status=not_recorded", nil
	}
	parts := []string{"backup status=" + backup.Status}
	if backup.ConfigSetID != "" {
		parts = append(parts, "config_set="+backup.ConfigSetID)
	}
	if backup.SchemaVersion != "" {
		parts = append(parts, "schema="+backup.SchemaVersion)
	}
	if backup.IsolatedRestoreRef != "" {
		parts = append(parts, "restore_ref="+backup.IsolatedRestoreRef)
	}
	if backup.FailureReport.Step != "" {
		parts = append(parts, "failure_step="+backup.FailureReport.Step)
	}
	return strings.Join(parts, " "), nil
}

func (p RuntimeCommandProvider) deploymentSummary(ctx context.Context) (string, error) {
	snapshot := p.Snapshot
	if p.SnapshotLookup != nil {
		got, ok, err := p.SnapshotLookup(ctx)
		if err != nil {
			return "", err
		}
		if ok {
			snapshot = &got
		}
	}
	if snapshot == nil {
		return "deployment status=not_recorded", nil
	}
	return fmt.Sprintf("deployment snapshot=%s config_set=%s migration=%s restore=%s images=%d plugins=%d", snapshot.ID, snapshot.GeneratedConfigSetID, snapshot.MigrationVersion, snapshot.VerifiedRestoreStatus, len(snapshot.ImageVersions), len(snapshot.PluginVersions)), nil
}

func (p RuntimeCommandProvider) pluginSummary(ctx context.Context) (string, error) {
	if p.PluginLookup != nil {
		statuses, err := p.PluginLookup(ctx)
		if err != nil {
			return "", err
		}
		healthy, unhealthy, disabled := 0, 0, 0
		for _, status := range statuses {
			if !status.Enabled {
				disabled++
			} else if status.Healthy {
				healthy++
			} else {
				unhealthy++
			}
		}
		return fmt.Sprintf("plugins registered=%d healthy=%d unhealthy=%d disabled=%d", len(statuses), healthy, unhealthy, disabled), nil
	}
	if len(p.Plugins.Plugins) == 0 {
		return "plugins registered=0 enabled=0 disabled=0", nil
	}
	enabled, disabled := 0, 0
	seams := map[plugin.Seam]int{}
	for _, reg := range p.Plugins.Plugins {
		if reg.Enabled {
			enabled++
		} else {
			disabled++
		}
		seams[reg.Seam]++
	}
	keys := make([]string, 0, len(seams))
	for seam := range seams {
		keys = append(keys, string(seam))
	}
	sort.Strings(keys)
	parts := []string{fmt.Sprintf("plugins registered=%d enabled=%d disabled=%d", len(p.Plugins.Plugins), enabled, disabled)}
	for _, seam := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", seam, seams[plugin.Seam(seam)]))
	}
	return strings.Join(parts, " "), nil
}

func countEnabledDomains(domains map[string]daemon.Domain) (int, int) {
	enabled, disabled := 0, 0
	for _, d := range domains {
		if d.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	return enabled, disabled
}
