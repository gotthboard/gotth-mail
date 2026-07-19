package notifyruntime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/notification"
	"forgejo/linus/gophermailforge/internal/ops"
	"forgejo/linus/gophermailforge/internal/plugin"
)

type RuntimeCommandProvider struct {
	Doctor   *ops.DoctorReport
	Queue    *ops.Queue
	Daemon   *daemon.Service
	Backup   *ops.Backup
	Snapshot *ops.SnapshotView
	Plugins  plugin.Registry
}

func (p RuntimeCommandProvider) Summary(ctx context.Context, cmd notification.ReadOnlyCommand) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch cmd {
	case notification.CommandDoctorSummary:
		return p.doctorSummary(), nil
	case notification.CommandQueueSummary:
		return p.queueSummary(), nil
	case notification.CommandDomainHealth:
		return p.domainSummary(), nil
	case notification.CommandBackupStatus:
		return p.backupSummary(), nil
	case notification.CommandDeploymentStatus:
		return p.deploymentSummary(), nil
	case notification.CommandPluginHealth:
		return p.pluginSummary(), nil
	default:
		return "", errors.New("unsupported notification command")
	}
}

func (p RuntimeCommandProvider) doctorSummary() string {
	if p.Doctor == nil {
		return "doctor status unavailable"
	}
	fail, warn := 0, 0
	for _, c := range p.Doctor.Checks {
		switch c.Status {
		case ops.Fail:
			fail++
		case ops.Warn:
			warn++
		}
	}
	return fmt.Sprintf("doctor status=%s checks=%d fail=%d warn=%d", p.Doctor.Status, len(p.Doctor.Checks), fail, warn)
}

func (p RuntimeCommandProvider) queueSummary() string {
	if p.Queue == nil {
		return "queue status unavailable"
	}
	return fmt.Sprintf("queue active=%d deferred=%d", p.Queue.Summary.Active, len(p.Queue.Summary.Deferred))
}

func (p RuntimeCommandProvider) domainSummary() string {
	if p.Daemon == nil {
		return "domain health unavailable"
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
	return fmt.Sprintf("domains enabled=%d disabled=%d mailboxes=%d aliases=%d", enabledDomains, disabledDomains, enabledMailboxes, enabledAliases)
}

func (p RuntimeCommandProvider) backupSummary() string {
	if p.Backup == nil {
		return "backup status unavailable"
	}
	parts := []string{"backup status=" + p.Backup.Status}
	if p.Backup.ConfigSetID != "" {
		parts = append(parts, "config_set="+p.Backup.ConfigSetID)
	}
	if p.Backup.SchemaVersion != "" {
		parts = append(parts, "schema="+p.Backup.SchemaVersion)
	}
	if p.Backup.IsolatedRestoreRef != "" {
		parts = append(parts, "restore_ref="+p.Backup.IsolatedRestoreRef)
	}
	if p.Backup.FailureReport.Step != "" {
		parts = append(parts, "failure_step="+p.Backup.FailureReport.Step)
	}
	return strings.Join(parts, " ")
}

func (p RuntimeCommandProvider) deploymentSummary() string {
	if p.Snapshot == nil {
		return "deployment status unavailable"
	}
	return fmt.Sprintf("deployment snapshot=%s config_set=%s migration=%s restore=%s images=%d plugins=%d", p.Snapshot.ID, p.Snapshot.GeneratedConfigSetID, p.Snapshot.MigrationVersion, p.Snapshot.VerifiedRestoreStatus, len(p.Snapshot.ImageVersions), len(p.Snapshot.PluginVersions))
}

func (p RuntimeCommandProvider) pluginSummary() string {
	if len(p.Plugins.Plugins) == 0 {
		return "plugins registered=0 enabled=0 disabled=0"
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
	return strings.Join(parts, " ")
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
