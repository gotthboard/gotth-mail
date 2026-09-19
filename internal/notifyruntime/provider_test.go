package notifyruntime

import (
	"context"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
)

func TestRuntimeCommandProviderSummarizesRealState(t *testing.T) {
	provider := RuntimeCommandProvider{
		Doctor:   &ops.DoctorReport{Status: ops.Warn, Checks: []ops.Check{{Status: ops.OK}, {Status: ops.Warn}, {Status: ops.Fail}}},
		Queue:    &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Active: 3, Deferred: 2, Total: 5, Digest: strings.Repeat("a", 64)}},
		Daemon:   &daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Enabled: true}, "disabled.test": {}}, Mailboxes: map[string]daemon.Mailbox{"a@example.test": {Enabled: true}, "b@example.test": {}}, Aliases: map[string]daemon.Alias{"alias@example.test": {Enabled: true}}},
		Backup:   &ops.Backup{Status: "verified", ConfigSetID: "cfg-1", SchemaVersion: "schema-1", IsolatedRestoreRef: "restore-1"},
		Snapshot: &ops.SnapshotView{ID: "snap-1", GeneratedConfigSetID: "cfg-1", MigrationVersion: "m1", VerifiedRestoreStatus: "verified", ImageVersions: []string{"gotth-mail:1"}, PluginVersions: []string{"dns:1", "backup:1"}},
		Plugins:  plugin.Registry{Plugins: map[string]plugin.Registration{"dns": {Seam: plugin.DNS, Enabled: true}, "notify": {Seam: plugin.Notification, Enabled: false}}},
	}
	cases := map[notification.ReadOnlyCommand][]string{
		notification.CommandDoctorSummary:    {"doctor status=warn", "checks=3", "fail=1", "warn=1"},
		notification.CommandQueueSummary:     {"queue active=3", "deferred=2"},
		notification.CommandDomainHealth:     {"domains enabled=1", "disabled=1", "mailboxes=1", "aliases=1"},
		notification.CommandBackupStatus:     {"backup status=verified", "config_set=cfg-1", "restore_ref=restore-1"},
		notification.CommandDeploymentStatus: {"deployment snapshot=snap-1", "restore=verified", "images=1", "plugins=2"},
		notification.CommandPluginHealth:     {"plugins registered=2", "enabled=1", "disabled=1", "dns=1", "notification=1"},
	}
	for cmd, wants := range cases {
		got, err := provider.Summary(context.Background(), cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Fatalf("%s missing %q in %q", cmd, want, got)
			}
		}
	}
}

func TestRuntimeCommandProviderUnavailableAndUnsupported(t *testing.T) {
	provider := RuntimeCommandProvider{}
	got, err := provider.Summary(context.Background(), notification.CommandBackupStatus)
	if err != nil || got != "backup status=not_recorded" {
		t.Fatalf("backup unavailable got=%q err=%v", got, err)
	}
	if _, err := provider.Summary(context.Background(), notification.ReadOnlyCommand("shell")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported command accepted: %v", err)
	}
}
