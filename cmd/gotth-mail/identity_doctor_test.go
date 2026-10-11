package main

import (
	"context"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"strings"
	"testing"
)

type doctorNoticeSink struct{ alerts []notification.Alert }

func (s *doctorNoticeSink) SendAlert(_ context.Context, a notification.Alert) (notification.DeliveryResult, error) {
	s.alerts = append(s.alerts, a)
	return notification.DeliveryResult{Status: notification.StatusDelivered, Reason: "fixture"}, nil
}
func TestProductionDoctorMonitorAndCommandSafeLocalFacts(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	const issuer = "https://private-issuer-canary.example/application/o/gotth-mail/"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000671','private-domain-canary.test',true,now(),now()); INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('private-scope-canary','Group','private-group-canary','v1',1,1,convert_to('{}','UTF8'))")
	for i, role := range []string{"global_admin", "domain_manager", "scoped_domain_access"} {
		var domain any
		if i > 0 {
			domain = "00000000-0000-4000-8000-000000000671"
		}
		exec("INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,'private-scope-canary','private-group-canary',$3,$4,now(),now())", fmt.Sprintf("00000000-0000-4000-8000-%012d", 680+i), issuer, role, domain)
	}
	registration, e := plugin.FirstMechanismPlugin(plugin.FirstNotifyName, "credential-canary-token")
	if e != nil {
		t.Fatal(e)
	}
	sink := &doctorNoticeSink{}
	server := api.Server{AuditDB: db, CurrentIssuer: issuer, Plugins: plugin.Registry{Plugins: map[string]plugin.Registration{plugin.FirstNotifyName: registration}}, NotificationService: &notification.Service{Backend: sink, Recorder: notification.SQLRecorder{DB: db}}}
	monitor := productionNotificationMonitor(&server, nil, plugin.FirstNotifyName)
	check := func(want ops.Status) {
		t.Helper()
		r, e := monitor.Doctor(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, c := range r.Checks {
			if c.Name == "authentik-role-mapping" {
				found = true
				if c.Status != want {
					t.Fatal(c, want)
				}
			}
		}
		if !found {
			t.Fatal("production monitor notwired")
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "canary") || strings.Contains(string(b), "00000000-0000-") {
			t.Fatal("monitor report disclosed", string(b))
		}
		summary, e := (notifyruntime.RuntimeCommandProvider{DoctorLookup: monitor.Doctor}).Summary(context.Background(), notification.CommandDoctorSummary)
		if e != nil || strings.Contains(summary, "canary") || !strings.Contains(summary, "doctor status=") {
			t.Fatal(summary, e)
		}
	}
	check(ops.OK)
	server.CurrentIssuer = "https://other.example/application/o/gotth-mail/"
	check(ops.Fail)
	if e = monitor.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(sink.alerts) == 0 {
		t.Fatal("no actual notices")
	}
	for _, a := range sink.alerts {
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "canary") || strings.Contains(string(b), "00000000-0000-") {
			t.Fatal("notice disclosed", string(b))
		}
	}
	exec("ALTER TABLE identity_group_role_mappings RENAME TO doctor_private_rows; CREATE FUNCTION doctor_error_guard() RETURNS boolean LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'raw-error-canary credential-canary'; END$$; CREATE VIEW identity_group_role_mappings AS SELECT * FROM doctor_private_rows WHERE doctor_error_guard()")
	server.CurrentIssuer = issuer
	check(ops.Fail)
}
