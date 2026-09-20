package main

import "testing"

func TestEveryProductionRoleHasBoundedHealthTargets(t *testing.T) {
	for _, name := range []string{"control-plane", "front", "postfix", "dovecot", "rspamd"} {
		ports := rolePorts[name]
		if len(ports) == 0 || len(ports) > 5 {
			t.Fatalf("role %s ports=%v", name, ports)
		}
	}
	if _, ok := rolePorts["invalid"]; ok {
		t.Fatal("invalid role has health targets")
	}
}

func TestHealthRejectsInvalidBuildIdentity(t *testing.T) {
	if err := validateBuildIdentity("release-candidate"); err == nil {
		t.Fatal("invalid health build identity accepted")
	}
	if err := validateBuildIdentity("1.0.0-beta.1"); err != nil {
		t.Fatalf("valid health build identity rejected: %v", err)
	}
}
