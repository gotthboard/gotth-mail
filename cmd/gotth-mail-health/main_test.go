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
