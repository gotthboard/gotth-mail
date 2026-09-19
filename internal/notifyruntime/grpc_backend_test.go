package notifyruntime

import "testing"

func TestNotificationGRPCRequiresUnixOrLoopbackBoundary(t *testing.T) {
	for _, endpoint := range []string{"unix:///run/gotth-mail-plugins/telegram.sock", "127.0.0.1:9443", "localhost:9443"} {
		if !localGRPCEndpoint(endpoint) {
			t.Fatalf("safe endpoint rejected: %s", endpoint)
		}
	}
	for _, endpoint := range []string{"notification-plugin:9443", "10.0.0.8:9443", "unix:///tmp/plugin.sock", "unix:///run/gotth-mail-plugins/../escape.sock"} {
		if localGRPCEndpoint(endpoint) {
			t.Fatalf("plaintext network endpoint accepted: %s", endpoint)
		}
	}
}
