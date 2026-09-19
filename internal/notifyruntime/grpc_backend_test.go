package notifyruntime

import (
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/plugin"
)

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

func TestNotificationGRPCRequiresAdmittedFoundation(t *testing.T) {
	registration, err := plugin.FirstMechanismPlugin(plugin.FirstNotifyName, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	registration.Foundation = nil
	if backend, err := NewGRPCNotificationBackend("127.0.0.1:9443", "0123456789abcdef", registration); err == nil {
		_ = backend.Close()
		t.Fatal("notification backend accepted missing extension foundation")
	}

	registration, err = plugin.FirstMechanismPlugin(plugin.FirstNotifyName, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewGRPCNotificationBackend("127.0.0.1:9443", "0123456789abcdef", registration)
	if err != nil {
		t.Fatal(err)
	}
	if backend.foundation == nil {
		t.Fatal("notification backend omitted extension foundation")
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
}
