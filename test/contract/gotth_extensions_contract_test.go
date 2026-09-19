package contract_test

import (
	"os"
	"strings"
	"testing"

	extensionsv1 "forgejo/gotthboard/gotth-mail/proto/gotth/extensions/v1"
	extensioncore "github.com/gotthboard/gotth-extensions/pkg/extensions"
)

const gotthExtensionsVersion = "v0.0.0-20260914032833-3822dd722bc8"

func TestGOTTHExtensionsPinAndPublicConsumerContract(t *testing.T) {
	module, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	wantPin := "github.com/gotthboard/gotth-extensions " + gotthExtensionsVersion
	if !strings.Contains(string(module), wantPin) || strings.Contains(string(module), "replace github.com/gotthboard/gotth-extensions") {
		t.Fatalf("go.mod missing immutable gotth-extensions pin %q", wantPin)
	}

	manifest := extensioncore.Manifest{
		Schema: extensioncore.ManifestSchema, ID: "gotth.mail.test.extension", Name: "test-extension", Version: "0.0.0-dev",
		Protocols:    []extensioncore.VersionRange{{Name: extensioncore.ControlName, Major: 1}},
		Interfaces:   []extensioncore.VersionRange{{Name: "gotth.mail.interface.test", Major: 1}},
		Capabilities: []string{"test.read"},
	}
	digest, err := extensioncore.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	grant := extensioncore.Grant{
		Schema: extensioncore.GrantSchema, InstanceID: "00000000-0000-4000-8000-000000000001",
		ExtensionID: manifest.ID, ManifestDigest: digest, Capabilities: []string{"test.read"},
		Interfaces: []extensioncore.InterfaceGrant{{Name: "gotth.mail.interface.test", Major: 1}},
	}
	session, err := extensioncore.Negotiate(manifest, grant, extensioncore.HostProfile{
		Protocols:  []extensioncore.VersionRange{{Name: extensioncore.ControlName, Major: 1}},
		Interfaces: []extensioncore.VersionRange{{Name: "gotth.mail.interface.test", Major: 1}},
	})
	if err != nil || session.Fingerprint == "" || session.ManifestDigest != digest {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	grant.Capabilities = append(grant.Capabilities, "test.write")
	if _, err := extensioncore.Negotiate(manifest, grant, extensioncore.HostProfile{Protocols: []extensioncore.VersionRange{{Name: extensioncore.ControlName, Major: 1}}}); err == nil {
		t.Fatal("capability expansion accepted")
	}
}

func TestGOTTHExtensionsControlDescriptorHasNoGenericAuthority(t *testing.T) {
	file := extensionsv1.File_proto_gotth_extensions_v1_control_proto
	services := file.Services()
	if services.Len() != 1 || string(services.Get(0).FullName()) != "gotth.extensions.v1.ExtensionControl" {
		t.Fatalf("services=%v", services.Len())
	}
	methods := services.Get(0).Methods()
	if methods.Len() != 2 || string(methods.Get(0).Name()) != "Handshake" || string(methods.Get(1).Name()) != "Health" {
		t.Fatalf("unexpected control methods: %v", methods.Len())
	}
	for i := 0; i < file.Messages().Len(); i++ {
		message := file.Messages().Get(i)
		for j := 0; j < message.Fields().Len(); j++ {
			name := string(message.Fields().Get(j).Name())
			for _, forbidden := range []string{"secret", "credential", "configuration", "payload", "metadata", "command", "action"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("forbidden generic field %s.%s", message.Name(), name)
				}
			}
		}
	}
}
