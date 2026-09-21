package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestControlEnvironmentClosedAndDeterministic(t *testing.T) {
	path := t.TempDir() + "/environment"
	if err := os.WriteFile(path, []byte("GOTTH_MAIL_LISTEN=:8080\nGOTTH_MAIL_DATABASE_URL_FILE=/run/secrets/database-url\nGOTTH_MAIL_DNS_PLAN_FILE=/etc/gotth-mail/control/dns-plan.json\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	first, err := controlEnvironment(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := controlEnvironment(path)
	if err != nil || !slices.Equal(first, second) {
		t.Fatalf("environment is not deterministic: first=%v second=%v err=%v", first, second, err)
	}
	if !slices.Contains(first, "GOTTH_MAIL_DNS_PLAN_FILE=/etc/gotth-mail/control/dns-plan.json") {
		t.Fatalf("DNS plan path missing from control environment: %v", first)
	}
	badPath := t.TempDir() + "/environment"
	if err := os.WriteFile(badPath, []byte("PATH=/attacker\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := controlEnvironment(badPath); err == nil {
		t.Fatal("unknown environment key accepted")
	}
}

func TestRenderFrontConfigKeepsCredentialOutOfArguments(t *testing.T) {
	dir := t.TempDir()
	templatePath, tokenPath, targetPath := dir+"/nginx.conf", dir+"/token", dir+"/runtime.conf"
	if err := os.WriteFile(templatePath, []byte("auth_http_header X-GOTTH-Mail-Front-Token @GOTTH_MAIL_FRONT_AUTH_TOKEN@;\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renderFrontConfig(templatePath, tokenPath, targetPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil || !strings.Contains(string(data), token) {
		t.Fatalf("rendered=%q err=%v", data, err)
	}
	info, err := os.Stat(targetPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	if err := renderFrontConfig(templatePath, tokenPath, targetPath); err == nil {
		t.Fatal("existing runtime configuration replaced")
	}
}

func TestRuntimeCommandRejectsRuntimeRoleSelection(t *testing.T) {
	if _, _, _, err := runtimeCommand("attacker"); err == nil {
		t.Fatal("unknown compiled role accepted")
	}
}

func TestEntrypointRejectsInvalidBuildIdentity(t *testing.T) {
	if err := validateBuildIdentity("1.0.0-alpha.0"); err == nil {
		t.Fatal("invalid entrypoint build identity accepted")
	}
	if err := validateBuildIdentity("1.0.0-alpha.1"); err != nil {
		t.Fatalf("valid entrypoint build identity rejected: %v", err)
	}
}

func TestRenderSecretConfigRejectsDirectiveInjection(t *testing.T) {
	dir := t.TempDir()
	templatePath, tokenPath, targetPath := dir+"/template", dir+"/token", dir+"/runtime"
	if err := os.WriteFile(templatePath, []byte("token=@TOKEN@\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcde;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renderSecretConfig(templatePath, tokenPath, targetPath, "@TOKEN@"); err == nil {
		t.Fatal("directive-injection token accepted")
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("rejected token created runtime file: %v", err)
	}
}
