package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var role = "invalid"

const (
	configRoot        = "/etc/gotth-mail"
	frontTokenPath    = "/run/secrets/front-auth-token"
	frontTemplate     = configRoot + "/front/nginx.conf"
	frontRuntimeFile  = "/tmp/gotth-mail-nginx.conf"
	rspamdTemplate    = configRoot + "/rspamd/rspamd.conf"
	rspamdTokenPath   = "/run/secrets/controller-token"
	rspamdRuntimeFile = "/tmp/gotth-mail-rspamd.conf"
	maxConfigBytes    = 1 << 20
)

var controlEnvironmentKeys = map[string]struct{}{
	"GOTTH_MAIL_LISTEN": {}, "GOTTH_MAIL_DATABASE_URL_FILE": {},
	"GOTTH_MAIL_AUTHENTIK_ISSUER": {}, "GOTTH_MAIL_AUTHENTIK_CLIENT_ID": {},
	"GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE": {}, "GOTTH_MAIL_AUTHENTIK_REDIRECT_URI": {},
	"GOTTH_MAIL_SCIM_EXTERNAL_URL": {}, "GOTTH_MAIL_FRONT_AUTH_TOKEN_FILE": {},
	"GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE": {}, "GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT": {},
	"GOTTH_MAIL_EXTENSION_RUNTIME_ROOT": {}, "GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME": {},
	"GOTTH_MAIL_NOTIFICATION_PLUGIN_ENDPOINT": {}, "GOTTH_MAIL_NOTIFICATION_PLUGIN_SERVICE_TOKEN_FILE": {},
	"GOTTH_MAIL_NOTIFICATION_EMAIL_FROM": {}, "GOTTH_MAIL_POSTFIX_HELPER_URL": {},
	"GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE": {}, "GOTTH_MAIL_POSTFIX_RELEASE_TOKEN_FILE": {},
	"GOTTH_MAIL_POSTFIX_POLICY_LISTEN": {}, "GOTTH_MAIL_POSTFIX_AUTOMATIC_SENDER_ADDRESS": {},
	"GOTTH_MAIL_POSTFIX_AUTOMATIC_SENDER_ID": {}, "GOTTH_MAIL_WEBMAIL_RUNTIME_FILE": {},
	"GOTTH_MAIL_POSTFIX_DOMAIN_MAP_LISTEN": {}, "GOTTH_MAIL_POSTFIX_MAILBOX_MAP_LISTEN": {},
	"GOTTH_MAIL_POSTFIX_ALIAS_MAP_LISTEN": {},
}

var postfixEnvironmentKeys = map[string]struct{}{
	"GOTTH_MAIL_CORE_URL": {}, "GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE": {},
	"GOTTH_MAIL_POSTFIX_RELEASE_TOKEN_FILE": {}, "GOTTH_MAIL_POSTFIX_INSTANCE": {},
	"GOTTH_MAIL_POSTFIX_HELPER_LISTEN": {}, "GOTTH_MAIL_OUTBOUND_RELAY_ADDR": {},
}

func main() {
	if role == "postfix" {
		if err := runPostfix(); err != nil {
			fmt.Fprintln(os.Stderr, "gotth-mail entrypoint:", err)
			os.Exit(1)
		}
		return
	}
	executable, arguments, environment, err := runtimeCommand(role)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gotth-mail entrypoint:", err)
		os.Exit(1)
	}
	if err := syscall.Exec(executable, arguments, environment); err != nil {
		fmt.Fprintln(os.Stderr, "gotth-mail entrypoint: exec failed")
		os.Exit(1)
	}
}

func runtimeCommand(selectedRole string) (string, []string, []string, error) {
	switch selectedRole {
	case "control-plane":
		environment, err := configuredEnvironment(configRoot+"/control/environment", controlEnvironmentKeys)
		return "/usr/local/bin/gotth-mail", []string{"gotth-mail"}, environment, err
	case "front":
		if err := renderFrontConfig(frontTemplate, frontTokenPath, frontRuntimeFile); err != nil {
			return "", nil, nil, err
		}
		return "/usr/sbin/nginx", []string{"nginx", "-e", "stderr", "-c", frontRuntimeFile, "-g", "daemon off;"}, fixedEnvironment(), nil
	case "postfix":
		return "", nil, nil, fmt.Errorf("Postfix uses the compiled supervisor")
	case "dovecot":
		return "/usr/sbin/dovecot", []string{"dovecot", "-F", "-c", configRoot + "/dovecot/dovecot.conf"}, fixedEnvironment(), nil
	case "rspamd":
		if err := renderSecretConfig(rspamdTemplate, rspamdTokenPath, rspamdRuntimeFile, "@GOTTH_MAIL_RSPAMD_CONTROLLER_TOKEN@"); err != nil {
			return "", nil, nil, err
		}
		return "/usr/bin/rspamd", []string{"rspamd", "-f", "-c", rspamdRuntimeFile}, fixedEnvironment(), nil
	default:
		return "", nil, nil, fmt.Errorf("image has invalid compiled role")
	}
}

func fixedEnvironment() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "TZ=UTC"}
}

func controlEnvironment(path string) ([]string, error) {
	return configuredEnvironment(path, controlEnvironmentKeys)
}

func configuredEnvironment(path string, allowedKeys map[string]struct{}) ([]string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open control environment: %w", err)
	}
	defer handle.Close()
	reader := bufio.NewReader(io.LimitReader(handle, maxConfigBytes+1))
	values := make(map[string]string)
	var total int
	for {
		line, readErr := reader.ReadString('\n')
		total += len(line)
		if total > maxConfigBytes {
			return nil, fmt.Errorf("control environment exceeds %d bytes", maxConfigBytes)
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line != "" && !strings.HasPrefix(line, "#") {
			name, value, found := strings.Cut(line, "=")
			_, allowed := allowedKeys[name]
			if !found || !allowed || value == "" || strings.TrimSpace(name) != name || strings.ContainsAny(value, "\x00\r\n") {
				return nil, fmt.Errorf("control environment contains invalid assignment")
			}
			if _, duplicate := values[name]; duplicate {
				return nil, fmt.Errorf("control environment contains duplicate assignment")
			}
			values[name] = value
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read control environment: %w", readErr)
		}
	}
	environment := fixedEnvironment()
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+values[name])
	}
	return environment, nil
}

func runPostfix() error {
	environment, err := configuredEnvironment(configRoot+"/postfix/environment", postfixEnvironmentKeys)
	if err != nil {
		return err
	}
	helper := exec.Command("/usr/local/bin/gotth-mail-postfix-gate", "helper")
	postfix := exec.Command("/usr/sbin/postfix", "-c", configRoot+"/postfix", "start-fg")
	for _, command := range []*exec.Cmd{helper, postfix} {
		command.Env = environment
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
	}
	if err := helper.Start(); err != nil {
		return fmt.Errorf("start Postfix helper: %w", err)
	}
	if err := postfix.Start(); err != nil {
		_ = helper.Process.Kill()
		_ = helper.Wait()
		return fmt.Errorf("start Postfix: %w", err)
	}
	type processResult struct {
		name string
		err  error
	}
	results := make(chan processResult, 2)
	go func() { results <- processResult{"Postfix helper", helper.Wait()} }()
	go func() { results <- processResult{"Postfix", postfix.Wait()} }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		terminateProcesses(helper, postfix)
		return nil
	case result := <-results:
		terminateProcesses(helper, postfix)
		if result.err == nil {
			return fmt.Errorf("%s stopped unexpectedly", result.name)
		}
		return fmt.Errorf("%s failed", result.name)
	}
}

func terminateProcesses(commands ...*exec.Cmd) {
	for _, command := range commands {
		if command.Process != nil {
			_ = command.Process.Signal(syscall.SIGTERM)
		}
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	<-timer.C
	for _, command := range commands {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
}

func renderFrontConfig(templatePath, tokenPath, targetPath string) error {
	return renderSecretConfig(templatePath, tokenPath, targetPath, "@GOTTH_MAIL_FRONT_AUTH_TOKEN@")
}

func renderSecretConfig(templatePath, tokenPath, targetPath, placeholder string) error {
	template, err := readBoundedRegular(templatePath, maxConfigBytes, false)
	if err != nil {
		return fmt.Errorf("read service configuration template: %w", err)
	}
	token, err := readBoundedRegular(tokenPath, 1025, true)
	if err != nil {
		return fmt.Errorf("read service credential")
	}
	token = []byte(strings.TrimSuffix(strings.TrimSuffix(string(token), "\n"), "\r"))
	if !safeConfigurationToken(token) {
		return fmt.Errorf("invalid service credential")
	}
	if strings.Count(string(template), placeholder) != 1 {
		return fmt.Errorf("configuration must contain one service credential placeholder")
	}
	rendered := strings.Replace(string(template), placeholder, string(token), 1)
	for index := range token {
		token[index] = 0
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return fmt.Errorf("prepare service runtime path: %w", err)
	}
	handle, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create service runtime configuration: %w", err)
	}
	if _, err := io.WriteString(handle, rendered); err != nil {
		handle.Close()
		return fmt.Errorf("write service runtime configuration: %w", err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close service runtime configuration: %w", err)
	}
	return nil
}

func safeConfigurationToken(token []byte) bool {
	if len(token) < 32 || len(token) > 1024 {
		return false
	}
	for _, value := range token {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' {
			continue
		}
		return false
	}
	return true
}

func readBoundedRegular(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("path is not an admissible regular file")
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds bound or cannot be read")
	}
	return data, nil
}
